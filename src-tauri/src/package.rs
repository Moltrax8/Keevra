//! Portable vault package (single-file export/import).
//!
//! A package bundles the encrypted vault envelope plus every encrypted
//! attachment blob beside it — all ciphertext, no keys or plaintext.
//! Format v1 JSON:
//! `{ format: "keevra-package", version: 1, vaultFileName, vaultEnvelope,
//!    attachments: [{ id, envelope }] }`.
//! Import accepts the legacy `vaulttrax-package` format for compatibility.
//! Import writes to a fresh random `<uuid>.vault` path chosen by the caller.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path};

use crate::vault::{read_limited, write_atomic, VaultError};

pub const PACKAGE_VERSION: u32 = 1;
pub const PACKAGE_FORMAT: &str = "keevra-package";
const LEGACY_PACKAGE_FORMAT: &str = "vaulttrax-package";
/// Hard ceiling for the single-file package read. A package is parsed into
/// memory, so the cap bounds peak usage; the value is deliberately far below
/// the old 1 GiB ceiling that could stall or OOM the app (K-05).
pub const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKAGE_ATTACHMENTS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobEntry {
    id: String,
    envelope: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Package {
    format: String,
    version: u32,
    vault_file_name: String,
    vault_envelope: serde_json::Value,
    attachments: Vec<BlobEntry>,
}

/// Exports the vault file at `vault_path` plus its sidecar blobs to
/// `dest_path` (atomic). Returns the blob count. Never decrypts unless a
/// session key is supplied: with a key, only blobs referenced by the current
/// document are included and every blob envelope is structurally verified.
///
/// The vault-file lock plus the attachment lock give the export a consistent
/// snapshot against concurrent saves, imports and sweeps (K-09).
pub fn export_package(
    vault_path: &Path,
    dest_path: &Path,
    key: Option<&[u8; 32]>,
) -> Result<usize, VaultError> {
    let _vault_guard = crate::vault::vault_write_guard();
    let _attachment_guard = crate::attachments::lock_attachments();
    let envelope_text = crate::vault::read_vault_file(vault_path)?;
    let envelope: serde_json::Value =
        serde_json::from_str(&envelope_text).map_err(|e| VaultError::Io(e.to_string()))?;
    crate::vault::validate_envelope_value(&envelope)?;
    // With a session key, take the metadata from the *same* decrypted
    // document and prove every referenced blob still decrypts to its recorded
    // hash before packaging it. Concurrent writes hold both locks below, so
    // the exported set always matches the exported document (K-09).
    let live_ids = match key {
        Some(key) => {
            let graph = crate::vault::open_envelope_with_key(&envelope_text, key)?;
            let metadata = crate::attachments::attachment_metadata(&graph.0);
            for (id, sha) in &metadata {
                crate::attachments::verify_attachment(key, vault_path, id, sha)?;
            }
            Some(
                metadata
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect::<Vec<String>>(),
            )
        }
        None => None,
    };
    let file_name = vault_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| VaultError::Io("invalid_vault_path".to_string()))?;
    let dir = crate::attachments::attachments_dir(vault_path);
    let mut attachments = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".bin") {
                continue;
            }
            let id = name.trim_end_matches(".bin").to_string();
            if let Some(live) = &live_ids {
                if !live.iter().any(|live_id| live_id == &id) {
                    continue;
                }
            }
            let blob_bytes = read_limited(
                &entry.path(),
                crate::attachments::MAX_BLOB_ENVELOPE_BYTES,
                "attachment_too_large",
            )?;
            let blob_text = String::from_utf8(blob_bytes)
                .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
            let blob: serde_json::Value =
                serde_json::from_str(&blob_text).map_err(|e| VaultError::Io(e.to_string()))?;
            crate::attachments::validate_blob_value(&blob)?;
            attachments.push(BlobEntry { id, envelope: blob });
        }
    }
    attachments.sort_by(|a, b| a.id.cmp(&b.id));
    let count = attachments.len();
    let package = Package {
        format: PACKAGE_FORMAT.to_string(),
        version: PACKAGE_VERSION,
        vault_file_name: file_name,
        vault_envelope: envelope,
        attachments,
    };
    let text = serde_json::to_string_pretty(&package).map_err(|e| VaultError::Io(e.to_string()))?;
    write_atomic(dest_path, &text)?;
    Ok(count)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedPackage {
    pub vault_path: String,
    pub attachment_count: usize,
}

/// Imports a package to `dest_vault_path` (must not exist). Everything is
/// validated and staged before the first final-path write, so a bad package
/// never leaves a half-imported vault (or stray blobs) behind.
pub fn import_package(source_path: &Path, dest_vault_path: &Path) -> Result<ImportedPackage, VaultError> {
    if dest_vault_path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    // Check the size from metadata first, then parse straight from a buffered
    // file reader: the old path kept the raw byte buffer *and* the parsed
    // package in memory at the same time (K-05).
    let metadata = fs::metadata(source_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(error.to_string())
        }
    })?;
    if metadata.len() > MAX_PACKAGE_BYTES {
        return Err(VaultError::Io("package_too_large".to_string()));
    }
    let file = fs::File::open(source_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(error.to_string())
        }
    })?;
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    let package = Package::deserialize(&mut deserializer)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    deserializer
        .end()
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    // Accept the current format and the legacy name so old exports still import.
    if (package.format != PACKAGE_FORMAT && package.format != LEGACY_PACKAGE_FORMAT)
        || package.version != PACKAGE_VERSION
    {
        return Err(VaultError::Io("unsupported_package_version".to_string()));
    }
    if package.vault_file_name.trim().is_empty()
        || package.vault_file_name.len() > 200
        || package.vault_file_name.contains('/')
        || package.vault_file_name.contains('\\')
        || package.vault_file_name.contains("..")
        || package.vault_file_name.chars().any(|c| c.is_control())
        || package.attachments.len() > MAX_PACKAGE_ATTACHMENTS
    {
        return Err(VaultError::Io("invalid_package".to_string()));
    }
    // Structural validation of the encrypted envelope: version, KDF algorithm
    // and bounds, salt/nonce sizes and ciphertext size. This is not a password
    // check (that happens when the user opens the vault), but it stops a
    // "successful" import of an unopenable file (K-08).
    crate::vault::validate_envelope_value(&package.vault_envelope)?;
    let envelope_text =
        serde_json::to_string_pretty(&package.vault_envelope).map_err(|e| VaultError::Io(e.to_string()))?;

    // Serialize and validate every blob up front.
    let mut blobs: Vec<(String, String)> = Vec::with_capacity(package.attachments.len());
    let mut seen = HashSet::new();
    for entry in &package.attachments {
        if !crate::attachments::is_valid_attachment_id(&entry.id) || !seen.insert(entry.id.as_str()) {
            return Err(VaultError::Io("invalid_package".to_string()));
        }
        crate::attachments::validate_blob_value(&entry.envelope)?;
        let blob_text =
            serde_json::to_string_pretty(&entry.envelope).map_err(|e| VaultError::Io(e.to_string()))?;
        blobs.push((entry.id.clone(), blob_text));
    }

    // Stage the vault and blobs under unique temp names, then commit with
    // renames. Any failure removes everything staged.
    let token = crate::registry::random_vault_filename();
    let temp_vault = dest_vault_path.with_file_name(format!(".import-{token}"));
    let temp_att_dir = crate::attachments::attachments_dir(&temp_vault);
    let final_att_dir = crate::attachments::attachments_dir(dest_vault_path);

    let result = (|| -> Result<ImportedPackage, VaultError> {
        write_atomic(&temp_vault, &envelope_text)?;
        if !blobs.is_empty() {
            fs::create_dir_all(&temp_att_dir).map_err(|e| VaultError::Io(e.to_string()))?;
            for (id, blob_text) in &blobs {
                write_atomic(&temp_att_dir.join(format!("{id}.bin")), blob_text)?;
            }
        }
        let mut attachments_committed = false;
        if !blobs.is_empty() {
            fs::rename(&temp_att_dir, &final_att_dir).map_err(|e| VaultError::Io(e.to_string()))?;
            attachments_committed = true;
        }
        if let Err(error) = fs::rename(&temp_vault, dest_vault_path) {
            if attachments_committed {
                let _ = fs::remove_dir_all(&final_att_dir);
            }
            return Err(VaultError::Io(error.to_string()));
        }
        Ok(ImportedPackage {
            vault_path: dest_vault_path.to_string_lossy().to_string(),
            attachment_count: blobs.len(),
        })
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_vault);
        let _ = fs::remove_dir_all(&temp_att_dir);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{create_vault, read_vault_file};

    fn create_real_vault(path: &Path) -> ([u8; 32], [u8; 16], crate::vault::KdfCost) {
        let (_graph, salt, key, cost) =
            create_vault(path, b"correct horse battery").expect("create vault");
        (*key, salt, cost)
    }

    fn envelope_value(vault: &Path) -> serde_json::Value {
        serde_json::from_str(&read_vault_file(vault).expect("read vault")).expect("envelope")
    }

    fn import_blob(
        vault: &Path,
        key: &[u8; 32],
        id: &str,
        dir: &Path,
    ) -> (serde_json::Value, String) {
        let source = dir.join(format!("{id}.src"));
        fs::write(&source, b"attachment-bytes").expect("fixture");
        let meta = crate::attachments::attachment_import(key, vault, id, "node-1", &source)
            .expect("import");
        let blob_path = crate::attachments::attachments_dir(vault).join(format!("{id}.bin"));
        let envelope =
            serde_json::from_str(&fs::read_to_string(blob_path).expect("blob")).expect("blob json");
        (envelope, meta.sha256_hex)
    }

    #[test]
    fn export_import_roundtrip() {
        let dir = std::env::temp_dir().join(format!("keevra-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let vault = dir.join("a.vault");
        let (key, salt, cost) = create_real_vault(&vault);
        let (_blob, sha) = import_blob(&vault, &key, "x", &dir);
        // Reference the blob from the document so a keyed export includes it.
        let graph: crate::vault::GraphData = serde_json::from_value(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [],
            "presets": [],
            "serviceIcons": {},
            "attachments": [{
                "id": "x",
                "nodeId": "node-1",
                "fileName": "x.src",
                "mimeType": "application/octet-stream",
                "sizeBytes": 16,
                "sha256Hex": sha,
                "createdAtMs": 0
            }]
        }))
        .expect("graph");
        crate::vault::save_vault(&vault, &graph, &key, &salt, cost).expect("save");
        let envelope = envelope_value(&vault);
        let dest = dir.join("export.vtpkg.json");
        let count = export_package(&vault, &dest, Some(&key)).expect("export");
        assert_eq!(count, 1);
        // The exported envelope is the real encrypted vault, not a placeholder.
        let package: Package =
            serde_json::from_str(&fs::read_to_string(&dest).expect("package")).expect("parse");
        assert_eq!(package.vault_envelope, envelope);
        let restored = dir.join("b.vault");
        let imported = import_package(&dest, &restored).expect("import");
        assert_eq!(imported.attachment_count, 1);
        assert!(crate::attachments::attachments_dir(&restored).join("x.bin").exists());
        assert!(import_package(&dest, &restored).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_refuses_a_tampered_referenced_blob() {
        let dir = std::env::temp_dir().join(format!("keevra-pkgtamper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let vault = dir.join("a.vault");
        let (key, salt, cost) = create_real_vault(&vault);
        let (_blob, sha) = import_blob(&vault, &key, "x", &dir);
        let graph: crate::vault::GraphData = serde_json::from_value(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [],
            "presets": [],
            "serviceIcons": {},
            "attachments": [{
                "id": "x",
                "nodeId": "node-1",
                "fileName": "x.src",
                "mimeType": "application/octet-stream",
                "sizeBytes": 16,
                "sha256Hex": sha,
                "createdAtMs": 0
            }]
        }))
        .expect("graph");
        crate::vault::save_vault(&vault, &graph, &key, &salt, cost).expect("save");

        // Flip one ciphertext character: the blob still parses structurally but
        // no longer authenticates, so export must refuse instead of publishing
        // a package whose attachment cannot be opened (K-09).
        let blob_path = crate::attachments::attachments_dir(&vault).join("x.bin");
        let mut blob: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&blob_path).expect("blob")).expect("json");
        let ciphertext = blob["ciphertext_b64"].as_str().expect("ciphertext");
        let tampered = format!("{}{}", if ciphertext.starts_with('A') { "B" } else { "A" }, &ciphertext[1..]);
        blob["ciphertext_b64"] = serde_json::Value::String(tampered);
        fs::write(&blob_path, serde_json::to_string(&blob).expect("json")).expect("tamper");

        let dest = dir.join("export.vtpkg.json");
        assert!(export_package(&vault, &dest, Some(&key)).is_err());
        assert!(!dest.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_package_format_still_imports() {
        let dir = std::env::temp_dir().join(format!("keevra-pkglegacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let vault = dir.join("a.vault");
        create_real_vault(&vault);
        let dest = dir.join("export.vtpkg.json");
        export_package(&vault, &dest, None).expect("export");
        let text = fs::read_to_string(&dest).expect("read");
        let legacy = text.replace(PACKAGE_FORMAT, LEGACY_PACKAGE_FORMAT);
        fs::write(&dest, legacy).expect("write legacy");
        let restored = dir.join("b.vault");
        let imported = import_package(&dest, &restored).expect("import legacy");
        assert_eq!(imported.attachment_count, 0);
        assert!(restored.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_packages() {
        let dir = std::env::temp_dir().join(format!("keevra-pkgbad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let seed = dir.join("seed.vault");
        let (key, _salt, _cost) = create_real_vault(&seed);
        let envelope = envelope_value(&seed);
        let (real_blob, _sha) = import_blob(&seed, &key, "good", &dir);

        let bad = dir.join("bad.json");
        fs::write(&bad, r#"{"format":"nope","version":99}"#).expect("bad");
        assert!(import_package(&bad, &dir.join("c.vault")).is_err());

        // A placeholder envelope (`{"version":1}`) must now be rejected.
        let placeholder = dir.join("placeholder.json");
        fs::write(
            &placeholder,
            serde_json::json!({
                "format": PACKAGE_FORMAT,
                "version": 1,
                "vaultFileName": "x.vault",
                "vaultEnvelope": {"version": 1},
                "attachments": [],
            })
            .to_string(),
        )
        .expect("placeholder");
        assert!(import_package(&placeholder, &dir.join("p.vault")).is_err());

        let traversal = dir.join("traversal.json");
        fs::write(
            &traversal,
            serde_json::json!({
                "format": PACKAGE_FORMAT,
                "version": 1,
                "vaultFileName": "x.vault",
                "vaultEnvelope": envelope,
                "attachments": [{"id": "../escape", "envelope": real_blob}],
            })
            .to_string(),
        )
        .expect("traversal fixture");
        assert!(import_package(&traversal, &dir.join("d.vault")).is_err());

        // A structurally invalid blob after a valid one must leave no partial
        // vault or blobs behind.
        let partial = dir.join("partial.json");
        fs::write(
            &partial,
            serde_json::json!({
                "format": "vaulttrax-package",
                "version": 1,
                "vaultFileName": "x.vault",
                "vaultEnvelope": envelope_value(&seed),
                "attachments": [
                    {"id": "good", "envelope": real_blob},
                    {"id": "bad", "envelope": {"version": 1}},
                ],
            })
            .to_string(),
        )
        .expect("partial fixture");
        let partial_dest = dir.join("e.vault");
        assert!(import_package(&partial, &partial_dest).is_err());
        assert!(!partial_dest.exists());
        assert!(!crate::attachments::attachments_dir(&partial_dest).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// K-05: the package cap is enforced from file metadata before any parse,
    /// so an oversized file is rejected without being read into memory.
    #[test]
    fn oversized_package_is_rejected_before_reading() {
        let dir = std::env::temp_dir().join(format!("keevra-pkgbig-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let oversized = dir.join("oversized.json");
        let file = fs::File::create(&oversized).expect("create");
        file.set_len(MAX_PACKAGE_BYTES + 1).expect("sparse size");
        drop(file);

        let error = import_package(&oversized, &dir.join("dest.vault"))
            .expect_err("oversized package must be rejected");
        assert!(
            matches!(error, VaultError::Io(ref message) if message == "package_too_large"),
            "unexpected error: {error:?}"
        );
        assert!(!dir.join("dest.vault").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
