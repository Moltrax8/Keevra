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

use crate::vault::{backup_path_for, write_atomic, VaultError};

pub const PACKAGE_VERSION: u32 = 1;
pub const PACKAGE_FORMAT: &str = "keevra-package";
const LEGACY_PACKAGE_FORMAT: &str = "vaulttrax-package";
/// Hard ceiling for the single-file package read (attachments are already
/// capped individually; this keeps a hostile file from exhausting memory).
pub const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;
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
/// `dest_path` (atomic). Returns the blob count. Never decrypts.
pub fn export_package(vault_path: &Path, dest_path: &Path) -> Result<usize, VaultError> {
    let envelope_text = fs::read_to_string(vault_path).map_err(|e| VaultError::Io(e.to_string()))?;
    let envelope: serde_json::Value =
        serde_json::from_str(&envelope_text).map_err(|e| VaultError::Io(e.to_string()))?;
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
            let text = fs::read_to_string(entry.path()).map_err(|e| VaultError::Io(e.to_string()))?;
            let blob: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| VaultError::Io(e.to_string()))?;
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
    // Touch nothing else: export must not delete or rotate the backup.
    let _ = backup_path_for(vault_path);
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
    let metadata = fs::metadata(source_path).map_err(|e| VaultError::Io(e.to_string()))?;
    if metadata.len() > MAX_PACKAGE_BYTES {
        return Err(VaultError::Io("package_too_large".to_string()));
    }
    let text = fs::read_to_string(source_path).map_err(|e| VaultError::Io(e.to_string()))?;
    let package: Package = serde_json::from_str(&text).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    // Accept the current format and the legacy name so old exports still import.
    if (package.format != PACKAGE_FORMAT && package.format != LEGACY_PACKAGE_FORMAT)
        || package.version != PACKAGE_VERSION
    {
        return Err(VaultError::Io("unsupported_package_version".to_string()));
    }
    if package.vault_file_name.trim().is_empty() || package.attachments.len() > MAX_PACKAGE_ATTACHMENTS {
        return Err(VaultError::Io("invalid_package".to_string()));
    }
    let envelope_text =
        serde_json::to_string_pretty(&package.vault_envelope).map_err(|e| VaultError::Io(e.to_string()))?;
    // Validate envelope shape without decrypting.
    let _: serde_json::Value =
        serde_json::from_str(&envelope_text).map_err(|e| VaultError::Io(e.to_string()))?;

    // Serialize and validate every blob up front.
    let mut blobs: Vec<(String, String)> = Vec::with_capacity(package.attachments.len());
    let mut seen = HashSet::new();
    for entry in &package.attachments {
        if !crate::attachments::is_valid_attachment_id(&entry.id) || !seen.insert(entry.id.as_str()) {
            return Err(VaultError::Io("invalid_package".to_string()));
        }
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

    #[test]
    fn export_import_roundtrip() {
        let dir = std::env::temp_dir().join(format!("keevra-pkg-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let vault = dir.join("a.vault");
        fs::write(&vault, serde_json::json!({"version": 1}).to_string()).expect("vault");
        let att_dir = crate::attachments::attachments_dir(&vault);
        fs::create_dir_all(&att_dir).expect("att dir");
        fs::write(att_dir.join("x.bin"), r#"{"version":1}"#).expect("blob");
        let dest = dir.join("export.vtpkg.json");
        let count = export_package(&vault, &dest).expect("export");
        assert_eq!(count, 1);
        let restored = dir.join("b.vault");
        let imported = import_package(&dest, &restored).expect("import");
        assert_eq!(imported.attachment_count, 1);
        assert!(att_dir.join("x.bin").exists() || crate::attachments::attachments_dir(&restored).join("x.bin").exists());
        assert!(import_package(&dest, &restored).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_package_format_still_imports() {
        let dir = std::env::temp_dir().join(format!("keevra-pkglegacy-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let vault = dir.join("a.vault");
        fs::write(&vault, serde_json::json!({"version": 1}).to_string()).expect("vault");
        let dest = dir.join("export.vtpkg.json");
        export_package(&vault, &dest).expect("export");
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
        let _ = fs::create_dir_all(&dir);
        let bad = dir.join("bad.json");
        fs::write(&bad, r#"{"format":"nope","version":99}"#).expect("bad");
        assert!(import_package(&bad, &dir.join("c.vault")).is_err());
        let traversal = dir.join("traversal.json");
        fs::write(
            &traversal,
            serde_json::json!({
                "format": PACKAGE_FORMAT,
                "version": 1,
                "vaultFileName": "x.vault",
                "vaultEnvelope": {"version": 1},
                "attachments": [{"id": "../escape", "envelope": {"version": 1}}],
            })
            .to_string(),
        )
        .expect("traversal fixture");
        assert!(import_package(&traversal, &dir.join("d.vault")).is_err());
        // A bad entry after a good one must leave no partial vault or blobs.
        let partial = dir.join("partial.json");
        fs::write(
            &partial,
            serde_json::json!({
                "format": "vaulttrax-package",
                "version": 1,
                "vaultFileName": "x.vault",
                "vaultEnvelope": {"version": 1},
                "attachments": [
                    {"id": "good", "envelope": {"version": 1}},
                    {"id": "../escape", "envelope": {"version": 1}},
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
}
