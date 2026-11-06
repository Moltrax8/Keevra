//! Encrypted attachments (post-MVP Phase D).
//!
//! Binary blobs live beside the vault file (`<vault>.attachments/<id>.bin`)
//! as versioned JSON envelopes: XChaCha20-Poly1305 over the raw bytes under
//! the session master key, fresh nonce per blob, attachment ID bound as
//! associated data. Metadata (name, MIME, size, sha256) lives in the vault
//! plaintext so listings never touch blobs. Cap: 25 MiB per file; chunked
//! streaming is deferred because the cap keeps whole-file handling safe.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::SystemTime,
};

use crate::vault::{open_raw, read_limited, seal_raw, VaultError};

pub const ATTACHMENT_VERSION: u32 = 1;
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
/// In-memory preview cap (downloads still allow the full 25 MiB).
pub const MAX_PREVIEW_BYTES: u64 = 10 * 1024 * 1024;
/// Base64 of the largest ciphertext plus JSON envelope overhead.
pub(crate) const MAX_BLOB_ENVELOPE_BYTES: u64 = 40 * 1024 * 1024;

/// Serializes blob writes with sweeps so a save-time sweep can never delete a
/// blob that an import is still writing (K-05).
static ATTACHMENT_IO_LOCK: Mutex<()> = Mutex::new(());

/// Imports that returned to the frontend but whose metadata has not reached
/// the vault document yet. The sweep must retain these until a save lists them.
static PENDING_IDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub(crate) fn lock_attachments() -> MutexGuard<'static, ()> {
    ATTACHMENT_IO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn mark_pending(id: &str) {
    let mut pending = PENDING_IDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !pending.iter().any(|existing| existing == id) {
        pending.push(id.to_string());
    }
}

fn clear_pending(id: &str) {
    let mut pending = PENDING_IDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pending.retain(|existing| existing != id);
}

fn pending_ids() -> Vec<String> {
    PENDING_IDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentMeta {
    pub id: String,
    pub node_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttachmentBlob {
    version: u32,
    nonce_b64: String,
    ciphertext_b64: String,
}

const MAX_BLOB_B64_LEN: usize = ((MAX_ATTACHMENT_BYTES as usize + 16 + 2) / 3) * 4;

/// Structural blob validation used by package import: no key needed, but the
/// version, nonce size and bounded ciphertext are checked before staging.
fn validate_blob_shape(blob: &AttachmentBlob) -> Result<(), VaultError> {
    if blob.version != ATTACHMENT_VERSION {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    let nonce = B64
        .decode(&blob.nonce_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    if nonce.len() != 24 {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    if blob.ciphertext_b64.is_empty() || blob.ciphertext_b64.len() > MAX_BLOB_B64_LEN {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    Ok(())
}

pub fn validate_blob_value(value: &serde_json::Value) -> Result<(), VaultError> {
    let blob: AttachmentBlob =
        serde_json::from_value(value.clone()).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_blob_shape(&blob)
}

const ATTACHMENT_AAD_PREFIX: &[u8] = b"keevra-attachment-v1:";
const LEGACY_ATTACHMENT_AAD_PREFIX: &[u8] = b"vaulttrax-attachment-v1:";

fn aad_with_prefix(prefix: &[u8], id: &str) -> Vec<u8> {
    let mut aad = prefix.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn attachment_aad(id: &str) -> Vec<u8> {
    aad_with_prefix(ATTACHMENT_AAD_PREFIX, id)
}

fn legacy_attachment_aad(id: &str) -> Vec<u8> {
    aad_with_prefix(LEGACY_ATTACHMENT_AAD_PREFIX, id)
}

/// Attachment IDs become file names, so only a safe, bounded character set is
/// accepted. Rejecting separators and `..` keeps a hostile package or IPC call
/// from writing outside `<vault>.attachments`.
pub(crate) fn is_valid_attachment_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 || id == "." || id == ".." || id.contains("..") {
        return false;
    }
    id.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
    })
}

pub(crate) fn attachments_dir(vault_path: &Path) -> PathBuf {
    let mut dir = vault_path.as_os_str().to_owned();
    dir.push(".attachments");
    PathBuf::from(dir)
}

fn blob_path(vault_path: &Path, id: &str) -> PathBuf {
    attachments_dir(vault_path).join(format!("{id}.bin"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Imports a file into encrypted blob storage. Reads the source directly —
/// no plaintext temp copies are ever written.
pub fn attachment_import(
    key: &[u8; 32],
    vault_path: &Path,
    attachment_id: &str,
    node_id: &str,
    source_path: &Path,
) -> Result<AttachmentMeta, VaultError> {
    if !is_valid_attachment_id(attachment_id) {
        return Err(VaultError::Io("invalid_attachment_id".to_string()));
    }
    let _guard = lock_attachments();
    // Publish the ID before the blob becomes visible so a concurrent sweep
    // retains it even if the frontend has not committed metadata yet.
    mark_pending(attachment_id);
    let result = (|| -> Result<AttachmentMeta, VaultError> {
        let bytes = read_limited(source_path, MAX_ATTACHMENT_BYTES, "attachment_too_large")?;
        let file_name = source_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| VaultError::Io("invalid_file_name".to_string()))?;
        let mime_type = mime_guess::from_path(source_path)
            .first_or_octet_stream()
            .essence_str()
            .to_string();
        let (nonce, ciphertext) = seal_raw(&bytes, key, &attachment_aad(attachment_id))?;
        let blob = AttachmentBlob {
            version: ATTACHMENT_VERSION,
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(&ciphertext),
        };
        let dir = attachments_dir(vault_path);
        fs::create_dir_all(&dir).map_err(|e| VaultError::Io(e.to_string()))?;
        let envelope =
            serde_json::to_string_pretty(&blob).map_err(|e| VaultError::Io(e.to_string()))?;
        crate::vault::write_atomic(&blob_path(vault_path, attachment_id), &envelope)?;
        Ok(AttachmentMeta {
            id: attachment_id.to_string(),
            node_id: node_id.to_string(),
            file_name,
            mime_type,
            size_bytes: bytes.len() as u64,
            sha256_hex: sha256_hex(&bytes),
            created_at_ms: now_ms(),
        })
    })();
    if result.is_err() {
        clear_pending(attachment_id);
    }
    result
}

/// Exports a blob after verifying it against expected metadata. The hash
/// binds the bytes to the vault's metadata record.
pub fn attachment_export(
    key: &[u8; 32],
    vault_path: &Path,
    attachment_id: &str,
    expected_sha256: &str,
    dest_path: &Path,
) -> Result<u64, VaultError> {
    let plaintext = decrypt_blob_bytes(key, vault_path, attachment_id, expected_sha256, None)?;
    crate::vault::write_atomic_bytes(dest_path, &plaintext)?;
    Ok(plaintext.len() as u64)
}

/// Decrypts a blob in memory for in-app preview. Never touches disk: the
/// caller holds bytes only while unlocked and must drop them on lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPreview {
    pub bytes_b64: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
}

pub fn attachment_read(
    key: &[u8; 32],
    vault_path: &Path,
    attachment_id: &str,
    expected_sha256: &str,
) -> Result<AttachmentPreview, VaultError> {
    let plaintext = decrypt_blob_bytes(
        key,
        vault_path,
        attachment_id,
        expected_sha256,
        Some(MAX_PREVIEW_BYTES),
    )?;
    Ok(AttachmentPreview {
        bytes_b64: B64.encode(&plaintext),
        sha256_hex: sha256_hex(&plaintext),
        size_bytes: plaintext.len() as u64,
    })
}

fn decrypt_blob_bytes(
    key: &[u8; 32],
    vault_path: &Path,
    attachment_id: &str,
    expected_sha256: &str,
    max_plaintext: Option<u64>,
) -> Result<Vec<u8>, VaultError> {
    if !is_valid_attachment_id(attachment_id) {
        return Err(VaultError::Io("invalid_attachment_id".to_string()));
    }
    let envelope_json = read_limited(
        &blob_path(vault_path, attachment_id),
        MAX_BLOB_ENVELOPE_BYTES,
        "attachment_too_large",
    )
    .map_err(|error| match error {
        VaultError::NotFound => VaultError::Io("attachment_not_found".to_string()),
        VaultError::Io(message) if message.contains("attachment_too_large") => {
            VaultError::Io("attachment_corrupt".to_string())
        }
        other => other,
    })?;
    let envelope_text =
        String::from_utf8(envelope_json).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let blob: AttachmentBlob =
        serde_json::from_str(&envelope_text).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_blob_shape(&blob)?;
    let nonce_vec = B64
        .decode(&blob.nonce_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let nonce: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let ciphertext = B64
        .decode(&blob.ciphertext_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    if let Some(max) = max_plaintext {
        if ciphertext.len() as u64 > max.saturating_add(16) {
            return Err(VaultError::Io("attachment_too_large_for_preview".to_string()));
        }
    }
    let plaintext = match open_raw(&ciphertext, key, &nonce, &attachment_aad(attachment_id)) {
        Ok(plaintext) => plaintext,
        Err(_) => open_raw(
            &ciphertext,
            key,
            &nonce,
            &legacy_attachment_aad(attachment_id),
        )?,
    };
    if max_plaintext.is_some_and(|max| plaintext.len() as u64 > max) {
        return Err(VaultError::Io("attachment_too_large_for_preview".to_string()));
    }
    if sha256_hex(&plaintext) != expected_sha256 {
        return Err(VaultError::Io("attachment_corrupt".to_string()));
    }
    Ok(plaintext)
}

/// Ids referenced by the vault document, for the save-time orphan sweep.
pub fn live_attachment_ids(
    document: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    document
        .get("attachments")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id")?.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// `(id, sha256)` pairs referenced by the vault document.
pub fn attachment_metadata(
    document: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    document
        .get("attachments")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let id = item.get("id")?.as_str()?.to_string();
                    let sha = item.get("sha256Hex")?.as_str()?.to_string();
                    Some((id, sha))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Decrypts a blob and verifies its plaintext hash without keeping the bytes.
/// Package export uses this so a tampered or inconsistent blob is never
/// published inside an otherwise valid package (K-09).
pub fn verify_attachment(
    key: &[u8; 32],
    vault_path: &Path,
    attachment_id: &str,
    expected_sha256: &str,
) -> Result<(), VaultError> {
    decrypt_blob_bytes(key, vault_path, attachment_id, expected_sha256, None).map(|_| ())
}

/// Removes blobs with no live metadata record. Returns removals count.
///
/// Runs under the same lock as imports, and never deletes an ID that an import
/// has published but not yet committed to the vault document (K-05).
pub fn attachment_sweep(vault_path: &Path, live_ids: &[String]) -> usize {
    let _guard = lock_attachments();
    {
        let mut pending = PENDING_IDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A live ID is committed metadata, so it is no longer pending.
        pending.retain(|id| !live_ids.iter().any(|live| live == id));
    }
    let pending = pending_ids();
    let dir = attachments_dir(vault_path);
    let entries = fs::read_dir(&dir).map(|read| {
        read.filter_map(|entry| entry.ok()).collect::<Vec<_>>()
    });
    let mut removed = 0;
    if let Ok(entries) = entries {
        for entry in entries {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".bin") {
                continue;
            }
            let id = name.trim_end_matches(".bin");
            if !live_ids.iter().any(|live| live == id)
                && !pending.iter().any(|held| held == id)
                && fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn sandbox() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("keevra-att-{}-{}", std::process::id(), id));
        let _ = fs::create_dir_all(&dir);
        dir.push("vault.vault");
        dir
    }

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn roundtrip_import_export_delete() {
        let vault = sandbox();
        let source = vault.with_extension("source.bin");
        fs::write(&source, b"attachment-bytes-123").expect("fixture");
        let meta = attachment_import(&key(), &vault, "att-1", "node-1", &source).expect("import");
        assert_eq!(meta.file_name, source.file_name().unwrap().to_string_lossy());
        assert_eq!(meta.size_bytes, 20);
        assert_eq!(meta.sha256_hex, sha256_hex(b"attachment-bytes-123"));
        let dest = vault.with_extension("exported.bin");
        let bytes = attachment_export(&key(), &vault, "att-1", &meta.sha256_hex, &dest).expect("export");
        assert_eq!(bytes, 20);
        assert_eq!(fs::read(&dest).expect("read back"), b"attachment-bytes-123");
        // Imports stay pending until a save lists them, so a sweep before that
        // must retain the blob (K-05)...
        assert_eq!(attachment_sweep(&vault, &[]), 0);
        assert!(blob_path(&vault, "att-1").exists());
        // ...and a save that lists the ID commits it, after which an orphan
        // sweep may remove it.
        assert_eq!(attachment_sweep(&vault, &["att-1".to_string()]), 0);
        assert_eq!(attachment_sweep(&vault, &[]), 1);
        assert!(!blob_path(&vault, "att-1").exists());
        assert_eq!(attachment_sweep(&vault, &[]), 0);
        let _ = fs::remove_dir_all(vault.parent().expect("parent"));
    }

    #[test]
    fn tampered_blob_and_wrong_metadata_fail() {
        let vault = sandbox();
        let source = vault.with_extension("source.bin");
        fs::write(&source, b"0123456789abcdef").expect("fixture");
        let meta = attachment_import(&key(), &vault, "att-2", "node-1", &source).expect("import");
        let blob_file = blob_path(&vault, "att-2");
        let mut envelope: AttachmentBlob =
            serde_json::from_str(&fs::read_to_string(&blob_file).expect("read")).expect("parse");
        let mut raw = B64.decode(&envelope.ciphertext_b64).expect("b64");
        raw[0] ^= 0x01;
        envelope.ciphertext_b64 = B64.encode(&raw);
        fs::write(&blob_file, serde_json::to_string(&envelope).expect("json")).expect("tamper");
        let dest = vault.with_extension("exported.bin");
        assert!(attachment_export(&key(), &vault, "att-2", &meta.sha256_hex, &dest).is_err());
        let _ = fs::remove_dir_all(vault.parent().expect("parent"));
    }

    #[test]
    fn legacy_aad_blobs_still_decrypt() {
        let vault = sandbox();
        let id = "att-legacy";
        let bytes = b"legacy-attachment";
        let (nonce, ciphertext) =
            seal_raw(bytes, &key(), &legacy_attachment_aad(id)).expect("seal");
        let blob = AttachmentBlob {
            version: ATTACHMENT_VERSION,
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        };
        let dir = attachments_dir(&vault);
        fs::create_dir_all(&dir).expect("dir");
        fs::write(
            blob_path(&vault, id),
            serde_json::to_string(&blob).expect("json"),
        )
        .expect("write");
        let out = attachment_read(&key(), &vault, id, &sha256_hex(bytes)).expect("read");
        assert_eq!(out.bytes_b64, B64.encode(bytes));
        assert_eq!(out.size_bytes, bytes.len() as u64);
        let _ = fs::remove_dir_all(vault.parent().expect("parent"));
    }

    #[test]
    fn oversize_and_bad_ids_rejected_and_sweep_cleans() {
        let vault = sandbox();
        let big = vault.with_extension("big.bin");
        fs::write(&big, vec![0u8; (MAX_ATTACHMENT_BYTES + 1) as usize]).expect("fixture");
        assert!(attachment_import(&key(), &vault, "att-3", "node-1", &big).is_err());
        assert!(attachment_import(&key(), &vault, "  ", "node-1", &big).is_err());
        let small = vault.with_extension("small.bin");
        fs::write(&small, b"x").expect("fixture");
        for bad in ["", ".", "..", "../escape", "a/b", "a\\b", "a:b", "a b"] {
            assert!(
                attachment_import(&key(), &vault, bad, "node-1", &small).is_err(),
                "id {bad:?} must be rejected"
            );
        }
        let dest = vault.with_extension("reject-export.bin");
        assert!(attachment_export(&key(), &vault, "../escape", "x", &dest).is_err());
        assert!(attachment_read(&key(), &vault, "../escape", "x").is_err());
        attachment_import(&key(), &vault, "keep-1", "node-1", &small).expect("import");
        attachment_import(&key(), &vault, "drop-1", "node-1", &small).expect("import");
        // Commit both imports, then sweep all orphans: only "keep-1" survives.
        assert_eq!(
            attachment_sweep(&vault, &["keep-1".to_string(), "drop-1".to_string()]),
            0
        );
        assert_eq!(
            attachment_sweep(&vault, &["keep-1".to_string()]),
            1
        );
        assert!(blob_path(&vault, "keep-1").exists());
        assert!(!blob_path(&vault, "drop-1").exists());
        let _ = fs::remove_dir_all(vault.parent().expect("parent"));
    }
}
