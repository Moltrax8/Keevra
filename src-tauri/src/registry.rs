//! Vault registry (display names for randomly-named vault files).
//!
//! The lock screen shows user-chosen display names ("Personal") while vault
//! files on disk carry random UUID names, so filenames never reveal purpose
//! or owner. The mapping itself lives in `vaults.json` beside the vaults —
//! readable by local file readers by design (it must be, to list vaults
//! without a password); vault *contents* stay encrypted regardless.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::vault::{write_atomic, VaultError};#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub name: String,
    pub path: String,
    /// Optional user-written password hint. Plaintext by design (it must
    /// show before unlock); the UI warns it is visible to anyone on device.
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub modified_ms: Option<u64>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub default_vault_path: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            default_vault_path: None,
        }
    }
}

pub fn settings_path(app_data_dir: &Path) -> PathBuf {
    // Keevra keeps all app data under its own `keevra/` directory.
    app_data_dir.join("keevra").join("settings.json")
}

pub fn read_settings(path: &Path) -> AppSettings {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

pub fn write_settings(path: &Path, settings: &AppSettings) -> Result<(), VaultError> {
    let contents = serde_json::to_string_pretty(settings).map_err(|e| VaultError::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    write_atomic(path, &contents)
}

/// Random vault filename inside `dir`: `<uuid>.vault`.
pub fn random_vault_filename() -> String {
    format!("{}.vault", uuid_simple())
}

fn uuid_simple() -> String {
    // UUIDv4 from the OS RNG without new dependencies (RFC 4122 layout).
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn registry_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("keevra").join("vaults.json")
}

pub fn vaults_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("keevra")
}

pub fn read_registry(registry: &Path) -> Vec<VaultEntry> {
    let entries: Vec<VaultEntry> = std::fs::read_to_string(registry)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default();
    with_metadata(entries)
}

fn write_registry(registry: &Path, entries: &[VaultEntry]) -> Result<(), VaultError> {
    // Persist identity only; file metadata is refreshed on every read.
    let stored: Vec<VaultEntry> = entries
        .iter()
        .map(|entry| VaultEntry {
            name: entry.name.clone(),
            path: entry.path.clone(),
            hint: entry.hint.clone(),
            modified_ms: None,
            size_bytes: None,
        })
        .collect();
    let contents = serde_json::to_string_pretty(&stored).map_err(|e| VaultError::Io(e.to_string()))?;
    if let Some(parent) = registry.parent() {
        std::fs::create_dir_all(parent).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    write_atomic(registry, &contents)
}

/// File metadata for lock-screen display. Missing files keep None fields
/// rather than failing the whole listing.
fn with_metadata(mut entries: Vec<VaultEntry>) -> Vec<VaultEntry> {
    for entry in &mut entries {
        if let Ok(metadata) = std::fs::metadata(&entry.path) {
            entry.size_bytes = Some(metadata.len());
            entry.modified_ms = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64);
        }
    }
    entries
}

/// Records (or renames) a vault. Entries are keyed by path; display names
/// may repeat because the random filenames underneath stay distinct.
pub fn remember_vault(
    registry: &Path,
    name: &str,
    path: &str,
    hint: Option<&str>,
) -> Result<Vec<VaultEntry>, VaultError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(VaultError::Io("invalid_vault_name".to_string()));
    }
    let mut entries = read_registry(registry);
    if let Some(entry) = entries.iter_mut().find(|entry| entry.path == path) {
        entry.name = trimmed.to_string();
        entry.hint = hint
            .map(str::trim)
            .filter(|hint| !hint.is_empty())
            .map(String::from);
    } else {
        entries.push(VaultEntry {
            name: trimmed.to_string(),
            path: path.to_string(),
            hint: hint
                .map(str::trim)
                .filter(|hint| !hint.is_empty())
                .map(String::from),
            modified_ms: None,
            size_bytes: None,
        });
    }
    write_registry(registry, &entries)?;
    Ok(with_metadata(entries))
}

/// Renames the listing for an existing vault path.
pub fn rename_vault(registry: &Path, path: &str, name: &str) -> Result<Vec<VaultEntry>, VaultError> {
    let entries = read_registry(registry);
    if !entries.iter().any(|entry| entry.path == path) {
        return Err(VaultError::Io("vault_not_listed".to_string()));
    }
    let hint = entries
        .iter()
        .find(|entry| entry.path == path)
        .and_then(|entry| entry.hint.clone());
    remember_vault(registry, name, path, None).and_then(|_| {
        // Preserve the existing hint across renames.
        let mut updated = read_registry(registry);
        if let Some(entry) = updated.iter_mut().find(|entry| entry.path == path) {
            entry.hint = hint;
        }
        write_registry(registry, &updated)?;
        Ok(with_metadata(updated))
    })
}

/// True when `path` names a vault the user has registered. Destructive IPC
/// commands (delete, restore) require this so an arbitrary path can never be
/// operated on through the frontend bridge.
pub fn is_registered(registry: &Path, path: &str) -> bool {
    let entries = read_registry(registry);
    if entries.iter().any(|entry| entry.path == path) {
        return true;
    }
    let Ok(candidate) = std::fs::canonicalize(path) else {
        return false;
    };
    entries.iter().any(|entry| {
        std::fs::canonicalize(&entry.path)
            .map(|registered| registered == candidate)
            .unwrap_or(false)
    })
}

/// True only when `path` is a `.vault` file directly inside the app-managed
/// vault directory (after resolving links/junctions). Externally located
/// vaults can be listed and opened, but never deleted through the app: for
/// them only the listing may be removed.
pub fn is_app_managed(app_data_dir: &Path, path: &str) -> bool {
    let Ok(candidate) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(dir) = std::fs::canonicalize(vaults_dir(app_data_dir)) else {
        return false;
    };
    candidate.parent() == Some(dir.as_path())
        && candidate
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("vault"))
}

/// Forgets a listing only; the vault file itself is never touched.
pub fn forget_vault(registry: &Path, path: &str) -> Result<Vec<VaultEntry>, VaultError> {
    let mut entries = read_registry(registry);
    entries.retain(|entry| entry.path != path);
    write_registry(registry, &entries)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox_registry() -> PathBuf {
        sandbox_registry_named("shared")
    }

    fn sandbox_registry_named(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("keevra-reg-{}-{}", std::process::id(), name));
        let _ = std::fs::create_dir_all(&dir);
        dir.push("vaults.json");
        dir
    }

    #[test]
    fn random_filenames_are_unique_vault_files() {
        let first = random_vault_filename();
        let second = random_vault_filename();
        assert!(first.ends_with(".vault") && second.ends_with(".vault"));
        assert_ne!(first, second);
        assert_eq!(first.len(), 32 + ".vault".len());
    }

    #[test]
    fn remember_renames_forget_keeps_file() {
        let registry = sandbox_registry();
        let _ = std::fs::remove_file(&registry);
        assert_eq!(read_registry(&registry), vec![]);
        let entries = remember_vault(&registry, "Personal", "/tmp/abc.vault", None).expect("remember");
        assert_eq!(entries.len(), 1);
        let renamed = remember_vault(&registry, "Personal 2", "/tmp/abc.vault", None).expect("rename");
        assert_eq!(renamed.len(), 1);
        assert_eq!(renamed[0].name, "Personal 2");
        assert!(remember_vault(&registry, "  ", "/tmp/x.vault", None).is_err());
        let after = forget_vault(&registry, "/tmp/abc.vault").expect("forget");
        assert!(after.is_empty());
        let _ = std::fs::remove_file(&registry);
    }

    #[test]
    fn duplicate_names_allowed_files_stay_distinct() {
        let registry = sandbox_registry_named("dupes");
        let _ = std::fs::remove_file(&registry);
        remember_vault(&registry, "Personal", "/tmp/a.vault", None).expect("first");
        // Same display name twice is fine: random filenames stay distinct.
        remember_vault(&registry, "personal", "/tmp/b.vault", None).expect("duplicate allowed");
        let listed = read_registry(&registry);
        assert_eq!(listed.len(), 2);
        assert_ne!(listed[0].path, listed[1].path);
        // Renaming onto an existing name is allowed too.
        rename_vault(&registry, "/tmp/b.vault", "PERSONAL").expect("rename onto duplicate");
        assert!(rename_vault(&registry, "/tmp/missing.vault", "X").is_err());
        let _ = std::fs::remove_file(&registry);
    }

    #[test]
    fn only_direct_children_of_the_vault_dir_are_app_managed() {
        let root = std::env::temp_dir().join(format!("keevra-managed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let managed_dir = vaults_dir(&root);
        std::fs::create_dir_all(&managed_dir).expect("vault dir");
        let managed = managed_dir.join("abc.vault");
        std::fs::write(&managed, b"vault").expect("managed file");
        let outside_dir = root.join("elsewhere");
        std::fs::create_dir_all(&outside_dir).expect("outside dir");
        let outside = outside_dir.join("abc.vault");
        std::fs::write(&outside, b"vault").expect("outside file");
        let not_vault = managed_dir.join("notes.txt");
        std::fs::write(&not_vault, b"text").expect("text file");

        assert!(is_app_managed(&root, &managed.to_string_lossy()));
        assert!(!is_app_managed(&root, &outside.to_string_lossy()));
        assert!(!is_app_managed(&root, &not_vault.to_string_lossy()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_attached_for_existing_files() {
        let dir = std::env::temp_dir().join(format!("keevra-regmeta-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let registry = dir.join("vaults.json");
        let vault_file = dir.join("real.vault");
        std::fs::write(&vault_file, b"data-bytes").expect("fixture");
        let entries = remember_vault(
            &registry,
            "Real",
            &vault_file.to_string_lossy(),
            Some("first pet"),
        )
        .expect("remember");
        assert_eq!(entries[0].size_bytes, Some(10));
        assert_eq!(entries[0].hint.as_deref(), Some("first pet"));
        assert_eq!(entries[0].size_bytes, Some(10));
        assert!(entries[0].modified_ms.is_some());
        // Stored file keeps identity only; metadata refreshes on read.
        let stored: Vec<VaultEntry> =
            serde_json::from_str(&std::fs::read_to_string(&registry).expect("read")).expect("parse");
        assert_eq!(stored[0].size_bytes, None);
        assert_eq!(read_registry(&registry)[0].size_bytes, Some(10));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
