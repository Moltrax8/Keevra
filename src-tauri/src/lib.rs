mod attachments;
mod brand;
mod package;
mod registry;
mod update_keys;
mod updates;
mod vault;

use std::{path::PathBuf, sync::Mutex, time::{Duration, Instant}};
use tauri::{AppHandle, Manager, State};
use vault::{GraphData, KdfCost, VaultError};
use zeroize::Zeroizing;

/// Backend-side inactivity backstop. The renderer owns the friendly 5-minute
/// timer; this longer limit only catches a throttled/suspended renderer that
/// never runs its own lock, while leaving enough slack for the renderer to
/// flush a draft just before its normal auto-lock (K-14).
const SESSION_IDLE_LIMIT: Duration = Duration::from_secs(15 * 60);

/// Unlocked session. The master key exists only here, zeroized on lock.
struct VaultSession {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    /// Cost the key was derived with; re-used verbatim on every save.
    kdf: KdfCost,
    path: PathBuf,
    last_touch: Instant,
}

struct VaultState(Mutex<Option<VaultSession>>);

/// A panicked command must never leave the session permanently unreachable
/// (or permanently unlockable). Recovering the poisoned guard keeps
/// `vault_lock` fail-closed instead of turning a panic into a stuck session.
fn lock_session<'a>(
    state: &'a State<'_, VaultState>,
) -> std::sync::MutexGuard<'a, Option<VaultSession>> {
    match state.0.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(serde::Serialize)]
struct VaultStatus {
    unlocked: bool,
    path: Option<String>,
}

/// True when a session has been idle past the backstop limit. Kept as a helper
/// so the expiry policy is testable without a live Tauri app (K-14).
fn idle_expired(last_touch: Instant) -> bool {
    last_touch.elapsed() >= SESSION_IDLE_LIMIT
}

fn session_path(
    state: &State<VaultState>,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 16], KdfCost, PathBuf), VaultError> {
    let mut guard = lock_session(state);
    let expired = guard
        .as_ref()
        .is_some_and(|session| idle_expired(session.last_touch));
    if expired {
        *guard = None;
        return Err(VaultError::Io("vault_locked".to_string()));
    }
    match guard.as_mut() {
        Some(session) => {
            session.last_touch = Instant::now();
            Ok((
                session.key.clone(),
                session.salt,
                session.kdf,
                session.path.clone(),
            ))
        }
        None => Err(VaultError::Io("vault_locked".to_string())),
    }
}

#[tauri::command]
fn vault_status(state: State<VaultState>) -> VaultStatus {
    let mut guard = lock_session(&state);
    if guard
        .as_ref()
        .is_some_and(|session| idle_expired(session.last_touch))
    {
        *guard = None;
    }
    match guard
        .as_ref()
        .map(|session| session.path.to_string_lossy().to_string())
    {
        Some(path) => VaultStatus {
            unlocked: true,
            path: Some(path),
        },
        None => VaultStatus {
            unlocked: false,
            path: None,
        },
    }
}

/// Heartbeat for genuine renderer activity. Polling must not call this; only
/// real pointer/key activity does, so an idle session still expires.
#[tauri::command]
fn vault_touch(state: State<VaultState>) -> Result<(), String> {
    let mut guard = lock_session(&state);
    let expired = guard
        .as_ref()
        .is_some_and(|session| idle_expired(session.last_touch));
    if expired {
        *guard = None;
        return Err(VaultError::Io("vault_locked".to_string()).to_string());
    }
    match guard.as_mut() {
        Some(session) => {
            session.last_touch = Instant::now();
            Ok(())
        }
        None => Err(VaultError::Io("vault_locked".to_string()).to_string()),
    }
}

/// Returns the decrypted document of the current session. The renderer calls
/// this after a reload: `vault_status` alone says "unlocked" but not *what*
/// is open, so the UI must never guess (or fall back to demo data).
#[tauri::command]
fn vault_get_document(state: State<VaultState>) -> Result<GraphData, String> {
    let (key, _, _, path) = session_path(&state).map_err(String::from)?;
    let contents = vault::read_vault_file(&path).map_err(String::from)?;
    vault::open_envelope_with_key(&contents, &key).map_err(String::from)
}

#[tauri::command]
fn vault_list(app: AppHandle) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(registry::read_registry(&registry::registry_path(&dir)))
}

#[derive(serde::Serialize)]
struct CreatedVault {
    graph: GraphData,
    path: String,
}

#[tauri::command]
fn vault_create(
    app: AppHandle,
    state: State<VaultState>,
    name: String,
    password: String,
    hint: Option<String>,
) -> Result<CreatedVault, String> {
    if name.trim().is_empty() {
        return Err(VaultError::Io("invalid_vault_name".to_string()).to_string());
    }
    vault::validate_new_password(&password).map_err(String::from)?;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    std::fs::create_dir_all(registry::vaults_dir(&dir))
        .map_err(|e| VaultError::Io(e.to_string()))
        .map_err(String::from)?;
    let vault_path = registry::vaults_dir(&dir).join(registry::random_vault_filename());
    let guarded_password = Zeroizing::new(password);
    let (graph, salt, key, kdf) =
        vault::create_vault(&vault_path, guarded_password.as_bytes()).map_err(String::from)?;
    let path_string = vault_path.to_string_lossy().to_string();
    registry::remember_vault(
        &registry::registry_path(&dir),
        name.trim(),
        &path_string,
        hint.as_deref(),
    )
    .map_err(String::from)?;
    lock_session(&state).replace(VaultSession {
        key,
        salt,
        kdf,
        path: vault_path,
        last_touch: Instant::now(),
    });
    Ok(CreatedVault {
        graph,
        path: path_string,
    })
}

#[tauri::command]
fn vault_remember(
    app: AppHandle,
    name: String,
    path: String,
    hint: Option<String>,
) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    registry::remember_vault(&registry::registry_path(&dir), &name, &path, hint.as_deref())
        .map_err(String::from)
}

#[tauri::command]
fn vault_forget(app: AppHandle, path: String) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    registry::forget_vault(&registry::registry_path(&dir), &path).map_err(String::from)
}

#[tauri::command]
fn vault_rename(app: AppHandle, path: String, name: String) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    registry::rename_vault(&registry::registry_path(&dir), &path, &name).map_err(String::from)
}

#[tauri::command]
fn app_settings_get(app: AppHandle) -> Result<registry::AppSettings, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(registry::read_settings(&registry::settings_path(&dir)))
}

#[tauri::command]
fn app_settings_set_default(
    app: AppHandle,
    path: Option<String>,
) -> Result<registry::AppSettings, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    let settings = registry::AppSettings {
        default_vault_path: path,
    };
    registry::write_settings(&registry::settings_path(&dir), &settings).map_err(String::from)?;
    Ok(settings)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultDeleteResult {
    /// True only when the vault file, its backup and its blobs were removed.
    files_deleted: bool,
    /// Always true on success; the listing is the one thing delete guarantees.
    listing_removed: bool,
}

/// Destructive, owner-confirmed reset for a forgotten password: removes the
/// vault file, its backup, its attachment blobs, and its registry listing.
/// There is no recovery — local encryption has no backdoor by design.
///
/// Safety rules:
/// - only app-managed `<app_data>/keevra/*.vault` files are ever deleted;
///   externally located vaults only lose their listing;
/// - the path must still look like a real vault envelope;
/// - any IO failure aborts before the listing is removed, so the user can
///   retry instead of being told "deleted" while ciphertext remains on disk.
#[tauri::command]
fn vault_delete_vault(
    app: AppHandle,
    state: State<VaultState>,
    path: String,
) -> Result<VaultDeleteResult, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    let registry_path = registry::registry_path(&dir);
    if !registry::is_registered(&registry_path, &path) {
        return Err(VaultError::Io("vault_not_listed".to_string()).to_string());
    }
    let vault_path = PathBuf::from(&path);

    // Never delete the vault the session currently holds open.
    {
        let guard = lock_session(&state);
        if guard.as_ref().is_some_and(|session| session.path == vault_path) {
            return Err(VaultError::Io("vault_unlocked".to_string()).to_string());
        }
    }

    let mut files_deleted = false;
    if vault_path.exists() {
        if !registry::is_app_managed(&dir, &path) {
            // Externally located vault: keep the file, drop the listing only.
            registry::forget_vault(&registry_path, &path).map_err(String::from)?;
            clear_default_if_matches(&dir, &path)?;
            return Ok(VaultDeleteResult {
                files_deleted: false,
                listing_removed: true,
            });
        }
        if !vault::looks_like_vault(&vault_path) {
            return Err(VaultError::Io("not_a_vault".to_string()).to_string());
        }
        let mut failures: Vec<String> = Vec::new();
        remove_if_exists(&vault_path, &mut failures);
        // Remove every retained generation and the restore rollback copy too;
        // "delete vault" must not leave older encrypted snapshots behind.
        for backup in vault::backup_paths(&vault_path) {
            remove_if_exists(&backup, &mut failures);
        }
        remove_if_exists(&vault::pre_restore_path_for(&vault_path), &mut failures);
        match std::fs::remove_dir_all(attachments::attachments_dir(&vault_path)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "{}: {error}",
                attachments::attachments_dir(&vault_path).display()
            )),
        }
        if !failures.is_empty() {
            return Err(VaultError::Io(format!("delete_failed: {}", failures.join("; "))).to_string());
        }
        files_deleted = true;
    }

    registry::forget_vault(&registry_path, &path).map_err(String::from)?;
    clear_default_if_matches(&dir, &path)?;
    Ok(VaultDeleteResult {
        files_deleted,
        listing_removed: true,
    })
}

fn remove_if_exists(path: &std::path::Path, failures: &mut Vec<String>) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("{}: {error}", path.display())),
    }
}

/// A deleted default stops being the default.
fn clear_default_if_matches(dir: &std::path::Path, path: &str) -> Result<(), String> {
    let settings_path = registry::settings_path(dir);
    let settings = registry::read_settings(&settings_path);
    if settings.default_vault_path.as_deref() == Some(path) {
        let cleared = registry::AppSettings {
            default_vault_path: None,
        };
        registry::write_settings(&settings_path, &cleared).map_err(String::from)?;
    }
    Ok(())
}

#[tauri::command]
fn vault_open(
    state: State<VaultState>,
    path: String,
    password: String,
) -> Result<GraphData, String> {
    let guarded_password = Zeroizing::new(password);
    let vault_path = PathBuf::from(&path);
    let contents = vault::read_vault_file(&vault_path).map_err(String::from)?;
    let (graph, salt, key, kdf) =
        vault::open_graph(&contents, guarded_password.as_bytes()).map_err(String::from)?;
    lock_session(&state).replace(VaultSession {
        key,
        salt,
        kdf,
        path: vault_path,
        last_touch: Instant::now(),
    });
    Ok(graph)
}

#[tauri::command]
fn vault_save(
    state: State<VaultState>,
    graph: GraphData,
    retain_attachment_ids: Vec<String>,
) -> Result<(), String> {
    let (key, salt, kdf, path) = session_path(&state).map_err(String::from)?;
    vault::save_vault(&path, &graph, &key, &salt, kdf).map_err(String::from)?;
    // Best-effort orphan sweep: keep blobs referenced by the new document,
    // the verified backup (restore must never miss blobs), plus any the UI
    // retains for undo/redo history. Sweep failures never fail the save.
    // Backup + current file are decrypted with the session key; failures
    // yield empty lists (retain, don't delete).
    let mut live = attachments::live_attachment_ids(&graph.0);
    for preserved in vault::backup_paths(&path)
        .into_iter()
        .chain(std::iter::once(vault::pre_restore_path_for(&path)))
    {
        live.extend(vault::attachment_ids_in_encrypted_file(&preserved, &key));
    }
    live.extend(retain_attachment_ids);
    let _ = attachments::attachment_sweep(&path, &live);
    Ok(())
}

#[tauri::command]
fn vault_lock(state: State<VaultState>) -> Result<(), String> {
    lock_session(&state).take();
    Ok(())
}

#[tauri::command]
fn vault_restore_backup(
    app: AppHandle,
    state: State<VaultState>,
    path: String,
    password: String,
) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    if !registry::is_registered(&registry::registry_path(&dir), &path) {
        return Err(VaultError::Io("vault_not_listed".to_string()).to_string());
    }
    let vault_path = PathBuf::from(&path);
    {
        let guard = lock_session(&state);
        if guard.as_ref().is_some_and(|session| session.path == vault_path) {
            return Err(VaultError::Io("vault_unlocked".to_string()).to_string());
        }
    }
    let guarded_password = Zeroizing::new(password);
    vault::restore_backup(&vault_path, guarded_password.as_bytes()).map_err(String::from)
}

#[tauri::command]
fn attachment_import(
    state: State<VaultState>,
    attachment_id: String,
    node_id: String,
    source_path: String,
) -> Result<attachments::AttachmentMeta, String> {
    let (key, _, _, path) = session_path(&state).map_err(String::from)?;
    attachments::attachment_import(&key, &path, &attachment_id, &node_id, &PathBuf::from(source_path))
        .map_err(String::from)
}

#[tauri::command]
fn attachment_export(
    state: State<VaultState>,
    attachment_id: String,
    expected_sha256: String,
    dest_path: String,
) -> Result<u64, String> {
    let (key, _, _, path) = session_path(&state).map_err(String::from)?;
    attachments::attachment_export(&key, &path, &attachment_id, &expected_sha256, &PathBuf::from(dest_path))
        .map_err(String::from)
}

#[tauri::command]
fn attachment_read(
    state: State<VaultState>,
    attachment_id: String,
    expected_sha256: String,
) -> Result<attachments::AttachmentPreview, String> {
    let (key, _, _, path) = session_path(&state).map_err(String::from)?;
    attachments::attachment_read(&key, &path, &attachment_id, &expected_sha256).map_err(String::from)
}

#[tauri::command]
fn vault_export_package(state: State<VaultState>, dest_path: String) -> Result<usize, String> {
    let (key, _, _, path) = session_path(&state).map_err(String::from)?;
    package::export_package(&path, &PathBuf::from(dest_path), Some(&key)).map_err(String::from)
}

#[tauri::command]
fn vault_import_package(
    app: AppHandle,
    source_path: String,
    name: String,
) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))
        .map_err(String::from)?;
    std::fs::create_dir_all(registry::vaults_dir(&dir))
        .map_err(|e| VaultError::Io(e.to_string()))
        .map_err(String::from)?;
    let dest = registry::vaults_dir(&dir).join(registry::random_vault_filename());
    package::import_package(&PathBuf::from(&source_path), &dest).map_err(String::from)?;
    let dest_string = dest.to_string_lossy().to_string();
    registry::remember_vault(&registry::registry_path(&dir), &name, &dest_string, None)
        .map_err(String::from)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedManifest {
    version: String,
    asset_names: Vec<String>,
}

/// Verifies a signed manifest without downloading anything.
#[tauri::command]
fn update_verify_manifest(manifest_json: String, manifest_sig: String) -> Result<VerifiedManifest, String> {
    let manifest =
        updates::parse_verified_manifest(&manifest_json, &manifest_sig).map_err(String::from)?;
    Ok(VerifiedManifest {
        version: manifest.version.clone(),
        asset_names: manifest.assets.iter().map(|asset| asset.name.clone()).collect(),
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestDownload {
    bytes: u64,
    version: String,
}

/// Full gate: manifest signature + strictly-newer version + manifest-bound
/// SHA download. Downgrades and unlisted assets are refused.
#[tauri::command]
async fn update_download_manifest_asset(
    installer_url: String,
    manifest_json: String,
    manifest_sig: String,
    current_version: String,
    dest_path: String,
) -> Result<ManifestDownload, String> {
    let (bytes, version) = updates::download_manifest_asset(
        &installer_url,
        &manifest_json,
        &manifest_sig,
        &current_version,
        &PathBuf::from(dest_path),
    )
    .await
    .map_err(String::from)?;
    Ok(ManifestDownload { bytes, version })
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_touch,
            vault_list,
            vault_create,
            vault_remember,
            vault_forget,
            vault_rename,
            vault_delete_vault,
            app_settings_get,
            app_settings_set_default,
            vault_open,
            vault_get_document,
            vault_save,
            vault_lock,
            vault_restore_backup,
            attachment_import,
            attachment_export,
            attachment_read,
            vault_export_package,
            vault_import_package,
            update_verify_manifest,
            update_download_manifest_asset
        ])
        .run(tauri::generate_context!())
        .expect(&format!("error while running {}", brand::APP_NAME));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_backstop_expires_stale_sessions_only() {
        assert!(!idle_expired(Instant::now()));
        assert!(idle_expired(
            Instant::now() - SESSION_IDLE_LIMIT - Duration::from_secs(1)
        ));
        // The backend backstop must outlast the renderer's own auto-lock so a
        // pending draft still has time to flush through the normal path.
        assert!(SESSION_IDLE_LIMIT > Duration::from_secs(5 * 60));
    }
}
