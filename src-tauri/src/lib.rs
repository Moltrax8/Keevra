mod attachments;
mod brand;
mod package;
mod registry;
mod update_keys;
mod updates;
mod vault;

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, State};
use vault::{GraphData, KdfCost, VaultError};
use zeroize::Zeroizing;

/// Backend-side inactivity backstop. The renderer owns the friendly 5-minute
/// timer; this longer limit only catches a throttled/suspended renderer that
/// never runs its own lock, while leaving enough slack for the renderer to
/// flush a draft just before its normal auto-lock (K-14).
const SESSION_IDLE_LIMIT: Duration = Duration::from_secs(15 * 60);

/// How often the backend watchdog checks the session clock. This runs on its
/// own thread so the key is dropped even when a suspended/throttled renderer
/// never sends another IPC call (K-08).
const SESSION_WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// Unlocked session. The master key exists only here, zeroized on lock.
struct VaultSession {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    /// Cost the key was derived with; re-used verbatim on every save.
    kdf: KdfCost,
    path: PathBuf,
    /// Monotonic id for this unlock. Attachment writes capture it together
    /// with the vault path; a write that arrives after a lock/open/switch is
    /// refused before it can touch the wrong vault (K-03).
    generation: u64,
    /// SHA-256 of the vault file when it was opened (and after every save).
    /// A save refuses to overwrite a file that no longer matches it, so an
    /// external writer cannot be silently rolled back (KV-02).
    fingerprint: [u8; 32],
    last_touch: Instant,
}

struct VaultState(Mutex<Option<VaultSession>>);

/// Source of session generations. Starts at 1 so `0` can mean "no session".
static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_session_generation() -> u64 {
    NEXT_SESSION_GENERATION.fetch_add(1, Ordering::SeqCst)
}

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
    generation: Option<u64>,
}

/// True when a session has been idle past the backstop limit. Kept as a helper
/// so the expiry policy is testable without a live Tauri app (K-14).
fn idle_expired(last_touch: Instant) -> bool {
    last_touch.elapsed() >= SESSION_IDLE_LIMIT
}

/// Drops a session that has been idle past the backstop. Returns whether it
/// removed anything; used by commands and by the independent watchdog (K-08).
fn expire_idle_session(session: &mut Option<VaultSession>) -> bool {
    let expired = session
        .as_ref()
        .is_some_and(|current| idle_expired(current.last_touch));
    if expired {
        // Dropping the session zeroizes the key through `Zeroizing`.
        *session = None;
    }
    expired
}

fn session_path(
    state: &State<VaultState>,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 16], KdfCost, PathBuf, u64), VaultError> {
    let mut guard = lock_session(state);
    if expire_idle_session(&mut guard) {
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
                session.generation,
            ))
        }
        None => Err(VaultError::Io("vault_locked".to_string())),
    }
}

/// Session handle captured by a long-running attachment operation. The
/// expected path and generation must still match the live session immediately
/// before the write (K-03); otherwise the command fails without touching disk.
fn guarded_session(
    state: &State<VaultState>,
    expected_path: &str,
    expected_generation: u64,
) -> Result<(Zeroizing<[u8; 32]>, PathBuf), VaultError> {
    let (key, _, _, path, generation) = session_path(state)?;
    verify_session_target(&path, generation, expected_path, expected_generation)?;
    Ok((key, path))
}

/// Refuses work that was prepared for a different vault session. Used by every
/// write command, including `vault_save`, so a document snapshot can never be
/// encrypted into a vault other than the one it came from (KV-04).
fn verify_session_target(
    path: &Path,
    generation: u64,
    expected_path: &str,
    expected_generation: u64,
) -> Result<(), VaultError> {
    if generation != expected_generation || path.to_string_lossy() != expected_path {
        return Err(VaultError::Io("vault_changed".to_string()));
    }
    Ok(())
}

#[tauri::command]
fn vault_status(state: State<VaultState>) -> VaultStatus {
    let mut guard = lock_session(&state);
    expire_idle_session(&mut guard);
    match guard.as_ref() {
        Some(session) => VaultStatus {
            unlocked: true,
            path: Some(session.path.to_string_lossy().to_string()),
            generation: Some(session.generation),
        },
        None => VaultStatus {
            unlocked: false,
            path: None,
            generation: None,
        },
    }
}

/// Heartbeat for genuine renderer activity. Polling must not call this; only
/// real pointer/key activity does, so an idle session still expires.
#[tauri::command]
fn vault_touch(state: State<VaultState>) -> Result<(), String> {
    let mut guard = lock_session(&state);
    if expire_idle_session(&mut guard) {
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
    let (key, _, _, path, _) = session_path(&state).map_err(String::from)?;
    let contents = vault::read_vault_file(&path).map_err(String::from)?;
    let graph = vault::open_envelope_with_key(&contents, &key).map_err(String::from)?;
    // This was a legitimate external update if it still opens with our key:
    // bind the next save to what we just read.
    let fingerprint = vault::fingerprint_bytes(contents.as_bytes());
    let mut guard = lock_session(&state);
    if let Some(session) = guard.as_mut().filter(|session| session.path == path) {
        session.fingerprint = fingerprint;
    }
    Ok(graph)
}

#[tauri::command]
fn vault_list(app: AppHandle) -> Result<Vec<registry::VaultEntry>, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    registry::read_registry_preserving(&registry::registry_path(&dir)).map_err(String::from)
}

#[derive(serde::Serialize)]
struct CreatedVault {
    graph: GraphData,
    path: String,
    generation: u64,
}

#[derive(serde::Serialize)]
struct OpenedVault {
    graph: GraphData,
    generation: u64,
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
    let fingerprint = vault::fingerprint_file(&vault_path).map_err(String::from)?;
    let path_string = vault_path.to_string_lossy().to_string();
    // A failed registry write must not leave an unlisted, unreachable vault on
    // disk (KV-06). Roll back everything this command just created.
    remember_or_rollback(
        &registry::registry_path(&dir),
        name.trim(),
        &vault_path,
        hint.as_deref(),
    )?;
    let generation = next_session_generation();
    lock_session(&state).replace(VaultSession {
        key,
        salt,
        kdf,
        path: vault_path,
        generation,
        fingerprint,
        last_touch: Instant::now(),
    });
    Ok(CreatedVault {
        graph,
        path: path_string,
        generation,
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

/// A session holds `vault_path` when the raw paths match or their identities
/// do (resolved parent + file name). Identity comparison also works when the
/// live file is missing after a partial delete.
fn session_holds_path(session: &VaultSession, vault_path: &Path) -> bool {
    session.path == vault_path
        || registry::path_identity(&session.path).as_deref() == Some(vault_path)
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

    // Managed-ness is derived from the path identity (resolved parent + file
    // name), not from the live file existing. A retry after an interrupted
    // delete therefore still cleans the backup and blob side files (K-01).
    let Some(vault_path) = registry::managed_vault_path(&dir, &path) else {
        registry::forget_vault(&registry_path, &path).map_err(String::from)?;
        clear_default_if_matches(&dir, &path)?;
        return Ok(VaultDeleteResult {
            files_deleted: false,
            listing_removed: true,
        });
    };

    // Never delete the vault the session currently holds open.
    {
        let guard = lock_session(&state);
        if guard
            .as_ref()
            .is_some_and(|session| session_holds_path(session, &vault_path))
        {
            return Err(VaultError::Io("vault_unlocked".to_string()).to_string());
        }
    }

    // An existing file must still look like a vault before it is destroyed.
    // A missing live file is fine: an earlier attempt may already have removed
    // it and failed on a backup or blob, and the retry must finish the job.
    if vault_path.exists() && !vault::looks_like_vault(&vault_path) {
        return Err(VaultError::Io("not_a_vault".to_string()).to_string());
    }

    // Idempotent cleanup: attempt every target even when the live file is
    // already gone. The registry listing is dropped only after nothing remains,
    // so the user can retry instead of being told "deleted" with ciphertext
    // still on disk (K-01).
    if let Err(error) = remove_managed_vault_files(&vault_path) {
        return Err(VaultError::Io(error).to_string());
    }

    registry::forget_vault(&registry_path, &path).map_err(String::from)?;
    clear_default_if_matches(&dir, &path)?;
    Ok(VaultDeleteResult {
        files_deleted: true,
        listing_removed: true,
    })
}

/// Removes every on-disk artifact of an app-managed vault: the live file, all
/// retained backup generations, the pre-restore rollback copy and the blob
/// directory. Missing targets are success, so a retry after a partial failure
/// continues instead of stopping at the first absent file (K-01).
fn remove_managed_vault_files(vault_path: &std::path::Path) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();
    remove_if_exists(vault_path, &mut failures);
    // Every retained generation and the restore rollback copy: "delete vault"
    // must not leave older encrypted snapshots behind.
    for backup in vault::backup_paths(vault_path) {
        remove_if_exists(&backup, &mut failures);
    }
    remove_if_exists(&vault::pre_restore_path_for(vault_path), &mut failures);
    let blob_dir = attachments::attachments_dir(vault_path);
    remove_blob_dir(&blob_dir, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("delete_failed: {}", failures.join("; ")))
    }
}

/// Removes the blob directory without ever traversing a link/junction: a
/// reparse point is unlinked itself, so a hostile or accidental link cannot
/// make "delete vault" erase a directory outside the managed vault root.
fn remove_blob_dir(blob_dir: &Path, failures: &mut Vec<String>) {
    match std::fs::symlink_metadata(blob_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if let Err(error) = std::fs::remove_dir(blob_dir)
                .or_else(|_| std::fs::remove_file(blob_dir))
            {
                if error.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("{}: {error}", blob_dir.display()));
                }
            }
        }
        Ok(_) => {
            if let Err(error) = std::fs::remove_dir_all(blob_dir) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("{}: {error}", blob_dir.display()));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("{}: {error}", blob_dir.display())),
    }
}

fn remove_if_exists(path: &std::path::Path, failures: &mut Vec<String>) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("{}: {error}", path.display())),
    }
}

/// Writes the registry entry for a vault this command just created, and removes
/// the vault (plus its blobs/backups) if that write fails. Without this, a full
/// disk or a corrupt/unwritable `vaults.json` leaves an encrypted file the UI
/// never shows and the user cannot open (KV-06).
fn remember_or_rollback(
    registry: &Path,
    name: &str,
    vault_path: &Path,
    hint: Option<&str>,
) -> Result<Vec<registry::VaultEntry>, String> {
    let path_string = vault_path.to_string_lossy().to_string();
    registry::remember_vault(registry, name, &path_string, hint).map_err(|error| {
        let _ = remove_managed_vault_files(vault_path);
        error.to_string()
    })
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
) -> Result<OpenedVault, String> {
    let guarded_password = Zeroizing::new(password);
    let vault_path = PathBuf::from(&path);
    let contents = vault::read_vault_file(&vault_path).map_err(String::from)?;
    let (graph, salt, key, kdf) =
        vault::open_graph(&contents, guarded_password.as_bytes()).map_err(String::from)?;
    let fingerprint = vault::fingerprint_bytes(contents.as_bytes());
    let generation = next_session_generation();
    lock_session(&state).replace(VaultSession {
        key,
        salt,
        kdf,
        path: vault_path,
        generation,
        fingerprint,
        last_touch: Instant::now(),
    });
    Ok(OpenedVault { graph, generation })
}

#[tauri::command]
fn vault_save(
    state: State<VaultState>,
    graph: GraphData,
    retain_attachment_ids: Vec<String>,
    expected_path: String,
    expected_generation: u64,
) -> Result<(), String> {
    // The session identity and the external-change fingerprint are validated
    // while the session lock is held, and the file write happens in the same
    // critical section. A snapshot prepared for vault A can therefore never be
    // encrypted into vault B (KV-04), and an external writer that changed the
    // file after open is refused instead of overwritten (KV-02).
    let (key, path) = {
        let mut guard = lock_session(&state);
        if expire_idle_session(&mut guard) {
            return Err(VaultError::Io("vault_locked".to_string()).to_string());
        }
        let Some(session) = guard.as_mut() else {
            return Err(VaultError::Io("vault_locked".to_string()).to_string());
        };
        verify_session_target(
            &session.path,
            session.generation,
            &expected_path,
            expected_generation,
        )
        .map_err(String::from)?;
        session.last_touch = Instant::now();
        let fingerprint = vault::save_vault_checked(
            &session.path,
            &graph,
            &session.key,
            &session.salt,
            session.kdf,
            &session.fingerprint,
        )
        .map_err(String::from)?;
        session.fingerprint = fingerprint;
        (session.key.clone(), session.path.clone())
    };
    // Best-effort orphan sweep: keep blobs referenced by the new document,
    // the verified backup (restore must never miss blobs), plus any the UI
    // retains for undo/redo history. Sweep failures never fail the save.
    //
    // If a backup exists but cannot be opened with the session key, the sweep
    // is skipped entirely: deleting now could remove a blob that only that
    // backup references, so the safe direction is to keep every blob (K-04).
    let mut live = attachments::live_attachment_ids(&graph.0);
    let mut preserved_verified = true;
    for preserved in vault::backup_paths(&path)
        .into_iter()
        .chain(std::iter::once(vault::pre_restore_path_for(&path)))
    {
        match vault::attachment_ids_in_encrypted_file(&preserved, &key) {
            Ok(Some(ids)) => live.extend(ids),
            // The file does not exist: nothing to preserve from it.
            Ok(None) => {}
            Err(_) => {
                preserved_verified = false;
                break;
            }
        }
    }
    if preserved_verified {
        live.extend(retain_attachment_ids);
        let _ = attachments::attachment_sweep(&path, &live);
    }
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
    let vault_identity = registry::path_identity(&vault_path).unwrap_or_else(|| vault_path.clone());
    {
        let guard = lock_session(&state);
        if guard
            .as_ref()
            .is_some_and(|session| session.path == vault_identity || registry::path_identity(&session.path).as_deref() == Some(vault_identity.as_path()))
        {
            return Err(VaultError::Io("vault_unlocked".to_string()).to_string());
        }
    }
    let guarded_password = Zeroizing::new(password);
    vault::restore_backup(&vault_path, guarded_password.as_bytes()).map_err(String::from)
}

/// Validates a user-chosen export path against Keevra-owned state before any
/// plaintext or package bytes are written (KV-01). Registered vaults are read
/// best-effort: a corrupt registry must not block an otherwise safe export,
/// while the known registry/settings files and app vault directory are always
/// protected.
fn guarded_export_destination(
    app: &AppHandle,
    state: &State<VaultState>,
    dest: &str,
) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))
        .map_err(String::from)?;
    let registry_path = registry::registry_path(&dir);
    let mut protected = vec![registry_path.clone(), registry::settings_path(&dir)];
    if let Ok((_, _, _, path, _)) = session_path(state) {
        protected.push(path);
    }
    if let Ok(entries) = registry::read_registry(&registry_path) {
        protected.extend(entries.into_iter().map(|entry| PathBuf::from(entry.path)));
    }
    let protected_dirs = vec![registry::vaults_dir(&dir)];
    let dest_path = PathBuf::from(dest);
    vault::ensure_export_destination(&dest_path, &protected, &protected_dirs)
        .map_err(String::from)?;
    Ok(dest_path)
}

/// Where a downloaded installer is staged before it is launched.
///
/// The path is fully derived here: a single `.exe` file name taken from the
/// installer URL (validated by `updates::installer_file_name`) inside
/// `<app data>/updates`. The frontend never supplies a path, so a verified
/// download cannot be redirected onto a vault, backup, blob or registry file.
fn update_staging_destination(app: &AppHandle, installer_url: &str) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| VaultError::Io(e.to_string()))
        .map_err(String::from)?;
    let name = updates::installer_file_name(installer_url).map_err(String::from)?;
    let staging = updates::staging_dir(&dir);
    std::fs::create_dir_all(&staging).map_err(|e| VaultError::Io(e.to_string()).to_string())?;
    Ok(staging.join(name))
}

/// Opens the verified installer with the shell, so Windows shows the setup
/// wizard and any required elevation prompt.
#[cfg(windows)]
fn launch_installer(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both strings are NUL-terminated and outlive the call; no other
    // pointers are dereferenced.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute returns a value greater than 32 on success.
    if (result as isize) <= 32 {
        return Err(VaultError::Io("update_launch_failed".to_string()).to_string());
    }
    Ok(())
}

#[cfg(not(windows))]
fn launch_installer(_path: &Path) -> Result<(), String> {
    Err(VaultError::Io("update_launch_failed".to_string()).to_string())
}

#[tauri::command]
fn attachment_import(
    state: State<VaultState>,
    attachment_id: String,
    node_id: String,
    source_path: String,
    expected_path: String,
    expected_generation: u64,
) -> Result<attachments::AttachmentMeta, String> {
    let (key, path) =
        guarded_session(&state, &expected_path, expected_generation).map_err(String::from)?;
    attachments::attachment_import(&key, &path, &attachment_id, &node_id, &PathBuf::from(source_path))
        .map_err(String::from)
}

#[tauri::command]
fn attachment_export(
    app: AppHandle,
    state: State<VaultState>,
    attachment_id: String,
    expected_sha256: String,
    dest_path: String,
    expected_path: String,
    expected_generation: u64,
) -> Result<u64, String> {
    let (key, path) =
        guarded_session(&state, &expected_path, expected_generation).map_err(String::from)?;
    let dest = guarded_export_destination(&app, &state, &dest_path)?;
    attachments::attachment_export(&key, &path, &attachment_id, &expected_sha256, &dest)
        .map_err(String::from)
}

#[tauri::command]
fn attachment_read(
    state: State<VaultState>,
    attachment_id: String,
    expected_sha256: String,
) -> Result<attachments::AttachmentPreview, String> {
    let (key, _, _, path, _) = session_path(&state).map_err(String::from)?;
    attachments::attachment_read(&key, &path, &attachment_id, &expected_sha256).map_err(String::from)
}

#[tauri::command]
fn vault_export_package(
    app: AppHandle,
    state: State<VaultState>,
    dest_path: String,
) -> Result<usize, String> {
    let dest = guarded_export_destination(&app, &state, &dest_path)?;
    let (key, _, _, path, _) = session_path(&state).map_err(String::from)?;
    package::export_package(&path, &dest, Some(&key)).map_err(String::from)
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
    // Reap abandoned staging files from an earlier crash before creating new
    // ones (N-02). Age-gated so a concurrent import is never touched.
    let _ = package::cleanup_stale_imports(
        &registry::vaults_dir(&dir),
        package::STALE_IMPORT_AGE,
    );
    let dest = registry::vaults_dir(&dir).join(registry::random_vault_filename());
    package::import_package(&PathBuf::from(&source_path), &dest).map_err(String::from)?;
    // A failed registry write removes the freshly imported vault and its
    // attachment directory instead of leaving unreachable ciphertext behind
    // (KV-06).
    remember_or_rollback(&registry::registry_path(&dir), &name, &dest, None)
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
struct SignedManifest {
    manifest_json: String,
    manifest_sig: String,
}

/// Fetches `updates.json` + `updates.json.minisig` through Rust.
///
/// The WebView cannot fetch GitHub release assets itself: they are served
/// without `Access-Control-Allow-Origin`, so the browser blocks the response
/// before any signature check can run. This keeps the GitHub-only HTTPS
/// allow-list and the byte caps in one place (`updates::fetch_signed_manifest`).
#[tauri::command]
async fn update_fetch_signed_manifest(
    manifest_url: String,
    sig_url: String,
) -> Result<SignedManifest, String> {
    let (manifest_json, manifest_sig) = updates::fetch_signed_manifest(&manifest_url, &sig_url)
        .await
        .map_err(String::from)?;
    Ok(SignedManifest {
        manifest_json,
        manifest_sig,
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestInstall {
    bytes: u64,
    version: String,
    file_name: String,
}

/// Full gate: manifest signature + strictly-newer version + manifest-bound
/// SHA download, staged inside the app's update directory. The verified setup
/// file is then opened in the Windows wizard. The frontend flushes and saves
/// the vault, then calls `update_restart` so the installer can replace the
/// running executable. Downgrades and unlisted assets are refused before
/// anything is written or launched.
#[tauri::command]
async fn update_download_and_launch(
    app: AppHandle,
    installer_url: String,
    manifest_json: String,
    manifest_sig: String,
    current_version: String,
) -> Result<ManifestInstall, String> {
    let dest = update_staging_destination(&app, &installer_url)?;
    let (bytes, version) = updates::download_manifest_asset(
        &installer_url,
        &manifest_json,
        &manifest_sig,
        &current_version,
        &dest,
    )
    .await
    .map_err(String::from)?;
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();

    if let Err(error) = launch_installer(&dest) {
        // Never leave an unlaunched setup file behind.
        let _ = std::fs::remove_file(&dest);
        return Err(error);
    }

    Ok(ManifestInstall {
        bytes,
        version,
        file_name,
    })
}

/// Closes Keevra so the setup wizard that is already open can replace it.
#[tauri::command]
fn update_restart(app: AppHandle) {
    app.exit(0);
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState(Mutex::new(None)))
        // Independent backend watchdog: the renderer's 5-minute timer is the
        // friendly path, but a suspended or compromised renderer must not keep
        // the master key alive past the 15-minute backstop (K-08).
        .setup(|app| {
            // Reap staging files left by an import that was interrupted by a
            // crash or power loss. Ciphertext never stays behind indefinitely
            // in the managed vault root (N-02).
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = package::cleanup_stale_imports(
                    &registry::vaults_dir(&dir),
                    package::STALE_IMPORT_AGE,
                );
                // Remove the setup file a previous update left behind: the
                // installer cannot delete its own running file, so the newly
                // installed app does it on the first start.
                updates::cleanup_staged_installers(&updates::staging_dir(&dir));
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(SESSION_WATCHDOG_INTERVAL);
                if let Some(state) = handle.try_state::<VaultState>() {
                    let mut guard = lock_session(&state);
                    expire_idle_session(&mut guard);
                }
            });
            Ok(())
        })
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
            update_fetch_signed_manifest,
            update_download_and_launch,
            update_restart
        ])
        .run(tauri::generate_context!())
        .expect(&format!("error while running {}", brand::APP_NAME));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keevra-lib-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        dir
    }

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

    #[test]
    fn watchdog_drops_idle_session_and_keeps_fresh_one() {
        let session = |last_touch| VaultSession {
            key: Zeroizing::new([7u8; 32]),
            salt: [0u8; 16],
            kdf: KdfCost::default(),
            path: PathBuf::from("test.vault"),
            generation: 1,
            fingerprint: [0u8; 32],
            last_touch,
        };

        let mut fresh = Some(session(Instant::now()));
        assert!(!expire_idle_session(&mut fresh));
        assert!(fresh.is_some());

        let mut stale = Some(session(
            Instant::now() - SESSION_IDLE_LIMIT - Duration::from_secs(1),
        ));
        assert!(expire_idle_session(&mut stale));
        assert!(stale.is_none());

        let mut empty: Option<VaultSession> = None;
        assert!(!expire_idle_session(&mut empty));
    }

    /// K-01: a delete that already removed the live file (and failed on a
    /// backup or blob) must finish the remaining targets on retry instead of
    /// reporting success with ciphertext still on disk.
    #[test]
    fn managed_delete_removes_leftovers_after_partial_failure() {
        let dir = unique_dir("delete");
        let vault_path = dir.join("v.vault");
        std::fs::write(&vault_path, b"live").expect("live");
        for backup in vault::backup_paths(&vault_path) {
            std::fs::write(&backup, b"backup").expect("backup");
        }
        std::fs::write(vault::pre_restore_path_for(&vault_path), b"rollback")
            .expect("pre-restore");
        let blob_dir = attachments::attachments_dir(&vault_path);
        std::fs::create_dir_all(&blob_dir).expect("blob dir");
        std::fs::write(blob_dir.join("a.bin"), b"blob").expect("blob");

        // Simulate the partial earlier attempt: the live file is already gone.
        std::fs::remove_file(&vault_path).expect("remove live");

        remove_managed_vault_files(&vault_path).expect("first cleanup");
        assert!(!vault_path.exists());
        for backup in vault::backup_paths(&vault_path) {
            assert!(!backup.exists(), "backup left behind: {}", backup.display());
        }
        assert!(!vault::pre_restore_path_for(&vault_path).exists());
        assert!(!blob_dir.exists());

        // A user retry must be idempotent, not an error.
        remove_managed_vault_files(&vault_path).expect("second cleanup");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KV-04: a save prepared for one session generation/path must be refused
    /// before it can touch another vault.
    #[test]
    fn save_target_requires_the_same_path_and_generation() {
        let path = PathBuf::from("A.vault");
        assert!(verify_session_target(&path, 7, "A.vault", 7).is_ok());
        assert!(matches!(
            verify_session_target(&path, 7, "B.vault", 7),
            Err(VaultError::Io(ref message)) if message == "vault_changed"
        ));
        assert!(matches!(
            verify_session_target(&path, 7, "A.vault", 8),
            Err(VaultError::Io(ref message)) if message == "vault_changed"
        ));
    }

    /// KV-01: the updater derives its own file name inside a dedicated
    /// directory, so a verified download cannot be pointed at a vault, backup
    /// or blob, and only an `.exe` installer can be staged and launched.
    #[test]
    fn update_staging_paths_stay_inside_the_update_directory() {
        let staging =
            PathBuf::from("C:\\Users\\me\\AppData\\Roaming\\com.keevra.desktop\\updates");
        let name = updates::installer_file_name(
            "https://github.com/Moltrax8/Keevra/releases/download/v1/Keevra_1_x64-setup.exe",
        )
        .expect("installer name");
        assert_eq!(staging.join(name), staging.join("Keevra_1_x64-setup.exe"));
        for rejected in [
            "https://github.com/Moltrax8/Keevra/releases/download/v1/updates.json",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/setup.bat",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/..%2Fvault.vault.exe",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/..%5C..%5Cvault.exe",
        ] {
            assert!(
                updates::installer_file_name(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    /// KV-06: when the registry cannot be written, the just-created vault and
    /// its attachment directory are removed instead of being left unreachable.
    #[test]
    fn registry_failure_rolls_back_created_vault() {
        let dir = unique_dir("registry-rollback");
        let vault_path = dir.join("new.vault");
        std::fs::write(&vault_path, b"ciphertext").expect("vault");
        let blobs = attachments::attachments_dir(&vault_path);
        std::fs::create_dir_all(&blobs).expect("blobs");
        std::fs::write(blobs.join("a.bin"), b"blob").expect("blob");

        // A directory at `vaults.json` makes every registry write fail.
        let registry = dir.join("vaults.json");
        std::fs::create_dir(&registry).expect("registry blocker");

        let error = remember_or_rollback(&registry, "New", &vault_path, None)
            .expect_err("registry write must fail");
        assert!(!error.is_empty());
        assert!(!vault_path.exists(), "vault left behind");
        assert!(!blobs.exists(), "blob directory left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
