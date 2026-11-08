//! Encrypted local vault (Stage 7).
//!
//! Design authority: `docs/THREAT_MODEL.md`. Envelope v1: Argon2id
//! password KDF plus XChaCha20-Poly1305 over canonical graph JSON, with the
//! file header bound as associated data. The master key lives only here in
//! Rust inside a zeroized session buffer; the frontend never holds keys.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use zeroize::Zeroizing;

pub const VAULT_VERSION: u32 = 1;
/// Hard ceiling for a vault envelope file. A legitimate vault with a few
/// thousand accounts stays far below this; a hostile or corrupt file is
/// rejected before it is read into memory.
pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
/// Newest first: `.bak`, `.bak.1`, `.bak.2` — verified previous generations.
const BACKUP_GENERATIONS: usize = 3;
/// New-vault password floor, enforced here as well as in the UI.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const KDF_MEMORY_KIB: u32 = 65536;
pub const KDF_ITERATIONS: u32 = 3;
pub const KDF_PARALLELISM: u32 = 1;
// DoS bounds for stored parameters honored on open. A hostile vault can set
// these, so the ceiling is a real computation budget, not just a sanity check:
// 256 MiB with 6 passes and 4 lanes is already several seconds of Argon2id on
// a normal desktop, while the defaults (64 MiB / 3 / 1) stay far below it.
// Older vaults above the ceiling are refused with the generic
// wrong-password-or-corrupt error instead of freezing the unlock path (K-05).
const KDF_MAX_MEMORY_KIB: u32 = 256 * 1024;
const KDF_MAX_ITERATIONS: u32 = 6;
const KDF_MAX_PARALLELISM: u32 = 4;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Coarse failures only: wrong passwords and corrupt files are deliberately
/// indistinguishable to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    WrongPasswordOrCorrupt,
    UnsupportedVersion(u32),
    AlreadyExists,
    NotFound,
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::WrongPasswordOrCorrupt => write!(f, "wrong_password_or_corrupt"),
            VaultError::UnsupportedVersion(v) => write!(f, "unsupported_version:{v}"),
            VaultError::AlreadyExists => write!(f, "vault_already_exists"),
            VaultError::NotFound => write!(f, "vault_not_found"),
            VaultError::Io(e) => write!(f, "io_error:{e}"),
        }
    }
}

impl From<VaultError> for String {
    fn from(error: VaultError) -> String {
        error.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    alg: String,
    m: u32,
    t: u32,
    p: u32,
    salt_b64: String,
}

/// Argon2id cost stored alongside a vault. Saving must reuse the exact cost
/// the session key was derived with: the key also encrypts attachments, so
/// silently switching to newer defaults would break every existing blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfCost {
    fn default() -> Self {
        KdfCost {
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
        }
    }
}

impl KdfCost {
    fn from_params(params: &KdfParams) -> Self {
        KdfCost {
            memory_kib: params.m,
            iterations: params.t,
            parallelism: params.p,
        }
    }

    fn to_params(self, salt: &[u8; SALT_LEN]) -> KdfParams {
        KdfParams {
            alg: "argon2id".to_string(),
            m: self.memory_kib,
            t: self.iterations,
            p: self.parallelism,
            salt_b64: B64.encode(salt),
        }
    }
}

/// Serializes vault-file replacement so a backup copy can never interleave
/// with another save's rename. Attachment/registry writes use unique temp
/// names instead and do not take this lock.
static VAULT_WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultHeader {
    version: u32,
    kdf: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultEnvelope {
    version: u32,
    kdf: KdfParams,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// Opaque vault payload: the frontend owns the document shape, so Rust
/// round-trips it untouched. That keeps older and newer documents openable
/// with one binary — only the identity structure of id-bearing collections is
/// checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GraphData(pub serde_json::Map<String, serde_json::Value>);

impl GraphData {
    pub fn empty() -> Self {
        GraphData(serde_json::Map::new())
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }
}

fn string_id(value: &serde_json::Value) -> Option<&str> {
    value.get("id")?.as_str()
}

/// Collections that carry IDs. Current schema first, plus older ID collections
/// so older vaults still validate on save.
const ID_COLLECTIONS: [(&str, &str); 4] = [
    ("accounts", "account"),
    ("presets", "preset"),
    ("nodes", "node"),
    ("relationships", "relationship"),
];

/// Light structural validation: every entry of every present ID collection
/// carries a non-empty unique string ID. Domain semantics stay in TypeScript.
pub fn validate_graph(graph: &GraphData) -> Result<(), VaultError> {
    for (key, label) in ID_COLLECTIONS {
        // Missing or non-array values are the frontend's business; only
        // arrays that are present get their IDs checked.
        let Some(items) = graph.get(key).and_then(|value| value.as_array()) else {
            continue;
        };
        let mut seen = std::collections::HashSet::new();
        for item in items {
            match string_id(item) {
                Some(id) if !id.trim().is_empty() => {
                    if !seen.insert(id) {
                        return Err(VaultError::Io(format!("duplicate_{label}_id")));
                    }
                }
                _ => return Err(VaultError::Io(format!("invalid_{label}_id"))),
            }
        }
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    derive_key_with(password, salt, KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM)
        .expect("fixed KDF parameters are valid")
}

fn derive_key_with(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    if memory_kib == 0
        || memory_kib > KDF_MAX_MEMORY_KIB
        || iterations == 0
        || iterations > KDF_MAX_ITERATIONS
        || parallelism == 0
        || parallelism > KDF_MAX_PARALLELISM
    {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    Ok(key)
}

fn aad_bytes(header: &VaultHeader) -> Vec<u8> {
    serde_json::to_vec(header).expect("header serializes")
}

/// Raw AEAD seal shared by the vault envelope and attachment blobs.
pub fn seal_raw(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    associated_data: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let nonce = random_bytes::<NONCE_LEN>();
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VaultError::Io(e.to_string()))?;
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(XNonce::from_slice(&nonce), associated_data, &mut buffer)
        .map_err(|_| VaultError::Io("encrypt_failed".to_string()))?;
    Ok((nonce, buffer))
}

/// Raw AEAD open. Authentication failure maps to WrongPasswordOrCorrupt so
/// tampering and wrong keys stay indistinguishable.
pub fn open_raw(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    associated_data: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VaultError::Io(e.to_string()))?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce), associated_data, &mut buffer)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    Ok(buffer)
}

/// Maximum base64 length accepted for a ciphertext field, checked *before*
/// decoding so a hostile envelope cannot force a huge allocation.
const MAX_VAULT_B64_LEN: usize = ((MAX_VAULT_BYTES as usize + 2) / 3) * 4;

/// Structural validation shared by open, restore, delete and package import.
/// No password/KDF work happens here: only the envelope shape and its bounds.
fn validate_envelope_shape(envelope: &VaultEnvelope) -> Result<(), VaultError> {
    if envelope.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(envelope.version));
    }
    if envelope.kdf.alg != "argon2id"
        || envelope.kdf.m == 0
        || envelope.kdf.m > KDF_MAX_MEMORY_KIB
        || envelope.kdf.t == 0
        || envelope.kdf.t > KDF_MAX_ITERATIONS
        || envelope.kdf.p == 0
        || envelope.kdf.p > KDF_MAX_PARALLELISM
    {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    let salt = B64
        .decode(&envelope.kdf.salt_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    let nonce = B64
        .decode(&envelope.nonce_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    if envelope.ciphertext_b64.is_empty() || envelope.ciphertext_b64.len() > MAX_VAULT_B64_LEN {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
    Ok(())
}

/// Value-based variant used by package import before anything is written.
pub fn validate_envelope_value(value: &serde_json::Value) -> Result<(), VaultError> {
    let envelope: VaultEnvelope =
        serde_json::from_value(value.clone()).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_envelope_shape(&envelope)
}

/// Bounded file read. The metadata check rejects the common case cheaply and
/// `take(limit + 1)` still protects against a file that grows after the check.
pub(crate) fn read_limited(path: &Path, limit: u64, too_large: &str) -> Result<Vec<u8>, VaultError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(error.to_string())
        }
    })?;
    if metadata.len() > limit {
        return Err(VaultError::Io(too_large.to_string()));
    }
    let file = fs::File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(error.to_string())
        }
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| VaultError::Io(error.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(VaultError::Io(too_large.to_string()));
    }
    Ok(bytes)
}

pub struct SealedVault {
    pub envelope_json: String,
}

/// Encrypt graph JSON under a fresh nonce. The header (version + KDF params)
/// is bound as associated data so it cannot be swapped unnoticed.
pub fn seal_graph(
    graph: &GraphData,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
) -> Result<SealedVault, VaultError> {
    let header = VaultHeader {
        version: VAULT_VERSION,
        kdf: cost.to_params(salt),
    };
    let plaintext = serde_json::to_vec(graph).map_err(|e| VaultError::Io(e.to_string()))?;
    let (nonce_bytes, buffer) = seal_raw(&plaintext, key, &aad_bytes(&header))?;
    let envelope = VaultEnvelope {
        version: header.version,
        kdf: header.kdf,
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(&buffer),
    };
    serde_json::to_string_pretty(&envelope)
        .map(|envelope_json| SealedVault { envelope_json })
        .map_err(|e| VaultError::Io(e.to_string()))
}

pub fn open_graph(
    envelope_json: &str,
    password: &[u8],
) -> Result<
    (
        GraphData,
        [u8; SALT_LEN],
        Zeroizing<[u8; KEY_LEN]>,
        KdfCost,
    ),
    VaultError,
> {
    let envelope: VaultEnvelope =
        serde_json::from_str(envelope_json).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    // Shape and bounds first: an unsupported version, absurd KDF cost or
    // oversized ciphertext must fail before any expensive work or allocation.
    validate_envelope_shape(&envelope)?;
    // Honor the stored parameters (bounded above): old vaults keep opening
    // with their original cost, new vaults are sealed with current defaults.
    let salt_vec = B64
        .decode(&envelope.kdf.salt_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let salt: [u8; SALT_LEN] = salt_vec
        .try_into()
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let cost = KdfCost::from_params(&envelope.kdf);
    let key = derive_key_with(
        password,
        &salt,
        cost.memory_kib,
        cost.iterations,
        cost.parallelism,
    )?;
    let nonce_vec = B64
        .decode(&envelope.nonce_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let ciphertext = B64
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let header = VaultHeader {
        version: envelope.version,
        kdf: envelope.kdf,
    };
    let plaintext = open_raw(&ciphertext, &key, &nonce, &aad_bytes(&header))?;
    let graph: GraphData =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_graph(&graph).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    Ok((graph, salt, key, cost))
}

/// Opens an already-sealed envelope with the session key, without running the
/// password KDF. Used to verify a new envelope before it replaces the live
/// vault, and to inspect the previous good backup.
pub fn open_envelope_with_key(
    envelope_json: &str,
    key: &[u8; KEY_LEN],
) -> Result<GraphData, VaultError> {
    let envelope: VaultEnvelope =
        serde_json::from_str(envelope_json).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_envelope_shape(&envelope)?;
    let nonce_vec = B64
        .decode(&envelope.nonce_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let ciphertext = B64
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let header = VaultHeader {
        version: envelope.version,
        kdf: envelope.kdf,
    };
    let plaintext = open_raw(&ciphertext, key, &nonce, &aad_bytes(&header))?;
    let graph: GraphData =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    validate_graph(&graph)?;
    Ok(graph)
}

/// Backend guard for new vaults; the lock screen also checks this so users get
/// immediate feedback, but IPC callers cannot bypass it.
pub fn validate_new_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::Io("weak_password".to_string()));
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(".bak");
    PathBuf::from(backup)
}

/// `.bak` is generation 0; `.bak.1` and `.bak.2` are older verified snapshots.
fn backup_path_generation(path: &Path, generation: usize) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(".bak");
    if generation > 0 {
        backup.push(format!(".{generation}"));
    }
    PathBuf::from(backup)
}

/// Every retained previous generation, newest first. Used by the orphan sweep
/// so a blob referenced only by an older backup is never deleted.
pub fn backup_paths(path: &Path) -> Vec<PathBuf> {
    (0..BACKUP_GENERATIONS)
        .map(|generation| backup_path_generation(path, generation))
        .collect()
}

/// Recover the write lock even after a panic (poisoned mutex) so a failed
/// command cannot make every later save/restore unreachable.
pub(crate) fn vault_write_guard() -> MutexGuard<'static, ()> {
    VAULT_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How long a save waits for another Keevra process to release the vault file
/// before reporting `vault_conflict`.
const VAULT_LOCK_WAIT: Duration = Duration::from_secs(2);

/// Opens the live vault with an OS-level writer lock held until the returned
/// handle is dropped (KV-02).
///
/// The process-wide mutex only serializes threads in one process. A second
/// Keevra process could otherwise read the same fingerprint, pass the check and
/// overwrite the first process's save. On Windows the share mode denies other
/// writers while still allowing readers and the final replace-on-rename, so the
/// whole read/compare/rotate/replace sequence is one critical section across
/// processes. Contention is retried briefly and then reported as a conflict,
/// which the caller resolves by reopening the vault.
#[cfg(windows)]
fn lock_vault_for_write(path: &Path) -> Result<fs::File, VaultError> {
    lock_vault_for_write_within(path, VAULT_LOCK_WAIT)
}

#[cfg(windows)]
fn lock_vault_for_write_within(path: &Path, wait: Duration) -> Result<fs::File, VaultError> {
    use std::os::windows::fs::OpenOptionsExt;
    // Share read + delete, deny write: readers keep working and the atomic
    // temp-file rename can replace the file while this handle is still open.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(path)
        {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(VaultError::NotFound);
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                ) =>
            {
                if std::time::Instant::now() >= deadline {
                    return Err(VaultError::Io("vault_conflict".to_string()));
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(error) => return Err(VaultError::Io(error.to_string())),
        }
    }
}

/// Non-Windows fallback: the desktop app targets Windows, and this build has no
/// portable advisory-lock dependency. The in-process guard and fingerprint
/// check still apply.
#[cfg(not(windows))]
fn lock_vault_for_write(path: &Path) -> Result<fs::File, VaultError> {
    fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => VaultError::NotFound,
            _ => VaultError::Io(error.to_string()),
        })
}

/// Rotates the retained backup chain and installs `current` as the new `.bak`.
///
/// The new backup is fully written and synced to a staging path *before* any
/// existing generation moves, so a disk-full or permission failure while
/// writing it can never leave the chain without a usable `.bak` (KV-03). The
/// final rename is the only step after rotation; if it fails, the previous
/// `.bak` is moved back into place.
fn rotate_backups(path: &Path, current: &[u8]) -> Result<(), VaultError> {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".bak.new");
    let staged = PathBuf::from(staged);
    if let Err(error) = write_atomic_bytes(&staged, current) {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    if let Err(error) = commit_backup_rotation(path, &staged) {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    Ok(())
}

/// Moves the staged backup into the chain. Older generations shift first so
/// `.bak` -> `.bak.1` never clobbers an unrotated `.bak.1`. If installing the
/// staged file fails, the just-moved `.bak` is restored so recovery still works.
fn commit_backup_rotation(path: &Path, staged: &Path) -> Result<(), VaultError> {
    let newest = backup_path(path);
    let had_newest = newest.exists();
    for generation in (0..BACKUP_GENERATIONS - 1).rev() {
        let newer = backup_path_generation(path, generation);
        let older = backup_path_generation(path, generation + 1);
        if newer.exists() {
            fs::rename(&newer, &older).map_err(|error| VaultError::Io(error.to_string()))?;
        }
    }
    if let Err(error) = fs::rename(staged, &newest) {
        if had_newest {
            // The previous newest now lives at `.bak.1`; put it back so the
            // user can still restore even though this save failed.
            let _ = fs::rename(backup_path_generation(path, 1), &newest);
        }
        return Err(VaultError::Io(error.to_string()));
    }
    Ok(())
}

/// Copy of the live vault kept when a backup is restored, so a restore of the
/// wrong file (or a later change of mind) never destroys the current vault.
fn pre_restore_path(path: &Path) -> PathBuf {
    let mut recovery = path.as_os_str().to_owned();
    recovery.push(".pre-restore");
    PathBuf::from(recovery)
}

/// Atomic durable write: temp file in the same directory, flush, rename.
/// Windows has no portable directory fsync; the replace-on-rename is the
/// crash-safe step and the file contents are synced before it.
pub fn write_atomic(path: &Path, contents: &str) -> Result<(), VaultError> {
    write_atomic_bytes(path, contents.as_bytes())
}

/// Binary variant of [`write_atomic`] for attachment exports.
pub fn write_atomic_bytes(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        fs::create_dir_all(dir).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    // A unique suffix keeps concurrent writers (auto-save vs. attachment
    // import vs. registry update) from sharing and truncating one temp file.
    let unique = u64::from_le_bytes(random_bytes::<8>());
    let mut temp_path = path.as_os_str().to_owned();
    temp_path.push(format!(".{unique:016x}.tmp"));
    let temp_path = PathBuf::from(temp_path);
    fs::write(&temp_path, contents).map_err(|e| VaultError::Io(e.to_string()))?;
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&temp_path)
        .map_err(|e| VaultError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| VaultError::Io(e.to_string()))?;
    drop(file);
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(VaultError::Io(error.to_string()));
    }
    Ok(())
}

pub fn read_vault_file(path: &Path) -> Result<String, VaultError> {
    let bytes = read_limited(path, MAX_VAULT_BYTES, "vault_too_large")?;
    String::from_utf8(bytes).map_err(|_| VaultError::WrongPasswordOrCorrupt)
}

/// Create a new vault. Refuses to overwrite an existing file.
pub fn create_vault(
    path: &Path,
    password: &[u8],
) -> Result<
    (
        GraphData,
        [u8; SALT_LEN],
        Zeroizing<[u8; KEY_LEN]>,
        KdfCost,
    ),
    VaultError,
> {
    let _guard = vault_write_guard();
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let salt = random_bytes::<SALT_LEN>();
    let key = derive_key(password, &salt);
    let cost = KdfCost::default();
    let graph = GraphData::empty();
    let sealed = seal_graph(&graph, &key, &salt, cost)?;
    write_atomic(path, &sealed.envelope_json)?;
    Ok((graph, salt, key, cost))
}

/// SHA-256 of raw file bytes. Used to bind a save to the exact file contents
/// the session opened, which catches an external writer (another process or a
/// manual restore) that changed the vault after it was unlocked (KV-02).
pub fn fingerprint_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Fingerprint of a vault file on disk.
pub fn fingerprint_file(path: &Path) -> Result<[u8; 32], VaultError> {
    let bytes = read_limited(path, MAX_VAULT_BYTES, "vault_too_large")?;
    Ok(fingerprint_bytes(&bytes))
}

/// Save under an existing session key. Keeps the previous good vault as
/// `.bak` (written only after the new vault verifies by re-parsing).
///
/// `cost` must be the cost the session key was derived with, not the current
/// defaults; see [`KdfCost`].
#[cfg(test)]
pub fn save_vault(
    path: &Path,
    graph: &GraphData,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
) -> Result<(), VaultError> {
    save_vault_inner(path, graph, key, salt, cost, None).map(|_| ())
}

/// Save that refuses to overwrite a file whose contents no longer match the
/// fingerprint captured when the session opened (KV-02). Returns the new
/// fingerprint so the caller can bind the next save to the file it just wrote.
pub fn save_vault_checked(
    path: &Path,
    graph: &GraphData,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
    expected: &[u8; 32],
) -> Result<[u8; 32], VaultError> {
    save_vault_inner(path, graph, key, salt, cost, Some(*expected))
}

fn save_vault_inner(
    path: &Path,
    graph: &GraphData,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
    expected: Option<[u8; 32]>,
) -> Result<[u8; 32], VaultError> {
    let _guard = vault_write_guard();
    validate_graph(graph)?;
    let sealed = seal_graph(graph, key, salt, cost)?;
    // Actually decrypt and re-parse the new envelope with the session key
    // before replacing the old file; a bad seal must never reach disk.
    let _verified = open_envelope_with_key(&sealed.envelope_json, key)?;
    // Cross-process critical section. The handle is held through the
    // fingerprint comparison, backup rotation and replace below, so another
    // Keevra process cannot slip a different version in between (KV-02).
    let _file_lock = match lock_vault_for_write(path) {
        Ok(file) => Some(file),
        Err(VaultError::NotFound) if expected.is_some() => {
            // The file vanished after the session opened. Never recreate it
            // from a stale in-memory snapshot.
            return Err(VaultError::Io("vault_conflict".to_string()));
        }
        Err(VaultError::NotFound) => None,
        Err(error) => return Err(error),
    };
    if path.exists() {
        let current = read_limited(path, MAX_VAULT_BYTES, "vault_too_large")?;
        if let Some(expected) = expected {
            if fingerprint_bytes(&current) != expected {
                return Err(VaultError::Io("vault_conflict".to_string()));
            }
        }
        // Preserve the previous vault only after proving it still opens, and
        // rotate older generations so one bad copy cannot erase the last good
        // backup. A current file that no longer verifies leaves the existing
        // backup chain untouched.
        let verifies = std::str::from_utf8(&current)
            .ok()
            .is_some_and(|text| open_envelope_with_key(text, key).is_ok());
        if verifies {
            rotate_backups(path, &current)?;
        } else if expected.is_some() {
            // Same fingerprint as at open time but no longer decryptable:
            // fail closed instead of overwriting evidence of a corrupt file.
            return Err(VaultError::Io("vault_conflict".to_string()));
        }
    }
    write_atomic(path, &sealed.envelope_json)?;
    Ok(fingerprint_bytes(sealed.envelope_json.as_bytes()))
}

/// Structural (non-decrypting) check that a file looks like a Keevra vault
/// envelope. Destructive commands use this so an arbitrary text file that was
/// registered by mistake can never be treated as a vault.
pub fn looks_like_vault(path: &Path) -> bool {
    let Ok(bytes) = read_limited(path, MAX_VAULT_BYTES, "vault_too_large") else {
        return false;
    };
    let Ok(contents) = String::from_utf8(bytes) else {
        return false;
    };
    let Ok(envelope) = serde_json::from_str::<VaultEnvelope>(&contents) else {
        return false;
    };
    validate_envelope_shape(&envelope).is_ok()
}

/// Explicit, never automatic, restore of the previous good vault.
///
/// The backup is opened with the user's password first: full AEAD
/// authentication and schema validation must succeed before the live file is
/// touched. The current vault is preserved as `<path>.pre-restore`.
pub fn restore_backup(path: &Path, password: &[u8]) -> Result<(), VaultError> {
    let _guard = vault_write_guard();
    // Hold the same writer lock as a save so a restore cannot interleave with
    // another process copying the file or rotating backups (KV-02/KV-03).
    let _file_lock = match lock_vault_for_write(path) {
        Ok(file) => Some(file),
        Err(VaultError::NotFound) => None,
        Err(error) => return Err(error),
    };
    // Try newest first and accept the first generation that verifies with the
    // supplied password. If a rotation failed after `.bak` moved aside, the
    // previous good vault may live at `.bak.1` or `.bak.2`; recovery must still
    // find it (KV-03).
    let mut found_any = false;
    let mut verified: Option<String> = None;
    for backup in backup_paths(path) {
        if !backup.exists() {
            continue;
        }
        found_any = true;
        let Ok(bytes) = read_limited(&backup, MAX_VAULT_BYTES, "vault_too_large") else {
            continue;
        };
        // Byte-preserving parse: `from_utf8_lossy` would silently rewrite a
        // corrupted backup into something "valid" looking instead of rejecting it.
        let Ok(contents) = String::from_utf8(bytes) else {
            continue;
        };
        // Wrong password, tampered ciphertext, swapped header and an
        // unsupported schema all fail here, before the live file changes.
        if open_graph(&contents, password).is_ok() {
            verified = Some(contents);
            break;
        }
    }
    let Some(contents) = verified else {
        return Err(if found_any {
            VaultError::WrongPasswordOrCorrupt
        } else {
            VaultError::NotFound
        });
    };
    if path.exists() {
        let current = read_limited(path, MAX_VAULT_BYTES, "vault_too_large")?;
        write_atomic_bytes(&pre_restore_path(path), &current)?;
    }
    write_atomic(path, &contents)?;
    Ok(())
}

/// Current-vault copy kept by a verified restore; its blobs must survive the
/// save-time orphan sweep so the rollback remains usable.
pub fn pre_restore_path_for(path: &Path) -> PathBuf {
    pre_restore_path(path)
}

/// Rejects export/download targets that would overwrite Keevra-owned state
/// (KV-01).
///
/// `protected_files` are files the caller knows about (the open vault and every
/// registered vault, plus the registry and settings files). Backup
/// generations, restore copies and attachment directories are derived from
/// each vault here, so a caller cannot forget one. `protected_dirs` are whole
/// app-owned directories; no export may land inside them.
///
/// The target is also refused when *any* path component is named like a Keevra
/// artifact, so writing inside an attachment or backup directory fails even
/// when the leaf name is harmless. Equality is checked against canonical
/// identities (and, for a target that does not exist yet, its canonical parent
/// + file name) to defeat `..`, case and symlink aliases on Windows.
pub fn ensure_export_destination(
    dest: &Path,
    protected_files: &[PathBuf],
    protected_dirs: &[PathBuf],
) -> Result<(), VaultError> {
    // Any component named like a Keevra artifact is refused, not just the final
    // file name: a blob or backup directory can be reached by writing *inside*
    // a path whose leaf looks harmless.
    let reserved_component = dest.components().any(|component| match component {
        std::path::Component::Normal(name) => match name.to_str() {
            Some(text) => is_reserved_artifact_name(text),
            // A non-Unicode name cannot be checked; fail closed.
            None => true,
        },
        _ => false,
    });
    if reserved_component
        || protected_files
            .iter()
            .any(|protected| paths_match(dest, protected))
    {
        return Err(VaultError::Io("protected_destination".to_string()));
    }

    let mut dirs: Vec<PathBuf> = protected_dirs.to_vec();
    for vault in protected_files {
        let mut staging = vault.as_os_str().to_owned();
        staging.push(".bak.new");
        if paths_match(dest, &pre_restore_path(vault))
            || paths_match(dest, &PathBuf::from(staging))
            || backup_paths(vault)
                .iter()
                .any(|backup| paths_match(dest, backup))
        {
            return Err(VaultError::Io("protected_destination".to_string()));
        }
        let blobs = crate::attachments::attachments_dir(vault);
        if paths_match(dest, &blobs) {
            return Err(VaultError::Io("protected_destination".to_string()));
        }
        dirs.push(blobs);
    }
    if dirs.iter().any(|dir| path_within(dest, dir)) {
        return Err(VaultError::Io("protected_destination".to_string()));
    }
    Ok(())
}

/// Names that are always Keevra-owned regardless of which directory they are
/// in: any vault envelope (`.vault`), its sidecars (`.vault.bak*`,
/// `.vault.pre-restore`, `.vault.attachments`) and the registry/settings files
/// (including the `.corrupt-*` preserved copies).
fn is_reserved_artifact_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "vaults.json"
        || lower.starts_with("vaults.json.")
        || lower == "settings.json"
        || lower.starts_with("settings.json.")
    {
        return true;
    }
    lower.ends_with(".vault") || lower.contains(".vault.")
}

/// Every path spelling that can identify `path`: as given, canonicalized, and
/// canonical-parent + file name (which also works when the file is missing).
fn comparison_forms(path: &Path) -> Vec<PathBuf> {
    let mut forms = vec![path.to_path_buf()];
    if let Ok(canonical) = fs::canonicalize(path) {
        forms.push(canonical);
    }
    if let (Some(name), Some(parent)) = (
        path.file_name(),
        path.parent().filter(|parent| !parent.as_os_str().is_empty()),
    ) {
        if let Ok(parent) = fs::canonicalize(parent) {
            forms.push(parent.join(name));
        }
    }
    forms
}

fn paths_match(left: &Path, right: &Path) -> bool {
    let right_forms = comparison_forms(right);
    comparison_forms(left)
        .iter()
        .any(|left| right_forms.iter().any(|right| same_path(left, right)))
}

fn path_within(candidate: &Path, root: &Path) -> bool {
    let candidate = path_text(candidate);
    let root = path_text(root);
    let root = root.trim_end_matches(std::path::MAIN_SEPARATOR);
    candidate == root
        || candidate.starts_with(&format!("{root}{}", std::path::MAIN_SEPARATOR))
}

fn path_text(path: &Path) -> String {
    let text = path
        .to_string_lossy()
        .replace(['/', '\\'], std::path::MAIN_SEPARATOR_STR);
    #[cfg(windows)]
    {
        text.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        text
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    path_text(left) == path_text(right)
}

/// Attachment IDs referenced by an encrypted vault file on disk, decrypted
/// with the session key.
///
/// `Ok(None)` means the file does not exist. An existing file that cannot be
/// read, decrypted or parsed is an error: callers must fail closed and keep
/// every blob rather than assume the backup is empty (K-04).
pub fn attachment_ids_in_encrypted_file(
    path: &Path,
    key: &[u8; KEY_LEN],
) -> Result<Option<Vec<String>>, VaultError> {
    if !path.exists() {
        return Ok(None);
    }
    let envelope_json = read_vault_file(path)?;
    let graph = open_envelope_with_key(&envelope_json, key)?;
    Ok(Some(crate::attachments::live_attachment_ids(&graph.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "keevra-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::create_dir_all(&dir);
        dir.push("vault.vault");
        dir
    }

    /// Build a vault document from literal JSON (what the frontend sends).
    fn doc(value: serde_json::Value) -> GraphData {
        serde_json::from_value(value).expect("vault document")
    }

    #[test]
    fn roundtrip_create_open_save() {
        let path = unique_path("roundtrip");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let password = b"correct horse battery staple";
        let (graph, salt, key, cost) = create_vault(&path, password).expect("create");
        assert!(graph.0.is_empty());
        let (opened, salt2, _, cost2) = open_graph(
            &read_vault_file(&path).expect("read"),
            password,
        )
        .expect("open");
        assert_eq!(salt, salt2);
        assert_eq!(cost, cost2);
        assert!(opened.0.is_empty());
        let graph2 = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "a", "name": "A", "service": "Mail", "tags": [], "fields": []}],
            "presets": [],
            "attachments": [],
        }));
        save_vault(&path, &graph2, &key, &salt, cost).expect("save");
        assert!(backup_path(&path).exists());
        // The backup is a real, decryptable vault, not just a copied blob.
        let (backup_graph, _, _, _) = open_graph(
            &read_vault_file(&backup_path(&path)).expect("read backup"),
            password,
        )
        .expect("backup opens");
        assert!(backup_graph.get("accounts").is_none());
        // The new file also decrypts with the session key without a password.
        let verified = open_envelope_with_key(
            &read_vault_file(&path).expect("read"),
            &key,
        )
        .expect("new envelope verifies");
        assert_eq!(
            verified.get("accounts").and_then(|value| value.as_array()).map(Vec::len),
            Some(1)
        );
        let (reopened, _, _, _) = open_graph(&read_vault_file(&path).expect("read"), password)
            .expect("reopen");
        assert_eq!(
            reopened.get("accounts").and_then(|value| value.as_array()).map(Vec::len),
            Some(1)
        );
        assert_eq!(reopened.get("schemaVersion"), Some(&serde_json::json!(3)));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn older_document_still_opens_and_saves() {
        let path = unique_path("legacy-doc");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let (_, salt, key, cost) = create_vault(&path, b"pw").expect("create");
        let legacy = doc(serde_json::json!({
            "schemaVersion": 2,
            "nodes": [{"id": "n1", "name": "Old"}],
            "relationships": [{"id": "r1"}],
            "layout": {"n1": {"x": 1, "y": 2}},
            "templates": [],
        }));
        save_vault(&path, &legacy, &key, &salt, cost).expect("legacy save");
        let (reopened, _, _, _) = open_graph(&read_vault_file(&path).expect("read"), b"pw")
            .expect("reopen");
        assert_eq!(reopened.get("nodes"), legacy.get("nodes"));
        assert_eq!(reopened.get("layout"), legacy.get("layout"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn wrong_password_fails_without_oracle() {
        let path = unique_path("wrongpw");
        let _ = fs::remove_file(&path);
        create_vault(&path, b"right-password").expect("create");
        let contents = read_vault_file(&path).expect("read");
        let err = open_graph(&contents, b"wrong-password").expect_err("must fail");
        assert_eq!(err, VaultError::WrongPasswordOrCorrupt);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_and_header_fail() {
        let path = unique_path("tamper");
        let _ = fs::remove_file(&path);
        create_vault(&path, b"password-1").expect("create");
        let contents = read_vault_file(&path).expect("read");
        let mut envelope: VaultEnvelope = serde_json::from_str(&contents).expect("parse");
        let mut raw = B64.decode(&envelope.ciphertext_b64).expect("b64");
        raw[0] ^= 0x01;
        envelope.ciphertext_b64 = B64.encode(&raw);
        let tampered = serde_json::to_string(&envelope).expect("json");
        assert_eq!(
            open_graph(&tampered, b"password-1").expect_err("tamper must fail"),
            VaultError::WrongPasswordOrCorrupt
        );
        // Header swap is bound as associated data: flipping KDF iterations
        // must also fail authentication.
        let mut envelope2: VaultEnvelope = serde_json::from_str(&contents).expect("parse");
        envelope2.kdf.t += 1;
        let swapped = serde_json::to_string(&envelope2).expect("json");
        assert_eq!(
            open_graph(&swapped, b"password-1").expect_err("header swap must fail"),
            VaultError::WrongPasswordOrCorrupt
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn legacy_kdf_parameters_still_open() {
        // Vaults sealed under the original cost (m=19456, t=2, p=1) must
        // keep opening after defaults are raised: parameters are honored,
        // not assumed.
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key_with(b"legacy-password", &salt, 19456, 2, 1).expect("legacy params valid");
        let graph = doc(serde_json::json!({
            "nodes": [{"id": "a", "name": "A"}],
            "relationships": [],
            "layout": {},
        }));
        let header = VaultHeader {
            version: VAULT_VERSION,
            kdf: KdfParams {
                alg: "argon2id".to_string(),
                m: 19456,
                t: 2,
                p: 1,
                salt_b64: B64.encode(salt),
            },
        };
        let plaintext = serde_json::to_vec(&graph).expect("json");
        let (nonce, ciphertext) = seal_raw(&plaintext, &key, &aad_bytes(&header)).expect("seal");
        let envelope = VaultEnvelope {
            version: header.version,
            kdf: header.kdf,
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(&ciphertext),
        };
        let (opened, salt2, key2, cost2) = open_graph(
            &serde_json::to_string(&envelope).expect("json"),
            b"legacy-password",
        )
        .expect("legacy vault opens");
        assert_eq!(opened.get("nodes").and_then(|v| v.as_array()).map(Vec::len), Some(1));
        assert_eq!(salt, salt2);
        assert_eq!(
            cost2,
            KdfCost {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            }
        );
        // Saving must keep the legacy cost the session key was derived with.
        let path = unique_path("legacy-kdf-save");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        write_atomic(
            &path,
            &serde_json::to_string(&VaultEnvelope {
                version: VAULT_VERSION,
                kdf: KdfParams {
                    alg: "argon2id".to_string(),
                    m: cost2.memory_kib,
                    t: cost2.iterations,
                    p: cost2.parallelism,
                    salt_b64: B64.encode(salt2),
                },
                nonce_b64: B64.encode(nonce),
                ciphertext_b64: B64.encode(&ciphertext),
            })
            .expect("json"),
        )
        .expect("seed legacy vault");
        save_vault(&path, &opened, &key2, &salt2, cost2).expect("legacy save");
        let stored: VaultEnvelope =
            serde_json::from_str(&read_vault_file(&path).expect("read")).expect("parse");
        assert_eq!(stored.kdf.m, 19456);
        assert_eq!(stored.kdf.t, 2);
        assert_eq!(stored.kdf.p, 1);
        open_graph(&read_vault_file(&path).expect("read"), b"legacy-password")
            .expect("legacy vault still opens after save");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        assert!(derive_key_with(b"legacy-password", &salt, 0, 2, 1).is_err());
        assert!(derive_key_with(b"legacy-password", &salt, 19456, 99, 1).is_err());
    }

    #[test]
    fn new_password_policy_is_enforced_in_the_backend() {
        assert_eq!(
            validate_new_password("short"),
            Err(VaultError::Io("weak_password".to_string()))
        );
        assert_eq!(
            validate_new_password("12345678901"),
            Err(VaultError::Io("weak_password".to_string()))
        );
        assert!(validate_new_password("123456789012").is_ok());
        assert!(validate_new_password("şifre-şifre-şifre").is_ok());
    }

    #[test]
    fn restore_rejects_wrong_password_and_corrupt_backup() {
        let path = unique_path("restore-reject");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let password = b"correct horse battery";
        let (_, salt, key, cost) = create_vault(&path, password).expect("create");
        let first = doc(serde_json::json!({"accounts": []}));
        save_vault(&path, &first, &key, &salt, cost).expect("save");
        let live_before = fs::read(&path).expect("live");

        assert_eq!(
            restore_backup(&path, b"wrong password").expect_err("wrong password"),
            VaultError::WrongPasswordOrCorrupt
        );
        assert_eq!(fs::read(&path).expect("live"), live_before);

        // A truncated/corrupt backup must never reach the live path.
        fs::write(backup_path(&path), b"{not a vault").expect("corrupt backup");
        assert!(restore_backup(&path, password).is_err());
        assert_eq!(fs::read(&path).expect("live"), live_before);

        // Non-UTF8 bytes are rejected instead of being lossy-converted.
        fs::write(backup_path(&path), [0xff, 0xfe, 0x00]).expect("binary backup");
        assert_eq!(
            restore_backup(&path, password).expect_err("non-utf8"),
            VaultError::WrongPasswordOrCorrupt
        );
        assert_eq!(fs::read(&path).expect("live"), live_before);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let _ = fs::remove_file(pre_restore_path(&path));
    }

    #[test]
    fn verified_restore_restores_backup_and_keeps_current_copy() {
        let path = unique_path("restore-ok");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let _ = fs::remove_file(pre_restore_path(&path));
        let password = b"correct horse battery";
        let (_, salt, key, cost) = create_vault(&path, password).expect("create");
        let first = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "a", "name": "A", "service": "", "tags": [], "fields": []}],
        }));
        save_vault(&path, &first, &key, &salt, cost).expect("save first");
        let second = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "b", "name": "B", "service": "", "tags": [], "fields": []}],
        }));
        save_vault(&path, &second, &key, &salt, cost).expect("save second");
        let live_before = fs::read(&path).expect("live");
        let backup_before = fs::read(backup_path(&path)).expect("backup");
        assert!(looks_like_vault(&path));
        assert!(looks_like_vault(&backup_path(&path)));

        restore_backup(&path, password).expect("verified restore");

        // The live file is byte-identical to the verified backup...
        assert_eq!(fs::read(&path).expect("live"), backup_before);
        // ...the previous vault is preserved for a manual roll-back...
        assert_eq!(fs::read(pre_restore_path(&path)).expect("recovery copy"), live_before);
        // ...and the restored document is the first one.
        let (restored, _, _, _) = open_graph(&read_vault_file(&path).expect("read"), password)
            .expect("restored vault opens");
        assert_eq!(
            restored.get("accounts").and_then(|value| value.as_array()).map(Vec::len),
            Some(1)
        );
        assert_eq!(
            restored
                .get("accounts")
                .and_then(|value| value.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("id")),
            Some(&serde_json::json!("a"))
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let _ = fs::remove_file(pre_restore_path(&path));
    }

    #[test]
    fn looks_like_vault_rejects_plain_files() {
        let path = unique_path("shape-check");
        let _ = fs::remove_file(&path);
        fs::write(&path, b"just a text file").expect("plain file");
        assert!(!looks_like_vault(&path));
        assert!(!looks_like_vault(&path.join("missing.vault")));
        fs::remove_file(&path).expect("remove plain file");
        let (_, _, _, _) = create_vault(&path, b"correct horse battery").expect("create");
        assert!(looks_like_vault(&path));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn refuses_to_overwrite_on_create_and_bad_graph_on_save() {
        let path = unique_path("refuse");
        let _ = fs::remove_file(&path);
        let (_, salt, key, cost) = create_vault(&path, b"pw").expect("create");
        assert_eq!(
            create_vault(&path, b"pw").expect_err("overwrite refused"),
            VaultError::AlreadyExists
        );
        let bad = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"name": "no-id"}],
            "presets": [],
        }));
        assert_eq!(
            save_vault(&path, &bad, &key, &salt, cost).expect_err("id-less account rejected"),
            VaultError::Io("invalid_account_id".to_string())
        );
        let duplicate = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "a"}, {"id": "a"}],
            "presets": [],
        }));
        assert_eq!(
            save_vault(&path, &duplicate, &key, &salt, cost).expect_err("duplicate rejected"),
            VaultError::Io("duplicate_account_id".to_string())
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn limited_reads_reject_files_over_the_cap() {
        let path = unique_path("limited-read");
        let _ = fs::remove_file(&path);
        fs::write(&path, vec![b'a'; 32]).expect("fixture");
        assert_eq!(
            read_limited(&path, 32, "vault_too_large")
                .expect("at the cap")
                .len(),
            32
        );
        let error = read_limited(&path, 31, "vault_too_large").expect_err("over the cap");
        assert!(
            matches!(error, VaultError::Io(ref message) if message == "vault_too_large"),
            "unexpected error: {error:?}"
        );
        assert_eq!(read_limited(&path, 64, "vault_too_large").expect("under").len(), 32);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn envelope_validation_rejects_placeholders_and_oversize_ciphertext() {
        // A placeholder package envelope must not pass structural validation.
        assert!(validate_envelope_value(&serde_json::json!({"version": 1})).is_err());
        let envelope = serde_json::json!({
            "version": VAULT_VERSION,
            "kdf": {
                "alg": "argon2id",
                "m": KDF_MEMORY_KIB,
                "t": KDF_ITERATIONS,
                "p": KDF_PARALLELISM,
                "salt_b64": B64.encode([0u8; SALT_LEN]),
            },
            "nonce_b64": B64.encode([0u8; NONCE_LEN]),
            "ciphertext_b64": "A".repeat(MAX_VAULT_B64_LEN + 1),
        });
        assert!(validate_envelope_value(&envelope).is_err());
    }

    #[test]
    fn backups_rotate_three_verified_generations() {
        let path = unique_path("backup-rotation");
        let _ = fs::remove_file(&path);
        for generation in 0..BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_path_generation(&path, generation));
        }
        // The created (empty) vault counts as the first live document.
        let (_, salt, key, cost) = create_vault(&path, b"correct horse battery").expect("create");
        for index in 0..4 {
            let graph = doc(serde_json::json!({
                "schemaVersion": 3,
                "accounts": [{
                    "id": format!("a{index}"),
                    "name": format!("Account {index}"),
                    "service": "",
                    "tags": [],
                    "fields": [],
                }],
            }));
            save_vault(&path, &graph, &key, &salt, cost).expect("save");
        }

        let generations = backup_paths(&path);
        assert_eq!(generations.len(), 3);
        // After four saves: live = a3, .bak = a2, .bak.1 = a1, .bak.2 = a0.
        for (expected_id, generation_path) in ["a2", "a1", "a0"].iter().zip(&generations) {
            let (graph, _, _, _) = open_graph(
                &read_vault_file(generation_path).expect("read generation"),
                b"correct horse battery",
            )
            .expect("generation opens");
            assert_eq!(
                graph
                    .get("accounts")
                    .and_then(|value| value.as_array())
                    .and_then(|items| items.first())
                    .and_then(|item| item.get("id")),
                Some(&serde_json::json!(expected_id)),
                "generation {generation_path:?}"
            );
        }
        let (live, _, _, _) =
            open_graph(&read_vault_file(&path).expect("read live"), b"correct horse battery")
                .expect("live opens");
        assert_eq!(
            live.get("accounts")
                .and_then(|value| value.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("id")),
            Some(&serde_json::json!("a3"))
        );

        for generation in &generations {
            let _ = fs::remove_file(generation);
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn attachment_ids_from_backup_distinguish_missing_and_corrupt() {
        let path = unique_path("attachment-ids");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
        let (_, salt, key, cost) = create_vault(&path, b"correct horse battery").expect("create");
        let graph = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [],
            "presets": [],
            "attachments": [{
                "id": "att-1",
                "nodeId": "a",
                "fileName": "x.txt",
                "mimeType": "text/plain",
                "sizeBytes": 1,
                "sha256Hex": "00",
                "createdAtMs": 0,
            }],
        }));
        save_vault(&path, &graph, &key, &salt, cost).expect("save");

        // A readable file returns its live IDs (K-04).
        assert_eq!(
            attachment_ids_in_encrypted_file(&path, &key).expect("readable"),
            Some(vec!["att-1".to_string()])
        );

        // Absent backups are fine: nothing to preserve.
        let missing = path.with_extension("missing.vault");
        assert_eq!(
            attachment_ids_in_encrypted_file(&missing, &key).expect("missing is ok"),
            None
        );

        // Existing but corrupt/foreign files must be an error, never an empty
        // list, so the caller can fail closed (K-04).
        let corrupt = path.with_extension("corrupt.vault");
        fs::write(&corrupt, b"not a vault").expect("corrupt fixture");
        assert!(attachment_ids_in_encrypted_file(&corrupt, &key).is_err());

        let other = path.with_extension("other.vault");
        let _ = fs::remove_file(&other);
        let (_, _, _, _) = create_vault(&other, b"another password").expect("other vault");
        assert!(attachment_ids_in_encrypted_file(&other, &key).is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&corrupt);
        let _ = fs::remove_file(&other);
        let _ = fs::remove_file(backup_path(&path));
        let _ = fs::remove_file(backup_path(&other));
    }

    #[test]
    fn stored_kdf_cost_above_budget_is_rejected() {
        let salt = [1u8; SALT_LEN];
        // The defaults must stay valid.
        assert!(derive_key_with(
            b"pw",
            &salt,
            KDF_MEMORY_KIB,
            KDF_ITERATIONS,
            KDF_PARALLELISM
        )
        .is_ok());
        // Anything above the accepted computation budget is refused before
        // Argon2 allocates memory (K-05).
        assert!(derive_key_with(
            b"pw",
            &salt,
            KDF_MAX_MEMORY_KIB + 1,
            KDF_ITERATIONS,
            KDF_PARALLELISM
        )
        .is_err());
        assert!(derive_key_with(
            b"pw",
            &salt,
            KDF_MEMORY_KIB,
            KDF_MAX_ITERATIONS + 1,
            KDF_PARALLELISM
        )
        .is_err());
        assert!(derive_key_with(
            b"pw",
            &salt,
            KDF_MEMORY_KIB,
            KDF_ITERATIONS,
            KDF_MAX_PARALLELISM + 1
        )
        .is_err());

        let oversized = serde_json::json!({
            "version": VAULT_VERSION,
            "kdf": {
                "alg": "argon2id",
                "m": KDF_MAX_MEMORY_KIB + 1,
                "t": KDF_ITERATIONS,
                "p": KDF_PARALLELISM,
                "salt_b64": B64.encode([0u8; SALT_LEN]),
            },
            "nonce_b64": B64.encode([0u8; NONCE_LEN]),
            "ciphertext_b64": B64.encode([1u8; 32]),
        });
        assert!(validate_envelope_value(&oversized).is_err());
    }

    /// KV-01: exports may not land on a vault, its backups/restore/attachment
    /// artifacts, the registry/settings files, or anywhere in an app-owned dir.
    #[test]
    fn export_destination_guard_rejects_keevra_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "keevra-test-{}-export-guard",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let vault = dir.join("personal.vault");
        fs::write(&vault, b"ciphertext").expect("vault");
        let protected = vec![vault.clone()];
        let app_dir = dir.join("keevra");
        let dirs = vec![app_dir.clone()];
        let blobs = crate::attachments::attachments_dir(&vault);
        let mut backup_staging = vault.as_os_str().to_owned();
        backup_staging.push(".bak.new");
        let backup_staging = PathBuf::from(backup_staging);

        for target in [
            vault.clone(),
            backup_path(&vault),
            backup_path_generation(&vault, 1),
            backup_path_generation(&vault, 2),
            backup_staging,
            pre_restore_path(&vault),
            blobs.clone(),
            blobs.join("x.bin"),
            dir.join("x.vault.attachments").join("y.bin"),
            dir.join("nested").join("x.vault.bak").join("y.bin"),
            dir.join("vaults.json"),
            dir.join("settings.json"),
            dir.join("other.vault"),
        ] {
            assert!(
                ensure_export_destination(&target, &protected, &dirs).is_err(),
                "protected target accepted: {}",
                target.display()
            );
        }

        // A plain export file beside the vault stays allowed.
        let dest = dir.join("export.vtpkg.json");
        ensure_export_destination(&dest, &protected, &dirs).expect("safe export");
        // Anything inside the app-owned directory is refused even when its
        // name looks harmless.
        let hidden = app_dir.join("notes.txt");
        assert!(ensure_export_destination(&hidden, &protected, &dirs).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// KV-02: the writer lock is an OS handle lock, not just a process mutex.
    /// A second writer is refused while the first handle is open, and the
    /// atomic replace still succeeds under the lock.
    #[cfg(windows)]
    #[test]
    fn writer_lock_excludes_a_second_writer_and_allows_replace() {
        let path = unique_path("writer-lock");
        let _ = fs::remove_file(&path);
        create_vault(&path, b"pw").expect("create");
        let first = lock_vault_for_write_within(&path, Duration::ZERO).expect("first lock");
        assert!(matches!(
            lock_vault_for_write_within(&path, Duration::ZERO),
            Err(VaultError::Io(ref message)) if message == "vault_conflict"
        ));
        write_atomic(&path, "replacement").expect("replace while locked");
        assert_eq!(fs::read_to_string(&path).expect("read"), "replacement");
        drop(first);
        lock_vault_for_write_within(&path, Duration::ZERO).expect("released");
        let _ = fs::remove_file(&path);
    }

    /// KV-02: a save whose fingerprint no longer matches the file (another
    /// process, a manual restore, or a different password) is refused and the
    /// newest file is left untouched.
    #[test]
    fn external_change_is_refused_instead_of_overwritten() {
        let path = unique_path("conflict");
        for generation in 0..BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_path_generation(&path, generation));
        }
        let password = b"correct horse battery";
        let (_, salt, key, cost) = create_vault(&path, password).expect("create");
        let first = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "a", "name": "A", "service": "", "tags": [], "fields": []}],
        }));
        let opened_fingerprint = fingerprint_file(&path).expect("fingerprint");
        let new_fingerprint =
            save_vault_checked(&path, &first, &key, &salt, cost, &opened_fingerprint)
                .expect("first checked save");
        assert_eq!(new_fingerprint, fingerprint_file(&path).expect("new fingerprint"));

        // Same-key external writer (a second Keevra process).
        let external = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "b", "name": "B", "service": "", "tags": [], "fields": []}],
        }));
        save_vault(&path, &external, &key, &salt, cost).expect("external save");
        let newest = fs::read(&path).expect("newest");
        let error = save_vault_checked(&path, &first, &key, &salt, cost, &new_fingerprint)
            .expect_err("stale save must be refused");
        assert!(
            matches!(error, VaultError::Io(ref message) if message == "vault_conflict"),
            "unexpected error: {error:?}"
        );
        assert_eq!(fs::read(&path).expect("untouched"), newest);

        // A different-password rewrite is also a conflict, never a silent
        // overwrite that would hide the other file.
        let other = unique_path("conflict-other");
        let _ = fs::remove_file(&other);
        create_vault(&other, b"another password entirely").expect("other vault");
        fs::copy(&other, &path).expect("foreign rewrite");
        let foreign = fs::read(&path).expect("foreign");
        let error = save_vault_checked(&path, &first, &key, &salt, cost, &new_fingerprint)
            .expect_err("foreign save must be refused");
        assert!(
            matches!(error, VaultError::Io(ref message) if message == "vault_conflict"),
            "unexpected error: {error:?}"
        );
        assert_eq!(fs::read(&path).expect("untouched"), foreign);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&other);
        for generation in 0..BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_path_generation(&path, generation));
            let _ = fs::remove_file(backup_path_generation(&other, generation));
        }
        let _ = fs::remove_file(pre_restore_path(&path));
    }

    /// KV-03: if installing the newly staged backup fails after `.bak` moved
    /// aside, the previous `.bak` is put back and restore still works.
    #[test]
    fn failed_backup_install_keeps_previous_bak_restorable() {
        let path = unique_path("rotation-failure");
        for generation in 0..BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_path_generation(&path, generation));
        }
        let _ = fs::remove_file(pre_restore_path(&path));
        let password = b"correct horse battery";
        let (_, salt, key, cost) = create_vault(&path, password).expect("create");
        let first = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "a", "name": "A", "service": "", "tags": [], "fields": []}],
        }));
        save_vault(&path, &first, &key, &salt, cost).expect("save first");
        let second = doc(serde_json::json!({
            "schemaVersion": 3,
            "accounts": [{"id": "b", "name": "B", "service": "", "tags": [], "fields": []}],
        }));
        save_vault(&path, &second, &key, &salt, cost).expect("save second");
        let bak_before = fs::read(backup_path(&path)).expect("backup");

        // Simulate the final install rename failing (disk full / permission):
        // rotation has already moved `.bak` to `.bak.1` when this returns.
        let missing_staged = path.with_extension("missing-staged");
        commit_backup_rotation(&path, &missing_staged).expect_err("install must fail");

        assert_eq!(
            fs::read(backup_path(&path)).expect("recovered backup"),
            bak_before,
            "previous .bak must be restored after a failed install"
        );
        restore_backup(&path, password).expect("restore from recovered .bak");
        let (restored, _, _, _) =
            open_graph(&read_vault_file(&path).expect("read"), password).expect("restored opens");
        assert_eq!(
            restored
                .get("accounts")
                .and_then(|value| value.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("id")),
            Some(&serde_json::json!("a"))
        );

        let _ = fs::remove_file(&path);
        for generation in 0..BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_path_generation(&path, generation));
        }
        let _ = fs::remove_file(pre_restore_path(&path));
    }
}
