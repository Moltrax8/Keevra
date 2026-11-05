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
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

pub const VAULT_VERSION: u32 = 1;
/// New-vault password floor, enforced here as well as in the UI.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const KDF_MEMORY_KIB: u32 = 65536;
pub const KDF_ITERATIONS: u32 = 3;
pub const KDF_PARALLELISM: u32 = 1;
// DoS bounds for stored parameters honored on open (generous ceilings: the
// defaults above sit far below them).
const KDF_MAX_MEMORY_KIB: u32 = 1 << 20;
const KDF_MAX_ITERATIONS: u32 = 10;
const KDF_MAX_PARALLELISM: u32 = 8;
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
    if envelope.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(envelope.version));
    }
    if envelope.kdf.alg != "argon2id" {
        return Err(VaultError::WrongPasswordOrCorrupt);
    }
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
    if envelope.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(envelope.version));
    }
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

fn backup_path(path: &Path) -> PathBuf {    let mut backup = path.as_os_str().to_owned();
    backup.push(".bak");
    PathBuf::from(backup)
}

/// Atomic durable write: temp file in the same directory, flush, rename.
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
    fs::read_to_string(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(e.to_string())
        }
    })
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
    let _guard = VAULT_WRITE_LOCK
        .lock()
        .map_err(|e| VaultError::Io(e.to_string()))?;
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

/// Save under an existing session key. Keeps the previous good vault as
/// `.bak` (written only after the new vault verifies by re-parsing).
///
/// `cost` must be the cost the session key was derived with, not the current
/// defaults; see [`KdfCost`].
pub fn save_vault(
    path: &Path,
    graph: &GraphData,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
) -> Result<(), VaultError> {
    let _guard = VAULT_WRITE_LOCK
        .lock()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    validate_graph(graph)?;
    let sealed = seal_graph(graph, key, salt, cost)?;
    // Actually decrypt and re-parse the new envelope with the session key
    // before replacing the old file; a bad seal must never reach disk.
    let _verified = open_envelope_with_key(&sealed.envelope_json, key)?;
    if path.exists() {
        let backup = backup_path(path);
        fs::copy(path, &backup).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    write_atomic(path, &sealed.envelope_json)?;
    Ok(())
}

/// Explicit, never automatic, restore of the previous good vault.
pub fn restore_backup(path: &Path) -> Result<(), VaultError> {
    let _guard = VAULT_WRITE_LOCK
        .lock()
        .map_err(|e| VaultError::Io(e.to_string()))?;
    let backup = backup_path(path);
    if !backup.exists() {
        return Err(VaultError::NotFound);
    }
    let contents = fs::read(&backup).map_err(|e| VaultError::Io(e.to_string()))?;
    write_atomic(path, &String::from_utf8_lossy(&contents))?;
    Ok(())
}

pub fn backup_path_for(path: &Path) -> PathBuf {
    backup_path(path)
}

/// Attachment IDs referenced by an encrypted vault file on disk, decrypted
/// with the session key. Best-effort: any failure yields an empty list so
/// callers retain rather than delete.
pub fn attachment_ids_in_encrypted_file(path: &Path, key: &[u8; KEY_LEN]) -> Vec<String> {
    let Ok(envelope_json) = fs::read_to_string(path) else {
        return Vec::new();
    };
    match open_envelope_with_key(&envelope_json, key) {
        Ok(graph) => crate::attachments::live_attachment_ids(&graph.0),
        Err(_) => Vec::new(),
    }
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
}
