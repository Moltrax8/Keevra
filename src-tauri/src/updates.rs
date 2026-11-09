//! Notify-only updater: signed-manifest gate + SHA256-verified download.
//!
//! Policy: the app never downloads silently. The frontend checks GitHub
//! releases, notifies, and calls download only after explicit user consent.
//! Downloads are gated on a signed manifest (`updates.json` + ed25519
//! `.minisig` published per release, private key offline): the installer
//! SHA comes from the verified manifest — never from an unsigned `.sha256`
//! file an attacker could forge alongside a malicious binary. Version must
//! be strictly newer (downgrades refused). A verified installer is opened in
//! the Windows setup wizard and the app exits so NSIS can replace it; the
//! staged setup file is deleted on the next start.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::update_keys::UPDATE_SIGNING_KEYS;
use crate::vault::{write_atomic_bytes, VaultError};

/// 200 MiB hard cap for installer downloads.
pub const MAX_UPDATE_BYTES: u64 = 200 * 1024 * 1024;

/// Signed manifest authority per release (`updates.json` asset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub assets: Vec<ManifestAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAsset {
    pub name: String,
    pub sha256: String,
}

fn parse_tag_numbers(tag: &str) -> Vec<u64> {
    tag.trim()
        .trim_start_matches(['v', 'V'])
        .split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

/// Strictly-newer comparison on numeric version tags.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let a = parse_tag_numbers(current);
    let b = parse_tag_numbers(latest);
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        if x != y {
            return y > x;
        }
    }
    false
}

/// Verifies ed25519 `sig_b64` over exact `manifest_bytes` against any baked key.
pub fn verify_manifest_signature(manifest_bytes: &[u8], sig_b64: &str) -> Result<(), VaultError> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    let sig_vec = B64
        .decode(sig_b64.trim())
        .map_err(|_| VaultError::Io("invalid_update_sig".to_string()))?;
    let sig_bytes: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| VaultError::Io("invalid_update_sig".to_string()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    for key_bytes in UPDATE_SIGNING_KEYS {
        if let Ok(key) = VerifyingKey::from_bytes(&key_bytes) {
            if key.verify(manifest_bytes, &signature).is_ok() {
                return Ok(());
            }
        }
    }
    Err(VaultError::Io("update_sig_mismatch".to_string()))
}

/// Verifies then parses a manifest, validating shape (names filesafe, SHAs hex).
pub fn parse_verified_manifest(manifest_text: &str, sig_text: &str) -> Result<UpdateManifest, VaultError> {
    verify_manifest_signature(manifest_text.as_bytes(), sig_text)?;
    let manifest: UpdateManifest =
        serde_json::from_str(manifest_text).map_err(|_| VaultError::Io("invalid_manifest".to_string()))?;
    if manifest.version.trim().is_empty() || manifest.assets.is_empty() {
        return Err(VaultError::Io("invalid_manifest".to_string()));
    }
    for asset in &manifest.assets {
        if asset.name.trim().is_empty()
            || asset.name.contains('/')
            || asset.name.contains('\\')
            || asset.name.contains("..")
        {
            return Err(VaultError::Io("invalid_manifest".to_string()));
        }
        let sha = asset.sha256.trim().to_lowercase();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::Io("invalid_manifest".to_string()));
        }
    }
    Ok(manifest)
}

fn allowed_update_host(host: &str) -> bool {
    let host = host.to_lowercase();
    host == "github.com"
        || host == "api.github.com"
        || host == "objects.githubusercontent.com"
        || host == "release-assets.githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

const MAX_UPDATE_REDIRECTS: usize = 10;

fn redirect_target_allowed(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(allowed_update_host)
}

/// Every hop of a redirect chain must stay on the update allow-list. Exposed
/// for tests: the reqwest policy below is a thin wrapper around this (K-10).
fn redirect_chain_allows(previous_hops: usize, url: &str) -> bool {
    if previous_hops >= MAX_UPDATE_REDIRECTS {
        return false;
    }
    reqwest::Url::parse(url)
        .ok()
        .is_some_and(|parsed| redirect_target_allowed(&parsed))
}

fn update_http_client() -> Result<reqwest::Client, VaultError> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if !redirect_chain_allows(attempt.previous().len(), attempt.url().as_str()) {
            return attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "update redirect left the HTTPS GitHub allow-list",
            ));
        }
        attempt.follow()
    });
    reqwest::Client::builder()
        // GitHub's API rejects requests without a User-Agent, and the same
        // client serves the asset-API fallback.
        .user_agent(concat!("Keevra/", env!("CARGO_PKG_VERSION")))
        .redirect(policy)
        .build()
        .map_err(|e| VaultError::Io(format!("update_client_failed:{e}")))
}

fn validate_update_url(url: &str) -> Result<reqwest::Url, VaultError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| VaultError::Io("invalid_update_url".to_string()))?;
    if !redirect_target_allowed(&parsed) {
        return Err(VaultError::Io("invalid_update_url".to_string()));
    }
    Ok(parsed)
}

/// Upper bound for the signed manifest, and for its detached signature. Both
/// are tiny JSON/base64 documents, so anything bigger is not a manifest.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_SIG_BYTES: u64 = 4 * 1024;

/// Validates both manifest URLs before any request is made, so a hostile
/// target is refused even before the size and redirect rules apply.
fn manifest_fetch_targets(
    manifest_url: &str,
    sig_url: &str,
) -> Result<(reqwest::Url, reqwest::Url), VaultError> {
    Ok((validate_update_url(manifest_url)?, validate_update_url(sig_url)?))
}

/// GitHub only serves raw asset bytes when this header is present; without it
/// an asset URL answers with its JSON metadata instead.
const BINARY_ACCEPT: &str = "application/octet-stream";
/// Header for GitHub's JSON API.
const JSON_ACCEPT: &str = "application/vnd.github+json";
/// Release metadata stays small even for releases with many assets.
const MAX_API_METADATA_BYTES: u64 = 2 * 1024 * 1024;

/// The slice of `GET /repos/{owner}/{repo}/releases/tags/{tag}` the fallback
/// needs: asset names mapped to their download endpoints.
#[derive(Debug, Deserialize)]
struct ApiRelease {
    assets: Vec<ApiAsset>,
}

#[derive(Debug, Deserialize)]
struct ApiAsset {
    name: String,
    url: String,
}

/// Splits `https://github.com/{owner}/{repo}/releases/download/{tag}/{name}`.
///
/// The asset-API fallback applies only to that exact shape, so redirects, CDN
/// URLs and plain repository links never trigger an extra API request.
fn release_download_parts(url: &reqwest::Url) -> Option<(String, String, String, String)> {
    if url.scheme() != "https" || url.host_str()? != "github.com" {
        return None;
    }
    let segments: Vec<&str> = url.path_segments()?.collect();
    // ["{owner}", "{repo}", "releases", "download", "{tag}", "{name}"]
    if segments.len() != 6 || segments[2] != "releases" || segments[3] != "download" {
        return None;
    }
    let (owner, repo, tag, name) = (segments[0], segments[1], segments[4], segments[5]);
    if [owner, repo, tag, name].iter().any(|part| part.is_empty()) {
        return None;
    }
    Some((
        owner.to_string(),
        repo.to_string(),
        tag.to_string(),
        name.to_string(),
    ))
}

/// `https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}`.
fn release_api_url(parts: &(String, String, String, String)) -> Result<reqwest::Url, VaultError> {
    let mut url = reqwest::Url::parse("https://api.github.com")
        .map_err(|_| VaultError::Io("invalid_update_url".to_string()))?;
    url.path_segments_mut()
        .map_err(|_| VaultError::Io("invalid_update_url".to_string()))?
        .extend(["repos", &parts.0, &parts.1, "releases", "tags", &parts.2]);
    Ok(url)
}

/// A failure a different endpoint might not repeat: transport error, TLS
/// problem, closed connection or an HTTP error status. Policy errors (size cap,
/// rejected URL) are never retried elsewhere.
fn is_download_failure(error: &VaultError) -> bool {
    matches!(error, VaultError::Io(message) if message.starts_with("update_download_failed"))
}

/// GET `url` with an optional `Accept` header and a hard byte cap.
async fn get_capped_bytes(
    client: &reqwest::Client,
    url: reqwest::Url,
    accept: Option<&str>,
    cap: u64,
    too_large: &str,
) -> Result<Vec<u8>, VaultError> {
    let mut request = client.get(url);
    if let Some(accept) = accept {
        request = request.header(reqwest::header::ACCEPT, accept);
    }
    let mut response = request
        .send()
        .await
        .map_err(|e| VaultError::Io(format!("update_download_failed:{e}")))?;
    if !response.status().is_success() {
        return Err(VaultError::Io("update_download_failed".to_string()));
    }
    if response.content_length().is_some_and(|length| length > cap) {
        return Err(VaultError::Io(too_large.to_string()));
    }
    // Stream with a running byte counter: a hostile/chunked response can never
    // force the whole body into memory before the cap is applied (K-10).
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| VaultError::Io(format!("update_download_failed:{e}")))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > cap {
            return Err(VaultError::Io(too_large.to_string()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Maps a release asset URL to its `api.github.com` endpoint by file name.
/// `None` means "not a plain release download, or no asset of that name".
async fn api_asset_url(
    client: &reqwest::Client,
    original: &reqwest::Url,
) -> Result<Option<reqwest::Url>, VaultError> {
    let Some(parts) = release_download_parts(original) else {
        return Ok(None);
    };
    let metadata = get_capped_bytes(
        client,
        release_api_url(&parts)?,
        Some(JSON_ACCEPT),
        MAX_API_METADATA_BYTES,
        "update_metadata_too_large",
    )
    .await?;
    let release: ApiRelease = serde_json::from_slice(&metadata)
        .map_err(|_| VaultError::Io("update_metadata_invalid".to_string()))?;
    let asset = release.assets.iter().find(|asset| asset.name == parts.3);
    match asset {
        Some(asset) => Ok(Some(validate_update_url(&asset.url)?)),
        None => Ok(None),
    }
}

/// The only file name the updater will write and launch: the final path segment
/// of the installer URL, restricted to ASCII alphanumerics plus `.`, `_`, `-`
/// with an `.exe` suffix.
///
/// The manifest binds downloads by asset name, so rejecting anything that is
/// not a plain single file name keeps a hostile release from steering the write
/// to another path. Percent signs are refused outright, which removes the
/// encoded-separator ambiguity that URL path segments can still carry.
fn installer_name_from_url(parsed: &reqwest::Url) -> Result<String, VaultError> {
    let name = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or("")
        .to_string();
    let safe_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if name.is_empty()
        || name.len() == ".exe".len()
        || !safe_chars
        || !name.to_ascii_lowercase().ends_with(".exe")
    {
        return Err(VaultError::Io("invalid_update_url".to_string()));
    }
    Ok(name)
}

/// Public wrapper so the command layer derives the staging file name from the
/// same validated URL the download will use.
pub fn installer_file_name(installer_url: &str) -> Result<String, VaultError> {
    let parsed = validate_update_url(installer_url)?;
    installer_name_from_url(&parsed)
}

/// Directory inside the app data folder that holds an in-flight installer.
/// It is never the vault directory, so cleanup cannot touch ciphertext.
pub const UPDATE_STAGING_DIR: &str = "updates";

pub fn staging_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(UPDATE_STAGING_DIR)
}

/// Removes setup files left behind by an earlier update attempt.
///
/// The installer cannot delete its own running file, so the setup file is
/// removed by the newly installed app on start (or by the next start after a
/// cancelled wizard). Only `.exe` installers and `.tmp` atomic-write leftovers
/// are touched; files with any other name are left alone. NSIS may still hold
/// the file open for a moment when the new app starts, so deletion is retried
/// in the background for a few seconds.
pub fn cleanup_staged_installers(dir: &Path) {
    remove_when_unlocked(staged_installers(dir));
}

/// The `.exe`/`.tmp` files present in `dir` right now.
pub fn staged_installers(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
            (lower.ends_with(".exe") || lower.ends_with(".tmp")).then_some(path)
        })
        .collect()
}

/// Deletes exactly these files, retrying once a second for ~15s.
///
/// Only the paths captured at startup are touched, so a setup file downloaded
/// after startup can never be removed by this background pass.
fn remove_when_unlocked(paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let mut pending = paths;
        for _ in 0..15 {
            pending.retain(|path| path.exists() && std::fs::remove_file(path).is_err());
            if pending.is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

/// Downloads over the update channel, falling back to the GitHub asset API.
///
/// `github.com/{owner}/{repo}/releases/download/...` can answer 5xx or drop the
/// connection while `api.github.com` still serves the identical bytes. The
/// fallback only changes where those bytes come from: the caller's signature
/// and SHA256 checks still decide whether they are accepted.
async fn fetch_update_bytes(
    url: reqwest::Url,
    cap: u64,
    too_large: &str,
) -> Result<Vec<u8>, VaultError> {
    let client = update_http_client()?;
    match get_capped_bytes(&client, url.clone(), None, cap, too_large).await {
        Ok(bytes) => Ok(bytes),
        Err(error) if is_download_failure(&error) => match api_asset_url(&client, &url).await {
            Ok(Some(api_url)) => {
                get_capped_bytes(&client, api_url, Some(BINARY_ACCEPT), cap, too_large).await
            }
            Ok(None) => Err(error),
            Err(fallback_error) => Err(fallback_error),
        },
        Err(error) => Err(error),
    }
}

/// Fetches a small text document over the update channel with a hard byte cap.
async fn fetch_limited_text(
    url: reqwest::Url,
    cap: u64,
    too_large: &str,
) -> Result<String, VaultError> {
    let bytes = fetch_update_bytes(url, cap, too_large).await?;
    String::from_utf8(bytes).map_err(|_| VaultError::Io("update_manifest_not_utf8".to_string()))
}

/// Fetches `updates.json` and `updates.json.minisig` in Rust.
///
/// GitHub serves release assets without `Access-Control-Allow-Origin`, so a
/// WebView `fetch()` of the asset URL is blocked by CORS before the signature
/// can ever be checked. Fetching here keeps the GitHub-only HTTPS allow-list,
/// the redirect policy and the size caps identical to the installer download.
pub async fn fetch_signed_manifest(
    manifest_url: &str,
    sig_url: &str,
) -> Result<(String, String), VaultError> {
    let (manifest_url, sig_url) = manifest_fetch_targets(manifest_url, sig_url)?;
    let manifest =
        fetch_limited_text(manifest_url, MAX_MANIFEST_BYTES, "update_manifest_too_large").await?;
    let sig = fetch_limited_text(sig_url, MAX_SIG_BYTES, "update_signature_too_large").await?;
    Ok((manifest, sig))
}

/// Downloads `url` (GitHub hosts, HTTPS only), verifies SHA256, saves to
/// `dest_path` atomically. Returns byte count. Mismatch deletes nothing and
/// writes nothing.
pub async fn download_verified(
    url: &str,
    expected_sha256_hex: &str,
    dest_path: &Path,
) -> Result<u64, VaultError> {
    let expected = expected_sha256_hex.trim().to_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError::Io("invalid_update_sha".to_string()));
    }
    let parsed = validate_update_url(url)?;
    let bytes = fetch_update_bytes(parsed, MAX_UPDATE_BYTES, "update_too_large").await?;
    let digest = Sha256::digest(&bytes);
    let actual = format!("{digest:x}");
    if actual != expected {
        return Err(VaultError::Io("update_sha_mismatch".to_string()));
    }
    write_atomic_bytes(dest_path, &bytes)?;
    Ok(bytes.len() as u64)
}

/// Full manifest gate: verifies signature, enforces strictly-newer version
/// (downgrades refused), binds the installer URL basename to a manifest
/// asset, then downloads with the manifest SHA. The SHA never comes from an
/// unsigned sidecar in this path.
pub async fn download_manifest_asset(
    installer_url: &str,
    manifest_text: &str,
    manifest_sig: &str,
    current_version: &str,
    dest_path: &Path,
) -> Result<(u64, String), VaultError> {
    let manifest = parse_verified_manifest(manifest_text, manifest_sig)?;
    if !is_newer_version(current_version, &manifest.version) {
        return Err(VaultError::Io("update_not_newer".to_string()));
    }
    let parsed = validate_update_url(installer_url)?;
    let file_name = installer_name_from_url(&parsed)?;
    let asset = manifest
        .assets
        .iter()
        .find(|asset| asset.name == file_name)
        .ok_or_else(|| VaultError::Io("update_asset_not_in_manifest".to_string()))?;
    let bytes = download_verified(installer_url, &asset.sha256, dest_path).await?;
    Ok((bytes, manifest.version.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_github_hosts_and_http() {
        assert!(validate_update_url("http://github.com/x.exe").is_err());
        assert!(validate_update_url("https://evil.example.com/x.exe").is_err());
        assert!(validate_update_url("https://github.com/Moltrax8/Keevra/releases/download/v1/x.exe").is_ok());
        assert!(validate_update_url("https://objects.githubusercontent.com/abc").is_ok());
    }

    #[test]
    fn manifest_fetch_requires_github_https_urls() {
        // Anything outside the allow-list, or plain HTTP, is refused before a
        // request is made.
        assert!(manifest_fetch_targets("http://github.com/updates.json", "https://github.com/s").is_err());
        assert!(manifest_fetch_targets("https://evil.example.com/updates.json", "https://github.com/s").is_err());
        assert!(manifest_fetch_targets("https://github.com/updates.json", "https://evil.example.com/s").is_err());
        assert!(manifest_fetch_targets("https://github.com/updates.json", "http://github.com/s").is_err());
        assert!(manifest_fetch_targets(
            "https://github.com/Moltrax8/Keevra/releases/download/v1/updates.json",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/updates.json.minisig"
        )
        .is_ok());
    }

    #[test]
    fn every_redirect_hop_must_stay_on_the_allow_list() {
        // Same-host and approved-CDN redirects are followed.
        assert!(redirect_chain_allows(
            0,
            "https://github.com/Moltrax8/Keevra/releases/download/v1/x.exe"
        ));
        assert!(redirect_chain_allows(
            1,
            "https://objects.githubusercontent.com/abc"
        ));
        assert!(redirect_chain_allows(
            2,
            "https://release-assets.githubusercontent.com/abc"
        ));
        // A redirect to another host, or to plain HTTP, is refused.
        assert!(!redirect_chain_allows(0, "https://evil.example.com/x.exe"));
        assert!(!redirect_chain_allows(0, "http://github.com/x.exe"));
        assert!(!redirect_chain_allows(0, "file:///C:/x.exe"));
        // Chains cannot grow without bound.
        assert!(!redirect_chain_allows(MAX_UPDATE_REDIRECTS, "https://github.com/x"));
        assert!(redirect_chain_allows(
            MAX_UPDATE_REDIRECTS - 1,
            "https://github.com/x"
        ));
    }

    #[test]
    fn release_download_urls_map_to_api_endpoints() {
        let url = reqwest::Url::parse(
            "https://github.com/Moltrax8/Keevra/releases/download/v0.2.4/updates.json",
        )
        .expect("valid url");
        let parts = release_download_parts(&url).expect("plain release download url");
        assert_eq!(parts.0, "Moltrax8");
        assert_eq!(parts.1, "Keevra");
        assert_eq!(parts.2, "v0.2.4");
        assert_eq!(parts.3, "updates.json");

        let api = release_api_url(&parts).expect("api url");
        assert_eq!(
            api.as_str(),
            "https://api.github.com/repos/Moltrax8/Keevra/releases/tags/v0.2.4"
        );
        // The asset endpoints the fallback then downloads from are themselves
        // on the update allow-list, so redirect checks still apply to them.
        assert!(validate_update_url(
            "https://api.github.com/repos/Moltrax8/Keevra/releases/assets/723568256"
        )
        .is_ok());
    }

    #[test]
    fn api_fallback_only_applies_to_plain_release_downloads() {
        for url in [
            "https://github.com/Moltrax8/Keevra/releases/tag/v0.2.4",
            "https://github.com/Moltrax8/Keevra/releases/download/v0.2.4",
            "https://github.com/Moltrax8/Keevra/releases/download/v0.2.4/",
            "https://api.github.com/repos/Moltrax8/Keevra/releases/assets/1",
            "https://objects.githubusercontent.com/Moltrax8/Keevra/releases/download/v0.2.4/x",
            "http://github.com/Moltrax8/Keevra/releases/download/v0.2.4/x",
        ] {
            let parsed = reqwest::Url::parse(url).expect("valid url");
            assert!(
                release_download_parts(&parsed).is_none(),
                "{url} must not trigger the asset-API fallback"
            );
        }
        // Names with characters that need escaping are kept as they appear on
        // the release, which is what the asset list compares against.
        let encoded = reqwest::Url::parse(
            "https://github.com/Moltrax8/Keevra/releases/download/v1/Keevra_1_x64-setup.exe",
        )
        .expect("valid url");
        assert_eq!(
            release_download_parts(&encoded).expect("plain release download url").3,
            "Keevra_1_x64-setup.exe"
        );
    }

    #[test]
    fn installer_names_are_single_ascii_exe_files() {
        assert_eq!(
            installer_file_name(
                "https://github.com/Moltrax8/Keevra/releases/download/v1/Keevra_1_x64-setup.exe"
            )
            .expect("plain installer name"),
            "Keevra_1_x64-setup.exe"
        );
        for rejected in [
            "https://github.com/Moltrax8/Keevra/releases/download/v1/",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/setup.msi",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/updates.json",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/.exe",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/..%2Fevil.exe",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/..%5Cevil.exe",
            "https://github.com/Moltrax8/Keevra/releases/download/v1/spa%20ce.exe",
            "https://evil.example.com/Keevra.exe",
        ] {
            assert!(installer_file_name(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn staged_cleanup_only_targets_installers_and_temp_files() {
        let dir = std::env::temp_dir().join(format!(
            "keevra-update-cleanup-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("staging dir");
        for name in ["Keevra_1_x64-setup.exe", "setup.EXE", "x.exe.123.tmp"] {
            std::fs::write(dir.join(name), b"x").expect("staged file");
        }
        for name in ["notes.txt", "updates.json"] {
            std::fs::write(dir.join(name), b"keep").expect("unrelated file");
        }
        let mut staged: Vec<String> = staged_installers(&dir)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        staged.sort();
        assert_eq!(
            staged,
            ["Keevra_1_x64-setup.exe", "setup.EXE", "x.exe.123.tmp"]
        );
        for path in staged_installers(&dir) {
            std::fs::remove_file(path).expect("remove staged file");
        }
        assert!(dir.join("notes.txt").exists());
        assert!(dir.join("updates.json").exists());
        // A missing directory is not an error: the app can start before the
        // first update ever downloads.
        assert!(staged_installers(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_gate_refuses_downgrades() {        assert!(is_newer_version("v1.0.0", "v1.0.1"));
        assert!(!is_newer_version("v1.0.1", "v1.0.0"));
        assert!(!is_newer_version("v1.0.1", "v1.0.1"));
        assert!(!is_newer_version("0.2.0", "0.2.0"));
        assert!(is_newer_version("0.2.0", "0.3.0"));
    }

    #[test]
    #[ignore = "hits the live GitHub API"]
    fn live_manifest_fetch_and_installer_download() {
        // Opt-in smoke test for the real network path (tools/release-local.ps1
        // runs it after publishing):
        //   cargo test --manifest-path src-tauri/Cargo.toml -- --ignored
        // It proves the asset-API fallback works while github.com's release
        // download redirect is misbehaving, then downloads the installer it
        // names and checks the signed SHA256.
        let tag = std::env::var("KEEVRA_LIVE_TAG").unwrap_or_else(|_| "v0.2.4".to_string());
        let current = std::env::var("KEEVRA_LIVE_CURRENT").unwrap_or_else(|_| "0.2.0".to_string());
        let manifest_url =
            format!("https://github.com/Moltrax8/Keevra/releases/download/{tag}/updates.json");
        let sig_url = format!("{manifest_url}.minisig");
        let (manifest, sig) =
            tauri::async_runtime::block_on(fetch_signed_manifest(&manifest_url, &sig_url))
                .expect("live manifest fetch");
        let parsed = parse_verified_manifest(&manifest, &sig).expect("live manifest verifies");
        assert!(!parsed.version.is_empty());

        // Exercise the fallback itself, whatever github.com is doing today:
        // resolve the same asset through api.github.com and fetch its bytes.
        let client = update_http_client().expect("update client");
        let original = reqwest::Url::parse(&manifest_url).expect("manifest url");
        let api_url = tauri::async_runtime::block_on(api_asset_url(&client, &original))
            .expect("asset lookup")
            .expect("manifest asset exists");
        let via_api = tauri::async_runtime::block_on(get_capped_bytes(
            &client,
            api_url,
            Some(BINARY_ACCEPT),
            MAX_MANIFEST_BYTES,
            "update_manifest_too_large",
        ))
        .expect("asset API download");
        assert_eq!(via_api, manifest.as_bytes());

        let installer_url = format!(
            "https://github.com/Moltrax8/Keevra/releases/download/{tag}/{}",
            parsed.assets[0].name
        );
        let dest = std::env::temp_dir().join("keevra-live-update-smoke.exe");
        let (bytes, version) = tauri::async_runtime::block_on(download_manifest_asset(
            &installer_url,
            &manifest,
            &sig,
            &current,
            &dest,
        ))
        .expect("live installer download");
        let _ = std::fs::remove_file(&dest);
        assert_eq!(version, parsed.version);
        assert!(bytes > 1_000_000, "installer bytes: {bytes}");
    }

    #[test]
    fn tampered_manifest_fails_closed() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let mut rng = rand::thread_rng();
        // Random key (NOT a baked key): must fail.
        let rogue = SigningKey::generate(&mut rng);
        let manifest = r#"{"version":"9.9.9","assets":[{"name":"x-setup.exe","sha256":"ab"}]}"#;
        let sig = rogue.sign(manifest.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        assert!(parse_verified_manifest(manifest, &sig_b64).is_err());
        // Garbage signature must fail.
        assert!(parse_verified_manifest(manifest, "aaaa").is_err());
    }
}
