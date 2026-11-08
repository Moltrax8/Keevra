//! Notify-only updater: signed-manifest gate + SHA256-verified download.
//!
//! Policy: the app never downloads silently. The frontend checks GitHub
//! releases, notifies, and calls download only after explicit user consent.
//! Downloads are gated on a signed manifest (`updates.json` + ed25519
//! `.minisig` published per release, private key offline): the installer
//! SHA comes from the verified manifest — never from an unsigned `.sha256`
//! file an attacker could forge alongside a malicious binary. Version must
//! be strictly newer (downgrades refused). Nothing is ever launched — the
//! user runs the installer manually.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

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

/// Fetches a small text document over the update channel with a hard byte cap.
async fn fetch_limited_text(
    url: reqwest::Url,
    cap: u64,
    too_large: &str,
) -> Result<String, VaultError> {
    let client = update_http_client()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| VaultError::Io(format!("update_download_failed:{e}")))?;
    if !response.status().is_success() {
        return Err(VaultError::Io("update_download_failed".to_string()));
    }
    if response.content_length().is_some_and(|length| length > cap) {
        return Err(VaultError::Io(too_large.to_string()));
    }
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
    let client = update_http_client()?;
    let mut response = client
        .get(parsed)
        .send()
        .await
        .map_err(|e| VaultError::Io(format!("update_download_failed:{e}")))?;
    if !response.status().is_success() {
        return Err(VaultError::Io("update_download_failed".to_string()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_UPDATE_BYTES)
    {
        return Err(VaultError::Io("update_too_large".to_string()));
    }
    // Stream with a running byte counter: a hostile/chunked response can never
    // force the whole body into memory before the cap is applied (K-10).
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| VaultError::Io(format!("update_download_failed:{e}")))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > MAX_UPDATE_BYTES {
            return Err(VaultError::Io("update_too_large".to_string()));
        }
        bytes.extend_from_slice(&chunk);
    }
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
    let file_name = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or("")
        .to_string();
    if file_name.is_empty() {
        return Err(VaultError::Io("invalid_update_url".to_string()));
    }
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
    fn version_gate_refuses_downgrades() {
        assert!(is_newer_version("v1.0.0", "v1.0.1"));
        assert!(!is_newer_version("v1.0.1", "v1.0.0"));
        assert!(!is_newer_version("v1.0.1", "v1.0.1"));
        assert!(!is_newer_version("0.2.0", "0.2.0"));
        assert!(is_newer_version("0.2.0", "0.3.0"));
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
