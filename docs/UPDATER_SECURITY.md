# Updater Security

Keevra updates are **notify-only, consent-gated, signature-verified**.
This document is the authority for the update channel alongside
`docs/THREAT_MODEL.md` (which still governs the vault itself).

## Network access (explicit)

- The automatic/manual **check** performs an unauthenticated HTTPS `GET` to
  `https://api.github.com/repos/<UPDATE_OWNER>/<UPDATE_REPO>/releases/latest`
  (`Moltrax8/Keevra`) with `Accept: application/vnd.github+json`.
  GitHub therefore sees the machine's IP and request time. The request carries
  **no** vault contents, account data, local paths, or telemetry.
- The optional **download** happens in the Rust backend, not the WebView:
  `updates.json`, its `.minisig` and the installer are fetched over HTTPS from
  `github.com` release asset URLs through one GitHub-only allow-list that also
  checks every redirect hop. The production CSP therefore allows only
  `api.github.com` for the version check; the window itself cannot reach
  release-asset hosts.
  If `github.com/.../releases/download/...` fails (5xx, dropped connection),
  the same asset is fetched from `api.github.com/repos/<owner>/<repo>/releases/`
  `assets/<id>` with `Accept: application/octet-stream`. The fallback only
  changes which endpoint serves the bytes: the manifest signature and the
  installer SHA256 are still checked exactly as before, and the asset is
  matched by file name against the requested release. Release metadata is
  capped at 2 MiB and the API host is already on the allow-list.
  GitHub release assets are served without `Access-Control-Allow-Origin`, so a
  WebView `fetch()` of them is blocked by the browser before any signature
  could be verified — that is why manifest fetching lives in Rust.
- The check runs 4s after launch and can be repeated from Settings; it fails
  silently when offline. There is no other network call in the app.

## Policy

1. The app **never** downloads or installs silently. A banner/Settings entry
   notifies; everything else requires explicit clicks.
2. The download authority is a **signed manifest** (`updates.json` +
   `updates.json.minisig` release assets), not the `.sha256` sidecar.
   SHA-from-GitHub alone proves transit integrity, not publisher — a
   compromised GitHub account could forge both binary and sidecar.
3. A verified installer is **opened in the Windows setup wizard**: the app
   stages it inside its own `<app data>/updates` directory under a single
   `.exe` name derived from the release URL, launches it through the shell
   (UAC prompt included) and then flushes drafts, saves and locks the vault
   before `update_restart` closes the process so NSIS can replace it. The user
   still clicks through the wizard; nothing is installed without that
   interaction, and the staged setup file is removed on the next start.
4. Unsigned releases get **no download button** — release page only.

## Keys

- Algorithm: ed25519 (`ed25519-dalek`), signatures base64-encoded (minisig style).
- Public key(s) baked in `src-tauri/src/update_keys.rs`. Private keys live
  **offline** with the release manager; they never enter git, CI, or Supabase.
- Key 0 (`qIa4woC9NAQ0…`, full value in `update_keys.rs`): generated
  2026-10-05 via `cargo run --manifest-path tools/update-tool/Cargo.toml -- gen-key`
  on the release manager machine. Retained so any artifact already signed with
  it still verifies; it is not used for new releases.
- Key 1 (`w0xD17RKn3m…`, full value in `update_keys.rs`): generated 2026-11-07
  with the same tool. This is the **active** signing key for releases from the
  0.2.2 re-issue onward. Its private half never enters git or CI.
- Rotation: append the new public key to `UPDATE_SIGNING_KEYS` (verify
  accepts any listed key), publish one release signed by **both** keys
  (two `.minisig` assets or dual-sign window per release notes), then remove
  the old key in the following release. Emergency revocation = release
  removing the compromised key + rotating the GitHub token + publishing a
  `REVOKED` note users can verify out-of-band.
- A build only trusts the keys baked into it. If a new key is introduced and
  the previous private key is unavailable, users on older builds must install
  the new build once manually; later releases update normally.

## Release process (maintainer)

1. Build the installer from the release tag with locked dependencies
   (`npm ci`, `cargo build --locked`). Pushing a `v<version>` tag runs
   `.github/workflows/release.yml`, which builds the NSIS installer, signs and
   verifies it when a certificate is configured, and attaches
   `SHA256SUMS.txt`, SBOMs and provenance attestations. See
   `docs/RELEASE_SECURITY.md`.
2. Compute SHA256 of `*-setup.exe`; write `updates.json`:
   `{"version":"0.1.0","assets":[{"name":"<exe>","sha256":"<hex>"}]}`
   (`version` must equal the release tag modulo leading `v`).
3. On the OFFLINE key machine:
   `cargo run --manifest-path tools/update-tool/Cargo.toml -- sign updates.json --key <offline.key>` → `updates.json.minisig`.
4. Attach to the GitHub release: installer EXE, `updates.json`,
   `updates.json.minisig` (keep any legacy `.sha256` as informational only).
5. Smoke test: fresh machine, Settings → Check → Download → the setup wizard
   opens and Keevra closes → finish the wizard → the next start removes the
   staged installer. Mismatch drill: a tampered manifest must refuse with a
   signature error.

## Verification (client)

- Rust `updates::fetch_signed_manifest` (command
  `update_fetch_signed_manifest`): downloads `updates.json` and its `.minisig`
  with the same GitHub-only HTTPS allow-list, redirect policy and byte caps as
  the installer, so the WebView never needs CORS access to release assets.
- Rust `updates::parse_verified_manifest`: ed25519 verify over exact
  manifest bytes against any baked key → parse → validate shape (filesafe
  names, 64-hex SHAs) — in `update_verify_manifest`.
- `download_manifest_asset`: re-verifies manifest, enforces
  strictly-newer version (`update_not_newer` otherwise — downgrades refused),
  binds installer basename to a manifest asset
  (`update_asset_not_in_manifest` otherwise), downloads over HTTPS from
  GitHub hosts only, compares SHA, atomic save only on match.
- `update_download_and_launch`: derives the staging path itself
  (`<app data>/updates/<single .exe name>`; ASCII letters, digits, `.`, `_`,
  `-` only), so the frontend cannot redirect a verified download onto a vault,
  backup, blob or registry file. After the gate passes it opens the file with
  `ShellExecuteW`. The frontend then flushes drafts and saves/locks the vault
  (a failed save keeps Keevra open) and calls `update_restart`; a failed
  launch deletes the staged file and reports `update_launch_failed`. Successful
  installs are removed by `cleanup_staged_installers` on the next start (the
  installer cannot delete its own running file).
- Frontend additionally: major-version bump requires a second `confirm()`;
  auto-check is delayed 4s post-launch, fails silent offline, and only ever
  renders a dismissible banner.

## Provenance (current limits)

- Today's gate is **signature + version + host + hash**. CI now runs
  `npm audit` and the RustSec audit, and publishes CycloneDX SBOMs for both
  dependency graphs (see `docs/RELEASE_SECURITY.md`).
- Installers are published **unsigned**; SmartScreen warns on first install.
  The release publishes SHA-256 checksums and build-provenance attestations so
  users can verify the download. A release must never claim a signed publisher
  identity unless `signtool verify /pa` actually passed.
- Full provenance (SLSA attestations / reproducible builds) is out of scope
  for this pre-1.0 build. The design accepts it without changing the client
  flow.
- On suspected compromise: rotate GitHub credentials, revoke/rotate the
  signing key per above, publish an out-of-band notice, and treat any
  installer downloaded before rotation as untrusted.

## Threats explicitly not solved

- Endpoint already compromised while unlocked (same as vault threat model).
- User ignoring the banner and running an unverified binary fetched manually.
- GitHub API availability (check fails closed: no banner, no download).
