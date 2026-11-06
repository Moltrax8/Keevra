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
- The optional **download** performs HTTPS requests to `github.com` release
  asset URLs for `updates.json`, its `.minisig`, and the installer. The
  production CSP allows `api.github.com`, `github.com`, and GitHub
  release-asset hosts for these requests, and nothing else.
- The check runs 4s after launch and can be repeated from Settings; it fails
  silently when offline. There is no other network call in the app.

## Policy

1. The app **never** downloads or installs silently. A banner/Settings entry
   notifies; everything else requires explicit clicks.
2. The download authority is a **signed manifest** (`updates.json` +
   `updates.json.minisig` release assets), not the `.sha256` sidecar.
   SHA-from-GitHub alone proves transit integrity, not publisher — a
   compromised GitHub account could forge both binary and sidecar.
3. The installer is **never launched** by the app. Verified bytes are saved
   via the user's own save dialog; the user runs the installer manually.
4. Unsigned releases get **no download button** — release page only.

## Keys

- Algorithm: ed25519 (`ed25519-dalek`), signatures base64-encoded (minisig style).
- Public key(s) baked in `src-tauri/src/update_keys.rs`. Private keys live
  **offline** with the release manager; they never enter git, CI, or Supabase.
- Key 0 (`qIa4woC9NAQ0…`, full value in `update_keys.rs`): generated
  2026-10-05 via `cargo run --manifest-path tools/update-tool/Cargo.toml -- gen-key`
  on the release manager machine.
- Rotation: append the new public key to `UPDATE_SIGNING_KEYS` (verify
  accepts any listed key), publish one release signed by **both** keys
  (two `.minisig` assets or dual-sign window per release notes), then remove
  the old key in the following release. Emergency revocation = release
  removing the compromised key + rotating the GitHub token + publishing a
  `REVOKED` note users can verify out-of-band.

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
5. Smoke test: fresh machine, Settings → Check → Download → mismatch drill
   (tampered manifest must refuse with signature error).

## Verification (client)

- Rust `updates::parse_verified_manifest`: ed25519 verify over exact
  manifest bytes against any baked key → parse → validate shape (filesafe
  names, 64-hex SHAs) — in `update_verify_manifest`.
- `download_manifest_asset`: re-verifies manifest, enforces
  strictly-newer version (`update_not_newer` otherwise — downgrades refused),
  binds installer basename to a manifest asset
  (`update_asset_not_in_manifest` otherwise), downloads over HTTPS from
  GitHub hosts only, compares SHA, atomic save only on match.
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
