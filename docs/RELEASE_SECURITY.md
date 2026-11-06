# Release Security

This document covers build provenance and Windows binary signing. The update
channel itself (manifest signature, host allow-list, hash check) is documented
in `docs/UPDATER_SECURITY.md`.

## Current status

| Control | Status |
| --- | --- |
| Locked dependency builds (`npm ci`, `cargo --locked`) | Enforced in CI and in the release job |
| `npm audit --audit-level=high` | Enforced in CI and in the release job |
| `cargo audit` against the RustSec advisory database | Enforced in CI (`supply-chain` job) and in the release job |
| CycloneDX SBOM for npm and Rust dependencies | Produced per CI run and per release |
| Weekly dependency and action updates | `.github/dependabot.yml` |
| Authenticode signature on the installer and executable | **Hard release gate** in `.github/workflows/release.yml`; releases fail until the certificate secrets are configured |
| Build provenance / SBOM attestations | Generated per release with `actions/attest-build-provenance` and `actions/attest` |
| Reproducible builds | Not implemented (tracked as a future improvement) |

## Code signing is a hard release gate

`.github/workflows/release.yml` runs on `v*.*.*` tags and refuses to build an
installer when either secret below is missing. There is deliberately **no
unsigned release path**: a release that cannot be signed fails instead of
publishing a binary whose publisher cannot be verified.

Required repository secrets:

1. `WINDOWS_CERT_BASE64` — the OV/EV Windows code-signing certificate exported
   as `.pfx` and base64-encoded. Keep the source `.pfx` and its password in a
   password manager or HSM, not in the repository.
2. `WINDOWS_CERT_PASSWORD` — the `.pfx` export password.

(`TAURI_SIGNING_PRIVATE_KEY` is **not** this: that is the offline updater key,
which must never enter CI.)

The workflow imports the certificate into the runner's `CurrentUser\My` store,
passes `bundle.windows.certificateThumbprint`, `digestAlgorithm` and
`timestampUrl` to Tauri through a generated config, builds, and then verifies
both binaries:

```powershell
signtool verify /pa /v src-tauri\target\release\keevra.exe
signtool verify /pa /v src-tauri\target\release\bundle\nsis\Keevra_<version>_x64-setup.exe
```

A verification failure aborts the job. The imported certificate is removed in
an `always()` step.

Local development builds made with `npm run tauri build` are still unsigned.
They must never be distributed; only the signed release artifacts may be
published.

### EV certificate / cloud HSM

EV certificates often cannot be exported as a `.pfx`. For those, replace the
`--config` signing block with Tauri's `signCommand` (or a cloud signing
provider's CLI) and keep the same gate: the release job must fail unless the
signature verifies. The rest of the pipeline (SBOM, attestation, draft
release) is unchanged.

## SBOMs and provenance

Every CI run publishes two CycloneDX documents:

- `keevra-npm-sbom.cdx.json` — frontend dependency inventory.
- `keevra-rust-sbom.cdx.json` — Rust/Tauri dependency inventory.

The release job additionally creates a Sigstore-backed attestation for every
release artifact (`actions/attest-build-provenance@v2`) and an SBOM
attestation (`actions/attest@v4`). Maintainers can verify an artifact with:

```powershell
gh attestation verify Keevra_<version>_x64-setup.exe --repo Moltrax8/Keevra
```

Attach both SBOMs to the release, or keep the CI artifact for at least as long
as the release is supported. They are the inventory used when a new advisory
needs to be matched against shipped versions.

## Release checklist

1. CI (including the `supply-chain` job) is green on the release commit.
2. Bump the version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json`, then push a `v<version>` tag. The release job
   aborts if the tag and the three version files disagree.
3. Confirm the workflow verified the Authenticode signature on both the app
   executable and the installer.
4. Download `updates.unsigned.json` from the draft release, sign it **offline**
   with the updater key, and upload `updates.json` + `updates.json.minisig`.
   Never publish `updates.unsigned.json` as the manifest.
5. Verify the draft release contains the signed installer, both SBOMs and the
   attestations; then publish.
6. Run the tamper drill from `docs/UPDATER_SECURITY.md` before announcing.

## Threat model limits

- A compromised GitHub account can still publish a *new* signed release if it
  also obtains the offline updater key. Authenticode reduces first-install
  impersonation but does not fix key custody.
- A compromised developer or CI runner can inject code before signing. Build
  provenance makes the origin auditable; reproducible builds are the stronger
  mitigation and are not implemented yet.
