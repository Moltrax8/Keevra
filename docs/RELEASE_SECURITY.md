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
| Authenticode signature on the installer and executable | **Not used.** Installers are published unsigned; SmartScreen warns "unknown publisher" |
| SHA-256 checksums for published artifacts | `SHA256SUMS.txt` attached to every release |
| Build provenance / SBOM attestations | Generated per release with `actions/attest-build-provenance` and `actions/attest` |
| Reproducible builds | Not implemented (tracked as a future improvement) |

## Unsigned release policy

The project does not use a paid code-signing certificate. Installers are built
from the tagged source in CI and published **unsigned**. This is a deliberate,
documented trade-off:

- Windows SmartScreen shows an "unknown publisher" warning on first run. The
  user must choose **More info → Run anyway**.
- There is no publisher identity in the binary. Trust comes from the published
  SHA-256 checksums, the GitHub build-provenance attestation, and the fact that
  the installer can be rebuilt from the tagged source.
- The app's own cryptography is unaffected: the vault, attachments and update
  manifest verification do not depend on Authenticode.

Users who do not want the SmartScreen warning can build from source with
`npm ci && npm run tauri build`.

### Verifying a download

```powershell
# 1. Hash matches the release's SHA256SUMS.txt
Get-FileHash .\Keevra_<version>_x64-setup.exe -Algorithm SHA256

# 2. The file was built by this repository's release workflow
gh attestation verify .\Keevra_<version>_x64-setup.exe --repo Moltrax8/Keevra
```

Do not install a download whose hash or attestation does not match.

### If a certificate becomes available

The workflow already supports Authenticode. Add these repository secrets and
re-run the release; the same job signs and verifies both binaries before
uploading:

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
an `always()` step. For an EV certificate that cannot be exported as a `.pfx`,
replace the `--config` block with Tauri's `signCommand` (or a cloud signing
provider's CLI) and keep the same verification gate.

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

### Publishing without GitHub Actions

GitHub Actions minutes are not always available. `tools/release-local.ps1`
reproduces the release job on the maintainer's Windows machine: the same gates
(`npm ci`, `npm audit`, `npm test`, `cargo test --locked`, `cargo check
--locked`), the same NSIS build, the same artefacts (`installer`, `keevra.exe`,
`SHA256SUMS.txt`, both CycloneDX SBOMs) and the same offline manifest signing
through `tools/update-tool`.

Those releases are labelled in their notes as built locally. They carry the
checksums, SBOMs and the signed update manifest, but **no Sigstore build
provenance attestation**, because that requires an OIDC identity from Actions.
`gh attestation verify` therefore fails for them by design. When Actions is
available again, prefer the workflow: it adds the attestations.

Signing the manifest remains a separate, offline step in both paths; the
private key never enters the repository, CI, or the release script's output.

## Release checklist

1. CI (including the `supply-chain` job) is green on the release commit.
2. Bump the version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json`, then push a `v<version>` tag. The release job
   aborts if the tag and the three version files disagree.
3. Confirm the release contains the installer, `SHA256SUMS.txt`, both SBOMs and
   the attestations. The installer is unsigned unless the certificate secrets
   are configured; note the SmartScreen warning in the release notes.
4. If you ship an updater-enabled binary, download `updates.unsigned.json`,
   sign it **offline** with the active updater key (key 1 in
   `src-tauri/src/update_keys.rs`), and upload `updates.json` +
   `updates.json.minisig`. Never publish `updates.unsigned.json` as the
   manifest. The private key and its backup stay outside the repository and
   CI.
5. Verify the install on a clean Windows machine and check the SHA-256 matches.
6. Run the tamper drill from `docs/UPDATER_SECURITY.md` before announcing.

## Threat model limits

- **Unsigned installers can be impersonated.** An attacker can rebuild or
  modify a release and host it elsewhere. The defense is the published SHA-256
  checksum and the provenance attestation; users must actually verify them.
- A compromised GitHub account can publish a malicious release. Provenance
  makes the origin auditable, but it does not prove the code is benign.
- A compromised developer or CI runner can inject code before packaging. Build
  provenance makes the origin auditable; reproducible builds are the stronger
  mitigation and are not implemented yet.
