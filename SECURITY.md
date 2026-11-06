# Security Policy

Keevra is pre-1.0 and has not been independently audited. Until a public
release has been reviewed, use fake data only. Do not store primary email,
banking, or other critical credentials.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting:

https://github.com/Moltrax8/Keevra/security/advisories/new

Please include:

- the Keevra version or commit,
- affected component (vault crypto, IPC, updater, attachments, CSP, UI),
- reproduction steps or a proof of concept,
- impact and any known mitigations.

We aim to acknowledge reports within 7 days. This is a small pre-1.0 project,
so timelines are best effort, but validated reports will be fixed before a
public release is promoted.

## Supported versions

Only the latest `main` and the latest published release (when one exists) are
supported. Pre-1.0 releases do not receive backports.

## In scope

- Vault encryption, key derivation, key custody, and save/restore behavior.
- Tauri IPC commands and capability boundaries.
- Updater signature verification, version checks, host allowlist, and download
  handling.
- Attachment encryption, path handling, and preview rendering.
- CSP, secret masking, clipboard clearing, and auto-lock.
- Local file handling that could escape the vault directory.

## Out of scope

- An attacker who already executes code as the same user while the vault is
  unlocked.
- Cold-memory or forensic attacks on an unlocked machine.
- SmartScreen warnings on unsigned builds.
- Vulnerabilities in third-party crates or npm packages that have no reachable
  path in Keevra; dependency advisories are still welcome.

## Disclosure

Please allow time for a fix before public disclosure. Credit is given on
request. There is no bug bounty.
