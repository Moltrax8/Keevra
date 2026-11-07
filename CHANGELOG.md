# Changelog

All notable changes to Keevra are recorded here, newest first.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Keevra is pre-1.0 and does not use Semantic Versioning yet.

## [0.2.2] - 2026-11-07

Follow-up to the independent review of `440dfd7`, closing K-01, K-03, N-01,
K-05a and N-02. No format or on-disk schema changes; existing vaults, backups
and packages remain compatible.

### Security

- **Signed update manifest (0.2.2 re-issue).** This build trusts a new offline
  ed25519 update-signing key (key 1) and the release ships `updates.json` +
  `updates.json.minisig`, so the in-app download path is enabled with signature
  and SHA-256 verification. The installer itself remains unsigned for
  Authenticode, so SmartScreen still warns. Users already on the earlier 0.2.2
  build should install this build once manually; the version number is
  unchanged, so it will not appear as an automatic update.
- **Delete retries finish cleanup after a partial failure (K-01).** A managed
  vault's identity is now derived from the resolved parent directory plus the
  file name instead of requiring the live file to exist. A retry after the live
  file was already removed therefore still deletes every backup generation, the
  pre-restore copy and the attachment blob directory. Blob directories are
  removed without following reparse points or junctions, and the listing is
  dropped only when no artifact remains.
- **Attachment writes are pinned to the vault that opened the picker (K-03).**
  The renderer captures the vault path and session generation before the native
  file dialog opens, and the dialog phase itself counts as pending work, so a
  lock or vault switch waits for it. Rust verifies the expected path and
  generation immediately before writing and refuses with `vault_changed`
  instead of writing into a different vault.
- **Package parsing is bounded end to end (K-05a).** Import opens the package
  once, reads the size from that same handle and parses through
  `take(MAX_PACKAGE_BYTES + 1)`. Reaching the cap is a rejection
  (`package_too_large`) even when the leading bytes form valid JSON, so a file
  that grows after the metadata check cannot bypass the ceiling.

### Fixed

- **A corrupt vault registry is no longer treated as an empty list (N-01).**
  Registry reads return a result and only a missing file means "no vaults yet".
  A corrupt or unreadable `vaults.json` is preserved as
  `vaults.json.corrupt-<timestamp>`, writers refuse to overwrite it, and the UI
  reports the problem instead of silently hiding every vault.
- **Crash-leftover import staging is cleaned up (N-02).** Startup and the next
  package import remove `.import-<32 hex>.vault` and
  `.import-<32 hex>.vault.attachments` entries older than one hour without
  traversing reparse points. Fresh staging entries and lookalike user files are
  left untouched.

### Tests

- Regression coverage for managed delete after the live file is gone, registry
  corruption preservation, identity for a missing vault file, package growth
  past the cap (including truncation exactly at the cap), stale staging
  cleanup, and the picker-open vault-switch race.

## [0.2.1] - 2026-11-07

Updater UX release. The update notice now appears before the vault is opened,
the download path no longer opens Settings, and release notes are readable
inside the app.

### Fixed

- **Update notice on the lock screen.** The notice lived inside the unlocked
  layout, so a released version was only announced after unlocking. The update
  dialog is now rendered at the app root and appears on the lock screen as soon
  as the background check finds a newer release.
- **Download no longer opens Settings.** Consent for the download opened the
  Settings dialog and buried the progress text. Progress and verification
  results now stay in the update dialog that asked for consent.
- **Release notes are visible.** `window.open` is unreliable in the Tauri
  WebView, so "Release notes" appeared to do nothing. The release body is shown
  inline in the dialog and a "Copy release link" action copies the release URL
  with visible feedback.
- **Window close is a native close off the unlocked state.** When the vault is
  locked, booting or in demo mode the close request is no longer prevented, so
  the title-bar X works even if an explicit `destroy()` is denied.

### Changed

- **Update decisions in one popup.** A newer release now opens a dialog listing
  what changed with "Download update…" and "Not now", instead of a passive
  banner. Nothing is fetched or installed without the user's consent.
- **Settings update section** reports the same status text as the dialog and
  disables its buttons while a download is in progress.

### Tests

- New `UpdateDialog` coverage: release notes rendered, both decisions wired,
  buttons disabled while busy, and the dialog hidden when no update exists.

## [0.2.0] - 2026-11-06

Security and data-integrity release closing the ten findings (K-01…K-10) of
the independent review of `066b1c3`, plus a window-close fix.

### Security

- **Complete, idempotent vault deletion (K-01).** Deleting an app-managed vault
  now attempts the live file, every backup generation, the pre-restore copy and
  the blob directory regardless of whether the live file still exists. The
  registry listing is kept when any artifact remains, so "deleted" is never
  reported while ciphertext is still on disk.
- **Bounded KDF work on open (K-05).** Stored Argon2id parameters are accepted
  only within 256 MiB / 6 passes / 4 lanes; a hostile header above that budget
  is refused with the generic corruption error instead of freezing or
  over-allocating. Package import is capped at 256 MiB, checked from metadata
  before reading, and parsed straight from a buffered reader so the raw bytes
  and parsed package are not held twice.
- **Fail-closed attachment sweep (K-04).** Backup inspection now distinguishes
  "file absent" from "file unreadable". If an existing backup cannot be
  decrypted, the save-time blob sweep is skipped entirely instead of treating
  the backup as empty and deleting blobs only it references.
- **Pinned workflow actions (K-06).** Every third-party GitHub Action in CI and
  release is pinned to a full 40-character commit SHA.
- **TOTP codes masked by default (K-07).** Generated codes require an explicit
  reveal that expires after 15 seconds and hides on window blur or tab
  visibility loss.
- **Backend session watchdog (K-08).** A Rust thread checks the idle clock every
  5 seconds and drops the key at the 15-minute backstop even when the renderer
  is suspended and sends no IPC.
- **Per-vault pending attachment IDs (K-09).** Pending imports are keyed by
  vault path, so two vaults using the same ID cannot protect or clear each
  other's blobs.
- **Redirect-checked update downloads (K-10).** A custom `reqwest` redirect
  policy re-validates HTTPS and the GitHub host allow-list on every hop and
  caps the chain at 10 redirects.

### Fixed

- **Window close on the lock screen.** The title-bar close button did nothing
  while locked because the `core:window:allow-destroy` permission was missing
  and the prevented close request never called `destroy()`. The permission is
  granted and the handler now explicitly destroys the window in every state.
- **Concurrent field saves no longer lose updates (K-02).** All account-field
  edits are applied inside `setAccounts(current => …)`, so two blur handlers
  flushing in the same tick keep both values instead of rebuilding from a stale
  snapshot.
- **Attachment imports cannot leak across vaults (K-03).** Uploads capture a
  document epoch; a result that returns after open/create/lock is discarded
  instead of being appended to the new document. Lock, close, export, package
  import and settings-create wait for in-flight imports before switching.

### Tests

- New regression coverage for every finding above: partial-delete retry,
  simultaneous field saves, stale import epoch, missing-vs-corrupt backup,
  oversized KDF/package inputs, watchdog expiry, per-vault pending IDs, redirect
  hops, and the close-button path.

## [0.1.0] - 2026-11-06

### Added

- **Account directory.** One record per account: name, service, tags, and any
  optional fields you add (username, password, PIN, expiry, TOTP, recovery
  codes, notes, custom fields). The product model is a flat
  `Account { id, name, service, tags[], fields[] }`; adding is one step (type a
  name, optional service, Enter) and every other field is optional.
- **Service grouping.** Accounts are grouped by service with counts. A service
  can carry an optional picture, stored as a small resized data URL inside the
  encrypted vault.
- **Quick add.** Type a name, optionally a service, press Enter.
- **Auto-save and undo/redo.** Edits commit on blur or after a short pause;
  undo and redo cover the whole vault.
- **Encrypted attachments.** Files are stored beside the vault as encrypted
  blobs under the same session key.
- **Portable packages.** Export and import an encrypted package that includes
  the vault and its attachments.
- **Dark mode.** Settings → Appearance offers Match system, Light and Dark, and
  a sun/moon button in the top bar toggles the two.
- **Warm paper theme.** Paper surfaces, ink text, serif headings, one persimmon
  accent and small offset shadows, in light and dark palettes.
- **Locked by default.** Argon2id-derived key, masked secrets, and a 5-minute
  inactivity auto-lock (save-then-lock).
- **Notify-only updater.** The app checks GitHub releases, shows a banner, and
  downloads only after an explicit click. The manifest is signature-verified
  and the installer never runs automatically.

### Changed

- **Vault schema v3.** The encrypted document contains `schemaVersion`,
  `accounts`, `presets`, `attachments`, and an optional `serviceIcons` map.
  The Rust vault treats the document as an opaque JSON map, so unknown keys
  round-trip and future schema changes do not require a backend change.
- **Two-pane workspace.** The directory (search, one add row, accounts grouped
  by service with counts) sits beside the account detail pane. Details save on
  blur; there is no per-field Save button.
- **Brand wordmarks.** The README uses horizontal dark/light serif wordmarks in
  the app's persimmon palette; the in-app mark ships from `src/assets/`.
- **Unsigned installers.** Windows builds are published without Authenticode;
  SmartScreen warns about an unknown publisher. Each release ships
  `SHA256SUMS.txt` and provenance attestations so the download can be verified.

### Fixed

- Deleting an account or an attachment no longer unlinks the encrypted blob
  immediately: the save-time sweep owns removal and keeps anything reachable
  from undo/redo, so undo restores the attachment intact.
- Lock-screen hints no longer leak their existence: nothing hint-related
  renders until two failed unlocks for that vault.
- Attachment image preview is no longer a broken icon: decrypted-in-memory
  `blob:` URLs are allowed in the image CSP. HTML and SVG stay download-only.
- Stored KDF parameters are honored on open, so older vaults keep working at
  their original cost.
