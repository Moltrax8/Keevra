# Changelog

All notable changes to Keevra are recorded here, newest first.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Keevra is pre-1.0 and does not use Semantic Versioning yet.

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
