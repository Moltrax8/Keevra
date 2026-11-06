# Changelog

All notable changes to Keevra are recorded here, newest first.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Keevra is pre-1.0 and does not use Semantic Versioning yet.

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
