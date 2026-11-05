# Design Decisions

This document records the current design choices behind Keevra. It is not a
history: superseded ideas are removed rather than kept as a changelog.

## Product model

**Decision:** a flat account directory.

`Account { id, name, service, tags[], fields[] }` is the whole model. `service`
is a label, not an entity; an empty service groups under **Other**. No field is
required, so the smallest valid record is a single name.

**Why:** the recurring task is lookup — which account do I have on this
service, and what belongs to it? A flat list grouped by service serves that
task directly.

## Storage

**Decision:** one encrypted vault file per vault, plus encrypted sidecar blobs.

The vault is a single file chosen by the user. Attachments live beside it as
`<vault>.attachments/<id>.bin`. A plaintext registry (`vaults.json`) maps
display names to random UUID filenames, and `settings.json` remembers the
default vault.

**Why:** a single file is easy to back up, move, and reason about. Random
filenames avoid leaking purpose or owner. The registry must be readable before
unlock, so it holds only display metadata.

## Cryptography

**Decision:** Argon2id + XChaCha20-Poly1305, envelope v1.

- Argon2id: m = 65536 KiB, t = 3, p = 1, 32-byte output, fresh 16-byte salt.
- XChaCha20-Poly1305: fresh 24-byte nonce per save.
- The versioned header is bound as associated data.
- Stored KDF parameters are honored on open within DoS bounds.

**Why:** a memory-hard KDF resists offline guessing of a stolen vault file;
an AEAD with a large nonce makes accidental reuse impractical. The master key
exists only in zeroized Rust memory and is cleared on lock.

## IPC and file access

**Decision:** a narrow Tauri command surface; Rust owns crypto and filesystem.

The React frontend never holds the password or key. It passes the password only
inside the create/open call. Filesystem access stays in Rust; the only plugins
are dialog path pickers.

**Why:** keeping secrets and file access out of the WebView limits the impact of
a frontend bug.

## Vault document

**Decision:** schema v3, validated in TypeScript, opaque in Rust.

The encrypted document contains `schemaVersion`, `accounts`, `presets`,
`attachments`, and an optional `serviceIcons` map. Rust treats it as a
transparent JSON map and only checks non-empty unique IDs in present
collections. Older documents are migrated in memory on open.

**Why:** Rust does not need to understand product fields, so schema changes do
not require backend changes. Unknown keys round-trip instead of being lost.

## UI

**Decision:** two panes, auto-save, undo/redo.

The directory holds search, one add row, and accounts grouped by service. The
detail pane edits the selected account. Edits save on blur or after a short
pause; undo and redo cover the whole vault. There is no separate Save button.

**Why:** the directory is the product; a second navigation layer would hide it.
Auto-save removes a common failure mode, and undo makes it safe.

## Attachments and packages

**Decision:** encrypted sidecar blobs and a single-file encrypted package.

Each attachment is its own XChaCha20-Poly1305 envelope with the attachment ID as
associated data. A save-time sweep removes only blobs that are no longer
reachable from the live document, the verified backup, or undo/redo history.
A package bundles the vault envelope and every blob into one JSON file for
export/import.

**Why:** large files should not inflate the main vault file, and a single
package is the simplest portable backup.

## Updater

**Decision:** notify-only, consent-gated, signature-verified.

The app checks GitHub releases, shows a banner, and downloads only after a
click. The manifest is verified with an offline ed25519 key before any download;
the installer never runs automatically.

**Why:** an update channel should not become a silent remote-code path.

## Brand

**Decision:** warm paper, ink, one persimmon accent, serif wordmark, 3D icon.

The app icon is the original 3D artwork recolored to persimmon; the wordmark is
Palatino/Georgia. Light and dark variants follow the app theme.

**Why:** the identity should match the interface, not a separate marketing skin.

## Testing

**Decision:** Vitest unit tests for domain modules, Rust unit tests for the
backend, and a production build check in CI.

**Why:** the domain logic is pure and fast to test; crypto and file handling are
covered on the Rust side. UI smoke tests are run manually before a release.

## Non-goals

- Cloud sync, sharing, multi-user access, or a server component.
- Graph features (canvas, relationships, layout, minimap).
- A hosted account system or browser extension.
