# Architecture

Keevra is a local-first, single-user **account directory**. The whole product
model is one flat list of accounts:

```text
Account { id, name, service, tags[], fields[] }
```

`service` (Discord, Instagram, Riot, …) is a plain label, not an entity. An
empty service groups the account under **Other**, and renaming a service is a
bulk edit over the accounts that carry it. `tags` are free-form labels (owner,
school, region) used for filtering. No field is required: the smallest valid
record is a single name.

The directory is the whole model.

## UI shape

Two panes, nothing else:

1. **Directory** (`AccountList`): one search box, one add row (name + service,
   Enter), then every account grouped under its service with a count. The add
   form is a single row — no multi-step dialog.
2. **Account detail** (`AccountDetail`): identity (name, service, tags) that
   saves on blur, a quick-add row of chips (Password, Username, Email, Note,
   Custom) that creates a detail row in one click, the existing details with
   reveal/copy, attachments, and a two-step delete.

There is no sidebar, no service filter pane, no tag cloud, no preset panel,
no security findings, and no command palette. The list already shows the
services and their accounts, which is the whole point of the product.

Details save when the field loses focus (or on Enter). There is no per-field
Save button and no type dropdown; specialized rows that already exist (TOTP,
recovery codes, expiry) keep their extra rendering. Search matches name,
service, tags, field labels and non-secret values (`matchesQuery` in
`src/display.ts`).

The theme is a warm card catalogue in light and dark (`src/theme.ts`, palette
variables in `src/App.css`); the preference is match-system by default and is
remembered in `localStorage`. A service can carry an optional picture, stored
inline as a resized data URL under `serviceIcons[service]` in the vault
document — still inside the ciphertext, with no extra files.

## Domain modules (pure, no React)

| Module | Responsibility |
| --- | --- |
| `src/domain.ts` | `Account`, `AccountPreset`, `Field`, field types, attachment metadata |
| `src/accountCreation.ts` | create an account (blank IDs/names rejected, duplicates rejected) |
| `src/accountEditing.ts` | rename, change service, set tags |
| `src/fieldOperations.ts` | create/update/remove fields, `isValidFieldValue` |
| `src/tags.ts` | normalize tags, tag matching |
| `src/theme.ts` | light/dark preference, system following, `<html data-theme>` |
| `src/serviceIcons.ts` | validate/normalize per-service pictures, resize a picked file |
| `src/history.ts` | undo/redo snapshots of accounts + presets + attachments + service pictures |
| `src/vaultDocument.ts` | schema v3 document + in-memory migration of older documents |

All domain operations return structured `{ ok, ... }` results; exceptions are
reserved for genuine programming/system failures. Error codes are typed string
literals and carry structured facts — user-facing wording lives in
`src/display.ts`.

## Vault document

Schema v3, encrypted as a whole:

```json
{
  "schemaVersion": 3,
  "accounts": [ ... ],
  "presets": [ ... ],
  "attachments": [ ... ],
  "serviceIcons": { "Riot Games": "data:image/png;base64,..." }
}
```

`serviceIcons` is optional and additive: old files load with `{}`, and a
picture is just a small data URL keyed by the exact service label. Keeping it
in the document means it is encrypted, included in undo snapshots, and travels
with the portable package for free.

Older vault documents are upgraded in memory on open; saving writes v3.
`presets` stays in the schema for compatibility: existing vaults keep whatever
they already had, the collection round-trips untouched, and nothing in the UI
creates or shows presets any more. Removing the key would be a migration with
no user benefit.

## Rust boundary

`src-tauri/src/vault.rs` treats the document as opaque. `GraphData` is a
transparent `serde_json::Map`, so Rust round-trips **any** schema without a
backend change and older vaults stay openable. The only structural check is
`validate_graph`: each present ID collection must contain non-empty, unique
string IDs. Domain semantics stay in TypeScript.

Cryptography: Argon2id (m = 65536 KiB, t = 3, p = 1, fresh 16-byte salt,
stored params honored on open within DoS bounds) + XChaCha20-Poly1305 (fresh
24-byte nonce per save) with the versioned header bound as associated data.
The master key exists only in zeroized Rust session memory.

Attachment blobs live beside the vault as `<vault>.attachments/<id>.bin`,
each its own encrypted envelope with the attachment ID as associated data. A
save-time orphan sweep keeps blobs referenced by the live document, the verified
backup, and undo/redo history.

## Technology

```text
React + TypeScript + Vite
           |
         Tauri 2
           |
          Rust
           |
   encrypted local vault
```

React handles the UI; Tauri 2 provides the Windows shell and IPC; Rust owns
all security-sensitive storage and crypto. No frontend key custody, no
filesystem plugin (dialog path-picking only), and no network in the app path
except the notify-only updater.

Design authority: `docs/THREAT_MODEL.md`.
