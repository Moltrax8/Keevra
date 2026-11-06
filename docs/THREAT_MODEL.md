# Threat Model

Keevra is a local-only Windows desktop secrets manager. This document is the
security design authority for Keevra. Anything here marked *deferred* is an
explicit non-goal with a reason, not an oversight.

## Assets

- Field values (passwords, secrets, TOTP seeds, recovery codes, attachment bytes and file names), account names, service labels, tags, and preset definitions — all treated as sensitive. Attachment blobs are opaque without the master key; file names stay inside the encrypted vault plaintext.
- The password-derived master key while unlocked (Rust memory only).
- Backup copies of the vault file.

## Adversaries and scope

In scope:

- **Offline vault-file theft** (lost/stolen device, backup exfiltration). Primary
  design driver: the vault file at rest must resist offline guessing via a
  memory-hard KDF plus authenticated encryption.
- **Another local user without file access.** OS file permissions are the
  boundary; the vault directory is created with user-only access where the
  platform supports it.
- **Casual observation / accidental exposure.** Masked secret display with
  explicit reveal; generated TOTP codes are masked too and an explicit reveal
  expires after 15 seconds or when the window loses focus/tab visibility, so a
  valid 2FA code is not left on screen during sharing or when looking away.
  No secrets in logs/panic messages/crash output, generic unlock-failure
  errors. TOTP codes assume a correct device clock; copied secrets are cleared
  from the OS clipboard after 30 seconds and on lock, but only when the
  clipboard still contains the value Keevra copied.
- **Interrupted writes and corruption.** Atomic save + verified backup + manual
  restore path; never silently roll back.

Out of scope (documented, not ignored):

- Attacker executing code as the same user while unlocked (commodity malware
  with full user context). A WebView app cannot defend here; the mitigation is
  minimizing plaintext lifetime (auto-lock, lock-on-demand, Rust-held keys).
- Cold memory forensics on an unlocked machine. Best effort: keys live only in
  Rust as `Zeroizing` buffers, cleared on lock; JS-side plaintext is an
  accepted limitation of the WebView architecture and is documented to users.
- Supply-chain compromise of crates/npm beyond pinning (`Cargo.lock`,
  `package-lock.json`) plus periodic `npm audit` / `cargo audit` review.

## Accepted decisions

- **KDF:** Argon2id (`argon2` crate), m = 65536 KiB, t = 3, p = 1, 32-byte
  output, fresh 16-byte random salt per vault, parameters stored in the file
  header (versioned for future tuning). Stored parameters are honored on open
  within a bounded computation budget — 256 MiB memory, 6 passes, 4 lanes —
  so older vaults keep opening at their original cost while a hostile header
  cannot freeze the unlock path or force a multi-gigabyte allocation. A vault
  above the budget is refused with the same generic corruption error rather
  than being opened at attacker-chosen cost. In-app unlock throttling
  (progressive 1–5 s delays) only slows manual guessing on the device — it
  cannot slow offline guessing of a stolen file, which is exactly what the
  KDF parameters defend against. New vault passwords require ≥12 characters.
- **AEAD:** XChaCha20-Poly1305 (`chacha20poly1305` crate), fresh 24-byte random
  nonce per save. Plaintext is canonical JSON `{ schemaVersion, accounts,
  presets, attachments }`.
  The file header (version + KDF parameters) is bound as associated data so
  parameters cannot be silently swapped.
- **Envelope v1 (JSON):** `{ version: 1, kdf: { alg, m, t, p, salt_b64 },
  nonce_b64, ciphertext_b64 }`. Unknown major versions are refused, never
  migrated implicitly.
- **Key hierarchy v1:** single password-derived master key encrypts the whole
  vault. Per-item keys are deferred; the format versions cleanly for them.
- **Key custody:** the master key exists only in the Rust process inside
  `Mutex<Option<Zeroizing<[u8; 32]>>>`, set on create/open, cleared on lock.
  The frontend never stores the password or key; it passes the password only
  inside the create/open invoke call.
- **Vault registry (`vaults.json` + `settings.json`):** display names map to random-UUID vault filenames so filenames never reveal purpose or owner. The mapping, optional password hints, and the default-vault choice are plaintext beside the vaults by necessity (needed before unlock); vault contents stay encrypted regardless. Hints are shown on the login card with a warning that anyone on the device can read them. Forgetting removes the listing only; forgot-password deletion removes file, backup, blobs, listing, and clears a pointing default — unrecoverable by design, so there is no backdoor to abuse.
- **Everything encrypted:** account names, service labels, tags, field values,
  presets, and attachment metadata all live inside the ciphertext. There is no
  plaintext metadata by design, so there is no metadata-leakage classification
  to maintain.
- **Atomicity:** save serializes → encrypts → writes temp file in the same
  directory → flushes → renames over the vault. The previous good vault is
  copied to `vault.bak` before replacement; restore is explicit
  (`vault_restore_backup`), never automatic.
- **Deletion is idempotent and complete.** `vault_delete_vault` removes the
  live file, every retained backup generation, the pre-restore rollback copy
  and the blob directory for an app-managed vault even when an earlier attempt
  already removed the live file. Every target is attempted; if anything
  remains the registry listing is kept and the error names the leftovers, so
  the user can retry instead of being told "deleted" while ciphertext stays on
  disk. Vaults outside the app's data directory are only unlisted, never
  deleted.
- **Attachment sweep fails closed.** Blob cleanup preserves every ID reachable
  from the live document, the verified backup, the pre-restore copy and the
  renderer's undo history. If an existing backup cannot be read or decrypted,
  the sweep is skipped entirely rather than treating it as empty; pending
  imports are tracked per vault path so one vault's sweep cannot clear another
  vault's in-flight blob.
- **Unlock failures** return a generic error, plus a progressive 1–5 s UI
  calm-down between manual attempts. The calm-down cannot slow offline
  guessing of a stolen file, so the KDF parameters — not throttling —
  are the defense.
- **IPC surface (least privilege):** `vault_status`, `vault_list`,
  `vault_create`, `vault_remember`, `vault_forget`, `vault_rename`,
  `vault_delete_vault`, `app_settings_get`, `app_settings_set_default`,
  `vault_open`, `vault_save`, `vault_lock`, `vault_restore_backup`,
  `attachment_import`, `attachment_export`, `attachment_read`,
  `vault_export_package`, `vault_import_package`, `update_verify_manifest`,
  `update_download_manifest_asset`. Filesystem access stays in Rust;
  the only plugins are dialog path-pickers (`dialog:allow-open/save`).
  Document validation stays in TypeScript (`vaultDocument.ts`); Rust treats
  the document as an opaque JSON map and only re-validates non-empty unique
  IDs in present collections.
- **Session:** locked by default. Unlock is per-launch; frontend auto-locks
  after 5 minutes without input and clears account state from memory. Rust
  additionally runs an independent 5-second watchdog that drops the key at a
  15-minute idle backstop, so a suspended or compromised renderer cannot keep
  the master key alive past the policy by simply not sending IPC calls.
- **Logging:** passwords, keys, and plaintext never enter logs, panic strings,
  or error payloads. Errors to the UI are coarse (`wrong_password_or_corrupt`
  deliberately does not distinguish).
- **Distribution:** manual installers, plus a notify-only update check that
  verifies a signed manifest before offering a download. It never installs
  silently and never downloads without explicit user action. Packaging is
  enabled for local test builds. Builds are unsigned by default.
  Update downloads use a custom redirect policy: every hop, not just the first
  URL, must stay on the HTTPS GitHub allow-list, and chains are capped at 10
  hops. Release and CI workflows pin every third-party action to a full
  40-character commit SHA so a moved tag cannot change privileged build steps.

## Exit criteria (all required before real secrets)

1. This model is accepted and committed. ✅ (this file)
2. Primitives come from reviewed crates, never custom crypto. ✅
3. Versioned envelope with bound header, backup, and explicit restore. ✅
4. Key custody documented and implemented (Rust-only, zeroized). ✅
5. IPC surface minimal with default capability. ✅
6. Failure/recovery paths exercised by tests before real-secret use. ✅
7. CSP configured for production. ✅
8. Explicit review sign-off recorded before a public release. ⏳ pending
