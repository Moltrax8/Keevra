# Roadmap

Keevra is pre-1.0. The list is intentionally short: the directory should be
used in practice before it grows.

## Now

- [x] Flat account directory with service grouping, tags, and optional fields.
- [x] Encrypted local vault (Argon2id + XChaCha20-Poly1305), lock screen,
      auto-save, undo/redo, and a 5-minute inactivity auto-lock.
- [x] Encrypted attachments and portable encrypted packages.
- [x] Notify-only, signature-verified update check.
- [x] Warm paper theme in light and dark, with the 3D persimmon brand kit.

## Next

- Live-use the directory for a week; fix what actually hurts.
- Hand it to a few testers and watch first-use friction before adding features.
- Keep the encrypted format and key custody stable across releases.

## Deliberately not planned

- Sync, shared vaults, multi-user access, or any server component. The model is
  one person, one machine, one encrypted file.
- Graph features of any kind (canvas, relationships, layout, minimap).
- Large feature work before the directory has been used in practice.
