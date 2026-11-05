# Product Direction

Keevra is a local-first, single-user **account directory**. It exists because
finding an account across the services you use should not mean scrolling
through chat history, a notes app, or a spreadsheet.

## Shape

- One record per account: name, service, tags, and optional fields.
- `service` is a label, not an entity. An empty service groups under **Other**;
  renaming a service is a bulk edit over the accounts that carry it.
- Two panes: the directory (search, one add row, accounts grouped by service)
  and the selected account's detail. Details save themselves.
- No field is required; the smallest valid record is a single name.
- Optional encrypted attachments, TOTP, recovery codes, expiry, and PIN fields.
- Local only: no cloud accounts, sync, telemetry, analytics, or sharing.

## Who it is for

Personal use first: people who keep accounts across games, social platforms,
school, and work, and who want a private local index rather than a cloud
password manager. Keevra is not a feature-for-feature replacement for a full
password manager.

## Security honesty

Keevra is pre-1.0 and has not been independently audited. Encryption is
implemented (Argon2id + XChaCha20-Poly1305), but until a public release has
been reviewed, use **fake data only**.

## Non-goals

- Cloud sync, sharing, collaboration, mobile apps, or browser extensions.
- A hosted service, account system, or server-side component.
- Replacing KeePassXC or 1Password feature-for-feature.
- Security scoring or findings dashboards; the directory stays quiet.

## Next

- Live-use the directory for a week and fix the friction that actually hurts.
- Hand it to a few testers and watch first-use friction before adding features.
- Keep the encrypted format and key custody stable across releases.
