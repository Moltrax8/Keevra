# Contributing

Keevra is a small, pre-1.0, local-first desktop app. Contributions are welcome,
but the product is deliberately narrow: a flat account directory, not a graph,
sync service, or cloud password manager.

## Before you start

- Open an issue for anything larger than a bug fix or documentation correction.
- Do not add cloud sync, sharing, telemetry, analytics, a hosted service, or a
  mobile/browser client without a written design decision.
- Security changes need a matching update to `docs/THREAT_MODEL.md` and tests.

## Development

Requirements: Node.js 22+, Rust stable, Windows MSVC build tools, and WebView2.

```powershell
npm ci
npm test
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

## Pull requests

- Keep changes focused and match the existing structure, naming, and style.
- Add or update tests for behavior changes.
- Run the checks above before opening the PR.
- Never commit vault files, attachment stores, PFX/PEM/key files, logs, or
  absolute local paths.
- Do not weaken the CSP, IPC surface, updater checks, or encryption format
  without a documented reason.

## Security

Do not report vulnerabilities in a public issue. See [SECURITY.md](SECURITY.md).
