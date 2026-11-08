# Release Notes Template

The update dialog renders each GitHub release body as structured notes, not as
raw text. The body comes from the `CHANGELOG.md` section for the released
version (composed by `.github/workflows/release.yml`), so the shape below is
the authoring contract for every release.

## Structure the app expects

```md
**A one-line headline describing the main improvement.**

One short paragraph that explains why the release matters to a user.

### New Features

- **Short title.** What the user can now do.

### Improvements

- **Short title.** What got faster, simpler or more polished.

### Bug Fixes

- **Short title.** What was broken and what the fix means for the user.

### Security

- **Short title.** What is safer and why it matters, without exploit details.

### Important Notes

- **Short title.** Compatibility, migration, or an action the user must take.
```

Rules:

- The **first bold line** becomes the headline. Start the changelog section
  with one; otherwise the dialog falls back to `What's new in <version>`.
- The paragraph after the headline becomes the intro.
- `###` headings map to cards automatically: `New Features ✨`,
  `Improvements ⚡`, `Bug Fixes 🐞`, `Security 🔐`, `Important Notes 📌`,
  `Tests & Internals 🧪`, anything else `Other Changes 📝`.
- A bullet that starts with `**Title.**` renders the title bold and the rest
  as the description. Keep item bodies to a few sentences.
- The workflow's "Unsigned build…" / "Draft…" preamble is moved into
  **Important Notes** automatically; the `See docs/…` pointer is stripped in
  the app.
- Version and release date come from the GitHub release itself, so no manual
  date is needed in the changelog.

## Motion and styling

`src/components/ReleaseNotes.tsx` + the `.release-notes*` rules in
`src/App.css` provide the badge, gradient headline, staggered card reveal,
floating emoji and hover lift. All animation is disabled under
`prefers-reduced-motion: reduce`, and colors use theme tokens so light and dark
mode both work.
