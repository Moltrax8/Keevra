import { describe, expect, it } from "vitest";
import { classifySection, formatReleaseDate, parseReleaseNotes } from "./releaseNotes";

const BODY = `Unsigned build. Windows SmartScreen will warn that the publisher is unknown. See docs/RELEASE_SECURITY.md.

**Cleaner deletes and a faster unlock.** This release tightens cleanup after
partial failures and makes the update notice appear before the vault opens.

### New Features

- **Pre-unlock update notice.** The update dialog now shows on the lock screen.
- **Inline release notes.** Notes are rendered inside the app.

### Improvements

- **Faster unlock.** Key derivation reuses the warm session.

### Fixed

- **Correct cleanup.** Leftover staging files are removed after a crash.

### Security

- **Bounded parsing.** Package imports stop at the size cap.

### Tests

- Regression coverage for the new cleanup paths.
`;

describe("release note parsing", () => {
  it("splits the headline, intro and sections", () => {
    const notes = parseReleaseNotes(BODY, "v0.3.0");

    expect(notes.headline).toBe("Cleaner deletes and a faster unlock.");
    expect(notes.intro).toContain("tightens cleanup after partial failures");
    expect(notes.sections.map((section) => section.kind)).toEqual([
      "notes",
      "features",
      "improvements",
      "fixes",
      "security",
      "technical",
    ]);
  });

  it("turns the workflow's unsigned warning into an important note", () => {
    const notes = parseReleaseNotes(BODY, "v0.3.0");
    const notesSection = notes.sections[0];

    expect(notesSection.kind).toBe("notes");
    expect(notesSection.label).toBe("Important Notes");
    expect(notesSection.items[0]?.body).toContain("SmartScreen");
    expect(notesSection.items[0]?.body).not.toContain("docs/RELEASE_SECURITY.md");
    // The whole reference goes, not just the part before the first dot.
    expect(notesSection.items[0]?.body).not.toContain(".md");
    expect(notesSection.items[0]?.body).not.toMatch(/See docs\//i);
  });

  it("keeps bold item titles and their bodies", () => {
    const features = parseReleaseNotes(BODY, "v0.3.0").sections.find(
      (section) => section.kind === "features",
    );

    expect(features?.items[0]).toEqual({
      title: "Pre-unlock update notice",
      body: "The update dialog now shows on the lock screen.",
    });
  });

  it("falls back to a tag headline when the body has none", () => {
    const notes = parseReleaseNotes("### Fixed\n\n- Something works now.", "v1.2.3");

    expect(notes.headline).toBe("What’s new in 1.2.3");
    expect(notes.intro).toBe("");
    expect(notes.sections[0]?.kind).toBe("fixes");
  });

  it("does not throw on empty or missing bodies", () => {
    expect(parseReleaseNotes(null).sections).toEqual([]);
    expect(parseReleaseNotes("   ").headline).toBe("What’s new");
    expect(parseReleaseNotes(undefined, "v0.2.2").headline).toBe("What’s new in 0.2.2");
  });

  it("classifies headings", () => {
    expect(classifySection("New Features")).toBe("features");
    expect(classifySection("Improvements")).toBe("improvements");
    expect(classifySection("Bug Fixes")).toBe("fixes");
    expect(classifySection("Security")).toBe("security");
    expect(classifySection("Important Notes")).toBe("notes");
    expect(classifySection("Tests")).toBe("technical");
    expect(classifySection("Something else")).toBe("other");
  });
});

describe("release date formatting", () => {
  it("formats an ISO timestamp and tolerates junk", () => {
    expect(formatReleaseDate("2026-11-07T17:31:16Z")).toBe("November 7, 2026");
    expect(formatReleaseDate(null)).toBe("");
    expect(formatReleaseDate("not-a-date")).toBe("");
  });
});
