import { describe, expect, it } from "vitest";
import { addTag, matchesTags, normalizeTag, normalizeTags, removeTag } from "./tags";

describe("normalizeTag", () => {
  it("trims and collapses inner whitespace", () => {
    expect(normalizeTag("  school   club ")).toBe("school club");
    expect(normalizeTag("   ")).toBe("");
  });
});

describe("normalizeTags", () => {
  it("drops empties and de-duplicates case-insensitively, keeping first casing", () => {
    expect(normalizeTags(["Owner", " owner ", "", "school", "SCHOOL", "okul"])).toEqual([
      "Owner",
      "school",
      "okul",
    ]);
  });
});

describe("addTag / removeTag", () => {
  it("adding an existing tag is a no-op", () => {
    expect(addTag(["Owner"], " owner ")).toEqual(["Owner"]);
    expect(addTag(["Owner"], "okul")).toEqual(["Owner", "okul"]);
  });

  it("removes case-insensitively and ignores unknown tags", () => {
    expect(removeTag(["Owner", "school"], "OWNER")).toEqual(["school"]);
    expect(removeTag(["Owner"], "missing")).toEqual(["Owner"]);
  });
});

describe("matchesTags", () => {
  it("requires every selected tag, case-insensitively", () => {
    expect(matchesTags(["Owner", "school"], [])).toBe(true);
    expect(matchesTags(["Owner", "school"], ["owner"])).toBe(true);
    expect(matchesTags(["Owner", "school"], ["Owner", "school"])).toBe(true);
    expect(matchesTags(["Owner"], ["Owner", "school"])).toBe(false);
  });
});
