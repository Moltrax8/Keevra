/**
 * Tags are free-form labels on an account — an owner, a school, a region.
 * They replace the graph's "ownership" relationships with something a user
 * can type in one keystroke.
 *
 * Normalisation is deliberately simple and lives here only: trim, collapse
 * inner whitespace, drop empties, and de-duplicate case-insensitively so
 * "Owner" and "owner" are the same tag.
 */

export function normalizeTag(raw: string): string {
  return raw.trim().replace(/\s+/g, " ");
}

/** Trimmed, non-empty, case-insensitively unique, original casing kept. */
export function normalizeTags(tags: readonly string[]): string[] {
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const raw of tags) {
    const tag = normalizeTag(raw);
    if (tag === "") continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    normalized.push(tag);
  }
  return normalized;
}

/** Appends one tag; re-adding an existing tag is a no-op. */
export function addTag(tags: readonly string[], raw: string): string[] {
  return normalizeTags([...tags, raw]);
}

/** Case-insensitive removal; an unknown tag is a no-op. */
export function removeTag(tags: readonly string[], raw: string): string[] {
  const key = normalizeTag(raw).toLowerCase();
  return normalizeTags(tags).filter((tag) => tag.toLowerCase() !== key);
}

/** True when the account carries every selected tag (empty filter matches all). */
export function matchesTags(tags: readonly string[], selected: readonly string[]): boolean {
  if (selected.length === 0) return true;
  const present = new Set(normalizeTags(tags).map((tag) => tag.toLowerCase()));
  return normalizeTags(selected).every((tag) => present.has(tag.toLowerCase()));
}
