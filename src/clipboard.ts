/**
 * Clipboard helpers for secret values.
 *
 * Copied secrets are *attempted* to be wiped after a short delay, but only
 * when the clipboard still contains exactly what we put there. Reads can be
 * denied and Windows clipboard history may keep its own copy, so this is a
 * best-effort mitigation, not a guarantee (K-13).
 */

export const CLIPBOARD_CLEAR_MS = 30_000;

const pendingSecrets = new Set<string>();

async function clearIfStillPresent(secret: string): Promise<void> {
  pendingSecrets.delete(secret);
  try {
    const current = await navigator.clipboard.readText();
    if (current === secret) await navigator.clipboard.writeText("");
  } catch {
    // Clipboard reads may be denied; never clobber unknown content.
  }
}

export async function copySecretWithAutoClear(
  text: string,
  clearAfterMs = CLIPBOARD_CLEAR_MS,
): Promise<void> {
  await navigator.clipboard.writeText(text);
  pendingSecrets.add(text);
  setTimeout(() => void clearIfStillPresent(text), clearAfterMs);
}

/** Best-effort wipe on lock/close for secrets copied recently. */
export async function clearCopiedSecrets(): Promise<void> {
  const secrets = [...pendingSecrets];
  pendingSecrets.clear();
  if (secrets.length === 0) return;
  try {
    const current = await navigator.clipboard.readText();
    if (secrets.includes(current)) await navigator.clipboard.writeText("");
  } catch {
    // Best effort only.
  }
}
