/**
 * Recovery-code sets: one code per line, consumed codes prefixed with `x `.
 * Example value: "a1b2-c3d4\nx e5f6-a7b8".
 */

export interface RecoveryCodeEntry {
  code: string;
  used: boolean;
}

const USED_PREFIX = /^x\s+/i;

export function parseRecoveryCodes(value: string): RecoveryCodeEntry[] {
  if (value.trim() === "") return [];
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      if (/^x$/i.test(line)) return { code: "", used: true };
      const used = USED_PREFIX.test(line);
      return { code: used ? line.replace(USED_PREFIX, "").trim() : line, used };
    });
}

export function isValidRecoveryCodes(value: string): boolean {
  if (value.trim() === "") return true;
  const entries = parseRecoveryCodes(value);
  if (entries.length === 0) return false;
  const seen = new Set<string>();
  for (const entry of entries) {
    if (entry.code.length === 0) return false;
    if (seen.has(entry.code)) return false;
    seen.add(entry.code);
  }
  return true;
}

/**
 * Display mask for a recovery code: keeps separators so the shape is
 * recognizable, hides every other character. Never used for storage.
 */
export function maskRecoveryCode(code: string): string {
  return code.replace(/[^\s-]/g, "•");
}

export function serializeRecoveryCodes(entries: readonly RecoveryCodeEntry[]): string {
  return entries.map((entry) => (entry.used ? `x ${entry.code}` : entry.code)).join("\n");
}

export type RecoveryConsumeError =
  | { readonly code: "code_not_found"; readonly fieldId: string; readonly entryCode: string }
  | { readonly code: "code_already_used"; readonly fieldId: string; readonly entryCode: string };

export type RecoveryConsumeResult =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly error: RecoveryConsumeError };

/** Marks one unused code as used. Pure and non-mutating. */
export function consumeRecoveryCode(
  fieldId: string,
  value: string,
  entryCode: string,
): RecoveryConsumeResult {
  const entries = parseRecoveryCodes(value);
  const index = entries.findIndex((entry) => entry.code === entryCode);
  if (index < 0) return { ok: false, error: { code: "code_not_found", fieldId, entryCode } };
  if (entries[index].used) {
    return { ok: false, error: { code: "code_already_used", fieldId, entryCode } };
  }
  const next = entries.map((entry, i) => (i === index ? { ...entry, used: true } : entry));
  return { ok: true, value: serializeRecoveryCodes(next) };
}
