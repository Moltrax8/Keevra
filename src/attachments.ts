import type { AttachmentMeta } from "./domain";

/** Per-file cap enforced by the backend (25 MiB). */
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

export function formatBytes(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  const kb = sizeBytes / 1024;
  if (kb < 1024) return `${Number.isInteger(kb) ? kb : kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${Number.isInteger(mb) ? mb : mb.toFixed(1)} MB`;
}

/** Defense-in-depth check on backend-returned metadata before trusting it. */
export function isAttachmentMeta(value: unknown): value is AttachmentMeta {
  if (value === null || typeof value !== "object") return false;
  const meta = value as Record<string, unknown>;
  return (
    typeof meta.id === "string" &&
    meta.id.trim().length > 0 &&
    typeof meta.nodeId === "string" &&
    meta.nodeId.trim().length > 0 &&
    typeof meta.fileName === "string" &&
    meta.fileName.trim().length > 0 &&
    typeof meta.mimeType === "string" &&
    Number.isInteger(meta.sizeBytes) &&
    (meta.sizeBytes as number) >= 0 &&
    (meta.sizeBytes as number) <= MAX_ATTACHMENT_BYTES &&
    typeof meta.sha256Hex === "string" &&
    /^[0-9a-f]{64}$/.test(meta.sha256Hex) &&
    typeof meta.createdAtMs === "number"
  );
}
