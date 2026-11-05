/** Secure in-app image preview: decrypt in memory, never temp files. */
import { useEffect, useState } from "react";
import type { AttachmentMeta } from "../domain";
import { attachmentRead } from "../vaultApi";

export const PREVIEWABLE_MIMES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
]);

export function isPreviewableMime(mimeType: string): boolean {
  return PREVIEWABLE_MIMES.has(mimeType.toLowerCase());
}

/** HTML/SVG are never rendered inline (script-capable) — download only. */
export function previewBlockedReason(mimeType: string): string | null {
  const lower = mimeType.toLowerCase();
  if (lower === "text/html" || lower === "image/svg+xml") {
    return "Preview blocked for this file type — download to view.";
  }
  return null;
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function AttachmentPreview({ meta }: { meta: AttachmentMeta }) {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const blocked = previewBlockedReason(meta.mimeType);
  const previewable = isPreviewableMime(meta.mimeType) && blocked === null;

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    if (!previewable) return;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const preview = await attachmentRead(meta.id, meta.sha256Hex);
        if (cancelled) return;
        const blob = new Blob([base64ToBytes(preview.bytesB64).buffer as ArrayBuffer], { type: meta.mimeType });
        objectUrl = URL.createObjectURL(blob);
        setUrl(objectUrl);
      } catch {
        if (!cancelled) setError("Preview failed verification.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      setUrl(null);
    };
  }, [meta.id, meta.sha256Hex, meta.mimeType, previewable]);

  if (blocked) return <p className="hint">{blocked}</p>;
  if (!previewable) {
    return meta.mimeType === "application/pdf" ? (
      <p className="hint">PDF preview coming later — download to view.</p>
    ) : (
      <p className="hint">No inline preview — download to view.</p>
    );
  }
  if (loading) return <p className="hint">Decrypting preview…</p>;
  if (error) return <p className="create-form__error">{error}</p>;
  if (!url) return null;
  return (
    <div className="attachment-preview">
      <img src={url} alt={`Preview of ${meta.fileName}`} loading="lazy" />
      <p className="hint attachment-preview__meta">Decrypted in memory only — never saved as a temp file.</p>
    </div>
  );
}
