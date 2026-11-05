/**
 * Per-service pictures.
 *
 * A service is only a label, so its picture is stored next to the label in the
 * vault document as a small data URL (`serviceIcons[service]`). Nothing leaves
 * the encrypted vault and no attachment bookkeeping is involved: a 128px
 * picture is a few kilobytes of JSON.
 */

/** Longest edge kept after resizing; enough for the 40px hero avatar. */
export const SERVICE_ICON_MAX_EDGE = 128;

/** Refuse absurd inputs before decoding them. */
export const SERVICE_ICON_MAX_INPUT_BYTES = 8 * 1024 * 1024;

/** Guard the vault against a pathological data URL. */
export const SERVICE_ICON_MAX_LENGTH = 400_000;

const DATA_URL = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

export function isServiceIconDataUrl(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= SERVICE_ICON_MAX_LENGTH &&
    DATA_URL.test(value)
  );
}

/** Drops blank keys and anything that is not a small raster data URL. */
export function normalizeServiceIcons(value: unknown): Record<string, string> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
  const icons: Record<string, string> = {};
  for (const [rawService, icon] of Object.entries(value as Record<string, unknown>)) {
    const service = rawService.trim();
    if (service === "" || !isServiceIconDataUrl(icon)) continue;
    icons[service] = icon;
  }
  return icons;
}

/** The picture for a service label, or null for "Other" / unset services. */
export function serviceIconFor(
  icons: Readonly<Record<string, string>>,
  service: string,
): string | null {
  const label = service.trim();
  if (label === "") return null;
  return icons[label] ?? null;
}

/**
 * Carries a service picture across a service-label rename. The old key is
 * removed; an existing picture under the new label wins over the moved one.
 */
export function moveServiceIcon(
  icons: Readonly<Record<string, string>>,
  from: string,
  to: string,
): Record<string, string> {
  const oldKey = from.trim();
  const newKey = to.trim();
  if (oldKey === "" || newKey === "" || oldKey === newKey || icons[oldKey] === undefined) {
    return { ...icons };
  }
  const next = { ...icons };
  if (next[newKey] === undefined) next[newKey] = next[oldKey];
  delete next[oldKey];
  return next;
}

/**
 * Reads a picked image and returns a square-ish PNG data URL no larger than
 * `SERVICE_ICON_MAX_EDGE`. Browser-only.
 */
export async function readServiceIconFile(file: File): Promise<string> {
  if (!file.type.startsWith("image/")) {
    throw new Error("Choose an image file (PNG, JPEG or WebP).");
  }
  if (file.size > SERVICE_ICON_MAX_INPUT_BYTES) {
    throw new Error("That picture is larger than 8 MB. Pick a smaller one.");
  }

  const bitmap = await createImageBitmap(file).catch(() => {
    throw new Error("Could not read that picture. Try a PNG or JPEG.");
  });

  try {
    const scale = Math.min(1, SERVICE_ICON_MAX_EDGE / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));

    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    if (context === null) throw new Error("Could not prepare that picture.");
    context.drawImage(bitmap, 0, 0, width, height);

    const dataUrl = canvas.toDataURL("image/png");
    if (!isServiceIconDataUrl(dataUrl)) {
      throw new Error("That picture is too detailed. Try a smaller one.");
    }
    return dataUrl;
  } finally {
    bitmap.close();
  }
}
