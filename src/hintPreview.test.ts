import { describe, expect, it } from "vitest";
import { HINT_FAILURE_THRESHOLD, shouldShowHint } from "./display";
import { isPreviewableMime, previewBlockedReason } from "./components/AttachmentPreview";

describe("hint gating", () => {
  it("hides hints until the failure threshold", () => {
    expect(HINT_FAILURE_THRESHOLD).toBe(2);
    expect(shouldShowHint(0)).toBe(false);
    expect(shouldShowHint(1)).toBe(false);
    expect(shouldShowHint(2)).toBe(true);
    expect(shouldShowHint(5)).toBe(true);
  });
});

describe("attachment preview policy", () => {
  it("allows JPEG/PNG/WebP/GIF only", () => {
    expect(isPreviewableMime("image/jpeg")).toBe(true);
    expect(isPreviewableMime("image/png")).toBe(true);
    expect(isPreviewableMime("image/webp")).toBe(true);
    expect(isPreviewableMime("image/gif")).toBe(true);
    expect(isPreviewableMime("application/pdf")).toBe(false);
    expect(isPreviewableMime("text/html")).toBe(false);
    expect(isPreviewableMime("image/svg+xml")).toBe(false);
  });

  it("blocks HTML/SVG explicitly", () => {
    expect(previewBlockedReason("text/html")).toContain("blocked");
    expect(previewBlockedReason("image/svg+xml")).toContain("blocked");
    expect(previewBlockedReason("image/png")).toBe(null);
  });
});
