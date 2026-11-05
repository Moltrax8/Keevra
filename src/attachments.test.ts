import { describe, expect, it } from "vitest";
import { formatBytes, isAttachmentMeta } from "./attachments";

describe("attachments", () => {
  it("formats byte sizes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5 MB");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("validates backend-returned metadata defensively", () => {
    const good = {
      id: "a-1",
      nodeId: "n-1",
      fileName: "doc.pdf",
      mimeType: "application/pdf",
      sizeBytes: 123,
      sha256Hex: "ab".repeat(32),
      createdAtMs: 123,
    };
    expect(isAttachmentMeta(good)).toBe(true);
    expect(isAttachmentMeta({ ...good, sizeBytes: -1 })).toBe(false);
    expect(isAttachmentMeta({ ...good, sha256Hex: "nope" })).toBe(false);
    expect(isAttachmentMeta({ ...good, fileName: "  " })).toBe(false);
    expect(isAttachmentMeta(null)).toBe(false);
    expect(isAttachmentMeta({ ...good, extra: 1 })).toBe(true);
  });
});
