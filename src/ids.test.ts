import { describe, expect, it } from "vitest";
import { newAccountId, newAttachmentId, newFieldId, newPresetId } from "./ids";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe("ids", () => {
  it("generates unique UUIDv4 account IDs", () => {
    const ids = new Set([newAccountId(), newAccountId(), newAccountId()]);
    expect(ids.size).toBe(3);
    for (const id of ids) expect(id).toMatch(uuid);
  });

  it("generates unique UUIDv4 field IDs", () => {
    const ids = new Set([newFieldId(), newFieldId(), newFieldId()]);
    expect(ids.size).toBe(3);
    for (const id of ids) expect(id).toMatch(uuid);
  });

  it("generates unique UUIDv4 preset IDs", () => {
    const ids = new Set([newPresetId(), newPresetId(), newPresetId()]);
    expect(ids.size).toBe(3);
    for (const id of ids) expect(id).toMatch(uuid);
  });

  it("generates unique UUIDv4 attachment IDs", () => {
    expect(newAttachmentId()).toMatch(uuid);
    expect(newAttachmentId()).not.toBe(newAttachmentId());
  });
});
