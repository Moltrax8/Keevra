import { describe, expect, it } from "vitest";
import {
  consumeRecoveryCode,
  isValidRecoveryCodes,
  maskRecoveryCode,
  parseRecoveryCodes,
  serializeRecoveryCodes,
} from "./recoveryCodes";

describe("recovery codes", () => {
  it("parses used and unused entries", () => {
    expect(parseRecoveryCodes("")).toEqual([]);
    expect(parseRecoveryCodes("a1\nx b2\n  X   c3  ")).toEqual([
      { code: "a1", used: false },
      { code: "b2", used: true },
      { code: "c3", used: true },
    ]);
  });

  it("validates sets", () => {
    expect(isValidRecoveryCodes("")).toBe(true);
    expect(isValidRecoveryCodes("a1\nb2")).toBe(true);
    expect(isValidRecoveryCodes("a1\nx b2")).toBe(true);
    expect(isValidRecoveryCodes("a1\na1")).toBe(false);
    expect(isValidRecoveryCodes("a1\nx ")).toBe(false);
  });

  it("masks codes while keeping separator shape", () => {
    expect(maskRecoveryCode("a1b2-c3d4")).toBe("••••-••••");
    expect(maskRecoveryCode("ABC 123")).toBe("••• •••");
    expect(maskRecoveryCode("")).toBe("");
  });

  it("round-trips through serialization", () => {
    const entries = [
      { code: "a1", used: false },
      { code: "b2", used: true },
    ];
    expect(parseRecoveryCodes(serializeRecoveryCodes(entries))).toEqual(entries);
  });

  it("consumes the named unused code", () => {
    expect(consumeRecoveryCode("f-1", "a1\nb2", "b2")).toEqual({ ok: true, value: "a1\nx b2" });
    expect(consumeRecoveryCode("f-1", "x a1", "a1")).toEqual({
      ok: false,
      error: { code: "code_already_used", fieldId: "f-1", entryCode: "a1" },
    });
    expect(consumeRecoveryCode("f-1", "a1", "missing")).toEqual({
      ok: false,
      error: { code: "code_not_found", fieldId: "f-1", entryCode: "missing" },
    });
  });
});
