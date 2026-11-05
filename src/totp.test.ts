import { describe, expect, it } from "vitest";
import {
  decodeBase32Seed,
  isValidTotpSeed,
  totpCodeAt,
  totpSecondsRemaining,
} from "./totp";

// RFC 6238 test secret "12345678901234567890" (ASCII) in base32.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp seeds", () => {
  it("validates base32 seeds", () => {
    expect(isValidTotpSeed("")).toBe(true);
    expect(isValidTotpSeed(RFC_SECRET)).toBe(true);
    expect(isValidTotpSeed("jbsw y3dp-eb3w 64tmmq")).toBe(true);
    expect(isValidTotpSeed("short")).toBe(false);
    expect(isValidTotpSeed("!!!!invalid!!!!")).toBe(false);
  });

  it("decodes base32 to the RFC test bytes", () => {
    expect(Array.from(decodeBase32Seed(RFC_SECRET))).toEqual(
      Array.from(new TextEncoder().encode("12345678901234567890")),
    );
    expect(() => decodeBase32Seed("!!!!")).toThrow();
  });

  it.each([
    { time: 59, code: "287082" },
    { time: 1111111109, code: "081804" },
    { time: 1111111111, code: "050471" },
    { time: 1234567890, code: "005924" },
    { time: 2000000000, code: "279037" },
    { time: 20000000000, code: "353130" },
  ])("matches RFC 6238 SHA-1 vectors at $time", async ({ time, code }) => {
    await expect(totpCodeAt(RFC_SECRET, time)).resolves.toBe(code);
  });

  it("reports seconds remaining in the period", () => {
    expect(totpSecondsRemaining(59)).toBe(1);
    expect(totpSecondsRemaining(60)).toBe(30);
    expect(totpSecondsRemaining(89)).toBe(1);
  });
});
