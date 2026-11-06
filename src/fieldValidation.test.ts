import { describe, expect, it } from "vitest";
import type { Account, FieldType } from "./domain";
import { createField, isValidFieldValue, updateField } from "./fieldOperations";

function account(id: string): Account {
  return { id, name: id, service: "", tags: [], fields: [] };
}

const ALL_TYPES: readonly FieldType[] = [
  "Text",
  "Username",
  "Password",
  "Email",
  "Phone",
  "URL",
  "Note",
  "Secret",
  "Expiry",
  "PIN",
  "TOTP",
  "RecoveryCodes",
];

describe("isValidFieldValue", () => {
  it("accepts empty values for every type", () => {
    for (const type of ALL_TYPES) {
      expect(isValidFieldValue(type, "")).toBe(true);
    }
  });

  it("validates PIN as 4-12 digits", () => {
    expect(isValidFieldValue("PIN", "1234")).toBe(true);
    expect(isValidFieldValue("PIN", "000000000000")).toBe(true);
    expect(isValidFieldValue("PIN", "123")).toBe(false);
    expect(isValidFieldValue("PIN", "1234567890123")).toBe(false);
    expect(isValidFieldValue("PIN", "12a4")).toBe(false);
  });

  it("validates Expiry as a real YYYY-MM-DD calendar date", () => {
    expect(isValidFieldValue("Expiry", "2027-02-28")).toBe(true);
    expect(isValidFieldValue("Expiry", "2024-02-29")).toBe(true);
    expect(isValidFieldValue("Expiry", "2023-02-29")).toBe(false);
    expect(isValidFieldValue("Expiry", "2027-13-01")).toBe(false);
    expect(isValidFieldValue("Expiry", "2027-04-31")).toBe(false);
    expect(isValidFieldValue("Expiry", "tomorrow")).toBe(false);
  });

  it("rejects invalid values on create and update", () => {
    expect(createField([account("a")], "a", "f-1", "PIN", "PIN", "12")).toEqual({
      ok: false,
      error: { code: "invalid_field_value", fieldId: "f-1" },
    });
    const accounts = [account("a")];
    const created = createField(accounts, "a", "f-2", "Expires", "Expiry", "2027-01-01");
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("setup failed");
    const withField: Account[] = [{ ...account("a"), fields: [created.field] }];
    expect(updateField(withField, "a", "f-2", { value: "not-a-date" })).toEqual({
      ok: false,
      error: { code: "invalid_field_value", fieldId: "f-2" },
    });
    expect(updateField(withField, "a", "f-2", { type: "PIN", value: "12" })).toEqual({
      ok: false,
      error: { code: "invalid_field_value", fieldId: "f-2" },
    });
  });
});
