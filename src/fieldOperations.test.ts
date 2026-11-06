import { describe, expect, it } from "vitest";
import type { Account } from "./domain";
import { createField, removeField, updateField } from "./fieldOperations";

function account(id: string, fields: Account["fields"] = []): Account {
  return { id, name: id, service: "Riot", tags: [], fields };
}

describe("createField", () => {
  it("creates a valid field for an existing account", () => {
    expect(createField([account("riot")], "riot", "f-username", "Username", "Username", "player1")).toEqual({
      ok: true,
      field: { id: "f-username", label: "Username", type: "Username", value: "player1" },
    });
  });

  it("returns account_not_found for a missing account", () => {
    expect(createField([], "missing", "f-1", "Username", "Username", "x")).toEqual({
      ok: false,
      error: { code: "account_not_found", accountId: "missing" },
    });
  });

  it("rejects an empty field ID", () => {
    expect(createField([account("riot")], "riot", "  ", "Username", "Username", "x")).toEqual({
      ok: false,
      error: { code: "invalid_field_id", fieldId: "  " },
    });
  });

  it("rejects a duplicate field ID within the same account", () => {
    const existing = account("riot", [{ id: "f-1", label: "Username", type: "Username", value: "a" }]);

    expect(createField([existing], "riot", "f-1", "Password", "Password", "b")).toEqual({
      ok: false,
      error: { code: "duplicate_field_id", fieldId: "f-1" },
    });
  });

  it("rejects an empty label", () => {
    expect(createField([account("riot")], "riot", "f-1", "   ", "Note", "x")).toEqual({
      ok: false,
      error: { code: "invalid_field_label", fieldId: "f-1" },
    });
  });

  it("does not mutate inputs", () => {
    const accounts = Object.freeze([account("riot")]);
    const before = structuredClone(accounts);

    expect(createField(accounts, "riot", "f-1", "Username", "Username", "x")).toEqual({
      ok: true,
      field: { id: "f-1", label: "Username", type: "Username", value: "x" },
    });
    expect(accounts).toEqual(before);
  });
});

describe("updateField", () => {
  it("applies label/type/value patches while preserving the field ID", () => {
    const accounts = [account("riot", [{ id: "f-1", label: "Username", type: "Username", value: "a" }])];

    expect(updateField(accounts, "riot", "f-1", { value: "b" })).toEqual({
      ok: true,
      field: { id: "f-1", label: "Username", type: "Username", value: "b" },
    });
    expect(updateField(accounts, "riot", "f-1", { label: "Login", type: "Text", value: "" })).toEqual({
      ok: true,
      field: { id: "f-1", label: "Login", type: "Text", value: "" },
    });
  });

  it("reports a missing account and field", () => {
    expect(updateField([], "missing", "f-1", { value: "x" })).toEqual({
      ok: false,
      error: { code: "account_not_found", accountId: "missing" },
    });
    expect(updateField([account("riot")], "riot", "f-9", { value: "x" })).toEqual({
      ok: false,
      error: { code: "field_not_found", accountId: "riot", fieldId: "f-9" },
    });
  });

  it("rejects an empty label update", () => {
    const accounts = [account("riot", [{ id: "f-1", label: "Username", type: "Username", value: "a" }])];

    expect(updateField(accounts, "riot", "f-1", { label: "  " })).toEqual({
      ok: false,
      error: { code: "invalid_field_label", fieldId: "f-1" },
    });
  });
});

describe("removeField", () => {
  it("confirms removal of an existing field", () => {
    const accounts = [account("riot", [{ id: "f-1", label: "Username", type: "Username", value: "a" }])];

    expect(removeField(accounts, "riot", "f-1")).toEqual({ ok: true, removedFieldId: "f-1" });
  });

  it("reports a missing account and field", () => {
    expect(removeField([], "missing", "f-1")).toEqual({
      ok: false,
      error: { code: "account_not_found", accountId: "missing" },
    });
    expect(removeField([account("riot")], "riot", "f-9")).toEqual({
      ok: false,
      error: { code: "field_not_found", accountId: "riot", fieldId: "f-9" },
    });
  });
});
