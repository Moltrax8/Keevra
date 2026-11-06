import { describe, expect, it } from "vitest";
import type { Account } from "./domain";
import { createAccount } from "./accountCreation";

function account(id: string, name: string = id): Account {
  return { id, name, service: "", tags: [], fields: [] };
}

describe("createAccount", () => {
  it("creates a name-only account with no fields", () => {
    expect(createAccount([], "riot", "owner_xx")).toEqual({
      ok: true,
      account: { id: "riot", name: "owner_xx", service: "", tags: [], fields: [] },
    });
  });

  it("keeps a service and normalises tags", () => {
    expect(createAccount([], "a", "  Main  ", " Riot ", ["Owner", " owner ", "", "school"])).toEqual({
      ok: true,
      account: { id: "a", name: "Main", service: "Riot", tags: ["Owner", "school"], fields: [] },
    });
  });

  it("rejects an empty account ID", () => {
    expect(createAccount([], "  ", "Main")).toEqual({
      ok: false,
      error: { code: "invalid_account_id", accountId: "  " },
    });
  });

  it("rejects a duplicate account ID", () => {
    expect(createAccount([account("riot")], "riot", "Other")).toEqual({
      ok: false,
      error: { code: "duplicate_account_id", accountId: "riot" },
    });
  });

  it("rejects an empty name", () => {
    expect(createAccount([], "riot", "   ")).toEqual({
      ok: false,
      error: { code: "invalid_account_name", accountId: "riot" },
    });
  });

  it("does not mutate inputs", () => {
    const accounts = Object.freeze([account("riot")]);
    const before = structuredClone(accounts);

    expect(createAccount(accounts, "valorant", "Valorant")).toEqual({
      ok: true,
      account: { id: "valorant", name: "Valorant", service: "", tags: [], fields: [] },
    });
    expect(accounts).toEqual(before);
  });
});
