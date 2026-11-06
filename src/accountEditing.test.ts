import { describe, expect, it } from "vitest";
import type { Account } from "./domain";
import { renameAccount, setAccountService, setAccountTags } from "./accountEditing";

function account(overrides: Partial<Account> = {}): Account {
  return {
    id: "a",
    name: "Main",
    service: "Riot",
    tags: ["Owner"],
    fields: [{ id: "f-1", label: "Password", type: "Password", value: "x" }],
    ...overrides,
  };
}

describe("renameAccount", () => {
  it("renames and trims, preserving service, tags and fields", () => {
    expect(renameAccount([account()], "a", "  Smurf  ")).toEqual({
      ok: true,
      account: {
        id: "a",
        name: "Smurf",
        service: "Riot",
        tags: ["Owner"],
        fields: [{ id: "f-1", label: "Password", type: "Password", value: "x" }],
      },
    });
  });

  it("rejects an empty name and reports a missing account", () => {
    expect(renameAccount([account()], "a", "   ")).toEqual({
      ok: false,
      error: { code: "invalid_account_name", accountId: "a" },
    });
    expect(renameAccount([], "a", "Main")).toEqual({
      ok: false,
      error: { code: "account_not_found", accountId: "a" },
    });
  });
});

describe("setAccountService", () => {
  it("moves an account and allows clearing to Other", () => {
    expect(setAccountService([account()], "a", " Discord ")).toMatchObject({
      ok: true,
      account: { service: "Discord", name: "Main" },
    });
    expect(setAccountService([account()], "a", "")).toMatchObject({
      ok: true,
      account: { service: "" },
    });
  });

  it("reports a missing account", () => {
    expect(setAccountService([], "a", "Riot")).toEqual({
      ok: false,
      error: { code: "account_not_found", accountId: "a" },
    });
  });
});

describe("setAccountTags", () => {
  it("replaces tags with a normalised set", () => {
    expect(setAccountTags([account()], "a", ["School", " school ", "", "Owner"])).toMatchObject({
      ok: true,
      account: { tags: ["School", "Owner"] },
    });
  });

  it("does not mutate inputs", () => {
    const accounts = Object.freeze([account()]);
    const before = structuredClone(accounts);
    setAccountTags(accounts, "a", ["other"]);
    expect(accounts).toEqual(before);
  });
});
