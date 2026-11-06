// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { Account } from "../domain";
import { useAccountEditing } from "./useAccountEditing";

function makeAccount(): Account {
  return {
    id: "acc-1",
    name: "Mail",
    service: "Mail",
    tags: [],
    fields: [
      { id: "field-user", label: "Username", type: "Username", value: "" },
      { id: "field-pass", label: "Password", type: "Password", value: "" },
    ],
  };
}

interface HarnessResult {
  accounts: Account[];
  editing: ReturnType<typeof useAccountEditing>;
}

function useHarness(initial: Account[]): HarnessResult {
  const [accounts, setAccounts] = useState<Account[]>(initial);
  // A stable commit mock: recreating it per render would reset the call count
  // being asserted after the flush.
  const { current: commit } = useRef(vi.fn());
  const editing = useAccountEditing({
    accounts,
    setAccounts,
    selectedAccount: accounts[0] ?? null,
    commit,
  });
  return { accounts, editing };
}

function fieldValue(accounts: Account[], fieldId: string): string | undefined {
  return accounts[0]?.fields.find((field) => field.id === fieldId)?.value;
}

describe("useAccountEditing (K-02)", () => {
  it("keeps both edits when two fields flush in the same tick", () => {
    const { result } = renderHook(() => useHarness([makeAccount()]));

    // Two blur handlers firing in the same commit: with a stale-closure
    // updater the second save would rebuild the account from the pre-edit
    // list and drop the first value.
    act(() => {
      result.current.editing.saveField("acc-1", "field-user", { value: "alice" });
      result.current.editing.saveField("acc-1", "field-pass", { value: "s3cret" });
    });

    expect(fieldValue(result.current.accounts, "field-user")).toBe("alice");
    expect(fieldValue(result.current.accounts, "field-pass")).toBe("s3cret");
  });

  it("rejects an invalid value without touching the document", () => {
    const { result } = renderHook(() => useHarness([makeAccount()]));

    let error: string | null = null;
    act(() => {
      error = result.current.editing.saveField("acc-1", "field-user", { label: "   " });
    });

    expect(error).not.toBeNull();
    expect(fieldValue(result.current.accounts, "field-user")).toBe("");
  });
});
