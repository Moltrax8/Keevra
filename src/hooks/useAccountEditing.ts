import type { Dispatch, SetStateAction } from "react";
import type { Account, AccountId, FieldId, FieldType } from "../domain";
import { renameAccount, setAccountService, setAccountTags } from "../accountEditing";
import { describeDomainError } from "../display";
import { createField, removeField as removeFieldOp, updateField, type FieldPatch } from "../fieldOperations";
import { newFieldId } from "../ids";

export interface AccountEditingOptions {
  accounts: Account[];
  setAccounts: Dispatch<SetStateAction<Account[]>>;
  selectedAccount: Account | null;
  commit: () => void;
}

export interface AccountEditingApi {
  saveIdentity: (name: string, service: string, tagsText: string) => string | null;
  addField: (label: string, type: FieldType) => { fieldId: FieldId | null; error: string | null };
  saveField: (accountId: AccountId, fieldId: FieldId, patch: FieldPatch) => string | null;
  removeField: (accountId: AccountId, fieldId: FieldId) => string | null;
}

/**
 * Applies a field edit to the *current* account list. Every mutation goes
 * through the functional form of `setAccounts`, so two editors that flush in
 * the same tick can never overwrite each other with a stale closure snapshot
 * (K-02). Validation is repeated against `current`; if the target disappeared
 * meanwhile, the list is returned unchanged.
 */
export function applyFieldEdit(
  accounts: Account[],
  accountId: AccountId,
  fieldId: FieldId,
  patch: FieldPatch,
): Account[] {
  const result = updateField(accounts, accountId, fieldId, patch);
  if (!result.ok) return accounts;
  return accounts.map((account) =>
    account.id === accountId
      ? {
          ...account,
          fields: account.fields.map((field) => (field.id === fieldId ? result.field : field)),
        }
      : account,
  );
}

function replaceAccountIn(current: Account[], updated: Account): Account[] {
  return current.map((account) => (account.id === updated.id ? updated : account));
}

export function useAccountEditing({
  accounts,
  setAccounts,
  selectedAccount,
  commit,
}: AccountEditingOptions): AccountEditingApi {
  function saveIdentity(name: string, service: string, tagsText: string): string | null {
    if (selectedAccount === null) return "Select an account first.";
    const accountId = selectedAccount.id;
    const steps = [
      (list: readonly Account[]) => renameAccount(list, accountId, name),
      (list: readonly Account[]) => setAccountService(list, accountId, service),
      (list: readonly Account[]) => setAccountTags(list, accountId, tagsText.split(",")),
    ];
    // Validate eagerly so the caller gets a synchronous error message. The
    // actual state transition is recomputed from `current` inside the updater.
    let probe: readonly Account[] = accounts;
    for (const step of steps) {
      const result = step(probe);
      if (!result.ok) return describeDomainError(result.error.code);
      probe = replaceAccountIn([...probe], result.account);
    }
    setAccounts((current) => {
      let next = current;
      for (const step of steps) {
        const result = step(next);
        // The account was removed between validation and this updater: keep
        // the current document instead of resurrecting a stale copy.
        if (!result.ok) return current;
        next = replaceAccountIn(next, result.account);
      }
      return next;
    });
    commit();
    return null;
  }

  function addField(label: string, type: FieldType): { fieldId: FieldId | null; error: string | null } {
    if (selectedAccount === null) return { fieldId: null, error: "Select an account first." };
    const accountId = selectedAccount.id;
    const fieldId = newFieldId();
    const trimmedLabel = label.trim();
    const check = createField(accounts, accountId, fieldId, trimmedLabel, type, "");
    if (!check.ok) return { fieldId: null, error: describeDomainError(check.error.code) };
    setAccounts((current) => {
      const result = createField(current, accountId, fieldId, trimmedLabel, type, "");
      if (!result.ok) return current;
      return current.map((account) =>
        account.id === accountId
          ? { ...account, fields: [...account.fields, result.field] }
          : account,
      );
    });
    commit();
    return { fieldId, error: null };
  }

  function saveField(accountId: AccountId, fieldId: FieldId, patch: FieldPatch): string | null {
    const check = updateField(accounts, accountId, fieldId, patch);
    if (!check.ok) return describeDomainError(check.error.code);
    setAccounts((current) => applyFieldEdit(current, accountId, fieldId, patch));
    commit();
    return null;
  }

  function removeField(accountId: AccountId, fieldId: FieldId): string | null {
    const check = removeFieldOp(accounts, accountId, fieldId);
    if (!check.ok) return describeDomainError(check.error.code);
    setAccounts((current) => {
      // Re-check against the current list so a concurrent removal is a no-op
      // instead of reapplying a stale view.
      const fresh = removeFieldOp(current, accountId, fieldId);
      if (!fresh.ok) return current;
      return current.map((account) =>
        account.id === accountId
          ? { ...account, fields: account.fields.filter((field) => field.id !== fieldId) }
          : account,
      );
    });
    commit();
    return null;
  }

  return { saveIdentity, addField, saveField, removeField };
}
