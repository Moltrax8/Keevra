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

export function useAccountEditing({
  accounts,
  setAccounts,
  selectedAccount,
  commit,
}: AccountEditingOptions): AccountEditingApi {
  function replaceAccount(updated: Account) {
    setAccounts((current) => current.map((account) => (account.id === updated.id ? updated : account)));
  }

  function saveIdentity(name: string, service: string, tagsText: string): string | null {
    if (selectedAccount === null) return "Select an account first.";
    const steps = [
      (list: readonly Account[]) => renameAccount(list, selectedAccount.id, name),
      (list: readonly Account[]) => setAccountService(list, selectedAccount.id, service),
      (list: readonly Account[]) => setAccountTags(list, selectedAccount.id, tagsText.split(",")),
    ];
    let next: readonly Account[] = accounts;
    for (const step of steps) {
      const result = step(next);
      if (!result.ok) return describeDomainError(result.error.code);
      next = next.map((account) => (account.id === result.account.id ? result.account : account));
    }
    setAccounts([...next]);
    commit();
    return null;
  }

  function addField(label: string, type: FieldType): { fieldId: FieldId | null; error: string | null } {
    if (selectedAccount === null) return { fieldId: null, error: "Select an account first." };
    const result = createField(accounts, selectedAccount.id, newFieldId(), label.trim(), type, "");
    if (!result.ok) return { fieldId: null, error: describeDomainError(result.error.code) };
    replaceAccount({ ...selectedAccount, fields: [...selectedAccount.fields, result.field] });
    commit();
    return { fieldId: result.field.id, error: null };
  }

  function saveField(accountId: AccountId, fieldId: FieldId, patch: FieldPatch): string | null {
    const result = updateField(accounts, accountId, fieldId, patch);
    if (!result.ok) return describeDomainError(result.error.code);
    const account = accounts.find((candidate) => candidate.id === accountId);
    if (account) {
      replaceAccount({
        ...account,
        fields: account.fields.map((field) => (field.id === fieldId ? result.field : field)),
      });
    }
    commit();
    return null;
  }

  function removeField(accountId: AccountId, fieldId: FieldId): string | null {
    const result = removeFieldOp(accounts, accountId, fieldId);
    if (!result.ok) return describeDomainError(result.error.code);
    const account = accounts.find((candidate) => candidate.id === accountId);
    if (account) {
      replaceAccount({ ...account, fields: account.fields.filter((field) => field.id !== fieldId) });
    }
    commit();
    return null;
  }

  return { saveIdentity, addField, saveField, removeField };
}
