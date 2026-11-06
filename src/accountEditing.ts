import type { Account, AccountId } from "./domain";
import { normalizeTags } from "./tags";

export type AccountEditError =
  | {
      readonly code: "account_not_found";
      readonly accountId: AccountId;
    }
  | {
      readonly code: "invalid_account_name";
      readonly accountId: AccountId;
    };

export type AccountEditResult =
  | { readonly ok: true; readonly account: Account }
  | { readonly ok: false; readonly error: AccountEditError };

/**
 * Applies a pure patch to one account. Single lookup shared by every edit
 * operation, so "not found" is reported in exactly one place.
 */
function update(
  accounts: readonly Account[],
  accountId: AccountId,
  patch: (account: Account) => AccountEditResult,
): AccountEditResult {
  const target = accounts.find((account) => account.id === accountId);
  if (!target) return { ok: false, error: { code: "account_not_found", accountId } };
  return patch(target);
}

/** Renames an account, preserving its immutable ID, service, tags and fields. */
export function renameAccount(
  accounts: readonly Account[],
  accountId: AccountId,
  name: string,
): AccountEditResult {
  return update(accounts, accountId, (account) => {
    if (name.trim().length === 0) {
      return { ok: false, error: { code: "invalid_account_name", accountId } };
    }
    return { ok: true, account: { ...account, name: name.trim(), fields: [...account.fields] } };
  });
}

/** Moves an account to another service. An empty string means "Other". */
export function setAccountService(
  accounts: readonly Account[],
  accountId: AccountId,
  service: string,
): AccountEditResult {
  return update(accounts, accountId, (account) => ({
    ok: true,
    account: { ...account, service: service.trim(), fields: [...account.fields] },
  }));
}

/** Replaces an account's tags with a normalised set. */
export function setAccountTags(
  accounts: readonly Account[],
  accountId: AccountId,
  tags: readonly string[],
): AccountEditResult {
  return update(accounts, accountId, (account) => ({
    ok: true,
    account: { ...account, tags: normalizeTags(tags), fields: [...account.fields] },
  }));
}
