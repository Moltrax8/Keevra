import type { Account, AccountId } from "./domain";
import { normalizeTags } from "./tags";

export type AccountCreationError =
  | {
      readonly code: "invalid_account_id";
      readonly accountId: AccountId;
    }
  | {
      readonly code: "duplicate_account_id";
      readonly accountId: AccountId;
    }
  | {
      readonly code: "invalid_account_name";
      readonly accountId: AccountId;
    };

export type AccountCreationResult =
  | { readonly ok: true; readonly account: Account }
  | { readonly ok: false; readonly error: AccountCreationError };

/**
 * Creates an account with no fields. This is the one-step "type, Enter" path:
 * only a name is required. An empty `service` groups the account under
 * "Other"; tags are normalised and default to none.
 *
 * Pure and non-mutating. The caller supplies the ID so ID generation stays
 * out of the domain layer.
 */
export function createAccount(
  accounts: readonly Account[],
  accountId: AccountId,
  name: string,
  service: string = "",
  tags: readonly string[] = [],
): AccountCreationResult {
  if (accountId.trim().length === 0) {
    return { ok: false, error: { code: "invalid_account_id", accountId } };
  }

  if (accounts.some((account) => account.id === accountId)) {
    return { ok: false, error: { code: "duplicate_account_id", accountId } };
  }

  if (name.trim().length === 0) {
    return { ok: false, error: { code: "invalid_account_name", accountId } };
  }

  return {
    ok: true,
    account: {
      id: accountId,
      name: name.trim(),
      service: service.trim(),
      tags: normalizeTags(tags),
      fields: [],
    },
  };
}
