import type { Account, AccountId, Field, FieldId, FieldType } from "./domain";
import { isValidRecoveryCodes } from "./recoveryCodes";
import { isValidTotpSeed } from "./totp";

export type FieldAddError =
  | {
      readonly code: "account_not_found";
      readonly accountId: AccountId;
    }
  | {
      readonly code: "invalid_field_id";
      readonly fieldId: FieldId;
    }
  | {
      readonly code: "duplicate_field_id";
      readonly fieldId: FieldId;
    }
  | {
      readonly code: "invalid_field_label";
      readonly fieldId: FieldId;
    }
  | {
      readonly code: "invalid_field_value";
      readonly fieldId: FieldId;
    };

export type FieldAddResult =
  | { readonly ok: true; readonly field: Field }
  | { readonly ok: false; readonly error: FieldAddError };

/**
 * Creates a validated field object for an existing account without mutating
 * inputs or persisting. The caller supplies the field ID; only non-empty IDs
 * unique within the account and non-empty labels are accepted. Value may be
 * empty — every field is optional by design.
 */
export function createField(
  accounts: readonly Account[],
  accountId: AccountId,
  fieldId: FieldId,
  label: string,
  type: FieldType,
  value: string,
): FieldAddResult {
  const target = accounts.find((account) => account.id === accountId);
  if (!target) {
    return { ok: false, error: { code: "account_not_found", accountId } };
  }

  if (fieldId.trim().length === 0) {
    return { ok: false, error: { code: "invalid_field_id", fieldId } };
  }

  if (target.fields.some((field) => field.id === fieldId)) {
    return { ok: false, error: { code: "duplicate_field_id", fieldId } };
  }

  if (label.trim().length === 0) {
    return { ok: false, error: { code: "invalid_field_label", fieldId } };
  }

  if (!isValidFieldValue(type, value)) {
    return { ok: false, error: { code: "invalid_field_value", fieldId } };
  }

  return { ok: true, field: { id: fieldId, label, type, value } };
}

export type FieldEditError =
  | {
      readonly code: "account_not_found";
      readonly accountId: AccountId;
    }
  | {
      readonly code: "field_not_found";
      readonly accountId: AccountId;
      readonly fieldId: FieldId;
    }
  | {
      readonly code: "invalid_field_label";
      readonly fieldId: FieldId;
    }
  | {
      readonly code: "invalid_field_value";
      readonly fieldId: FieldId;
    };

/** Parses a strict `YYYY-MM-DD` calendar date as UTC midnight, or null. */
export function parseIsoDate(value: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }
  return date;
}

/**
 * Per-type value rules — the distinct behavior justifying each specialized
 * type. Empty values are always allowed (every field is optional).
 * - Expiry: valid YYYY-MM-DD calendar date.
 * - PIN: 4–12 ASCII digits.
 * - TOTP: valid base32 seed (empty allowed).
 * - RecoveryCodes: one code per line, `x `-prefixed lines are consumed,
 *   no empty or duplicate codes.
 */
export function isValidFieldValue(type: FieldType, value: string): boolean {
  if (value === "") return true;
  if (type === "PIN") return /^[0-9]{4,12}$/.test(value);
  if (type === "TOTP") return isValidTotpSeed(value);
  if (type === "RecoveryCodes") return isValidRecoveryCodes(value);
  if (type === "Expiry") return parseIsoDate(value) !== null;
  return true;
}

export type FieldEditResult =
  | { readonly ok: true; readonly field: Field }
  | { readonly ok: false; readonly error: FieldEditError };

export interface FieldPatch {
  readonly label?: string;
  readonly type?: FieldType;
  readonly value?: string;
}

/**
 * Returns an updated field copy with the patch applied, preserving immutable
 * field ID. Pure and non-mutating. Empty label updates are rejected; the
 * resulting type/value pair must satisfy `isValidFieldValue`.
 */
export function updateField(
  accounts: readonly Account[],
  accountId: AccountId,
  fieldId: FieldId,
  patch: FieldPatch,
): FieldEditResult {
  const target = accounts.find((account) => account.id === accountId);
  if (!target) {
    return { ok: false, error: { code: "account_not_found", accountId } };
  }

  const existing = target.fields.find((field) => field.id === fieldId);
  if (!existing) {
    return { ok: false, error: { code: "field_not_found", accountId, fieldId } };
  }

  if (patch.label !== undefined && patch.label.trim().length === 0) {
    return { ok: false, error: { code: "invalid_field_label", fieldId } };
  }

  const nextType = patch.type ?? existing.type;
  const nextValue = patch.value ?? existing.value;
  if (!isValidFieldValue(nextType, nextValue)) {
    return { ok: false, error: { code: "invalid_field_value", fieldId } };
  }

  return {
    ok: true,
    field: {
      ...existing,
      label: patch.label ?? existing.label,
      type: nextType,
      value: nextValue,
    },
  };
}

/**
 * Returns the updated field list with the field removed. Pure and
 * non-mutating; unknown field IDs report field_not_found so callers can
 * distinguish no-ops from successful removals.
 */
export function removeField(
  accounts: readonly Account[],
  accountId: AccountId,
  fieldId: FieldId,
): FieldEditResult | { readonly ok: true; readonly removedFieldId: FieldId } {
  const target = accounts.find((account) => account.id === accountId);
  if (!target) {
    return { ok: false, error: { code: "account_not_found", accountId } };
  }

  if (!target.fields.some((field) => field.id === fieldId)) {
    return { ok: false, error: { code: "field_not_found", accountId, fieldId } };
  }

  return { ok: true, removedFieldId: fieldId };
}
