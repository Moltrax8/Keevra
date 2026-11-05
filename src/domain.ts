export type FieldId = string;

/** Immutable identity of one account record. */
export type AccountId = string;
/** Immutable identity of a reusable account preset. */
export type PresetId = string;
/** Immutable identity of an encrypted attachment record. */
export type AttachmentId = string;

export type FieldType =
  | "Text"
  | "Username"
  | "Password"
  | "Email"
  | "Phone"
  | "URL"
  | "Note"
  | "Secret"
  | "Expiry"
  | "PIN"
  | "TOTP"
  | "RecoveryCodes";

export const FIELD_TYPES: readonly FieldType[] = [
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

/** Field types whose values are masked in the UI until explicitly revealed. */
export const SECRET_FIELD_TYPES: readonly FieldType[] = ["Password", "Secret", "PIN", "TOTP", "RecoveryCodes"];

export interface Field {
  readonly id: FieldId;
  label: string;
  type: FieldType;
  value: string;
}

export interface TypeFieldBlueprint {
  label: string;
  type: FieldType;
}

export interface PresetFieldBlueprint extends TypeFieldBlueprint {
  value: string;
}

/**
 * One account on one service — the whole product model.
 *
 * `service` is a plain label, not an entity: an empty string groups the
 * account under "Other", and renaming a service is a bulk edit of the
 * accounts that carry it. `tags` are free-form labels (owner, school,
 * region) used for filtering. Everything else is an optional field, so the
 * smallest valid record is just a name.
 */
export interface Account {
  readonly id: AccountId;
  name: string;
  service: string;
  tags: string[];
  fields: Field[];
}

/** Reusable account shape. Instantiating one creates an ordinary Account. */
export interface AccountPreset {
  readonly id: PresetId;
  name: string;
  service: string;
  tags: string[];
  fields: PresetFieldBlueprint[];
}

/**
 * Encrypted file attachment metadata. The bytes live in a sidecar blob
 * beside the vault file; this record lives in the vault plaintext so
 * listings never touch blobs. sha256Hex binds bytes to metadata on export.
 *
 * `nodeId` is the owning account's ID. The field keeps its historical name
 * because it is part of the encrypted wire format: renaming it would strand
 * every attachment stored by an earlier version.
 */
export interface AttachmentMeta {
  readonly id: AttachmentId;
  nodeId: AccountId;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256Hex: string;
  createdAtMs: number;
}
