import type { AccountId, AttachmentId, FieldId, PresetId } from "./domain";

/**
 * Official ID generation: UUIDv4 via `crypto.randomUUID()`.
 *
 * Globally unique without coordination, available in WebView2 and Node 20+,
 * no new dependency, and a stable string form compatible with the `*Id`
 * aliases. IDs are immutable once assigned; provisioning stays caller-side.
 */
export function newAccountId(): AccountId {
  return crypto.randomUUID();
}

export function newFieldId(): FieldId {
  return crypto.randomUUID();
}

export function newPresetId(): PresetId {
  return crypto.randomUUID();
}

export function newAttachmentId(): AttachmentId {
  return crypto.randomUUID();
}
