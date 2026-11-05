import type {
  Account,
  AccountPreset,
  AttachmentMeta,
  Field,
  FieldType,
  PresetFieldBlueprint,
} from "./domain";
import { isAttachmentMeta } from "./attachments";
import { normalizeServiceIcons } from "./serviceIcons";

/**
 * Plaintext vault document schema, versioned for migration.
 *
 * v3 is the account-directory shape: a flat account list plus presets. The
 * graph's `nodes`, `relationships`, `layout` and `nodeTypeDefinitions` are
 * gone; `migrateVaultGraph` converts older files.
 */
export const VAULT_SCHEMA_VERSION = 3;

/** Thrown when a vault was written by a newer build; never silently downgrade. */
export class UnsupportedVaultVersionError extends Error {
  readonly version: number;

  constructor(version: number) {
    super(`unsupported_vault_version:${version}`);
    this.name = "UnsupportedVaultVersionError";
    this.version = version;
  }
}

/** The whole vault plaintext. Everything here is encrypted at rest. */
export interface VaultGraph {
  accounts: Account[];
  schemaVersion: number;
  presets: AccountPreset[];
  attachments: AttachmentMeta[];
  /** Optional pictures keyed by the exact service label; absent in old files. */
  serviceIcons: Record<string, string>;
  /** Top-level keys this build does not understand, preserved verbatim. */
  extraKeys?: Record<string, unknown>;
}

export interface MigrationReport {
  graph: VaultGraph;
  /** User-facing notes about records that could not be migrated. */
  warnings: string[];
}

/** Keys consumed by the current or legacy schema; everything else is kept. */
const KNOWN_TOP_LEVEL_KEYS = new Set([
  "accounts",
  "schemaVersion",
  "presets",
  "templates",
  "attachments",
  "serviceIcons",
  "nodes",
  "relationships",
  "layout",
  "nodeTypeDefinitions",
  "extraKeys",
]);

interface MigrationCounts {
  accounts: number;
  fields: number;
  presets: number;
  presetFields: number;
  attachments: number;
  serviceIcons: number;
}

export function emptyVaultGraph(): VaultGraph {
  return {
    accounts: [],
    schemaVersion: VAULT_SCHEMA_VERSION,
    presets: [],
    attachments: [],
    serviceIcons: {},
  };
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asFields(value: unknown, counts: MigrationCounts): Field[] {
  const source = asArray(value);
  const fields = source.flatMap((entry): Field[] => {
    const field = asRecord(entry);
    if (
      field === null ||
      typeof field.id !== "string" ||
      typeof field.label !== "string" ||
      typeof field.type !== "string" ||
      typeof field.value !== "string"
    ) {
      return [];
    }
    return [{ id: field.id, label: field.label, type: field.type as FieldType, value: field.value }];
  });
  counts.fields += source.length - fields.length;
  return fields;
}

function asTags(value: unknown): string[] {
  return asArray(value).filter((tag): tag is string => typeof tag === "string");
}

function asBlueprintFields(value: unknown, counts: MigrationCounts): PresetFieldBlueprint[] {
  const source = asArray(value);
  const fields = source.flatMap((entry): PresetFieldBlueprint[] => {
    const field = asRecord(entry);
    if (field === null || typeof field.label !== "string" || typeof field.type !== "string") {
      return [];
    }
    return [{ label: field.label, type: field.type as FieldType, value: asString(field.value) }];
  });
  counts.presetFields += source.length - fields.length;
  return fields;
}

function asAccount(value: unknown, counts: MigrationCounts): Account | null {
  const account = asRecord(value);
  if (account === null) {
    counts.accounts += 1;
    return null;
  }
  const id = asString(account.id);
  if (id.trim() === "") {
    counts.accounts += 1;
    return null;
  }
  return {
    id,
    name: asString(account.name, id),
    service: asString(account.service),
    tags: asTags(account.tags),
    fields: asFields(account.fields, counts),
  };
}

function asPreset(value: unknown, counts: MigrationCounts): AccountPreset | null {
  const preset = asRecord(value);
  if (preset === null) {
    counts.presets += 1;
    return null;
  }
  const id = asString(preset.id);
  if (id.trim() === "") {
    counts.presets += 1;
    return null;
  }
  return {
    id,
    name: asString(preset.name, id),
    service: asString(preset.service),
    tags: asTags(preset.tags),
    fields: asBlueprintFields(preset.fields, counts),
  };
}

/**
 * Converts a v2 graph document into accounts.
 *
 * A node contained by a `Service` node inherits that service name, so
 * "Riot ─contains─► Main" becomes an account with service "Riot". A Service
 * node with no fields is a pure container — its name now lives on its
 * children, so it is dropped instead of becoming an empty account.
 * Relationships, layout and custom type definitions have no equivalent and
 * are discarded; every node's fields and name survive.
 */
function accountsFromNodes(document: Record<string, unknown>, counts: MigrationCounts): Account[] {
  const nodes = asArray(document.nodes).map(asRecord).filter((node): node is Record<string, unknown> => node !== null);
  const relationships = asArray(document.relationships)
    .map(asRecord)
    .filter((relationship): relationship is Record<string, unknown> => relationship !== null);

  const serviceByNode = new Map<string, string>();
  for (const relationship of relationships) {
    if (relationship.category !== "Organizational" || relationship.type !== "contains") continue;
    const sourceId = asString(relationship.sourceNodeId);
    const source = nodes.find((node) => node.id === sourceId);
    if (source?.type !== "Service") continue;
    const service = asString(source.name).trim();
    if (service !== "") serviceByNode.set(asString(relationship.targetNodeId), service);
  }

  const accounts: Account[] = [];
  for (const node of nodes) {
    const account = asAccount(node, counts);
    if (account === null) continue;
    // A pure service container is migrated into its children, not dropped as
    // malformed data.
    if (node.type === "Service" && account.fields.length === 0) continue;
    accounts.push({ ...account, service: serviceByNode.get(account.id) ?? account.service });
  }
  return accounts;
}

function summarizeSkipped(counts: MigrationCounts): string[] {
  const parts: string[] = [];
  if (counts.accounts > 0) parts.push(`${counts.accounts} account record(s)`);
  if (counts.fields > 0) parts.push(`${counts.fields} field record(s)`);
  if (counts.presets > 0) parts.push(`${counts.presets} preset record(s)`);
  if (counts.presetFields > 0) parts.push(`${counts.presetFields} preset field record(s)`);
  if (counts.attachments > 0) parts.push(`${counts.attachments} attachment record(s)`);
  if (counts.serviceIcons > 0) parts.push(`${counts.serviceIcons} service picture record(s)`);
  return parts.length === 0 ? [] : [`Skipped unreadable ${parts.join(", ")} while opening this vault.`];
}

/**
 * Migrates any stored document to the current schema and reports what was
 * skipped. Handles both the v3 shape and every older graph shape. Unknown
 * top-level keys are carried forward; a document from a newer schema version
 * is rejected instead of being silently rewritten.
 */
export function migrateVaultGraphReport(stored: unknown): MigrationReport {
  const document = asRecord(stored) ?? {};
  const version = document.schemaVersion;
  if (typeof version === "number" && version > VAULT_SCHEMA_VERSION) {
    throw new UnsupportedVaultVersionError(version);
  }

  const counts: MigrationCounts = {
    accounts: 0,
    fields: 0,
    presets: 0,
    presetFields: 0,
    attachments: 0,
    serviceIcons: 0,
  };

  const accounts = Array.isArray(document.accounts)
    ? asArray(document.accounts)
        .map((entry) => asAccount(entry, counts))
        .filter((account): account is Account => account !== null)
    : accountsFromNodes(document, counts);

  const presetSource = Array.isArray(document.presets) ? document.presets : document.templates;
  const presets = asArray(presetSource)
    .map((entry) => asPreset(entry, counts))
    .filter((preset): preset is AccountPreset => preset !== null);

  const attachmentSource = asArray(document.attachments);
  const attachments = attachmentSource.filter(isAttachmentMeta);
  counts.attachments += attachmentSource.length - attachments.length;

  const serviceIcons = normalizeServiceIcons(document.serviceIcons);
  const iconSource = asRecord(document.serviceIcons);
  if (iconSource !== null) {
    counts.serviceIcons += Object.keys(iconSource).length - Object.keys(serviceIcons).length;
  }

  const extraKeys: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(document)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) extraKeys[key] = value;
  }

  const graph: VaultGraph = {
    accounts,
    schemaVersion: VAULT_SCHEMA_VERSION,
    presets,
    attachments,
    serviceIcons,
  };
  if (Object.keys(extraKeys).length > 0) graph.extraKeys = extraKeys;

  return { graph, warnings: summarizeSkipped(counts) };
}

/** Convenience wrapper for callers that only need the migrated document. */
export function migrateVaultGraph(stored: unknown): VaultGraph {
  return migrateVaultGraphReport(stored).graph;
}
