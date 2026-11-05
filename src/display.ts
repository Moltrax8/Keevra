/**
 * Presentation-layer shared definitions (UI-only, no domain rules).
 *
 * Service grouping, search matching, demo fixtures and user-facing error text
 * live here so view components stay focused. Nothing in this module may alter
 * vault semantics; all rules live in the domain modules (accountCreation.ts,
 * fieldOperations.ts…).
 */
import type { Account, Field } from "./domain";
import { FIELD_TYPES, SECRET_FIELD_TYPES } from "./domain";
import { AUTO_LOCK_TEST_HOOK } from "./brand";

/** Label used for accounts that carry no service. */
export const OTHER_SERVICE_LABEL = "Other";

export interface ServiceGroup {
  /** The raw `Account.service` value; "" is the "Other" group. */
  readonly service: string;
  readonly label: string;
  readonly accounts: Account[];
}

/** A service is a plain label, so "" is the only special case. */
export function serviceLabel(service: string): string {
  return service === "" ? OTHER_SERVICE_LABEL : service;
}

/**
 * A stable, purely decorative tint per service so grouped rows are scannable.
 * Six muted tones, no meaning attached — the same service always gets the
 * same one.
 */
const SERVICE_TINTS = ["clay", "olive", "plum", "teal", "gold", "rose"] as const;

export function serviceTint(service: string): (typeof SERVICE_TINTS)[number] {
  let hash = 0;
  for (const char of service) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return SERVICE_TINTS[hash % SERVICE_TINTS.length];
}

/**
 * Groups accounts by service for the sidebar: alphabetical by label, with
 * "Other" last so the catch-all never outranks a real service.
 */
export function groupAccountsByService(accounts: readonly Account[]): ServiceGroup[] {
  const groups = new Map<string, Account[]>();
  for (const account of accounts) {
    const existing = groups.get(account.service);
    if (existing) existing.push(account);
    else groups.set(account.service, [account]);
  }
  return [...groups.entries()]
    .map(([service, members]) => ({ service, label: serviceLabel(service), accounts: members }))
    .sort((left, right) => {
      if (left.service === "") return 1;
      if (right.service === "") return -1;
      return left.label.localeCompare(right.label, undefined, { sensitivity: "base" });
    });
}

/** Every tag in the vault, alphabetically, for the detail pane's suggestions. */
export function tagOptions(accounts: readonly Account[]): string[] {
  return [...new Set(accounts.flatMap((account) => account.tags))].sort((left, right) =>
    left.localeCompare(right, undefined, { sensitivity: "base" }),
  );
}

/**
 * Free-text match over the things a person would type: name, service, tags,
 * field labels, and non-secret values such as an email or username.
 */
export function matchesQuery(account: Account, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === "") return true;
  const haystack = [
    account.name,
    serviceLabel(account.service),
    ...account.tags,
    ...account.fields.flatMap((field) => [field.label, isSecretField(field.type) ? "" : field.value]),
  ];
  return haystack.some((value) => value.toLowerCase().includes(needle));
}

export const fieldTypeOptions: Field["type"][] = [...FIELD_TYPES];

export function isSecretField(type: Field["type"]): boolean {
  return (SECRET_FIELD_TYPES as readonly string[]).includes(type);
}

// Inactivity auto-lock. Overridable in tests via window.__KEEVRA_AUTO_LOCK_MS.
export function autoLockTimeoutMs(): number {
  const override = (window as unknown as Record<string, unknown>)[AUTO_LOCK_TEST_HOOK];
  return typeof override === "number" && override > 0 ? override : 5 * 60 * 1000;
}

/** Password hints stay hidden until 2 failed unlocks for that vault. */
export const HINT_FAILURE_THRESHOLD = 2;

export function shouldShowHint(failures: number): boolean {
  return Number.isFinite(failures) && failures >= HINT_FAILURE_THRESHOLD;
}

export function strengthOf(password: string): number {
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 20) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(4, score);
}

/**
 * Demo fixtures shown when no native backend is available. Fake data only:
 * enough services and fields to show the grouping and the detail pane.
 */
export function demoAccounts(): Account[] {
  return [
    {
      id: "demo-gmail",
      name: "demo.personal",
      service: "Gmail",
      tags: ["personal"],
      fields: [
        { id: "demo-f-1", label: "Email", type: "Email", value: "demo@example.com" },
        { id: "demo-f-2", label: "Password", type: "Password", value: "correct horse battery staple" },
      ],
    },
    {
      id: "demo-discord",
      name: "demo_user",
      service: "Discord",
      tags: ["personal"],
      fields: [
        { id: "demo-f-3", label: "Email", type: "Email", value: "demo@example.com" },
        { id: "demo-f-4", label: "Password", type: "Password", value: "discord-pass-1" },
        { id: "demo-f-5", label: "2FA seed", type: "TOTP", value: "JBSWY3DPEHPK3PXP" },
      ],
    },
    {
      id: "demo-riot",
      name: "demo_user",
      service: "Riot",
      tags: ["gaming"],
      fields: [
        { id: "demo-f-6", label: "Username", type: "Username", value: "demo_user" },
        { id: "demo-f-7", label: "Password", type: "Password", value: "riot-pass-1" },
        { id: "demo-f-8", label: "Recovery codes", type: "RecoveryCodes", value: "A1B2-C3D4\nE5F6-G7H8" },
      ],
    },
    {
      id: "demo-valorant",
      name: "Smurf",
      service: "Riot",
      tags: ["gaming"],
      fields: [
        { id: "demo-f-9", label: "Username", type: "Username", value: "smurf_01" },
        { id: "demo-f-10", label: "Password", type: "Password", value: "smurf-pass-1" },
      ],
    },
    {
      id: "demo-school",
      name: "student portal",
      service: "University",
      tags: ["school"],
      fields: [
        { id: "demo-f-11", label: "Student ID", type: "Username", value: "20260123" },
        { id: "demo-f-12", label: "Password", type: "Password", value: "school-pass-1" },
        { id: "demo-f-13", label: "Password expires", type: "Expiry", value: "2026-12-01" },
      ],
    },
    {
      id: "demo-netflix",
      name: "Family plan",
      service: "",
      tags: ["family"],
      fields: [{ id: "demo-f-14", label: "Password", type: "Password", value: "netflix-pass-1" }],
    },
  ];
}

export function describeDomainError(code: string): string {
  switch (code) {
    case "invalid_account_id":
      return "Internal ID error. Try again.";
    case "duplicate_account_id":
      return "An ID collision occurred. Try again.";
    case "invalid_account_name":
      return "Enter an account name.";
    case "account_not_found":
      return "That account no longer exists.";
    case "invalid_field_id":
      return "Internal ID error. Try again.";
    case "duplicate_field_id":
      return "An ID collision occurred. Try again.";
    case "invalid_field_label":
      return "Enter a field label.";
    case "invalid_field_value":
      return "Check the value format for this field type.";
    case "field_not_found":
      return "That field no longer exists.";
    case "invalid_preset_id":
      return "Internal ID error. Try again.";
    case "duplicate_preset_id":
      return "An ID collision occurred. Try again.";
    case "invalid_preset_name":
      return "Enter a preset name.";
    case "invalid_preset_label":
      return "Preset field labels must be non-empty.";
    case "preset_not_found":
      return "That preset no longer exists.";
    case "field_count_mismatch":
      return "Preset fields changed. Try again.";
    case "code_not_found":
      return "That recovery code is not in this field.";
    case "code_already_used":
      return "That recovery code is already marked used.";
    default:
      return "Could not complete. Try again.";
  }
}
