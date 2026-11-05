import { useMemo, useRef, useState, type Dispatch, type SetStateAction } from "react";
import type {
  Account,
  AccountId,
  AccountPreset,
  AttachmentId,
  AttachmentMeta,
  FieldId,
  FieldType,
} from "../domain";
import { createAccount } from "../accountCreation";
import { demoAccounts, describeDomainError, matchesQuery } from "../display";
import { newAccountId } from "../ids";
import { moveServiceIcon } from "../serviceIcons";
import type { FieldPatch } from "../fieldOperations";
import { snapshotOf, type DomainSnapshot } from "../history";
import { migrateVaultGraphReport, type VaultGraph } from "../vaultDocument";
import { useAccountEditing } from "./useAccountEditing";
import { useAttachments } from "./useAttachments";

function byName(left: Account, right: Account): number {
  return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
}

export interface AccountsApi {
  accounts: Account[];
  presets: AccountPreset[];
  attachments: AttachmentMeta[];
  serviceIcons: Record<string, string>;
  /** Top-level vault keys this build does not understand, preserved on save. */
  extraKeys: Record<string, unknown>;
  migrationWarnings: string[];
  dismissMigrationWarnings: () => void;
  selectedAccountId: AccountId | null;
  setSelectedAccountId: Dispatch<SetStateAction<AccountId | null>>;
  query: string;
  setQuery: Dispatch<SetStateAction<string>>;
  addError: string | null;
  serviceOptions: string[];
  tagOptions: string[];
  visibleAccounts: Account[];
  selectedAccount: Account | null;
  selectedAttachments: AttachmentMeta[];
  dirty: boolean;
  saveError: boolean;
  /** Monotonic counter of domain mutations; used to match saves to revisions. */
  revision: number;
  snapshot: () => DomainSnapshot;
  applySnapshot: (snapshot: DomainSnapshot) => void;
  applyVaultDocument: (stored: VaultGraph) => void;
  clearDomain: () => void;
  /** Clears dirty only when the saved revision is still the latest one. */
  markSaved: (revision: number) => void;
  markSaveFailed: () => void;
  addAccount: (name: string, service: string) => boolean;
  deleteAccount: () => void;
  setServiceIcon: (dataUrl: string | null) => void;
  saveIdentity: (name: string, service: string, tagsText: string) => string | null;
  addField: (label: string, type: FieldType) => { fieldId: FieldId | null; error: string | null };
  saveField: (accountId: AccountId, fieldId: FieldId, patch: FieldPatch) => string | null;
  removeField: (accountId: AccountId, fieldId: FieldId) => string | null;
  attachmentError: string | null;
  attachmentNotice: string | null;
  confirmingAttId: AttachmentId | null;
  pickerBusy: boolean;
  uploadAttachment: () => Promise<void>;
  downloadAttachment: (meta: AttachmentMeta) => Promise<void>;
  deleteAttachment: (meta: AttachmentMeta) => void;
}

export function useAccounts(onCommit: (snapshot: DomainSnapshot) => void): AccountsApi {
  const [accounts, setAccounts] = useState<Account[]>(() => demoAccounts());
  const [presets, setPresets] = useState<AccountPreset[]>([]);
  const [attachments, setAttachments] = useState<AttachmentMeta[]>([]);
  const [serviceIcons, setServiceIcons] = useState<Record<string, string>>({});
  const [extraKeys, setExtraKeys] = useState<Record<string, unknown>>({});
  const [migrationWarnings, setMigrationWarnings] = useState<string[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<AccountId | null>(null);
  const [query, setQuery] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [savedRevision, setSavedRevision] = useState(0);
  const [saveError, setSaveError] = useState(false);
  const revisionRef = useRef(0);
  const dirty = revision !== savedRevision;

  const serviceOptions = useMemo(
    () =>
      [...new Set(accounts.map((account) => account.service).filter((service) => service !== ""))].sort(
        (left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }),
      ),
    [accounts],
  );
  const tagOptions = useMemo(
    () =>
      [...new Set(accounts.flatMap((account) => account.tags))].sort((left, right) =>
        left.localeCompare(right, undefined, { sensitivity: "base" }),
      ),
    [accounts],
  );

  const visibleAccounts = useMemo(
    () => accounts.filter((account) => matchesQuery(account, query)).sort(byName),
    [accounts, query],
  );

  const selectedAccount = accounts.find((account) => account.id === selectedAccountId) ?? null;
  const selectedAttachments = selectedAccount
    ? attachments.filter((attachment) => attachment.nodeId === selectedAccount.id)
    : [];

  function snapshot(): DomainSnapshot {
    return snapshotOf(accounts, presets, attachments, serviceIcons);
  }

  /** Advances the mutation counter synchronously (ref) and for rendering. */
  function bumpRevision() {
    revisionRef.current += 1;
    setRevision(revisionRef.current);
  }

  function applySnapshot(next: DomainSnapshot) {
    setAccounts([...next.accounts]);
    setPresets([...next.presets]);
    setAttachments([...next.attachments]);
    setServiceIcons({ ...next.serviceIcons });
    bumpRevision();
  }

  /**
   * Records pre-mutation state for undo and marks the vault dirty so the
   * auto-save pass picks it up. Call at every domain mutation; undo/redo
   * application itself bumps the revision directly and must NOT call this.
   */
  function commit() {
    onCommit(snapshot());
    bumpRevision();
  }

  /**
   * A save only clears dirty when no mutation happened after its snapshot was
   * taken; otherwise the newer revision stays pending for the next save.
   */
  function markSaved(revisionAtSave: number) {
    if (revisionAtSave === revisionRef.current) {
      setSavedRevision(revisionAtSave);
      setSaveError(false);
    }
  }

  function markSaveFailed() {
    setSaveError(true);
  }

  const editing = useAccountEditing({ accounts, setAccounts, selectedAccount, commit });

  /**
   * Identity edits can also rename a service. Carry that service's picture to
   * the new label, but only when no other account still uses the old label.
   */
  function saveIdentity(name: string, service: string, tagsText: string): string | null {
    const previousService = selectedAccount?.service.trim() ?? "";
    const message = editing.saveIdentity(name, service, tagsText);
    if (message !== null || selectedAccount === null) return message;
    const nextService = service.trim();
    if (previousService === "" || nextService === "" || previousService === nextService) {
      return null;
    }
    const stillUsed = accounts.some(
      (account) => account.id !== selectedAccount.id && account.service.trim() === previousService,
    );
    if (stillUsed) return null;
    setServiceIcons((current) => moveServiceIcon(current, previousService, nextService));
    return null;
  }

  const attachmentUi = useAttachments({ selectedAccount, setAttachments, commit });

  function applyVaultDocument(stored: VaultGraph): string[] {
    const { graph, warnings } = migrateVaultGraphReport(stored);
    setAccounts(graph.accounts);
    setPresets(graph.presets);
    setAttachments(graph.attachments);
    setServiceIcons(graph.serviceIcons);
    setExtraKeys(graph.extraKeys ?? {});
    setMigrationWarnings(warnings);
    setSelectedAccountId(null);
    setQuery("");
    setAddError(null);
    attachmentUi.resetUi();
    revisionRef.current = 0;
    setRevision(0);
    setSavedRevision(0);
    setSaveError(false);
    return warnings;
  }

  function dismissMigrationWarnings() {
    setMigrationWarnings([]);
  }

  function clearDomain() {
    setAccounts([]);
    setPresets([]);
    setAttachments([]);
    setServiceIcons({});
    setExtraKeys({});
    setMigrationWarnings([]);
    setSelectedAccountId(null);
    setQuery("");
    setAddError(null);
    attachmentUi.resetUi();
    revisionRef.current = 0;
    setRevision(0);
    setSavedRevision(0);
    setSaveError(false);
  }

  function addAccount(name: string, service: string): boolean {
    const result = createAccount(accounts, newAccountId(), name, service);
    if (!result.ok) {
      setAddError(describeDomainError(result.error.code));
      return false;
    }
    setAddError(null);
    setAccounts((current) => [...current, result.account]);
    setSelectedAccountId(result.account.id);
    setQuery("");
    commit();
    return true;
  }

  function deleteAccount() {
    if (selectedAccount === null) return;
    commit();
    // Blobs are not deleted here: the save-time sweep removes orphans, and it
    // keeps anything still reachable through undo/redo history.
    const doomedIds = new Set(
      attachments.filter((attachment) => attachment.nodeId === selectedAccount.id).map((attachment) => attachment.id),
    );
    if (doomedIds.size > 0) {
      setAttachments((current) => current.filter((attachment) => !doomedIds.has(attachment.id)));
    }
    setAccounts((current) => current.filter((account) => account.id !== selectedAccount.id));
    setSelectedAccountId(null);
  }

  /** Sets or clears the picture for the selected account's service label. */
  function setServiceIcon(dataUrl: string | null) {
    if (selectedAccount === null) return;
    const service = selectedAccount.service.trim();
    if (service === "") return;
    commit();
    setServiceIcons((current) => {
      const next = { ...current };
      if (dataUrl === null) delete next[service];
      else next[service] = dataUrl;
      return next;
    });
  }

  return {
    accounts,
    presets,
    attachments,
    serviceIcons,
    extraKeys,
    migrationWarnings,
    dismissMigrationWarnings,
    selectedAccountId,
    setSelectedAccountId,
    query,
    setQuery,
    addError,
    serviceOptions,
    tagOptions,
    visibleAccounts,
    selectedAccount,
    selectedAttachments,
    dirty,
    saveError,
    revision,
    snapshot,
    applySnapshot,
    applyVaultDocument,
    clearDomain,
    markSaved,
    markSaveFailed,
    addAccount,
    deleteAccount,
    setServiceIcon,
    saveIdentity,
    addField: editing.addField,
    saveField: editing.saveField,
    removeField: editing.removeField,
    attachmentError: attachmentUi.attachmentError,
    attachmentNotice: attachmentUi.attachmentNotice,
    confirmingAttId: attachmentUi.confirmingAttId,
    pickerBusy: attachmentUi.pickerBusy,
    uploadAttachment: attachmentUi.uploadAttachment,
    downloadAttachment: attachmentUi.downloadAttachment,
    deleteAttachment: attachmentUi.deleteAttachment,
  };
}
