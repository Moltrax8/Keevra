import { useRef, useState, type Dispatch, type SetStateAction } from "react";
import type { Account, AttachmentId, AttachmentMeta } from "../domain";
import {
  attachmentExport,
  attachmentImport,
  pickExportFile,
  pickImportFile,
  vaultStatus,
} from "../vaultApi";
import { formatBytes, isAttachmentMeta } from "../attachments";
import { newAttachmentId } from "../ids";

export interface AttachmentUiOptions {
  selectedAccount: Account | null;
  /** Increments whenever the document is replaced (open/create/lock). */
  documentEpoch: number;
  setAttachments: Dispatch<SetStateAction<AttachmentMeta[]>>;
  commit: () => void;
}

export interface AttachmentUiApi {
  attachmentError: string | null;
  attachmentNotice: string | null;
  confirmingAttId: AttachmentId | null;
  pickerBusy: boolean;
  uploadAttachment: () => Promise<void>;
  downloadAttachment: (meta: AttachmentMeta) => Promise<void>;
  deleteAttachment: (meta: AttachmentMeta) => void;
  /** Waits for imports that are already running; used before a vault switch. */
  waitForPending: () => Promise<void>;
  /** Clears transient messages when the document changes or the vault locks. */
  resetUi: () => void;
}

function describeAttachmentError(error: unknown): string {
  const message = typeof error === "string" ? error : "";
  if (message.includes("attachment_too_large")) return "File exceeds 25 MB.";
  if (message.includes("attachment_not_found")) return "Attachment file is missing.";
  if (message.includes("attachment_corrupt")) return "Attachment failed verification.";
  if (message.includes("vault_changed")) {
    return "The vault changed while the file dialog was open. Try again.";
  }
  if (message.includes("vault_locked")) return "Vault is locked.";
  return "Attachment operation failed.";
}

/** Path + session generation of the vault that was open when a dialog began. */
interface VaultIdentity {
  path: string;
  generation: number;
}

/**
 * Reads the current backend identity for a long-running file operation.
 *
 * Captured *before* the native picker opens so a vault switch during the
 * dialog cannot retarget the write. The identity is also checked again in Rust
 * immediately before the blob is touched (K-03).
 */
async function captureVaultIdentity(): Promise<VaultIdentity | null> {
  try {
    const status = await vaultStatus();
    if (!status.unlocked || status.path === null || status.generation === null) {
      return null;
    }
    return { path: status.path, generation: status.generation };
  } catch {
    return null;
  }
}

export function useAttachments({
  selectedAccount,
  documentEpoch,
  setAttachments,
  commit,
}: AttachmentUiOptions): AttachmentUiApi {
  const [attachmentError, setAttachmentError] = useState<string | null>(null);
  const [attachmentNotice, setAttachmentNotice] = useState<string | null>(null);
  const [confirmingAttId, setConfirmingAttId] = useState<AttachmentId | null>(null);
  const [pickerBusy, setPickerBusy] = useState(false);
  // The epoch is mirrored in a ref so an import that finishes after a vault
  // switch can compare against the value captured when it started (K-03).
  const epochRef = useRef(documentEpoch);
  epochRef.current = documentEpoch;
  const pendingImports = useRef<Set<Promise<void>>>(new Set());

  /** Lets lock/switch wait for an in-flight import instead of clearing state. */
  async function waitForPending(): Promise<void> {
    // A loop also covers an import that starts while this call is awaiting,
    // though `pickerBusy` normally serialises uploads already.
    while (pendingImports.current.size > 0) {
      await Promise.allSettled([...pendingImports.current]);
    }
  }

  async function uploadAttachment() {
    if (selectedAccount === null || pickerBusy) return;
    const accountId = selectedAccount.id;
    const startEpoch = documentEpoch;
    setAttachmentError(null);
    setAttachmentNotice(null);
    setPickerBusy(true);

    // The whole flow — identity capture, the native picker and the encrypted
    // write — is one pending task. A lock/switch that starts while the picker
    // is still open therefore waits for it instead of racing it (K-03).
    const task = (async () => {
      const identity = await captureVaultIdentity();
      if (identity === null) {
        setAttachmentError("Vault is locked.");
        return;
      }
      let sourcePath: string | null;
      try {
        sourcePath = await pickImportFile();
      } catch {
        setAttachmentError("File picker failed.");
        return;
      }
      if (!sourcePath) return;

      try {
        const meta = await attachmentImport(
          newAttachmentId(),
          accountId,
          sourcePath,
          identity.path,
          identity.generation,
        );
        // The vault was opened/created/locked while the blob was being
        // written. Its metadata belongs to the old document: never append it
        // to the new vault (K-03).
        if (epochRef.current !== startEpoch) {
          return;
        }
        if (!isAttachmentMeta(meta)) {
          setAttachmentError("Attachment operation failed.");
          return;
        }
        setAttachments((current) => [...current, meta]);
        commit();
        setAttachmentNotice(`Attached ${meta.fileName} (${formatBytes(meta.sizeBytes)}).`);
      } catch (error) {
        if (epochRef.current === startEpoch) {
          setAttachmentError(describeAttachmentError(error));
        }
      }
    })();
    pendingImports.current.add(task);
    try {
      await task;
    } finally {
      pendingImports.current.delete(task);
      setPickerBusy(false);
    }
  }

  async function downloadAttachment(meta: AttachmentMeta) {
    if (pickerBusy) return;
    setAttachmentError(null);
    setAttachmentNotice(null);
    setPickerBusy(true);

    const task = (async () => {
      const identity = await captureVaultIdentity();
      if (identity === null) {
        setAttachmentError("Vault is locked.");
        return;
      }
      let destPath: string | null;
      try {
        destPath = await pickExportFile(meta.fileName);
      } catch {
        setAttachmentError("File picker failed.");
        return;
      }
      if (!destPath) return;
      try {
        const bytes = await attachmentExport(
          meta.id,
          meta.sha256Hex,
          destPath,
          identity.path,
          identity.generation,
        );
        setAttachmentNotice(`Exported ${formatBytes(bytes)} verified.`);
      } catch (error) {
        setAttachmentError(describeAttachmentError(error));
      }
    })();
    pendingImports.current.add(task);
    try {
      await task;
    } finally {
      pendingImports.current.delete(task);
      setPickerBusy(false);
    }
  }

  function deleteAttachment(meta: AttachmentMeta) {
    if (confirmingAttId !== meta.id) {
      setConfirmingAttId(meta.id);
      return;
    }
    setConfirmingAttId(null);
    setAttachmentError(null);
    // Blob removal is deferred to the save-time sweep so undo stays lossless.
    setAttachments((current) => current.filter((attachment) => attachment.id !== meta.id));
    commit();
  }

  function resetUi() {
    setAttachmentError(null);
    setAttachmentNotice(null);
    setConfirmingAttId(null);
  }

  return {
    attachmentError,
    attachmentNotice,
    confirmingAttId,
    pickerBusy,
    uploadAttachment,
    downloadAttachment,
    deleteAttachment,
    waitForPending,
    resetUi,
  };
}
