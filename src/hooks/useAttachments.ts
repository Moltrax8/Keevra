import { useRef, useState, type Dispatch, type SetStateAction } from "react";
import type { Account, AttachmentId, AttachmentMeta } from "../domain";
import { attachmentExport, attachmentImport, pickExportFile, pickImportFile } from "../vaultApi";
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
  if (message.includes("vault_locked")) return "Vault is locked.";
  return "Attachment operation failed.";
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
    let sourcePath: string | null;
    try {
      sourcePath = await pickImportFile();
    } catch {
      setAttachmentError("File picker failed.");
      setPickerBusy(false);
      return;
    }
    if (!sourcePath) {
      setPickerBusy(false);
      return;
    }

    const task = (async () => {
      try {
        const meta = await attachmentImport(newAttachmentId(), accountId, sourcePath);
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
    let destPath: string | null;
    try {
      destPath = await pickExportFile(meta.fileName);
    } catch {
      setAttachmentError("File picker failed.");
      setPickerBusy(false);
      return;
    }
    if (!destPath) {
      setPickerBusy(false);
      return;
    }
    try {
      const bytes = await attachmentExport(meta.id, meta.sha256Hex, destPath);
      setAttachmentNotice(`Exported ${formatBytes(bytes)} verified.`);
    } catch (error) {
      setAttachmentError(describeAttachmentError(error));
    } finally {
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
