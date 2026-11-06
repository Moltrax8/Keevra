import { useState, type Dispatch, type SetStateAction } from "react";
import type { Account, AttachmentId, AttachmentMeta } from "../domain";
import { attachmentExport, attachmentImport, pickExportFile, pickImportFile } from "../vaultApi";
import { formatBytes, isAttachmentMeta } from "../attachments";
import { newAttachmentId } from "../ids";

export interface AttachmentUiOptions {
  selectedAccount: Account | null;
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
  setAttachments,
  commit,
}: AttachmentUiOptions): AttachmentUiApi {
  const [attachmentError, setAttachmentError] = useState<string | null>(null);
  const [attachmentNotice, setAttachmentNotice] = useState<string | null>(null);
  const [confirmingAttId, setConfirmingAttId] = useState<AttachmentId | null>(null);
  const [pickerBusy, setPickerBusy] = useState(false);

  async function uploadAttachment() {
    if (selectedAccount === null || pickerBusy) return;
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
    try {
      const meta = await attachmentImport(newAttachmentId(), selectedAccount.id, sourcePath);
      if (!isAttachmentMeta(meta)) {
        setAttachmentError("Attachment operation failed.");
        return;
      }
      setAttachments((current) => [...current, meta]);
      commit();
      setAttachmentNotice(`Attached ${meta.fileName} (${formatBytes(meta.sizeBytes)}).`);
    } catch (error) {
      setAttachmentError(describeAttachmentError(error));
    } finally {
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
    resetUi,
  };
}
