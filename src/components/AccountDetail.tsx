/**
 * Right pane: one account.
 *
 * Identity saves itself when you leave a field; optional details are added
 * with a single chip click and save the same way. There is no field editor to
 * configure — just rows you type into.
 */
import { useEffect, useRef, useState } from "react";
import {
  Camera,
  Download,
  KeyRound,
  Paperclip,
  Plus,
  Tag,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import type { Account, AccountId, AttachmentId, AttachmentMeta, FieldId, FieldType } from "../domain";
import type { FieldPatch } from "../fieldOperations";
import { formatBytes } from "../attachments";
import { serviceLabel, serviceTint } from "../display";
import { readServiceIconFile } from "../serviceIcons";
import { AttachmentPreview } from "./AttachmentPreview";
import { FieldRow } from "./FieldRow";

/** The only field shapes the quick-add row offers. */
const QUICK_FIELDS: readonly { label: string; type: FieldType }[] = [
  { label: "Password", type: "Password" },
  { label: "Username", type: "Username" },
  { label: "Email", type: "Email" },
  { label: "PIN", type: "PIN" },
  { label: "Expiry", type: "Expiry" },
  { label: "TOTP", type: "TOTP" },
  { label: "Recovery codes", type: "RecoveryCodes" },
  { label: "Note", type: "Note" },
  { label: "Custom", type: "Text" },
];

function identityKey(name: string, service: string, tagsText: string): string {
  return `${name}\u0000${service}\u0000${tagsText}`;
}

export function AccountDetail({
  account,
  attachments,
  serviceIcon,
  onSetServiceIcon,
  services,
  tags,
  onSaveIdentity,
  onAddField,
  onSaveField,
  onRemoveField,
  onUploadAttachment,
  onDownloadAttachment,
  onDeleteAttachment,
  attachmentBusy,
  attachmentError,
  attachmentNotice,
  confirmingAttachmentId,
  onDelete,
}: {
  account: Account;
  attachments: readonly AttachmentMeta[];
  /** Picture for this account's service, or null to show the initial. */
  serviceIcon: string | null;
  onSetServiceIcon: (dataUrl: string | null) => void;
  services: readonly string[];
  tags: readonly string[];
  onSaveIdentity: (name: string, service: string, tags: string) => string | null;
  onAddField: (label: string, type: FieldType) => { fieldId: FieldId | null; error: string | null };
  onSaveField: (accountId: AccountId, fieldId: FieldId, patch: FieldPatch) => string | null;
  onRemoveField: (accountId: AccountId, fieldId: FieldId) => string | null;
  onUploadAttachment: () => void;
  onDownloadAttachment: (meta: AttachmentMeta) => void;
  onDeleteAttachment: (meta: AttachmentMeta) => void;
  attachmentBusy: boolean;
  attachmentError: string | null;
  attachmentNotice: string | null;
  confirmingAttachmentId: AttachmentId | null;
  onDelete: () => void;
}) {
  const [name, setName] = useState(account.name);
  const [service, setService] = useState(account.service);
  const [tagText, setTagText] = useState(account.tags.join(", "));
  const [identityError, setIdentityError] = useState<string | null>(null);

  const [fieldError, setFieldError] = useState<string | null>(null);
  const [focusFieldId, setFocusFieldId] = useState<FieldId | null>(null);

  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const iconInput = useRef<HTMLInputElement | null>(null);
  const [iconError, setIconError] = useState<string | null>(null);
  const [iconBusy, setIconBusy] = useState(false);

  const savedIdentity = useRef(identityKey(account.name, account.service, account.tags.join(", ")));

  // Undo/redo can replace the stored identity under a mounted pane; resync the
  // drafts so the form never shows values the vault no longer holds.
  useEffect(() => {
    setName(account.name);
    setService(account.service);
    setTagText(account.tags.join(", "));
    savedIdentity.current = identityKey(account.name, account.service, account.tags.join(", "));
  }, [account.name, account.service, account.tags]);

  function saveIdentity() {
    const key = identityKey(name, service, tagText);
    if (key === savedIdentity.current) return;
    const message = onSaveIdentity(name, service, tagText);
    setIdentityError(message);
    if (message === null) savedIdentity.current = key;
  }

  // Same draft protection as FieldRow: pause-save plus close-time flush. Skip
  // the pause-save while an identity input is focused so a save cannot
  // re-render the form mid-typing; blur and close still save it.
  useEffect(() => {
    const flush = () => saveIdentity();
    window.addEventListener("keevra:flush-drafts", flush);
    const dirtyDraft = identityKey(name, service, tagText) !== savedIdentity.current;
    const focused =
      document.activeElement !== null &&
      document.activeElement.closest('section[aria-label="Account details"]') !== null;
    const timer = dirtyDraft && !focused ? setTimeout(flush, 500) : null;
    return () => {
      if (timer !== null) clearTimeout(timer);
      window.removeEventListener("keevra:flush-drafts", flush);
    };
  }, [name, service, tagText]);

  function addField(label: string, type: FieldType) {
    const result = onAddField(label, type);
    setFieldError(result.error);
    if (result.fieldId !== null) setFocusFieldId(result.fieldId);
  }

  async function pickServiceIcon(file: File | undefined) {
    if (!file) return;
    setIconBusy(true);
    setIconError(null);
    try {
      onSetServiceIcon(await readServiceIconFile(file));
    } catch (error) {
      setIconError(error instanceof Error ? error.message : "Could not read that picture.");
    } finally {
      setIconBusy(false);
      if (iconInput.current !== null) iconInput.current.value = "";
    }
  }

  const canSetServiceIcon = account.service.trim() !== "";

  return (
    <aside className="details-pane" aria-labelledby="details-heading">
      <header className="details-hero">
        <div className="details-hero__avatar">
          <button
            type="button"
            className={`service-avatar service-avatar--${serviceTint(account.service)}${
              serviceIcon === null ? "" : " service-avatar--image"
            }`}
            onClick={() => iconInput.current?.click()}
            disabled={!canSetServiceIcon || iconBusy}
            title={
              canSetServiceIcon
                ? serviceIcon === null
                  ? "Add a picture for this service"
                  : "Change this service's picture"
                : "Give the account a service first"
            }
            aria-label={serviceIcon === null ? "Add service picture" : "Change service picture"}
          >
            {serviceIcon === null ? (
              serviceLabel(account.service).slice(0, 1).toUpperCase()
            ) : (
              <img src={serviceIcon} alt="" />
            )}
            {canSetServiceIcon ? (
              <span className="service-avatar__badge" aria-hidden="true">
                <Camera />
              </span>
            ) : null}
          </button>
          {serviceIcon !== null ? (
            <button
              type="button"
              className="service-avatar__remove"
              onClick={() => onSetServiceIcon(null)}
              title="Remove service picture"
              aria-label="Remove service picture"
            >
              <X />
            </button>
          ) : null}
          <input
            ref={iconInput}
            type="file"
            className="visually-hidden"
            accept="image/png,image/jpeg,image/webp"
            aria-label="Service picture file"
            onChange={(event) => void pickServiceIcon(event.target.files?.[0])}
          />
        </div>
        <div className="details-hero__text">
          <h3 id="details-heading">{account.name}</h3>
          <p>
            {serviceLabel(account.service)} · {account.fields.length} field
            {account.fields.length === 1 ? "" : "s"}
            {account.tags.length > 0 ? ` · ${account.tags.join(", ")}` : ""}
          </p>
        </div>
      </header>
      {iconError !== null ? <p className="create-form__error details-hero__error">{iconError}</p> : null}

      <section className="detail-card" aria-label="Account details">
        <div className="detail-card__head">
          <Tag /> Account
          <span className="detail-card__hint">saves when you click away</span>
        </div>
        <div className="detail-card__body">
          <form
            className="create-form"
            onSubmit={(event) => {
              event.preventDefault();
              saveIdentity();
            }}
          >
            <label className="field-label" htmlFor="account-name">
              Name
            </label>
            <input
              id="account-name"
              type="text"
              value={name}
              onChange={(event) => setName(event.target.value)}
              onBlur={saveIdentity}
              placeholder="Account name"
            />
            <label className="field-label" htmlFor="account-service">
              Service
            </label>
            <input
              id="account-service"
              type="text"
              value={service}
              list="service-options"
              onChange={(event) => setService(event.target.value)}
              onBlur={saveIdentity}
              placeholder="Service (empty = Other)"
            />
            <label className="field-label" htmlFor="account-tags">
              Tags <span className="hint">comma separated</span>
            </label>
            <input
              id="account-tags"
              type="text"
              value={tagText}
              list="tag-options"
              onChange={(event) => setTagText(event.target.value)}
              onBlur={saveIdentity}
              placeholder="personal, gaming…"
            />
            <datalist id="service-options">
              {services.map((option) => (
                <option key={option} value={option} />
              ))}
            </datalist>
            <datalist id="tag-options">
              {tags.map((option) => (
                <option key={option} value={option} />
              ))}
            </datalist>
            {identityError ? <p className="create-form__error">{identityError}</p> : null}
          </form>
        </div>
      </section>

      <section className="detail-card" aria-label="Fields">
        <div className="detail-card__head">
          <KeyRound /> Details
          <span className="count">{account.fields.length}</span>
        </div>
        <div className="detail-card__body">
          {account.fields.length > 0 ? (
            <ul className="field-list">
              {account.fields.map((field) => (
                <FieldRow
                  key={field.id}
                  accountId={account.id}
                  field={field}
                  autoFocus={field.id === focusFieldId}
                  onSave={onSaveField}
                  onRemove={onRemoveField}
                />
              ))}
            </ul>
          ) : (
            <p className="hint">Nothing yet. Add what you want to keep:</p>
          )}

          <div className="quick-add" aria-label="Add a detail">
            {QUICK_FIELDS.map((entry) => (
              <button
                key={entry.label}
                type="button"
                className="quick-add__chip"
                aria-label={`Add ${entry.label.toLowerCase()} field`}
                onClick={() => addField(entry.label, entry.type)}
              >
                <Plus /> {entry.label}
              </button>
            ))}
          </div>
          {fieldError ? <p className="create-form__error">{fieldError}</p> : null}
        </div>
      </section>

      <section className="detail-card" aria-label="Attachments">
        <div className="detail-card__head">
          <Paperclip /> Files
        </div>
        <div className="detail-card__body">
          {attachments.length > 0 ? (
            <ul className="stack-list">
              {attachments.map((meta) => (
                <li key={meta.id} className="attachment-card">
                  <div className="attachment-card__top">
                    <Paperclip />
                    <b>{meta.fileName}</b>
                  </div>
                  <small>
                    {formatBytes(meta.sizeBytes)} · {meta.mimeType}
                  </small>
                  <AttachmentPreview meta={meta} />
                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => onDownloadAttachment(meta)}
                      title="Download writes a normal readable copy outside the app"
                    >
                      <Download /> Download
                    </button>
                    <button type="button" className="btn-ghost" onClick={() => onDeleteAttachment(meta)}>
                      <Trash2 /> {confirmingAttachmentId === meta.id ? "Confirm" : "Remove"}
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="hint">No files. They stay encrypted beside the vault.</p>
          )}
          {attachmentError ? <p className="create-form__error">{attachmentError}</p> : null}
          {attachmentNotice ? <p className="notice-ok">{attachmentNotice}</p> : null}
          <button
            type="button"
            className="btn-secondary btn-block"
            onClick={onUploadAttachment}
            disabled={attachmentBusy}
            title="Upload keeps an encrypted copy; the original file is left untouched"
          >
            <Upload /> {attachmentBusy ? "Waiting for file picker…" : "Attach a file…"}
          </button>
        </div>
      </section>

      <section className="detail-card danger-zone" aria-label="Delete account">
        <div className="detail-card__body">
          {confirmingDelete ? (
            <>
              <p className="hint">
                Delete “{account.name}”? Its details and files are removed. Undo is available.
              </p>
              <div className="btn-row">
                <button type="button" className="btn-danger-strong" onClick={onDelete}>
                  Delete account
                </button>
                <button type="button" className="btn-secondary" onClick={() => setConfirmingDelete(false)}>
                  Cancel
                </button>
              </div>
            </>
          ) : (
            <button type="button" className="btn-ghost" onClick={() => setConfirmingDelete(true)}>
              <Trash2 /> Delete account…
            </button>
          )}
        </div>
      </section>
    </aside>
  );
}
