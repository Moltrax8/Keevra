/**
 * One detail row: label + value, saved when you leave the field.
 *
 * No type picker and no per-row Save button. Specialized values keep their
 * extras — a live TOTP code, a recovery-code checklist — but the editing
 * surface is just text.
 */
import { useEffect, useRef, useState } from "react";
import { Clock, Copy, Eye, EyeOff, KeyRound, Trash2 } from "lucide-react";
import type { Field, FieldId, AccountId } from "../domain";
import type { FieldPatch } from "../fieldOperations";
import { totpCodeAt, totpSecondsRemaining } from "../totp";
import { consumeRecoveryCode, maskRecoveryCode, parseRecoveryCodes } from "../recoveryCodes";
import { CLIPBOARD_CLEAR_MS, copySecretWithAutoClear } from "../clipboard";
import { describeDomainError, isSecretField } from "../display";

export function FieldRow({
  accountId,
  field,
  autoFocus = false,
  onSave,
  onRemove,
}: {
  accountId: AccountId;
  field: Field;
  autoFocus?: boolean;
  onSave: (accountId: AccountId, fieldId: FieldId, patch: FieldPatch) => string | null;
  onRemove: (accountId: AccountId, fieldId: FieldId) => string | null;
}) {
  const [label, setLabel] = useState(field.label);
  const [value, setValue] = useState(field.value);
  const [revealed, setRevealed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState<string | null>(null);
  const [totpRemaining, setTotpRemaining] = useState<number | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const [newCode, setNewCode] = useState("");
  const [codesRevealed, setCodesRevealed] = useState(false);

  const saved = useRef({ label: field.label, value: field.value });
  const rowRef = useRef<HTMLLIElement>(null);

  // Undo/redo can replace the stored field under this row; resync the drafts.
  useEffect(() => {
    setLabel(field.label);
    setValue(field.value);
    saved.current = { label: field.label, value: field.value };
  }, [field.label, field.value]);

  // Drafts used to survive only until blur. Save them after a short pause and
  // on an explicit close-time flush so an unexpected exit loses less work. A
  // focused row is left alone: blur/close already save it, and re-rendering
  // mid-typing would move the caret.
  useEffect(() => {
    const flush = () => save();
    window.addEventListener("keevra:flush-drafts", flush);
    const dirtyDraft = label !== saved.current.label || value !== saved.current.value;
    const focused = rowRef.current !== null && rowRef.current.contains(document.activeElement);
    const timer = dirtyDraft && !focused ? setTimeout(flush, 500) : null;
    return () => {
      if (timer !== null) clearTimeout(timer);
      window.removeEventListener("keevra:flush-drafts", flush);
    };
  }, [label, value]);

  useEffect(() => {
    if (field.type !== "TOTP" || field.value.trim() === "") {
      setTotpCode(null);
      return;
    }
    let cancelled = false;
    const refresh = async () => {
      try {
        const code = await totpCodeAt(field.value, Date.now() / 1000);
        if (!cancelled) {
          setTotpCode(code);
          setTotpRemaining(totpSecondsRemaining(Date.now() / 1000));
        }
      } catch {
        if (!cancelled) setTotpCode(null);
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [field.type, field.value]);

  function save() {
    if (label === saved.current.label && value === saved.current.value) return;
    const message = onSave(accountId, field.id, { label, value });
    setError(message);
    if (message === null) saved.current = { label, value };
  }

  async function copyText(text: string) {
    try {
      await copySecretWithAutoClear(text);
      setCopyNotice(`Copied. Clipboard clears in ${Math.round(CLIPBOARD_CLEAR_MS / 1000)}s.`);
    } catch {
      setCopyNotice("Copy failed.");
    }
  }

  function handleConsumeCode(entryCode: string) {
    const consumed = consumeRecoveryCode(field.id, field.value, entryCode);
    if (!consumed.ok) {
      setError(describeDomainError(consumed.error.code));
      return;
    }
    setError(onSave(accountId, field.id, { value: consumed.value }));
  }

  function handleAddCode() {
    const code = newCode.trim();
    if (code === "") {
      setError("Enter a recovery code.");
      return;
    }
    const next = field.value.trim() === "" ? code : `${field.value.replace(/\s+$/, "")}\n${code}`;
    const message = onSave(accountId, field.id, { value: next });
    setError(message);
    if (message === null) setNewCode("");
  }

  const recoveryEntries = field.type === "RecoveryCodes" ? parseRecoveryCodes(field.value) : [];
  const secret = isSecretField(field.type);
  const isNote = field.type === "Note";

  return (
    <li className="field-row" ref={rowRef}>
      <div className="field-row__head">
        <input
          type="text"
          className="field-row__label"
          value={label}
          onChange={(event) => setLabel(event.target.value)}
          onBlur={save}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              event.currentTarget.blur();
            }
          }}
          aria-label="Field label"
          placeholder="Label"
        />
        <span className={`field-type-badge${secret ? " field-type-badge--secret" : ""}`}>{field.type}</span>
        <button
          type="button"
          className="field-row__remove"
          onClick={() => setError(onRemove(accountId, field.id))}
          aria-label={`Remove ${field.label} field`}
          title="Remove this detail (Ctrl+Z to undo)"
        >
          <Trash2 />
        </button>
      </div>

      {field.type === "RecoveryCodes" ? (
        <div className="recovery-list">
          {recoveryEntries.length > 0 ? (
            <>
              <div className="recovery-list__head">
                <span>
                  {recoveryEntries.length} code{recoveryEntries.length === 1 ? "" : "s"}
                </span>
                <button
                  type="button"
                  className="mini-btn"
                  onClick={() => setCodesRevealed((current) => !current)}
                  aria-label={codesRevealed ? "Hide recovery codes" : "Reveal recovery codes"}
                >
                  {codesRevealed ? <EyeOff /> : <Eye />}
                  {codesRevealed ? "Hide" : "Reveal"}
                </button>
              </div>
              {recoveryEntries.map((entry) => (
                <div className="recovery-code" key={entry.code}>
                  <KeyRound />
                  <span className={entry.used ? "recovery-list__used" : undefined}>
                    {codesRevealed ? entry.code : maskRecoveryCode(entry.code)}
                  </span>
                  <span className="recovery-code__actions">
                    <button
                      type="button"
                      className="mini-btn"
                      onClick={() => void copyText(entry.code)}
                      aria-label="Copy recovery code"
                      title="Copy"
                    >
                      <Copy />
                    </button>
                    {entry.used ? (
                      <small>Used</small>
                    ) : (
                      <button
                        type="button"
                        className="mini-btn"
                        onClick={() => handleConsumeCode(entry.code)}
                      >
                        Mark used
                      </button>
                    )}
                  </span>
                </div>
              ))}
            </>
          ) : (
            <p className="hint">No codes yet.</p>
          )}
          <div className="field-row__value">
            <input
              type="text"
              placeholder="New recovery code"
              value={newCode}
              onChange={(event) => setNewCode(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  handleAddCode();
                }
              }}
              aria-label="New recovery code"
            />
            <button type="button" className="mini-btn" onClick={handleAddCode}>
              Add
            </button>
          </div>
        </div>
      ) : (
        <div className="field-row__value">
          {isNote ? (
            <textarea
              value={value}
              onChange={(event) => setValue(event.target.value)}
              onBlur={save}
              aria-label="Field value"
              placeholder="Write anything…"
              rows={3}
            />
          ) : (
            <input
              type={revealed || !secret ? "text" : "password"}
              value={value}
              onChange={(event) => setValue(event.target.value)}
              onBlur={save}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  event.currentTarget.blur();
                }
              }}
              autoFocus={autoFocus}
              aria-label="Field value"
              placeholder="Value"
            />
          )}
          {secret ? (
            <button
              type="button"
              className="field-row__reveal"
              onClick={() => setRevealed((current) => !current)}
              aria-label={revealed ? "Hide field value" : "Reveal field value"}
              title={revealed ? "Hide" : "Reveal"}
            >
              {revealed ? <EyeOff /> : <Eye />}
            </button>
          ) : null}
          {value !== "" ? (
            <button
              type="button"
              className="field-row__reveal"
              onClick={() => void copyText(value)}
              aria-label="Copy field value"
              title="Copy"
            >
              <Copy />
            </button>
          ) : null}
        </div>
      )}

      {field.type === "TOTP" ? (
        <div className="totp-box" aria-live="polite">
          {totpCode !== null ? (
            <>
              <div className="totp-box__code">{totpCode}</div>
              <div className="totp-box__meta">
                <Clock />
                <span>{totpRemaining ?? 30}s left</span>
                <button type="button" className="mini-btn" onClick={() => void copyText(totpCode)}>
                  <Copy /> Copy code
                </button>
              </div>
              <div className="totp-bar" aria-hidden="true">
                <i style={{ width: `${(((totpRemaining ?? 30) / 30) * 100).toFixed(1)}%` }} />
              </div>
            </>
          ) : (
            <span className="hint">Invalid seed.</span>
          )}
        </div>
      ) : null}

      {error ? <p className="create-form__error">{error}</p> : null}
      {copyNotice && field.type !== "TOTP" ? <p className="hint">{copyNotice}</p> : null}
    </li>
  );
}
