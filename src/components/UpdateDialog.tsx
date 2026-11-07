/** Non-silent update notice: never auto-downloads or auto-installs. */
import { Download, ExternalLink, Sparkles } from "lucide-react";
import type { GitHubRelease } from "../updates";
import { APP_NAME } from "../brand";

export interface UpdateCheck {
  phase: "idle" | "checking" | "available" | "up-to-date" | "error";
  current: string;
  release: GitHubRelease | null;
  message: string | null;
}

/**
 * Modal announcement for a newer release. Rendered at the app root so it also
 * appears on the lock screen, before the vault is opened (the previous banner
 * lived inside the unlocked layout and therefore showed up late).
 *
 * The release body is displayed inline: review what changed, then choose
 * "Download update" or "Not now". Nothing is fetched or installed until the
 * user consents.
 */
export function UpdateDialog({
  check,
  busy,
  onDownload,
  onLater,
  onCopyLink,
}: {
  check: UpdateCheck;
  busy: boolean;
  onDownload: () => void;
  onLater: () => void;
  onCopyLink: () => void;
}) {
  if (check.phase !== "available" || !check.release) return null;

  const notes = check.release.body?.trim() ?? "";
  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Update available"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onLater();
      }}
    >
      <section className="create-form lock-screen__card modal-card update-dialog">
        <h2>
          <Sparkles style={{ width: 18, height: 18 }} /> {APP_NAME} {check.release.tag_name} is available
        </h2>
        <p className="lock-sub">
          You have {check.current}. Nothing downloads or installs without your permission.
        </p>

        <h3 className="stack-heading">What changed</h3>
        {notes !== "" ? (
          <pre className="update-notes" aria-label="Release notes">{notes}</pre>
        ) : (
          <p className="hint">No release notes were published for this version.</p>
        )}

        {check.message ? <p className="hint update-dialog__message">{check.message}</p> : null}

        <div className="btn-row">
          <button
            type="button"
            className="create-form__submit"
            onClick={onDownload}
            disabled={busy}
          >
            <Download style={{ width: 14, height: 14 }} /> {busy ? "Working…" : "Download update…"}
          </button>
          <button type="button" className="btn-secondary" onClick={onLater} disabled={busy}>
            Not now
          </button>
          <button type="button" className="btn-secondary" onClick={onCopyLink}>
            <ExternalLink style={{ width: 14, height: 14 }} /> Copy release link
          </button>
        </div>
        <p className="hint">
          The installer is checked against the signed manifest and its SHA-256. {APP_NAME} never
          installs silently; you run the saved file yourself.
        </p>
      </section>
    </div>
  );
}
