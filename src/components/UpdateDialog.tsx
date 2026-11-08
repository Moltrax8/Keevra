/** Non-silent update notice: never auto-downloads or auto-installs. */
import { Download, ExternalLink, Sparkles } from "lucide-react";
import type { GitHubRelease } from "../updates";
import { APP_NAME } from "../brand";
import { ReleaseNotes } from "./ReleaseNotes";

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
 * The release body is rendered as structured, sectional release notes:
 * review what changed, then choose "Download update" or "Not now". Nothing is
 * fetched or installed until the user consents.
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

  return (
    <div
      className="modal-overlay update-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Update available"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onLater();
      }}
    >
      <section className="create-form lock-screen__card modal-card update-dialog">
        <p className="update-dialog__eyebrow">
          <Sparkles aria-hidden="true" style={{ width: 14, height: 14 }} />
          <span>
            {APP_NAME} {check.release.tag_name} is available. You have {check.current}.
          </span>
        </p>

        <ReleaseNotes
          body={check.release.body}
          tag={check.release.tag_name}
          publishedAt={check.release.published_at}
        />

        {check.message ? <p className="hint update-dialog__message">{check.message}</p> : null}

        <div className="update-dialog__footer">
          <button
            type="button"
            className="update-dialog__details"
            onClick={onCopyLink}
            aria-label="Copy release link (full changelog and technical details)"
          >
            Full changelog and technical details
            <ExternalLink aria-hidden="true" style={{ width: 13, height: 13 }} />
          </button>
          <button type="button" className="btn-secondary" onClick={onLater} disabled={busy}>
            Not now
          </button>
        </div>

        <button
          type="button"
          className="create-form__submit update-dialog__download"
          onClick={onDownload}
          disabled={busy}
        >
          <Download style={{ width: 14, height: 14 }} /> {busy ? "Working…" : "Download update"}
        </button>

        <p className="hint">
          The installer is checked against the signed manifest and its SHA-256. {APP_NAME} never
          installs silently; you run the saved file yourself.
        </p>
      </section>
    </div>
  );
}
