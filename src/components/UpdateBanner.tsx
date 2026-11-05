/** Non-silent update notice: never auto-downloads or auto-installs. */
import type { GitHubRelease } from "../updates";
import { APP_NAME } from "../brand";

export interface UpdateCheck {
  phase: "idle" | "checking" | "available" | "up-to-date" | "error";
  current: string;
  release: GitHubRelease | null;
  message: string | null;
}

export function UpdateBanner({
  check,
  onViewNotes,
  onDownload,
  onLater,
  onRecheck,
}: {
  check: UpdateCheck;
  onViewNotes: () => void;
  onDownload: () => void;
  onLater: () => void;
  onRecheck: () => void;
}) {
  if (check.phase === "available" && check.release) {
    return (
      <div className="update-banner" role="status" aria-label="Update available">
        <b>{APP_NAME} {check.release.tag_name} is available</b>
        <span className="hint">You have {check.current}. Nothing downloads without your permission.</span>
        <div className="btn-row">
          <button type="button" className="create-form__submit" onClick={onDownload}>
            Download…
          </button>
          <button type="button" className="btn-secondary" onClick={onViewNotes}>
            Release notes
          </button>
          <button type="button" className="btn-secondary" onClick={onRecheck}>
            Re-check
          </button>
          <button type="button" className="btn-secondary" onClick={onLater}>
            Later
          </button>
        </div>
        <p className="hint">After download the installer SHA256 is checked against GitHub — install only on match.</p>
      </div>
    );
  }
  return null;
}
