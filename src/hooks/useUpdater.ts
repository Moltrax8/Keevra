import { useEffect, useState } from "react";
import { pickExportFile, updateDownloadManifestAsset, updateFetchSignedManifest, updateVerifyManifest } from "../vaultApi";
import { APP_NAME } from "../brand";
import {
  compareVersionTags,
  isMajorBump,
  isNewerVersion,
  manifestAssets,
  pickInstallerAsset,
  UPDATE_API_LATEST,
  type GitHubRelease,
} from "../updates";
import type { UpdateCheck } from "../components/UpdateDialog";

/** Used only when `getVersion()` is unavailable (browser preview). */
const FALLBACK_VERSION = "0.0.0";

export interface UpdaterApi {
  updateCheck: UpdateCheck;
  updateDismissedTag: string | null;
  updateBusy: boolean;
  dismissUpdate: () => void;
  checkForUpdates: (manual: boolean) => Promise<void>;
  handleUpdateDownload: () => Promise<void>;
  copyReleaseLink: () => Promise<void>;
}

export function useUpdater(): UpdaterApi {
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck>({
    phase: "idle",
    current: FALLBACK_VERSION,
    release: null,
    message: null,
  });
  const [updateDismissedTag, setUpdateDismissedTag] = useState<string | null>(null);
  const [updateBusy, setUpdateBusy] = useState(false);

  async function currentAppVersion(): Promise<string> {
    try {
      const mod = await import("@tauri-apps/api/app");
      return await mod.getVersion();
    } catch {
      return FALLBACK_VERSION;
    }
  }

  /** Progress/result text shown in both the dialog and the settings section. */
  function setStatus(message: string | null) {
    setUpdateCheck((current) => ({ ...current, message }));
  }

  /** Notify-only check: fetches latest GitHub release, never downloads. */
  async function checkForUpdates(manual: boolean): Promise<void> {
    setUpdateCheck((current) => ({ ...current, phase: "checking", message: manual ? "Checking GitHub…" : null }));
    try {
      const current = await currentAppVersion();
      const response = await fetch(UPDATE_API_LATEST, { headers: { Accept: "application/vnd.github+json" } });
      if (!response.ok) throw new Error(`github_${response.status}`);
      const release = (await response.json()) as GitHubRelease;
      if (!release?.tag_name) throw new Error("bad_release");
      if (isNewerVersion(current, release.tag_name)) {
        setUpdateCheck({ phase: "available", current, release, message: null });
      } else {
        setUpdateCheck({
          phase: "up-to-date",
          current,
          release: null,
          message: manual ? `You are on the latest (${current}).` : null,
        });
      }
    } catch {
      // Automatic checks stay silent when offline. A manual check reports it.
      if (manual) {
        setUpdateCheck((current) => ({ ...current, phase: "error", message: "Update check failed (offline?)." }));
      }
    }
  }

  /**
   * User-consented download gated on a signed manifest. Never auto-runs and
   * never opens Settings: progress and verification results stay in the
   * update dialog that asked for consent.
   */
  async function handleUpdateDownload(): Promise<void> {
    const release = updateCheck.release;
    if (!release || updateBusy) return;

    const installer = pickInstallerAsset(release);
    if (!installer) {
      setStatus("No Windows installer on this release. Use “Copy release link” to review it.");
      return;
    }
    // Unsigned releases (pre-signing): no download — manual review only.
    const pair = manifestAssets(release);
    if (!pair) {
      setStatus(
        "This release has no signed manifest (updates.json + .minisig), so download is disabled. Use “Copy release link” and verify manually.",
      );
      return;
    }

    setUpdateBusy(true);
    try {
      const current = await currentAppVersion();
      if (isMajorBump(current, release.tag_name)) {
        const ok = window.confirm(
          `Major version change (${current} → ${release.tag_name}). Review the release notes first. Download anyway?`,
        );
        if (!ok) {
          setStatus("Major-version download cancelled — nothing was fetched.");
          return;
        }
      }

      setStatus("Fetching + verifying signed manifest…");
      let manifestJson = "";
      let manifestSig = "";
      try {
        // Rust, not `fetch`: GitHub release assets carry no CORS headers, so a
        // WebView request is blocked before the signature can be verified.
        const fetched = await updateFetchSignedManifest(pair.manifestUrl, pair.sigUrl);
        manifestJson = fetched.manifestJson;
        manifestSig = fetched.manifestSig;
      } catch {
        setStatus(
          "Could not fetch the signed manifest. Not downloading. Try Settings → Check again, or install the latest release manually.",
        );
        return;
      }

      try {
        const verified = await updateVerifyManifest(manifestJson, manifestSig);
        if (compareVersionTags(verified.version, release.tag_name) !== 0) {
          setStatus("Manifest version does not match the release tag. Treated as untrusted — not downloading.");
          return;
        }
      } catch {
        setStatus("Manifest SIGNATURE INVALID — treated as untrusted. Not downloading.");
        return;
      }

      let dest: string | null = null;
      try {
        dest = await pickExportFile(installer.name);
      } catch {
        setStatus("File picker failed.");
        return;
      }
      if (!dest) {
        setStatus("Download cancelled — nothing was fetched.");
        return;
      }

      setStatus(`Downloading ${installer.name}… (manifest SHA check after download)`);
      try {
        const result = await updateDownloadManifestAsset(
          installer.browser_download_url,
          manifestJson,
          manifestSig,
          current,
          dest,
        );
        setStatus(
          `Verified signed manifest for ${result.version} and SHA-256 (${(result.bytes / 1048576).toFixed(1)} MB). Saved — run the file yourself to update; ${APP_NAME} never installs silently.`,
        );
      } catch (error) {
        const message = typeof error === "string" ? error : "";
        if (message.includes("not_newer")) {
          setStatus("Release is not newer than your version. Nothing downloaded.");
        } else if (
          message.includes("sig_mismatch") ||
          message.includes("sha_mismatch") ||
          message.includes("not_in_manifest")
        ) {
          setStatus("VERIFICATION FAILED — file was NOT saved or installed. Treat the release as untrusted.");
        } else if (message.includes("invalid_update_destination")) {
          setStatus("Save the installer with an .exe file name outside the Keevra data folder.");
        } else if (message.includes("protected_destination")) {
          setStatus("That location belongs to Keevra. Choose a different file name or folder.");
        } else {
          setStatus("Download failed. Nothing was installed.");
        }
      }
    } finally {
      setUpdateBusy(false);
    }
  }

  /**
   * External links cannot be opened reliably from a Tauri WebView without an
   * opener plugin, and `window.open` failing silently was the old no-op bug.
   * Copying the URL with explicit feedback always does something useful; the
   * full release notes are already shown in the dialog.
   */
  async function copyReleaseLink(): Promise<void> {
    const url = updateCheck.release?.html_url;
    if (!url) {
      setStatus("This release has no public page link.");
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
      setStatus(`Release link copied: ${url}`);
    } catch {
      setStatus(`Release link: ${url}`);
    }
  }

  function dismissUpdate() {
    setUpdateDismissedTag(updateCheck.release?.tag_name ?? "dismissed");
  }

  // Notify-only auto-check once per launch (delayed, best-effort, offline = silent).
  useEffect(() => {
    const timer = setTimeout(() => void checkForUpdates(false), 4000);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    updateCheck,
    updateDismissedTag,
    updateBusy,
    dismissUpdate,
    checkForUpdates,
    handleUpdateDownload,
    copyReleaseLink,
  };
}
