import { useEffect, useState } from "react";
import { pickExportFile, updateDownloadManifestAsset, updateVerifyManifest } from "../vaultApi";
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
import type { UpdateCheck } from "../components/UpdateBanner";

export interface UpdaterOptions {
  openSettings: () => void;
  setMessage: (message: string | null) => void;
}

export interface UpdaterApi {
  updateCheck: UpdateCheck;
  updateDismissedTag: string | null;
  dismissUpdate: () => void;
  checkForUpdates: (manual: boolean) => Promise<void>;
  handleUpdateDownload: () => Promise<void>;
  handleUpdateNotes: () => void;
}

export function useUpdater({ openSettings, setMessage }: UpdaterOptions): UpdaterApi {
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck>({
    phase: "idle",
    current: "0.3.0",
    release: null,
    message: null,
  });
  const [updateDismissedTag, setUpdateDismissedTag] = useState<string | null>(null);

  async function currentAppVersion(): Promise<string> {
    try {
      const mod = await import("@tauri-apps/api/app");
      return await mod.getVersion();
    } catch {
      return updateCheck.current;
    }
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
      if (manual) {
        setUpdateCheck((current) => ({ ...current, phase: "error", message: "Update check failed (offline?)." }));
      } else {
        setUpdateCheck((current) => (current.phase === "idle" ? { ...current, phase: "idle" } : current));
      }
    }
  }

  /** User-consented download gated on a signed manifest. Never auto-runs. */
  async function handleUpdateDownload() {
    const release = updateCheck.release;
    if (!release) return;
    const installer = pickInstallerAsset(release);
    if (!installer) {
      setMessage("No Windows installer on this release. See the release page.");
      openSettings();
      return;
    }
    // Unsigned releases (pre-signing): no download — manual review only.
    // This is the secure default going forward.
    const pair = manifestAssets(release);
    if (!pair) {
      setMessage(
        "This release has no signed manifest (updates.json + .minisig) — download is disabled. Open the release page and verify manually.",
      );
      openSettings();
      return;
    }
    const current = await currentAppVersion();
    if (isMajorBump(current, release.tag_name)) {
      const ok = window.confirm(
        `Major version change (${current} → ${release.tag_name}). Review the release notes first. Download anyway?`,
      );
      if (!ok) {
        setMessage("Major-version download cancelled — nothing was fetched.");
        return;
      }
    }
    setMessage("Fetching + verifying signed manifest…");
    openSettings();
    let manifestJson = "";
    let manifestSig = "";
    try {
      const [manifestResponse, sigResponse] = await Promise.all([fetch(pair.manifestUrl), fetch(pair.sigUrl)]);
      if (!manifestResponse.ok || !sigResponse.ok) throw new Error("manifest_fetch");
      manifestJson = await manifestResponse.text();
      manifestSig = await sigResponse.text();
    } catch {
      setMessage("Could not fetch the signed manifest. Not downloading.");
      return;
    }
    try {
      const verified = await updateVerifyManifest(manifestJson, manifestSig);
      if (compareVersionTags(verified.version, release.tag_name) !== 0) {
        setMessage("Manifest version does not match the release tag. Treated as untrusted — not downloading.");
        return;
      }
    } catch {
      setMessage("Manifest SIGNATURE INVALID — treated as untrusted. Not downloading.");
      return;
    }
    // Legacy sidecar is informational only — authority is the signed manifest.
    let dest: string | null = null;
    try {
      dest = await pickExportFile(installer.name);
    } catch {
      setMessage("File picker failed.");
      return;
    }
    if (!dest) {
      setMessage("Download cancelled — nothing was fetched.");
      return;
    }
    setMessage(`Downloading ${installer.name}… (manifest SHA check after download)`);
    try {
      const result = await updateDownloadManifestAsset(
        installer.browser_download_url,
        manifestJson,
        manifestSig,
        current,
        dest,
      );
      setMessage(
        `Verified signed manifest for ${result.version} + SHA256 (${(result.bytes / 1048576).toFixed(1)} MB) and saved. Run the file yourself to update — ${APP_NAME} never installs silently.`,
      );
    } catch (error) {
      const message = typeof error === "string" ? error : "";
      if (message.includes("not_newer")) {
        setMessage("Release is not newer than your version. Nothing downloaded.");
      } else if (
        message.includes("sig_mismatch") ||
        message.includes("sha_mismatch") ||
        message.includes("not_in_manifest")
      ) {
        setMessage("VERIFICATION FAILED — file was NOT saved or installed. Treat the release as untrusted.");
      } else {
        setMessage("Download failed. Nothing was installed.");
      }
    }
  }

  function handleUpdateNotes() {
    const url = updateCheck.release?.html_url;
    if (!url) return;
    try {
      window.open(url, "_blank", "noopener,noreferrer");
    } catch {
      void navigator.clipboard?.writeText(url).catch(() => {});
      setMessage(`Release notes: ${url} (link copied).`);
      openSettings();
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
    dismissUpdate,
    checkForUpdates,
    handleUpdateDownload,
    handleUpdateNotes,
  };
}
