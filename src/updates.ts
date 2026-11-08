/**
 * Notify-only updater helpers (pure, testable).
 *
 * Policy: never silent. The app checks GitHub releases, notifies when a
 * newer tag exists, downloads only with explicit user consent, verifies a
 * signed manifest and the manifest's SHA256, and never auto-launches the
 * installer — the user runs it manually.
 */

/** Updater identity lives in brand.ts so a rename only edits one place. */
export { UPDATE_OWNER, UPDATE_REPO, UPDATE_API_LATEST } from "./brand";

export interface GitHubAsset {
  name: string;
  browser_download_url: string;
}

export interface GitHubRelease {
  tag_name: string;
  html_url: string;
  body: string | null;
  published_at?: string | null;
  assets: GitHubAsset[];
}

/** "v1.0.1" / "1.0.1" -> [1,0,1]; non-numeric parts ignored. */
export function parseVersionTag(tag: string): number[] {
  const cleaned = tag.trim().replace(/^v/i, "");
  return cleaned
    .split(".")
    .map((part) => Number.parseInt(part.replace(/[^0-9].*$/, ""), 10))
    .map((n) => (Number.isFinite(n) ? n : 0));
}

/** -1 | 0 | 1 comparing semantic version tags. */
export function compareVersionTags(a: string, b: string): number {
  const pa = parseVersionTag(a);
  const pb = parseVersionTag(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

export function isNewerVersion(current: string, latest: string): boolean {
  return compareVersionTags(current, latest) < 0;
}

/** Picks the Windows NSIS installer asset (`*-setup.exe`). */
export function pickInstallerAsset(release: GitHubRelease): GitHubAsset | null {
  const exe = release.assets.find((asset) => asset.name.toLowerCase().endsWith("-setup.exe"));
  return exe ?? null;
}

/** Signed manifest authority (`updates.json` + `.minisig` per release). */
export interface UpdateManifestAsset {
  name: string;
  sha256: string;
}

export interface UpdateManifest {
  version: string;
  assets: UpdateManifestAsset[];
}

export const MANIFEST_ASSET_NAME = "updates.json";
export const MANIFEST_SIG_ASSET_NAME = "updates.json.minisig";

export function manifestAssets(release: GitHubRelease): { manifestUrl: string; sigUrl: string } | null {
  const manifest = release.assets.find((asset) => asset.name === MANIFEST_ASSET_NAME);
  const sig = release.assets.find((asset) => asset.name === MANIFEST_SIG_ASSET_NAME);
  if (!manifest || !sig) return null;
  return { manifestUrl: manifest.browser_download_url, sigUrl: sig.browser_download_url };
}

/** True when crossing a major version (extra confirm in UI). */
export function isMajorBump(current: string, latest: string): boolean {
  const major = (tag: string): number => {
    const n = Number.parseInt(tag.trim().replace(/^v/i, "").split(".")[0]?.replace(/[^0-9].*$/, "") ?? "0", 10);
    return Number.isFinite(n) ? n : 0;
  };
  return major(current) !== major(latest);
}


