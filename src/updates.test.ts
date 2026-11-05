import { describe, expect, it } from "vitest";
import {
  compareVersionTags,
  isMajorBump,
  isNewerVersion,
  manifestAssets,
  parseVersionTag,
  pickInstallerAsset,
  type GitHubRelease,
} from "./updates";

function release(tag: string): GitHubRelease {
  return {
    tag_name: tag,
    html_url: `https://github.com/x/y/releases/tag/${tag}`,
    body: null,
    assets: [
      { name: "Keevra_1.0.1_x64-setup.exe", browser_download_url: "https://example.com/a.exe" },
      { name: "Keevra_1.0.1_x64-setup.exe.sha256", browser_download_url: "https://example.com/a.exe.sha256" },
    ],
  };
}

describe("updater version compare", () => {
  it("parses v-prefixed tags", () => {
    expect(parseVersionTag("v1.0.1")).toEqual([1, 0, 1]);
    expect(parseVersionTag("0.1.1")).toEqual([0, 1, 1]);
  });

  it("detects newer releases (v1.0.0 -> v1.0.1)", () => {
    expect(isNewerVersion("v1.0.0", "v1.0.1")).toBe(true);
    expect(isNewerVersion("v1.0.1", "v1.0.0")).toBe(false);
    expect(isNewerVersion("v1.0.1", "v1.0.1")).toBe(false);
    expect(compareVersionTags("0.1.1", "0.2.0")).toBe(-1);
  });

  it("picks the installer asset (-setup.exe suffix, name-agnostic)", () => {
    const rel = release("v1.0.1");
    expect(pickInstallerAsset(rel)?.name).toContain("-setup.exe");
    expect(pickInstallerAsset({ ...rel, assets: [] })).toBe(null);
  });

  it("finds signed manifests and detects major bumps", () => {
    const signed: GitHubRelease = {
      ...release("v1.0.1"),
      assets: [
        { name: "Keevra_1.0.1_x64-setup.exe", browser_download_url: "https://example.com/a.exe" },
        { name: "updates.json", browser_download_url: "https://example.com/updates.json" },
        { name: "updates.json.minisig", browser_download_url: "https://example.com/updates.json.minisig" },
      ],
    };
    expect(manifestAssets(signed)?.manifestUrl).toContain("updates.json");
    expect(manifestAssets(release("v1.0.1"))).toBe(null);
    expect(isMajorBump("0.2.0", "1.0.0")).toBe(true);
    expect(isMajorBump("0.2.0", "0.3.0")).toBe(false);
  });
});
