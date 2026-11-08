// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  pickExportFile,
  updateDownloadManifestAsset,
  updateFetchSignedManifest,
  updateVerifyManifest,
} from "../vaultApi";
import { useUpdater } from "./useUpdater";

vi.mock("../vaultApi", () => ({
  pickExportFile: vi.fn(),
  updateDownloadManifestAsset: vi.fn(),
  updateFetchSignedManifest: vi.fn(),
  updateVerifyManifest: vi.fn(),
}));

// Same major version as the fake release, so the extra major-bump confirm (a
// blocking window.confirm) does not interfere with the download flow.
vi.mock("@tauri-apps/api/app", () => ({ getVersion: async () => "9.9.8" }));

const RELEASE = {
  tag_name: "v9.9.9",
  html_url: "https://github.com/Moltrax8/Keevra/releases/tag/v9.9.9",
  body: "**Test release.**",
  published_at: "2026-11-08T00:00:00Z",
  assets: [
    {
      name: "Keevra_9.9.9_x64-setup.exe",
      browser_download_url:
        "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/Keevra_9.9.9_x64-setup.exe",
    },
    {
      name: "updates.json",
      browser_download_url: "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/updates.json",
    },
    {
      name: "updates.json.minisig",
      browser_download_url:
        "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/updates.json.minisig",
    },
  ],
};

const MANIFEST_URL = "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/updates.json";
const SIG_URL = "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/updates.json.minisig";

const fetchMock = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  fetchMock.mockResolvedValue({ ok: true, json: async () => RELEASE });
  vi.stubGlobal("fetch", fetchMock);
});

async function availableUpdater() {
  const hook = renderHook(() => useUpdater());
  await act(async () => {
    await hook.result.current.checkForUpdates(true);
  });
  expect(hook.result.current.updateCheck.phase).toBe("available");
  return hook;
}

describe("update download", () => {
  it("fetches and verifies the signed manifest through Rust, never through fetch()", async () => {
    // GitHub release assets send no CORS headers, so a WebView fetch() would be
    // blocked before the signature check. The manifest must come from the
    // backend command with the same allow-list as the installer download.
    vi.mocked(updateFetchSignedManifest).mockResolvedValue({
      manifestJson: '{"version":"9.9.9","assets":[]}',
      manifestSig: "c2ln",
    });
    vi.mocked(updateVerifyManifest).mockResolvedValue({ version: "9.9.9", assetNames: [] });
    vi.mocked(pickExportFile).mockResolvedValue("C:\\Users\\me\\Keevra_9.9.9_x64-setup.exe");
    vi.mocked(updateDownloadManifestAsset).mockResolvedValue({ bytes: 2048, version: "9.9.9" });

    const hook = await availableUpdater();
    fetchMock.mockClear();

    await act(async () => {
      await hook.result.current.handleUpdateDownload();
    });

    expect(updateFetchSignedManifest).toHaveBeenCalledWith(MANIFEST_URL, SIG_URL);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(updateDownloadManifestAsset).toHaveBeenCalledWith(
      "https://github.com/Moltrax8/Keevra/releases/download/v9.9.9/Keevra_9.9.9_x64-setup.exe",
      '{"version":"9.9.9","assets":[]}',
      "c2ln",
      expect.any(String),
      "C:\\Users\\me\\Keevra_9.9.9_x64-setup.exe",
    );
    expect(hook.result.current.updateCheck.message).toContain("Verified signed manifest");
  });

  it("reports a backend fetch failure without touching the installer", async () => {
    vi.mocked(updateFetchSignedManifest).mockRejectedValue("update_download_failed");

    const hook = await availableUpdater();
    await act(async () => {
      await hook.result.current.handleUpdateDownload();
    });

    expect(updateDownloadManifestAsset).not.toHaveBeenCalled();
    expect(pickExportFile).not.toHaveBeenCalled();
    expect(hook.result.current.updateCheck.message).toContain("Could not fetch the signed manifest");
  });

  it("refuses to download when the manifest signature is invalid", async () => {
    vi.mocked(updateFetchSignedManifest).mockResolvedValue({ manifestJson: "{}", manifestSig: "bad" });
    vi.mocked(updateVerifyManifest).mockRejectedValue("update_sig_mismatch");

    const hook = await availableUpdater();
    await act(async () => {
      await hook.result.current.handleUpdateDownload();
    });

    expect(updateDownloadManifestAsset).not.toHaveBeenCalled();
    expect(hook.result.current.updateCheck.message).toContain("SIGNATURE INVALID");
  });
});
