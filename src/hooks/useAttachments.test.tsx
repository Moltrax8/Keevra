// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, AttachmentMeta } from "../domain";
import { attachmentImport, pickImportFile } from "../vaultApi";
import { useAttachments, type AttachmentUiApi } from "./useAttachments";

vi.mock("../vaultApi", () => ({
  attachmentImport: vi.fn(),
  attachmentExport: vi.fn(),
  pickImportFile: vi.fn(),
  pickExportFile: vi.fn(),
}));

const account: Account = { id: "acc-1", name: "Mail", service: "Mail", tags: [], fields: [] };

function makeMeta(): AttachmentMeta {
  return {
    id: "att-1",
    nodeId: "acc-1",
    fileName: "secret.bin",
    mimeType: "application/octet-stream",
    sizeBytes: 4,
    sha256Hex: "0".repeat(64),
    createdAtMs: 0,
  };
}

interface HarnessState {
  attachments: AttachmentMeta[];
  epoch: number;
  setEpoch: (next: number) => void;
  commit: ReturnType<typeof vi.fn>;
}

type Harness = HarnessState & AttachmentUiApi;

function useHarness(initialEpoch = 0): Harness {
  const [attachments, setAttachments] = useState<AttachmentMeta[]>([]);
  const [epoch, setEpoch] = useState(initialEpoch);
  // Stable commit mock: recreating it per render would reset the call count
  // being asserted after the flush.
  const { current: commit } = useRef(vi.fn());
  const api = useAttachments({
    selectedAccount: account,
    documentEpoch: epoch,
    setAttachments,
    commit,
  });
  return { attachments, epoch, setEpoch, commit, ...api };
}

/**
 * Starts an upload and parks it on the deferred import. One macro-task is
 * enough for the picker promise plus the import call to settle; the test then
 * resolves the deferred to let the epoch guard run.
 */
function armUpload() {
  let settle!: (meta: AttachmentMeta) => void;
  const gate = new Promise<AttachmentMeta>((resolve) => {
    settle = resolve;
  });
  vi.mocked(pickImportFile).mockResolvedValue("C:\\secret.bin");
  vi.mocked(attachmentImport).mockReturnValue(gate);
  return settle;
}

describe("useAttachments document epoch (K-03)", () => {
  beforeEach(() => {
    vi.mocked(pickImportFile).mockClear();
    vi.mocked(attachmentImport).mockClear();
  });

  it("applies metadata when the document did not change", async () => {
    const settle = armUpload();

    const { result } = renderHook(() => useHarness(0));
    let upload!: Promise<void>;
    await act(async () => {
      upload = result.current.uploadAttachment();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(vi.mocked(attachmentImport).mock.calls.length).toBe(1);

    settle(makeMeta());
    await act(async () => {
      await upload;
    });

    expect(result.current.attachments).toHaveLength(1);
    expect(result.current.attachments[0].fileName).toBe("secret.bin");
  });

  it("drops metadata when the vault switched while the import was running", async () => {
    const settle = armUpload();

    const { result } = renderHook(() => useHarness(0));
    let upload!: Promise<void>;
    await act(async () => {
      upload = result.current.uploadAttachment();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(vi.mocked(attachmentImport).mock.calls.length).toBe(1);

    // Open/create/lock replaces the document and bumps the epoch.
    act(() => {
      result.current.setEpoch(1);
    });

    settle(makeMeta());
    await act(async () => {
      await upload;
    });

    expect(result.current.attachments).toHaveLength(0);
    expect(result.current.commit).not.toHaveBeenCalled();
  });

  it("waitForPending resolves only after the in-flight import finishes", async () => {
    const settle = armUpload();

    const { result } = renderHook(() => useHarness(0));
    let upload!: Promise<void>;
    await act(async () => {
      upload = result.current.uploadAttachment();
      await new Promise((r) => setTimeout(r, 0));
    });

    let finished = false;
    const waiting = result.current.waitForPending().then(() => {
      finished = true;
    });

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(finished).toBe(false);

    settle(makeMeta());
    await act(async () => {
      await Promise.all([upload, waiting]);
    });
    expect(finished).toBe(true);
    expect(result.current.attachments).toHaveLength(1);
  });
});
