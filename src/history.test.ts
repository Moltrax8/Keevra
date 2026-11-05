import { describe, expect, it } from "vitest";
import {
  emptyHistory,
  MAX_HISTORY_ENTRIES,
  pushHistory,
  redoStep,
  retainedAttachmentIds,
  snapshotOf,
  undoStep,
  type DomainSnapshot,
} from "./history";
import type { Account } from "./domain";

function account(id: string): Account {
  return { id, name: id, service: "", tags: [], fields: [] };
}

function snapshot(accountIds: string[] = [], attachmentIds: string[] = []): DomainSnapshot {
  return snapshotOf(
    accountIds.map(account),
    [],
    attachmentIds.map((id) => ({
      id,
      nodeId: "a",
      fileName: "f",
      mimeType: "application/octet-stream",
      sizeBytes: 1,
      sha256Hex: "ab".repeat(32),
      createdAtMs: 0,
    })),
  );
}

describe("history", () => {
  it("undoes and redoes one step", () => {
    const history = pushHistory(emptyHistory(), snapshot(["a"]));
    const undone = undoStep(history, snapshot(["a", "b"]));
    expect(undone?.snapshot.accounts.map((entry) => entry.id)).toEqual(["a"]);
    const redone = redoStep(undone!.history, undone!.snapshot);
    expect(redone?.snapshot.accounts.map((entry) => entry.id)).toEqual(["a", "b"]);
  });

  it("returns null at the ends and clears redo on push", () => {
    expect(undoStep(emptyHistory(), snapshot())).toBeNull();
    expect(redoStep(emptyHistory(), snapshot())).toBeNull();
    const history = pushHistory({ past: [snapshot(["a"])], future: [snapshot(["b"])] }, snapshot(["c"]));
    expect(history.future).toEqual([]);
    expect(history.past.map((entry) => entry.accounts.length)).toEqual([1, 1]);
  });

  it("caps the past at MAX_HISTORY_ENTRIES", () => {
    let history = emptyHistory();
    for (let i = 0; i < MAX_HISTORY_ENTRIES + 10; i++) {
      history = pushHistory(history, snapshot([`a-${i}`]));
    }
    expect(history.past.length).toBe(MAX_HISTORY_ENTRIES);
  });

  it("retains attachment IDs across current, past, and future", () => {
    const history = {
      past: [snapshot([], ["p1"])],
      future: [snapshot([], ["f1"])],
    };
    expect(retainedAttachmentIds(snapshot([], ["c1"]), history).sort()).toEqual(["c1", "f1", "p1"]);
  });
});
