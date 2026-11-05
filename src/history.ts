import type { Account, AccountPreset, AttachmentMeta } from "./domain";

/**
 * Undo/redo over vault domain state (v0.1.0 user request: no manual save).
 *
 * A snapshot covers everything the vault document holds. Attachment BLOB
 * bytes are not snapshotted; instead the save-time sweep retains blobs
 * referenced by any live, undo, or redo snapshot, so undoing within a
 * session never resurrects dangling metadata. History is per unlock session
 * and cleared on lock/open/create.
 */
export interface DomainSnapshot {
  readonly accounts: readonly Account[];
  readonly presets: readonly AccountPreset[];
  readonly attachments: readonly AttachmentMeta[];
  readonly serviceIcons: Readonly<Record<string, string>>;
}

export interface HistoryState {
  readonly past: readonly DomainSnapshot[];
  readonly future: readonly DomainSnapshot[];
}

export const MAX_HISTORY_ENTRIES = 100;

export function emptyHistory(): HistoryState {
  return { past: [], future: [] };
}

export function snapshotOf(
  accounts: readonly Account[],
  presets: readonly AccountPreset[],
  attachments: readonly AttachmentMeta[],
  serviceIcons: Readonly<Record<string, string>> = {},
): DomainSnapshot {
  return {
    accounts: [...accounts],
    presets: [...presets],
    attachments: [...attachments],
    serviceIcons: { ...serviceIcons },
  };
}

/** Records the pre-mutation snapshot; any redo future is discarded. */
export function pushHistory(history: HistoryState, snapshot: DomainSnapshot): HistoryState {
  const past = [...history.past, snapshot].slice(-MAX_HISTORY_ENTRIES);
  return { past, future: [] };
}

/** Steps back one snapshot. Returns null when there is nothing to undo. */
export function undoStep(
  history: HistoryState,
  current: DomainSnapshot,
): { history: HistoryState; snapshot: DomainSnapshot } | null {
  if (history.past.length === 0) return null;
  const snapshot = history.past[history.past.length - 1];
  return {
    history: { past: history.past.slice(0, -1), future: [current, ...history.future] },
    snapshot,
  };
}

/** Steps forward one snapshot. Returns null when there is nothing to redo. */
export function redoStep(
  history: HistoryState,
  current: DomainSnapshot,
): { history: HistoryState; snapshot: DomainSnapshot } | null {
  if (history.future.length === 0) return null;
  const [snapshot, ...future] = history.future;
  return {
    history: { past: [...history.past, current].slice(-MAX_HISTORY_ENTRIES), future },
    snapshot,
  };
}

/** Every attachment ID the sweep must retain: live plus all history. */
export function retainedAttachmentIds(
  current: DomainSnapshot,
  history: HistoryState,
): string[] {
  const ids = new Set<string>();
  const collect = (snapshot: DomainSnapshot) => {
    for (const attachment of snapshot.attachments) ids.add(attachment.id);
  };
  collect(current);
  for (const snapshot of history.past) collect(snapshot);
  for (const snapshot of history.future) collect(snapshot);
  return [...ids];
}
