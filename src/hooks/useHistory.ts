import { useEffect, useEffectEvent, useState } from "react";
import {
  emptyHistory,
  pushHistory,
  redoStep,
  undoStep,
  type DomainSnapshot,
  type HistoryState,
} from "../history";

export interface HistoryApi {
  history: HistoryState;
  /** Records the pre-mutation snapshot; any redo future is discarded. */
  commit: (snapshot: DomainSnapshot) => void;
  /** Steps back one snapshot. Returns the snapshot to apply, or null. */
  undo: (current: DomainSnapshot) => DomainSnapshot | null;
  /** Steps forward one snapshot. Returns the snapshot to apply, or null. */
  redo: (current: DomainSnapshot) => DomainSnapshot | null;
  /** Clears history on lock/open/create. */
  reset: () => void;
}

export function useHistory(): HistoryApi {
  const [history, setHistory] = useState<HistoryState>(emptyHistory);

  function commit(snapshot: DomainSnapshot) {
    setHistory((current) => pushHistory(current, snapshot));
  }

  function undo(current: DomainSnapshot): DomainSnapshot | null {
    const step = undoStep(history, current);
    if (!step) return null;
    setHistory(step.history);
    return step.snapshot;
  }

  function redo(current: DomainSnapshot): DomainSnapshot | null {
    const step = redoStep(history, current);
    if (!step) return null;
    setHistory(step.history);
    return step.snapshot;
  }

  function reset() {
    setHistory(emptyHistory());
  }

  return { history, commit, undo, redo, reset };
}

/** Undo/redo keys everywhere except while typing in form controls. */
export function useUndoRedoShortcuts(undo: () => void, redo: () => void) {
  const undoRef = useEffectEvent(undo);
  const redoRef = useEffectEvent(redo);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!event.ctrlKey && !event.metaKey) return;
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target?.isContentEditable) return;
      if (event.key === "z" && !event.shiftKey) {
        event.preventDefault();
        undoRef();
      } else if (event.key === "y" || (event.key === "Z" && event.shiftKey) || (event.key === "z" && event.shiftKey)) {
        event.preventDefault();
        redoRef();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}
