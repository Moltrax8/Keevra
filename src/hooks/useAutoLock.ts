import { useEffect, useEffectEvent } from "react";
import { autoLockTimeoutMs } from "../display";

/** Re-arms an idle timer on pointer/key activity while the vault is unlocked. */
export function useAutoLock(active: boolean, onIdle: () => void) {
  const onAutoLock = useEffectEvent(onIdle);

  useEffect(() => {
    if (!active) return;
    let timer: ReturnType<typeof setTimeout>;
    const arm = () => {
      clearTimeout(timer);
      timer = setTimeout(() => onAutoLock(), autoLockTimeoutMs());
    };
    arm();
    window.addEventListener("pointerdown", arm);
    window.addEventListener("keydown", arm);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("pointerdown", arm);
      window.removeEventListener("keydown", arm);
    };
  }, [active]);
}
