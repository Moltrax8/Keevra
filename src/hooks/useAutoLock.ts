import { useEffect, useEffectEvent } from "react";
import { autoLockTimeoutMs } from "../display";
import { vaultTouch } from "../vaultApi";

/** How often genuine activity is forwarded to the backend backstop. */
const TOUCH_INTERVAL_MS = 30_000;

/**
 * Re-arms an idle timer on pointer/key activity while the vault is unlocked.
 *
 * Uses wall-clock elapsed time instead of trusting one `setTimeout`: renderer
 * timers are throttled while minimized, and a laptop can sleep past the whole
 * timeout. On `visibilitychange`/`focus` the real elapsed time is measured and
 * the vault locks immediately when it exceeded the policy (K-14).
 *
 * `onIdle` returns false when the lock was refused (for example because
 * unsaved changes could not be written); the lock is then retried shortly so
 * a single failed save can never leave the vault unlocked indefinitely.
 */
export function useAutoLock(active: boolean, onIdle: () => Promise<boolean>) {
  const onAutoLock = useEffectEvent(onIdle);

  useEffect(() => {
    if (!active) return;
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;
    let locking = false;
    let lastActivity = Date.now();
    let lastTouch = 0;

    const reportActivity = () => {
      lastActivity = Date.now();
      if (lastActivity - lastTouch < TOUCH_INTERVAL_MS) return;
      lastTouch = lastActivity;
      void vaultTouch().catch(() => {
        // The backend may already have expired the session; the regular lock
        // path below reconciles the UI with the authoritative state.
      });
    };

    const fire = async () => {
      // A visibility change and the timer can land together; only one lock
      // attempt may run so a flush is never persisted twice concurrently.
      if (locking) return;
      if (Date.now() - lastActivity < autoLockTimeoutMs()) {
        arm();
        return;
      }
      locking = true;
      let locked = false;
      try {
        locked = await onAutoLock();
      } finally {
        locking = false;
      }
      if (!locked && !cancelled) {
        timer = setTimeout(fire, 5000);
      }
    };

    const arm = () => {
      clearTimeout(timer);
      const remaining = autoLockTimeoutMs() - (Date.now() - lastActivity);
      timer = setTimeout(fire, Math.max(0, remaining));
    };

    const onActivity = () => {
      reportActivity();
      arm();
    };

    const onVisibility = () => {
      if (document.visibilityState === "hidden") return;
      // Time spent hidden/minimized/suspended counts as inactivity. Lock now
      // if it exceeded the policy, otherwise re-arm only the remainder.
      if (Date.now() - lastActivity >= autoLockTimeoutMs()) {
        clearTimeout(timer);
        void fire();
        return;
      }
      reportActivity();
      arm();
    };

    reportActivity();
    arm();
    window.addEventListener("pointerdown", onActivity);
    window.addEventListener("keydown", onActivity);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onVisibility);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("keydown", onActivity);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onVisibility);
    };
  }, [active]);
}
