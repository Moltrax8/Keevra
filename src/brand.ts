/**
 * Single source of truth for user-facing branding and the identifiers the
 * brand implies. Change the name here; every TS display occurrence imports
 * from this module.
 */

/** Human-readable display name (safe to change freely). */
export const APP_NAME = "Keevra";

/**
 * Wordmark halves: `{APP_NAME_HEAD}{APP_NAME_TAIL}` === APP_NAME. The brand
 * is single-tone, so the tail is empty; the split is kept because the topbar
 * renders the accent `<em>` tail and future marks may want one again.
 */
export const APP_NAME_HEAD = "Keevra";
export const APP_NAME_TAIL = "";

/**
 * Inactivity auto-lock override, set by tests as
 * `window[AUTO_LOCK_TEST_HOOK] = ms` (read in src/display.ts).
 */
export const AUTO_LOCK_TEST_HOOK = "__KEEVRA_AUTO_LOCK_MS";

/**
 * GitHub release source for the notify-only updater. MUST match the repo
 * actually publishing releases — a stale owner/repo makes every update
 * check 404 (fetched at src/hooks/useUpdater.ts).
 */
export const UPDATE_OWNER = "Moltrax8";
export const UPDATE_REPO = "Keevra";
export const UPDATE_API_LATEST = `https://api.github.com/repos/${UPDATE_OWNER}/${UPDATE_REPO}/releases/latest`;
