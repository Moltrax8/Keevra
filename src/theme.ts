/**
 * Theme preference and application.
 *
 * The palette is warm paper (light) or a warm, lamp-lit dark. Users can follow
 * the OS, or pin light/dark in Settings. The choice is remembered in
 * localStorage; the vault itself is untouched.
 */
import { useEffect, useState } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "keevra.theme";

export const THEME_OPTIONS: readonly { value: ThemePreference; label: string }[] = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

export function parseThemePreference(value: string | null): ThemePreference {
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

export function resolveTheme(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ResolvedTheme {
  if (preference === "system") return systemPrefersDark ? "dark" : "light";
  return preference;
}

function canUseDom(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

export function readThemePreference(): ThemePreference {
  if (!canUseDom()) return "system";
  try {
    return parseThemePreference(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return "system";
  }
}

export function saveThemePreference(preference: ThemePreference): void {
  if (!canUseDom()) return;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // Storage can be unavailable; the session still keeps the choice.
  }
}

export function systemPrefersDark(): boolean {
  if (!canUseDom() || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Paints the resolved theme on <html> so CSS variables switch wholesale. */
export function applyTheme(theme: ResolvedTheme): void {
  if (!canUseDom()) return;
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

/** Reads the stored preference and paints it; call before React renders. */
export function applyStoredTheme(): void {
  applyTheme(resolveTheme(readThemePreference(), systemPrefersDark()));
}

export function useTheme(): {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
} {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => readThemePreference());
  const [prefersDark, setPrefersDark] = useState<boolean>(() => systemPrefersDark());

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setPrefersDark(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  const resolved = resolveTheme(preference, prefersDark);

  useEffect(() => {
    applyTheme(resolved);
  }, [resolved]);

  function setPreference(next: ThemePreference) {
    setPreferenceState(next);
    saveThemePreference(next);
  }

  return { preference, resolved, setPreference };
}
