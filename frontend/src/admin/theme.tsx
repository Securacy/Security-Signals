import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/**
 * Appearance preference: Light / Dark / System. Unlike the auth session
 * (sessionStorage, cleared per-tab - see auth/AuthContext.tsx), this is a
 * non-sensitive UI preference that should persist across sessions and
 * tabs, so it uses localStorage. admin/index.html applies the same
 * resolution logic inline, synchronously, before first paint, so there is
 * no flash of the wrong theme while this context initializes - this
 * context re-applies it (so it can react to live OS-theme changes and to
 * the user picking a new preference) rather than being the only place it
 * happens.
 */

export type ThemePreference = "light" | "dark" | "system";
type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "ss-admin-theme";

function isThemePreference(value: string | null): value is ThemePreference {
  return value === "light" || value === "dark" || value === "system";
}

function readStoredPreference(): ThemePreference {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return isThemePreference(raw) ? raw : "system";
  } catch {
    return "system";
  }
}

function systemPrefersDark(): boolean {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    return false;
  }
}

function resolve(preference: ThemePreference): ResolvedTheme {
  return preference === "system" ? (systemPrefersDark() ? "dark" : "light") : preference;
}

interface ThemeContextValue {
  /** The user's stored preference - may be "system". */
  preference: ThemePreference;
  /** The actual light/dark currently applied (system resolved). */
  resolved: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readStoredPreference);
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolve(preference));

  useEffect(() => {
    setResolved(resolve(preference));
    document.documentElement.setAttribute("data-theme", resolve(preference));
  }, [preference]);

  // Live-update when the OS theme changes while "system" is selected.
  useEffect(() => {
    if (preference !== "system") return undefined;
    let media: MediaQueryList;
    try {
      media = window.matchMedia("(prefers-color-scheme: dark)");
    } catch {
      return undefined;
    }
    const onChange = () => {
      const next = systemPrefersDark() ? "dark" : "light";
      setResolved(next);
      document.documentElement.setAttribute("data-theme", next);
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [preference]);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage unavailable - preference still applies for this page load.
    }
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({ preference, resolved, setPreference }),
    [preference, resolved, setPreference],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within a ThemeProvider");
  return ctx;
}
