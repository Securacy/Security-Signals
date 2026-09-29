import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getAdminConfig } from "../config";
import type { AuthSession, AuthUser } from "./types";

/**
 * Owns only a mechanism-agnostic AuthSession - it has no idea whether that
 * session came from the password login or Microsoft Entra ID (see
 * auth/providers/). See auth/types.ts for the seam explanation.
 *
 * Token storage: sessionStorage, not localStorage - per the RBAC/admin
 * design brief's security requirements, privileged credentials must not
 * sit in localStorage. sessionStorage still isn't as safe as an httpOnly
 * cookie against XSS, but the backend currently issues the token via a
 * JSON login response rather than a Set-Cookie header, and switching that
 * is a real backend auth architecture change outside this UI work. Using
 * sessionStorage (cleared when the tab closes, never shared across tabs)
 * is the safer of the two client-storage options available today.
 */

const SESSION_STORAGE_KEY = "ss-admin-session";
const NOTICE_STORAGE_KEY = "ss-admin-signin-notice";

export type SignOutReason = "expired" | "password_changed";

const _SIGN_OUT_REASONS: SignOutReason[] = ["expired", "password_changed"];

/** One-shot message for the login page after an involuntary sign-out - a
 * 401 from the API means the session token expired, or the user just
 * changed their own password (which invalidates the very token they used
 * to change it). Read once, then cleared, so it is never shown twice. */
export function consumeSignInNotice(): SignOutReason | null {
  try {
    const value = window.sessionStorage.getItem(NOTICE_STORAGE_KEY);
    window.sessionStorage.removeItem(NOTICE_STORAGE_KEY);
    return (_SIGN_OUT_REASONS as string[]).includes(value ?? "") ? (value as SignOutReason) : null;
  } catch {
    return null;
  }
}

/** Best-effort: tell the backend this session ended so the sign-out is
 * audited. Failure is ignored - signing out locally must always work. */
function notifyServerSignOut(token: string): void {
  try {
    void fetch(`${getAdminConfig().apiBaseUrl}/api/v1/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      keepalive: true,
    }).catch(() => undefined);
  } catch {
    // ignore
  }
}

interface AuthContextValue {
  session: AuthSession | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  /** True only while the initial sessionStorage read is happening, so the
   * app can avoid flashing the login page before a restored session is
   * known. */
  isRestoring: boolean;
  completeSignIn: (session: AuthSession) => void;
  /** `signOut()` is a user-initiated sign-out; `signOut("expired")` or
   * `signOut("password_changed")` are involuntary and each leave a
   * one-time, distinct notice for the login page. */
  signOut: (reason?: SignOutReason) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readStoredSession(): AuthSession | null {
  try {
    const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<AuthSession>;
    if (typeof parsed.token === "string" && parsed.user) {
      return parsed as AuthSession;
    }
    return null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [isRestoring, setIsRestoring] = useState(true);

  useEffect(() => {
    setSession(readStoredSession());
    setIsRestoring(false);
  }, []);

  const completeSignIn = useCallback((next: AuthSession) => {
    setSession(next);
    try {
      window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // sessionStorage unavailable (private browsing, storage disabled) -
      // the session still works for the current page lifetime, it just
      // won't survive a refresh.
    }
  }, []);

  const sessionRef = useRef<AuthSession | null>(null);
  sessionRef.current = session;

  const signOut = useCallback((reason?: SignOutReason) => {
    const ending = sessionRef.current;
    setSession(null);
    try {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
      if (reason) window.sessionStorage.setItem(NOTICE_STORAGE_KEY, reason);
    } catch {
      // ignore
    }
    // Only a deliberate sign-out is reported here: an expired token can't
    // authenticate the logout call anyway, and a password change already
    // has its own PASSWORD_CHANGED audit entry from the backend.
    if (ending && reason === undefined) notifyServerSignOut(ending.token);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      user: session?.user ?? null,
      isAuthenticated: session !== null,
      isRestoring,
      completeSignIn,
      signOut,
    }),
    [session, isRestoring, completeSignIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
