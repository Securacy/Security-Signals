import { useEffect, useRef, useState, type FormEvent } from "react";
import { consumeSignInNotice, useAuth } from "../auth/AuthContext";
import { signInWithPassword } from "../auth/providers/passwordProvider";
import {
  completeEntraSignIn,
  fetchAuthProviders,
  messageForSignInError,
  microsoftSignInUrl,
} from "../auth/providers/entraProvider";
import { ApiError } from "../../widget/api";
import { useLoad } from "../useLoad";
import { Button } from "../components/Button";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";

/** What the backend's redirects put on this page's URL: `?error=<code>`
 * after a failed Microsoft sign-in, `?signin=complete` after a successful
 * one. Both are flags/codes only - never a token. Read once. */
function readEntryParams(): { completing: boolean; errorCode: string | null } {
  const params = new URLSearchParams(window.location.search);
  return { completing: params.get("signin") === "complete", errorCode: params.get("error") };
}

function stripQueryFromUrl(): void {
  if (window.location.search) {
    window.history.replaceState(null, "", window.location.pathname);
  }
}

function MicrosoftLogo() {
  return (
    <svg className="adm-ms-logo" width="18" height="18" viewBox="0 0 21 21" aria-hidden="true" focusable="false">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  );
}

export function LoginPage() {
  const { completeSignIn } = useAuth();
  const [entry] = useState(readEntryParams);
  const [retryToken, setRetryToken] = useState(0);
  const providersState = useLoad(fetchAuthProviders, [retryToken]);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(() => messageForSignInError(entry.errorCode));
  const [notice, setNotice] = useState<string | null>(null);
  const [isCompleting, setIsCompleting] = useState(entry.completing);

  // React StrictMode runs effects twice in development, and both of these
  // are one-shot (the notice is cleared once read; the Entra handoff is
  // single-use) - so each is guarded by a ref, which survives that
  // simulated remount, to run exactly once per page instance.
  const noticeRead = useRef(false);
  const completionStarted = useRef(false);

  useEffect(() => {
    if (noticeRead.current) return;
    noticeRead.current = true;
    const reason = consumeSignInNotice();
    if (reason === "expired") {
      setNotice("Your session has expired. Please sign in again.");
    } else if (reason === "password_changed") {
      setNotice("Your password was changed. Please sign in again.");
    }
    if (entry.errorCode) stripQueryFromUrl();
  }, [entry.errorCode]);

  useEffect(() => {
    if (!entry.completing || completionStarted.current) return;
    completionStarted.current = true;
    completeEntraSignIn()
      .then((session) => {
        window.history.replaceState(null, "", "/admin/");
        completeSignIn(session);
      })
      .catch((err) => {
        stripQueryFromUrl();
        setError(err instanceof ApiError ? err.message : "Sign-in failed. Please try again.");
        setIsCompleting(false);
      });
  }, [entry.completing, completeSignIn]);

  async function handlePasswordSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setIsSubmitting(true);
    try {
      const session = await signInWithPassword(username, password);
      completeSignIn(session);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to sign in. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  const providers = providersState.status === "ready" ? providersState.data : null;

  return (
    <div className="adm-login">
      <div className="adm-login__card">
        <h1 className="adm-login__title">
          Cyber<span className="adm-sidebar__brand-accent">scope</span>
        </h1>
        <p className="adm-login__subtitle">Sign in to the admin console</p>

        {notice && (
          <p role="status" className="adm-login__notice">
            {notice}
          </p>
        )}
        {error && (
          <p role="alert" className="adm-form-error">
            {error}
          </p>
        )}

        {isCompleting && <LoadingState label="Completing Microsoft sign-in…" />}

        {!isCompleting && providersState.status === "loading" && <LoadingState label="Loading sign-in options…" />}
        {!isCompleting && providersState.status === "error" && (
          <ErrorState message={providersState.message} onRetry={() => setRetryToken((n) => n + 1)} />
        )}

        {!isCompleting && providers && !providers.entra && !providers.local && (
          <p role="alert" className="adm-form-error">
            No sign-in method is available. Contact an administrator.
          </p>
        )}

        {!isCompleting && providers?.entra && (
          <a className="adm-btn adm-btn--microsoft adm-login__submit" href={microsoftSignInUrl()}>
            <MicrosoftLogo />
            <span>Sign in with Microsoft</span>
          </a>
        )}

        {!isCompleting && providers?.entra && providers.local && (
          <p className="adm-login__divider" aria-hidden="true">
            <span>or</span>
          </p>
        )}

        {!isCompleting && providers?.local && (
          <form onSubmit={handlePasswordSubmit} noValidate>
            <div className="adm-field">
              <label htmlFor="adm-username" className="adm-field__label">
                Username
              </label>
              <input
                id="adm-username"
                name="username"
                className="adm-input"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </div>
            <div className="adm-field">
              <label htmlFor="adm-password" className="adm-field__label">
                Password
              </label>
              <input
                id="adm-password"
                name="password"
                className="adm-input"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </div>
            <Button type="submit" variant="primary" disabled={isSubmitting} className="adm-login__submit">
              {isSubmitting ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}
