/**
 * Microsoft Entra ID sign-in, frontend half. The whole OIDC flow (state,
 * nonce, PKCE, code exchange with the CLIENT SECRET, ID-token validation,
 * role mapping) runs on the backend - this file only:
 *   - links the browser to the backend's login endpoint,
 *   - trades the one-time HttpOnly handoff cookie for the app session, and
 *   - turns the backend's coarse error codes into user-facing messages.
 * It never sees, stores, or forwards a Microsoft token, the tenant ID, the
 * client ID or the client secret, and nothing here reads such configuration.
 */
import { ApiError } from "../../../widget/api";
import { getAdminConfig } from "../../config";
import type { AuthSession } from "../types";
import { parseLoginResponse } from "./loginResponse";

export interface AuthProviders {
  local: boolean;
  entra: boolean;
}

/** GET /api/v1/auth/providers - which sign-in methods to offer. */
export async function fetchAuthProviders(): Promise<AuthProviders> {
  const { apiBaseUrl } = getAdminConfig();
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/api/v1/auth/providers`, { headers: { Accept: "application/json" } });
  } catch {
    throw new ApiError("Network error while reaching Cyberscope API", null);
  }
  if (!response.ok) {
    throw new ApiError(`Cyberscope API returned ${response.status}`, response.status);
  }
  const body = (await response.json().catch(() => null)) as Partial<AuthProviders> | null;
  return { local: body?.local === true, entra: body?.entra === true };
}

/** Where the "Sign in with Microsoft" link goes: a full-page navigation to
 * the backend, which redirects on to Microsoft. */
export function microsoftSignInUrl(): string {
  return `${getAdminConfig().apiBaseUrl}/api/v1/auth/entra/login`;
}

/**
 * After the backend's callback redirects back here with ?signin=complete,
 * trade the one-time HttpOnly handoff cookie for the application session -
 * the same bearer JWT the password login returns. `credentials: "include"`
 * is what sends the cookie; the custom header forces a CORS preflight so no
 * foreign origin can trigger this call.
 */
export async function completeEntraSignIn(): Promise<AuthSession> {
  const { apiBaseUrl } = getAdminConfig();
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/api/v1/auth/entra/session`, {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json", "X-Requested-With": "ss-admin" },
    });
  } catch {
    throw new ApiError("Network error while reaching Cyberscope API", null);
  }
  if (response.status === 401 || response.status === 403) {
    throw new ApiError("Your Microsoft sign-in could not be completed. Please try again.", response.status);
  }
  if (!response.ok) {
    throw new ApiError(`Sign-in failed (${response.status})`, response.status);
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new ApiError("Cyberscope API returned an invalid response", response.status);
  }
  return parseLoginResponse(data, response.status);
}

const DEFAULT_ERROR = "Sign-in failed. Please try again.";

const ERROR_MESSAGES: Record<string, string> = {
  // Also covers an unassigned user: the Security Signals Enterprise
  // Application's own "user assignment required" setting rejects them via
  // Microsoft's own access_denied response, before our backend ever sees
  // a code - there's no separate application-side "not authorized" case.
  access_denied: "Microsoft sign-in was cancelled or is not permitted for this account.",
  invalid_state: "Your sign-in attempt expired or could not be verified. Please try again.",
  invalid_token: "Microsoft returned a sign-in response that could not be verified. Please try again.",
  not_provisioned: "Your account has not been set up for this application yet. Contact an administrator.",
  account_disabled: "This account has been deactivated. Contact an administrator.",
  account_conflict: "This email address is already linked to a different account. Contact an administrator.",
  entra_disabled: "Microsoft sign-in is not enabled.",
  auth_failed: DEFAULT_ERROR,
};

/** Message for the `?error=` code the backend put on the login redirect.
 * Unknown codes get the generic message - never the raw value. */
export function messageForSignInError(code: string | null): string | null {
  if (code === null || code === "") return null;
  return ERROR_MESSAGES[code] ?? DEFAULT_ERROR;
}
