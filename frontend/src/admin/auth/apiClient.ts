import { useCallback } from "react";
import { ApiError } from "../../widget/api";
import { getAdminConfig } from "../config";
import { useAuth } from "./AuthContext";

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: object;
}

/** The type of the bound fetch function `useAuthorizedFetch()` returns -
 * imported by api/client.ts so its request helpers stay decoupled from how
 * the token is obtained/attached. */
export type AuthorizedFetch = <T>(path: string, options?: RequestOptions) => Promise<T>;

async function parseJsonBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/** FastAPI's `detail` is a plain string for handler-raised HTTPExceptions,
 * but a list of {msg, loc, ...} objects for Pydantic request-validation
 * errors (422s, e.g. a too-short password) - without this, that shape
 * would stringify into an unreadable "[object Object]" in the UI. */
function extractErrorMessage(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | undefined)?.detail;
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const messages = detail
      .map((item) => (item && typeof item === "object" && typeof (item as { msg?: unknown }).msg === "string" ? (item as { msg: string }).msg : null))
      .filter((msg): msg is string => msg !== null);
    if (messages.length > 0) return messages.join(" ");
  }
  return `Security Signals API returned ${status}`;
}

/**
 * Bound fetch function for every protected admin API call. Mechanism-
 * agnostic with respect to auth: it only ever reads the current session's
 * bearer token and reacts to 401s by signing out - it works identically no
 * matter how that session was obtained (password login today, Entra
 * ID/OIDC later).
 *
 * On 401, clears the session via signOut() - the app tree re-renders to
 * the login page automatically (see AdminApp.tsx), so no explicit
 * navigation is needed here.
 */
export function useAuthorizedFetch(): AuthorizedFetch {
  const { session, signOut } = useAuth();

  return useCallback(
    async <T,>(path: string, options: RequestOptions = {}): Promise<T> => {
      const { apiBaseUrl } = getAdminConfig();
      const { method = "GET", body } = options;

      let response: Response;
      try {
        response = await fetch(`${apiBaseUrl}${path}`, {
          method,
          headers: {
            Accept: "application/json",
            ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
            ...(session ? { Authorization: `Bearer ${session.token}` } : {}),
          },
          body: body !== undefined ? JSON.stringify(body) : undefined,
        });
      } catch {
        throw new ApiError("Network error while reaching Security Signals API", null);
      }

      if (response.status === 401) {
        signOut("expired");
        throw new ApiError("Your session has expired. Please sign in again.", 401);
      }

      if (!response.ok) {
        const parsed = await parseJsonBody(response);
        throw new ApiError(extractErrorMessage(parsed, response.status), response.status);
      }

      if (response.status === 204) {
        return undefined as T;
      }

      const parsed = await parseJsonBody(response);
      if (parsed === undefined) {
        throw new ApiError("Security Signals API returned an invalid response", response.status);
      }
      return parsed as T;
    },
    [session, signOut],
  );
}
