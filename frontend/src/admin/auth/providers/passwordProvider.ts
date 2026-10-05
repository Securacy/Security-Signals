/**
 * The ONLY file in the admin app that knows the username/password login
 * HTTP contract (POST /api/v1/auth/login). Only LoginPage.tsx calls this.
 * AuthContext, the router, navigation, permissions, and every other page
 * consume just the resulting AuthSession - see auth/types.ts.
 *
 * Its sibling entraProvider.ts implements Microsoft Entra ID sign-in and
 * produces the same AuthSession shape, exactly as that seam anticipated:
 * nothing outside LoginPage and the providers had to change.
 */
import { ApiError } from "../../../widget/api";
import { getAdminConfig } from "../../config";
import type { AuthSession } from "../types";
import { parseLoginResponse } from "./loginResponse";

export async function signInWithPassword(username: string, password: string): Promise<AuthSession> {
  const { apiBaseUrl } = getAdminConfig();

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new ApiError("Network error while reaching Cyberscope API", null);
  }

  if (!response.ok) {
    if (response.status === 401) {
      throw new ApiError("Invalid username or password", 401);
    }
    if (response.status === 403) {
      const body = (await response.json().catch(() => null)) as { detail?: unknown } | null;
      if (typeof body?.detail === "string" && body.detail.toLowerCase().includes("disabled")) {
        throw new ApiError("Password sign-in is disabled. Use Microsoft sign-in.", 403);
      }
      throw new ApiError("This account is inactive", 403);
    }
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
