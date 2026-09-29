import { ApiError } from "../../../widget/api";
import type { AuthSession, Role } from "../types";

const ROLES: readonly Role[] = ["admin", "reviewer", "viewer"];

/** Shape both sign-in mechanisms (password login and the Entra session
 * exchange) return - the backend's LoginResponse. */
interface LoginResponseBody {
  access_token: string;
  user: {
    id: string;
    username: string;
    email: string;
    role: string;
    has_local_credential?: boolean;
    entra_linked?: boolean;
  };
}

/** Validate and convert a backend LoginResponse into an AuthSession. The
 * role here only drives what the UI shows - the backend re-derives the real
 * role from its own database on every request. */
export function parseLoginResponse(data: unknown, status: number): AuthSession {
  const body = data as Partial<LoginResponseBody> | null;
  if (
    !body ||
    typeof body.access_token !== "string" ||
    !body.user ||
    typeof body.user.id !== "string" ||
    typeof body.user.username !== "string" ||
    !ROLES.includes(body.user.role as Role)
  ) {
    throw new ApiError("Security Signals API returned an invalid response", status);
  }
  return {
    token: body.access_token,
    user: {
      id: body.user.id,
      username: body.user.username,
      email: typeof body.user.email === "string" ? body.user.email : "",
      role: body.user.role as Role,
      // Defaults preserve prior behavior (always offer local password
      // change, never claim Entra-managed) for any response that omits
      // these - real backend responses always include them now.
      hasLocalCredential: typeof body.user.has_local_credential === "boolean" ? body.user.has_local_credential : true,
      entraLinked: typeof body.user.entra_linked === "boolean" ? body.user.entra_linked : false,
    },
  };
}
