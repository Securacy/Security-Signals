/**
 * Mechanism-agnostic auth types shared by AuthContext, the router, nav, and
 * every admin page. None of these types - or anything that consumes them -
 * know or care how a session was obtained. Today that's username/password
 * (see auth/providers/passwordProvider.ts); the CTO's plan is to replace
 * that with Microsoft Entra ID / OIDC later. When that happens, a new
 * auth/providers/oidcProvider.ts produces the same AuthSession shape via a
 * redirect+callback flow and hands it to the same AuthContext.completeSignIn
 * - nothing here, in the router, in permissions.ts, or in any page needs to
 * change.
 */

/** Matches the backend's UserRole enum values exactly (app/db/models.py). */
export type Role = "admin" | "reviewer" | "viewer";

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: Role;
  /** Whether THIS account has a local password_hash / is Entra-linked -
   * drives the profile menu's "Password managed"/"Microsoft Entra managed"
   * display and whether to offer a local password-change action. Defaults
   * assumed if the backend response omits them (older mocks in tests) -
   * see parseLoginResponse. */
  hasLocalCredential: boolean;
  entraLinked: boolean;
}

export interface AuthSession {
  token: string;
  user: AuthUser;
}
