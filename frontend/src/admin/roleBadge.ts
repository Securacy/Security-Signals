import type { Role } from "./auth/types";

/** Shared role display: label + badge tone, used anywhere a user's role is
 * shown (TopBar, Users page) so it reads consistently across the app. */
export const ROLE_LABEL: Record<Role, string> = { admin: "Admin", reviewer: "Reviewer", viewer: "Viewer" };

export const ROLE_TONE: Record<Role, "accent" | "info" | "neutral"> = {
  admin: "accent",
  reviewer: "info",
  viewer: "neutral",
};
