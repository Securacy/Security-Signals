import type { AuthorizedFetch } from "../auth/apiClient";
import type { Role } from "../auth/types";
import type {
  AdminSignalActionResult,
  AdminSignalDetail,
  AdminSignalListItem,
  AdminUser,
  AuditEntry,
  CategoryHealthEntry,
  InternalAnalytics,
} from "./types";

function buildQuery(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/** GET /api/v1/signals/draft - DRAFT + IN_REVIEW signals. REVIEWER/ADMIN. */
export function fetchDraftSignals(fetcher: AuthorizedFetch): Promise<AdminSignalListItem[]> {
  return fetcher<AdminSignalListItem[]>("/api/v1/signals/draft");
}

/** GET /api/v1/signals/approved - APPROVED signals awaiting publish. ADMIN only. */
export function fetchApprovedSignals(fetcher: AuthorizedFetch): Promise<AdminSignalListItem[]> {
  return fetcher<AdminSignalListItem[]>("/api/v1/signals/approved");
}

/** GET /api/v1/signals/rejected - REJECTED signals. REVIEWER/ADMIN. */
export function fetchRejectedSignals(fetcher: AuthorizedFetch): Promise<AdminSignalListItem[]> {
  return fetcher<AdminSignalListItem[]>("/api/v1/signals/rejected");
}

/** GET /api/v1/signals/{id} - full detail (evidence + categories + visual)
 * for a signal in any status, for the review detail panel. REVIEWER/ADMIN. */
export function fetchSignalDetail(fetcher: AuthorizedFetch, id: string): Promise<AdminSignalDetail> {
  return fetcher<AdminSignalDetail>(`/api/v1/signals/${id}`);
}

export interface AuditQueryParams {
  limit?: number;
  skip?: number;
  resource_type?: string;
  resource_id?: string;
  user_id?: string;
  action?: string;
}

/** GET /api/v1/audit - audit entries, optionally filtered/paginated. ADMIN only. */
export function fetchAuditEntries(fetcher: AuthorizedFetch, params: AuditQueryParams = {}): Promise<AuditEntry[]> {
  return fetcher<AuditEntry[]>(`/api/v1/audit${buildQuery(params)}`);
}

/** GET /api/v1/admin/category-health - per-category coverage/source health. ADMIN only. */
export function fetchCategoryHealth(fetcher: AuthorizedFetch): Promise<CategoryHealthEntry[]> {
  return fetcher<CategoryHealthEntry[]>("/api/v1/admin/category-health");
}

/** GET /api/v1/analytics/internal - monthly signal counts across ALL
 * statuses, with a per-status breakdown. REVIEWER/ADMIN only (reveals
 * unpublished pipeline volume). */
export function fetchInternalAnalytics(fetcher: AuthorizedFetch, months = 12): Promise<InternalAnalytics> {
  return fetcher<InternalAnalytics>(`/api/v1/analytics/internal${buildQuery({ months })}`);
}

/** POST /api/v1/signals/{id}/submit-for-review - DRAFT -> IN_REVIEW. REVIEWER/ADMIN. */
export function submitForReview(fetcher: AuthorizedFetch, id: string): Promise<AdminSignalActionResult> {
  return fetcher<AdminSignalActionResult>(`/api/v1/signals/${id}/submit-for-review`, { method: "POST" });
}

/** POST /api/v1/signals/{id}/approve - IN_REVIEW -> APPROVED. REVIEWER/ADMIN. */
export function approveSignal(fetcher: AuthorizedFetch, id: string): Promise<AdminSignalActionResult> {
  return fetcher<AdminSignalActionResult>(`/api/v1/signals/${id}/approve`, { method: "POST" });
}

/** POST /api/v1/signals/{id}/reject - IN_REVIEW -> REJECTED, with an optional review note. REVIEWER/ADMIN. */
export function rejectSignal(fetcher: AuthorizedFetch, id: string, reason: string): Promise<AdminSignalActionResult> {
  return fetcher<AdminSignalActionResult>(`/api/v1/signals/${id}/reject`, { method: "POST", body: { reason } });
}

/** POST /api/v1/signals/{id}/publish - APPROVED -> PUBLISHED. ADMIN only. */
export function publishSignal(fetcher: AuthorizedFetch, id: string): Promise<AdminSignalActionResult> {
  return fetcher<AdminSignalActionResult>(`/api/v1/signals/${id}/publish`, { method: "POST" });
}

/** GET /api/v1/users - paginated user list. ADMIN only. */
export function fetchUsers(
  fetcher: AuthorizedFetch,
  params: { skip?: number; limit?: number } = {},
): Promise<AdminUser[]> {
  return fetcher<AdminUser[]>(`/api/v1/users${buildQuery(params)}`);
}

export interface CreateUserInput {
  username: string;
  email: string;
  role: Role;
  password: string;
}

/** POST /api/v1/users - create a new account. ADMIN only. */
export function createUser(fetcher: AuthorizedFetch, input: CreateUserInput): Promise<AdminUser> {
  return fetcher<AdminUser>("/api/v1/users", { method: "POST", body: input });
}

/** PATCH /api/v1/users/{id} - role change. ADMIN only. */
export function updateUserRole(fetcher: AuthorizedFetch, id: string, role: Role): Promise<AdminUser> {
  return fetcher<AdminUser>(`/api/v1/users/${id}`, { method: "PATCH", body: { role } });
}

/** POST /api/v1/users/{id}/deactivate - one-way soft deactivation, never a
 * hard delete and never reversible through this API. ADMIN only. */
export function deactivateUser(fetcher: AuthorizedFetch, id: string): Promise<AdminUser> {
  return fetcher<AdminUser>(`/api/v1/users/${id}/deactivate`, { method: "POST" });
}

/** DELETE /api/v1/users/{id} - permanently remove an already-inactive
 * account. Refused (400) if the target is still active. ADMIN only. */
export function purgeInactiveUser(fetcher: AuthorizedFetch, id: string): Promise<void> {
  return fetcher<void>(`/api/v1/users/${id}`, { method: "DELETE" });
}

/** POST /api/v1/users/{id}/reset-password - ADMIN sets a fresh password for
 * another LOCAL user. Refused (400) for an Entra-only account. */
export function adminResetPassword(
  fetcher: AuthorizedFetch, id: string, newPassword: string, confirmPassword: string,
): Promise<AdminUser> {
  return fetcher<AdminUser>(`/api/v1/users/${id}/reset-password`, {
    method: "POST",
    body: { new_password: newPassword, confirm_password: confirmPassword },
  });
}

/** POST /api/v1/auth/change-password - self-service password change for
 * the currently authenticated LOCAL user. Invalidates every token issued
 * before this call, including the one used to make it. */
export function changeOwnPassword(
  fetcher: AuthorizedFetch, currentPassword: string, newPassword: string, confirmPassword: string,
): Promise<void> {
  return fetcher<void>("/api/v1/auth/change-password", {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword, confirm_password: confirmPassword },
  });
}
