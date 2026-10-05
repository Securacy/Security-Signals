/**
 * Types matching the protected admin API response shapes exactly, the same
 * approach widget/types.ts uses for the public API - source of truth is
 * the backend serializers themselves (app/api/routes/signals.py,
 * app/api/routes/audit.py, app/api/routes/category_health.py).
 */
import type { EvidenceItem, SignalCategoryTag } from "../../widget/types";
import type { Role } from "../auth/types";

export type AdminVisualStatus = "none" | "pending" | "generated" | "failed";

export type AdminSignalStatus = "draft" | "in_review" | "approved" | "rejected" | "published";

/** Shape returned by GET /api/v1/signals/draft and GET /api/v1/signals/approved. */
export interface AdminSignalListItem {
  id: string;
  title: string;
  summary: string;
  status: AdminSignalStatus;
  security_impact: string;
  principle: string;
  recommended_action: string;
  created_at: string | null;
  reviewed_by: string | null;
  reviewed_at?: string | null;
  categories: SignalCategoryTag[];
  /** "none" = no SignalVisual row at all (persisted before visuals were
   * generated at DRAFT time); "pending" = generation genuinely queued. */
  visual_status: AdminVisualStatus;
  /** Backend-relative path (e.g. "/media/signals/<id>.png"), only when generated. */
  visual_url: string | null;
  visual_requested_at: string | null;
}

/** Shape returned by GET /api/v1/signals/{id} - full detail (evidence +
 * categories + visual) for a signal in ANY status, for the review detail
 * panel. REVIEWER/ADMIN only. */
export interface AdminSignalDetail {
  id: string;
  title: string;
  status: AdminSignalStatus;
  summary: string;
  security_impact: string;
  principle: string;
  recommended_action: string;
  created_at: string | null;
  /** Used as the optimistic-lock token when editing (see editSignalContent/
   * editSignalCategory) - sent back as expected_updated_at so a concurrent
   * edit since this was loaded is rejected (409) rather than silently
   * overwritten. */
  updated_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  published_at: string | null;
  categories: SignalCategoryTag[];
  public_categories: string[];
  evidence: EvidenceItem[];
  visual_status: AdminVisualStatus;
  visual_url: string | null;
  visual_requested_at: string | null;
}

/** Shape returned by the review-action endpoints (submit-for-review,
 * approve, reject, publish) - see _serialize_signal_detail in
 * app/api/routes/signals.py. */
export interface AdminSignalActionResult {
  id: string;
  title: string;
  status: AdminSignalStatus;
  summary: string;
  security_impact: string;
  principle: string;
  recommended_action: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  published_at: string | null;
}

/** Shape returned by GET /api/v1/audit. */
export interface AuditEntry {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string;
  changes: Record<string, unknown> | null;
  timestamp: string | null;
}

/** Shape returned by GET/POST/PATCH /api/v1/users and
 * POST /api/v1/users/{id}/deactivate - see _serialize_user in
 * app/api/routes/users.py. Never includes password_hash - the backend
 * serializer never sends it. */
export interface AdminUser {
  id: string;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  /** True iff this account has a local password_hash at all - a user can
   * be entra_linked AND have a local credential simultaneously (linked by
   * email, never touching the password). Only accounts with a local
   * credential can use self-service change / admin reset-password. */
  has_local_credential: boolean;
  entra_linked: boolean;
  created_at: string | null;
  updated_at: string | null;
  last_login_at: string | null;
}

/** Shape returned by GET /api/v1/analytics/internal - see
 * AnalyticsService.get_internal_analytics. Real counts across every
 * signal status, bucketed by creation month within the requested window
 * (not an all-time total). */
export interface InternalAnalytics {
  generated_at: string;
  window_months: number;
  total_signals: number;
  status_totals: Partial<Record<AdminSignalStatus, number>>;
  monthly_counts: { month: string; count: number }[];
  monthly_counts_by_status: Record<string, Partial<Record<AdminSignalStatus, number>>>;
}

/** Shape returned by GET /api/v1/admin/category-health. */
export interface CategoryHealthEntry {
  category: string;
  primary_sources: string[];
  secondary_sources: string[];
  source_health: unknown[];
  has_current_coverage: boolean;
  current_signal_count: number;
  last_current_signal_at: string | null;
  coverage_age_days: number | null;
  is_stale: boolean;
  last_new_article_at: string | null;
  coverage_status: string;
}
