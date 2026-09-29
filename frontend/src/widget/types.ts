/**
 * Types matching the public Security Signals API response shapes exactly.
 * Source of truth: backend app/api/routes/signals.py
 * (GET /api/v1/signals/published, GET /api/v1/signals/published/{id}).
 */

/** The fixed, backend-defined category taxonomy (SecurityCategoryType).
 * Security Signals is a threat-modeling platform: categories name a
 * security domain/design concern, not "is this technically a
 * vulnerability" - insecure_design is the domain for broken trust
 * boundaries, insecure auth architecture, fail-open behavior, and other
 * design-level weaknesses. */
export const SECURITY_CATEGORIES = [
  "insecure_design",
  "cloud_security",
  "iam",
  "app_api",
  "supply_chain",
  "data_privacy",
  "ransomware",
  "threat_intel",
  "ai_security",
  "infrastructure",
] as const;

export type SecurityCategory = (typeof SECURITY_CATEGORIES)[number];

/** AI Security subcategories (AISecuritySubcategory) - only meaningful
 * when the signal's category is "ai_security". */
export const AI_SECURITY_SUBCATEGORIES = [
  "llm_vulnerability",
  "agent_abuse",
  "ai_data_leakage",
  "model_poisoning",
  "ai_supply_chain",
  "ai_infrastructure",
  "ai_enabled_attacks",
  "misaligned_ai_permissions",
] as const;

export type AISecuritySubcategory = (typeof AI_SECURITY_SUBCATEGORIES)[number];

/** The consolidated PUBLIC-facing taxonomy (8 categories) - an aggregation
 * layer over the 10-value internal taxonomy above. The mapping logic
 * (which internal categories collapse into which public category, and
 * deduplication) lives ONLY on the backend (app/taxonomy.py) - the API
 * computes and returns `public_categories` per signal already, so this
 * frontend never reimplements that mapping. This list exists purely for
 * presentation: the category filter dropdown's options and the
 * slug->icon/label lookup (see publicTaxonomy.tsx). Must stay in sync
 * with app/taxonomy.py's PUBLIC_CATEGORIES/PUBLIC_CATEGORY_LABELS. */
export const PUBLIC_CATEGORIES = [
  "product_security",
  "cloud_identity_security",
  "supply_chain",
  "data_privacy",
  "ransomware",
  "threat_intel",
  "ai_security",
  "infrastructure",
] as const;

export type PublicCategory = (typeof PUBLIC_CATEGORIES)[number];

export const SORT_OPTIONS = ["recent", "relevant", "priority", "sources"] as const;
export type SortOption = (typeof SORT_OPTIONS)[number];

export interface SignalCategoryTag {
  id: string;
  category: string;
  subcategory: string | null;
}

export interface EvidenceItem {
  id: string;
  source_url: string;
  source_title: string;
  excerpt: string;
  created_at: string | null;
}

/** Item shape returned by GET /api/v1/signals/published (list). */
export interface SignalSummary {
  id: string;
  title: string;
  summary: string;
  security_impact: string;
  principle: string;
  recommended_action: string;
  published_at: string | null;
  categories: SignalCategoryTag[];
  /** Deduplicated public categories for this signal, already computed
   * server-side (app.taxonomy.internal_categories_to_public) - e.g.
   * [cloud_security, iam] -> ["cloud_identity_security"] (one, not two). */
  public_categories: string[];
}

/** Shape returned by GET /api/v1/analytics/public - computed ONLY from
 * PUBLISHED signals, so it can never reveal that a draft/in-review/approved/
 * rejected signal exists. Source of truth: AnalyticsService.get_public_analytics. */
export interface PublicAnalytics {
  generated_at: string;
  window_months: number;
  total_published: number;
  monthly_counts: { month: string; count: number }[];
  category_counts: Record<string, number>;
  principle_counts: Record<string, number>;
  dominant_theme: string | null;
}

/** "none" means no SignalVisual row exists at all (the signal predates the
 * visual-generation feature) - distinct from "pending" (generation is
 * genuinely queued/in flight). The public feed/detail API only ever
 * returns "none" here for that legacy case; it never implies a fabricated
 * generation attempt. */
export type VisualStatus = "pending" | "generated" | "failed" | "none";

/** Shape returned by GET /api/v1/signals/published/{id} (detail). Only the
 * detail endpoint exposes visual fields - the list/feed endpoint never
 * does, so loading the feed never implies loading (or generating) images. */
export interface SignalDetail extends SignalSummary {
  evidence: EvidenceItem[];
  visual_status: VisualStatus;
  /** Relative path (e.g. "/media/signals/<id>.png"), or null when no
   * generated visual exists yet (visual_status !== "generated") - render
   * the category-based fallback in that case. */
  visual_url: string | null;
}
