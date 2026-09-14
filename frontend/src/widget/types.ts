/**
 * Types matching the public Security Signals API response shapes exactly.
 * Source of truth: backend app/api/routes/signals.py
 * (GET /api/v1/signals/published, GET /api/v1/signals/published/{id}).
 */

/** The fixed, backend-defined category taxonomy (SecurityCategoryType). */
export const SECURITY_CATEGORIES = [
  "vulnerability",
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

export interface SignalCategoryTag {
  id: string;
  category: string;
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
}

/** Shape returned by GET /api/v1/signals/published/{id} (detail). */
export interface SignalDetail extends SignalSummary {
  evidence: EvidenceItem[];
}
