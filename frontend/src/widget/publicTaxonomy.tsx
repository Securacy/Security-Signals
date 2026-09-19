/**
 * Public-facing category taxonomy: labels + small, reusable SVG icons.
 *
 * This is presentation-only. The actual internal->public mapping logic
 * (which internal categories collapse into which public category, plus
 * deduplication) lives solely on the backend (app/taxonomy.py) - the API
 * already returns each signal's deduplicated `public_categories`, so this
 * file only needs to know how to LABEL and ICON the 8 known public
 * category slugs. Must stay in sync with app/taxonomy.py's
 * PUBLIC_CATEGORIES/PUBLIC_CATEGORY_LABELS.
 *
 * These icons are a reusable, category-level visual identity - distinct
 * from a Signal's own unique AI-generated visual (see SignalVisual /
 * ThreatVisualService on the backend, rendered in SignalDetail). A
 * category icon never changes per-signal; a signal's visual is never
 * reused between signals.
 */
import type { CSSProperties } from "react";
import type { PublicCategory } from "./types";

export const PUBLIC_CATEGORY_LABELS: Record<PublicCategory, string> = {
  product_security: "Product Security",
  cloud_identity_security: "Cloud & Identity Security",
  supply_chain: "Supply Chain",
  data_privacy: "Data & Privacy",
  ransomware: "Ransomware",
  threat_intel: "Threat Intelligence",
  ai_security: "AI Security",
  infrastructure: "Infrastructure",
};

export function publicCategoryLabel(category: string): string {
  return PUBLIC_CATEGORY_LABELS[category as PublicCategory] ?? category;
}

interface IconProps {
  className?: string;
}

/** Shield with an alert mark - Product Security (secure architecture / design flaws). */
function ProductSecurityIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" strokeLinejoin="round" />
      <path d="M12 8v4.5" strokeLinecap="round" />
      <circle cx="12" cy="15.2" r="0.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** Cloud with a small lock - Cloud & Identity Security. */
function CloudIdentitySecurityIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M7 17.5a4 4 0 0 1-.5-7.97 5 5 0 0 1 9.7-1.8A4.5 4.5 0 0 1 17.5 17.5H7z" strokeLinejoin="round" />
      <rect x="10" y="12.5" width="4" height="3.4" rx="0.7" />
      <path d="M10.8 12.5v-1a1.2 1.2 0 0 1 2.4 0v1" />
    </svg>
  );
}

/** Linked nodes - Supply Chain. */
function SupplyChainIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="6" cy="7" r="2.3" />
      <circle cx="18" cy="7" r="2.3" />
      <circle cx="12" cy="17" r="2.3" />
      <path d="M8 8.2 10.3 15.3M16 8.2 13.7 15.3" strokeLinecap="round" />
    </svg>
  );
}

/** Document with a lock - Data & Privacy. */
function DataPrivacyIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M7 3.5h7l3 3v14h-10z" strokeLinejoin="round" />
      <path d="M14 3.5v3h3" strokeLinejoin="round" />
      <rect x="8.5" y="13" width="6" height="4.4" rx="0.7" />
      <path d="M9.6 13v-1.2a1.9 1.9 0 0 1 3.8 0V13" />
    </svg>
  );
}

/** Locked file - Ransomware. */
function RansomwareIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M6 3.5h9l3 3.5v13.5h-12z" strokeLinejoin="round" />
      <rect x="9" y="12" width="6" height="5" rx="0.8" />
      <path d="M10.3 12v-1.5a1.7 1.7 0 0 1 3.4 0V12" />
      <path d="M12 14.2v1.3" strokeLinecap="round" />
    </svg>
  );
}

/** Radar/scan sweep - Threat Intelligence. */
function ThreatIntelIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4.2" opacity="0.6" />
      <circle cx="12" cy="12" r="0.9" fill="currentColor" stroke="none" />
      <path d="M12 12 17 7.2" strokeLinecap="round" />
    </svg>
  );
}

/** Brain/node with a small shield accent - AI Security (kept independent). */
function AISecurityIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="8.5" cy="9" r="1.4" />
      <circle cx="15.5" cy="9" r="1.4" />
      <circle cx="12" cy="15.5" r="1.4" />
      <path d="M9.7 9.9 11 14.3M14.3 9.9 13 14.3M9.9 8.5H14.1" strokeLinecap="round" />
      <path d="M12 3.3l2 1v2l-2 1-2-1v-2z" strokeLinejoin="round" />
    </svg>
  );
}

/** Server stack - Infrastructure. */
function InfrastructureIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <rect x="4.5" y="4" width="15" height="5" rx="1" />
      <rect x="4.5" y="10.5" width="15" height="5" rx="1" />
      <rect x="4.5" y="17" width="15" height="3" rx="1" />
      <circle cx="7.3" cy="6.5" r="0.6" fill="currentColor" stroke="none" />
      <circle cx="7.3" cy="13" r="0.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

const PUBLIC_CATEGORY_ICONS: Record<PublicCategory, (props: IconProps) => JSX.Element> = {
  product_security: ProductSecurityIcon,
  cloud_identity_security: CloudIdentitySecurityIcon,
  supply_chain: SupplyChainIcon,
  data_privacy: DataPrivacyIcon,
  ransomware: RansomwareIcon,
  threat_intel: ThreatIntelIcon,
  ai_security: AISecurityIcon,
  infrastructure: InfrastructureIcon,
};

interface CategoryIconProps {
  category: string;
  className?: string;
}

/** Renders one small, accessible category icon with an aria-label and a
 * native tooltip (title) - never relies on color alone to communicate
 * which category it represents. Falls back to nothing (renders null) for
 * an unrecognized slug rather than a broken/generic icon. */
export function CategoryIcon({ category, className }: CategoryIconProps) {
  const Icon = PUBLIC_CATEGORY_ICONS[category as PublicCategory];
  if (!Icon) return null;
  const label = publicCategoryLabel(category);
  return (
    <span
      className="ss-category-icon"
      role="img"
      aria-label={label}
      title={label}
      style={{ "--ss-cat-color": `var(--ss-cat-${category})` } as CSSProperties}
    >
      <Icon className={className ?? "ss-category-icon__svg"} />
    </span>
  );
}
