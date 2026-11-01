/**
 * Public-facing category taxonomy: labels + small, reusable duotone icons.
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
import {
  DETECTIVE,
  Duotone,
  FILE_LOCK,
  FINGERPRINT,
  HARD_DRIVES,
  LOCK_KEY,
  PACKAGE,
  ROBOT,
  SHIELD_WARNING,
  type DuotoneIconData,
} from "./icons";

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

/** One Phosphor duotone glyph per public category (see icons.tsx for the
 * source/licence). Picked for what each domain is ABOUT, so the icon still
 * reads correctly at 16-24px without its label:
 *   product_security        -> ShieldWarning  (a flaw in what you ship)
 *   cloud_identity_security -> Fingerprint    (identity is the cloud perimeter)
 *   supply_chain            -> Package        (third-party components)
 *   data_privacy            -> LockKey        (protected data)
 *   ransomware              -> FileLock       (files held hostage)
 *   threat_intel            -> Detective      (adversary tracking)
 *   ai_security             -> Robot          (models and agents)
 *   infrastructure          -> HardDrives     (servers and hosts) */
const PUBLIC_CATEGORY_ICONS: Record<PublicCategory, DuotoneIconData> = {
  product_security: SHIELD_WARNING,
  cloud_identity_security: FINGERPRINT,
  supply_chain: PACKAGE,
  data_privacy: LOCK_KEY,
  ransomware: FILE_LOCK,
  threat_intel: DETECTIVE,
  ai_security: ROBOT,
  infrastructure: HARD_DRIVES,
};

/** Inline style that points the shared --ss-cat-color custom property at
 * this category's palette entry (see widget.css) - every category-tinted
 * element (icon badge, card tile, pill, filter chip) reads that one
 * property, so the palette lives only in CSS. */
export function categoryColorStyle(category: string): CSSProperties {
  return { "--ss-cat-color": `var(--ss-cat-${category})` } as CSSProperties;
}

/** Decorative category glyph (aria-hidden) for use next to a visible text
 * label. Renders nothing for an unrecognized slug. */
export function CategoryGlyph({ category, className }: { category: string; className?: string }) {
  const icon = PUBLIC_CATEGORY_ICONS[category as PublicCategory];
  if (!icon) return null;
  return <Duotone icon={icon} className={className} />;
}

interface CategoryIconProps {
  category: string;
  className?: string;
}

/** Renders one small, accessible category icon with an aria-label and a
 * native tooltip (title) - never relies on color alone to communicate
 * which category it represents. Falls back to nothing (renders null) for
 * an unrecognized slug rather than a broken/generic icon. */
export function CategoryIcon({ category, className }: CategoryIconProps) {
  const icon = PUBLIC_CATEGORY_ICONS[category as PublicCategory];
  if (!icon) return null;
  const label = publicCategoryLabel(category);
  return (
    <span className="ss-category-icon" role="img" aria-label={label} title={label} style={categoryColorStyle(category)}>
      <Duotone icon={icon} className={className ?? "ss-category-icon__svg"} />
    </span>
  );
}
