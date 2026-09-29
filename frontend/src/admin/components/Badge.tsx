import type { ReactNode } from "react";

type Tone = "neutral" | "success" | "warning" | "danger" | "info" | "accent";

/**
 * Status pill: always pairs a tone (color) with a text label passed as
 * children - status must never be communicated through color alone (WCAG
 * 1.4.1). Callers are expected to pass a short label, e.g. <Badge
 * tone="success">Published</Badge>, not an icon-only child.
 */
export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`adm-badge adm-badge--${tone}`}>{children}</span>;
}
