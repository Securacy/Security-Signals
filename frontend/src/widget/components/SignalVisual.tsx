import { useState } from "react";
import type { VisualStatus } from "../types";
import { resolveMediaUrl } from "../api";
import { CategoryIcon } from "../publicTaxonomy";
import { isSafeExternalUrl } from "../safeUrl";

interface SignalVisualProps {
  apiBaseUrl: string;
  visualStatus: VisualStatus;
  visualUrl: string | null;
  /** First public category, used only for the fallback icon - the
   * fallback is a small, reusable category icon, never a substitute for
   * the signal's own generated visual. */
  fallbackCategory: string | null;
}

/**
 * Fixed 16:9 aspect-ratio box for a signal's own AI-generated visual
 * (see SignalVisual/ThreatVisualService on the backend) - never a
 * category-level stock image. Falls back to a polished, clearly-distinct
 * category-icon placeholder whenever no generated image exists yet
 * (pending/failed/never attempted), so layout never shifts and a missing
 * image never looks broken.
 */
export function SignalVisualBox({ apiBaseUrl, visualStatus, visualUrl, fallbackCategory }: SignalVisualProps) {
  const [loadFailed, setLoadFailed] = useState(false);

  const resolvedUrl = visualUrl ? resolveMediaUrl(apiBaseUrl, visualUrl) : null;
  const canRenderImage =
    visualStatus === "generated" && resolvedUrl !== null && isSafeExternalUrl(resolvedUrl) && !loadFailed;

  return (
    <div className="ss-visual" data-state={canRenderImage ? "image" : "fallback"}>
      {canRenderImage ? (
        <img
          className="ss-visual__image"
          src={resolvedUrl}
          alt=""
          loading="lazy"
          onError={() => setLoadFailed(true)}
        />
      ) : (
        <div className="ss-visual__fallback" role="img" aria-label="Security signal illustration unavailable">
          {fallbackCategory && <CategoryIcon category={fallbackCategory} className="ss-visual__fallback-icon" />}
        </div>
      )}
    </div>
  );
}
