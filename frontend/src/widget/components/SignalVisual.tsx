import { useEffect, useState } from "react";
import type { VisualStatus } from "../types";
import { resolveMediaUrl } from "../api";
import { CategoryGlyph, categoryColorStyle } from "../publicTaxonomy";
import { isSafeExternalUrl } from "../safeUrl";
import { Duotone, SHIELD_CHECK } from "../icons";
import { WATERMARK_MASK_STYLE } from "../watermark";

interface SignalVisualProps {
  apiBaseUrl: string;
  visualStatus: VisualStatus;
  visualUrl: string | null;
  /** First public category - drives the fallback's tint and glyph. The
   * fallback is a reusable category treatment, never a substitute
   * presented as the signal's own generated visual. */
  fallbackCategory: string | null;
  /** True while it isn't known yet whether a generated visual exists (the
   * card's detail lookup is in flight): shows only the shimmer, so the
   * fallback never flashes up before a real image replaces it. */
  pending?: boolean;
  className?: string;
}

/**
 * A signal's own AI-generated visual, filling whatever box the caller sizes
 * via className (callers reserve the aspect ratio, so nothing shifts).
 *
 * States: "loading" - shimmer only; "image" - the image fades in over a
 * shimmer once loaded (opacity only); "fallback" - designed category art
 * (pastel gradient, faint icon pattern, raised emblem) that reads as an
 * intentional card, not a missing image. Only the fallback carries an
 * accessible name when it's what's shown. Spans, not divs, so it can sit
 * inside a feed card's <button>.
 */
export function SignalVisualBox({
  apiBaseUrl,
  visualStatus,
  visualUrl,
  fallbackCategory,
  pending = false,
  className,
}: SignalVisualProps) {
  const [loadFailed, setLoadFailed] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    setLoadFailed(false);
    setLoaded(false);
  }, [visualUrl]);

  const resolvedUrl = visualUrl ? resolveMediaUrl(apiBaseUrl, visualUrl) : null;
  const canRenderImage =
    !pending && visualStatus === "generated" && !!resolvedUrl && isSafeExternalUrl(resolvedUrl) && !loadFailed;
  const state = pending ? "loading" : canRenderImage ? "image" : "fallback";

  return (
    <span
      className={["ss-visual", className].filter(Boolean).join(" ")}
      data-state={state}
      style={fallbackCategory ? categoryColorStyle(fallbackCategory) : undefined}
    >
      {state !== "loading" && (
        <span
          className={`ss-visual__fallback${fallbackCategory ? "" : " ss-visual__fallback--neutral"}`}
          role={canRenderImage ? undefined : "img"}
          aria-label={canRenderImage ? undefined : "Security signal illustration unavailable"}
          aria-hidden={canRenderImage ? true : undefined}
        >
          <span className="ss-visual__pattern" style={WATERMARK_MASK_STYLE} />
          <span className="ss-visual__emblem">
            {fallbackCategory ? (
              <CategoryGlyph category={fallbackCategory} className="ss-visual__fallback-icon" />
            ) : (
              <Duotone icon={SHIELD_CHECK} className="ss-visual__fallback-icon" />
            )}
          </span>
        </span>
      )}
      {canRenderImage && (
        <img
          className={`ss-visual__image${loaded ? " ss-visual__image--loaded" : ""}`}
          src={resolvedUrl}
          alt=""
          loading="lazy"
          decoding="async"
          onLoad={() => setLoaded(true)}
          onError={() => setLoadFailed(true)}
        />
      )}
      {(state === "loading" || (canRenderImage && !loaded)) && (
        <span className="ss-visual__shimmer ss-skel" aria-hidden="true" />
      )}
    </span>
  );
}
