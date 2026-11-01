import { useEffect, useId, useRef, useState } from "react";
import type { SignalSummary } from "../types";
import { CategoryGlyph, categoryColorStyle, publicCategoryLabel } from "../publicTaxonomy";
import { formatRelativeTime } from "../formatRelativeTime";
import { useReaderLaunch } from "../readerLaunch";
import { observeOnce, PREFETCH_MARGIN } from "../inView";
import { loadSignalVisual, peekSignalVisual, type SignalVisualInfo } from "../signalVisual";
import { SignalVisualBox } from "./SignalVisual";

interface SignalCardProps {
  signal: SignalSummary;
  onOpen: (id: string) => void;
  /** Where to look up this signal's generated visual. Without it the card
   * shows its category art only and makes no request. */
  apiBaseUrl?: string;
}

function formatShortDate(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

/**
 * A feed card: the visual (or designed category art) on top with no
 * overlays at all, then the headline, then a footer - date on the left,
 * the primary category pill on the right.
 *
 * The button's aria-label ("Open signal: <title>") would otherwise hide
 * every child from a screen reader, so the footer (date + every category)
 * is wired in via aria-describedby. Children are phrasing content only (spans),
 * since that's all a <button> may contain.
 */
export function SignalCard({ signal, onOpen, apiBaseUrl }: SignalCardProps) {
  const metaId = useId();
  const cardRef = useRef<HTMLButtonElement>(null);
  const mediaRef = useRef<HTMLSpanElement>(null);
  const { prepare } = useReaderLaunch();
  const [visual, setVisual] = useState<SignalVisualInfo | null>(() =>
    apiBaseUrl ? peekSignalVisual(apiBaseUrl, signal.id) : null,
  );
  const primary = signal.public_categories[0] ?? null;
  const extraCategories = signal.public_categories.slice(1);
  const time = formatRelativeTime(signal.published_at);
  const shortDate = formatShortDate(signal.published_at);

  // Look up the card's own visual just before it scrolls into view.
  useEffect(() => {
    if (!apiBaseUrl) return undefined;
    let cancelled = false;
    const stopObserving = observeOnce(
      cardRef.current,
      () => {
        void loadSignalVisual(apiBaseUrl, signal.id).then((info) => {
          if (!cancelled) setVisual(info);
        });
      },
      PREFETCH_MARGIN,
    );
    return () => {
      cancelled = true;
      stopObserving();
    };
  }, [apiBaseUrl, signal.id]);

  return (
    <button
      ref={cardRef}
      type="button"
      className="ss-card"
      onClick={() => {
        prepare(signal, mediaRef.current);
        onOpen(signal.id);
      }}
      aria-label={`Open signal: ${signal.title}`}
      aria-describedby={metaId}
    >
      <span className="ss-card__media" ref={mediaRef}>
        <span className="ss-card__zoom">
          <SignalVisualBox
            apiBaseUrl={apiBaseUrl ?? ""}
            visualStatus={visual?.status ?? "none"}
            visualUrl={visual?.url ?? null}
            fallbackCategory={primary}
            pending={!!apiBaseUrl && visual === null}
            className="ss-card__visual"
          />
        </span>
      </span>

      <span className="ss-card__body">
        <span className="ss-card__title">{signal.title}</span>
        <span id={metaId} className="ss-card__footer">
          {time && (
            <time className="ss-card__date" dateTime={signal.published_at ?? undefined} title={shortDate ?? undefined}>
              {/* Spaces as separate text nodes: the accessible-name algorithm
                  trims whitespace inside each element, which would otherwise
                  read as "Publishedjust nowProduct Security". */}
              <span className="ss-visually-hidden">Published</span> {time}
            </time>
          )}{" "}
          {primary && (
            <span className="ss-pill" style={categoryColorStyle(primary)}>
              <CategoryGlyph category={primary} className="ss-pill__icon" />
              <span className="ss-pill__label">{publicCategoryLabel(primary)}</span>
              {extraCategories.length > 0 && (
                <>
                  <span className="ss-pill__more" aria-hidden="true">
                    +{extraCategories.length}
                  </span>
                  <span className="ss-visually-hidden">
                    , also {extraCategories.map((c) => publicCategoryLabel(c)).join(", ")}
                  </span>
                </>
              )}
            </span>
          )}
        </span>
      </span>
    </button>
  );
}
