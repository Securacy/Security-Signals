import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import type { SignalSummary } from "../types";
import { prefersReducedMotion } from "../motion";
import { SignalCard } from "./SignalCard";

export const DECK_HINT_STORAGE_KEY = "ss-widget-deck-hint-seen";
const HINT_VISIBLE_MS = 3000;
const NEIGHBOUR_SCALE = 0.94;
const NEIGHBOUR_OPACITY = 0.6;

interface SignalDeckProps {
  apiBaseUrl: string;
  signals: SignalSummary[];
  onOpenSignal: (id: string) => void;
  /** More pages exist: the deck ends with a "Load more" slide. */
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
}

function hintAlreadySeen(): boolean {
  try {
    return window.localStorage.getItem(DECK_HINT_STORAGE_KEY) !== null;
  } catch {
    return true; // Storage unavailable: never risk showing the hint every visit.
  }
}

function markHintSeen(): void {
  try {
    window.localStorage.setItem(DECK_HINT_STORAGE_KEY, "1");
  } catch {
    // ignore
  }
}

function ArrowIcon({ direction }: { direction: "left" | "right" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true" className="ss-deck__arrow-icon">
      {direction === "left" ? (
        <path d="M14.5 6 8.5 12l6 6" strokeLinecap="round" strokeLinejoin="round" />
      ) : (
        <path d="M9.5 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  );
}

/**
 * Horizontal swipe deck: one card in focus, the next peeking from the right.
 * Swiping is plain native scrolling with `scroll-snap-type: x mandatory` -
 * touch, trackpad and drag all work without a carousel library - and the
 * deck never moves on its own (no autoplay).
 *
 * Scroll position drives everything else: the active index (arrows, the
 * screen-reader position announcement) and each slide's scale/opacity, interpolated continuously from
 * its distance to the snap point and written straight to the slide's inline
 * style once per animation frame (transform + opacity only, no re-render
 * per scroll event).
 */
export function SignalDeck({ apiBaseUrl, signals, onOpenSignal, hasMore, loadingMore, onLoadMore }: SignalDeckProps) {
  const trackRef = useRef<HTMLDivElement>(null);
  const slideRefs = useRef<(HTMLDivElement | null)[]>([]);
  const frameRef = useRef<number | null>(null);
  const [active, setActive] = useState(0);
  const [hint, setHint] = useState<"none" | "on" | "fading">("none");

  const total = signals.length;
  const slideCount = total + (hasMore ? 1 : 0);

  /** Distance between consecutive slides' snap points, in px. */
  const step = useCallback((): number => {
    const [first, second] = slideRefs.current;
    if (first && second) return second.offsetLeft - first.offsetLeft;
    return first?.offsetWidth ?? 0;
  }, []);

  const paint = useCallback(() => {
    frameRef.current = null;
    const track = trackRef.current;
    const distance = step();
    if (!track || distance <= 0) return;
    const position = track.scrollLeft / distance;
    const scaleSlides = !prefersReducedMotion();
    slideRefs.current.forEach((slide, i) => {
      if (!slide) return;
      const d = Math.min(1, Math.abs(i - position));
      const frame = slide.firstElementChild as HTMLElement | null;
      if (!frame) return;
      frame.style.transform = scaleSlides ? `scale(${1 - (1 - NEIGHBOUR_SCALE) * d})` : "";
      frame.style.opacity = String(1 - (1 - NEIGHBOUR_OPACITY) * d);
    });
    setActive(Math.max(0, Math.min(slideCount - 1, Math.round(position))));
  }, [slideCount, step]);

  const schedulePaint = useCallback(() => {
    if (frameRef.current === null) frameRef.current = window.requestAnimationFrame(paint);
  }, [paint]);

  useLayoutEffect(() => {
    paint();
  }, [paint, slideCount]);

  useEffect(() => {
    window.addEventListener("resize", schedulePaint);
    return () => {
      window.removeEventListener("resize", schedulePaint);
      if (frameRef.current !== null) window.cancelAnimationFrame(frameRef.current);
    };
  }, [schedulePaint]);

  // First visit only: nudge the peeking card + a "swipe" label for 3s.
  useEffect(() => {
    if (total < 2 || hintAlreadySeen()) return undefined;
    markHintSeen();
    setHint("on");
    const timer = window.setTimeout(() => setHint("fading"), HINT_VISIBLE_MS);
    return () => window.clearTimeout(timer);
  }, [total]);

  const goTo = useCallback(
    (index: number) => {
      const track = trackRef.current;
      const target = Math.max(0, Math.min(slideCount - 1, index));
      if (!track) return;
      const left = target * step();
      if (typeof track.scrollTo === "function") {
        track.scrollTo({ left, behavior: prefersReducedMotion() ? "auto" : "smooth" });
      } else {
        track.scrollLeft = left;
      }
      setActive(target);
      setHint((h) => (h === "on" ? "fading" : h));
      // Keyboard users stay with the content: if focus was on a card, it
      // follows to the new one (without its own scroll jump).
      if (track.contains(document.activeElement)) {
        const next = slideRefs.current[target]?.querySelector<HTMLElement>("button");
        next?.focus({ preventScroll: true });
      }
    },
    [slideCount, step],
  );

  function onKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      goTo(active + 1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      goTo(active - 1);
    }
  }

  const shownIndex = Math.min(active + 1, total);
  const totalLabel = `${total}${hasMore ? "+" : ""}`;

  return (
    <section
      className={`ss-deck${hint === "on" ? " ss-deck--hint" : ""}`}
      aria-roledescription="carousel"
      aria-label="Security signals"
      tabIndex={0}
      onKeyDown={onKeyDown}
    >
      <div className="ss-deck__track" ref={trackRef} onScroll={schedulePaint} data-scroll-root>
        {signals.map((signal, i) => (
          <div
            key={signal.id}
            ref={(el) => {
              slideRefs.current[i] = el;
            }}
            className="ss-deck__slide"
            role="group"
            aria-roledescription="slide"
            aria-label={`${i + 1} of ${total}`}
          >
            <div className="ss-deck__frame">
              <SignalCard apiBaseUrl={apiBaseUrl} signal={signal} onOpen={onOpenSignal} />
            </div>
          </div>
        ))}
        {hasMore && (
          <div
            ref={(el) => {
              slideRefs.current[total] = el;
            }}
            className="ss-deck__slide ss-deck__slide--more"
          >
            <div className="ss-deck__frame">
              {loadingMore ? (
                <p className="ss-loading-more" role="status">
                  Loading more…
                </p>
              ) : (
                <button type="button" className="ss-button ss-button--load-more" onClick={onLoadMore}>
                  Load more
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {(hint === "on" || hint === "fading") && (
        <span className={`ss-deck__hint${hint === "on" ? " ss-deck__hint--visible" : ""}`} aria-hidden="true">
          Swipe →
        </span>
      )}

      {/* No visible counter or dots - but a screen reader still hears
          where it is in the deck after each move. */}
      <p className="ss-visually-hidden" aria-live="polite" aria-atomic="true">
        Signal {shownIndex} of {totalLabel}
      </p>

      <div className="ss-deck__controls">
        <button
          type="button"
          className="ss-deck__arrow ss-deck__arrow--prev"
          aria-label="Previous signal"
          disabled={active <= 0}
          onClick={() => goTo(active - 1)}
        >
          <ArrowIcon direction="left" />
        </button>

        <button
          type="button"
          className="ss-deck__arrow ss-deck__arrow--next"
          aria-label="Next signal"
          disabled={active >= slideCount - 1}
          onClick={() => goTo(active + 1)}
        >
          <ArrowIcon direction="right" />
        </button>
      </div>
    </section>
  );
}
