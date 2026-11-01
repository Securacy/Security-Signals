import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import type { SignalDetail as SignalDetailType, SignalSummary } from "../types";
import { fetchSignalDetail } from "../api";
import { CategoryIcon, publicCategoryLabel } from "../publicTaxonomy";
import { isSafeExternalUrl } from "../safeUrl";
import { ARROW_UP_RIGHT, Duotone, INFO, LIGHTBULB, LIGHTNING, LIST_CHECKS, type DuotoneIconData } from "../icons";
import { prefersReducedMotion } from "../motion";
import { ErrorState } from "./ErrorState";
import { SignalVisualBox } from "./SignalVisual";

interface SignalDetailProps {
  apiBaseUrl: string;
  signalId: string;
  titleId: string;
  /** The feed's summary for this signal, when opened from the feed - lets
   * the hero (title, category, date) paint immediately, before the detail
   * request resolves. */
  preview?: SignalSummary | null;
  /** On-screen rect of the feed image that was tapped: the FLIP origin
   * the hero expands from. */
  originRect?: DOMRect | null;
}

type DetailStatus = "loading" | "error" | "ready";

const FLIP_MS = 300;

/** Absolute, human date for the reading view ("3 October 2026") - the
 * relative "2 days ago" stays in the feed where it's scannable. */
function formatPublishedDate(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
}

/** Display-only publisher hint derived from a real source URL's hostname
 * (there is no separate publisher field in the data). Null for anything
 * that doesn't parse as a URL - never guessed. */
function publisherFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/^www\./, "") || null;
  } catch {
    return null;
  }
}

/** The principle field is stored as a semicolon-separated list of
 * principle names; split it for display, dropping empty fragments. */
function principleItems(principle: string): string[] {
  return principle
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

/**
 * Expand the hero image from the tapped feed image: measure where it
 * actually landed, transform it back onto the origin rect, then let the
 * transform transition away (FLIP). transform-only, skipped entirely for
 * reduced motion or when either box can't be measured.
 */
function useFlipFrom(originRect: DOMRect | null | undefined) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || !originRect || prefersReducedMotion()) return;
    const target = el.getBoundingClientRect();
    if (target.width === 0 || target.height === 0 || originRect.width === 0 || originRect.height === 0) return;

    el.style.transformOrigin = "0 0";
    el.style.transition = "none";
    el.style.transform =
      `translate(${originRect.left - target.left}px, ${originRect.top - target.top}px) ` +
      `scale(${originRect.width / target.width}, ${originRect.height / target.height})`;
    void el.getBoundingClientRect(); // commit the inverted frame
    el.style.transition = `transform ${FLIP_MS}ms cubic-bezier(0.2, 0.7, 0.2, 1)`;
    el.style.transform = "";
    el.dataset.flip = "true";
    // Empty deps on purpose: the origin is a one-shot, used only on this
    // reader's first paint - never replayed on later re-renders.
  }, []);
  return ref;
}

/** Icon tiles cycle through the palette's soft tints by card position. */
const TILE_TONES = ["lavender", "butter", "mint"] as const;

function DetailCard({
  heading,
  icon,
  index,
  children,
}: {
  heading: string;
  icon: DuotoneIconData;
  index: number;
  children: ReactNode;
}) {
  return (
    <section className="ss-dcard" style={{ "--i": index } as CSSProperties}>
      <span className={`ss-dcard__tile ss-dcard__tile--${TILE_TONES[index % TILE_TONES.length]}`} aria-hidden="true">
        <Duotone icon={icon} className="ss-dcard__icon" />
      </span>
      <div className="ss-dcard__content">
        <h3 className="ss-dcard__heading">{heading}</h3>
        {children}
      </div>
    </section>
  );
}

export function SignalDetail({ apiBaseUrl, signalId, titleId, preview = null, originRect = null }: SignalDetailProps) {
  const [signal, setSignal] = useState<SignalDetailType | null>(null);
  const [status, setStatus] = useState<DetailStatus>("loading");
  const [attempt, setAttempt] = useState(0);
  const heroRef = useFlipFrom(originRect);

  useEffect(() => {
    let cancelled = false;
    setStatus("loading");
    setSignal(null);

    fetchSignalDetail(apiBaseUrl, signalId)
      .then((data) => {
        if (cancelled) return;
        setSignal(data);
        setStatus("ready");
      })
      .catch(() => {
        if (cancelled) return;
        setStatus("error");
      });

    return () => {
      cancelled = true;
    };
  }, [apiBaseUrl, signalId, attempt]);

  // What the hero can show right now: the full detail once it's here,
  // otherwise the feed's preview of the same signal.
  const head: SignalSummary | null = signal ?? (preview && preview.id === signalId ? preview : null);

  if (!head) {
    if (status === "error") return <ErrorState onRetry={() => setAttempt((n) => n + 1)} />;
    return (
      <div className="ss-reader__skeleton" role="status" aria-label="Loading signal">
        <div className="ss-skel ss-skel--hero" />
        <div className="ss-reader__skeleton-cards">
          <div className="ss-skel ss-skel--card" />
          <div className="ss-skel ss-skel--card" />
        </div>
      </div>
    );
  }

  const primary = head.public_categories[0] ?? null;
  const publishedDate = formatPublishedDate(head.published_at);

  return (
    <article className="ss-reader__article">
      {/* The image stays fully visible - only a light top fade for the
          pills; the headline sits BELOW it, on the page background. */}
      <header className="ss-reader__hero">
        <div className="ss-reader__media" ref={heroRef}>
          <SignalVisualBox
            apiBaseUrl={apiBaseUrl}
            visualStatus={signal?.visual_status ?? "none"}
            visualUrl={signal?.visual_url ?? null}
            fallbackCategory={primary}
            className="ss-reader__visual"
          />
          <span className="ss-reader__topfade" aria-hidden="true" />
          <div className="ss-reader__hero-top">
            {head.public_categories.length > 0 && (
              <ul className="ss-reader__categories" aria-label="Categories">
                {head.public_categories.map((category) => (
                  <li key={category} className="ss-reader__category">
                    <CategoryIcon category={category} />
                    <span aria-hidden="true">{publicCategoryLabel(category)}</span>
                  </li>
                ))}
              </ul>
            )}
            {publishedDate && (
              <p className="ss-reader__byline">
                Published <time dateTime={head.published_at ?? undefined}>{publishedDate}</time>
              </p>
            )}
          </div>
        </div>
        <h2 id={titleId} className="ss-reader__title">
          {head.title}
        </h2>
      </header>

      {status === "error" && <ErrorState onRetry={() => setAttempt((n) => n + 1)} />}

      {status === "loading" && (
        <div className="ss-reader__skeleton-cards" role="status" aria-label="Loading signal">
          <div className="ss-skel ss-skel--card" />
          <div className="ss-skel ss-skel--card" />
        </div>
      )}

      {status === "ready" && signal && <DetailBody signal={signal} />}
    </article>
  );
}

function DetailBody({ signal }: { signal: SignalDetailType }) {
  const principles = principleItems(signal.principle);
  const sources = signal.evidence.filter((item) => item.source_title || item.source_url);
  let index = 0;

  return (
    <div className={`ss-reader__body-grid${sources.length > 0 ? " ss-reader__body-grid--with-sources" : ""}`}>
      <div className="ss-reader__cards">
        {signal.summary && (
          <DetailCard heading="What happened" icon={INFO} index={index++}>
            <p className="ss-dcard__text">{signal.summary}</p>
          </DetailCard>
        )}
        {signal.security_impact && (
          <DetailCard heading="Why it matters" icon={LIGHTNING} index={index++}>
            <p className="ss-dcard__text">{signal.security_impact}</p>
          </DetailCard>
        )}
        {signal.recommended_action && (
          <DetailCard heading="What to do" icon={LIST_CHECKS} index={index++}>
            <p className="ss-dcard__text">{signal.recommended_action}</p>
          </DetailCard>
        )}
        {principles.length > 0 && (
          <DetailCard heading="Design principle" icon={LIGHTBULB} index={index++}>
            <ul className="ss-reader__principles">
              {principles.map((principle) => (
                <li key={principle}>{principle}</li>
              ))}
            </ul>
          </DetailCard>
        )}
      </div>

      {sources.length > 0 && (
        <aside className="ss-reader__sources-col" style={{ "--i": index } as CSSProperties}>
          <h3 className="ss-reader__sources-heading">Sources</h3>
          <ul className="ss-reader__sources">
            {sources.map((item) => {
              const publisher = publisherFromUrl(item.source_url);
              const safe = isSafeExternalUrl(item.source_url);
              const initial = (publisher ?? item.source_title ?? "?").trim().charAt(0).toUpperCase() || "?";
              return (
                <li key={item.id} className="ss-source">
                  {/* No per-source image exists in the data - the thumb is
                      the publisher's initial, never a fetched favicon. */}
                  <span className="ss-source__thumb" aria-hidden="true">
                    {initial}
                  </span>
                  <div className="ss-source__body">
                    {safe ? (
                      <a className="ss-source__title" href={item.source_url} target="_blank" rel="noopener noreferrer">
                        {item.source_title || item.source_url}
                      </a>
                    ) : (
                      <span className="ss-source__title">{item.source_title || "Untitled source"}</span>
                    )}
                    {publisher && <span className="ss-source__publisher">{publisher}</span>}
                  </div>
                  {safe && (
                    <a className="ss-source__read" href={item.source_url} target="_blank" rel="noopener noreferrer">
                      Read the original article
                      <Duotone icon={ARROW_UP_RIGHT} className="ss-source__read-icon" lineOnly />
                    </a>
                  )}
                </li>
              );
            })}
          </ul>
        </aside>
      )}
    </div>
  );
}
