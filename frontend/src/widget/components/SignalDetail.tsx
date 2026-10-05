import { useEffect, useState, type ReactNode } from "react";
import type { SignalDetail as SignalDetailType } from "../types";
import { fetchSignalDetail } from "../api";
import { CategoryIcon, publicCategoryLabel } from "../publicTaxonomy";
import { isSafeExternalUrl } from "../safeUrl";
import { ErrorState } from "./ErrorState";
import { SignalVisualBox } from "./SignalVisual";

interface SignalDetailProps {
  apiBaseUrl: string;
  signalId: string;
  titleId: string;
}

type DetailStatus = "loading" | "error" | "ready";

/** Absolute, human date for the reading view ("3 October 2026") - the
 * relative "2 days ago" stays on the compact card where it's scannable. */
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

function Section({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <section className="ss-reader__section">
      <h3 className="ss-reader__section-heading">{heading}</h3>
      {children}
    </section>
  );
}

export function SignalDetail({ apiBaseUrl, signalId, titleId }: SignalDetailProps) {
  const [signal, setSignal] = useState<SignalDetailType | null>(null);
  const [status, setStatus] = useState<DetailStatus>("loading");
  const [attempt, setAttempt] = useState(0);

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

  if (status === "loading") {
    return (
      <div className="ss-reader__skeleton" role="status" aria-label="Loading signal">
        <div className="ss-skeleton-line ss-skeleton-line--title" />
        <div className="ss-skeleton-line" />
        <div className="ss-skeleton-line" />
        <div className="ss-skeleton-line ss-skeleton-line--short" />
      </div>
    );
  }

  if (status === "error" || !signal) {
    return <ErrorState onRetry={() => setAttempt((n) => n + 1)} />;
  }

  const publishedDate = formatPublishedDate(signal.published_at);
  const principles = principleItems(signal.principle);
  const sources = signal.evidence.filter((item) => item.source_title || item.source_url);

  return (
    <article className="ss-reader__article">
      <header className="ss-reader__header">
        {signal.public_categories.length > 0 && (
          <ul className="ss-reader__categories" aria-label="Categories">
            {signal.public_categories.map((category) => (
              <li key={category} className="ss-reader__category">
                <CategoryIcon category={category} />
                <span>{publicCategoryLabel(category)}</span>
              </li>
            ))}
          </ul>
        )}
        <h2 id={titleId} className="ss-reader__title">
          {signal.title}
        </h2>
        {publishedDate && (
          <p className="ss-reader__byline">
            Published <time dateTime={signal.published_at ?? undefined}>{publishedDate}</time>
          </p>
        )}
      </header>

      <SignalVisualBox
        apiBaseUrl={apiBaseUrl}
        visualStatus={signal.visual_status}
        visualUrl={signal.visual_url}
        fallbackCategory={signal.public_categories[0] ?? null}
      />

      {signal.summary && <p className="ss-reader__lede">{signal.summary}</p>}

      {signal.security_impact && (
        <Section heading="Would this affect you?">
          <p className="ss-reader__body">{signal.security_impact}</p>
        </Section>
      )}

      {principles.length > 0 && (
        <Section heading="Design principle">
          <ul className="ss-reader__principles">
            {principles.map((principle) => (
              <li key={principle}>{principle}</li>
            ))}
          </ul>
        </Section>
      )}

      {signal.recommended_action && (
        <Section heading="High-level mitigations">
          <p className="ss-reader__body">{signal.recommended_action}</p>
        </Section>
      )}

      {sources.length > 0 && (
        <Section heading="Sources">
          <ul className="ss-reader__sources">
            {sources.map((item) => {
              const publisher = publisherFromUrl(item.source_url);
              const safe = isSafeExternalUrl(item.source_url);
              return (
                <li key={item.id} className="ss-reader__source">
                  {safe ? (
                    <a
                      className="ss-reader__source-title"
                      href={item.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {item.source_title || item.source_url}
                    </a>
                  ) : (
                    <span className="ss-reader__source-title">{item.source_title || "Untitled source"}</span>
                  )}
                  {publisher && <span className="ss-reader__source-publisher">{publisher}</span>}
                  {safe && (
                    <a
                      className="ss-reader__read-link"
                      href={item.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Read the original article <span aria-hidden="true">→</span>
                    </a>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      )}
    </article>
  );
}
