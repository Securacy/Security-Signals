import { useEffect, useState } from "react";
import type { SignalDetail as SignalDetailType } from "../types";
import { fetchSignalDetail } from "../api";
import { CategoryIcon } from "../publicTaxonomy";
import { formatRelativeTime } from "../formatRelativeTime";
import { isSafeExternalUrl } from "../safeUrl";
import { ErrorState } from "./ErrorState";
import { SignalVisualBox } from "./SignalVisual";

interface SignalDetailProps {
  apiBaseUrl: string;
  signalId: string;
  onBack: () => void;
}

type DetailStatus = "loading" | "error" | "ready";

export function SignalDetail({ apiBaseUrl, signalId, onBack }: SignalDetailProps) {
  const [signal, setSignal] = useState<SignalDetailType | null>(null);
  const [status, setStatus] = useState<DetailStatus>("loading");

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
  }, [apiBaseUrl, signalId]);

  return (
    <div className="ss-detail">
      <button type="button" className="ss-back-button" onClick={onBack}>
        ← Back
      </button>

      {status === "loading" && (
        <div className="ss-detail__skeleton" role="status" aria-label="Loading signal">
          <div className="ss-skeleton-line ss-skeleton-line--title" />
          <div className="ss-skeleton-line" />
          <div className="ss-skeleton-line" />
          <div className="ss-skeleton-line ss-skeleton-line--short" />
        </div>
      )}

      {status === "error" && (
        <ErrorState
          onRetry={() => {
            setStatus("loading");
            fetchSignalDetail(apiBaseUrl, signalId)
              .then((data) => {
                setSignal(data);
                setStatus("ready");
              })
              .catch(() => setStatus("error"));
          }}
        />
      )}

      {status === "ready" && signal && (
        <article>
          <h2 className="ss-detail__title">{signal.title}</h2>
          <div className="ss-card__meta-row ss-detail__meta-row">
            {signal.public_categories.length > 0 && (
              <span className="ss-card__category-icons">
                {signal.public_categories.map((category) => (
                  <CategoryIcon key={category} category={category} />
                ))}
              </span>
            )}
            <p className="ss-detail__meta">{formatRelativeTime(signal.published_at)}</p>
          </div>

          <SignalVisualBox
            apiBaseUrl={apiBaseUrl}
            visualStatus={signal.visual_status}
            visualUrl={signal.visual_url}
            fallbackCategory={signal.public_categories[0] ?? null}
          />

          <section className="ss-detail__section">
            <h3>What happened</h3>
            <p>{signal.summary}</p>
          </section>

          <section className="ss-detail__section">
            <h3>Why it matters</h3>
            <p>{signal.security_impact}</p>
          </section>

          <section className="ss-detail__section">
            <h3>Security principle</h3>
            <p>{signal.principle}</p>
          </section>

          <section className="ss-detail__section">
            <h3>Recommended action</h3>
            <p>{signal.recommended_action}</p>
          </section>

          {signal.evidence.length > 0 && (
            <section className="ss-detail__section">
              <h3>Sources</h3>
              <ul className="ss-evidence-list">
                {signal.evidence.map((item) =>
                  isSafeExternalUrl(item.source_url) ? (
                    <li key={item.id}>
                      <a href={item.source_url} target="_blank" rel="noopener noreferrer">
                        {item.source_title}
                      </a>
                    </li>
                  ) : (
                    <li key={item.id}>{item.source_title}</li>
                  ),
                )}
              </ul>
            </section>
          )}
        </article>
      )}
    </div>
  );
}
