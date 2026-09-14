import { useCallback, useEffect, useState } from "react";
import type { SignalSummary } from "../types";
import { fetchPublishedSignals } from "../api";
import { CategoryFilter } from "./CategoryFilter";
import { SignalCard } from "./SignalCard";
import { FeedSkeleton } from "./LoadingSkeleton";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";

const PAGE_SIZE = 10;

type FeedStatus = "loading" | "loading-more" | "error" | "ready";

interface SignalFeedProps {
  apiBaseUrl: string;
  onOpenSignal: (id: string) => void;
}

export function SignalFeed({ apiBaseUrl, onOpenSignal }: SignalFeedProps) {
  const [category, setCategory] = useState<string | null>(null);
  const [signals, setSignals] = useState<SignalSummary[]>([]);
  const [skip, setSkip] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [status, setStatus] = useState<FeedStatus>("loading");

  const load = useCallback(
    async (nextSkip: number, replace: boolean) => {
      setStatus(replace ? "loading" : "loading-more");
      try {
        const result = await fetchPublishedSignals(apiBaseUrl, {
          skip: nextSkip,
          limit: PAGE_SIZE,
          category,
        });
        setSignals((prev) => (replace ? result.signals : [...prev, ...result.signals]));
        setHasMore(result.hasMore);
        setSkip(nextSkip);
        setStatus("ready");
      } catch {
        setStatus("error");
      }
    },
    [apiBaseUrl, category],
  );

  useEffect(() => {
    load(0, true);
  }, [load]);

  return (
    <div className="ss-feed">
      <CategoryFilter selected={category} onSelect={setCategory} />

      {status === "loading" && <FeedSkeleton />}

      {status === "error" && <ErrorState onRetry={() => load(0, true)} />}

      {status !== "loading" && status !== "error" && signals.length === 0 && (
        <EmptyState filtered={category !== null} />
      )}

      {status !== "loading" && status !== "error" && signals.length > 0 && (
        <div className="ss-feed__list">
          {signals.map((signal) => (
            <SignalCard key={signal.id} signal={signal} onOpen={onOpenSignal} />
          ))}
        </div>
      )}

      {status === "loading-more" && (
        <div className="ss-loading-more" role="status">
          Loading more…
        </div>
      )}

      {status === "ready" && hasMore && (
        <button
          type="button"
          className="ss-button ss-button--load-more"
          onClick={() => load(skip + PAGE_SIZE, false)}
        >
          Load more
        </button>
      )}
    </div>
  );
}
