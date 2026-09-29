import { useCallback, useEffect, useRef, useState } from "react";
import type { SignalSummary, SortOption } from "../types";
import { fetchPublishedSignals, searchSignals } from "../api";
import { FilterBar } from "./FilterBar";
import { SignalCard } from "./SignalCard";
import { FeedSkeleton } from "./LoadingSkeleton";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { publicCategoryLabel } from "../publicTaxonomy";

const PAGE_SIZE = 10;
const SEARCH_RESULT_LIMIT = 30;

type FeedStatus = "loading" | "loading-more" | "error" | "ready";

interface SignalFeedProps {
  apiBaseUrl: string;
  onOpenSignal: (id: string) => void;
}

export function SignalFeed({ apiBaseUrl, onOpenSignal }: SignalFeedProps) {
  const [category, setCategory] = useState<string | null>(null);
  const [subcategory, setSubcategory] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortOption>("recent");
  const [signals, setSignals] = useState<SignalSummary[]>([]);
  const [skip, setSkip] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [status, setStatus] = useState<FeedStatus>("loading");
  const [aiUnderstood, setAiUnderstood] = useState(false);
  const [understoodPublicCategories, setUnderstoodPublicCategories] = useState<string[]>([]);

  const isSearchMode = search.trim() !== "";

  // Race-safety: exactly one request may ever "own" the displayed feed
  // state. Every call to load() first aborts whatever request is still in
  // flight (cancelling the underlying fetch, which also avoids wasting a
  // backend/AI call on a query the user has already changed), then stamps
  // its own monotonically increasing sequence number. When a response
  // comes back, it's only applied to state if it's still the most recent
  // request issued - a stale request finishing late (e.g. the initial
  // mount's normal-feed fetch resolving after a since-typed search query)
  // can no longer clobber newer, more relevant results. This fixes the bug
  // where a slow, superseded /published response overwrote a correct,
  // already-displayed search result a second or two after it appeared.
  const requestSeqRef = useRef(0);
  const abortControllerRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (nextSkip: number, replace: boolean) => {
      abortControllerRef.current?.abort();
      const controller = new AbortController();
      abortControllerRef.current = controller;
      const requestId = ++requestSeqRef.current;
      const isStale = () => requestId !== requestSeqRef.current;

      setStatus(replace ? "loading" : "loading-more");
      try {
        if (isSearchMode) {
          // Natural-language search (Feature 3) - a bounded, single page
          // of AI-ranked-or-keyword-matched results; the backend already
          // falls back to deterministic search on any AI failure, so this
          // call never needs its own AI-specific error handling.
          const result = await searchSignals(apiBaseUrl, {
            query: search.trim(),
            category,
            subcategory,
            sort,
            limit: SEARCH_RESULT_LIMIT,
            signal: controller.signal,
          });
          if (isStale()) return;
          setSignals(result.signals);
          setAiUnderstood(result.aiUnderstood);
          setUnderstoodPublicCategories(result.understoodPublicCategories);
          setHasMore(false);
          setSkip(0);
        } else {
          const result = await fetchPublishedSignals(apiBaseUrl, {
            skip: nextSkip,
            limit: PAGE_SIZE,
            category,
            subcategory,
            sort,
            signal: controller.signal,
          });
          if (isStale()) return;
          setSignals((prev) => (replace ? result.signals : [...prev, ...result.signals]));
          setHasMore(result.hasMore);
          setSkip(nextSkip);
          setAiUnderstood(false);
          setUnderstoodPublicCategories([]);
        }
        setStatus("ready");
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        if (isStale()) return;
        setStatus("error");
      }
    },
    [apiBaseUrl, category, subcategory, search, sort, isSearchMode],
  );

  useEffect(() => {
    const timeout = setTimeout(() => load(0, true), search ? 300 : 0);
    return () => clearTimeout(timeout);
  }, [load, search]);

  useEffect(() => {
    return () => abortControllerRef.current?.abort();
  }, []);

  const isFiltered = category !== null || subcategory !== null || isSearchMode;

  const clearFilters = () => {
    setCategory(null);
    setSubcategory(null);
    setSearch("");
    setSort("recent");
  };

  return (
    <div className="ss-feed">
      <FilterBar
        category={category}
        subcategory={subcategory}
        search={search}
        sort={sort}
        isSearching={isSearchMode && status === "loading"}
        onCategoryChange={setCategory}
        onSubcategoryChange={setSubcategory}
        onSearchChange={setSearch}
        onSortChange={setSort}
        onClear={clearFilters}
      />

      {status === "loading" && <FeedSkeleton />}

      {status === "error" && <ErrorState onRetry={() => load(0, true)} />}

      {status === "ready" && isSearchMode && (
        <p className="ss-search-understood" role="status">
          {aiUnderstood && understoodPublicCategories.length > 0
            ? `Understood as: ${understoodPublicCategories.map((c) => publicCategoryLabel(c)).join(", ")} — `
            : ""}
          {signals.length === 0
            ? "no matching signals"
            : `${signals.length} matching signal${signals.length === 1 ? "" : "s"}`}
        </p>
      )}

      {status !== "loading" && status !== "error" && signals.length === 0 && (
        <EmptyState filtered={isFiltered} isSearchMode={isSearchMode} />
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

      {status === "ready" && !isSearchMode && hasMore && (
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
