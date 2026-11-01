import { useCallback, useEffect, useRef, useState } from "react";
import type { SignalSummary } from "../types";
import { fetchPublishedSignals, searchSignals } from "../api";
import { FilterBar } from "./FilterBar";
import { SignalDeck } from "./SignalDeck";
import { FeedSkeleton } from "./LoadingSkeleton";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { publicCategoryLabel } from "../publicTaxonomy";

const PAGE_SIZE = 10;
const SEARCH_RESULT_LIMIT = 30;
/** The feed is always newest-first: the date-grouped layout (Today / This
 * week / Earlier) only makes sense in that order. */
const FEED_SORT = "recent";

type FeedStatus = "loading" | "loading-more" | "error" | "ready";

interface SignalFeedProps {
  apiBaseUrl: string;
  onOpenSignal: (id: string) => void;
}

export function SignalFeed({ apiBaseUrl, onOpenSignal }: SignalFeedProps) {
  const [category, setCategory] = useState<string | null>(null);
  const [subcategory, setSubcategory] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [signals, setSignals] = useState<SignalSummary[]>([]);
  const [skip, setSkip] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [status, setStatus] = useState<FeedStatus>("loading");
  // Bumped whenever a fresh result set replaces the list (new filter or
  // query), so the deck remounts: back to card 1, with its fade-in.
  const [generation, setGeneration] = useState(0);
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
            sort: FEED_SORT,
            limit: SEARCH_RESULT_LIMIT,
            signal: controller.signal,
          });
          if (isStale()) return;
          setSignals(result.signals);
          setGeneration((g) => g + 1);
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
            sort: FEED_SORT,
            signal: controller.signal,
          });
          if (isStale()) return;
          setSignals((prev) => (replace ? result.signals : [...prev, ...result.signals]));
          if (replace) setGeneration((g) => g + 1);
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
    [apiBaseUrl, category, subcategory, search, isSearchMode],
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
  };

  // A reload while results are already on screen (filter change, new
  // search query) keeps them visible, dimmed, under a pull-to-refresh
  // style spinner; the skeleton is only for a feed with nothing to show.
  const isRefreshing = status === "loading" && signals.length > 0;
  const showList = signals.length > 0 && (status === "ready" || status === "loading-more" || isRefreshing);
  return (
    <div className="ss-feed">
      <FilterBar
        category={category}
        subcategory={subcategory}
        search={search}
        isSearching={isSearchMode && status === "loading"}
        onCategoryChange={setCategory}
        onSubcategoryChange={setSubcategory}
        onSearchChange={setSearch}
        onClear={clearFilters}
      />

      {isRefreshing && (
        <div className="ss-refresh" role="status" aria-label="Refreshing security signals">
          <span className="ss-refresh__spinner" aria-hidden="true" />
        </div>
      )}

      {status === "loading" && signals.length === 0 && <FeedSkeleton />}

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

      {status === "ready" && signals.length === 0 && <EmptyState filtered={isFiltered} isSearchMode={isSearchMode} />}

      {showList && (
        <div className={`ss-feed__list${isRefreshing ? " ss-feed__list--refreshing" : ""}`}>
          <SignalDeck
            key={generation}
            apiBaseUrl={apiBaseUrl}
            signals={signals}
            onOpenSignal={onOpenSignal}
            hasMore={!isSearchMode && hasMore}
            loadingMore={status === "loading-more"}
            onLoadMore={() => load(skip + PAGE_SIZE, false)}
          />
        </div>
      )}
    </div>
  );
}
