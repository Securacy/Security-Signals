/**
 * API client for the public Security Signals feed.
 *
 * Calls ONLY public, unauthenticated endpoints:
 *   GET /api/v1/signals/published
 *   GET /api/v1/signals/published/{id}
 *   GET /api/v1/signals/search (natural-language search, Feature 3)
 *   GET /api/v1/analytics/public (published-only aggregate counts)
 *
 * No token/credential handling of any kind belongs here - this widget never
 * authenticates and must never call internal admin/reviewer/audit/auth
 * endpoints. The admin app also imports the public-endpoint functions here
 * directly (e.g. for its Dashboard) rather than duplicating this fetch
 * logic, since they carry no auth and are safe to reuse as-is.
 */
import type { PublicAnalytics, SignalDetail, SignalSummary } from "./types";

export class ApiError extends Error {
  status: number | null;

  constructor(message: string, status: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface FetchPublishedSignalsParams {
  skip?: number;
  limit?: number;
  /** A PUBLIC category slug (e.g. "product_security") - sent as the
   * backend's `public_category` param, which translates it into the
   * internal categories it aggregates (see app/taxonomy.py). */
  category?: string | null;
  subcategory?: string | null;
  search?: string | null;
  sort?: string | null;
  signal?: AbortSignal;
}

export interface FetchPublishedSignalsResult {
  signals: SignalSummary[];
  /** True when the page returned as many items as requested, i.e. there may
   * be more to load. The API doesn't return a total count. */
  hasMore: boolean;
}

function buildUrl(apiBaseUrl: string, path: string, query: Record<string, string | number | undefined | null>): string {
  const url = new URL(apiBaseUrl + path);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (err) {
    // Propagate an intentional abort as-is (name === "AbortError") so
    // callers can distinguish "this request was superseded" from "this
    // request actually failed" - collapsing both into ApiError would make
    // it impossible for the feed to tell a cancelled stale request apart
    // from a real network failure.
    if (err instanceof DOMException && err.name === "AbortError") {
      throw err;
    }
    throw new ApiError("Network error while reaching Cyberscope API", null);
  }

  if (!response.ok) {
    throw new ApiError(`Cyberscope API returned ${response.status}`, response.status);
  }

  try {
    return (await response.json()) as T;
  } catch (err) {
    throw new ApiError("Cyberscope API returned an invalid response", response.status);
  }
}

export async function fetchPublishedSignals(
  apiBaseUrl: string,
  { skip = 0, limit = 10, category = null, subcategory = null, search = null, sort = null, signal }: FetchPublishedSignalsParams = {},
): Promise<FetchPublishedSignalsResult> {
  const url = buildUrl(apiBaseUrl, "/api/v1/signals/published", {
    skip, limit, public_category: category, subcategory, search, sort,
  });
  const signals = await getJson<SignalSummary[]>(url, signal);
  return { signals, hasMore: signals.length === limit };
}

export async function fetchSignalDetail(apiBaseUrl: string, id: string): Promise<SignalDetail> {
  const url = buildUrl(apiBaseUrl, `/api/v1/signals/published/${encodeURIComponent(id)}`, {});
  return getJson<SignalDetail>(url);
}

export async function fetchPublicAnalytics(apiBaseUrl: string, months = 12): Promise<PublicAnalytics> {
  const url = buildUrl(apiBaseUrl, "/api/v1/analytics/public", { months });
  return getJson<PublicAnalytics>(url);
}

/**
 * Resolve a signal's backend-relative visual path (e.g.
 * "/media/signals/<id>.png") against the widget's own API origin, the same
 * way every other API call is built - never a user/AI-controlled URL, only
 * ever a path this backend itself generated and returned.
 */
export function resolveMediaUrl(apiBaseUrl: string, path: string): string {
  return apiBaseUrl.replace(/\/+$/, "") + path;
}

export interface SearchSignalsParams {
  query: string;
  /** A PUBLIC category slug - sent as `public_category`, see
   * FetchPublishedSignalsParams.category. */
  category?: string | null;
  subcategory?: string | null;
  sort?: string | null;
  limit?: number;
  signal?: AbortSignal;
}

export interface SearchSignalsResult {
  signals: SignalSummary[];
  aiUnderstood: boolean;
  /** Deduplicated PUBLIC categories the AI understood the query as
   * relating to (already translated server-side), for the "Understood
   * as: ..." UI hint. */
  understoodPublicCategories: string[];
}

interface SearchApiResponse {
  query: string;
  ai_understood: boolean;
  understood_categories: string[];
  understood_public_categories: string[];
  results: SignalSummary[];
}

/**
 * Natural-language (or plain keyword) search over PUBLISHED signals only.
 * The backend transparently falls back to deterministic keyword search
 * when AI understanding is unavailable or fails - this call never needs
 * to know which path served the request, only whether it succeeded.
 */
export async function searchSignals(
  apiBaseUrl: string,
  { query, category = null, subcategory = null, sort = null, limit = 30, signal }: SearchSignalsParams,
): Promise<SearchSignalsResult> {
  const url = buildUrl(apiBaseUrl, "/api/v1/signals/search", {
    q: query, public_category: category, subcategory, sort, limit,
  });
  const response = await getJson<SearchApiResponse>(url, signal);
  return {
    signals: response.results,
    aiUnderstood: response.ai_understood,
    understoodPublicCategories: response.understood_public_categories ?? [],
  };
}
