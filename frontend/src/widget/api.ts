/**
 * API client for the public Security Signals feed.
 *
 * Calls ONLY the two public, unauthenticated endpoints:
 *   GET /api/v1/signals/published
 *   GET /api/v1/signals/published/{id}
 *
 * No token/credential handling of any kind belongs here - this widget never
 * authenticates and must never call internal admin/reviewer/audit/auth
 * endpoints.
 */
import type { SignalDetail, SignalSummary } from "./types";

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
  category?: string | null;
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

async function getJson<T>(url: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    throw new ApiError("Network error while reaching Security Signals API", null);
  }

  if (!response.ok) {
    throw new ApiError(`Security Signals API returned ${response.status}`, response.status);
  }

  try {
    return (await response.json()) as T;
  } catch (err) {
    throw new ApiError("Security Signals API returned an invalid response", response.status);
  }
}

export async function fetchPublishedSignals(
  apiBaseUrl: string,
  { skip = 0, limit = 10, category = null }: FetchPublishedSignalsParams = {},
): Promise<FetchPublishedSignalsResult> {
  const url = buildUrl(apiBaseUrl, "/api/v1/signals/published", { skip, limit, category });
  const signals = await getJson<SignalSummary[]>(url);
  return { signals, hasMore: signals.length === limit };
}

export async function fetchSignalDetail(apiBaseUrl: string, id: string): Promise<SignalDetail> {
  const url = buildUrl(apiBaseUrl, `/api/v1/signals/published/${encodeURIComponent(id)}`, {});
  return getJson<SignalDetail>(url);
}
