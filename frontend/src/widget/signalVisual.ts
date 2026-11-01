import { fetchSignalDetail } from "./api";
import type { VisualStatus } from "./types";

export interface SignalVisualInfo {
  status: VisualStatus;
  url: string | null;
}

export const NO_VISUAL: SignalVisualInfo = { status: "none", url: null };

const cache = new Map<string, SignalVisualInfo>();

/**
 * A feed card's own generated visual. The list endpoint carries no visual
 * fields, so each card asks the PUBLIC detail endpoint for its signal - only
 * when the card nears the viewport (see SignalCard), and once per signal:
 * successful answers are cached for the page's lifetime, so filtering back
 * and forth doesn't refetch. Never rejects: any failure resolves to
 * NO_VISUAL (the category fallback) and isn't cached, so a later mount can
 * retry.
 */
export async function loadSignalVisual(apiBaseUrl: string, signalId: string): Promise<SignalVisualInfo> {
  const key = `${apiBaseUrl}|${signalId}`;
  const cached = cache.get(key);
  if (cached) return cached;
  try {
    const detail = await fetchSignalDetail(apiBaseUrl, signalId);
    if (!detail || typeof detail !== "object" || Array.isArray(detail)) return NO_VISUAL;
    const info: SignalVisualInfo = {
      status: detail.visual_status ?? "none",
      url: typeof detail.visual_url === "string" ? detail.visual_url : null,
    };
    cache.set(key, info);
    return info;
  } catch {
    return NO_VISUAL;
  }
}

export function peekSignalVisual(apiBaseUrl: string, signalId: string): SignalVisualInfo | null {
  return cache.get(`${apiBaseUrl}|${signalId}`) ?? null;
}

/** Test hook - each test starts from an empty cache. */
export function clearSignalVisualCache(): void {
  cache.clear();
}
