import { NAV_ITEMS, type RouteKey } from "./auth/permissions";

/** The current page's title for the top bar - derived from the same
 * NAV_ITEMS labels the sidebar already uses (single source of truth, no
 * second copy of "Drafts"/"In Review"/etc.). "signal-detail" isn't a
 * nav-listed route (it's only ever reached by clicking into a signal), so
 * it gets one fixed fallback title here rather than a nav lookup. */
export function pageTitleForRoute(routeKey: RouteKey): string {
  if (routeKey === "signal-detail") return "Signal Detail";
  const item = NAV_ITEMS.find((i) => i.key === routeKey);
  return item?.label ?? "Cyberscope";
}
