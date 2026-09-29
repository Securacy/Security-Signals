import type { Role } from "./types";

/**
 * Single source of truth for what each role's UI shows - consumed by the
 * sidebar (what to render, grouped) and the router (what to allow landing
 * on via a typed URL, not just what's linked). This is UX only: the
 * backend's require_admin/require_reviewer dependencies remain the actual
 * authorization boundary, unchanged by anything here (see
 * app/api/dependencies.py).
 */
export type RouteKey =
  | "dashboard"
  | "signals-all"
  | "signals-draft"
  | "signals-in-review"
  | "signals-approved"
  | "signals-published"
  | "signals-rejected"
  | "signal-detail"
  | "insights"
  | "users"
  | "audit";

export interface NavLeaf {
  /** Never "signal-detail" - that route is reachable only by clicking into
   * a signal, never listed in the nav. */
  key: Exclude<RouteKey, "signal-detail">;
  label: string;
  path: string;
  roles: Role[];
}

export interface NavGroup {
  label: string;
  items: NavLeaf[];
}

export type NavEntry = { kind: "leaf"; item: NavLeaf } | { kind: "group"; group: NavGroup };

const DASHBOARD: NavLeaf = { key: "dashboard", label: "Dashboard", path: "/admin/", roles: ["admin", "reviewer", "viewer"] };

const SIGNALS_GROUP: NavGroup = {
  label: "Signals",
  items: [
    { key: "signals-all", label: "All Signals", path: "/admin/signals", roles: ["admin", "reviewer", "viewer"] },
    { key: "signals-draft", label: "Drafts", path: "/admin/signals/draft", roles: ["admin", "reviewer"] },
    { key: "signals-in-review", label: "In Review", path: "/admin/signals/in-review", roles: ["admin", "reviewer"] },
    { key: "signals-approved", label: "Approved", path: "/admin/signals/approved", roles: ["admin"] },
    { key: "signals-published", label: "Published", path: "/admin/signals/published", roles: ["admin", "reviewer", "viewer"] },
    { key: "signals-rejected", label: "Rejected", path: "/admin/signals/rejected", roles: ["admin", "reviewer"] },
  ],
};

const INSIGHTS_GROUP: NavGroup = {
  label: "Insights",
  items: [{ key: "insights", label: "Analytics", path: "/admin/insights", roles: ["admin", "reviewer"] }],
};

const ADMINISTRATION_GROUP: NavGroup = {
  label: "Administration",
  items: [
    { key: "users", label: "Users", path: "/admin/users", roles: ["admin"] },
    { key: "audit", label: "Audit Log", path: "/admin/audit", roles: ["admin"] },
  ],
};

/** Every leaf route, flattened - the router's canAccess() and the
 * dashboard's/signal detail's "where does this role land" logic both
 * consult this rather than walking the grouped tree themselves. */
export const NAV_ITEMS: NavLeaf[] = [
  DASHBOARD,
  ...SIGNALS_GROUP.items,
  ...INSIGHTS_GROUP.items,
  ...ADMINISTRATION_GROUP.items,
];

/** The grouped structure the sidebar actually renders. */
export const NAV_STRUCTURE: NavEntry[] = [
  { kind: "leaf", item: DASHBOARD },
  { kind: "group", group: SIGNALS_GROUP },
  { kind: "group", group: INSIGHTS_GROUP },
  { kind: "group", group: ADMINISTRATION_GROUP },
];

export function canAccess(role: Role | null, routeKey: RouteKey): boolean {
  if (!role) return false;
  if (routeKey === "signal-detail") return role === "admin" || role === "reviewer" || role === "viewer";
  const item = NAV_ITEMS.find((i) => i.key === routeKey);
  return item ? item.roles.includes(role) : false;
}

/** The grouped nav, filtered to what this role may see - a group with no
 * visible children is omitted entirely rather than shown empty. */
export function navStructureForRole(role: Role | null): NavEntry[] {
  if (!role) return [];
  const result: NavEntry[] = [];
  for (const entry of NAV_STRUCTURE) {
    if (entry.kind === "leaf") {
      if (entry.item.roles.includes(role)) result.push(entry);
      continue;
    }
    const items = entry.group.items.filter((item) => item.roles.includes(role));
    if (items.length > 0) result.push({ kind: "group", group: { ...entry.group, items } });
  }
  return result;
}
