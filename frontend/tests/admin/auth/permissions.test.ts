import { describe, it, expect } from "vitest";
import { canAccess, navStructureForRole, NAV_ITEMS, type RouteKey } from "../../../src/admin/auth/permissions";

/** Flattens the grouped nav (leaves + group items) back into a flat list of
 * keys, in display order - mirrors how the Sidebar itself walks the tree,
 * without duplicating its rendering logic here. */
function flattenKeys(role: Parameters<typeof navStructureForRole>[0]): string[] {
  return navStructureForRole(role).flatMap((entry) =>
    entry.kind === "leaf" ? [entry.item.key] : entry.group.items.map((item) => item.key),
  );
}

const ALL_ROUTE_KEYS = NAV_ITEMS.map((item) => item.key) as Exclude<RouteKey, "signal-detail">[];

describe("permissions", () => {
  it("ADMIN sees every nav item, including all Signals stages and both admin-only pages", () => {
    const keys = flattenKeys("admin");
    expect(keys).toEqual([
      "dashboard",
      "signals-all",
      "signals-draft",
      "signals-in-review",
      "signals-approved",
      "signals-published",
      "signals-rejected",
      "insights",
      "users",
      "audit",
    ]);
  });

  it("REVIEWER sees Dashboard, most Signals stages, and Insights, but never Approved, Users, or Audit", () => {
    const keys = flattenKeys("reviewer");
    expect(keys).toEqual([
      "dashboard",
      "signals-all",
      "signals-draft",
      "signals-in-review",
      "signals-published",
      "signals-rejected",
      "insights",
    ]);
    expect(keys).not.toContain("signals-approved");
    expect(keys).not.toContain("users");
    expect(keys).not.toContain("audit");
  });

  it("VIEWER sees only the read-only items: Dashboard, All Signals, and Published", () => {
    const keys = flattenKeys("viewer");
    expect(keys).toEqual(["dashboard", "signals-all", "signals-published"]);
  });

  it("no role (unauthenticated) sees nothing, and no empty group is rendered", () => {
    expect(navStructureForRole(null)).toEqual([]);
  });

  it("omits a whole group when the role can see none of its items (VIEWER: no Insights/Administration group)", () => {
    const structure = navStructureForRole("viewer");
    const groupLabels = structure.filter((e) => e.kind === "group").map((e) => (e.kind === "group" ? e.group.label : ""));
    expect(groupLabels).not.toContain("Insights");
    expect(groupLabels).not.toContain("Administration");
  });

  it("canAccess matches the flattened nav structure for every role/route combination", () => {
    (["admin", "reviewer", "viewer"] as const).forEach((role) => {
      const allowedKeys = flattenKeys(role);
      ALL_ROUTE_KEYS.forEach((key) => {
        expect(canAccess(role, key)).toBe(allowedKeys.includes(key));
      });
    });
  });

  it("canAccess is false for every route when role is null", () => {
    ALL_ROUTE_KEYS.forEach((key) => {
      expect(canAccess(null, key)).toBe(false);
    });
  });

  it("canAccess allows any authenticated role to reach signal-detail (not a nav-listed route)", () => {
    expect(canAccess("admin", "signal-detail")).toBe(true);
    expect(canAccess("reviewer", "signal-detail")).toBe(true);
    expect(canAccess("viewer", "signal-detail")).toBe(true);
    expect(canAccess(null, "signal-detail")).toBe(false);
  });
});
