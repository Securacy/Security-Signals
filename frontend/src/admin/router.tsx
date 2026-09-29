import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from "react";
import type { RouteKey } from "./auth/permissions";

/**
 * Small History-API-based router - no routing library dependency, matching
 * the project's current zero-extra-deps posture. Handles a small, fixed
 * set of admin routes, including one dynamic segment (a signal ID) and a
 * literal-vs-dynamic disambiguation under /admin/signals/*.
 */

export type RouteMatch =
  | { key: Exclude<RouteKey, "signal-detail">; params?: undefined }
  | { key: "signal-detail"; params: { id: string } }
  | { key: "login"; params?: undefined }
  | { key: "not-found"; params?: undefined };

const SIGNALS_LITERAL_SEGMENTS: Record<string, Exclude<RouteKey, "signal-detail">> = {
  "": "signals-all",
  draft: "signals-draft",
  "in-review": "signals-in-review",
  approved: "signals-approved",
  published: "signals-published",
  rejected: "signals-rejected",
};

function matchRoute(pathname: string): RouteMatch {
  const normalized = pathname === "/admin" ? "/admin/" : pathname;
  if (normalized === "/admin/login") return { key: "login" };
  if (normalized === "/admin/" || normalized === "/admin") return { key: "dashboard" };
  if (normalized === "/admin/users") return { key: "users" };
  if (normalized === "/admin/audit") return { key: "audit" };
  if (normalized === "/admin/insights") return { key: "insights" };
  // /admin/review is a retired route name (folded into the Signals list
  // pages + signal detail actions) - redirected, not just 404ed, so any
  // existing bookmark/link still lands somewhere useful.
  if (normalized === "/admin/review") return { key: "signals-in-review" };

  if (normalized.startsWith("/admin/signals")) {
    const rest = normalized.slice("/admin/signals".length).replace(/^\//, "");
    if (rest in SIGNALS_LITERAL_SEGMENTS) {
      return { key: SIGNALS_LITERAL_SEGMENTS[rest] };
    }
    // Anything else under /admin/signals/* is treated as a signal ID -
    // the backend is the source of truth on whether it's a real one
    // (a bad ID surfaces as a normal 404 inside the detail page).
    if (rest && !rest.includes("/")) {
      return { key: "signal-detail", params: { id: rest } };
    }
  }

  return { key: "not-found" };
}

interface RouterContextValue {
  pathname: string;
  route: RouteMatch;
  navigate: (path: string) => void;
}

const RouterContext = createContext<RouterContextValue | null>(null);

export function RouterProvider({ children }: { children: ReactNode }) {
  const [pathname, setPathname] = useState(() => window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = (path: string) => {
    if (path !== window.location.pathname) {
      window.history.pushState(null, "", path);
    }
    setPathname(path);
  };

  const value = useMemo<RouterContextValue>(
    () => ({
      pathname,
      route: matchRoute(pathname),
      navigate,
    }),
    [pathname],
  );

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter(): RouterContextValue {
  const ctx = useContext(RouterContext);
  if (!ctx) {
    throw new Error("useRouter must be used within a RouterProvider");
  }
  return ctx;
}

/** Path builder for a signal's detail page - the one place that formats
 * this URL, so every caller (list pages, dashboard, audit log) stays in
 * sync with the router's own matching. */
export function signalDetailPath(id: string): string {
  return `/admin/signals/${id}`;
}

type LinkProps = { to: string } & AnchorHTMLAttributes<HTMLAnchorElement>;

export function Link({ to, onClick, ...rest }: LinkProps) {
  const { navigate } = useRouter();

  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(to);
  };

  return <a href={to} onClick={handleClick} {...rest} />;
}
