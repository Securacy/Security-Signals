import { useAuth } from "../auth/AuthContext";
import { useRouter } from "../router";
import { pageTitleForRoute } from "../pageTitle";
import { ProfileMenu } from "./ProfileMenu";

/** Branding lives in the sidebar now (see Sidebar.tsx) - the top bar's job
 * is page context (title) plus the account menu, so it earns its place at
 * the top of every page rather than repeating the product name. */
export function TopBar() {
  const { user } = useAuth();
  const { route } = useRouter();
  if (!user) return null;

  const isDashboard = route.key === "dashboard";
  const title = route.key === "login" || route.key === "not-found" ? "Cyberscope" : pageTitleForRoute(route.key);

  // The dashboard already opens with its own greeting heading, so a
  // separate "Dashboard" label above it is redundant - the bar stays only
  // for the account menu, compacted to just that.
  return (
    <header className={isDashboard ? "adm-topbar adm-topbar--compact" : "adm-topbar"}>
      {/* Not a heading element - each page already renders its own real
          <h1> (e.g. UsersPage's "Users") further down; this is a visual
          breadcrumb/context label, not a second top-level heading. */}
      {!isDashboard && <p className="adm-topbar__title">{title}</p>}
      <div className="adm-topbar__account">
        <ProfileMenu />
      </div>
    </header>
  );
}
