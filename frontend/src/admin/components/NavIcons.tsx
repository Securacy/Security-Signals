import type { RouteKey } from "../auth/permissions";

interface IconProps {
  className?: string;
}

/** One small, restrained line icon per nav item - purely a wayfinding aid,
 * never the only way to identify a section (every item still has its text
 * label). Same minimal stroke-icon style as the widget's category icons -
 * the project's existing hand-rolled icon system, kept consistent rather
 * than introducing a new icon library dependency. */

function DashboardIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.2" />
      <rect x="13" y="3.5" width="7.5" height="4.5" rx="1.2" />
      <rect x="13" y="10" width="7.5" height="10.5" rx="1.2" />
      <rect x="3.5" y="13" width="7.5" height="7.5" rx="1.2" />
    </svg>
  );
}

function SignalsIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M12 3v3.2M12 17.8V21M3 12h3.2M17.8 12H21" strokeLinecap="round" />
      <path d="M6.3 6.3l2.2 2.2M15.5 15.5l2.2 2.2M17.7 6.3l-2.2 2.2M8.5 15.5l-2.2 2.2" strokeLinecap="round" />
      <circle cx="12" cy="12" r="2.6" />
    </svg>
  );
}

function DraftIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M6 3.8h8l4 4v12.4H6z" strokeLinejoin="round" />
      <path d="M9 12h6M9 15.5h6M9 8.5h3" strokeLinecap="round" />
    </svg>
  );
}

function InReviewIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path
        d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="2.8" />
    </svg>
  );
}

function ApprovedIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.3 12.3l2.4 2.4 5-5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function PublishedIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.7 9.5h16.6M3.7 14.5h16.6" strokeLinecap="round" />
      <path d="M12 3.5c2.4 2.3 3.6 5.3 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.3-3.6-8.5S9.6 5.8 12 3.5z" />
    </svg>
  );
}

function RejectedIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M9 9l6 6M15 9l-6 6" strokeLinecap="round" />
    </svg>
  );
}

function InsightsIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M4 20V10M11 20V4M18 20v-7" strokeLinecap="round" />
      <path d="M3 20h18" strokeLinecap="round" />
    </svg>
  );
}

function UsersIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="9" cy="8" r="3" />
      <path d="M3.5 19.5c0-3 2.5-5.2 5.5-5.2s5.5 2.2 5.5 5.2" strokeLinecap="round" />
      <circle cx="17" cy="7.5" r="2.3" />
      <path d="M15.2 12.7c2.6 0.2 4.6 2.2 4.6 4.9" strokeLinecap="round" />
    </svg>
  );
}

function AuditIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="11" cy="12" r="7.5" />
      <path d="M11 8v4l2.6 1.6" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M20.5 20.5l-3-3" strokeLinecap="round" />
    </svg>
  );
}

/** Every RouteKey that can appear as a nav item - signal-detail is
 * reachable only by clicking into a signal, never listed in the sidebar,
 * so it has no icon here. */
type NavRouteKey = Exclude<RouteKey, "signal-detail">;

const ICONS: Record<NavRouteKey, (props: IconProps) => JSX.Element> = {
  dashboard: DashboardIcon,
  "signals-all": SignalsIcon,
  "signals-draft": DraftIcon,
  "signals-in-review": InReviewIcon,
  "signals-approved": ApprovedIcon,
  "signals-published": PublishedIcon,
  "signals-rejected": RejectedIcon,
  insights: InsightsIcon,
  users: UsersIcon,
  audit: AuditIcon,
};

export function NavIcon({ routeKey, className }: { routeKey: NavRouteKey; className?: string }) {
  const Icon = ICONS[routeKey];
  return <Icon className={className ?? "adm-nav-link__icon"} />;
}
