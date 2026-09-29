import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  fetchApprovedSignals,
  fetchAuditEntries,
  fetchCategoryHealth,
  fetchDraftSignals,
  fetchInternalAnalytics,
  fetchUsers,
} from "../api/client";
import type { AdminSignalListItem, AdminSignalStatus, AdminUser, AuditEntry, CategoryHealthEntry, InternalAnalytics } from "../api/types";
import { fetchPublishedSignals, fetchPublicAnalytics } from "../../widget/api";
import type { PublicAnalytics, SignalSummary } from "../../widget/types";
import { categoryLabel } from "../../widget/categoryLabels";
import { formatRelativeTime } from "../../widget/formatRelativeTime";
import { formatAction } from "../formatAction";
import { auditActionTone } from "../auditActionTone";
import { getAdminConfig } from "../config";
import { timeOfDayGreeting } from "../greeting";
import { SIGNAL_STATUS_LABEL } from "../signalStatus";
import { useLoad, type LoadState } from "../useLoad";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";
import { Link, signalDetailPath } from "../router";

const EMPTY_SIGNALS: AdminSignalListItem[] = [];
const EMPTY_AUDIT: AuditEntry[] = [];
const EMPTY_HEALTH: CategoryHealthEntry[] = [];
const EMPTY_USERS: AdminUser[] = [];

const ROLE_SUBTITLE: Record<string, string> = {
  admin: "Here's what needs your attention today.",
  reviewer: "Here's what's waiting on your review.",
  viewer: "Here's what's been published recently.",
};

const LIFECYCLE_STAGES: { status: AdminSignalStatus; path: string }[] = [
  { status: "draft", path: "/admin/signals/draft" },
  { status: "in_review", path: "/admin/signals/in-review" },
  { status: "approved", path: "/admin/signals/approved" },
  { status: "published", path: "/admin/signals/published" },
];

export function DashboardPage() {
  const { user } = useAuth();
  const role = user!.role;
  const isAdmin = role === "admin";
  const isReviewerOrAdmin = role === "admin" || role === "reviewer";
  const authorizedFetch = useAuthorizedFetch();
  const { apiBaseUrl } = getAdminConfig();

  const pipelineState = useLoad(
    () => (isReviewerOrAdmin ? fetchDraftSignals(authorizedFetch) : Promise.resolve(EMPTY_SIGNALS)),
    [authorizedFetch, isReviewerOrAdmin],
  );

  const approvedState = useLoad(
    () => (isAdmin ? fetchApprovedSignals(authorizedFetch) : Promise.resolve(EMPTY_SIGNALS)),
    [authorizedFetch, isAdmin],
  );

  const auditState = useLoad(
    () => (isAdmin ? fetchAuditEntries(authorizedFetch, { limit: 6 }) : Promise.resolve(EMPTY_AUDIT)),
    [authorizedFetch, isAdmin],
  );

  const categoryHealthState = useLoad(
    () => (isAdmin ? fetchCategoryHealth(authorizedFetch) : Promise.resolve(EMPTY_HEALTH)),
    [authorizedFetch, isAdmin],
  );

  const usersState = useLoad(
    () => (isAdmin ? fetchUsers(authorizedFetch, { limit: 200 }) : Promise.resolve(EMPTY_USERS)),
    [authorizedFetch, isAdmin],
  );

  const publishedState = useLoad(
    () => fetchPublishedSignals(apiBaseUrl, { limit: 5, sort: "recent" }).then((result) => result.signals),
    [apiBaseUrl],
  );

  // The widest window the endpoint accepts, as a practical stand-in for an
  // "all time" total - see AnalyticsService.get_internal_analytics (it is
  // genuinely windowed by creation month, not a true lifetime count).
  const lifecycleState = useLoad(
    () => (isReviewerOrAdmin ? fetchInternalAnalytics(authorizedFetch, 36) : Promise.resolve(null)),
    [authorizedFetch, isReviewerOrAdmin],
  );

  const landscapeState = useLoad(() => fetchPublicAnalytics(apiBaseUrl, 12), [apiBaseUrl]);

  const draftValue = attentionValue(pipelineState, (s) => s.status === "draft");
  const inReviewValue = attentionValue(pipelineState, (s) => s.status === "in_review");
  const readyToPublishValue = attentionValue(approvedState, () => true);

  return (
    <div className="adm-page">
      <header className="adm-greeting">
        <div className="adm-greeting__pattern" aria-hidden="true" />
        <h1 className="adm-greeting__title">
          {timeOfDayGreeting()}, {user!.username} 👋
        </h1>
        <p className="adm-greeting__subtitle">{ROLE_SUBTITLE[role] ?? ROLE_SUBTITLE.viewer}</p>
      </header>

      {isReviewerOrAdmin && (
        <section aria-labelledby="lifecycle-heading" className="adm-lifecycle-section">
          <h2 id="lifecycle-heading" className="adm-section-heading">
            Signal lifecycle
          </h2>
          <LifecycleBar state={lifecycleState} />
        </section>
      )}

      {isReviewerOrAdmin && (
        <section className="adm-attention" aria-labelledby="needs-attention-heading">
          <h2 id="needs-attention-heading" className="adm-attention__heading">
            Needs your attention
          </h2>
          <div className="adm-attention-strip">
            <AttentionTile
              to="/admin/signals/draft"
              value={draftValue}
              label={(count) => (count === 1 ? "Draft to submit" : "Drafts to submit")}
              hint="Ready to send for approval"
              cta="View drafts →"
            />
            <AttentionTile
              to="/admin/signals/in-review"
              value={inReviewValue}
              label={(count) => (count === 1 ? "Signal awaiting your review" : "Signals awaiting your review")}
              hint="Approve or reject"
              cta="Review signals →"
            />
            {isAdmin && (
              <AttentionTile
                to="/admin/signals/approved"
                value={readyToPublishValue}
                label={(count) => (count === 1 ? "Signal ready to publish" : "Signals ready to publish")}
                hint="Approved, awaiting publish"
                cta="Publish queue →"
              />
            )}
          </div>
        </section>
      )}

      <div className="adm-dashboard-grid">
        <Card title="Recently published" action={<Link to="/admin/signals/published">View all</Link>}>
          <PublishedListSection state={publishedState} />
        </Card>

        <Card title="Security landscape" action={<Link to="/admin/insights">View analytics</Link>}>
          <SecurityLandscapeSection state={landscapeState} />
        </Card>

        {isAdmin && (
          <Card title="Recent activity" action={<Link to="/admin/audit">View all</Link>}>
            <AuditListSection state={auditState} />
          </Card>
        )}

        {isAdmin && (
          <Card title="Source health" action={<Link to="/admin/signals">View signals</Link>}>
            <CategoryHealthSection state={categoryHealthState} />
          </Card>
        )}

        {isAdmin && (
          <Card title="Team" action={<Link to="/admin/users">Manage</Link>}>
            <TeamSection state={usersState} />
          </Card>
        )}
      </div>
    </div>
  );
}

function LifecycleBar({ state }: { state: LoadState<InternalAnalytics | null> }) {
  if (state.status === "loading") return <LoadingState label="Loading lifecycle…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;
  if (!state.data) return null;

  const totals = state.data.status_totals ?? {};

  return (
    <ol className="adm-lifecycle-bar">
      {LIFECYCLE_STAGES.map((stage, index) => (
        <li key={stage.status} className="adm-lifecycle-bar__stage">
          <Link to={stage.path} className="adm-lifecycle-bar__link">
            <span className={`adm-lifecycle-bar__icon adm-lifecycle-bar__icon--${stage.status}`} aria-hidden="true" />
            <span className="adm-lifecycle-bar__count">{totals[stage.status] ?? 0}</span>
            <span className="adm-lifecycle-bar__label">{SIGNAL_STATUS_LABEL[stage.status]}</span>
          </Link>
          {index < LIFECYCLE_STAGES.length - 1 && (
            <span className="adm-lifecycle-bar__arrow" aria-hidden="true">
              →
            </span>
          )}
        </li>
      ))}
    </ol>
  );
}

type AttentionValue = { status: "loading" } | { status: "error" } | { status: "ready"; count: number };

function attentionValue<T>(state: LoadState<T[]>, filter: (item: T) => boolean): AttentionValue {
  if (state.status === "loading") return { status: "loading" };
  if (state.status === "error") return { status: "error" };
  return { status: "ready", count: state.data.filter(filter).length };
}

function AttentionTile({
  to,
  value,
  label,
  hint,
  cta,
}: {
  to: string;
  value: AttentionValue;
  label: (count: number) => string;
  hint: string;
  cta: string;
}) {
  if (value.status === "loading") {
    return (
      <div className="adm-attention-tile" aria-busy="true">
        <span className="adm-attention-tile__count">···</span>
        <span>
          <span className="adm-attention-tile__label">{label(0)}</span>
        </span>
      </div>
    );
  }
  if (value.status === "error") {
    return (
      <div className="adm-attention-tile adm-attention-tile--error" role="alert">
        <span className="adm-attention-tile__count">—</span>
        <span>
          <span className="adm-attention-tile__label">{label(0)}</span>
          <span className="adm-attention-tile__hint">Couldn't load</span>
        </span>
      </div>
    );
  }
  const { count } = value;
  const isEmpty = count === 0;
  return (
    <Link
      to={to}
      className={`adm-attention-tile${isEmpty ? " adm-attention-tile--empty" : ""}`}
      aria-label={`${count} ${label(count).toLowerCase()} - ${cta}`}
    >
      <span className="adm-attention-tile__count">{count}</span>
      <span>
        <span className="adm-attention-tile__label">{label(count)}</span>
        <span className="adm-attention-tile__hint">{isEmpty ? "All caught up" : hint}</span>
        {!isEmpty && <span className="adm-attention-tile__cta">{cta}</span>}
      </span>
    </Link>
  );
}

function PublishedListSection({ state }: { state: LoadState<SignalSummary[]> }) {
  if (state.status === "loading") return <LoadingState label="Loading recent signals…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;
  if (state.data.length === 0) {
    return <EmptyState message="No signals have been published yet." />;
  }

  return (
    <ul className="adm-mini-list">
      {state.data.map((signal) => (
        <li key={signal.id} className="adm-mini-list__item">
          <Link to={signalDetailPath(signal.id)} className="adm-mini-list__title">
            {signal.title}
          </Link>
          <span className="adm-mini-list__meta">{formatRelativeTime(signal.published_at)}</span>
        </li>
      ))}
    </ul>
  );
}

function AuditListSection({ state }: { state: LoadState<AuditEntry[]> }) {
  if (state.status === "loading") return <LoadingState label="Loading recent activity…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;
  if (state.data.length === 0) {
    return <EmptyState message="No activity has been recorded yet." />;
  }

  return (
    <ul className="adm-timeline">
      {state.data.map((entry) => (
        <li key={entry.id} className="adm-timeline__item">
          <span className={`adm-timeline__dot adm-timeline__dot--${auditActionTone(entry.action)}`} aria-hidden="true" />
          <span className="adm-timeline__title">{formatAction(entry.action)}</span>
          <span className="adm-timeline__meta">{formatRelativeTime(entry.timestamp)}</span>
        </li>
      ))}
    </ul>
  );
}

function SecurityLandscapeSection({ state }: { state: LoadState<PublicAnalytics> }) {
  if (state.status === "loading") return <LoadingState label="Loading category distribution…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;

  const entries = Object.entries(state.data.category_counts ?? {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return <EmptyState message="No published signals yet to break down by category." />;
  }

  const max = Math.max(...entries.map(([, count]) => count));
  return (
    <ul className="adm-bar-list adm-bar-list--compact">
      {entries.slice(0, 8).map(([category, count]) => (
        <li key={category} className="adm-bar-list__row">
          <span className="adm-bar-list__label">{categoryLabel(category)}</span>
          <span className="adm-bar-list__track">
            <span className="adm-bar-list__fill" style={{ width: `${(count / max) * 100}%` }} />
          </span>
          <span className="adm-bar-list__value">{count}</span>
        </li>
      ))}
    </ul>
  );
}

function CategoryHealthSection({ state }: { state: LoadState<CategoryHealthEntry[]> }) {
  if (state.status === "loading") return <LoadingState label="Loading source health…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;
  if (state.data.length === 0) {
    return <EmptyState message="No category coverage data is available." />;
  }

  const stale = state.data.filter((entry) => entry.is_stale);
  const current = state.data.length - stale.length;

  return (
    <>
      <p className="adm-stat-line">
        <strong>{current}</strong> of <strong>{state.data.length}</strong> categories have current coverage.
      </p>
      {stale.length > 0 ? (
        <ul className="adm-mini-list">
          {stale.map((entry) => (
            <li key={entry.category} className="adm-mini-list__item">
              <span className="adm-mini-list__title">{categoryLabel(entry.category)}</span>
              <Badge tone="warning">Stale</Badge>
            </li>
          ))}
        </ul>
      ) : (
        <p className="adm-stat-line adm-stat-line--positive">All categories are current.</p>
      )}
    </>
  );
}

function TeamSection({ state }: { state: LoadState<AdminUser[]> }) {
  if (state.status === "loading") return <LoadingState label="Loading team…" />;
  if (state.status === "error") return <ErrorState message={state.message} />;
  if (state.data.length === 0) return <EmptyState message="No users exist yet." />;

  const active = state.data.filter((u) => u.is_active).length;
  const byRole = { admin: 0, reviewer: 0, viewer: 0 };
  for (const u of state.data) byRole[u.role] += 1;

  return (
    <>
      <p className="adm-metric-row">
        <span className="adm-metric-row__value">{active}</span>
        <span>of {state.data.length} accounts active</span>
      </p>
      <p className="adm-stat-line">
        {byRole.admin} admin{byRole.admin === 1 ? "" : "s"} · {byRole.reviewer} reviewer{byRole.reviewer === 1 ? "" : "s"} ·{" "}
        {byRole.viewer} viewer{byRole.viewer === 1 ? "" : "s"}
      </p>
    </>
  );
}
