import { useMemo, useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  fetchApprovedSignals,
  fetchDraftSignals,
  fetchRejectedSignals,
} from "../api/client";
import type { AdminSignalListItem, AdminSignalStatus, AdminVisualStatus } from "../api/types";
import { fetchPublishedSignals } from "../../widget/api";
import type { SignalCategoryTag } from "../../widget/types";
import { categoryLabel } from "../../widget/categoryLabels";
import { formatRelativeTime } from "../../widget/formatRelativeTime";
import { getAdminConfig } from "../config";
import { useLoad, type LoadState } from "../useLoad";
import { SIGNAL_STATUS_LABEL, SIGNAL_STATUS_TONE } from "../signalStatus";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";
import { VisualPreview } from "../components/VisualPreview";
import { Link, signalDetailPath } from "../router";

export type SignalListStatus = "all" | AdminSignalStatus;

const PAGE_COPY: Record<SignalListStatus, { title: string; description: string }> = {
  all: { title: "All Signals", description: "Every signal across the full lifecycle, in one place." },
  draft: { title: "Drafts", description: "AI-generated signals not yet submitted for approval." },
  in_review: { title: "In Review", description: "Signals waiting on a reviewer's approve/reject decision." },
  approved: { title: "Approved", description: "Reviewed and approved - ready to publish." },
  published: { title: "Published", description: "Live, publicly visible signals." },
  rejected: { title: "Rejected", description: "Signals a reviewer declined to move forward." },
};

/** A row shape every signal source (the three protected list endpoints,
 * which share AdminSignalListItem, and the public published endpoint,
 * which returns the narrower SignalSummary with no visual fields) is
 * normalized into, so one card renderer covers every status. */
interface Row {
  id: string;
  title: string;
  summary: string;
  status: AdminSignalStatus;
  categories: SignalCategoryTag[];
  dateLabel: string;
  dateValue: string | null;
  visualStatus?: AdminVisualStatus;
  visualUrl?: string | null;
  visualRequestedAt?: string | null;
}

function fromListItem(item: AdminSignalListItem): Row {
  const isReviewed = item.status === "approved" || item.status === "rejected";
  return {
    id: item.id,
    title: item.title,
    summary: item.summary,
    status: item.status,
    categories: item.categories,
    dateLabel: isReviewed ? "Reviewed" : "Created",
    dateValue: (isReviewed ? item.reviewed_at : item.created_at) ?? item.created_at,
    visualStatus: item.visual_status,
    visualUrl: item.visual_url,
    visualRequestedAt: item.visual_requested_at,
  };
}

export function SignalListPage({ status }: { status: SignalListStatus }) {
  const { user } = useAuth();
  const role = user!.role;
  const authorizedFetch = useAuthorizedFetch();
  const { apiBaseUrl } = getAdminConfig();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");

  const includeDraftPipeline = status === "all" || status === "draft" || status === "in_review";
  const includeApproved = (status === "all" || status === "approved") && role === "admin";
  const includeRejected = (status === "all" || status === "rejected") && role !== "viewer";
  const includePublished = status === "all" || status === "published";

  const draftState = useLoad(
    () => (includeDraftPipeline ? fetchDraftSignals(authorizedFetch) : Promise.resolve<AdminSignalListItem[]>([])),
    [authorizedFetch, includeDraftPipeline],
  );
  const approvedState = useLoad(
    () => (includeApproved ? fetchApprovedSignals(authorizedFetch) : Promise.resolve<AdminSignalListItem[]>([])),
    [authorizedFetch, includeApproved],
  );
  const rejectedState = useLoad(
    () => (includeRejected ? fetchRejectedSignals(authorizedFetch) : Promise.resolve<AdminSignalListItem[]>([])),
    [authorizedFetch, includeRejected],
  );
  const publishedState = useLoad(
    () =>
      includePublished
        ? fetchPublishedSignals(apiBaseUrl, { limit: 100, sort: "recent" }).then((r) => r.signals)
        : Promise.resolve([]),
    [apiBaseUrl, includePublished],
  );

  const states = [draftState, approvedState, rejectedState, publishedState].filter(
    (_, i) => [includeDraftPipeline, includeApproved, includeRejected, includePublished][i],
  );
  const anyLoading = states.some((s) => s.status === "loading");
  const firstError = states.find((s): s is Extract<LoadState<unknown>, { status: "error" }> => s.status === "error");

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    if (draftState.status === "ready") {
      for (const item of draftState.data) {
        if (status === "all" || item.status === status) out.push(fromListItem(item));
      }
    }
    if (approvedState.status === "ready") {
      for (const item of approvedState.data) out.push(fromListItem(item));
    }
    if (rejectedState.status === "ready") {
      for (const item of rejectedState.data) out.push(fromListItem(item));
    }
    if (publishedState.status === "ready") {
      for (const item of publishedState.data) {
        out.push({
          id: item.id,
          title: item.title,
          summary: item.summary,
          status: "published",
          categories: item.categories,
          dateLabel: "Published",
          dateValue: item.published_at,
        });
      }
    }
    return out;
  }, [draftState, approvedState, rejectedState, publishedState, status]);

  const availableCategories = useMemo(() => {
    const set = new Set<string>();
    for (const row of rows) for (const c of row.categories) set.add(c.category);
    return Array.from(set).sort();
  }, [rows]);

  const filtered = rows.filter((row) => {
    if (categoryFilter && !row.categories.some((c) => c.category === categoryFilter)) return false;
    if (!search.trim()) return true;
    const needle = search.trim().toLowerCase();
    return row.title.toLowerCase().includes(needle) || row.summary.toLowerCase().includes(needle);
  });

  const copy = PAGE_COPY[status];

  return (
    <div className="adm-page">
      <header className="adm-page__header">
        <h1>{copy.title}</h1>
        <p className="adm-page__subtitle">{copy.description}</p>
      </header>

      {!anyLoading && !firstError && (
        <div className="adm-list-toolbar">
          <input
            type="search"
            className="adm-input adm-list-toolbar__search"
            placeholder="Search title or summary…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label={`Search ${copy.title.toLowerCase()}`}
          />
          {availableCategories.length > 0 && (
            <select
              className="adm-input adm-list-toolbar__filter"
              value={categoryFilter}
              onChange={(event) => setCategoryFilter(event.target.value)}
              aria-label="Filter by category"
            >
              <option value="">All categories</option>
              {availableCategories.map((c) => (
                <option key={c} value={c}>
                  {categoryLabel(c)}
                </option>
              ))}
            </select>
          )}
          <span className="adm-list-toolbar__count">
            {filtered.length} signal{filtered.length === 1 ? "" : "s"}
          </span>
        </div>
      )}

      {anyLoading && <LoadingState label={`Loading ${copy.title.toLowerCase()}…`} />}
      {firstError && <ErrorState message={firstError.message} />}
      {!anyLoading && !firstError && filtered.length === 0 && (
        <EmptyState
          message={rows.length === 0 ? `No signals are currently ${status === "all" ? "in the system" : copy.title.toLowerCase()}.` : "No signals match your search."}
        />
      )}
      {!anyLoading && !firstError && filtered.length > 0 && (
        <ul className="adm-signal-card-grid">
          {filtered.map((row) => (
            <li key={`${row.status}-${row.id}`} className="adm-signal-card">
              <Link to={signalDetailPath(row.id)} className="adm-signal-card__link">
                {row.visualStatus !== undefined && (
                  <VisualPreview
                    title={row.title}
                    status={row.visualStatus}
                    url={row.visualUrl ?? null}
                    requestedAt={row.visualRequestedAt ?? null}
                  />
                )}
                <div className="adm-signal-card__body">
                  <div className="adm-signal-card__top">
                    <Badge tone={SIGNAL_STATUS_TONE[row.status]}>{SIGNAL_STATUS_LABEL[row.status]}</Badge>
                    <span className="adm-signal-card__date">
                      {row.dateLabel} {formatRelativeTime(row.dateValue)}
                    </span>
                  </div>
                  <h3 className="adm-signal-card__title">{row.title}</h3>
                  <p className="adm-signal-card__summary">{row.summary}</p>
                  {row.categories.length > 0 && (
                    <span className="adm-signal-card__categories">
                      {row.categories.map((c) => (
                        <span key={c.id} className="adm-category-chip">
                          {categoryLabel(c.category)}
                        </span>
                      ))}
                    </span>
                  )}
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
