import { useMemo, useState, type FormEvent } from "react";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  fetchApprovedSignals,
  fetchAuditEntries,
  fetchDraftSignals,
  fetchRejectedSignals,
  fetchUsers,
} from "../api/client";
import { fetchPublishedSignals } from "../../widget/api";
import { auditActionTone } from "../auditActionTone";
import { describeAuditEntry } from "../auditDescribe";
import { useLoad } from "../useLoad";
import { AuditActionIcon } from "../components/AuditActionIcon";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";
import { getAdminConfig } from "../config";

const PAGE_SIZE = 50;

interface Filters {
  resourceType: string;
  action: string;
  userId: string;
}

const EMPTY_FILTERS: Filters = { resourceType: "", action: "", userId: "" };

function formatTimestamp(iso: string | null): string {
  if (!iso) return "Unknown time";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/**
 * ADMIN-only, read-only view of the real append-only audit_log table (GET
 * /api/v1/audit) - no writes happen anywhere on this page. Filters map
 * directly to the backend's own query params (resource_type, action,
 * user_id) - no client-side search over fields the API doesn't support.
 *
 * Each entry is rendered as a short, human-readable description (see
 * auditDescribe.ts) rather than a raw action code - the actor/target/
 * signal names are resolved best-effort from the admin's own user and
 * signal lists (this page's role is already admin-only, so every signal
 * status list is reachable). The raw `changes` JSON stays available behind
 * an expandable "View raw details" for anyone who wants the exact
 * before/after payload the backend recorded.
 */
export function AuditLogPage() {
  const authorizedFetch = useAuthorizedFetch();
  const { apiBaseUrl } = getAdminConfig();

  const [limit, setLimit] = useState(PAGE_SIZE);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [draft, setDraft] = useState<Filters>(EMPTY_FILTERS);

  const auditState = useLoad(
    () =>
      fetchAuditEntries(authorizedFetch, {
        limit,
        resource_type: filters.resourceType || undefined,
        action: filters.action || undefined,
        user_id: filters.userId || undefined,
      }),
    [authorizedFetch, limit, filters.resourceType, filters.action, filters.userId],
  );

  // Best-effort name resolution: three independent loads so a failure in
  // any one of them never breaks the audit list itself - entries just fall
  // back to a short id or the raw changes payload.
  const usersState = useLoad(() => fetchUsers(authorizedFetch, { limit: 200 }), [authorizedFetch]);
  const usernameById = useMemo(() => {
    const map = new Map<string, string>();
    if (usersState.status === "ready") {
      for (const user of usersState.data) map.set(user.id, user.username);
    }
    return map;
  }, [usersState]);

  const signalTitlesState = useLoad(
    () =>
      Promise.allSettled([
        fetchDraftSignals(authorizedFetch),
        fetchApprovedSignals(authorizedFetch),
        fetchRejectedSignals(authorizedFetch),
        fetchPublishedSignals(apiBaseUrl, { limit: 500, sort: "recent" }).then((r) => r.signals),
      ]),
    [authorizedFetch, apiBaseUrl],
  );
  const signalTitleById = useMemo(() => {
    const map = new Map<string, string>();
    if (signalTitlesState.status === "ready") {
      for (const result of signalTitlesState.data) {
        if (result.status !== "fulfilled") continue;
        for (const signal of result.value) map.set(signal.id, signal.title);
      }
    }
    return map;
  }, [signalTitlesState]);

  const suggestions = useMemo(() => {
    const resourceTypes = new Set<string>();
    const actions = new Set<string>();
    if (auditState.status === "ready") {
      for (const entry of auditState.data) {
        resourceTypes.add(entry.resource_type);
        actions.add(entry.action);
      }
    }
    return { resourceTypes: Array.from(resourceTypes), actions: Array.from(actions) };
  }, [auditState]);

  const hasMore = auditState.status === "ready" && auditState.data.length === limit;

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    setLimit(PAGE_SIZE);
    setFilters(draft);
  }

  function clearFilters() {
    setDraft(EMPTY_FILTERS);
    setFilters(EMPTY_FILTERS);
    setLimit(PAGE_SIZE);
  }

  const hasActiveFilters = filters.resourceType !== "" || filters.action !== "" || filters.userId !== "";

  return (
    <div className="adm-page">
      <header className="adm-page__header">
        <h1>Audit Logs</h1>
        <p className="adm-page__subtitle">A human-readable, append-only record of admin and review actions</p>
      </header>

      <Card title="Filters">
        <form className="adm-filter-form" onSubmit={applyFilters}>
          <div className="adm-filter-form__row">
            <div className="adm-field">
              <label htmlFor="adm-filter-resource-type" className="adm-field__label">
                Resource type
              </label>
              <input
                id="adm-filter-resource-type"
                className="adm-input"
                list="adm-resource-type-options"
                value={draft.resourceType}
                onChange={(event) => setDraft((d) => ({ ...d, resourceType: event.target.value }))}
                placeholder="e.g. SIGNAL"
              />
              <datalist id="adm-resource-type-options">
                {suggestions.resourceTypes.map((value) => (
                  <option key={value} value={value} />
                ))}
              </datalist>
            </div>
            <div className="adm-field">
              <label htmlFor="adm-filter-action" className="adm-field__label">
                Action
              </label>
              <input
                id="adm-filter-action"
                className="adm-input"
                list="adm-action-options"
                value={draft.action}
                onChange={(event) => setDraft((d) => ({ ...d, action: event.target.value }))}
                placeholder="e.g. SIGNAL_APPROVED"
              />
              <datalist id="adm-action-options">
                {suggestions.actions.map((value) => (
                  <option key={value} value={value} />
                ))}
              </datalist>
            </div>
            <div className="adm-field">
              <label htmlFor="adm-filter-user-id" className="adm-field__label">
                Actor user ID
              </label>
              <input
                id="adm-filter-user-id"
                className="adm-input"
                value={draft.userId}
                onChange={(event) => setDraft((d) => ({ ...d, userId: event.target.value }))}
                placeholder="UUID"
              />
            </div>
          </div>
          <div className="adm-filter-form__actions">
            <Button type="submit" variant="primary">
              Apply filters
            </Button>
            {hasActiveFilters && (
              <Button type="button" variant="ghost" onClick={clearFilters}>
                Clear filters
              </Button>
            )}
          </div>
        </form>
      </Card>

      <Card title="Entries">
        {auditState.status === "loading" && <LoadingState label="Loading audit entries…" />}
        {auditState.status === "error" && <ErrorState message={auditState.message} />}
        {auditState.status === "ready" && auditState.data.length === 0 && (
          <EmptyState
            message={hasActiveFilters ? "No audit entries match these filters." : "No audit entries have been recorded yet."}
          />
        )}
        {auditState.status === "ready" && auditState.data.length > 0 && (
          <>
            <ul className="adm-audit-list">
              {auditState.data.map((entry) => {
                const actorName = entry.user_id ? (usernameById.get(entry.user_id) ?? "Unknown user") : "System";
                const targetUserName =
                  entry.resource_type.toUpperCase() === "USER" ? (usernameById.get(entry.resource_id) ?? null) : null;
                const signalTitle =
                  entry.resource_type.toUpperCase() === "SIGNAL" ? (signalTitleById.get(entry.resource_id) ?? null) : null;
                const description = describeAuditEntry(entry, actorName, signalTitle, targetUserName);
                const tone = auditActionTone(entry.action);

                return (
                  <li key={entry.id} className="adm-audit-row">
                    <span className={`adm-audit-row__icon adm-audit-row__icon--${tone}`} aria-hidden="true">
                      <AuditActionIcon action={entry.action} />
                    </span>
                    <div className="adm-audit-row__main">
                      <div className="adm-audit-row__title-line">
                        <Badge tone={tone}>{description.title}</Badge>
                      </div>
                      <dl className="adm-audit-row__facts">
                        {description.lines.map((line) => (
                          <div key={line.label} className="adm-audit-row__fact">
                            <dt>{line.label}</dt>
                            <dd>{line.value}</dd>
                          </div>
                        ))}
                      </dl>
                      {entry.changes && Object.keys(entry.changes).length > 0 && (
                        <details className="adm-audit-row__details">
                          <summary>View raw details</summary>
                          <dl className="adm-audit-row__changes">
                            {Object.entries(entry.changes).map(([key, value]) => (
                              <div key={key} className="adm-audit-row__change">
                                <dt>{key}</dt>
                                <dd>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
                              </div>
                            ))}
                          </dl>
                        </details>
                      )}
                    </div>
                    <time className="adm-audit-row__timestamp" dateTime={entry.timestamp ?? undefined}>
                      {formatTimestamp(entry.timestamp)}
                    </time>
                  </li>
                );
              })}
            </ul>
            {hasMore && (
              <div className="adm-load-more">
                <Button variant="secondary" onClick={() => setLimit((n) => n + PAGE_SIZE)}>
                  Load more
                </Button>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
