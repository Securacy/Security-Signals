import { useAuthorizedFetch } from "../auth/apiClient";
import { fetchInternalAnalytics } from "../api/client";
import { SIGNAL_STATUS_LABEL, SIGNAL_STATUS_TONE } from "../signalStatus";
import type { AdminSignalStatus } from "../api/types";
import { useLoad } from "../useLoad";
import { Card } from "../components/Card";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";

const STATUS_ORDER: AdminSignalStatus[] = ["draft", "in_review", "approved", "published", "rejected"];

/**
 * Real pipeline analytics - REVIEWER/ADMIN only, backed entirely by the
 * existing GET /api/v1/analytics/internal (Phase 5), never a fabricated
 * number. Monthly volume as horizontal bars (no charting library - the
 * data is simple enough that hand-rolled bars stay accurate and light).
 */
export function AnalyticsPage() {
  const authorizedFetch = useAuthorizedFetch();
  const analyticsState = useLoad(() => fetchInternalAnalytics(authorizedFetch, 12), [authorizedFetch]);

  return (
    <div className="adm-page">
      <header className="adm-page__header">
        <h1>Analytics</h1>
        <p className="adm-page__subtitle">Signal volume and pipeline distribution over the last 12 months</p>
      </header>

      {analyticsState.status === "loading" && <LoadingState label="Loading analytics…" />}
      {analyticsState.status === "error" && <ErrorState message={analyticsState.message} />}
      {analyticsState.status === "ready" && (
        <div className="adm-dashboard-grid">
          <Card title="Monthly volume">
            {analyticsState.data.total_signals === 0 ? (
              <EmptyState message="No signals have been created yet." />
            ) : (
              <MonthlyBars months={analyticsState.data.monthly_counts} />
            )}
          </Card>

          <Card title="Status distribution">
            {analyticsState.data.total_signals === 0 ? (
              <EmptyState message="No signals to break down yet." />
            ) : (
              <StatusBars totals={analyticsState.data.status_totals} total={analyticsState.data.total_signals} />
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

function MonthlyBars({ months }: { months: { month: string; count: number }[] }) {
  const max = Math.max(1, ...months.map((m) => m.count));
  return (
    <ul className="adm-bar-list">
      {months.map((m) => (
        <li key={m.month} className="adm-bar-list__row">
          <span className="adm-bar-list__label">{formatMonth(m.month)}</span>
          <span className="adm-bar-list__track">
            <span className="adm-bar-list__fill" style={{ width: `${(m.count / max) * 100}%` }} />
          </span>
          <span className="adm-bar-list__value">{m.count}</span>
        </li>
      ))}
    </ul>
  );
}

function StatusBars({ totals, total }: { totals: Partial<Record<AdminSignalStatus, number>>; total: number }) {
  return (
    <ul className="adm-bar-list">
      {STATUS_ORDER.map((status) => {
        const count = totals[status] ?? 0;
        return (
          <li key={status} className="adm-bar-list__row">
            <span className="adm-bar-list__label">{SIGNAL_STATUS_LABEL[status]}</span>
            <span className="adm-bar-list__track">
              <span
                className={`adm-bar-list__fill adm-bar-list__fill--${SIGNAL_STATUS_TONE[status]}`}
                style={{ width: `${total > 0 ? (count / total) * 100 : 0}%` }}
              />
            </span>
            <span className="adm-bar-list__value">{count}</span>
          </li>
        );
      })}
    </ul>
  );
}

function formatMonth(key: string): string {
  const [year, month] = key.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, 1)).toLocaleDateString(undefined, { month: "short", year: "2-digit", timeZone: "UTC" });
}
