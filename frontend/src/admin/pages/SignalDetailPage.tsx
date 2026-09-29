import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  approveSignal,
  fetchSignalDetail,
  fetchUsers,
  publishSignal,
  rejectSignal,
  submitForReview,
} from "../api/client";
import type { AdminSignalDetail, AdminUser } from "../api/types";
import { ApiError, fetchSignalDetail as fetchPublicSignalDetail } from "../../widget/api";
import type { SignalDetail as PublicSignalDetail } from "../../widget/types";
import { isSafeExternalUrl } from "../../widget/safeUrl";
import { getAdminConfig } from "../config";
import { categoryLabel } from "../../widget/categoryLabels";
import { formatRelativeTime } from "../../widget/formatRelativeTime";
import { SIGNAL_STATUS_LABEL, SIGNAL_STATUS_TONE } from "../signalStatus";
import { useLoad } from "../useLoad";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";
import { VisualPreview } from "../components/VisualPreview";
import { Link } from "../router";

type ActionKind = "submit" | "approve" | "reject" | "publish";

interface Feedback {
  tone: "success" | "error";
  message: string;
}

/** GET /api/v1/signals/{id} (used below) requires REVIEWER/ADMIN - a
 * VIEWER has no protected signal visibility at all, only the public
 * /signals/published endpoints (same boundary list_draft_signals'
 * docstring documents). Adapts the narrower public SignalDetail shape into
 * AdminSignalDetail so the rest of this page renders identically either
 * way; the review-only fields (reviewed_by/reviewed_at/created_at) simply
 * have nothing to show a viewer, who has no access to that information
 * regardless of this page. Status is always "published" here - the public
 * endpoint 404s for anything else. */
function fromPublicDetail(detail: PublicSignalDetail): AdminSignalDetail {
  return {
    id: detail.id,
    title: detail.title,
    status: "published",
    summary: detail.summary,
    security_impact: detail.security_impact,
    principle: detail.principle,
    recommended_action: detail.recommended_action,
    created_at: null,
    reviewed_by: null,
    reviewed_at: null,
    published_at: detail.published_at,
    categories: detail.categories,
    public_categories: detail.public_categories,
    evidence: detail.evidence,
    visual_status: detail.visual_status,
    visual_url: detail.visual_url,
    visual_requested_at: null,
  };
}

/**
 * Full-page signal detail workspace - the primary way to view a signal and
 * (for REVIEWER/ADMIN) act on it. Replaces the earlier modal dialog: with
 * real routing available, a dedicated route is a first-class view rather
 * than something that only exists layered over a list. Every review
 * action still goes through the backend's require_reviewer/require_admin
 * dependencies unchanged - this page only decides what to show and ask
 * confirmation for.
 */
export function SignalDetailPage({ signalId }: { signalId: string }) {
  const { user } = useAuth();
  const role = user!.role;
  const isAdmin = role === "admin";
  const isViewer = role === "viewer";
  const authorizedFetch = useAuthorizedFetch();
  const { apiBaseUrl } = getAdminConfig();

  const [reloadToken, setReloadToken] = useState(0);
  const [pendingAction, setPendingAction] = useState<ActionKind | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [isSubmittingAction, setIsSubmittingAction] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const detailState = useLoad(
    () =>
      isViewer
        ? fetchPublicSignalDetail(apiBaseUrl, signalId).then(fromPublicDetail)
        : fetchSignalDetail(authorizedFetch, signalId),
    [authorizedFetch, apiBaseUrl, isViewer, signalId, reloadToken],
  );

  // Best-effort reviewer-name resolution - ADMIN only endpoint, so a
  // REVIEWER simply sees the raw ID fallback. A failure here never blocks
  // the signal content itself.
  const usersState = useLoad(
    () => (isAdmin ? fetchUsers(authorizedFetch, { limit: 200 }) : Promise.resolve<AdminUser[]>([])),
    [authorizedFetch, isAdmin],
  );
  const usernameById = new Map(usersState.status === "ready" ? usersState.data.map((u) => [u.id, u.username]) : []);

  function openAction(kind: ActionKind) {
    setFeedback(null);
    setActionError(null);
    setRejectReason("");
    setPendingAction(kind);
  }

  function closeAction() {
    if (isSubmittingAction) return;
    setPendingAction(null);
    setRejectReason("");
    setActionError(null);
  }

  async function confirmAction() {
    if (!pendingAction || detailState.status !== "ready") return;
    const title = detailState.data.title;
    setIsSubmittingAction(true);
    setActionError(null);
    try {
      if (pendingAction === "submit") {
        await submitForReview(authorizedFetch, signalId);
        setFeedback({ tone: "success", message: `"${title}" was submitted for approval.` });
      } else if (pendingAction === "approve") {
        await approveSignal(authorizedFetch, signalId);
        setFeedback({ tone: "success", message: `"${title}" was approved.` });
      } else if (pendingAction === "reject") {
        await rejectSignal(authorizedFetch, signalId, rejectReason.trim());
        setFeedback({ tone: "success", message: `"${title}" was rejected.` });
      } else {
        await publishSignal(authorizedFetch, signalId);
        setFeedback({ tone: "success", message: `"${title}" was published.` });
      }
      setPendingAction(null);
      setRejectReason("");
      setReloadToken((n) => n + 1);
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "That action failed. Please try again.");
    } finally {
      setIsSubmittingAction(false);
    }
  }

  const reasonTooShort = pendingAction === "reject" && rejectReason.trim().length === 0;

  return (
    <div className="adm-page adm-detail-page">
      <Link to="/admin/signals" className="adm-detail-page__back">
        ← Back to signals
      </Link>

      {feedback && (
        <div className={`adm-banner adm-banner--${feedback.tone}`} role="status">
          <span>{feedback.message}</span>
          <button type="button" className="adm-banner__dismiss" onClick={() => setFeedback(null)} aria-label="Dismiss">
            &times;
          </button>
        </div>
      )}

      {detailState.status === "loading" && <LoadingState label="Loading signal…" />}
      {detailState.status === "error" && <ErrorState message={detailState.message} />}

      {detailState.status === "ready" && (
        <>
          <header className="adm-detail-page__header">
            <div className="adm-detail-page__header-main">
              <div className="adm-detail-page__meta-line">
                <Badge tone={SIGNAL_STATUS_TONE[detailState.data.status]}>{SIGNAL_STATUS_LABEL[detailState.data.status]}</Badge>
                {detailState.data.categories.map((c) => (
                  <Badge key={c.id} tone="neutral">
                    {categoryLabel(c.category)}
                    {c.subcategory ? ` · ${c.subcategory}` : ""}
                  </Badge>
                ))}
              </div>
              <h1>{detailState.data.title}</h1>
            </div>
            <DetailActions
              detail={detailState.data}
              isAdmin={isAdmin}
              busy={isSubmittingAction}
              onAction={openAction}
            />
          </header>

          <div className="adm-detail-page__layout">
            <div className="adm-detail-page__main">
              <VisualPreview
                title={detailState.data.title}
                status={detailState.data.visual_status}
                url={detailState.data.visual_url}
                requestedAt={detailState.data.visual_requested_at}
              />

              <DetailSection heading="Security event" hint="What happened">
                {detailState.data.summary}
              </DetailSection>
              <DetailSection heading="Why it matters" hint="Security impact">
                {detailState.data.security_impact}
              </DetailSection>
              <DetailSection heading="Secure design principle">{detailState.data.principle}</DetailSection>
              <DetailSection heading="Recommended action">{detailState.data.recommended_action}</DetailSection>

              <section className="adm-detail-section">
                <h2 className="adm-detail-section__heading">Evidence &amp; sources</h2>
                {detailState.data.evidence.length === 0 ? (
                  <p className="adm-detail-section__body adm-detail-section__body--muted">No evidence recorded.</p>
                ) : (
                  <ul className="adm-evidence-list">
                    {detailState.data.evidence.map((item) => (
                      <li key={item.id} className="adm-evidence-list__item">
                        {isSafeExternalUrl(item.source_url) ? (
                          <a href={item.source_url} target="_blank" rel="noopener noreferrer">
                            {item.source_title}
                          </a>
                        ) : (
                          <span>{item.source_title}</span>
                        )}
                        {item.excerpt && <p className="adm-evidence-list__excerpt">{item.excerpt}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </div>

            <aside className="adm-detail-page__sidebar">
              <section className="adm-detail-section adm-detail-section--panel">
                <h2 className="adm-detail-section__heading">{isViewer ? "Signal information" : "Review information"}</h2>
                <dl className="adm-detail-page__facts">
                  <div>
                    <dt>Status</dt>
                    <dd>{SIGNAL_STATUS_LABEL[detailState.data.status]}</dd>
                  </div>
                  {detailState.data.created_at && (
                    <div>
                      <dt>Created</dt>
                      <dd>{formatRelativeTime(detailState.data.created_at)}</dd>
                    </div>
                  )}
                  {detailState.data.reviewed_by && (
                    <div>
                      <dt>Reviewed by</dt>
                      <dd>{usernameById.get(detailState.data.reviewed_by) ?? `${detailState.data.reviewed_by.slice(0, 8)}…`}</dd>
                    </div>
                  )}
                  {detailState.data.reviewed_at && (
                    <div>
                      <dt>Reviewed</dt>
                      <dd>{formatRelativeTime(detailState.data.reviewed_at)}</dd>
                    </div>
                  )}
                  {detailState.data.published_at && (
                    <div>
                      <dt>Published</dt>
                      <dd>{formatRelativeTime(detailState.data.published_at)}</dd>
                    </div>
                  )}
                </dl>
              </section>
            </aside>
          </div>
        </>
      )}

      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction ? dialogTitle(pendingAction) : ""}
        description={
          pendingAction && detailState.status === "ready" ? dialogDescription(pendingAction, detailState.data.title) : undefined
        }
        confirmLabel={pendingAction ? dialogConfirmLabel(pendingAction) : "Confirm"}
        tone={pendingAction === "reject" ? "danger" : "primary"}
        onConfirm={confirmAction}
        onCancel={closeAction}
        confirmDisabled={isSubmittingAction || reasonTooShort}
      >
        {pendingAction === "reject" && (
          <div className="adm-field">
            <label htmlFor="adm-reject-reason" className="adm-field__label">
              Reason for rejection
            </label>
            <textarea
              id="adm-reject-reason"
              className="adm-input adm-textarea"
              rows={3}
              value={rejectReason}
              onChange={(event) => setRejectReason(event.target.value)}
              required
            />
          </div>
        )}
        {actionError && (
          <p role="alert" className="adm-form-error">
            {actionError}
          </p>
        )}
      </ConfirmDialog>
    </div>
  );
}

function DetailActions({
  detail,
  isAdmin,
  busy,
  onAction,
}: {
  detail: AdminSignalDetail;
  isAdmin: boolean;
  busy: boolean;
  onAction: (kind: ActionKind) => void;
}) {
  if (detail.status === "draft") {
    return (
      <div className="adm-detail-page__actions">
        <Button variant="primary" disabled={busy} onClick={() => onAction("submit")}>
          Submit for approval
        </Button>
      </div>
    );
  }
  if (detail.status === "in_review") {
    return (
      <div className="adm-detail-page__actions">
        <Button variant="primary" disabled={busy} onClick={() => onAction("approve")}>
          Approve
        </Button>
        <Button variant="danger" disabled={busy} onClick={() => onAction("reject")}>
          Reject
        </Button>
      </div>
    );
  }
  if (detail.status === "approved" && isAdmin) {
    return (
      <div className="adm-detail-page__actions">
        <Button variant="primary" disabled={busy} onClick={() => onAction("publish")}>
          Publish
        </Button>
      </div>
    );
  }
  return null;
}

function DetailSection({ heading, hint, children }: { heading: string; hint?: string; children: string }) {
  return (
    <section className="adm-detail-section">
      <h2 className="adm-detail-section__heading">
        {heading}
        {hint && <span className="adm-detail-section__hint"> · {hint}</span>}
      </h2>
      <p className="adm-detail-section__body">{children}</p>
    </section>
  );
}

function dialogTitle(kind: ActionKind): string {
  switch (kind) {
    case "submit":
      return "Submit for approval?";
    case "approve":
      return "Approve this signal?";
    case "reject":
      return "Reject this signal?";
    case "publish":
      return "Publish this signal?";
  }
}

function dialogDescription(kind: ActionKind, title: string): string {
  switch (kind) {
    case "submit":
      return `"${title}" will move to Waiting for Approval.`;
    case "approve":
      return `"${title}" will be approved and move to Ready to Publish.`;
    case "reject":
      return `"${title}" will be rejected. This cannot be undone.`;
    case "publish":
      return `"${title}" will be published and become publicly visible. This cannot be undone.`;
  }
}

function dialogConfirmLabel(kind: ActionKind): string {
  switch (kind) {
    case "submit":
      return "Submit";
    case "approve":
      return "Approve";
    case "reject":
      return "Reject";
    case "publish":
      return "Publish";
  }
}
