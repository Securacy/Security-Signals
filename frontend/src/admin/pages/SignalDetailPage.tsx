import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  approveSignal,
  deleteSignalVisual,
  editSignalCategory,
  editSignalContent,
  fetchSignalDetail,
  fetchUsers,
  publishSignal,
  rejectSignal,
  submitForReview,
} from "../api/client";
import type { AdminSignalDetail, AdminUser } from "../api/types";
import { ApiError, fetchSignalDetail as fetchPublicSignalDetail } from "../../widget/api";
import type { SignalDetail as PublicSignalDetail } from "../../widget/types";
import { AI_SECURITY_SUBCATEGORIES, SECURITY_CATEGORIES } from "../../widget/types";
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
import { SafeHtml } from "../components/SafeHtml";
import { Link } from "../router";

type ActionKind = "submit" | "approve" | "reject" | "publish" | "delete-visual";

interface Feedback {
  tone: "success" | "error";
  message: string;
}

/** DRAFT/IN_REVIEW only, same gate the backend enforces (SignalService.
 * edit_signal_content/_category) - this is UX convenience, never the real
 * authorization boundary. */
function canEditContent(role: string, status: AdminSignalDetail["status"]): boolean {
  return (role === "admin" || role === "reviewer") && (status === "draft" || status === "in_review");
}

interface EditDraft {
  title: string;
  summary: string;
  security_impact: string;
  principle: string;
  recommended_action: string;
  category: string;
  subcategory: string;
}

function draftFromDetail(detail: AdminSignalDetail): EditDraft {
  const first = detail.categories[0];
  return {
    title: detail.title,
    summary: detail.summary,
    security_impact: detail.security_impact,
    principle: detail.principle,
    recommended_action: detail.recommended_action,
    category: first?.category ?? "",
    subcategory: first?.subcategory ?? "",
  };
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
    updated_at: null,
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
  const [isEditing, setIsEditing] = useState(false);
  const [editDraft, setEditDraft] = useState<EditDraft | null>(null);
  const [isSavingEdit, setIsSavingEdit] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [staleConflict, setStaleConflict] = useState(false);

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
      } else if (pendingAction === "publish") {
        await publishSignal(authorizedFetch, signalId);
        setFeedback({ tone: "success", message: `"${title}" was published.` });
      } else {
        await deleteSignalVisual(authorizedFetch, signalId);
        setFeedback({ tone: "success", message: `The visual for "${title}" was deleted.` });
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

  function startEditing() {
    if (detailState.status !== "ready") return;
    setEditDraft(draftFromDetail(detailState.data));
    setEditError(null);
    setStaleConflict(false);
    setFeedback(null);
    setIsEditing(true);
  }

  function cancelEditing() {
    if (isSavingEdit) return;
    setIsEditing(false);
    setEditDraft(null);
    setEditError(null);
    setStaleConflict(false);
  }

  async function saveEdits() {
    if (!editDraft || detailState.status !== "ready") return;
    const original = detailState.data;
    setIsSavingEdit(true);
    setEditError(null);
    setStaleConflict(false);

    const contentFields: (keyof Omit<EditDraft, "category" | "subcategory">)[] = [
      "title", "summary", "security_impact", "principle", "recommended_action",
    ];
    const contentUpdates: Record<string, string> = {};
    for (const field of contentFields) {
      if (editDraft[field] !== original[field]) contentUpdates[field] = editDraft[field];
    }
    const originalCategory = original.categories[0];
    const categoryChanged =
      editDraft.category !== (originalCategory?.category ?? "") ||
      editDraft.subcategory !== (originalCategory?.subcategory ?? "");

    try {
      if (Object.keys(contentUpdates).length > 0) {
        await editSignalContent(authorizedFetch, signalId, {
          ...contentUpdates,
          expected_updated_at: original.updated_at,
        });
      }
      if (categoryChanged && editDraft.category) {
        await editSignalCategory(authorizedFetch, signalId, {
          category: editDraft.category,
          subcategory: editDraft.category === "ai_security" ? editDraft.subcategory || undefined : undefined,
          expected_updated_at: original.updated_at,
        });
      }
      setFeedback({ tone: "success", message: `"${editDraft.title}" was updated.` });
      setIsEditing(false);
      setEditDraft(null);
      setReloadToken((n) => n + 1);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setStaleConflict(true);
        setEditError("This signal was changed by someone else since you loaded it. Reload to see the latest version.");
      } else {
        setEditError(err instanceof ApiError ? err.message : "That edit could not be saved. Please try again.");
      }
    } finally {
      setIsSavingEdit(false);
    }
  }

  function reloadAfterConflict() {
    setIsEditing(false);
    setEditDraft(null);
    setEditError(null);
    setStaleConflict(false);
    setReloadToken((n) => n + 1);
  }

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
                {!isEditing &&
                  detailState.data.categories.map((c) => (
                    <Badge key={c.id} tone="neutral">
                      {categoryLabel(c.category)}
                      {c.subcategory ? ` · ${c.subcategory}` : ""}
                    </Badge>
                  ))}
              </div>
              {isEditing && editDraft ? (
                <input
                  className="adm-input adm-detail-page__title-input"
                  value={editDraft.title}
                  onChange={(event) => setEditDraft({ ...editDraft, title: event.target.value })}
                  aria-label="Title"
                  maxLength={500}
                />
              ) : (
                <h1>{detailState.data.title}</h1>
              )}
            </div>
            {isEditing ? (
              <div className="adm-detail-page__actions">
                <Button variant="secondary" disabled={isSavingEdit} onClick={cancelEditing}>
                  Cancel
                </Button>
                <Button variant="primary" disabled={isSavingEdit} onClick={saveEdits}>
                  {isSavingEdit ? "Saving…" : "Save changes"}
                </Button>
              </div>
            ) : (
              <div className="adm-detail-page__actions">
                {canEditContent(role, detailState.data.status) && (
                  <Button variant="secondary" onClick={startEditing}>
                    Edit
                  </Button>
                )}
                <DetailActions
                  detail={detailState.data}
                  isAdmin={isAdmin}
                  busy={isSubmittingAction}
                  onAction={openAction}
                />
              </div>
            )}
          </header>

          {editError && (
            <div className="adm-banner adm-banner--error" role="alert">
              <span>{editError}</span>
              {staleConflict ? (
                <Button variant="secondary" onClick={reloadAfterConflict}>
                  Reload
                </Button>
              ) : (
                <button type="button" className="adm-banner__dismiss" onClick={() => setEditError(null)} aria-label="Dismiss">
                  &times;
                </button>
              )}
            </div>
          )}

          <div className="adm-detail-page__layout">
            <div className="adm-detail-page__main">
              <VisualPreview
                title={detailState.data.title}
                status={detailState.data.visual_status}
                url={detailState.data.visual_url}
                requestedAt={detailState.data.visual_requested_at}
              />
              {!isEditing && detailState.data.visual_status === "generated" && (
                <div className="adm-detail-page__visual-actions">
                  <Button variant="danger" onClick={() => openAction("delete-visual")}>
                    Delete visual
                  </Button>
                </div>
              )}

              {isEditing && editDraft && (
                <section className="adm-detail-section">
                  <h2 className="adm-detail-section__heading">Category</h2>
                  <div className="adm-edit-category-row">
                    <select
                      className="adm-input"
                      aria-label="Category"
                      value={editDraft.category}
                      onChange={(event) =>
                        setEditDraft({ ...editDraft, category: event.target.value, subcategory: "" })
                      }
                    >
                      <option value="" disabled>
                        Select a category…
                      </option>
                      {SECURITY_CATEGORIES.map((c) => (
                        <option key={c} value={c}>
                          {categoryLabel(c)}
                        </option>
                      ))}
                    </select>
                    {editDraft.category === "ai_security" && (
                      <select
                        className="adm-input"
                        aria-label="Subcategory"
                        value={editDraft.subcategory}
                        onChange={(event) => setEditDraft({ ...editDraft, subcategory: event.target.value })}
                      >
                        <option value="" disabled>
                          Select a subcategory…
                        </option>
                        {AI_SECURITY_SUBCATEGORIES.map((sc) => (
                          <option key={sc} value={sc}>
                            {sc.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </section>
              )}

              {isEditing && editDraft ? (
                <EditableSection
                  heading="Security event"
                  hint="What happened"
                  value={editDraft.summary}
                  onChange={(value) => setEditDraft({ ...editDraft, summary: value })}
                />
              ) : (
                <DetailSection heading="Security event" hint="What happened">
                  {detailState.data.summary}
                </DetailSection>
              )}
              {isEditing && editDraft ? (
                <EditableSection
                  heading="Why it matters"
                  hint="Security impact"
                  value={editDraft.security_impact}
                  onChange={(value) => setEditDraft({ ...editDraft, security_impact: value })}
                />
              ) : (
                <DetailSection heading="Why it matters" hint="Security impact">
                  {detailState.data.security_impact}
                </DetailSection>
              )}
              {isEditing && editDraft ? (
                <EditableSection
                  heading="Secure design principle"
                  value={editDraft.principle}
                  onChange={(value) => setEditDraft({ ...editDraft, principle: value })}
                />
              ) : (
                <DetailSection heading="Secure design principle">{detailState.data.principle}</DetailSection>
              )}
              {isEditing && editDraft ? (
                <EditableSection
                  heading="Recommended action"
                  value={editDraft.recommended_action}
                  onChange={(value) => setEditDraft({ ...editDraft, recommended_action: value })}
                />
              ) : (
                <DetailSection heading="Recommended action">{detailState.data.recommended_action}</DetailSection>
              )}

              <section className="adm-detail-section">
                <h2 className="adm-detail-section__heading">Evidence &amp; sources</h2>
                {detailState.data.evidence.length === 0 ? (
                  <p className="adm-detail-section__body adm-detail-section__body--muted">No evidence recorded.</p>
                ) : (
                  <ul className="adm-evidence-list">
                    {detailState.data.evidence.map((item) => {
                      const safeLink = isSafeExternalUrl(item.source_url);
                      return (
                        <li key={item.id} className="adm-evidence-list__item">
                          <div className="adm-evidence-list__top">
                            {safeLink ? (
                              <a
                                className="adm-evidence-list__title"
                                href={item.source_url}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                {item.source_title}
                              </a>
                            ) : (
                              <span className="adm-evidence-list__title">{item.source_title}</span>
                            )}
                            {item.created_at && (
                              <span className="adm-evidence-list__date">{formatRelativeTime(item.created_at)}</span>
                            )}
                          </div>
                          {item.excerpt && <SafeHtml className="adm-evidence-list__excerpt" html={item.excerpt} />}
                          {safeLink && (
                            <a
                              className="adm-evidence-list__view-link"
                              href={item.source_url}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              View article →
                            </a>
                          )}
                        </li>
                      );
                    })}
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
        tone={pendingAction === "reject" || pendingAction === "delete-visual" ? "danger" : "primary"}
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
  // No wrapping div here - the caller already provides one
  // .adm-detail-page__actions row shared with the "Edit" button, so this
  // never doubles up a nested flex container.
  if (detail.status === "draft") {
    return (
      <Button variant="primary" disabled={busy} onClick={() => onAction("submit")}>
        Submit for approval
      </Button>
    );
  }
  if (detail.status === "in_review") {
    return (
      <>
        <Button variant="primary" disabled={busy} onClick={() => onAction("approve")}>
          Approve
        </Button>
        <Button variant="danger" disabled={busy} onClick={() => onAction("reject")}>
          Reject
        </Button>
      </>
    );
  }
  if (detail.status === "approved" && isAdmin) {
    return (
      <Button variant="primary" disabled={busy} onClick={() => onAction("publish")}>
        Publish
      </Button>
    );
  }
  return null;
}

function EditableSection({
  heading,
  hint,
  value,
  onChange,
}: {
  heading: string;
  hint?: string;
  value: string;
  onChange: (value: string) => void;
}) {
  const fieldId = `adm-edit-${heading.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <section className="adm-detail-section">
      <h2 className="adm-detail-section__heading">
        <label htmlFor={fieldId}>
          {heading}
          {hint && <span className="adm-detail-section__hint"> · {hint}</span>}
        </label>
      </h2>
      <textarea
        id={fieldId}
        className="adm-input adm-textarea adm-detail-section__edit-textarea"
        rows={4}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </section>
  );
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
    case "delete-visual":
      return "Delete this visual?";
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
    case "delete-visual":
      return "This removes the current signal visual. It will not automatically regenerate.";
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
    case "delete-visual":
      return "Delete visual";
  }
}
