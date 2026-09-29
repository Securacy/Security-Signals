import { useState } from "react";
import { resolveMediaUrl } from "../../widget/api";
import { getAdminConfig } from "../config";
import type { AdminVisualStatus } from "../api/types";

/** A PENDING visual normally resolves within a few minutes; one still
 * pending well past that means its generation job died (mirrors the
 * backend's PENDING_STALLED_AFTER_MINUTES) - shown honestly rather than
 * "generating" forever. */
const STALLED_AFTER_MS = 15 * 60 * 1000;

interface VisualPreviewProps {
  title: string;
  status: AdminVisualStatus;
  url: string | null;
  requestedAt: string | null;
}

/**
 * Reviewer-facing view of a signal's OWN generated visual - never a
 * category icon or stock image standing in for a missing one. Exactly one
 * of: the persisted image, "Visual generating…", or a clear "Visual
 * unavailable" state.
 */
export function VisualPreview({ title, status, url, requestedAt }: VisualPreviewProps) {
  const [loadFailed, setLoadFailed] = useState(false);
  const { apiBaseUrl } = getAdminConfig();

  // Only ever render a backend-relative media path this backend generated.
  const isSafePath = url !== null && url.startsWith("/") && !url.startsWith("//");

  if (status === "generated" && isSafePath && !loadFailed) {
    return (
      <div className="adm-visual" data-state="image">
        <img
          className="adm-visual__image"
          src={resolveMediaUrl(apiBaseUrl, url)}
          alt={`Generated illustration for ${title}`}
          loading="lazy"
          onError={() => setLoadFailed(true)}
        />
      </div>
    );
  }

  if (status === "pending") {
    const requested = requestedAt ? new Date(requestedAt).getTime() : NaN;
    const stalled = Number.isFinite(requested) && Date.now() - requested > STALLED_AFTER_MS;
    if (!stalled) {
      return (
        <div className="adm-visual adm-visual--note" data-state="generating" role="status">
          <span className="adm-spinner" aria-hidden="true" />
          <span>Visual generating…</span>
        </div>
      );
    }
    return (
      <div className="adm-visual adm-visual--note" data-state="unavailable">
        <span>Visual unavailable</span>
        <span className="adm-visual__hint">Generation did not finish. An operator can retry it with regenerate_visuals.py.</span>
      </div>
    );
  }

  if (status === "failed" || (status === "generated" && (loadFailed || !isSafePath))) {
    return (
      <div className="adm-visual adm-visual--note" data-state="unavailable">
        <span>Visual unavailable</span>
        <span className="adm-visual__hint">An operator can retry failed visuals with regenerate_visuals.py.</span>
      </div>
    );
  }

  return (
    <div className="adm-visual adm-visual--note" data-state="none">
      <span>No visual has been generated for this signal.</span>
    </div>
  );
}
