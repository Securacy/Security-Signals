import DOMPurify, { type Config } from "dompurify";
import { isSafeExternalUrl } from "../widget/safeUrl";

/**
 * Evidence.excerpt is AI-ingested bulletin/news text that the backend
 * stores verbatim, including embedded formatting markup (e.g.
 * "<p><b>Bulletin ID:</b> ... <br /> <a href=\"...\">View article</a></p>").
 * It is untrusted at this rendering boundary regardless of having passed
 * through our own backend/AI pipeline - never assume "came from our API"
 * means "safe to parse as HTML."
 *
 * This allowlists a minimal set of formatting tags/attributes (never a
 * blocklist - DOMPurify drops everything not explicitly allowed, which is
 * what actually keeps <script>/<iframe>/<object>/<embed>/<form>/event-
 * handler attributes/javascript: URLs out, by construction rather than by
 * enumeration), then re-validates every surviving link's href through the
 * SAME isSafeExternalUrl used everywhere else in this app for backend-
 * supplied URLs (widget/safeUrl.ts) - one source of truth for "is this URL
 * safe to put in href," not a second, possibly-inconsistent check.
 */

let hookInstalled = false;

function installLinkSafetyHook(): void {
  if (hookInstalled) return;
  hookInstalled = true;
  DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    if (node.tagName !== "A") return;
    const href = node.getAttribute("href");
    if (!href || !isSafeExternalUrl(href)) {
      node.removeAttribute("href");
      return;
    }
    // Every surviving external link opens safely, regardless of what the
    // sanitized markup itself specified.
    node.setAttribute("target", "_blank");
    node.setAttribute("rel", "noopener noreferrer");
  });
}

const SANITIZE_CONFIG: Config = {
  ALLOWED_TAGS: ["p", "br", "strong", "b", "em", "i", "ul", "ol", "li", "a"],
  ALLOWED_ATTR: ["href"],
  ALLOW_DATA_ATTR: false,
};

/** Sanitizes raw evidence excerpt text for safe use in
 * dangerouslySetInnerHTML - the only intended caller is SafeHtml.tsx. */
export function sanitizeEvidenceHtml(raw: string): string {
  installLinkSafetyHook();
  return DOMPurify.sanitize(raw, SANITIZE_CONFIG);
}
