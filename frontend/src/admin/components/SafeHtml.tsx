import { sanitizeEvidenceHtml } from "../sanitizeHtml";

/**
 * The ONLY place dangerouslySetInnerHTML is used anywhere in this app -
 * and it is only ever fed the output of sanitizeEvidenceHtml, never a raw
 * string. Renders formatted evidence excerpt text (bold labels, line
 * breaks, lists, safe links) instead of showing literal "<p><b>...</b>"
 * tag characters to the reviewer.
 */
export function SafeHtml({ html, className }: { html: string; className?: string }) {
  return <div className={className} dangerouslySetInnerHTML={{ __html: sanitizeEvidenceHtml(html) }} />;
}
