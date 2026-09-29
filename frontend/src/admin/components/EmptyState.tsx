interface EmptyStateProps {
  message: string;
  hint?: string;
}

/** A small, quiet shield-check glyph - the one recurring "security
 * personality" motif used sparingly across the admin app (empty states,
 * the "all caught up" attention tile), never a literal mascot or stock
 * hacker imagery. Monochrome and muted so it reads as part of the UI
 * chrome, not decoration competing with real content. */
function ShieldCheckGlyph() {
  return (
    <svg className="adm-empty-state__icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3l7 3v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Explains what's true and, where useful, what the user can do next -
 * never a bare blank card. */
export function EmptyState({ message, hint }: EmptyStateProps) {
  return (
    <div className="adm-empty-state">
      <ShieldCheckGlyph />
      <p className="adm-empty-state__message">{message}</p>
      {hint && <p className="adm-empty-state__hint">{hint}</p>}
    </div>
  );
}
