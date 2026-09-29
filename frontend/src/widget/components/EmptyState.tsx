interface EmptyStateProps {
  filtered: boolean;
  isSearchMode?: boolean;
}

export function EmptyState({ filtered, isSearchMode = false }: EmptyStateProps) {
  const title = isSearchMode
    ? "No matching signals found"
    : filtered
      ? "No signals in this category yet"
      : "No published signals yet";

  const body = isSearchMode
    ? "Try a broader security term, or clear the search to browse everything."
    : filtered
      ? "Try a different category or check back soon."
      : "Check back soon for the latest security developments.";

  return (
    <div className="ss-empty-state" role="status">
      <p className="ss-empty-state__title">{title}</p>
      <p className="ss-empty-state__body">{body}</p>
    </div>
  );
}
