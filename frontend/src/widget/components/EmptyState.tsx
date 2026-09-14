export function EmptyState({ filtered }: { filtered: boolean }) {
  return (
    <div className="ss-empty-state" role="status">
      <p className="ss-empty-state__title">
        {filtered ? "No signals in this category yet" : "No published signals yet"}
      </p>
      <p className="ss-empty-state__body">
        {filtered
          ? "Try a different category or check back soon."
          : "Check back soon for the latest security developments."}
      </p>
    </div>
  );
}
