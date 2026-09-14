export function CardSkeleton() {
  return (
    <div className="ss-card ss-card--skeleton" aria-hidden="true">
      <div className="ss-skeleton-line ss-skeleton-line--title" />
      <div className="ss-skeleton-line ss-skeleton-line--chip" />
      <div className="ss-skeleton-line" />
      <div className="ss-skeleton-line ss-skeleton-line--short" />
    </div>
  );
}

export function FeedSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="ss-feed-skeleton" role="status" aria-label="Loading security signals">
      {Array.from({ length: count }).map((_, i) => (
        <CardSkeleton key={i} />
      ))}
    </div>
  );
}
