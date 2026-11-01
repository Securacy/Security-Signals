/** Deck-shaped placeholder: one card in focus with the next peeking, at
 * the real card's proportions, so nothing jumps when content arrives. */
export function FeedSkeleton() {
  return (
    <div className="ss-feed-skeleton" role="status" aria-label="Loading security signals">
      <div className="ss-feed-skeleton__card" aria-hidden="true">
        <div className="ss-skel ss-skel--media" />
        <div className="ss-skel ss-skel--line" />
        <div className="ss-skel ss-skel--line ss-skel--short" />
      </div>
      <div className="ss-feed-skeleton__card ss-feed-skeleton__card--peek" aria-hidden="true">
        <div className="ss-skel ss-skel--media" />
      </div>
    </div>
  );
}
