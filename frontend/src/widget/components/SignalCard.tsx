import type { SignalSummary } from "../types";
import { CategoryIcon } from "../publicTaxonomy";
import { formatRelativeTime } from "../formatRelativeTime";

interface SignalCardProps {
  signal: SignalSummary;
  onOpen: (id: string) => void;
}

export function SignalCard({ signal, onOpen }: SignalCardProps) {
  return (
    <button
      type="button"
      className="ss-card"
      onClick={() => onOpen(signal.id)}
      aria-label={`Open signal: ${signal.title}`}
    >
      <h3 className="ss-card__title">{signal.title}</h3>
      <p className="ss-card__summary">{signal.summary}</p>
      <div className="ss-card__meta-row">
        {signal.public_categories.length > 0 && (
          <span className="ss-card__category-icons">
            {signal.public_categories.map((category) => (
              <CategoryIcon key={category} category={category} />
            ))}
          </span>
        )}
        <span className="ss-card__meta">{formatRelativeTime(signal.published_at)}</span>
      </div>
    </button>
  );
}
