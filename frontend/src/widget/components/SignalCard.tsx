import type { SignalSummary } from "../types";
import { categoryLabel } from "../categoryLabels";
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
      {signal.categories.length > 0 && (
        <div className="ss-card__chips">
          {signal.categories.map((c) => (
            <span className="ss-chip ss-chip--static" key={c.id}>
              {categoryLabel(c.category)}
            </span>
          ))}
        </div>
      )}
      <h3 className="ss-card__title">{signal.title}</h3>
      <p className="ss-card__summary">{signal.summary}</p>
      <span className="ss-card__meta">{formatRelativeTime(signal.published_at)}</span>
    </button>
  );
}
