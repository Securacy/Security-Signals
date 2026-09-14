import { SECURITY_CATEGORIES } from "../types";
import { categoryLabel } from "../categoryLabels";

interface CategoryFilterProps {
  selected: string | null;
  onSelect: (category: string | null) => void;
}

export function CategoryFilter({ selected, onSelect }: CategoryFilterProps) {
  return (
    <div className="ss-category-filter" role="group" aria-label="Filter by category">
      <button
        type="button"
        className="ss-chip"
        aria-pressed={selected === null}
        data-active={selected === null}
        onClick={() => onSelect(null)}
      >
        All
      </button>
      {SECURITY_CATEGORIES.map((category) => (
        <button
          key={category}
          type="button"
          className="ss-chip"
          aria-pressed={selected === category}
          data-active={selected === category}
          onClick={() => onSelect(category)}
        >
          {categoryLabel(category)}
        </button>
      ))}
    </div>
  );
}
