import { PUBLIC_CATEGORIES, AI_SECURITY_SUBCATEGORIES, SORT_OPTIONS } from "../types";
import type { SortOption } from "../types";
import { subcategoryLabel } from "../categoryLabels";
import { publicCategoryLabel } from "../publicTaxonomy";

const SORT_LABELS: Record<SortOption, string> = {
  recent: "Most Recent",
  relevant: "Most Relevant",
  priority: "Highest Priority",
  sources: "Most Sources",
};

interface FilterBarProps {
  category: string | null;
  subcategory: string | null;
  search: string;
  sort: SortOption;
  isSearching: boolean;
  onCategoryChange: (category: string | null) => void;
  onSubcategoryChange: (subcategory: string | null) => void;
  onSearchChange: (search: string) => void;
  onSortChange: (sort: SortOption) => void;
  onClear: () => void;
}

function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true" className="ss-search-field__icon">
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="M19.5 19.5 15 15" strokeLinecap="round" />
    </svg>
  );
}

function SearchSpinner() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className="ss-search-field__spinner"
      role="status"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.5" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

export function FilterBar({
  category,
  subcategory,
  search,
  sort,
  isSearching,
  onCategoryChange,
  onSubcategoryChange,
  onSearchChange,
  onSortChange,
  onClear,
}: FilterBarProps) {
  const hasActiveFilters = category !== null || subcategory !== null || search !== "" || sort !== "recent";

  return (
    <div className="ss-filter-bar" role="search" aria-label="Filter security signals">
      <div className="ss-filter-bar__row">
        <div className="ss-field">
          <label className="ss-field__label" htmlFor="ss-filter-search">
            Search
          </label>
          <div className="ss-search-field">
            <SearchIcon />
            <input
              id="ss-filter-search"
              type="search"
              className="ss-input ss-search-field__input"
              placeholder="Ask about a security threat, e.g. “is there anything about OAuth?”"
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
            />
            {isSearching && <SearchSpinner />}
          </div>
        </div>
      </div>

      <div className="ss-filter-bar__row ss-filter-bar__row--controls">
        <div className="ss-field">
          <label className="ss-field__label" htmlFor="ss-filter-category">
            Category
          </label>
          <select
            id="ss-filter-category"
            className="ss-select"
            value={category ?? ""}
            onChange={(e) => {
              const value = e.target.value || null;
              onCategoryChange(value);
              if (value !== "ai_security") {
                onSubcategoryChange(null);
              }
            }}
          >
            <option value="">All categories</option>
            {PUBLIC_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {publicCategoryLabel(c)}
              </option>
            ))}
          </select>
        </div>

        {category === "ai_security" && (
          <div className="ss-field">
            <label className="ss-field__label" htmlFor="ss-filter-subcategory">
              Subcategory
            </label>
            <select
              id="ss-filter-subcategory"
              className="ss-select"
              value={subcategory ?? ""}
              onChange={(e) => onSubcategoryChange(e.target.value || null)}
            >
              <option value="">All subcategories</option>
              {AI_SECURITY_SUBCATEGORIES.map((s) => (
                <option key={s} value={s}>
                  {subcategoryLabel(s)}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="ss-field">
          <label className="ss-field__label" htmlFor="ss-filter-sort">
            Sort
          </label>
          <select
            id="ss-filter-sort"
            className="ss-select"
            value={sort}
            onChange={(e) => onSortChange(e.target.value as SortOption)}
          >
            {SORT_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {SORT_LABELS[s]}
              </option>
            ))}
          </select>
        </div>

        {hasActiveFilters && (
          <button type="button" className="ss-button ss-button--clear" onClick={onClear}>
            Clear Filters
          </button>
        )}
      </div>
    </div>
  );
}
