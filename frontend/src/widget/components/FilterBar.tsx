import { useEffect, useLayoutEffect, useRef } from "react";
import { PUBLIC_CATEGORIES, AI_SECURITY_SUBCATEGORIES } from "../types";
import { subcategoryLabel } from "../categoryLabels";
import { CategoryGlyph, categoryColorStyle, publicCategoryLabel } from "../publicTaxonomy";
import { Duotone, SQUARES_FOUR, X } from "../icons";
import { prefersReducedMotion } from "../motion";

interface FilterBarProps {
  category: string | null;
  subcategory: string | null;
  search: string;
  isSearching: boolean;
  onCategoryChange: (category: string | null) => void;
  onSubcategoryChange: (subcategory: string | null) => void;
  onSearchChange: (search: string) => void;
  onClear: () => void;
}

const ALL_KEY = "__all__";

/** Outlined magnifier with a filled "shadow" disc offset behind the lens -
 * the disc is its own element so focus can pop it (scale) independently. */
function SearchIcon() {
  return (
    <svg viewBox="0 0 28 28" fill="none" aria-hidden="true" className="ss-search__icon">
      <circle className="ss-search__lens-shadow" cx="13.5" cy="13.5" r="7" />
      <circle cx="11.5" cy="11.5" r="7" stroke="currentColor" strokeWidth="2" />
      <path d="M17 17l6 6" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
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

/**
 * Keeps one absolutely-positioned black pill under the active chip and
 * slides it between chips with FLIP: jump the pill to the new chip's box,
 * invert with translateX/scaleX back to the old box, then transition the
 * transform away - so chips of different widths still animate with
 * transform alone. Re-measured (without animating) when the row resizes,
 * e.g. once web fonts finish loading.
 */
function useSlidingIndicator(activeKey: string) {
  const rowRef = useRef<HTMLDivElement>(null);
  const indicatorRef = useRef<HTMLSpanElement>(null);
  const chipRefs = useRef(new Map<string, HTMLButtonElement>());
  const lastBox = useRef<{ left: number; width: number } | null>(null);

  function place(animate: boolean) {
    const indicator = indicatorRef.current;
    const chip = chipRefs.current.get(activeKey);
    if (!indicator || !chip) return;
    const box = { left: chip.offsetLeft, width: chip.offsetWidth };
    const previous = lastBox.current;
    lastBox.current = box;

    indicator.style.width = `${box.width}px`;
    indicator.style.left = `${box.left}px`;
    if (!animate || !previous || box.width === 0 || prefersReducedMotion()) {
      indicator.style.transition = "none";
      indicator.style.transform = "";
      return;
    }
    indicator.style.transition = "none";
    indicator.style.transform = `translateX(${previous.left - box.left}px) scaleX(${previous.width / box.width})`;
    void indicator.getBoundingClientRect(); // commit the inverted frame before transitioning away from it
    indicator.style.transition = "";
    indicator.style.transform = "";
  }

  useLayoutEffect(() => {
    // place() reads only refs, so it re-runs purely when the active chip
    // changes - not on every render.
    place(true);
  }, [activeKey]);

  useEffect(() => {
    const row = rowRef.current;
    if (!row || typeof ResizeObserver !== "function") return undefined;
    const observer = new ResizeObserver(() => place(false));
    observer.observe(row);
    return () => observer.disconnect();
  }, [activeKey]);

  function chipRef(key: string) {
    return (el: HTMLButtonElement | null) => {
      if (el) chipRefs.current.set(key, el);
      else chipRefs.current.delete(key);
    };
  }

  return { rowRef, indicatorRef, chipRef };
}

export function FilterBar({
  category,
  subcategory,
  search,
  isSearching,
  onCategoryChange,
  onSubcategoryChange,
  onSearchChange,
  onClear,
}: FilterBarProps) {
  const hasActiveFilters = category !== null || subcategory !== null || search !== "";
  const inputRef = useRef<HTMLInputElement>(null);
  const { rowRef, indicatorRef, chipRef } = useSlidingIndicator(category ?? ALL_KEY);

  function selectCategory(value: string | null) {
    onCategoryChange(value);
    if (value !== "ai_security") {
      onSubcategoryChange(null);
    }
  }

  return (
    <div className="ss-filter-bar" role="search" aria-label="Filter security signals">
      {/* Open, underline-style field: no box, a 2px ink rule with an offset
          teal highlight under it (purple, sliding in, on focus), and the
          magnifier on the right. No visible label - aria-label instead. */}
      <div className="ss-search">
        <input
          ref={inputRef}
          id="ss-filter-search"
          type="search"
          className="ss-search__input"
          aria-label="Search signals"
          placeholder="looking for something?"
          autoComplete="off"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
        />
        {search !== "" && (
          <button
            type="button"
            className="ss-search__clear"
            aria-label="Clear search"
            onClick={() => {
              onSearchChange("");
              inputRef.current?.focus();
            }}
          >
            <Duotone icon={X} className="ss-search__clear-icon" lineOnly />
          </button>
        )}
        {isSearching ? <SearchSpinner /> : <SearchIcon />}
        <span className="ss-search__highlight" aria-hidden="true" />
        <span className="ss-search__highlight ss-search__highlight--focus" aria-hidden="true" />
        <span className="ss-search__rule" aria-hidden="true" />
      </div>

      {/* Single-select filter chips. Toggle buttons (aria-pressed) rather
          than a radio group: each chip is its own tab stop, which keeps
          the horizontally-scrolling row reachable chip by chip - focusing
          an off-screen chip scrolls it into view natively. */}
      <div className="ss-chips" role="group" aria-label="Category" ref={rowRef}>
        <span className="ss-chips__indicator" ref={indicatorRef} aria-hidden="true" />
        <button
          ref={chipRef(ALL_KEY)}
          type="button"
          className="ss-chip ss-chip--all"
          aria-pressed={category === null}
          onClick={() => selectCategory(null)}
        >
          <Duotone icon={SQUARES_FOUR} className="ss-chip__icon" />
          All
        </button>
        {PUBLIC_CATEGORIES.map((c) => (
          <button
            key={c}
            ref={chipRef(c)}
            type="button"
            className="ss-chip"
            aria-pressed={category === c}
            style={categoryColorStyle(c)}
            onClick={() => selectCategory(c)}
          >
            <CategoryGlyph category={c} className="ss-chip__icon" />
            {publicCategoryLabel(c)}
          </button>
        ))}
      </div>

      {(category === "ai_security" || hasActiveFilters) && (
        <div className="ss-filter-bar__row">
          {category === "ai_security" && (
            <div className="ss-field ss-field--inline">
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

          {hasActiveFilters && (
            <button type="button" className="ss-button ss-button--clear" onClick={onClear}>
              Clear Filters
            </button>
          )}
        </div>
      )}
    </div>
  );
}
