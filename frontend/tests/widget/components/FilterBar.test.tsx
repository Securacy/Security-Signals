import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { FilterBar } from "../../../src/widget/components/FilterBar";

function renderBar(overrides: Partial<React.ComponentProps<typeof FilterBar>> = {}) {
  const props = {
    category: null,
    subcategory: null,
    search: "",
    isSearching: false,
    onCategoryChange: vi.fn(),
    onSubcategoryChange: vi.fn(),
    onSearchChange: vi.fn(),
    onClear: vi.fn(),
    ...overrides,
  };
  render(<FilterBar {...props} />);
  return props;
}

function categoryChipLabels(): string[] {
  const group = screen.getByRole("group", { name: "Category" });
  return within(group)
    .getAllByRole("button")
    .map((b) => b.textContent ?? "");
}

describe("FilterBar", () => {
  it("renders exactly the 8 consolidated public categories plus an 'All' chip", () => {
    renderBar();

    expect(categoryChipLabels()).toEqual([
      "All",
      "Product Security",
      "Cloud & Identity Security",
      "Supply Chain",
      "Data & Privacy",
      "Ransomware",
      "Threat Intelligence",
      "AI Security",
      "Infrastructure",
    ]);
  });

  it("never renders the old, pre-consolidation public category labels", () => {
    renderBar();

    const optionLabels = categoryChipLabels();

    expect(optionLabels).not.toContain("Insecure Design");
    expect(optionLabels).not.toContain("App & API");
    expect(optionLabels).not.toContain("Cloud Security");
    expect(optionLabels).not.toContain("IAM");
    expect(optionLabels).not.toContain("Vulnerability");
  });

  it("does not show a subcategory dropdown unless AI Security is selected", () => {
    renderBar({ category: "cloud_identity_security" });
    expect(screen.queryByLabelText("Subcategory")).not.toBeInTheDocument();
  });

  it("shows the AI subcategory dropdown when category is ai_security", () => {
    renderBar({ category: "ai_security" });

    const select = screen.getByLabelText("Subcategory") as HTMLSelectElement;
    const optionLabels = Array.from(select.options).map((o) => o.textContent);
    expect(optionLabels).toContain("Agent Abuse");
    expect(optionLabels).toContain("LLM Vulnerability");
  });

  it("calls onCategoryChange with the public category slug when a chip is picked", () => {
    const { onCategoryChange } = renderBar();

    fireEvent.click(screen.getByRole("button", { name: "Cloud & Identity Security" }));

    expect(onCategoryChange).toHaveBeenCalledWith("cloud_identity_security");
  });

  it("calls onCategoryChange(null) from the 'All' chip", () => {
    const { onCategoryChange } = renderBar({ category: "ransomware" });

    fireEvent.click(screen.getByRole("button", { name: "All" }));

    expect(onCategoryChange).toHaveBeenCalledWith(null);
  });

  it("marks exactly the active category chip as pressed", () => {
    renderBar({ category: "supply_chain" });

    expect(screen.getByRole("button", { name: "Supply Chain" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "false");
    const pressed = within(screen.getByRole("group", { name: "Category" }))
      .getAllByRole("button")
      .filter((b) => b.getAttribute("aria-pressed") === "true");
    expect(pressed).toHaveLength(1);
  });

  it("tints every category chip with its own category colour variable", () => {
    renderBar();

    expect(screen.getByRole("button", { name: "Ransomware" }).style.getPropertyValue("--ss-cat-color")).toBe(
      "var(--ss-cat-ransomware)",
    );
  });

  it("clears subcategory when switching away from ai_security", () => {
    const { onSubcategoryChange } = renderBar({ category: "ai_security" });

    fireEvent.click(screen.getByRole("button", { name: "Cloud & Identity Security" }));

    expect(onSubcategoryChange).toHaveBeenCalledWith(null);
  });

  it("calls onSearchChange as the user types", () => {
    const { onSearchChange } = renderBar();

    fireEvent.change(screen.getByLabelText("Search signals"), { target: { value: "prompt injection" } });

    expect(onSearchChange).toHaveBeenCalledWith("prompt injection");
  });

  it("has no sort control - the feed is always newest-first", () => {
    renderBar();
    expect(screen.queryByRole("radiogroup", { name: "Sort" })).toBeNull();
    expect(screen.queryByLabelText("Sort")).toBeNull();
  });

  it("hides Clear Filters when nothing is active", () => {
    renderBar();
    expect(screen.queryByRole("button", { name: "Clear Filters" })).not.toBeInTheDocument();
  });

  it("shows Clear Filters when a category is active", () => {
    renderBar({ category: "cloud_identity_security" });
    expect(screen.getByRole("button", { name: "Clear Filters" })).toBeInTheDocument();
  });

  it("shows Clear Filters when search text is active", () => {
    renderBar({ search: "ransomware" });
    expect(screen.getByRole("button", { name: "Clear Filters" })).toBeInTheDocument();
  });

  it("calls onClear when Clear Filters is clicked", () => {
    const { onClear } = renderBar({ category: "cloud_identity_security" });

    fireEvent.click(screen.getByRole("button", { name: "Clear Filters" }));

    expect(onClear).toHaveBeenCalled();
  });

  describe("underline search field", () => {
    it("has no visible label but an accessible name, and the friendly placeholder", () => {
      renderBar();
      const input = screen.getByRole("searchbox", { name: "Search signals" });
      expect(input).toHaveAttribute("aria-label", "Search signals");
      expect(input).toHaveAttribute("placeholder", "looking for something?");
      expect(document.querySelector("label[for='ss-filter-search']")).toBeNull();
    });

    it("shows a clear button only once there's text", () => {
      renderBar();
      expect(screen.queryByRole("button", { name: "Clear search" })).toBeNull();
    });

    it("clear empties the query and puts focus back in the field", () => {
      const { onSearchChange } = renderBar({ search: "oauth" });
      fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
      expect(onSearchChange).toHaveBeenCalledWith("");
      expect(screen.getByRole("searchbox", { name: "Search signals" })).toHaveFocus();
    });

    it("puts the magnifier on the right, swapped for a spinner while searching", () => {
      const { container, unmount } = render(
        <FilterBar
          category={null}
          subcategory={null}
          search="x"
          isSearching={false}
          onCategoryChange={vi.fn()}
          onSubcategoryChange={vi.fn()}
          onSearchChange={vi.fn()}
          onClear={vi.fn()}
        />,
      );
      const field = container.querySelector(".ss-search")!;
      const order = Array.from(field.children).map((el) => el.getAttribute("class")?.split(" ")[0]);
      expect(order.slice(0, 3)).toEqual(["ss-search__input", "ss-search__clear", "ss-search__icon"]);
      unmount();

      renderBar({ search: "x", isSearching: true });
      expect(document.querySelector(".ss-search__icon")).toBeNull();
      expect(document.querySelector(".ss-search-field__spinner")).not.toBeNull();
    });
  });
});
