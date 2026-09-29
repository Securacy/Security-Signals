import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { FilterBar } from "../../../src/widget/components/FilterBar";

function renderBar(overrides: Partial<React.ComponentProps<typeof FilterBar>> = {}) {
  const props = {
    category: null,
    subcategory: null,
    search: "",
    sort: "recent" as const,
    isSearching: false,
    onCategoryChange: vi.fn(),
    onSubcategoryChange: vi.fn(),
    onSearchChange: vi.fn(),
    onSortChange: vi.fn(),
    onClear: vi.fn(),
    ...overrides,
  };
  render(<FilterBar {...props} />);
  return props;
}

describe("FilterBar", () => {
  it("renders exactly the 8 consolidated public categories plus an 'All' option", () => {
    renderBar();

    const select = screen.getByLabelText("Category") as HTMLSelectElement;
    const optionLabels = Array.from(select.options).map((o) => o.textContent);

    expect(optionLabels).toEqual([
      "All categories",
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

    const select = screen.getByLabelText("Category") as HTMLSelectElement;
    const optionLabels = Array.from(select.options).map((o) => o.textContent);

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

  it("calls onCategoryChange with the public category slug when picked", () => {
    const { onCategoryChange } = renderBar();

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "cloud_identity_security" } });

    expect(onCategoryChange).toHaveBeenCalledWith("cloud_identity_security");
  });

  it("clears subcategory when switching away from ai_security", () => {
    const { onSubcategoryChange } = renderBar({ category: "ai_security" });

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "cloud_identity_security" } });

    expect(onSubcategoryChange).toHaveBeenCalledWith(null);
  });

  it("calls onSearchChange as the user types", () => {
    const { onSearchChange } = renderBar();

    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "prompt injection" } });

    expect(onSearchChange).toHaveBeenCalledWith("prompt injection");
  });

  it("renders all four sort options", () => {
    renderBar();

    const select = screen.getByLabelText("Sort") as HTMLSelectElement;
    const optionLabels = Array.from(select.options).map((o) => o.textContent);

    expect(optionLabels).toEqual(["Most Recent", "Most Relevant", "Highest Priority", "Most Sources"]);
  });

  it("calls onSortChange when sort is changed", () => {
    const { onSortChange } = renderBar();

    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "sources" } });

    expect(onSortChange).toHaveBeenCalledWith("sources");
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
});
