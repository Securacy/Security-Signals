import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { CategoryFilter } from "../../../src/widget/components/CategoryFilter";

describe("CategoryFilter", () => {
  it("renders an 'All' chip plus one chip per known category", () => {
    render(<CategoryFilter selected={null} onSelect={vi.fn()} />);

    expect(screen.getByRole("button", { name: "All" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Vulnerability" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "IAM" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "AI Security" })).toBeInTheDocument();
  });

  it("marks the selected category as pressed", () => {
    render(<CategoryFilter selected="iam" onSelect={vi.fn()} />);

    expect(screen.getByRole("button", { name: "IAM" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "false");
  });

  it("calls onSelect with the category value when a chip is clicked", () => {
    const onSelect = vi.fn();
    render(<CategoryFilter selected={null} onSelect={onSelect} />);

    fireEvent.click(screen.getByRole("button", { name: "Ransomware" }));

    expect(onSelect).toHaveBeenCalledWith("ransomware");
  });

  it("calls onSelect with null when 'All' is clicked", () => {
    const onSelect = vi.fn();
    render(<CategoryFilter selected="iam" onSelect={onSelect} />);

    fireEvent.click(screen.getByRole("button", { name: "All" }));

    expect(onSelect).toHaveBeenCalledWith(null);
  });
});
