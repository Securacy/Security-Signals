import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { SignalCard } from "../../../src/widget/components/SignalCard";
import type { SignalSummary } from "../../../src/widget/types";

const baseSignal: SignalSummary = {
  id: "sig-1",
  title: "Critical Apache RCE disclosed",
  summary: "A remote code execution vulnerability was disclosed in Apache HTTP Server.",
  security_impact: "Attackers could gain full server control.",
  principle: "Defense in depth",
  recommended_action: "Patch immediately.",
  published_at: new Date().toISOString(),
  categories: [{ id: "cat-1", category: "insecure_design", subcategory: null }],
  public_categories: ["product_security"],
};

describe("SignalCard", () => {
  it("renders title, summary, and a category icon with an accessible label", () => {
    render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument();
    expect(screen.getByText(/remote code execution/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Product Security" })).toBeInTheDocument();
  });

  it("renders one icon per distinct public category, never a bulky text chip", () => {
    const multiCategorySignal: SignalSummary = {
      ...baseSignal,
      public_categories: ["cloud_identity_security", "supply_chain"],
    };
    render(<SignalCard signal={multiCategorySignal} onOpen={vi.fn()} />);

    expect(screen.getByRole("img", { name: "Cloud & Identity Security" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Supply Chain" })).toBeInTheDocument();
    expect(screen.queryByText("Cloud & Identity Security")).toBeNull(); // no bulky text label
  });

  it("renders exactly one icon when multiple internal categories collapse into one public category", () => {
    const collapsedSignal: SignalSummary = {
      ...baseSignal,
      categories: [
        { id: "cat-1", category: "cloud_security", subcategory: null },
        { id: "cat-2", category: "iam", subcategory: null },
      ],
      public_categories: ["cloud_identity_security"],
    };
    render(<SignalCard signal={collapsedSignal} onOpen={vi.fn()} />);

    expect(screen.getAllByRole("img", { name: "Cloud & Identity Security" })).toHaveLength(1);
  });

  it("renders the AI Security icon independently, not merged with other categories", () => {
    const aiSignal: SignalSummary = {
      ...baseSignal,
      categories: [{ id: "cat-2", category: "ai_security", subcategory: "agent_abuse" }],
      public_categories: ["ai_security"],
    };
    render(<SignalCard signal={aiSignal} onOpen={vi.fn()} />);

    expect(screen.getByRole("img", { name: "AI Security" })).toBeInTheDocument();
  });

  it("calls onOpen with the signal id when clicked", () => {
    const onOpen = vi.fn();
    render(<SignalCard signal={baseSignal} onOpen={onOpen} />);

    fireEvent.click(screen.getByRole("button", { name: /Open signal/ }));

    expect(onOpen).toHaveBeenCalledWith("sig-1");
  });

  it("renders a title containing HTML-like text as plain text, never as markup", () => {
    const maliciousSignal: SignalSummary = {
      ...baseSignal,
      title: '<img src=x onerror="window.__xss=true">',
    };
    render(<SignalCard signal={maliciousSignal} onOpen={vi.fn()} />);

    // React escapes text content by default; assert the literal string is
    // rendered as text and no injected element/side effect occurred.
    expect(screen.getByText('<img src=x onerror="window.__xss=true">')).toBeInTheDocument();
    expect((window as any).__xss).toBeUndefined();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });

  it("renders no category icons when there are no public categories", () => {
    const { container } = render(
      <SignalCard signal={{ ...baseSignal, public_categories: [] }} onOpen={vi.fn()} />,
    );
    expect(container.querySelector(".ss-card__category-icons")).toBeNull();
  });

  it("positions category icons before the timestamp in the footer row, for a bottom-left layout", () => {
    const { container } = render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    const metaRow = container.querySelector(".ss-card__meta-row");
    expect(metaRow).not.toBeNull();
    const children = Array.from(metaRow!.children);
    const iconsIndex = children.findIndex((el) => el.classList.contains("ss-card__category-icons"));
    const timestampIndex = children.findIndex((el) => el.classList.contains("ss-card__meta"));
    expect(iconsIndex).toBeGreaterThanOrEqual(0);
    expect(timestampIndex).toBeGreaterThan(iconsIndex);
  });

  it("gives each category icon a distinct per-category color variable, not the muted default", () => {
    const multiCategorySignal: SignalSummary = {
      ...baseSignal,
      public_categories: ["cloud_identity_security", "supply_chain"],
    };
    render(<SignalCard signal={multiCategorySignal} onOpen={vi.fn()} />);

    const cloudIcon = screen.getByRole("img", { name: "Cloud & Identity Security" });
    const supplyChainIcon = screen.getByRole("img", { name: "Supply Chain" });
    const cloudColor = cloudIcon.style.getPropertyValue("--ss-cat-color");
    const supplyChainColor = supplyChainIcon.style.getPropertyValue("--ss-cat-color");
    expect(cloudColor).toBe("var(--ss-cat-cloud_identity_security)");
    expect(supplyChainColor).toBe("var(--ss-cat-supply_chain)");
    expect(cloudColor).not.toBe(supplyChainColor);
  });
});
