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
  it("renders the title and a category pill with icon + visible name, but no excerpt", () => {
    const { container } = render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument();
    expect(screen.queryByText(/remote code execution/)).toBeNull();
    const pill = container.querySelector(".ss-pill");
    expect(pill).toHaveTextContent("Product Security");
    expect(pill!.querySelector("svg")).not.toBeNull();
  });

  it("shows one pill for the primary category, with +N (and the full list for screen readers)", () => {
    const multiCategorySignal: SignalSummary = {
      ...baseSignal,
      public_categories: ["cloud_identity_security", "supply_chain"],
    };
    const { container } = render(<SignalCard signal={multiCategorySignal} onOpen={vi.fn()} />);

    const pills = container.querySelectorAll(".ss-pill");
    expect(pills).toHaveLength(1);
    expect(pills[0].querySelector(".ss-pill__label")).toHaveTextContent("Cloud & Identity Security");
    expect(pills[0].querySelector(".ss-pill__more")).toHaveTextContent("+1");
    expect(pills[0]).toHaveTextContent(/also Supply Chain/);
  });

  it("renders exactly one pill when multiple internal categories collapse into one public category", () => {
    const collapsedSignal: SignalSummary = {
      ...baseSignal,
      categories: [
        { id: "cat-1", category: "cloud_security", subcategory: null },
        { id: "cat-2", category: "iam", subcategory: null },
      ],
      public_categories: ["cloud_identity_security"],
    };
    const { container } = render(<SignalCard signal={collapsedSignal} onOpen={vi.fn()} />);

    expect(container.querySelectorAll(".ss-pill")).toHaveLength(1);
  });

  it("renders the AI Security pill independently, not merged with other categories", () => {
    const aiSignal: SignalSummary = {
      ...baseSignal,
      categories: [{ id: "cat-2", category: "ai_security", subcategory: "agent_abuse" }],
      public_categories: ["ai_security"],
    };
    const { container } = render(<SignalCard signal={aiSignal} onOpen={vi.fn()} />);

    expect(container.querySelector(".ss-pill")).toHaveTextContent("AI Security");
  });

  it("fills the card with category art tinted by the primary (first) category", () => {
    const { container } = render(
      <SignalCard signal={{ ...baseSignal, public_categories: ["ransomware", "threat_intel"] }} onOpen={vi.fn()} />,
    );

    const visual = container.querySelector(".ss-card .ss-visual") as HTMLElement;
    expect(visual).toHaveAttribute("data-state", "fallback");
    expect(visual.style.getPropertyValue("--ss-cat-color")).toBe("var(--ss-cat-ransomware)");
    expect(visual.querySelector(".ss-visual__emblem svg")).not.toBeNull();
    expect(visual.querySelector(".ss-visual__pattern")).not.toBeNull();
  });

  it("keeps the image clean: no pill, date or headline over it", () => {
    const { container } = render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);
    const media = container.querySelector(".ss-card__media")!;
    expect(media).not.toContainElement(screen.getByText("Critical Apache RCE disclosed"));
    expect(media.querySelector(".ss-pill, time")).toBeNull();
    expect(container.querySelector(".ss-card__body time")).not.toBeNull();
    expect(screen.queryByText("Human-reviewed")).toBeNull();
  });

  it("exposes categories and time to screen readers via aria-describedby, not just the button label", () => {
    render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    const button = screen.getByRole("button", { name: "Open signal: Critical Apache RCE disclosed" });
    expect(button).toHaveAccessibleDescription(/Published just now.*Product Security/);
  });

  it("puts the footer below the title: date on the left, category pill on the right", () => {
    const { container } = render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    const title = screen.getByText("Critical Apache RCE disclosed");
    const footer = container.querySelector(".ss-card__footer")!;
    expect(title.compareDocumentPosition(footer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const [first, second] = Array.from(footer.children);
    expect(first.tagName).toBe("TIME");
    expect(second).toHaveClass("ss-pill");
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

  it("renders no pills and neutral (still designed) art when there are no public categories", () => {
    const { container } = render(
      <SignalCard signal={{ ...baseSignal, public_categories: [] }} onOpen={vi.fn()} />,
    );
    expect(container.querySelector(".ss-pill")).toBeNull();
    expect(container.querySelector(".ss-visual__fallback--neutral .ss-visual__emblem svg")).not.toBeNull();
  });

  it("gives each pill its own category colour variable, not the muted default", () => {
    const { container } = render(
      <>
        <SignalCard signal={{ ...baseSignal, id: "a", public_categories: ["cloud_identity_security"] }} onOpen={vi.fn()} />
        <SignalCard signal={{ ...baseSignal, id: "b", public_categories: ["supply_chain"] }} onOpen={vi.fn()} />
      </>,
    );

    const [cloudPill, supplyChainPill] = Array.from(container.querySelectorAll<HTMLElement>(".ss-pill"));
    expect(cloudPill.style.getPropertyValue("--ss-cat-color")).toBe("var(--ss-cat-cloud_identity_security)");
    expect(supplyChainPill.style.getPropertyValue("--ss-cat-color")).toBe("var(--ss-cat-supply_chain)");
  });
});
