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
  categories: [{ id: "cat-1", category: "vulnerability" }],
};

describe("SignalCard", () => {
  it("renders title, summary, and category chip", () => {
    render(<SignalCard signal={baseSignal} onOpen={vi.fn()} />);

    expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument();
    expect(screen.getByText(/remote code execution/)).toBeInTheDocument();
    expect(screen.getByText("Vulnerability")).toBeInTheDocument();
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

  it("renders nothing for the chips row when there are no categories", () => {
    const { container } = render(<SignalCard signal={{ ...baseSignal, categories: [] }} onOpen={vi.fn()} />);
    expect(container.querySelector(".ss-card__chips")).toBeNull();
  });
});
