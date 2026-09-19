import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SignalDetail } from "../../../src/widget/components/SignalDetail";
import * as api from "../../../src/widget/api";
import { ApiError } from "../../../src/widget/api";
import type { SignalDetail as SignalDetailType } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

const baseDetail: SignalDetailType = {
  id: "sig-1",
  title: "Critical Apache RCE disclosed",
  summary: "What happened text.",
  security_impact: "Why it matters text.",
  principle: "Defense in depth",
  recommended_action: "Patch immediately.",
  published_at: new Date().toISOString(),
  categories: [{ id: "cat-1", category: "insecure_design", subcategory: null }],
  public_categories: ["product_security"],
  visual_status: "generated",
  visual_url: "/media/signals/sig-1.png",
  evidence: [
    { id: "ev-1", source_url: "https://example.com/advisory", source_title: "Vendor Advisory", excerpt: "quote", created_at: null },
  ],
};

describe("SignalDetail", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // vi.mock("../api") auto-mocks every export, including the new
    // resolveMediaUrl - give it back its real (pure, deterministic)
    // behavior rather than the default undefined-returning stub.
    vi.mocked(api.resolveMediaUrl).mockImplementation(
      (base: string, path: string) => base.replace(/\/+$/, "") + path,
    );
  });

  it("shows a loading state before the fetch resolves", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    expect(screen.getByLabelText("Loading signal")).toBeInTheDocument();
  });

  it("renders what happened, why it matters, principle, and recommended action", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument());
    expect(screen.getByText("What happened text.")).toBeInTheDocument();
    expect(screen.getByText("Why it matters text.")).toBeInTheDocument();
    expect(screen.getByText("Defense in depth")).toBeInTheDocument();
    expect(screen.getByText("Patch immediately.")).toBeInTheDocument();
  });

  it("renders a safe https evidence link with target=_blank and rel=noopener noreferrer", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    const link = await screen.findByRole("link", { name: "Vendor Advisory" });
    expect(link).toHaveAttribute("href", "https://example.com/advisory");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("does not render an unsafe evidence URL as a clickable link", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail,
      evidence: [{ id: "ev-2", source_url: "javascript:alert(1)", source_title: "Suspicious Source", excerpt: "x", created_at: null }],
    });

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    await screen.findByText("Suspicious Source");
    expect(screen.queryByRole("link", { name: "Suspicious Source" })).toBeNull();
  });

  it("shows an error state with retry on failure", async () => {
    vi.mocked(api.fetchSignalDetail)
      .mockRejectedValueOnce(new ApiError("boom", 500))
      .mockResolvedValueOnce(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("Couldn't load security signals")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument());
  });

  it("calls onBack when the back button is clicked", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);
    const onBack = vi.fn();

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={onBack} />);
    await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));

    fireEvent.click(screen.getByRole("button", { name: /Back/ }));

    expect(onBack).toHaveBeenCalled();
  });

  it("renders a malicious-looking summary as plain text, never executes it", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail,
      summary: '<img src=x onerror="window.__xss=true">',
    });

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    await screen.findByText('<img src=x onerror="window.__xss=true">');
    expect((window as any).__xss).toBeUndefined();
  });

  it("renders a category icon with an accessible label near the timestamp", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByRole("img", { name: "Product Security" })).toBeInTheDocument());
  });

  it("renders the signal's own generated visual when status is generated", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "image"));
    const img = container.querySelector(".ss-visual__image") as HTMLImageElement;
    expect(img.src).toBe("https://api.example.com/media/signals/sig-1.png");
    expect(img.getAttribute("loading")).toBe("lazy");
  });

  it("renders the category-based fallback when visual_status is pending", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail, visual_status: "pending", visual_url: null,
    });

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
    expect(container.querySelector(".ss-visual__image")).toBeNull();
  });

  it("renders the category-based fallback when visual_status is failed", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail, visual_status: "failed", visual_url: null,
    });

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
  });

  it("falls back to the category visual when the image fails to load client-side", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" onBack={vi.fn()} />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual__image")).toBeInTheDocument());
    fireEvent.error(container.querySelector(".ss-visual__image") as HTMLImageElement);

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
  });
});
