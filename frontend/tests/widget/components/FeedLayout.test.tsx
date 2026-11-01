import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SignalFeed } from "../../../src/widget/components/SignalFeed";
import { SignalCard } from "../../../src/widget/components/SignalCard";
import { clearSignalVisualCache } from "../../../src/widget/signalVisual";
import { FilterBar } from "../../../src/widget/components/FilterBar";
import * as api from "../../../src/widget/api";
import type { SignalDetail, SignalSummary } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

function hoursAgo(h: number): string {
  return new Date(Date.now() - h * 3_600_000).toISOString();
}

function makeSignal(id: string, published_at: string | null, overrides: Partial<SignalSummary> = {}): SignalSummary {
  return {
    id,
    title: `Signal ${id}`,
    summary: `Summary ${id}`,
    security_impact: "",
    principle: "",
    recommended_action: "",
    published_at,
    categories: [],
    public_categories: ["ransomware"],
    ...overrides,
  };
}

describe("image-card feed layout", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    clearSignalVisualCache();
    vi.mocked(api.resolveMediaUrl).mockImplementation((base: string, path: string) => base + path);
  });

  it("renders every signal as a card in one swipe deck, with no date header above it", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [
        makeSignal("lead", hoursAgo(0.1)),
        makeSignal("today", hoursAgo(0.2)),
        makeSignal("week", hoursAgo(24 * 3)),
        makeSignal("old", hoursAgo(24 * 30)),
      ],
      hasMore: false,
    });

    const { container } = render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await screen.findByText("Signal lead");

    const deck = screen.getByRole("region", { name: "Security signals" });
    expect(within(deck).getAllByRole("group")).toHaveLength(4);
    expect(container.querySelectorAll(".ss-card")).toHaveLength(4);
    expect(container.querySelectorAll(".ss-card .ss-visual")).toHaveLength(4);
    expect(screen.queryByText(/^(Today|This week|Earlier)$/i)).toBeNull();
  });

  it("a new filter result remounts the deck (back to card 1)", async () => {
    vi.mocked(api.fetchPublishedSignals)
      .mockResolvedValueOnce({ signals: [makeSignal("a", hoursAgo(1)), makeSignal("b", hoursAgo(2))], hasMore: false })
      .mockResolvedValueOnce({ signals: [makeSignal("c", hoursAgo(1))], hasMore: false });
    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await screen.findByText("Signal a");
    const before = screen.getByRole("region", { name: "Security signals" });

    fireEvent.click(screen.getByRole("button", { name: "Supply Chain" }));

    await screen.findByText("Signal c");
    const after = screen.getByRole("region", { name: "Security signals" });
    expect(after).not.toBe(before);
    expect(screen.getByText("Signal 1 of 1")).toBeInTheDocument();
  });

  it("cards carry no excerpt", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal("lead", hoursAgo(1)), makeSignal("row", hoursAgo(2))],
      hasMore: false,
    });
    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await screen.findByText("Signal row");
    expect(screen.queryByText("Summary row")).toBeNull();
  });

  it("search results use the same deck", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [makeSignal("s1", hoursAgo(1)), makeSignal("s2", hoursAgo(2))],
      aiUnderstood: false,
      understoodPublicCategories: [],
    });
    const { container } = render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    fireEvent.change(screen.getByLabelText("Search signals"), { target: { value: "ransom" } });

    await screen.findByText("Signal s1");
    expect(container.querySelectorAll(".ss-deck .ss-card")).toHaveLength(2);
    expect(screen.getByText("Signal s2")).toBeInTheDocument();
  });

  it("keeps current results visible (dimmed) under a refresh spinner while reloading", async () => {
    vi.mocked(api.fetchPublishedSignals)
      .mockResolvedValueOnce({ signals: [makeSignal("lead", hoursAgo(1))], hasMore: false })
      .mockReturnValueOnce(new Promise(() => {}));
    const { container } = render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await screen.findByText("Signal lead");

    fireEvent.click(screen.getByRole("button", { name: "Supply Chain" }));

    await screen.findByRole("status", { name: "Refreshing security signals" });
    expect(screen.getByText("Signal lead")).toBeInTheDocument();
    expect(container.querySelector(".ss-feed__list--refreshing")).not.toBeNull();
    expect(screen.queryByLabelText("Loading security signals")).toBeNull();
  });

  it("asks each card's own visual from the public detail endpoint", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal("lead", hoursAgo(1)), makeSignal("r1", hoursAgo(2))],
      hasMore: false,
    });
    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await screen.findByText("Signal r1");
    await waitFor(() => expect(api.fetchSignalDetail).toHaveBeenCalledTimes(2));
    expect(api.fetchSignalDetail).toHaveBeenCalledWith("https://api.example.com", "r1");
  });
});

describe("SignalCard", () => {
  const signal = makeSignal("hero", hoursAgo(1), { public_categories: ["ai_security"] });

  beforeEach(() => {
    vi.resetAllMocks();
    clearSignalVisualCache();
    vi.mocked(api.resolveMediaUrl).mockImplementation((base: string, path: string) => base + path);
  });

  function renderLead(onOpen = vi.fn()) {
    return render(<SignalCard apiBaseUrl="https://api.example.com" signal={signal} onOpen={onOpen} />);
  }

  it("shows only a shimmer while it's unknown whether a visual exists - no fallback flash", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    const { container } = renderLead();
    const visual = container.querySelector(".ss-visual")!;
    expect(visual).toHaveAttribute("data-state", "loading");
    expect(visual.querySelector(".ss-visual__shimmer")).not.toBeNull();
    expect(visual.querySelector(".ss-visual__fallback")).toBeNull();
  });

  it("lazy-loads its generated visual and keeps the shimmer until the image has loaded", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...signal,
      evidence: [],
      visual_status: "generated",
      visual_url: "/media/signals/hero.png",
    } as SignalDetail);

    const { container } = renderLead();

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "image"));
    const img = container.querySelector(".ss-visual__image") as HTMLImageElement;
    expect(img.src).toBe("https://api.example.com/media/signals/hero.png");
    expect(img).toHaveAttribute("loading", "lazy");
    expect(container.querySelector(".ss-visual__shimmer")).not.toBeNull();
    expect(img).not.toHaveClass("ss-visual__image--loaded");

    fireEvent.load(img);
    expect(img).toHaveClass("ss-visual__image--loaded");
    expect(container.querySelector(".ss-visual__shimmer")).toBeNull();
  });

  it("falls back to the category art when the detail request fails", async () => {
    vi.mocked(api.fetchSignalDetail).mockRejectedValue(new Error("boom"));
    const { container } = renderLead();
    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
  });

  it("is one labelled button exposing category + date as its description", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    renderLead();
    const button = screen.getByRole("button", { name: "Open signal: Signal hero" });
    expect(button).toHaveAccessibleDescription(/Published 1h ago.*AI Security/);
  });

  it("calls onOpen with just the id", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    const onOpen = vi.fn();
    renderLead(onOpen);
    fireEvent.click(screen.getByRole("button", { name: /Open signal/ }));
    expect(onOpen).toHaveBeenCalledWith("hero");
  });
});

describe("category chip sliding indicator", () => {
  function Bar({ category }: { category: string | null }) {
    return (
      <FilterBar
        category={category}
        subcategory={null}
        search=""
        isSearching={false}
        onCategoryChange={vi.fn()}
        onSubcategoryChange={vi.fn()}
        onSearchChange={vi.fn()}
        onClear={vi.fn()}
      />
    );
  }

  function stubChipBoxes() {
    const chips = screen.getAllByRole("button").filter((b) => b.classList.contains("ss-chip"));
    chips.forEach((chip, i) => {
      Object.defineProperty(chip, "offsetLeft", { configurable: true, value: 20 + i * 100 });
      Object.defineProperty(chip, "offsetWidth", { configurable: true, value: 60 + i * 5 });
    });
  }

  it("moves the single black indicator onto the newly active chip", () => {
    const { container, rerender } = render(<Bar category={null} />);
    stubChipBoxes();

    rerender(<Bar category="supply_chain" />); // 4th chip (index 3)

    const indicator = container.querySelector(".ss-chips__indicator") as HTMLElement;
    expect(container.querySelectorAll(".ss-chips__indicator")).toHaveLength(1);
    expect(indicator).toHaveAttribute("aria-hidden", "true");
    expect(indicator.style.left).toBe("320px");
    expect(indicator.style.width).toBe("75px");
    // The FLIP inversion has already been released: it's transitioning to rest.
    expect(indicator.style.transform).toBe("");
  });
});
