import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DECK_HINT_STORAGE_KEY, SignalDeck } from "../../../src/widget/components/SignalDeck";
import type { SignalSummary } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

const STEP = 300;

function signals(n: number): SignalSummary[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `s${i + 1}`,
    title: `Signal ${i + 1}`,
    summary: "",
    security_impact: "",
    principle: "",
    recommended_action: "",
    published_at: new Date().toISOString(),
    categories: [],
    public_categories: ["ransomware"],
  }));
}

function renderDeck(n = 3, props: Partial<React.ComponentProps<typeof SignalDeck>> = {}) {
  const utils = render(
    <SignalDeck
      apiBaseUrl=""
      signals={signals(n)}
      onOpenSignal={vi.fn()}
      hasMore={false}
      loadingMore={false}
      onLoadMore={vi.fn()}
      {...props}
    />,
  );
  const track = utils.container.querySelector(".ss-deck__track") as HTMLElement;
  const scrollTo = vi.fn();
  track.scrollTo = scrollTo as unknown as typeof track.scrollTo;
  // jsdom has no layout: give the slides a real geometry (snap points every STEP px).
  utils.container.querySelectorAll<HTMLElement>(".ss-deck__slide").forEach((slide, i) => {
    Object.defineProperty(slide, "offsetLeft", { configurable: true, value: 20 + i * STEP });
    Object.defineProperty(slide, "offsetWidth", { configurable: true, value: STEP - 12 });
  });
  return { ...utils, track, scrollTo };
}

// Real rAF is asynchronous - queue frames and flush them explicitly.
let frames: FrameRequestCallback[] = [];
function flushFrames() {
  act(() => {
    const pending = frames;
    frames = [];
    pending.forEach((cb) => cb(0));
  });
}

/** The deck's only position read-out is the screen-reader announcement. */
const position = () => screen.getByText(/^Signal \d+ of \d+\+?$/);

describe("SignalDeck", () => {
  beforeEach(() => {
    window.localStorage.setItem(DECK_HINT_STORAGE_KEY, "1"); // most tests: returning visitor
    frames = [];
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => frames.push(cb));
    vi.stubGlobal("cancelAnimationFrame", () => undefined);
  });

  afterEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("is a labelled carousel of 'N of M' slides", () => {
    renderDeck(3);
    const deck = screen.getByRole("region", { name: "Security signals" });
    expect(deck).toHaveAttribute("aria-roledescription", "carousel");
    const slides = within(deck).getAllByRole("group");
    expect(slides.map((s) => s.getAttribute("aria-label"))).toEqual(["1 of 3", "2 of 3", "3 of 3"]);
    for (const s of slides) expect(s).toHaveAttribute("aria-roledescription", "slide");
  });

  it("shows no visible counter or dots, only a polite screen-reader position", () => {
    const { container } = renderDeck(3);
    expect(container.querySelector(".ss-deck__dots, .ss-deck__dot, .ss-deck__counter")).toBeNull();
    expect(screen.queryByText("1 / 3")).toBeNull();
    const live = position();
    expect(live).toHaveTextContent("Signal 1 of 3");
    expect(live).toHaveClass("ss-visually-hidden");
    expect(live).toHaveAttribute("aria-live", "polite");
  });

  it("arrows smooth-scroll one card and disable at the ends", () => {
    const { scrollTo } = renderDeck(3);
    const prev = screen.getByRole("button", { name: "Previous signal" });
    const next = screen.getByRole("button", { name: "Next signal" });
    expect(prev).toBeDisabled();

    fireEvent.click(next);
    expect(scrollTo).toHaveBeenLastCalledWith({ left: STEP, behavior: "smooth" });
    expect(position()).toHaveTextContent("Signal 2 of 3");

    fireEvent.click(next);
    // Disabled at the end, but still rendered - the row never shifts.
    expect(next).toBeDisabled();
    expect(next).toBeInTheDocument();
    expect(prev).not.toBeDisabled();
  });

  it("← → keys move the deck when it has focus, and focus follows the card", () => {
    renderDeck(3);
    const first = screen.getByRole("button", { name: "Open signal: Signal 1" });
    first.focus();

    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(position()).toHaveTextContent("Signal 2 of 3");
    expect(screen.getByRole("button", { name: "Open signal: Signal 2" })).toHaveFocus();

    fireEvent.keyDown(screen.getByRole("region", { name: "Security signals" }), { key: "ArrowLeft" });
    expect(position()).toHaveTextContent("Signal 1 of 3");
  });

  it("follows native swiping: the active card and neighbour scale/opacity track the scroll position", () => {
    const { container, track } = renderDeck(3);
    track.scrollLeft = 2 * STEP;
    fireEvent.scroll(track);
    fireEvent.scroll(track); // a burst of scroll events = one paint per frame
    flushFrames();

    expect(position()).toHaveTextContent("Signal 3 of 3");
    const frameEls = Array.from(container.querySelectorAll<HTMLElement>(".ss-deck__frame"));
    expect(frameEls[2].style.transform).toBe("scale(1)");
    expect(frameEls[2].style.opacity).toBe("1");
    expect(frameEls[1].style.transform).toBe("scale(0.94)");
    expect(frameEls[1].style.opacity).toBe("0.6");

    track.scrollLeft = 1.5 * STEP; // mid-swipe: halfway between
    fireEvent.scroll(track);
    flushFrames();
    expect(frameEls[1].style.transform).toBe("scale(0.97)");
    expect(frameEls[1].style.opacity).toBe("0.8");
  });

  it("under reduced motion: no scaling, and arrows jump instantly", () => {
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("reduce"), addEventListener() {}, removeEventListener() {} }));
    const { container, track, scrollTo } = renderDeck(3);
    track.scrollLeft = STEP;
    fireEvent.scroll(track);
    flushFrames();
    const frameEls = container.querySelectorAll<HTMLElement>(".ss-deck__frame");
    expect(frameEls[0].style.transform).toBe("");

    fireEvent.click(screen.getByRole("button", { name: "Next signal" }));
    expect(scrollTo).toHaveBeenLastCalledWith({ left: 2 * STEP, behavior: "auto" });
  });

  it("never moves on its own (no autoplay)", () => {
    vi.useFakeTimers();
    const { scrollTo } = renderDeck(3);
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(scrollTo).not.toHaveBeenCalled();
    expect(position()).toHaveTextContent("Signal 1 of 3");
  });

  it("ends with a Load more slide when more pages exist", () => {
    const onLoadMore = vi.fn();
    renderDeck(2, { hasMore: true, onLoadMore });
    expect(position()).toHaveTextContent("Signal 1 of 2+");
    fireEvent.click(screen.getByRole("button", { name: "Next signal" }));
    // Not disabled on the last signal: the Load more slide is next.
    expect(screen.getByRole("button", { name: "Next signal" })).not.toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(onLoadMore).toHaveBeenCalled();
  });

  describe("first-visit swipe hint", () => {
    it("nudges + labels once, then never again", () => {
      vi.useFakeTimers();
      window.localStorage.clear();
      const first = renderDeck(3);
      const deck = first.container.querySelector(".ss-deck")!;
      expect(deck).toHaveClass("ss-deck--hint");
      expect(first.container.querySelector(".ss-deck__hint--visible")).toHaveTextContent("Swipe →");
      expect(window.localStorage.getItem(DECK_HINT_STORAGE_KEY)).toBe("1");

      act(() => {
        vi.advanceTimersByTime(3000);
      });
      expect(deck).not.toHaveClass("ss-deck--hint");
      expect(first.container.querySelector(".ss-deck__hint--visible")).toBeNull();
      first.unmount();

      const again = renderDeck(3);
      expect(again.container.querySelector(".ss-deck--hint")).toBeNull();
      expect(again.container.querySelector(".ss-deck__hint")).toBeNull();
    });

    it("is skipped when storage is unavailable (never shown on every visit)", () => {
      vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
        throw new DOMException("blocked", "SecurityError");
      });
      const { container } = renderDeck(3);
      expect(container.querySelector(".ss-deck--hint")).toBeNull();
      vi.restoreAllMocks();
    });
  });
});
