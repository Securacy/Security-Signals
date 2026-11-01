import { act, render } from "@testing-library/react";
import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import { SignalCard } from "../../../src/widget/components/SignalCard";
import * as api from "../../../src/widget/api";
import { clearSignalVisualCache } from "../../../src/widget/signalVisual";
import { PREFETCH_MARGIN } from "../../../src/widget/inView";
import type { SignalSummary } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

/** Minimal IntersectionObserver stand-in: records observed elements per
 * rootMargin and lets a test "scroll" chosen elements into view. */
class FakeObserver {
  static instances: FakeObserver[] = [];
  observed = new Set<Element>();
  constructor(
    private readonly callback: IntersectionObserverCallback,
    readonly options: IntersectionObserverInit = {},
  ) {
    FakeObserver.instances.push(this);
  }
  observe(el: Element) {
    this.observed.add(el);
  }
  unobserve(el: Element) {
    this.observed.delete(el);
  }
  disconnect() {
    this.observed.clear();
  }
  enter(elements: Element[]) {
    const entries = elements.map((target) => ({ target, isIntersecting: true }) as IntersectionObserverEntry);
    this.callback(entries, this as unknown as IntersectionObserver);
  }
  static owning(el: Element) {
    return FakeObserver.instances.filter((o) => o.observed.has(el));
  }
}

function signal(id: string): SignalSummary {
  return {
    id,
    title: `Signal ${id}`,
    summary: "",
    security_impact: "",
    principle: "",
    recommended_action: "",
    published_at: new Date().toISOString(),
    categories: [],
    public_categories: ["supply_chain"],
  };
}

describe("card visual prefetch (IntersectionObserver)", () => {
  beforeAll(() => {
    vi.stubGlobal("IntersectionObserver", FakeObserver);
  });

  beforeEach(() => {
    vi.mocked(api.fetchSignalDetail).mockReset();
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    clearSignalVisualCache();
  });

  it("only asks for a card's visual once it nears its scroll root", () => {
    const { container } = render(<SignalCard apiBaseUrl="https://api.example.com" signal={signal("c")} onOpen={vi.fn()} />);
    const card = container.querySelector(".ss-card")!;
    expect(api.fetchSignalDetail).not.toHaveBeenCalled();
    const [observer] = FakeObserver.owning(card);
    expect(observer.options.rootMargin).toBe(PREFETCH_MARGIN);

    act(() => observer.enter([card]));

    expect(api.fetchSignalDetail).toHaveBeenCalledWith("https://api.example.com", "c");
  });

  it("observes against the nearest scroll container (the deck track), not the viewport", () => {
    const { container } = render(
      <div data-scroll-root className="outer">
        <div data-scroll-root className="track">
          <SignalCard apiBaseUrl="https://api.example.com" signal={signal("f")} onOpen={vi.fn()} />
        </div>
      </div>,
    );
    const card = container.querySelector(".ss-card")!;
    const owning = FakeObserver.owning(card);
    expect(owning).toHaveLength(1);
    expect(owning[0].options.root).toBe(container.querySelector(".track"));
  });

  it("stops observing when the card unmounts", () => {
    const { container, unmount } = render(
      <SignalCard apiBaseUrl="https://api.example.com" signal={signal("d")} onOpen={vi.fn()} />,
    );
    const card = container.querySelector(".ss-card")!;
    expect(FakeObserver.owning(card)).toHaveLength(1);
    unmount();
    expect(FakeObserver.owning(card)).toHaveLength(0);
  });
});
