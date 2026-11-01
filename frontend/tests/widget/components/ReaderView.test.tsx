import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SignalDetail } from "../../../src/widget/components/SignalDetail";
import { Drawer } from "../../../src/widget/components/Drawer";
import * as api from "../../../src/widget/api";
import type { SignalDetail as SignalDetailType, SignalSummary } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

const summary: SignalSummary = {
  id: "sig-1",
  title: "OAuth token replay",
  summary: "What happened text.",
  security_impact: "Why it matters text.",
  principle: "Least Privilege",
  recommended_action: "Rotate tokens.",
  published_at: new Date().toISOString(),
  categories: [],
  public_categories: ["cloud_identity_security"],
};

const detail: SignalDetailType = {
  ...summary,
  evidence: [
    { id: "ev-1", source_url: "https://www.example.com/a", source_title: "Vendor advisory", excerpt: "", created_at: null },
  ],
  visual_status: "none",
  visual_url: null,
};

function rect(left: number, top: number, width: number, height: number): DOMRect {
  return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) } as DOMRect;
}

describe("reader view", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.resolveMediaUrl).mockImplementation((base: string, path: string) => base + path);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("paints the hero from the feed preview before the detail request resolves", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="t" preview={summary} />);

    expect(screen.getByRole("heading", { name: "OAuth token replay" })).toBeInTheDocument();
    expect(screen.getByLabelText("Loading signal")).toBeInTheDocument();
  });

  it("ignores a preview for a different signal", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="other" titleId="t" preview={summary} />,
    );
    expect(screen.queryByRole("heading", { name: "OAuth token replay" })).toBeNull();
  });

  it("keeps the hero image clear: the headline sits below it", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="t" preview={summary} />,
    );
    const title = screen.getByRole("heading", { name: "OAuth token replay" });
    expect(container.querySelector(".ss-reader__media")).not.toContainElement(title);
  });

  it("maps fields to off-white cards in order, tiles cycling lavender/butter/mint, staggered", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(detail);
    const { container } = render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="t" />);
    await screen.findByText("What happened text.");

    const cards = Array.from(container.querySelectorAll<HTMLElement>(".ss-dcard"));
    expect(cards.map((c) => c.querySelector("h3")!.textContent)).toEqual([
      "What happened",
      "Why it matters",
      "What to do",
      "Design principle",
    ]);
    expect(cards.map((c) => c.style.getPropertyValue("--i"))).toEqual(["0", "1", "2", "3"]);
    for (const card of cards) expect(card.querySelector(".ss-dcard__tile svg")).not.toBeNull();
    expect(cards.map((c) => c.querySelector(".ss-dcard__tile")!.className.match(/--(\w+)/)![1])).toEqual([
      "lavender",
      "butter",
      "mint",
      "lavender",
    ]);
    expect(cards[2]).toHaveTextContent("Rotate tokens.");
  });

  it("lists sources as small cards with an initial thumbnail (no fetched favicon)", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(detail);
    const { container } = render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="t" />);
    await screen.findByText("Vendor advisory");

    const source = container.querySelector(".ss-source")!;
    expect(source.querySelector(".ss-source__thumb")).toHaveTextContent("E");
    expect(source.querySelector("img")).toBeNull();
    expect(screen.getByRole("heading", { name: "Sources" })).toBeInTheDocument();
  });

  it("expands the hero from the tapped feed image (FLIP)", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue(rect(0, 0, 400, 300));

    const { container } = render(
      <SignalDetail
        apiBaseUrl="https://api.example.com"
        signalId="sig-1"
        titleId="t"
        preview={summary}
        originRect={rect(300, 200, 72, 72)}
      />,
    );

    const media = container.querySelector(".ss-reader__media") as HTMLElement;
    expect(media.dataset.flip).toBe("true");
    expect(media.style.transition).toContain("transform");
    expect(media.style.transform).toBe(""); // released to animate back to its natural box
  });

  it("skips the FLIP entirely under reduced motion", () => {
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("reduce"), addEventListener() {}, removeEventListener() {} }));
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue(rect(0, 0, 400, 300));

    const { container } = render(
      <SignalDetail
        apiBaseUrl="https://api.example.com"
        signalId="sig-1"
        titleId="t"
        preview={summary}
        originRect={rect(300, 200, 72, 72)}
      />,
    );

    expect((container.querySelector(".ss-reader__media") as HTMLElement).dataset.flip).toBeUndefined();
  });
});

describe("Drawer shell", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.stubGlobal("parent", { postMessage: vi.fn() });
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("reduce"), addEventListener() {}, removeEventListener() {} }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the Threatline wordmark and exactly one watermark node", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    const { container } = render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin={null} />);

    expect(screen.getByRole("heading", { level: 1, name: "Threatline" })).toBeInTheDocument();
    const marks = container.querySelectorAll(".ss-watermark");
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveAttribute("aria-hidden", "true");
    const bg = (marks[0] as HTMLElement).style.backgroundImage;
    expect(bg).toMatch(/^url\("data:image\/svg\+xml,/);
    expect(decodeURIComponent(bg)).toContain('fill="#D9A800"');
    expect(decodeURIComponent(bg)).toContain('fill="#801D91"');
    // The wallpaper lives outside the scrolling body, so it doesn't scroll.
    expect(container.querySelector(".ss-drawer__body")!.contains(marks[0])).toBe(false);
    await screen.findByText("No published signals yet");
  });

  it("hands the tapped row's summary to the reader, so its title shows before the detail loads", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [{ ...summary, id: "lead", title: "Lead story" }, summary],
      hasMore: false,
    });
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));
    render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin={null} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open signal: OAuth token replay" }));

    const reader = await screen.findByRole("dialog", { name: "OAuth token replay" });
    expect(reader).toBeInTheDocument();
    await waitFor(() => expect(api.fetchSignalDetail).toHaveBeenCalledWith("https://api.example.com", "sig-1"));
  });
});
