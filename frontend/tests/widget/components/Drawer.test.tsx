import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Drawer } from "../../../src/widget/components/Drawer";
import * as api from "../../../src/widget/api";
import { SECURITY_SIGNALS_MESSAGE_SOURCE } from "../../../src/widget/messaging";

vi.mock("../../../src/widget/api");

describe("Drawer", () => {
  let fakeParent: { postMessage: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    fakeParent = { postMessage: vi.fn() };
    vi.stubGlobal("parent", fakeParent);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it("renders the header and feed", () => {
    render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin="https://host.example" />);

    expect(screen.getByRole("dialog", { name: "Cyberscope" })).toBeInTheDocument();
  });

  it("sends a 'ready' message to the parent on mount, targeted at the known parent origin", () => {
    render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin="https://host.example" />);

    expect(fakeParent.postMessage).toHaveBeenCalledWith(
      { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:ready" },
      "https://host.example",
    );
  });

  it("sends a 'close' message when the close button is clicked", () => {
    render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin="https://host.example" />);
    fakeParent.postMessage.mockClear();

    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(fakeParent.postMessage).toHaveBeenCalledWith(
      { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
      "https://host.example",
    );
  });

  it("sends a 'close' message when Escape is pressed", () => {
    render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin="https://host.example" />);
    fakeParent.postMessage.mockClear();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(fakeParent.postMessage).toHaveBeenCalledWith(
      { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
      "https://host.example",
    );
  });

  describe("expanded reading view", () => {
    const summaryCard = {
      id: "sig-1",
      title: "Critical Apache RCE disclosed",
      summary: "What happened text.",
      security_impact: "Why it matters text.",
      principle: "Defense in depth",
      recommended_action: "Patch immediately.",
      published_at: "2026-10-01T00:00:00Z",
      categories: [],
      public_categories: ["product_security"],
    };
    const detail = {
      ...summaryCard,
      evidence: [],
      visual_status: "none",
      visual_url: null,
    };

    function stubReducedMotion(matches: boolean) {
      vi.stubGlobal(
        "matchMedia",
        vi.fn((query: string) => ({
          matches: query.includes("reduce") ? matches : false,
          media: query,
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
        })),
      );
    }

    async function renderWithOneSignal() {
      vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [summaryCard], hasMore: false });
      vi.mocked(api.fetchSignalDetail).mockResolvedValue(detail);
      render(<Drawer apiBaseUrl="https://api.example.com" parentOrigin="https://host.example" />);
      const card = await screen.findByRole("button", { name: "Open signal: Critical Apache RCE disclosed" });
      return card;
    }

    it("opens the reader as a modal dialog labelled by the signal title and tells the parent to expand", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      fakeParent.postMessage.mockClear();

      fireEvent.click(card);

      const reader = await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      expect(reader).toHaveAttribute("aria-modal", "true");
      expect(fakeParent.postMessage).toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:expand" },
        "https://host.example",
      );
    });

    it("keeps the feed mounted underneath and hides it from assistive tech while the reader is open", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();

      fireEvent.click(card);

      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      expect(document.querySelector(".ss-drawer__body")).toHaveAttribute("aria-hidden", "true");
      expect(card).toBeInTheDocument();
    });

    it("moves focus into the reader on open and returns focus to the card on close", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      card.focus();
      fireEvent.click(card);

      const reader = await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      expect(reader).toHaveFocus();

      fireEvent.click(screen.getByRole("button", { name: "Close signal" }));

      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull());
      expect(card).toHaveFocus();
    });

    it("the close button returns to the feed and tells the parent to collapse, without closing the widget", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      fireEvent.click(card);
      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      fakeParent.postMessage.mockClear();

      fireEvent.click(screen.getByRole("button", { name: "Close signal" }));

      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull());
      expect(fakeParent.postMessage).toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:collapse" },
        "https://host.example",
      );
      expect(fakeParent.postMessage).not.toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
        "https://host.example",
      );
    });

    it("Escape closes only the reader while it is open", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      fireEvent.click(card);
      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      fakeParent.postMessage.mockClear();

      fireEvent.keyDown(document, { key: "Escape" });

      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull());
      expect(fakeParent.postMessage).not.toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
        "https://host.example",
      );
    });

    it("a second Escape, once the reader is closed, closes the whole widget", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      fireEvent.click(card);
      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });
      fireEvent.keyDown(document, { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull());
      fakeParent.postMessage.mockClear();

      fireEvent.keyDown(document, { key: "Escape" });

      expect(fakeParent.postMessage).toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
        "https://host.example",
      );
    });

    it("clicking the backdrop closes the reader", async () => {
      stubReducedMotion(true);
      const card = await renderWithOneSignal();
      fireEvent.click(card);
      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });

      fireEvent.click(document.querySelector(".ss-reader-backdrop") as HTMLElement);

      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull());
    });

    it("plays the exit animation before unmounting when motion is allowed", async () => {
      stubReducedMotion(false);
      const card = await renderWithOneSignal();
      fireEvent.click(card);
      await screen.findByRole("dialog", { name: "Critical Apache RCE disclosed" });

      fireEvent.click(screen.getByRole("button", { name: "Close signal" }));

      expect(document.querySelector(".ss-reader-layer--closing")).not.toBeNull();
      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Critical Apache RCE disclosed" })).toBeNull(), {
        timeout: 1000,
      });
    });
  });
});
