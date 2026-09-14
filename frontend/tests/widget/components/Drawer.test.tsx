import { render, screen, fireEvent } from "@testing-library/react";
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

    expect(screen.getByRole("dialog", { name: "Security Signals" })).toBeInTheDocument();
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
});
