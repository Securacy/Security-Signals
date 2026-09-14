import { describe, it, expect, vi, afterEach } from "vitest";
import { sendToParent, isValidIncomingMessage, SECURITY_SIGNALS_MESSAGE_SOURCE } from "../../src/widget/messaging";

describe("messaging", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("sendToParent", () => {
    it("does nothing when not embedded (window.parent === window)", () => {
      const postMessageSpy = vi.spyOn(window, "postMessage");
      sendToParent("security-signals:ready", null);
      expect(postMessageSpy).not.toHaveBeenCalled();
    });

    it("targets the known parent origin precisely, not '*', when one is configured", () => {
      const fakeParent = { postMessage: vi.fn() };
      vi.stubGlobal("parent", fakeParent);

      sendToParent("security-signals:close", "https://host.example");

      expect(fakeParent.postMessage).toHaveBeenCalledWith(
        { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" },
        "https://host.example",
      );
      vi.unstubAllGlobals();
    });

    it("falls back to '*' only when no parent origin is known", () => {
      const fakeParent = { postMessage: vi.fn() };
      vi.stubGlobal("parent", fakeParent);

      sendToParent("security-signals:ready", null);

      expect(fakeParent.postMessage).toHaveBeenCalledWith(expect.anything(), "*");
      vi.unstubAllGlobals();
    });
  });

  describe("isValidIncomingMessage", () => {
    const validPayload = { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "security-signals:close" };

    function makeEvent(overrides: Partial<MessageEvent> & { data?: any } = {}): MessageEvent {
      return {
        origin: "https://widget.example",
        source: window,
        data: validPayload,
        ...overrides,
      } as unknown as MessageEvent;
    }

    it("accepts a message with matching origin, source, and shape", () => {
      const event = makeEvent();
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(true);
    });

    it("rejects a message from an unexpected origin", () => {
      const event = makeEvent({ origin: "https://evil.example" });
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(false);
    });

    it("rejects a message from an unexpected source window", () => {
      const otherWindow = {} as Window;
      const event = makeEvent({ source: otherWindow });
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(false);
    });

    it("rejects a message with no data", () => {
      const event = makeEvent({ data: null });
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(false);
    });

    it("rejects a message with the wrong source tag", () => {
      const event = makeEvent({ data: { source: "some-other-widget", type: "security-signals:close" } });
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(false);
    });

    it("rejects a message with an unrecognized type", () => {
      const event = makeEvent({ data: { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type: "do-something-else" } });
      expect(isValidIncomingMessage(event, "https://widget.example", window)).toBe(false);
    });
  });
});
