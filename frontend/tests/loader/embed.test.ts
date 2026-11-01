import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  resolveConfigFromScriptElement,
  getDrawerLayout,
  isValidMessageFromWidget,
  createWidget,
  countNewSignals,
  formatBadgeCount,
  readLastVisit,
  LAST_VISIT_STORAGE_KEY,
  TOOLTIP_SEEN_STORAGE_KEY,
  UNREAD_FETCH_DELAY_MS,
  TOOLTIP_VISIBLE_MS,
  FIRST_VISIT_WINDOW_MS,
  WIGGLE_INTERVAL_MS,
} from "../../loader/embed.js";

describe("resolveConfigFromScriptElement", () => {
  it("defaults to bottom-right for a missing/invalid position", () => {
    const script = document.createElement("script");
    script.src = "https://cdn.example.com/embed.js";
    expect(resolveConfigFromScriptElement(script).position).toBe("bottom-right");

    script.dataset.position = "not-a-real-position";
    expect(resolveConfigFromScriptElement(script).position).toBe("bottom-right");
  });

  it("reads data-position, data-api-base, and data-widget-url", () => {
    const script = document.createElement("script");
    script.src = "https://cdn.example.com/embed.js";
    script.dataset.position = "top-left";
    script.dataset.apiBase = "https://api.example.com";
    script.dataset.widgetUrl = "https://widget.example.com/";

    const config = resolveConfigFromScriptElement(script);

    expect(config.position).toBe("top-left");
    expect(config.apiBase).toBe("https://api.example.com");
    expect(config.widgetUrl).toBe("https://widget.example.com/");
  });

  it("defaults widgetUrl to the script's own origin when not provided", () => {
    const script = document.createElement("script");
    script.src = "https://cdn.example.com/path/embed.js";

    const config = resolveConfigFromScriptElement(script);

    expect(config.widgetUrl).toBe("https://cdn.example.com/");
  });
});

describe("getDrawerLayout", () => {
  it("returns a full-screen layout below the mobile breakpoint", () => {
    const layout = getDrawerLayout("bottom-right", 375);
    expect(layout).toMatchObject({ top: "0", left: "0", right: "0", bottom: "0", width: "100%", height: "100%" });
  });

  it("widens the desktop panel while expanded, keeping its corner anchoring", () => {
    const expanded = getDrawerLayout("bottom-right", 1280, true);
    expect(expanded.width).toBe("min(720px, calc(100vw - 48px))");
    expect(expanded).toMatchObject({ bottom: "88px", right: "24px" });
    expect(getDrawerLayout("bottom-right", 1280, false).width).toBe("400px");
  });

  it("keeps the full-screen mobile layout even when expanded", () => {
    expect(getDrawerLayout("bottom-right", 375, true)).toMatchObject({ width: "100%", height: "100%" });
  });

  it("anchors a fixed-size panel per position on desktop widths", () => {
    expect(getDrawerLayout("bottom-right", 1280)).toMatchObject({ bottom: "88px", right: "24px" });
    expect(getDrawerLayout("bottom-left", 1280)).toMatchObject({ bottom: "88px", left: "24px" });
    expect(getDrawerLayout("top-right", 1280)).toMatchObject({ top: "24px", right: "24px" });
    expect(getDrawerLayout("top-left", 1280)).toMatchObject({ top: "24px", left: "24px" });
  });
});

describe("isValidMessageFromWidget", () => {
  const validData = { source: "security-signals-widget", type: "security-signals:close" };

  it("accepts a matching origin/source/shape", () => {
    const event = { origin: "https://widget.example", source: window, data: validData };
    expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(true);
  });

  it("rejects a mismatched origin", () => {
    const event = { origin: "https://evil.example", source: window, data: validData };
    expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(false);
  });

  it("rejects a mismatched source window", () => {
    const event = { origin: "https://widget.example", source: {}, data: validData };
    expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(false);
  });

  it("rejects a payload from a different message source tag", () => {
    const event = {
      origin: "https://widget.example",
      source: window,
      data: { source: "unrelated-widget", type: "security-signals:close" },
    };
    expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(false);
  });

  it("accepts the expand and collapse messages from its own iframe", () => {
    for (const type of ["security-signals:expand", "security-signals:collapse"]) {
      const event = {
        origin: "https://widget.example",
        source: window,
        data: { source: "security-signals-widget", type },
      };
      expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(true);
    }
  });

  it("rejects an unrecognized message type", () => {
    const event = {
      origin: "https://widget.example",
      source: window,
      data: { source: "security-signals-widget", type: "steal-cookies" },
    };
    expect(isValidMessageFromWidget(event as any, "https://widget.example", window)).toBe(false);
  });
});

describe("createWidget", () => {
  let widget: ReturnType<typeof createWidget>;

  afterEach(() => {
    widget?.destroy();
    document.body.innerHTML = "";
  });

  function build() {
    widget = createWidget(
      { widgetUrl: "https://widget.example.com/", apiBase: "https://api.example.com", position: "bottom-right" },
      document,
      window,
    );
    return widget;
  }

  it("renders a launcher button, closed by default", () => {
    build();
    const button = document.querySelector("button[aria-label='Open Threatline']");
    expect(button).not.toBeNull();
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(widget.isOpen()).toBe(false);
  });

  it("opens on first launcher click and creates the iframe with the right query params", () => {
    build();
    const button = document.querySelector("button[aria-label='Open Threatline']") as HTMLButtonElement;

    button.click();

    expect(widget.isOpen()).toBe(true);
    expect(button).toHaveAttribute("aria-expanded", "true");

    const iframe = document.querySelector("iframe") as HTMLIFrameElement;
    expect(iframe).not.toBeNull();
    const src = new URL(iframe.src);
    expect(src.origin).toBe("https://widget.example.com");
    expect(src.searchParams.get("apiBase")).toBe("https://api.example.com");
    expect(src.searchParams.get("parentOrigin")).toBe(window.location.origin);
  });

  it("toggles closed on a second launcher click", () => {
    build();
    const button = document.querySelector("button[aria-label='Open Threatline']") as HTMLButtonElement;

    button.click();
    button.click();

    expect(widget.isOpen()).toBe(false);
  });

  it("closes when clicking outside the launcher/drawer", () => {
    build();
    widget.open();
    expect(widget.isOpen()).toBe(true);

    document.body.click();

    expect(widget.isOpen()).toBe(false);
  });

  it("closes on Escape", () => {
    build();
    widget.open();

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));

    expect(widget.isOpen()).toBe(false);
  });

  it("closes when a valid 'close' message arrives from its own iframe", () => {
    build();
    widget.open();
    const iframe = document.querySelector("iframe") as HTMLIFrameElement;

    const event = new MessageEvent("message", {
      data: { source: "security-signals-widget", type: "security-signals:close" },
      origin: "https://widget.example.com",
      source: iframe.contentWindow as Window,
    });
    window.dispatchEvent(event);

    expect(widget.isOpen()).toBe(false);
  });

  it("ignores a 'close' message from an unexpected origin", () => {
    build();
    widget.open();
    const iframe = document.querySelector("iframe") as HTMLIFrameElement;

    const event = new MessageEvent("message", {
      data: { source: "security-signals-widget", type: "security-signals:close" },
      origin: "https://attacker.example",
      source: iframe.contentWindow as Window,
    });
    window.dispatchEvent(event);

    expect(widget.isOpen()).toBe(true);
  });

  it("ignores a message from a source window that isn't its iframe", () => {
    build();
    widget.open();

    const event = new MessageEvent("message", {
      data: { source: "security-signals-widget", type: "security-signals:close" },
      origin: "https://widget.example.com",
      source: window, // top window, not the iframe's contentWindow
    });
    window.dispatchEvent(event);

    expect(widget.isOpen()).toBe(true);
  });

  it("destroy() removes its DOM nodes", () => {
    build();
    widget.open();
    widget.destroy();

    expect(document.querySelector("button[aria-label='Open Threatline']")).toBeNull();
    expect(document.querySelector("iframe")).toBeNull();
  });
});

describe("countNewSignals", () => {
  const now = Date.parse("2026-11-01T12:00:00Z");
  const at = (iso: string) => ({ published_at: iso });

  it("counts only signals published after the last visit", () => {
    const lastVisit = Date.parse("2026-11-01T08:00:00Z");
    const signals = [at("2026-11-01T11:00:00Z"), at("2026-11-01T09:00:00Z"), at("2026-10-31T09:00:00Z")];
    expect(countNewSignals(signals, lastVisit, now)).toBe(2);
  });

  it("on a first visit (no last visit) counts only the recent window, not everything", () => {
    const signals = [at("2026-10-31T12:00:00Z"), at(new Date(now - FIRST_VISIT_WINDOW_MS - 1000).toISOString())];
    expect(countNewSignals(signals, null, now)).toBe(1);
  });

  it("ignores entries without a parseable published_at and non-array input", () => {
    expect(countNewSignals([{ published_at: null }, {}, null, at("garbage")], 0, now)).toBe(0);
    expect(countNewSignals({ not: "an array" }, 0, now)).toBe(0);
  });
});

describe("formatBadgeCount", () => {
  it("caps the badge at 9+", () => {
    expect(formatBadgeCount(3)).toBe("3");
    expect(formatBadgeCount(9)).toBe("9");
    expect(formatBadgeCount(10)).toBe("9+");
  });
});

describe("launcher", () => {
  let widget: ReturnType<typeof createWidget> | undefined;
  const config = { widgetUrl: "https://widget.example.com/", apiBase: "https://api.example.com", position: "bottom-right" };

  function stubFetch(signals: unknown[]) {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve(signals) }));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  async function runUnreadCheck() {
    await vi.advanceTimersByTimeAsync(UNREAD_FETCH_DELAY_MS);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
  }

  const recent = (minutesAgo: number) => ({ published_at: new Date(Date.now() - minutesAgo * 60_000).toISOString() });

  beforeEach(() => {
    vi.useFakeTimers();
    window.localStorage.clear();
  });

  afterEach(() => {
    widget?.destroy();
    widget = undefined;
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    window.localStorage.clear();
    document.body.innerHTML = "";
  });

  const button = () => document.querySelector(".ssl-btn") as HTMLButtonElement;
  const badge = () => document.querySelector(".ssl-badge") as HTMLElement;
  const tip = () => document.querySelector(".ssl-tip") as HTMLElement;

  it("morphs to a close control while open: label and expanded state flip", () => {
    stubFetch([]);
    widget = createWidget(config, document, window);

    button().click();
    expect(button()).toHaveAttribute("aria-label", "Close Threatline");
    expect(button()).toHaveAttribute("aria-expanded", "true");
    expect(button().querySelector(".ssl-icon--open")).not.toBeNull();
    expect(button().querySelector(".ssl-icon--close")).not.toBeNull();

    button().click();
    expect(button()).toHaveAttribute("aria-label", "Open Threatline");
    expect(button()).toHaveAttribute("aria-expanded", "false");
  });

  it("injects its stylesheet once and removes it on destroy", () => {
    stubFetch([]);
    widget = createWidget(config, document, window);
    expect(document.querySelectorAll("#ss-launcher-styles")).toHaveLength(1);

    widget.destroy();
    widget = undefined;
    expect(document.getElementById("ss-launcher-styles")).toBeNull();
  });

  it("waits before fetching, then calls only the public published endpoint", async () => {
    const fetchMock = stubFetch([]);
    widget = createWidget(config, document, window);
    expect(fetchMock).not.toHaveBeenCalled();

    await runUnreadCheck();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.origin + url.pathname).toBe("https://api.example.com/api/v1/signals/published");
    expect(url.searchParams.get("sort")).toBe("recent");
    expect((fetchMock.mock.calls[0][1] as RequestInit).credentials).toBe("omit");
  });

  it("shows an unread badge for signals newer than the stored last visit", async () => {
    window.localStorage.setItem(LAST_VISIT_STORAGE_KEY, String(Date.now() - 60 * 60_000));
    stubFetch([recent(5), recent(30), recent(120)]);
    widget = createWidget(config, document, window);

    await runUnreadCheck();

    expect(badge()).toHaveAttribute("data-visible", "true");
    expect(badge()).toHaveTextContent("2");
    expect(button()).toHaveAttribute("aria-label", "Open Threatline, 2 new security signals");
  });

  it("opening clears the badge and records this visit", async () => {
    window.localStorage.setItem(LAST_VISIT_STORAGE_KEY, String(Date.now() - 60 * 60_000));
    stubFetch([recent(5)]);
    widget = createWidget(config, document, window);
    await runUnreadCheck();
    expect(badge()).toHaveAttribute("data-visible", "true");

    widget.open();
    widget.close();

    expect(badge()).toHaveAttribute("data-visible", "false");
    expect(button()).toHaveAttribute("aria-label", "Open Threatline");
    expect(readLastVisit(window)).toBe(Date.now());
  });

  it("first visit: slides out a tooltip that auto-hides after 5s, and only ever once", async () => {
    stubFetch([recent(10), recent(60)]);
    widget = createWidget(config, document, window);
    await runUnreadCheck();

    expect(tip()).toHaveAttribute("data-visible", "true");
    expect(tip()).toHaveAttribute("role", "status");
    expect(tip()).toHaveTextContent("2 new security signals");
    expect(window.localStorage.getItem(TOOLTIP_SEEN_STORAGE_KEY)).toBe("1");

    vi.advanceTimersByTime(TOOLTIP_VISIBLE_MS);
    expect(tip()).toHaveAttribute("data-visible", "false");

    widget.destroy();
    widget = createWidget(config, document, window);
    await runUnreadCheck();
    expect(tip()).toHaveAttribute("data-visible", "false");
  });

  it("does not show the first-visit tooltip to a returning visitor", async () => {
    window.localStorage.setItem(LAST_VISIT_STORAGE_KEY, String(Date.now() - 60 * 60_000));
    stubFetch([recent(5)]);
    widget = createWidget(config, document, window);
    await runUnreadCheck();

    expect(tip()).toHaveAttribute("data-visible", "false");
  });

  it("keeps working when localStorage throws", async () => {
    vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    stubFetch([recent(5)]);
    widget = createWidget(config, document, window);

    await runUnreadCheck();
    expect(badge()).toHaveTextContent("1");
    expect(() => widget!.open()).not.toThrow();
    expect(widget.isOpen()).toBe(true);
  });

  it("shows no badge when the request fails", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("CORS"))));
    widget = createWidget(config, document, window);

    await runUnreadCheck();

    expect(badge()).toHaveAttribute("data-visible", "false");
    expect(button()).toHaveAttribute("aria-label", "Open Threatline");
  });

  it("never fetches without an apiBase, or after an early destroy", async () => {
    const fetchMock = stubFetch([recent(5)]);

    widget = createWidget({ ...config, apiBase: "" }, document, window);
    await runUnreadCheck();
    widget.destroy();

    widget = createWidget(config, document, window);
    widget.destroy();
    widget = undefined;
    await runUnreadCheck();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still morphs and hides its badge correctly with the stylesheet blocked (strict host CSP)", () => {
    stubFetch([]);
    widget = createWidget(config, document, window);
    document.getElementById("ss-launcher-styles")!.remove();

    const openIcon = document.querySelector(".ssl-icon--open") as SVGElement;
    const closeIcon = document.querySelector(".ssl-icon--close") as SVGElement;
    expect(closeIcon.style.opacity).toBe("0");
    expect(openIcon.style.opacity).toBe("1");
    expect(badge().style.opacity).toBe("0");
    expect(tip().style.opacity).toBe("0");

    widget.open();
    expect(closeIcon.style.opacity).toBe("1");
    expect(openIcon.style.opacity).toBe("0");
  });

  it("forwards the loader script's nonce to its injected stylesheet", () => {
    stubFetch([]);
    const script = document.createElement("script");
    script.src = "https://cdn.example.com/embed.js";
    script.nonce = "abc123";
    const resolved = resolveConfigFromScriptElement(script);
    expect(resolved.nonce).toBe("abc123");

    widget = createWidget({ ...config, nonce: resolved.nonce }, document, window);
    expect((document.getElementById("ss-launcher-styles") as HTMLStyleElement).nonce).toBe("abc123");
  });

  it("wiggles every ~10s while unread signals wait, and stops once opened", async () => {
    window.localStorage.setItem(LAST_VISIT_STORAGE_KEY, String(Date.now() - 60 * 60_000));
    stubFetch([recent(5)]);
    widget = createWidget(config, document, window);
    await runUnreadCheck();
    expect(button()).not.toHaveClass("ssl-btn--wiggle");

    vi.advanceTimersByTime(WIGGLE_INTERVAL_MS);
    expect(button()).toHaveClass("ssl-btn--wiggle");
    vi.advanceTimersByTime(700);
    expect(button()).not.toHaveClass("ssl-btn--wiggle");

    widget.open();
    widget.close(); // opening marked the visit: no unread left
    vi.advanceTimersByTime(WIGGLE_INTERVAL_MS * 3);
    expect(button()).not.toHaveClass("ssl-btn--wiggle");
  });

  it("never wiggles with nothing unread", async () => {
    window.localStorage.setItem(LAST_VISIT_STORAGE_KEY, String(Date.now()));
    stubFetch([recent(60)]);
    widget = createWidget(config, document, window);
    await runUnreadCheck();
    vi.advanceTimersByTime(WIGGLE_INTERVAL_MS * 2);
    expect(button()).not.toHaveClass("ssl-btn--wiggle");
  });

  it("names itself Threatline", () => {
    stubFetch([]);
    widget = createWidget(config, document, window);
    expect(button()).toHaveAttribute("aria-label", "Open Threatline");
    widget.open();
    expect(document.querySelector("iframe")).toHaveAttribute("title", "Threatline");
  });

  it("anchors the tooltip to the right of a left-positioned launcher", () => {
    stubFetch([]);
    widget = createWidget({ ...config, position: "bottom-left" }, document, window);
    expect(document.querySelector(".ssl-root")).toHaveClass("ssl-root--left");
  });
});
