import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  resolveConfigFromScriptElement,
  getDrawerLayout,
  isValidMessageFromWidget,
  createWidget,
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
    const button = document.querySelector("button[aria-label='Open Cyberscope']");
    expect(button).not.toBeNull();
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(widget.isOpen()).toBe(false);
  });

  it("opens on first launcher click and creates the iframe with the right query params", () => {
    build();
    const button = document.querySelector("button[aria-label='Open Cyberscope']") as HTMLButtonElement;

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
    const button = document.querySelector("button[aria-label='Open Cyberscope']") as HTMLButtonElement;

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

    expect(document.querySelector("button[aria-label='Open Cyberscope']")).toBeNull();
    expect(document.querySelector("iframe")).toBeNull();
  });
});
