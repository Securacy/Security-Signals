import { describe, it, expect, afterEach } from "vitest";
import { getWidgetConfig } from "../../src/widget/config";

function setUrl(search: string) {
  window.history.pushState({}, "", `/${search}`);
}

describe("getWidgetConfig", () => {
  afterEach(() => {
    setUrl("");
  });

  it("reads apiBase and parentOrigin from the query string", () => {
    setUrl("?apiBase=https%3A%2F%2Fapi.example.com&parentOrigin=https%3A%2F%2Fhost.example");

    const config = getWidgetConfig();

    expect(config.apiBaseUrl).toBe("https://api.example.com");
    expect(config.parentOrigin).toBe("https://host.example");
  });

  it("strips a trailing slash from apiBaseUrl", () => {
    setUrl("?apiBase=https%3A%2F%2Fapi.example.com%2F");

    expect(getWidgetConfig().apiBaseUrl).toBe("https://api.example.com");
  });

  it("falls back to a default when apiBase is not provided", () => {
    setUrl("");

    const config = getWidgetConfig();

    expect(config.apiBaseUrl.length).toBeGreaterThan(0);
    expect(config.parentOrigin).toBeNull();
  });

  it("never reads or exposes anything auth-related", () => {
    setUrl("?apiBase=https%3A%2F%2Fapi.example.com&token=should-be-ignored");

    const config = getWidgetConfig();

    expect(config).not.toHaveProperty("token");
    expect(JSON.stringify(config)).not.toContain("should-be-ignored");
  });
});
