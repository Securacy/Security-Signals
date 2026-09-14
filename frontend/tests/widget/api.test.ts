import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetchPublishedSignals, fetchSignalDetail, ApiError } from "../../src/widget/api";

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("fetchPublishedSignals", () => {
    it("calls only the public published-signals endpoint", async () => {
      (fetch as any).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await fetchPublishedSignals("https://api.example.com");

      const calledUrl = (fetch as any).mock.calls[0][0] as string;
      expect(calledUrl).toContain("https://api.example.com/api/v1/signals/published");
    });

    it("passes skip/limit/category as query params", async () => {
      (fetch as any).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });

      await fetchPublishedSignals("https://api.example.com", { skip: 20, limit: 5, category: "iam" });

      const calledUrl = new URL((fetch as any).mock.calls[0][0] as string);
      expect(calledUrl.searchParams.get("skip")).toBe("20");
      expect(calledUrl.searchParams.get("limit")).toBe("5");
      expect(calledUrl.searchParams.get("category")).toBe("iam");
    });

    it("omits category param when not provided", async () => {
      (fetch as any).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });

      await fetchPublishedSignals("https://api.example.com");

      const calledUrl = new URL((fetch as any).mock.calls[0][0] as string);
      expect(calledUrl.searchParams.has("category")).toBe(false);
    });

    it("reports hasMore=true when a full page is returned", async () => {
      const fullPage = Array.from({ length: 10 }, (_, i) => ({ id: String(i) }));
      (fetch as any).mockResolvedValue({ ok: true, json: () => Promise.resolve(fullPage) });

      const result = await fetchPublishedSignals("https://api.example.com", { limit: 10 });
      expect(result.hasMore).toBe(true);
    });

    it("reports hasMore=false for a partial page", async () => {
      const partialPage = [{ id: "1" }];
      (fetch as any).mockResolvedValue({ ok: true, json: () => Promise.resolve(partialPage) });

      const result = await fetchPublishedSignals("https://api.example.com", { limit: 10 });
      expect(result.hasMore).toBe(false);
    });

    it("throws ApiError on a non-ok response", async () => {
      (fetch as any).mockResolvedValue({ ok: false, status: 500 });

      await expect(fetchPublishedSignals("https://api.example.com")).rejects.toThrow(ApiError);
    });

    it("throws ApiError on a network failure", async () => {
      (fetch as any).mockRejectedValue(new TypeError("Failed to fetch"));

      await expect(fetchPublishedSignals("https://api.example.com")).rejects.toThrow(ApiError);
    });
  });

  describe("fetchSignalDetail", () => {
    it("calls the public signal-detail endpoint with the given id", async () => {
      (fetch as any).mockResolvedValue({ ok: true, json: () => Promise.resolve({ id: "abc-123" }) });

      await fetchSignalDetail("https://api.example.com", "abc-123");

      const calledUrl = (fetch as any).mock.calls[0][0] as string;
      expect(calledUrl).toBe("https://api.example.com/api/v1/signals/published/abc-123");
    });

    it("throws ApiError on 404", async () => {
      (fetch as any).mockResolvedValue({ ok: false, status: 404 });

      await expect(fetchSignalDetail("https://api.example.com", "missing")).rejects.toThrow(ApiError);
    });
  });
});
