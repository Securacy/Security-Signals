import { describe, it, expect } from "vitest";
import { isSafeExternalUrl } from "../../src/widget/safeUrl";

describe("isSafeExternalUrl", () => {
  it("accepts https URLs", () => {
    expect(isSafeExternalUrl("https://example.com/advisory")).toBe(true);
  });

  it("accepts http URLs", () => {
    expect(isSafeExternalUrl("http://example.com/advisory")).toBe(true);
  });

  it("rejects javascript: URLs", () => {
    expect(isSafeExternalUrl("javascript:alert(1)")).toBe(false);
  });

  it("rejects data: URLs", () => {
    expect(isSafeExternalUrl("data:text/html,<script>alert(1)</script>")).toBe(false);
  });

  it("rejects malformed strings", () => {
    expect(isSafeExternalUrl("not a url")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(isSafeExternalUrl("")).toBe(false);
  });
});
