import { describe, it, expect } from "vitest";
import { buildWatermarkDataUri, WATERMARK_COLORS, WATERMARK_TILE_PX } from "../../src/widget/watermark";
import { SHIELD_WARNING } from "../../src/widget/icons";

function decode(uri: string): string {
  const match = /^url\("data:image\/svg\+xml,(.*)"\)$/.exec(uri);
  expect(match).not.toBeNull();
  return decodeURIComponent(match![1]);
}

describe("watermark", () => {
  it("is a single self-contained SVG tile data URI", () => {
    const svg = decode(buildWatermarkDataUri());
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain(`width="${WATERMARK_TILE_PX}"`);
    // No external references of any kind.
    expect(svg).not.toMatch(/href|url\(|<image|<script/i);
  });

  it("draws all eight category glyphs as outlines (line path only, no tone fill)", () => {
    const svg = decode(buildWatermarkDataUri());
    expect(svg.match(/<path /g)).toHaveLength(8);
    expect(svg).toContain(SHIELD_WARNING.line);
    expect(svg).not.toContain(SHIELD_WARNING.tone);
    expect(svg).not.toContain('opacity="0.2"');
  });

  it("scatters glyphs with slight, varied rotations", () => {
    const svg = decode(buildWatermarkDataUri());
    const rotations = Array.from(svg.matchAll(/rotate\((-?\d+)/g)).map((m) => Number(m[1]));
    expect(rotations).toHaveLength(8);
    expect(new Set(rotations).size).toBe(8);
    for (const r of rotations) expect(Math.abs(r)).toBeLessThanOrEqual(15);
  });

  it("alternates mustard (deeper than brand yellow, for contrast) and purple", () => {
    const svg = decode(buildWatermarkDataUri(WATERMARK_COLORS));
    const fills = Array.from(svg.matchAll(/fill="([^"]+)"/g)).map((m) => m[1]);
    expect(fills).toEqual(["#D9A800", "#801D91", "#D9A800", "#801D91", "#D9A800", "#801D91", "#D9A800", "#801D91"]);
  });
});
