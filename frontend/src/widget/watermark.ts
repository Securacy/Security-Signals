import type { CSSProperties } from "react";
import {
  DETECTIVE,
  FILE_LOCK,
  FINGERPRINT,
  HARD_DRIVES,
  LOCK_KEY,
  PACKAGE,
  ROBOT,
  SHIELD_WARNING,
  type DuotoneIconData,
} from "./icons";

/** Edge length (px) of one repeating watermark tile. widget.css drifts the
 * layer by exactly this distance per loop, so the drift is seamless. */
export const WATERMARK_TILE_PX = 240;

/** [icon, x, y, rotation°, size] - hand-scattered so the repeat doesn't
 * read as a grid, every glyph kept >= 6px inside the tile so rotation
 * never clips it at a seam. */
const PLACEMENTS: [DuotoneIconData, number, number, number, number][] = [
  [SHIELD_WARNING, 16, 18, -12, 28],
  [FINGERPRINT, 126, 10, 9, 26],
  [PACKAGE, 196, 68, -6, 30],
  [LOCK_KEY, 62, 90, 14, 26],
  [FILE_LOCK, 146, 118, -14, 28],
  [DETECTIVE, 14, 166, 7, 30],
  [ROBOT, 94, 196, -8, 26],
  [HARD_DRIVES, 194, 184, 12, 28],
];

/** The drawer wallpaper alternates the two brand highlight colours. The
 * yellow is the deeper mustard: brand #FBCD00 is too close to the light
 * background (1.09:1) to read as an outline. */
export const WATERMARK_COLORS = ["#D9A800", "#801D91"];

/**
 * One self-contained SVG tile of every category glyph's OUTLINE (the line
 * path only - no tone fill), as a data URI, so a whole wallpaper is one DOM
 * node rather than one per icon. Glyph fills cycle through `fills`: the
 * default single black fill is for use as a CSS mask (colour supplied by
 * CSS); WATERMARK_COLORS bakes the brand colours in for direct use as a
 * background image.
 */
export function buildWatermarkDataUri(fills: string[] = ["#000"]): string {
  const glyphs = PLACEMENTS.map(([icon, x, y, rotation, size], i) => {
    const half = size / 2;
    const scale = size / 256;
    return (
      `<g transform="translate(${x} ${y}) rotate(${rotation} ${half} ${half}) scale(${scale})">` +
      `<path fill="${fills[i % fills.length]}" d="${icon.line}"/></g>`
    );
  }).join("");
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${WATERMARK_TILE_PX}" height="${WATERMARK_TILE_PX}" ` +
    `viewBox="0 0 ${WATERMARK_TILE_PX} ${WATERMARK_TILE_PX}">${glyphs}</svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}

export const WATERMARK_DATA_URI = buildWatermarkDataUri();
export const WATERMARK_COLOR_DATA_URI = buildWatermarkDataUri(WATERMARK_COLORS);

/** Inline style that paints the single-colour tile as a repeating mask -
 * the faint pattern inside fallback card art (tinted by CSS). */
export const WATERMARK_MASK_STYLE = {
  WebkitMaskImage: WATERMARK_DATA_URI,
  maskImage: WATERMARK_DATA_URI,
} as CSSProperties;

/** The drawer wallpaper: the yellow/purple tile as a plain background. */
export const WATERMARK_BACKGROUND_STYLE = {
  backgroundImage: WATERMARK_COLOR_DATA_URI,
} as CSSProperties;
