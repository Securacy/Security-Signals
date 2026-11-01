/** True when the viewer asked the OS for reduced motion. JS-driven motion
 * (FLIP transitions, timed exits) must check this itself - the CSS
 * reduced-motion block in widget.css only covers CSS animations. */
export function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
