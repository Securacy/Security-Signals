/**
 * Security Signals embed loader.
 *
 * Dependency-free vanilla JS. This is the ONLY thing a host page needs to
 * include - it creates and fully controls a floating launcher button and
 * the iframe that holds the actual React widget. The host never needs to
 * know anything about React, the widget's build tooling, or the backend.
 *
 * Usage (see docs/embedding.md for the full contract):
 *
 *   <script
 *     type="module"
 *     src="https://<where-this-file-is-hosted>/embed.js"
 *     data-widget-url="https://<where-the-widget-app-is-hosted>/"
 *     data-api-base="https://<your-security-signals-api>"
 *     data-position="bottom-right">
 *   </script>
 *
 * `data-widget-url` may be omitted if the widget app is hosted at the same
 * origin as this script; it then defaults to that origin.
 */

const MESSAGE_SOURCE = "security-signals-widget";
const MOBILE_BREAKPOINT_PX = 640;
const VALID_POSITIONS = ["bottom-right", "bottom-left", "top-right", "top-left"];
const DEFAULT_POSITION = "bottom-right";

/** Find the <script> element that loaded this module, so we can read its
 * data-* attributes. document.currentScript is always null for module
 * scripts, so we match by resolved URL instead - a standard workaround. */
export function findOwnScriptElement(doc = document, selfUrl = import.meta.url) {
  const scripts = doc.querySelectorAll('script[type="module"][src]');
  for (const el of scripts) {
    try {
      if (new URL(el.getAttribute("src"), doc.baseURI).href === selfUrl) {
        return el;
      }
    } catch {
      // Ignore unparsable src values and keep looking.
    }
  }
  return null;
}

/** Pure config resolution from a <script> element's attributes. No
 * production domain is hardcoded here - data-widget-url must be supplied
 * unless the widget happens to be hosted alongside this script. */
export function resolveConfigFromScriptElement(scriptEl) {
  const dataset = scriptEl ? scriptEl.dataset || {} : {};

  const scriptOrigin = scriptEl && scriptEl.src ? new URL(scriptEl.src).origin : window.location.origin;
  const widgetUrl = dataset.widgetUrl || scriptOrigin + "/";

  const position = VALID_POSITIONS.includes(dataset.position) ? dataset.position : DEFAULT_POSITION;

  return {
    widgetUrl,
    apiBase: dataset.apiBase || "",
    position,
    // Forwarded to the launcher's injected <style> so a host with a
    // nonce-based CSP style-src can allow it (see ensureStyles).
    nonce: (scriptEl && scriptEl.nonce) || "",
  };
}

/** The iframe box dimensions/placement for the current viewport. Mobile
 * gets a full-screen sheet; desktop gets a fixed-size anchored panel that
 * widens while the widget is showing a signal's full reading view
 * (`expanded`). */
export function getDrawerLayout(position, viewportWidth, expanded = false) {
  if (viewportWidth <= MOBILE_BREAKPOINT_PX) {
    return { top: "0", left: "0", right: "0", bottom: "0", width: "100%", height: "100%", borderRadius: "0" };
  }

  const base = expanded
    ? { width: "min(720px, calc(100vw - 48px))", height: "min(760px, 88vh)", borderRadius: "16px" }
    : { width: "400px", height: "min(640px, 80vh)", borderRadius: "16px" };
  switch (position) {
    case "bottom-left":
      return { ...base, bottom: "88px", left: "24px" };
    case "top-right":
      return { ...base, top: "24px", right: "24px" };
    case "top-left":
      return { ...base, top: "24px", left: "24px" };
    case "bottom-right":
    default:
      return { ...base, bottom: "88px", right: "24px" };
  }
}

function getLauncherPlacement(position) {
  switch (position) {
    case "bottom-left":
      return { bottom: "24px", left: "24px" };
    case "top-right":
      return { top: "24px", right: "24px" };
    case "top-left":
      return { top: "24px", left: "24px" };
    case "bottom-right":
    default:
      return { bottom: "24px", right: "24px" };
  }
}

/** Validate an incoming message really came from our own iframe and
 * matches our tiny protocol - never trust postMessage payloads without
 * checking both origin and source. */
export function isValidMessageFromWidget(event, expectedOrigin, expectedSource) {
  if (!event || event.origin !== expectedOrigin) {
    return false;
  }
  if (expectedSource && event.source !== expectedSource) {
    return false;
  }
  const data = event.data;
  if (!data || typeof data !== "object" || data.source !== MESSAGE_SOURCE) {
    return false;
  }
  return (
    data.type === "security-signals:ready" ||
    data.type === "security-signals:close" ||
    data.type === "security-signals:expand" ||
    data.type === "security-signals:collapse"
  );
}

/* Launcher glyphs - Phosphor Icons (MIT, Copyright (c) 2023 Phosphor
 * Icons, https://phosphoricons.com): ShieldCheck (duotone) and X (the
 * duotone X's line path only - its tone layer is a filled square). Same
 * path data as src/widget/icons.tsx; duplicated because this loader is
 * plain, unbundled JS. */
const SHIELD_SVG =
  '<svg class="ssl-icon ssl-icon--open" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true" focusable="false">' +
  '<path opacity="0.25" d="M216,56v56c0,96-88,120-88,120S40,208,40,112V56a8,8,0,0,1,8-8H208A8,8,0,0,1,216,56Z"/>' +
  '<path d="M208,40H48A16,16,0,0,0,32,56v56c0,52.72,25.52,84.67,46.93,102.19,23.06,18.86,46,25.26,47,25.53a8,8,0,0,0,4.2,0c1-.27,23.91-6.67,47-25.53C198.48,196.67,224,164.72,224,112V56A16,16,0,0,0,208,40Zm0,72c0,37.07-13.66,67.16-40.6,89.42A129.3,129.3,0,0,1,128,223.62a128.25,128.25,0,0,1-38.92-21.81C61.82,179.51,48,149.3,48,112l0-56,160,0ZM82.34,141.66a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32l-56,56a8,8,0,0,1-11.32,0Z"/>' +
  "</svg>";

const CLOSE_SVG =
  '<svg class="ssl-icon ssl-icon--close" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true" focusable="false">' +
  '<path d="M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z"/>' +
  "</svg>";

const BRAND_GRADIENT = "linear-gradient(135deg, #801d91 0%, #db2777 100%)";
/** Display name only - the loader's code, message protocol and storage
 * keys keep their existing identifiers. */
const DISPLAY_NAME = "Threatline";
const OPEN_LABEL = `Open ${DISPLAY_NAME}`;
const CLOSE_LABEL = `Close ${DISPLAY_NAME}`;

const STYLE_ID = "ss-launcher-styles";

/* Base AND state styling (sizes, the open/close icon morph, badge and
 * tooltip visibility) is applied inline from JS: a host page whose CSP
 * blocks injected <style> elements still gets a correct, working launcher,
 * because CSSOM writes (element.style) aren't subject to style-src. This
 * stylesheet only ADDS what inline styles can't express - hover/active/
 * focus states, the radar-pulse keyframes, and the reduced-motion override
 * (whose !important beats the inline transitions). Every class is
 * prefixed "ssl-" to stay out of the host's way. Only transform/opacity
 * ever animate. */
const LAUNCHER_CSS = `
.ssl-pulse { animation: ssl-radar 2.8s cubic-bezier(0.2, 0.6, 0.3, 1) infinite; }
.ssl-root[data-open="true"] .ssl-pulse { animation: none; }
@keyframes ssl-radar {
  0% { transform: scale(1); opacity: 0.45; }
  70%, 100% { transform: scale(1.85); opacity: 0; }
}
.ssl-btn { transition: transform 260ms cubic-bezier(0.34, 1.56, 0.64, 1); }
.ssl-btn:hover { transform: scale(1.08); }
.ssl-btn:active { transform: scale(0.94); transition-duration: 150ms; }
.ssl-btn:focus-visible { outline: 3px solid #801d91; outline-offset: 3px; }
.ssl-btn--wiggle { animation: ssl-wiggle 600ms ease-in-out; }
@keyframes ssl-wiggle {
  0%, 100% { transform: rotate(0); }
  20% { transform: rotate(-12deg); }
  40% { transform: rotate(10deg); }
  60% { transform: rotate(-6deg); }
  80% { transform: rotate(3deg); }
}
@media (prefers-reduced-motion: reduce) {
  .ssl-pulse { display: none; }
  .ssl-btn--wiggle { animation: none; }
  .ssl-btn, .ssl-icon, .ssl-badge, .ssl-tip { transition: none !important; }
  .ssl-btn:hover, .ssl-btn:active { transform: none; }
}
`;

const EASE_OUT = "cubic-bezier(0.2, 0.7, 0.2, 1)";
const EASE_BOUNCE = "cubic-bezier(0.34, 1.56, 0.64, 1)";
const SYSTEM_FONT = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

/* Unread badge: a count of published signals newer than this browser's
 * last visit, from the same PUBLIC endpoint the widget itself reads. */
export const LAST_VISIT_STORAGE_KEY = "ss-widget-last-visit";
export const TOOLTIP_SEEN_STORAGE_KEY = "ss-widget-tooltip-seen";
/** Delay before the one unread-count request, so the launcher never
 * competes with the host page's own initial load. */
export const UNREAD_FETCH_DELAY_MS = 1500;
export const UNREAD_FETCH_LIMIT = 50;
/** With no stored last visit (a first visit), "new" means published in
 * this window - not "every signal that exists". */
export const FIRST_VISIT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
export const TOOLTIP_VISIBLE_MS = 5000;
/** While unread signals are waiting (and the drawer is closed), the
 * launcher gives a small attention wiggle this often. */
export const WIGGLE_INTERVAL_MS = 10000;
const WIGGLE_DURATION_MS = 600;
const BADGE_MAX = 9;

/** Pure: how many signals were published after `lastVisitMs` (or within
 * FIRST_VISIT_WINDOW_MS of `nowMs` when there's no last visit). Entries
 * without a parseable published_at are ignored, never counted. */
export function countNewSignals(signals, lastVisitMs, nowMs) {
  if (!Array.isArray(signals)) return 0;
  const since = lastVisitMs === null || lastVisitMs === undefined ? nowMs - FIRST_VISIT_WINDOW_MS : lastVisitMs;
  let count = 0;
  for (const signal of signals) {
    const published = signal && typeof signal.published_at === "string" ? Date.parse(signal.published_at) : NaN;
    if (Number.isFinite(published) && published > since) count += 1;
  }
  return count;
}

export function formatBadgeCount(count) {
  return count > BADGE_MAX ? `${BADGE_MAX}+` : String(count);
}

/** localStorage can be missing or throw (privacy modes, storage blocked by
 * the host's policy, sandboxed frames) - every access is guarded and a
 * failure just means "no stored value". */
function readStorage(win, key) {
  try {
    return win.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(win, key, value) {
  try {
    win.localStorage.setItem(key, value);
  } catch {
    // Storage unavailable - the badge simply can't remember this visit.
  }
}

export function readLastVisit(win = window) {
  const raw = readStorage(win, LAST_VISIT_STORAGE_KEY);
  const value = raw === null ? NaN : Number(raw);
  return Number.isFinite(value) ? value : null;
}

function ensureStyles(doc, nonce) {
  if (doc.getElementById(STYLE_ID)) return null;
  const style = doc.createElement("style");
  style.id = STYLE_ID;
  if (nonce) style.nonce = nonce;
  style.textContent = LAUNCHER_CSS;
  (doc.head || doc.documentElement).appendChild(style);
  return style;
}

/**
 * Build the launcher + iframe wrapper and wire up all behavior. Returns a
 * small control API ({open, close, destroy}) rather than nothing, so both
 * tests and, if ever needed, the host page itself can drive it
 * programmatically.
 */
export function createWidget(config, doc = document, win = window) {
  const widgetOrigin = new URL(config.widgetUrl).origin;
  const ownStyle = ensureStyles(doc, config.nonce);
  const isLeft = config.position.endsWith("-left");

  const root = doc.createElement("div");
  root.className = isLeft ? "ssl-root ssl-root--left" : "ssl-root";
  Object.assign(root.style, {
    position: "fixed",
    zIndex: "2147483000",
    width: "56px",
    height: "56px",
    ...getLauncherPlacement(config.position),
  });

  const pulse = doc.createElement("span");
  pulse.className = "ssl-pulse";
  pulse.setAttribute("aria-hidden", "true");
  Object.assign(pulse.style, {
    position: "absolute",
    inset: "0",
    borderRadius: "50%",
    background: BRAND_GRADIENT,
    opacity: "0",
    pointerEvents: "none",
  });

  const button = doc.createElement("button");
  button.type = "button";
  button.className = "ssl-btn";
  button.setAttribute("aria-label", OPEN_LABEL);
  button.setAttribute("aria-expanded", "false");
  button.innerHTML = SHIELD_SVG + CLOSE_SVG;
  const openIcon = button.querySelector(".ssl-icon--open");
  const closeIcon = button.querySelector(".ssl-icon--close");
  for (const icon of [openIcon, closeIcon]) {
    Object.assign(icon.style, {
      position: "absolute",
      top: "50%",
      left: "50%",
      width: "26px",
      height: "26px",
      margin: "-13px 0 0 -13px",
      transition: `transform 240ms ${EASE_OUT}, opacity 200ms ease`,
    });
  }
  Object.assign(button.style, {
    position: "relative",
    boxSizing: "border-box",
    width: "56px",
    height: "56px",
    margin: "0",
    padding: "0",
    borderRadius: "50%",
    border: "none",
    cursor: "pointer",
    background: BRAND_GRADIENT,
    color: "#ffffff",
    boxShadow: "0 6px 18px -4px rgba(128, 29, 145, 0.45), 0 2px 6px rgba(28, 25, 23, 0.12)",
  });

  const badge = doc.createElement("span");
  badge.className = "ssl-badge";
  badge.setAttribute("aria-hidden", "true");
  Object.assign(badge.style, {
    position: "absolute",
    top: "-3px",
    right: "-3px",
    minWidth: "20px",
    height: "20px",
    padding: "0 5px",
    boxSizing: "border-box",
    borderRadius: "10px",
    // Brand yellow highlight; ink text on it is 11.2:1.
    background: "#fbcd00",
    color: "#1c1c1c",
    font: `700 11px/20px ${SYSTEM_FONT}`,
    textAlign: "center",
    boxShadow: "0 0 0 2px #ffffff",
    pointerEvents: "none",
    transition: `transform 220ms ${EASE_BOUNCE}, opacity 150ms ease`,
  });
  button.appendChild(badge);

  // Created empty up front: a live region only announces reliably if it
  // already exists before its text changes.
  const tip = doc.createElement("div");
  tip.className = "ssl-tip";
  tip.setAttribute("role", "status");
  Object.assign(tip.style, {
    position: "absolute",
    top: "50%",
    ...(isLeft ? { left: "calc(100% + 12px)" } : { right: "calc(100% + 12px)" }),
    padding: "8px 12px",
    borderRadius: "10px",
    whiteSpace: "nowrap",
    background: "#1c1917",
    color: "#ffffff",
    font: `600 13px/18px ${SYSTEM_FONT}`,
    boxShadow: "0 8px 24px -8px rgba(28, 25, 23, 0.4)",
    pointerEvents: "none",
    transition: `transform 260ms ${EASE_OUT}, opacity 200ms ease`,
  });

  const wrapper = doc.createElement("div");
  Object.assign(wrapper.style, {
    position: "fixed",
    display: "none",
    overflow: "hidden",
    boxShadow: "0 12px 40px rgba(28, 25, 23, 0.22)",
    background: "#fafaf7",
  });

  root.appendChild(pulse);
  root.appendChild(button);
  root.appendChild(tip);
  doc.body.appendChild(root);
  doc.body.appendChild(wrapper);

  let iframeEl = null;
  let isOpen = false;
  let isExpanded = false;
  let destroyed = false;
  let unreadCount = 0;
  let unreadTimer = null;
  let tipTimer = null;
  let unreadAbort = null;
  let wiggleTimer = null;

  // Each visual state is written inline (see LAUNCHER_CSS for why), and
  // mirrored to a data-* attribute as a styling/testing hook.
  function applyIconState(open) {
    openIcon.style.opacity = open ? "0" : "1";
    openIcon.style.transform = open ? "rotate(90deg) scale(0.6)" : "none";
    closeIcon.style.opacity = open ? "1" : "0";
    closeIcon.style.transform = open ? "none" : "rotate(-90deg) scale(0.6)";
  }

  function applyBadgeVisible(visible) {
    badge.dataset.visible = visible ? "true" : "false";
    badge.style.opacity = visible ? "1" : "0";
    badge.style.transform = visible ? "scale(1)" : "scale(0)";
  }

  function applyTipVisible(visible) {
    const offset = isLeft ? "-8px" : "8px";
    tip.dataset.visible = visible ? "true" : "false";
    tip.style.opacity = visible ? "1" : "0";
    tip.style.transform = visible ? "translate(0, -50%)" : `translate(${offset}, -50%)`;
  }

  applyIconState(false);
  applyBadgeVisible(false);
  applyTipVisible(false);

  function closedLabel() {
    if (unreadCount <= 0) return OPEN_LABEL;
    const shown = unreadCount >= UNREAD_FETCH_LIMIT ? `${UNREAD_FETCH_LIMIT}+` : String(unreadCount);
    return `${OPEN_LABEL}, ${shown} new security signal${unreadCount === 1 ? "" : "s"}`;
  }

  function wiggle() {
    button.classList.remove("ssl-btn--wiggle");
    void button.offsetWidth; // restart the animation if it's somehow still applied
    button.classList.add("ssl-btn--wiggle");
    win.setTimeout(() => button.classList.remove("ssl-btn--wiggle"), WIGGLE_DURATION_MS);
  }

  function updateWiggle() {
    const shouldWiggle = unreadCount > 0 && !isOpen && !destroyed;
    if (shouldWiggle && wiggleTimer === null) {
      wiggleTimer = win.setInterval(wiggle, WIGGLE_INTERVAL_MS);
    } else if (!shouldWiggle && wiggleTimer !== null) {
      win.clearInterval(wiggleTimer);
      wiggleTimer = null;
      button.classList.remove("ssl-btn--wiggle");
    }
  }

  function setUnread(count) {
    unreadCount = count;
    badge.textContent = count > 0 ? formatBadgeCount(count) : "";
    applyBadgeVisible(count > 0);
    if (!isOpen) button.setAttribute("aria-label", closedLabel());
    updateWiggle();
  }

  function hideTip() {
    if (tipTimer !== null) win.clearTimeout(tipTimer);
    tipTimer = null;
    applyTipVisible(false);
    tip.setAttribute("aria-hidden", "true");
  }

  function showTip(count) {
    const shown = count >= UNREAD_FETCH_LIMIT ? `${UNREAD_FETCH_LIMIT}+` : String(count);
    tip.removeAttribute("aria-hidden");
    tip.textContent = `${shown} new security signal${count === 1 ? "" : "s"}`;
    applyTipVisible(true);
    writeStorage(win, TOOLTIP_SEEN_STORAGE_KEY, "1");
    tipTimer = win.setTimeout(hideTip, TOOLTIP_VISIBLE_MS);
  }

  async function checkUnread() {
    unreadTimer = null;
    const controller = typeof win.AbortController === "function" ? new win.AbortController() : null;
    unreadAbort = controller;
    try {
      const url = new URL(config.apiBase.replace(/\/+$/, "") + "/api/v1/signals/published");
      url.searchParams.set("limit", String(UNREAD_FETCH_LIMIT));
      url.searchParams.set("sort", "recent");
      const response = await win.fetch(url.toString(), {
        method: "GET",
        headers: { Accept: "application/json" },
        credentials: "omit",
        signal: controller ? controller.signal : undefined,
      });
      if (!response.ok) return;
      const signals = await response.json();
      // Opening the drawer already counts as this visit - a response that
      // lands after that must not resurrect the badge.
      if (destroyed || isOpen) return;
      const lastVisit = readLastVisit(win);
      const count = countNewSignals(signals, lastVisit, Date.now());
      setUnread(count);
      if (count > 0 && lastVisit === null && readStorage(win, TOOLTIP_SEEN_STORAGE_KEY) === null) {
        showTip(count);
      }
    } catch {
      // Network/CORS/parse failure or abort: no badge, nothing else changes.
    } finally {
      if (unreadAbort === controller) unreadAbort = null;
    }
  }

  function markVisited() {
    writeStorage(win, LAST_VISIT_STORAGE_KEY, String(Date.now()));
    setUnread(0);
    hideTip();
  }

  function applyLayout() {
    const layout = getDrawerLayout(config.position, win.innerWidth, isExpanded);
    Object.assign(wrapper.style, layout);
  }

  function ensureIframe() {
    if (iframeEl) return;
    const url = new URL(config.widgetUrl);
    if (config.apiBase) url.searchParams.set("apiBase", config.apiBase);
    url.searchParams.set("parentOrigin", win.location.origin);

    iframeEl = doc.createElement("iframe");
    iframeEl.src = url.toString();
    iframeEl.title = DISPLAY_NAME;
    Object.assign(iframeEl.style, { width: "100%", height: "100%", border: "none" });
    wrapper.appendChild(iframeEl);
  }

  function open() {
    ensureIframe();
    applyLayout();
    wrapper.style.display = "block";
    isOpen = true;
    root.dataset.open = "true";
    applyIconState(true);
    button.setAttribute("aria-expanded", "true");
    button.setAttribute("aria-label", CLOSE_LABEL);
    markVisited();
    updateWiggle();
  }

  function close() {
    wrapper.style.display = "none";
    isOpen = false;
    isExpanded = false;
    root.dataset.open = "false";
    applyIconState(false);
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-label", closedLabel());
    updateWiggle();
  }

  function toggle() {
    if (isOpen) close();
    else open();
  }

  function onDocumentClick(event) {
    if (!isOpen) return;
    if (root.contains(event.target) || wrapper.contains(event.target)) return;
    close();
  }

  function onDocumentKeydown(event) {
    if (isOpen && event.key === "Escape") close();
  }

  function onResize() {
    if (isOpen) applyLayout();
  }

  function onMessage(event) {
    const expectedSource = iframeEl ? iframeEl.contentWindow : null;
    if (!isValidMessageFromWidget(event, widgetOrigin, expectedSource)) return;
    const type = event.data.type;
    if (type === "security-signals:close") {
      close();
    } else if (type === "security-signals:expand" || type === "security-signals:collapse") {
      isExpanded = type === "security-signals:expand";
      if (isOpen) applyLayout();
    }
  }

  button.addEventListener("click", toggle);
  doc.addEventListener("click", onDocumentClick, true);
  doc.addEventListener("keydown", onDocumentKeydown);
  win.addEventListener("resize", onResize);
  win.addEventListener("message", onMessage);

  if (config.apiBase && typeof win.fetch === "function") {
    unreadTimer = win.setTimeout(checkUnread, UNREAD_FETCH_DELAY_MS);
  }

  function destroy() {
    destroyed = true;
    updateWiggle();
    if (unreadTimer !== null) win.clearTimeout(unreadTimer);
    if (unreadAbort) unreadAbort.abort();
    hideTip();
    button.removeEventListener("click", toggle);
    doc.removeEventListener("click", onDocumentClick, true);
    doc.removeEventListener("keydown", onDocumentKeydown);
    win.removeEventListener("resize", onResize);
    win.removeEventListener("message", onMessage);
    root.remove();
    wrapper.remove();
    if (ownStyle) ownStyle.remove();
  }

  return { open, close, toggle, destroy, isOpen: () => isOpen };
}

const ownScript = findOwnScriptElement();
if (ownScript) {
  createWidget(resolveConfigFromScriptElement(ownScript));
}
