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

const BUTTON_SVG =
  '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">' +
  '<path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>' +
  '<path d="M9 12.2 11.2 14.4 15.4 10" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
  "</svg>";

/**
 * Build the launcher + iframe wrapper and wire up all behavior. Returns a
 * small control API ({open, close, destroy}) rather than nothing, so both
 * tests and, if ever needed, the host page itself can drive it
 * programmatically.
 */
export function createWidget(config, doc = document, win = window) {
  const widgetOrigin = new URL(config.widgetUrl).origin;

  const root = doc.createElement("div");
  Object.assign(root.style, {
    position: "fixed",
    zIndex: "2147483000",
    ...getLauncherPlacement(config.position),
  });

  const button = doc.createElement("button");
  button.type = "button";
  button.setAttribute("aria-label", "Open Cyberscope");
  button.setAttribute("aria-expanded", "false");
  button.innerHTML = BUTTON_SVG;
  Object.assign(button.style, {
    width: "56px",
    height: "56px",
    borderRadius: "50%",
    border: "none",
    cursor: "pointer",
    background: "#2563eb",
    color: "#ffffff",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxShadow: "0 4px 16px rgba(15, 23, 42, 0.25)",
  });

  const wrapper = doc.createElement("div");
  Object.assign(wrapper.style, {
    position: "fixed",
    display: "none",
    overflow: "hidden",
    boxShadow: "0 12px 40px rgba(15, 23, 42, 0.3)",
    background: "#ffffff",
  });

  root.appendChild(button);
  doc.body.appendChild(root);
  doc.body.appendChild(wrapper);

  let iframeEl = null;
  let isOpen = false;
  let isExpanded = false;

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
    iframeEl.title = "Cyberscope";
    Object.assign(iframeEl.style, { width: "100%", height: "100%", border: "none" });
    wrapper.appendChild(iframeEl);
  }

  function open() {
    ensureIframe();
    applyLayout();
    wrapper.style.display = "block";
    button.setAttribute("aria-expanded", "true");
    isOpen = true;
  }

  function close() {
    wrapper.style.display = "none";
    button.setAttribute("aria-expanded", "false");
    isOpen = false;
    isExpanded = false;
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

  function destroy() {
    button.removeEventListener("click", toggle);
    doc.removeEventListener("click", onDocumentClick, true);
    doc.removeEventListener("keydown", onDocumentKeydown);
    win.removeEventListener("resize", onResize);
    win.removeEventListener("message", onMessage);
    root.remove();
    wrapper.remove();
  }

  return { open, close, toggle, destroy, isOpen: () => isOpen };
}

const ownScript = findOwnScriptElement();
if (ownScript) {
  createWidget(resolveConfigFromScriptElement(ownScript));
}
