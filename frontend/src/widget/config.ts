/**
 * Runtime configuration for the widget, resolved from URL query params set
 * by the loader when it creates the iframe (see loader/embed.js). Falling
 * back to build-time env vars keeps `npm run dev` usable standalone,
 * without a loader/parent page at all.
 */

function readParam(name: string): string | null {
  const params = new URLSearchParams(window.location.search);
  const value = params.get(name);
  return value && value.trim() ? value : null;
}

export interface WidgetConfig {
  /** Base URL of the Security Signals backend, e.g. "https://api.example.com". */
  apiBaseUrl: string;
  /** Origin of the host page that embedded this widget, used to target
   * postMessage precisely instead of using "*". Null when not embedded
   * (e.g. running standalone in a dev browser tab). */
  parentOrigin: string | null;
  /** Whether this app is actually running inside an iframe. */
  isEmbedded: boolean;
}

export function getWidgetConfig(): WidgetConfig {
  const apiBaseUrl =
    readParam("apiBase") ||
    (import.meta.env.VITE_API_BASE_URL as string | undefined) ||
    "http://localhost:8000";

  const parentOrigin = readParam("parentOrigin");

  let isEmbedded = false;
  try {
    isEmbedded = window.self !== window.top;
  } catch {
    // Cross-origin access to window.top throws in some sandboxed contexts;
    // being unable to read window.top at all means we ARE framed.
    isEmbedded = true;
  }

  return {
    apiBaseUrl: apiBaseUrl.replace(/\/+$/, ""),
    parentOrigin,
    isEmbedded,
  };
}
