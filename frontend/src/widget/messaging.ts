/**
 * postMessage protocol between this iframe (the React widget) and the
 * loader running on the host page. Deliberately minimal - only two message
 * types exist, each with a concrete reason to cross the frame boundary
 * rather than being handled locally:
 *
 *  - "security-signals:ready": sent once, after first mount, so the loader
 *    knows it's safe to reveal the iframe (avoids a flash of an empty/
 *    loading iframe on first open).
 *  - "security-signals:close": sent when the user closes the drawer from
 *    inside the iframe (the in-app close button, or Escape while focus is
 *    inside the iframe) - the loader owns visibility/sizing of the iframe
 *    element itself, so the iframe can't close itself; it has to ask.
 *
 * Everything else (open, positioning, resizing for mobile) is handled
 * entirely on the loader side without needing to talk to the iframe at all.
 */

export const SECURITY_SIGNALS_MESSAGE_SOURCE = "security-signals-widget";

export type OutgoingMessageType = "security-signals:ready" | "security-signals:close";

export interface OutgoingMessage {
  source: typeof SECURITY_SIGNALS_MESSAGE_SOURCE;
  type: OutgoingMessageType;
}

function buildMessage(type: OutgoingMessageType): OutgoingMessage {
  return { source: SECURITY_SIGNALS_MESSAGE_SOURCE, type };
}

/**
 * Send a message to the parent (host) window. Targets the specific parent
 * origin resolved at load time when known, and only falls back to "*" when
 * genuinely unknown (e.g. local standalone testing without a loader) -
 * since these messages carry no sensitive data, a fallback wildcard target
 * here is a usability tradeoff, not a data-exposure risk.
 */
export function sendToParent(type: OutgoingMessageType, parentOrigin: string | null): void {
  if (window.parent === window) {
    return; // Not embedded - nothing to notify.
  }
  const targetOrigin = parentOrigin || "*";
  window.parent.postMessage(buildMessage(type), targetOrigin);
}

/**
 * Validate an incoming MessageEvent came from OUR iframe and matches our
 * protocol shape. Used on the loader side. Never trust origin alone or
 * shape alone - both must check out.
 */
export function isValidIncomingMessage(
  event: MessageEvent,
  expectedOrigin: string,
  expectedSource: Window | null,
): event is MessageEvent<OutgoingMessage> {
  if (event.origin !== expectedOrigin) {
    return false;
  }
  if (expectedSource && event.source !== expectedSource) {
    return false;
  }
  const data = event.data;
  if (!data || typeof data !== "object") {
    return false;
  }
  if (data.source !== SECURITY_SIGNALS_MESSAGE_SOURCE) {
    return false;
  }
  return data.type === "security-signals:ready" || data.type === "security-signals:close";
}
