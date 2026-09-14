import { useCallback, useEffect, useRef, useState } from "react";
import { sendToParent } from "../messaging";
import { SignalFeed } from "./SignalFeed";
import { SignalDetail } from "./SignalDetail";

interface DrawerProps {
  apiBaseUrl: string;
  parentOrigin: string | null;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input, textarea, select, [tabindex]:not([tabindex="-1"])';

export function Drawer({ apiBaseUrl, parentOrigin }: DrawerProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Tell the loader we've mounted and it's safe to reveal the iframe.
  useEffect(() => {
    sendToParent("security-signals:ready", parentOrigin);
  }, [parentOrigin]);

  const handleClose = useCallback(() => {
    sendToParent("security-signals:close", parentOrigin);
  }, [parentOrigin]);

  // Escape closes the drawer. This only fires for keydowns inside this
  // document (the iframe) - the loader handles Escape on the host side
  // separately, for when focus is on the host page instead.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        handleClose();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [handleClose]);

  // Simple focus trap so Tab/Shift+Tab cycles within the drawer instead of
  // escaping into... nothing, since this document only contains the drawer.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Tab" || !containerRef.current) return;
      const focusable = containerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    containerRef.current?.focus();
  }, []);

  return (
    <div
      className="ss-drawer"
      ref={containerRef}
      role="dialog"
      aria-modal="true"
      aria-label="Security Signals"
      tabIndex={-1}
    >
      <header className="ss-drawer__header">
        <h1 className="ss-drawer__title">Security Signals</h1>
        <button type="button" className="ss-close-button" onClick={handleClose} aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </header>
      <div className="ss-drawer__body">
        {selectedId ? (
          <SignalDetail apiBaseUrl={apiBaseUrl} signalId={selectedId} onBack={() => setSelectedId(null)} />
        ) : (
          <SignalFeed apiBaseUrl={apiBaseUrl} onOpenSignal={setSelectedId} />
        )}
      </div>
    </div>
  );
}
