import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { sendToParent } from "../messaging";
import { prefersReducedMotion } from "../motion";
import { Duotone, X } from "../icons";
import { ReaderLaunchContext, type ReaderLaunch } from "../readerLaunch";
import type { SignalSummary } from "../types";
import { WATERMARK_BACKGROUND_STYLE } from "../watermark";
import { SignalFeed } from "./SignalFeed";
import { SignalDetail } from "./SignalDetail";

/** Display name only - code, files, message types and storage keys keep
 * their existing identifiers. */
export const WIDGET_DISPLAY_NAME = "Threatline";

interface DrawerProps {
  apiBaseUrl: string;
  parentOrigin: string | null;
}

type ReaderState = "closed" | "open" | "closing";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input, textarea, select, [tabindex]:not([tabindex="-1"])';

/** Matches the CSS exit animation duration in widget.css (.ss-reader-layer
 * --closing). Reduced-motion users skip the wait entirely. */
const READER_EXIT_MS = 160;

export function Drawer({ apiBaseUrl, parentOrigin }: DrawerProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [readerState, setReaderState] = useState<ReaderState>("closed");
  const containerRef = useRef<HTMLDivElement>(null);
  const readerRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const pendingLaunchRef = useRef<ReaderLaunch | null>(null);
  const [launch, setLaunch] = useState<ReaderLaunch | null>(null);
  const titleId = useId();

  const launchContext = useMemo(
    () => ({
      prepare(signal: SignalSummary, originEl: Element | null) {
        pendingLaunchRef.current = { signal, originRect: originEl ? originEl.getBoundingClientRect() : null };
      },
    }),
    [],
  );

  // Tell the loader we've mounted and it's safe to reveal the iframe.
  useEffect(() => {
    sendToParent("security-signals:ready", parentOrigin);
  }, [parentOrigin]);

  const handleClose = useCallback(() => {
    sendToParent("security-signals:close", parentOrigin);
  }, [parentOrigin]);

  const openSignal = useCallback(
    (id: string) => {
      openerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      const pending = pendingLaunchRef.current;
      pendingLaunchRef.current = null;
      setLaunch(pending && pending.signal.id === id ? pending : null);
      setSelectedId(id);
      setReaderState("open");
      sendToParent("security-signals:expand", parentOrigin);
    },
    [parentOrigin],
  );

  const requestCloseReader = useCallback(() => {
    setReaderState((current) => (current === "open" ? "closing" : current));
  }, []);

  // Runs once the exit animation has played (or immediately for reduced
  // motion): unmounts the reader, collapses the panel back to its compact
  // size, and returns focus to the card that opened the reader.
  const finishCloseReader = useCallback(() => {
    setSelectedId(null);
    setLaunch(null);
    setReaderState("closed");
    sendToParent("security-signals:collapse", parentOrigin);
    const opener = openerRef.current;
    openerRef.current = null;
    if (opener && opener.isConnected) opener.focus();
  }, [parentOrigin]);

  useEffect(() => {
    if (readerState !== "closing") return;
    if (prefersReducedMotion()) {
      finishCloseReader();
      return;
    }
    const timer = window.setTimeout(finishCloseReader, READER_EXIT_MS);
    return () => window.clearTimeout(timer);
  }, [readerState, finishCloseReader]);

  // Escape closes the innermost thing first: the reader if it's open,
  // otherwise the whole widget. Only fires for keydowns inside this
  // document (the iframe) - the loader handles Escape on the host side
  // separately, for when focus is on the host page instead.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (readerState !== "closed") {
        requestCloseReader();
      } else {
        handleClose();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [handleClose, readerState, requestCloseReader]);

  // Focus trap: Tab/Shift+Tab cycles within whichever layer is on top -
  // the reader while it's open, otherwise the whole drawer.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Tab") return;
      const layer = readerState !== "closed" ? readerRef.current : containerRef.current;
      if (!layer) return;
      const focusable = layer.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
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
  }, [readerState]);

  useEffect(() => {
    containerRef.current?.focus();
  }, []);

  // Move focus into the reader as soon as it opens, so keyboard and
  // screen-reader users land on the content they just asked for.
  useEffect(() => {
    if (readerState === "open") readerRef.current?.focus();
  }, [readerState]);

  const readerVisible = readerState !== "closed" && selectedId !== null;

  return (
    <div
      className="ss-drawer"
      ref={containerRef}
      role="dialog"
      aria-modal="true"
      aria-label={WIDGET_DISPLAY_NAME}
      tabIndex={-1}
    >
      {/* One fixed wallpaper node behind everything (see watermark.ts). */}
      <div className="ss-watermark" style={WATERMARK_BACKGROUND_STYLE} aria-hidden="true" />
      <header className="ss-drawer__header">
        <h1 className="ss-drawer__title">{WIDGET_DISPLAY_NAME}</h1>
        <button type="button" className="ss-close-button" onClick={handleClose} aria-label="Close">
          <Duotone icon={X} className="ss-close-button__icon" lineOnly />
        </button>
      </header>
      <div className="ss-drawer__body" data-scroll-root aria-hidden={readerVisible ? "true" : undefined}>
        <ReaderLaunchContext.Provider value={launchContext}>
          <SignalFeed apiBaseUrl={apiBaseUrl} onOpenSignal={openSignal} />
        </ReaderLaunchContext.Provider>
      </div>

      {readerVisible && selectedId && (
        <div className={`ss-reader-layer${readerState === "closing" ? " ss-reader-layer--closing" : ""}`}>
          <button
            type="button"
            className="ss-reader-backdrop"
            onClick={requestCloseReader}
            tabIndex={-1}
            aria-hidden="true"
          />
          <div
            className="ss-reader"
            ref={readerRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
          >
            <button type="button" className="ss-reader__close" onClick={requestCloseReader} aria-label="Close signal">
              <Duotone icon={X} className="ss-reader__close-icon" lineOnly />
            </button>
            <div className="ss-reader__scroll">
              <SignalDetail
                apiBaseUrl={apiBaseUrl}
                signalId={selectedId}
                titleId={titleId}
                preview={launch?.signal ?? null}
                originRect={launch?.originRect ?? null}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
