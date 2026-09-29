import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { Button } from "./Button";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: string;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: "primary" | "danger";
  onConfirm: () => void;
  onCancel: () => void;
  confirmDisabled?: boolean;
  /** Extra content between the description and the action buttons, e.g. a
   * required reason field for a rejection. */
  children?: ReactNode;
}

/**
 * A small, hand-rolled accessible modal (role="dialog", focus trap, Escape
 * to close, focus restored to the triggering element) rather than relying
 * on native <dialog> - keeps behavior consistent and testable across
 * browsers/jsdom rather than depending on how completely each implements
 * showModal(). Used for every consequential Review Queue action (approve,
 * reject, publish) per the design brief's "confirmation before
 * destructive/state-changing actions" requirement.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  tone = "primary",
  onConfirm,
  onCancel,
  confirmDisabled = false,
  children,
}: ConfirmDialogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (!open) return undefined;
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    cancelButtonRef.current?.focus();
    return () => {
      previouslyFocused.current?.focus?.();
    };
  }, [open]);

  if (!open) return null;

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.stopPropagation();
      onCancel();
      return;
    }
    if (event.key !== "Tab") return;

    const container = containerRef.current;
    if (!container) return;
    const focusable = container.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    );
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

  return (
    <div
      className="adm-dialog-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div
        ref={containerRef}
        className="adm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        onKeyDown={handleKeyDown}
      >
        <h2 id={titleId} className="adm-dialog__title">
          {title}
        </h2>
        {description && (
          <p id={descriptionId} className="adm-dialog__description">
            {description}
          </p>
        )}
        {children}
        <div className="adm-dialog__actions">
          <Button ref={cancelButtonRef} variant="secondary" onClick={onCancel}>
            {cancelLabel}
          </Button>
          <Button variant={tone === "danger" ? "danger" : "primary"} onClick={onConfirm} disabled={confirmDisabled}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
