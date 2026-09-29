import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ConfirmDialog } from "../../../src/admin/components/ConfirmDialog";

function renderDialog(overrides: Partial<React.ComponentProps<typeof ConfirmDialog>> = {}) {
  const props = {
    open: true,
    title: "Reject this signal?",
    description: "This cannot be undone.",
    confirmLabel: "Reject",
    tone: "danger" as const,
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
    ...overrides,
  };
  render(<ConfirmDialog {...props} />);
  return props;
}

describe("ConfirmDialog", () => {
  it("renders nothing when closed", () => {
    renderDialog({ open: false });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("exposes title and description via aria-labelledby/aria-describedby", () => {
    renderDialog();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAccessibleName("Reject this signal?");
    expect(dialog).toHaveAccessibleDescription("This cannot be undone.");
  });

  it("focuses the cancel button on open", () => {
    renderDialog();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
  });

  it("calls onConfirm when the confirm button is clicked", () => {
    const { onConfirm } = renderDialog();
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(onConfirm).toHaveBeenCalled();
  });

  it("calls onCancel on Escape", () => {
    const { onCancel } = renderDialog();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onCancel).toHaveBeenCalled();
  });

  it("calls onCancel when the backdrop is clicked", () => {
    const { onCancel } = renderDialog();
    const dialog = screen.getByRole("dialog");
    const backdrop = dialog.parentElement!;
    fireEvent.mouseDown(backdrop, { target: backdrop });
    expect(onCancel).toHaveBeenCalled();
  });

  it("does not call onCancel when clicking inside the dialog", () => {
    const { onCancel } = renderDialog();
    fireEvent.mouseDown(screen.getByText("This cannot be undone."));
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("disables the confirm button when confirmDisabled is true", () => {
    renderDialog({ confirmDisabled: true });
    expect(screen.getByRole("button", { name: "Reject" })).toBeDisabled();
  });

  it("renders extra content passed as children", () => {
    renderDialog({ children: <p>Extra content</p> });
    expect(screen.getByText("Extra content")).toBeInTheDocument();
  });
});
