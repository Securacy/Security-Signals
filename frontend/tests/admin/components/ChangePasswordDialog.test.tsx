import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthProvider } from "../../../src/admin/auth/AuthContext";
import { ChangePasswordDialog } from "../../../src/admin/components/ChangePasswordDialog";

function seedSession() {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id: "u1", username: "tester", email: "tester@example.test", role: "reviewer" },
    }),
  );
}

function mockFetch(handler: (url: string, init?: RequestInit) => { ok: boolean; status: number; json: () => Promise<unknown> }) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string, init?: RequestInit) => Promise.resolve(handler(String(input), init))),
  );
}

function renderDialog(open = true) {
  const onClose = vi.fn();
  render(
    <AuthProvider>
      <ChangePasswordDialog open={open} onClose={onClose} />
    </AuthProvider>,
  );
  return { onClose };
}

describe("ChangePasswordDialog", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    seedSession();
  });

  it("renders nothing when closed", () => {
    renderDialog(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows the live requirement checklist and disables submit until every rule and confirmation are met", () => {
    renderDialog();
    const dialog = screen.getByRole("dialog");
    const submit = screen.getByRole("button", { name: "Change password" });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "OldPassword123!" } });
    expect(submit).toBeDisabled(); // new password still empty

    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "weak" } });
    expect(submit).toBeDisabled();
    expect(dialog).toHaveTextContent("12+ characters");

    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    expect(submit).toBeDisabled(); // confirmation not yet entered

    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "Different!Pw12" } });
    expect(submit).toBeDisabled(); // mismatch
    expect(dialog).toHaveTextContent("don't match");

    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "Br4nd!NewPassword" } });
    expect(submit).toBeEnabled();
  });

  it("rejects a new password identical to the user's own username or email before submitting", () => {
    renderDialog();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "OldPassword123!" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "tester" } });
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();
    expect(screen.getByText(/can't be your username or email/i)).toBeInTheDocument();
  });

  it("submits current/new/confirm and, on success, signs out with a friendly notice instead of showing a body", async () => {
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).includes("/api/v1/auth/change-password")) {
        return Promise.resolve({ ok: true, status: 204, json: () => Promise.resolve(undefined) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
    });
    vi.stubGlobal("fetch", fetchMock);

    const { onClose } = renderDialog();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "OldPassword123!" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/api/v1/auth/change-password"));
      expect(call).toBeDefined();
      expect(JSON.parse((call![1] as RequestInit).body as string)).toEqual({
        current_password: "OldPassword123!",
        new_password: "Br4nd!NewPassword",
        confirm_password: "Br4nd!NewPassword",
      });
    });

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    // Signed out: the session is gone and a one-time notice is queued for
    // the login page.
    expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
    expect(window.sessionStorage.getItem("ss-admin-signin-notice")).toBe("password_changed");
  });

  it("shows an inline error and keeps the dialog open when the current password is wrong", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/auth/change-password")) {
        // 400, not 401: a wrong current password is a validation failure
        // on an already-authenticated request, never treated as an
        // expired session (useAuthorizedFetch forces a sign-out on any
        // 401, which must NOT happen here).
        return { ok: false, status: 400, json: () => Promise.resolve({ detail: "Current password is incorrect" }) };
      }
      return { ok: true, status: 200, json: () => Promise.resolve({}) };
    });

    const { onClose } = renderDialog();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "WrongPassword!" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByText("Current password is incorrect")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    // Not signed out on failure - the session is still intact.
    expect(window.sessionStorage.getItem("ss-admin-session")).not.toBeNull();
  });

  it("never displays the password value anywhere after typing it", () => {
    renderDialog();
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    // The input itself is type="password" by default (masked) - only the
    // show/hide toggle, never the raw value, is exposed as visible text.
    const input = screen.getByLabelText("New password") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(screen.queryByText("Br4nd!NewPassword")).not.toBeInTheDocument();
  });

  it("the show/hide toggle reveals and re-masks the password", () => {
    renderDialog();
    const input = screen.getByLabelText("New password") as HTMLInputElement;
    expect(input.type).toBe("password");

    fireEvent.click(screen.getByRole("button", { name: "Show new password" }));
    expect(input.type).toBe("text");

    fireEvent.click(screen.getByRole("button", { name: "Hide new password" }));
    expect(input.type).toBe("password");
  });

  it("cancelling closes the dialog without calling the API", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { onClose } = renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
