import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthProvider } from "../../../src/admin/auth/AuthContext";
import { LoginPage } from "../../../src/admin/pages/LoginPage";

function renderLogin() {
  return render(
    <AuthProvider>
      <LoginPage />
    </AuthProvider>,
  );
}

/** The login page first asks GET /auth/providers which sign-in methods to
 * offer (password-only here, as before Entra existed); every other request
 * is answered by the per-test `loginHandler`. */
function mockFetch(loginHandler: () => unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string) => {
      if (String(input).includes("/api/v1/auth/providers")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ local: true, entra: false }) });
      }
      return loginHandler();
    }),
  );
}

async function fillAndSubmit(username: string, password: string) {
  fireEvent.change(await screen.findByLabelText("Username"), { target: { value: username } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
}

describe("LoginPage", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    vi.stubGlobal("fetch", vi.fn());
  });

  it("shows a loading state while signing in", async () => {
    let resolveFetch: (value: unknown) => void = () => {};
    const pendingLogin = new Promise((resolve) => {
      resolveFetch = resolve;
    });
    mockFetch(() => pendingLogin);

    renderLogin();
    await fillAndSubmit("admin-demo", "correct-password");

    expect(screen.getByRole("button", { name: /signing in/i })).toBeDisabled();

    resolveFetch({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve({
          access_token: "tok",
          token_type: "bearer",
          user: { id: "1", username: "admin-demo", email: "a@test.local", role: "admin", is_active: true },
        }),
    });

    await waitFor(() => expect(screen.queryByRole("button", { name: /signing in/i })).not.toBeInTheDocument());
  });

  it("shows an inline error on invalid credentials, without crashing or navigating away", async () => {
    mockFetch(() =>
      Promise.resolve({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ detail: "Invalid username or password" }),
      }),
    );

    renderLogin();
    await fillAndSubmit("admin-demo", "wrong-password");

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  it("does not store any session in sessionStorage after a failed login", async () => {
    mockFetch(() =>
      Promise.resolve({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ detail: "Invalid username or password" }),
      }),
    );

    renderLogin();
    await fillAndSubmit("admin-demo", "wrong-password");
    await screen.findByRole("alert");

    expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
  });
});
