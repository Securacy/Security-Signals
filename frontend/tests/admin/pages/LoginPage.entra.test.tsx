import { StrictMode } from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthProvider } from "../../../src/admin/auth/AuthContext";
import { LoginPage } from "../../../src/admin/pages/LoginPage";

type Providers = { local: boolean; entra: boolean };

const SESSION_RESPONSE = {
  access_token: "app-jwt-from-backend",
  token_type: "bearer",
  user: { id: "u1", username: "ada@corp.test", email: "ada@corp.test", role: "reviewer", is_active: true },
};

function stubBackend(opts: { providers?: Providers | "error"; session?: () => Promise<unknown> } = {}) {
  const fetchMock = vi.fn((input: string, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/v1/auth/providers")) {
      if (opts.providers === "error") return Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(opts.providers ?? { local: true, entra: true }) });
    }
    if (url.includes("/api/v1/auth/entra/session")) {
      return opts.session ? opts.session() : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(SESSION_RESPONSE) });
    }
    void init;
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderLogin(strict = false) {
  const tree = (
    <AuthProvider>
      <LoginPage />
    </AuthProvider>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

function visitLoginUrl(search = "") {
  window.history.replaceState(null, "", `/admin/login${search}`);
}

describe("LoginPage - Microsoft Entra ID sign-in", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    visitLoginUrl();
  });

  describe("which sign-in methods are offered", () => {
    it("offers 'Sign in with Microsoft' as a link to the backend login endpoint, alongside the password form", async () => {
      stubBackend({ providers: { local: true, entra: true } });
      renderLogin();

      const link = await screen.findByRole("link", { name: "Sign in with Microsoft" });
      expect(link).toHaveAttribute("href", expect.stringMatching(/\/api\/v1\/auth\/entra\/login$/));
      expect(screen.getByLabelText("Username")).toBeInTheDocument();
    });

    it("shows only Microsoft sign-in when the password login is switched off", async () => {
      stubBackend({ providers: { local: false, entra: true } });
      renderLogin();

      expect(await screen.findByRole("link", { name: "Sign in with Microsoft" })).toBeInTheDocument();
      expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
      expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    });

    it("shows only the password form when Entra is not enabled", async () => {
      stubBackend({ providers: { local: true, entra: false } });
      renderLogin();

      expect(await screen.findByLabelText("Username")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /microsoft/i })).not.toBeInTheDocument();
    });

    it("says so plainly when no sign-in method is available", async () => {
      stubBackend({ providers: { local: false, entra: false } });
      renderLogin();

      expect(await screen.findByRole("alert")).toHaveTextContent("No sign-in method is available");
    });

    it("shows a loading state while the options load, and an error with retry if they can't", async () => {
      const fetchMock = stubBackend({ providers: "error" });
      renderLogin();

      expect(screen.getByText("Loading sign-in options…")).toBeInTheDocument();
      expect(await screen.findByRole("alert")).toHaveTextContent("503");

      fetchMock.mockImplementation((input: string) =>
        Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(input.includes("providers") ? { local: true, entra: true } : {}) }),
      );
      fireEvent.click(screen.getByRole("button", { name: "Try again" }));
      expect(await screen.findByRole("link", { name: "Sign in with Microsoft" })).toBeInTheDocument();
    });
  });

  describe("errors returned by the backend after a failed Microsoft sign-in", () => {
    it.each([
      ["not_provisioned", /not been set up/i],
      ["access_denied", /cancelled or is not permitted/i],
      ["invalid_state", /expired or could not be verified/i],
      ["invalid_token", /could not be verified/i],
      ["account_disabled", /deactivated/i],
      ["account_conflict", /already linked to a different account/i],
      ["auth_failed", /Sign-in failed/i],
    ])("maps ?error=%s to a clear message", async (code, expected) => {
      stubBackend();
      visitLoginUrl(`?error=${code}`);
      renderLogin();

      expect(await screen.findByRole("alert")).toHaveTextContent(expected);
    });

    it("never echoes an unknown or hostile error code back into the page", async () => {
      stubBackend();
      visitLoginUrl("?error=%3Cscript%3Ealert(1)%3C/script%3E");
      renderLogin();

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("Sign-in failed. Please try again.");
      expect(alert.textContent).not.toContain("script");
    });

    it("removes the error code from the URL after showing it, so a refresh doesn't repeat it", async () => {
      stubBackend();
      visitLoginUrl("?error=access_denied");
      renderLogin();

      await screen.findByRole("alert");
      await waitFor(() => expect(window.location.search).toBe(""));
    });

    it("the password form is still usable after a Microsoft error", async () => {
      stubBackend({ providers: { local: true, entra: true } });
      visitLoginUrl("?error=access_denied");
      renderLogin();

      expect(await screen.findByLabelText("Username")).toBeInTheDocument();
    });
  });

  describe("completing a successful Microsoft sign-in (?signin=complete)", () => {
    it("exchanges the handoff cookie for the app session using a credentialed, headed request - and no token ever sits in the URL", async () => {
      const fetchMock = stubBackend();
      visitLoginUrl("?signin=complete");
      renderLogin();

      expect(screen.getByText("Completing Microsoft sign-in…")).toBeInTheDocument();
      await waitFor(() => expect(window.sessionStorage.getItem("ss-admin-session")).not.toBeNull());

      const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/api/v1/auth/entra/session"))!;
      const init = call[1] as RequestInit;
      expect(init.method).toBe("POST");
      expect(init.credentials).toBe("include");
      expect((init.headers as Record<string, string>)["X-Requested-With"]).toBe("ss-admin");
      expect(init.body).toBeUndefined();

      const stored = JSON.parse(window.sessionStorage.getItem("ss-admin-session")!);
      expect(stored.token).toBe("app-jwt-from-backend");
      expect(stored.user.role).toBe("reviewer");
      expect(window.location.href).not.toContain("app-jwt-from-backend");
      expect(window.location.search).toBe("");
    });

    it("shows a clear error and returns to the sign-in options if the exchange is rejected", async () => {
      stubBackend({ session: () => Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({ detail: "No pending sign-in" }) }) });
      visitLoginUrl("?signin=complete");
      renderLogin();

      expect(await screen.findByRole("alert")).toHaveTextContent("could not be completed");
      expect(await screen.findByRole("link", { name: "Sign in with Microsoft" })).toBeInTheDocument();
      expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
    });

    it("shows an error if the backend is unreachable during the exchange", async () => {
      stubBackend({ session: () => Promise.reject(new TypeError("network down")) });
      visitLoginUrl("?signin=complete");
      renderLogin();

      expect(await screen.findByRole("alert")).toHaveTextContent("Network error");
      expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
    });

    it("rejects a malformed or role-less session response instead of trusting it", async () => {
      stubBackend({ session: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ access_token: "t", user: { id: "1", username: "x", role: "superuser" } }) }) });
      visitLoginUrl("?signin=complete");
      renderLogin();

      expect(await screen.findByRole("alert")).toHaveTextContent("invalid response");
      expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
    });

    it("makes the single-use exchange exactly once even under React StrictMode's double effect run", async () => {
      const fetchMock = stubBackend();
      visitLoginUrl("?signin=complete");
      renderLogin(true);

      await waitFor(() => expect(window.sessionStorage.getItem("ss-admin-session")).not.toBeNull());
      const exchanges = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/v1/auth/entra/session"));
      expect(exchanges).toHaveLength(1);
    });
  });

  describe("expired sessions", () => {
    it("tells the user their session expired, once", async () => {
      stubBackend();
      window.sessionStorage.setItem("ss-admin-signin-notice", "expired");
      const first = renderLogin();

      expect(await screen.findByRole("status")).toHaveTextContent("Your session has expired");
      first.unmount();

      renderLogin();
      await screen.findByRole("link", { name: "Sign in with Microsoft" });
      expect(screen.queryByText(/session has expired/i)).not.toBeInTheDocument();
    });

    it("tells the user their password was changed, once, distinctly from an expired session", async () => {
      stubBackend();
      window.sessionStorage.setItem("ss-admin-signin-notice", "password_changed");
      const first = renderLogin();

      expect(await screen.findByRole("status")).toHaveTextContent("Your password was changed");
      first.unmount();

      renderLogin();
      await screen.findByRole("link", { name: "Sign in with Microsoft" });
      expect(screen.queryByText(/password was changed/i)).not.toBeInTheDocument();
    });
  });

  describe("password login when Entra is also available", () => {
    it("explains a disabled password login instead of calling the account inactive", async () => {
      stubBackend({ providers: { local: true, entra: true } });
      const fetchMock = vi.mocked(fetch);
      const base = fetchMock.getMockImplementation()!;
      fetchMock.mockImplementation((input, init) =>
        String(input).includes("/api/v1/auth/login")
          ? Promise.resolve({ ok: false, status: 403, json: () => Promise.resolve({ detail: "Password sign-in is disabled" }) } as Response)
          : (base as (i: unknown, n?: unknown) => Promise<Response>)(input, init),
      );
      renderLogin();

      fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "u" } });
      fireEvent.change(screen.getByLabelText("Password"), { target: { value: "p" } });
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

      expect(await screen.findByRole("alert")).toHaveTextContent("Password sign-in is disabled");
    });
  });
});
