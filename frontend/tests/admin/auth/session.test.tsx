import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AdminApp } from "../../../src/admin/AdminApp";
import { consumeSignInNotice } from "../../../src/admin/auth/AuthContext";

function seedReviewer() {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({ token: "live-token", user: { id: "u1", username: "rita", email: "r@x.test", role: "reviewer" } }),
  );
}

describe("sign-out and session expiry", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    window.history.replaceState(null, "", "/admin/");
  });

  it("a user-initiated sign-out clears the session and reports it to the backend for the audit log", async () => {
    seedReviewer();
    const fetchMock = vi.fn((input: string) => {
      if (String(input).includes("/auth/providers")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ local: true, entra: true }) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<AdminApp />);

    fireEvent.click(await screen.findByRole("button", { name: /rita/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Sign out" }));

    await waitFor(() => expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull());
    const logout = fetchMock.mock.calls.find((c) => String(c[0]).includes("/api/v1/auth/logout"))!;
    expect((logout[1] as RequestInit).method).toBe("POST");
    expect((logout[1] as { headers: Record<string, string> }).headers.Authorization).toBe("Bearer live-token");
    expect(consumeSignInNotice()).toBeNull(); // a deliberate sign-out is not an "expired" notice
    expect(await screen.findByRole("link", { name: "Sign in with Microsoft" })).toBeInTheDocument();
  });

  it("a rejected token (401) signs the user out and the login page explains the session expired", async () => {
    seedReviewer();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string) => {
        const url = String(input);
        if (url.includes("/auth/providers")) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ local: true, entra: true }) });
        }
        if (url.includes("/api/v1/signals/draft")) {
          return Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({ detail: "Invalid or expired token" }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
      }),
    );
    render(<AdminApp />);

    expect(await screen.findByText("Your session has expired. Please sign in again.")).toBeInTheDocument();
    expect(window.sessionStorage.getItem("ss-admin-session")).toBeNull();
    expect(await screen.findByRole("link", { name: "Sign in with Microsoft" })).toBeInTheDocument();
  });

  it("does not try to call the logout endpoint with an already-expired token", async () => {
    seedReviewer();
    const fetchMock = vi.fn((input: string) => {
      const url = String(input);
      if (url.includes("/auth/providers")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ local: true, entra: false }) });
      }
      if (url.includes("/signals/draft")) {
        return Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<AdminApp />);

    await screen.findByText("Your session has expired. Please sign in again.");
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/auth/logout"))).toBe(false);
  });
});
