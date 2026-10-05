import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { AuthProvider } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { ThemeProvider } from "../../../src/admin/theme";
import { TopBar } from "../../../src/admin/components/TopBar";

function seedSession() {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: {
        id: "u1",
        username: "tester",
        email: "tester@example.test",
        role: "admin",
        hasLocalCredential: true,
        entraLinked: false,
      },
    }),
  );
}

function renderTopBar() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <RouterProvider>
          <TopBar />
        </RouterProvider>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("TopBar", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    seedSession();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) })));
  });

  it("renders nothing before a session exists", () => {
    window.sessionStorage.clear();
    renderTopBar();
    expect(screen.queryByRole("button", { name: /tester/i })).not.toBeInTheDocument();
  });

  it("shows the signed-in user's profile menu, with Change password and Sign out inside it", () => {
    renderTopBar();

    expect(screen.queryByText("Change password")).not.toBeInTheDocument();
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /tester/i }));

    expect(screen.getAllByText("tester").length).toBeGreaterThan(0);
    expect(screen.getByText("tester@example.test")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Change password" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Sign out" })).toBeInTheDocument();
  });

  it("opens the change-password dialog from the profile menu", () => {
    renderTopBar();

    fireEvent.click(screen.getByRole("button", { name: /tester/i }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("menuitem", { name: "Change password" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("Change your password");
  });

  it("shows the current page's title instead of standalone branding - branding now lives in the sidebar", () => {
    window.history.pushState(null, "", "/admin/users");
    renderTopBar();

    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.queryByText("Security Signals Admin")).not.toBeInTheDocument();
  });

  it("falls back to the Cyberscope brand name, not the old Security Signals name, on an unmatched route", () => {
    window.history.pushState(null, "", "/admin/does-not-exist");
    renderTopBar();

    expect(screen.getByText("Cyberscope")).toBeInTheDocument();
    expect(screen.queryByText("Security Signals")).not.toBeInTheDocument();
  });

  it("on the dashboard shows no separate 'Dashboard' label, but keeps the account menu", () => {
    window.history.pushState(null, "", "/admin/");
    renderTopBar();

    expect(screen.queryByText("Dashboard")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /tester/i })).toBeInTheDocument();
  });
});
