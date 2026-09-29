import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AdminApp } from "../../src/admin/AdminApp";
import type { Role } from "../../src/admin/auth/types";

function seedSession(role: Role) {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id: "u1", username: "tester", email: "tester@test.local", role },
    }),
  );
}

describe("AdminApp routing + RBAC guard", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })));
  });

  it("shows the login page when not authenticated, regardless of the requested path", () => {
    window.history.pushState(null, "", "/admin/users");

    render(<AdminApp />);

    expect(screen.getByRole("heading", { name: "Security Signals" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users" })).not.toBeInTheDocument();
  });

  it("blocks a REVIEWER from /admin/users via a typed URL and does not render the Users page", async () => {
    seedSession("reviewer");
    window.history.pushState(null, "", "/admin/users");

    render(<AdminApp />);

    expect(await screen.findByText("You don't have access to this page.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users" })).not.toBeInTheDocument();
  });

  it("blocks a VIEWER from /admin/review via a typed URL", async () => {
    seedSession("viewer");
    window.history.pushState(null, "", "/admin/review");

    render(<AdminApp />);

    expect(await screen.findByText("You don't have access to this page.")).toBeInTheDocument();
  });

  it("redirects a REVIEWER's legacy /admin/review link to the real In Review signals list (not a placeholder)", async () => {
    seedSession("reviewer");
    window.history.pushState(null, "", "/admin/review");

    render(<AdminApp />);

    expect(await screen.findByRole("heading", { name: "In Review" })).toBeInTheDocument();
    expect(screen.queryByText("This section is coming in the next update.")).not.toBeInTheDocument();
  });

  it("allows an ADMIN to reach every route, including admin-only ones", async () => {
    seedSession("admin");
    window.history.pushState(null, "", "/admin/audit");

    render(<AdminApp />);

    expect(await screen.findByRole("heading", { name: "Audit Logs" })).toBeInTheDocument();
    expect(screen.queryByText("This section is coming in the next update.")).not.toBeInTheDocument();
  });

  it("lets an ADMIN reach the real Users page (not a placeholder) at /admin/users", async () => {
    seedSession("admin");
    window.history.pushState(null, "", "/admin/users");

    render(<AdminApp />);

    expect(await screen.findByRole("heading", { name: "Users" })).toBeInTheDocument();
    expect(screen.queryByText("This section is coming in the next update.")).not.toBeInTheDocument();
  });

  it("blocks a REVIEWER from /admin/audit via a typed URL", async () => {
    seedSession("reviewer");
    window.history.pushState(null, "", "/admin/audit");

    render(<AdminApp />);

    expect(await screen.findByText("You don't have access to this page.")).toBeInTheDocument();
  });

  it("redirects an already-authenticated user away from /admin/login to the dashboard", async () => {
    seedSession("viewer");
    window.history.pushState(null, "", "/admin/login");

    render(<AdminApp />);

    // The dashboard's own heading is a personalized, time-of-day greeting
    // rather than a static "Dashboard" title - matching it loosely confirms
    // the redirect landed on the dashboard without pinning the exact greeting.
    expect(await screen.findByRole("heading", { level: 1, name: /good (morning|afternoon|evening), tester/i })).toBeInTheDocument();
  });

  it("only shows the REVIEWER's own nav items, not Approved/Users/Audit", async () => {
    seedSession("reviewer");
    window.history.pushState(null, "", "/admin/");

    render(<AdminApp />);

    await screen.findByRole("heading", { level: 1, name: /good (morning|afternoon|evening), tester/i });
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveTextContent("In Review");
    expect(nav).toHaveTextContent("Drafts");
    expect(nav).not.toHaveTextContent("Approved");
    expect(nav).not.toHaveTextContent("Users");
    expect(nav).not.toHaveTextContent("Audit Log");
  });
});
