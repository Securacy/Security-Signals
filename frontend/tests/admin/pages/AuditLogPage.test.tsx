import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { AuditLogPage } from "../../../src/admin/pages/AuditLogPage";

function WaitForSession({ children }: { children: ReactNode }) {
  const { isRestoring, isAuthenticated } = useAuth();
  if (isRestoring || !isAuthenticated) return null;
  return <>{children}</>;
}

function seedSession() {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id: "u-self", username: "current-admin", email: "current-admin@test.local", role: "admin" },
    }),
  );
}

const approvedEntry = {
  id: "audit-1",
  user_id: "u-self",
  action: "SIGNAL_APPROVED",
  resource_type: "SIGNAL",
  resource_id: "sig-123456789",
  changes: { status_from: "in_review", status_to: "approved" },
  timestamp: "2026-01-05T10:00:00Z",
};

const rejectedEntry = {
  id: "audit-2",
  user_id: null,
  action: "SIGNAL_REJECTED",
  resource_type: "SIGNAL",
  resource_id: "sig-987654321",
  changes: { status_from: "in_review", status_to: "rejected", reason: "Stale evidence" },
  timestamp: "2026-01-04T09:00:00Z",
};

const roleUpdatedEntry = {
  id: "audit-3",
  user_id: "u-self",
  action: "USER_UPDATED",
  resource_type: "USER",
  resource_id: "u-target",
  changes: { role: { from: "viewer", to: "reviewer" } },
  timestamp: "2026-01-03T09:00:00Z",
};

const usersResponse = [
  {
    id: "u-self",
    username: "current-admin",
    email: "a@test.local",
    role: "admin",
    is_active: true,
    has_local_credential: true,
    entra_linked: false,
    created_at: null,
    updated_at: null,
    last_login_at: null,
  },
  {
    id: "u-target",
    username: "John Doe",
    email: "j@test.local",
    role: "reviewer",
    is_active: true,
    has_local_credential: true,
    entra_linked: false,
    created_at: null,
    updated_at: null,
    last_login_at: null,
  },
];

/** Routes every fetch this page can issue to a sensible default (empty
 * signal lists, empty user list) so tests only need to override the /audit
 * response and, when relevant, /users - the three signal-title lookups
 * (draft/approved/rejected + the public published list) never need to be
 * mocked per-test just to avoid a crash. */
function mockAuditFetches(auditResponse: unknown, usersOverride: unknown = usersResponse) {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const u = String(url);
      if (u.includes("/api/v1/users")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(usersOverride) });
      }
      if (u.includes("/api/v1/audit")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(auditResponse) });
      }
      // draft/approved/rejected/published signal-title lookups
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    }),
  );
}

function renderPage() {
  return render(
    <AuthProvider>
      <RouterProvider>
        <WaitForSession>
          <AuditLogPage />
        </WaitForSession>
      </RouterProvider>
    </AuthProvider>,
  );
}

describe("AuditLogPage", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("renders a signal event as a human-readable title, signal/actor facts, and timestamp", async () => {
    seedSession();
    mockAuditFetches([approvedEntry, rejectedEntry]);

    renderPage();

    expect(await screen.findByText("Signal approved")).toBeInTheDocument();
    expect(screen.getByText("Signal rejected")).toBeInTheDocument();
    // actor resolved from the real /users list, not a raw UUID
    expect(screen.getByText("current-admin")).toBeInTheDocument();
    // no user_id -> "System", never fabricated
    expect(screen.getAllByText("System").length).toBeGreaterThan(0);
    // the reject reason is surfaced as a real fact, not buried in raw JSON
    // (it also appears inside the collapsed raw-details payload, hence >0)
    expect(screen.getByText("Review note")).toBeInTheDocument();
    expect(screen.getAllByText("Stale evidence").length).toBeGreaterThan(0);
  });

  it("renders a user-management event with resolved target name, previous/new role, and actor", async () => {
    seedSession();
    mockAuditFetches([roleUpdatedEntry]);

    renderPage();

    expect(await screen.findByText("User role updated")).toBeInTheDocument();
    expect(screen.getByText("John Doe")).toBeInTheDocument(); // Target, resolved from /users
    expect(screen.getByText("Viewer")).toBeInTheDocument(); // Previous
    expect(screen.getByText("Reviewer")).toBeInTheDocument(); // New
    expect(screen.getByText("current-admin")).toBeInTheDocument(); // Changed by
  });

  it("shows an empty state when there are no entries", async () => {
    seedSession();
    mockAuditFetches([]);

    renderPage();

    expect(await screen.findByText("No audit entries have been recorded yet.")).toBeInTheDocument();
  });

  it("shows an error state when the log fails to load", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (String(url).includes("/api/v1/audit")) {
          return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({ detail: "boom" }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
      }),
    );

    renderPage();

    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("applying filters sends the exact backend query params, and Clear filters resets them", async () => {
    seedSession();
    const fetchMock = vi.fn((url: string) => {
      const u = String(url);
      if (u.includes("/api/v1/users")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(usersResponse) });
      }
      if (u.includes("/api/v1/audit")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([approvedEntry]) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("Signal approved");

    fireEvent.change(screen.getByLabelText("Resource type"), { target: { value: "SIGNAL" } });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "SIGNAL_APPROVED" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes("resource_type=SIGNAL") && String(c[0]).includes("action=SIGNAL_APPROVED"),
      );
      expect(call).toBeDefined();
    });

    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));

    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
    });
  });

  it("shows a distinct empty-state message when filters exclude everything", async () => {
    seedSession();
    let callCount = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        const u = String(url);
        if (u.includes("/api/v1/users")) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(usersResponse) });
        }
        if (u.includes("/api/v1/audit")) {
          callCount += 1;
          // first load: has data (so filter inputs get a suggestion), second (filtered) load: empty
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(callCount === 1 ? [approvedEntry] : []),
          });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
      }),
    );

    renderPage();
    await screen.findByText("Signal approved");

    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "NO_SUCH_ACTION" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(await screen.findByText("No audit entries match these filters.")).toBeInTheDocument();
  });

  it("does not render changes as raw JSON keys the user can't parse - uses a collapsible raw-details section", async () => {
    seedSession();
    mockAuditFetches([rejectedEntry]);

    renderPage();
    await screen.findByText("Signal rejected");

    // "Stale evidence" is already visible as the human-readable "Review
    // note" fact - the raw details section additionally exposes the exact
    // changes payload behind an explicit toggle.
    const details = screen.getByText("View raw details");
    fireEvent.click(details);
    expect(await screen.findByText("reason")).toBeInTheDocument();
  });
});
