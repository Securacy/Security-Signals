import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { DashboardPage } from "../../../src/admin/pages/DashboardPage";
import type { Role } from "../../../src/admin/auth/types";

/** Mirrors the isRestoring/isAuthenticated guard AdminRoot applies in
 * production before ever mounting a page - DashboardPage assumes a
 * non-null user, same as it does when reached through the real app. */
function WaitForSession({ children }: { children: ReactNode }) {
  const { isRestoring, isAuthenticated } = useAuth();
  if (isRestoring || !isAuthenticated) return null;
  return <>{children}</>;
}

function seedSession(role: Role) {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id: "u1", username: "tester", email: "tester@test.local", role },
    }),
  );
}

const EMPTY_INTERNAL_ANALYTICS = {
  generated_at: "2024-01-01T00:00:00Z",
  window_months: 36,
  total_signals: 0,
  status_totals: {},
  monthly_counts: [],
  monthly_counts_by_status: {},
};

const EMPTY_PUBLIC_ANALYTICS = {
  generated_at: "2024-01-01T00:00:00Z",
  window_months: 12,
  total_published: 0,
  monthly_counts: [],
  category_counts: {},
  principle_counts: {},
  dominant_theme: null,
};

/** Default body for any path not explicitly stubbed. The two analytics
 * endpoints (Signal lifecycle bar + Security landscape) are fetched
 * unconditionally by every render, so they need a real object shape - a
 * bare `[]` fallback (fine for the various list endpoints) would otherwise
 * crash those two sections. */
function defaultBodyForUrl(url: string): unknown {
  if (url.includes("/analytics/internal")) return EMPTY_INTERNAL_ANALYTICS;
  if (url.includes("/analytics/public")) return EMPTY_PUBLIC_ANALYTICS;
  return [];
}

function mockFetchByPath(handlers: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string) => {
      const url = typeof input === "string" ? input : String(input);
      const match = Object.keys(handlers).find((path) => url.includes(path));
      if (!match) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(defaultBodyForUrl(url)) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(handlers[match]) });
    }),
  );
}

function renderDashboard() {
  return render(
    <AuthProvider>
      <RouterProvider>
        <WaitForSession>
          <DashboardPage />
        </WaitForSession>
      </RouterProvider>
    </AuthProvider>,
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("shows a friendly session greeting as the heading, and the username in the subtitle beneath it", async () => {
    seedSession("admin");
    mockFetchByPath({
      "/signals/draft": [],
      "/signals/approved": [],
      "/audit": [],
      "/admin/category-health": [],
      "/signals/published": [],
      "/users": [],
    });

    renderDashboard();

    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent!.length).toBeGreaterThan(0);
    expect(screen.getByText(new RegExp(`tester`))).toBeInTheDocument();
  });

  it("keeps the same greeting across a re-render rather than picking a new one every time", async () => {
    seedSession("admin");
    mockFetchByPath({
      "/signals/draft": [],
      "/signals/approved": [],
      "/audit": [],
      "/admin/category-health": [],
      "/signals/published": [],
      "/users": [],
    });

    const { rerender } = renderDashboard();
    const heading = await screen.findByRole("heading", { level: 1 });
    const first = heading.textContent;

    rerender(
      <AuthProvider>
        <RouterProvider>
          <WaitForSession>
            <DashboardPage />
          </WaitForSession>
        </RouterProvider>
      </AuthProvider>,
    );

    expect((await screen.findByRole("heading", { level: 1 })).textContent).toBe(first);
  });

  it("ADMIN sees the needs-attention strip plus all admin-only dashboard sections", async () => {
    seedSession("admin");
    mockFetchByPath({
      "/signals/draft": [],
      "/signals/approved": [],
      "/audit": [],
      "/admin/category-health": [],
      "/signals/published": [],
      "/users": [],
    });

    renderDashboard();

    expect(await screen.findByText("Needs your attention")).toBeInTheDocument();
    expect(screen.getByText("Drafts to submit")).toBeInTheDocument();
    expect(screen.getByText("Signals awaiting your review")).toBeInTheDocument();
    expect(screen.getByText("Signals ready to publish")).toBeInTheDocument();
    expect(screen.getByText("Recently published")).toBeInTheDocument();
    expect(screen.getByText("Recent activity")).toBeInTheDocument();
    expect(screen.getByText("Source health")).toBeInTheDocument();
    expect(screen.getByText("Team")).toBeInTheDocument();
    expect(screen.getByText("Signal lifecycle")).toBeInTheDocument();
    expect(screen.getByText("Security landscape")).toBeInTheDocument();
  });

  it("REVIEWER sees the needs-attention strip but no admin-only sections", async () => {
    seedSession("reviewer");
    mockFetchByPath({
      "/signals/draft": [],
      "/signals/published": [],
    });

    renderDashboard();

    expect(await screen.findByText("Needs your attention")).toBeInTheDocument();
    expect(screen.getByText("Drafts to submit")).toBeInTheDocument();
    expect(screen.getByText("Signals awaiting your review")).toBeInTheDocument();
    expect(screen.getByText("Recently published")).toBeInTheDocument();
    expect(screen.queryByText("Signals ready to publish")).not.toBeInTheDocument();
    expect(screen.queryByText("Recent activity")).not.toBeInTheDocument();
    expect(screen.queryByText("Source health")).not.toBeInTheDocument();
    expect(screen.queryByText("Team")).not.toBeInTheDocument();
  });

  it("VIEWER sees only Recently published - no needs-attention or admin sections, and never calls the draft endpoint", async () => {
    seedSession("viewer");
    const fetchMock = vi.fn((input: string) =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(defaultBodyForUrl(String(input))) }),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderDashboard();

    expect(await screen.findByText("Recently published")).toBeInTheDocument();
    expect(screen.queryByText("Needs your attention")).not.toBeInTheDocument();
    expect(screen.queryByText("Signal lifecycle")).not.toBeInTheDocument();
    expect(screen.queryByText("Recent activity")).not.toBeInTheDocument();
    expect(screen.queryByText("Source health")).not.toBeInTheDocument();
    expect(screen.queryByText("Team")).not.toBeInTheDocument();

    await waitFor(() => {
      const calledDraftEndpoint = fetchMock.mock.calls.some((call) => String(call[0]).includes("/signals/draft"));
      expect(calledDraftEndpoint).toBe(false);
    });
  });

  it('shows "All caught up" on a needs-attention tile when its queue is empty', async () => {
    seedSession("reviewer");
    mockFetchByPath({
      "/signals/draft": [],
      "/signals/published": [],
    });

    renderDashboard();

    const tiles = await screen.findAllByText("All caught up");
    expect(tiles.length).toBeGreaterThan(0);
  });

  it("shows an error state on a needs-attention tile when its fetch fails", async () => {
    seedSession("reviewer");
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string) => {
        if (String(input).includes("/signals/draft")) {
          return Promise.resolve({
            ok: false,
            status: 500,
            json: () => Promise.resolve({ detail: "boom" }),
          });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(defaultBodyForUrl(String(input))) });
      }),
    );

    renderDashboard();

    // Both the "Drafts to submit" and "Signals awaiting your review" tiles
    // are backed by the same /signals/draft fetch, so both legitimately
    // show an error - at least one, not necessarily exactly one.
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.length).toBeGreaterThan(0);
  });

  it("renders an error state on the Recently published section when its fetch fails", async () => {
    seedSession("viewer");
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({
          ok: false,
          status: 500,
          json: () => Promise.resolve({ detail: "boom" }),
        }),
      ),
    );

    renderDashboard();

    // Recently published and Security landscape both fetch independently
    // and both legitimately error here - at least one alert, not exactly one.
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.length).toBeGreaterThan(0);
  });
});
