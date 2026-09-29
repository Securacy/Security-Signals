import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { SignalDetailPage } from "../../../src/admin/pages/SignalDetailPage";
import type { Role } from "../../../src/admin/auth/types";

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
      user: { id: "u-self", username: "tester", email: "tester@test.local", role },
    }),
  );
}

const adminDetail = {
  id: "sig-1",
  title: "OAuth Audience Validation Bypass",
  status: "published",
  summary: "summary text",
  security_impact: "impact text",
  principle: "principle text",
  recommended_action: "action text",
  created_at: "2026-01-01T00:00:00Z",
  reviewed_by: null,
  reviewed_at: null,
  published_at: "2026-01-02T00:00:00Z",
  categories: [],
  public_categories: [],
  evidence: [],
  visual_status: "generated",
  visual_url: "/media/signals/sig-1.png",
  visual_requested_at: "2026-01-01T00:00:01Z",
};

const publicDetail = {
  id: "sig-1",
  title: "OAuth Audience Validation Bypass",
  summary: "summary text",
  security_impact: "impact text",
  principle: "principle text",
  recommended_action: "action text",
  published_at: "2026-01-02T00:00:00Z",
  categories: [],
  public_categories: [],
  evidence: [],
  visual_status: "none",
  visual_url: null,
};

function renderPage(signalId = "sig-1") {
  return render(
    <AuthProvider>
      <RouterProvider>
        <WaitForSession>
          <SignalDetailPage signalId={signalId} />
        </WaitForSession>
      </RouterProvider>
    </AuthProvider>,
  );
}

describe("SignalDetailPage", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("ADMIN fetches via the protected /signals/{id} endpoint, never the public one", async () => {
    seedSession("admin");
    const fetchMock = vi.fn((url: string) => {
      if (String(url).includes("/api/v1/users")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(adminDetail) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    expect(await screen.findByText("OAuth Audience Validation Bypass")).toBeInTheDocument();
    const detailCall = fetchMock.mock.calls.find((c) => !String(c[0]).includes("/users"));
    const calledUrl = String(detailCall![0]);
    expect(calledUrl).toContain("/api/v1/signals/sig-1");
    expect(calledUrl).not.toContain("/published/");
  });

  it("VIEWER fetches via the public /signals/published/{id} endpoint instead - regression test for the 403 a viewer previously got from the protected endpoint", async () => {
    seedSession("viewer");
    const fetchMock = vi.fn((url: string) =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(publicDetail) }),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    expect(await screen.findByText("OAuth Audience Validation Bypass")).toBeInTheDocument();
    const calledUrl = String(fetchMock.mock.calls[0][0]);
    expect(calledUrl).toContain("/api/v1/signals/published/sig-1");

    // No submit/approve/reject/publish action for a read-only VIEWER on a
    // published signal.
    expect(screen.queryByRole("button", { name: /submit|approve|reject|publish/i })).not.toBeInTheDocument();
  });

  it("VIEWER sees a legacy signal's missing visual as a distinct, honest state rather than a fabricated 'generating'", async () => {
    seedSession("viewer");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(publicDetail) })),
    );

    renderPage();

    await screen.findByText("OAuth Audience Validation Bypass");
    expect(screen.getByText("No visual has been generated for this signal.")).toBeInTheDocument();
    expect(screen.queryByText("Visual generating…")).not.toBeInTheDocument();
  });

  it("shows an error state when the fetch fails", async () => {
    seedSession("admin");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({ detail: "boom" }) })),
    );

    renderPage();

    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
