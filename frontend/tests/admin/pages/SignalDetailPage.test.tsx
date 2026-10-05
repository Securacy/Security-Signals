import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
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
  updated_at: "2026-01-01T00:00:00Z",
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

const draftDetail = {
  ...adminDetail,
  status: "draft",
  published_at: null,
  categories: [{ id: "cat-1", category: "iam", subcategory: null }],
  public_categories: ["cloud_identity_security"],
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

  describe("evidence & sources rendering", () => {
    function detailWithEvidence(excerpt: string, source_url = "https://example.com/bulletin") {
      return {
        ...adminDetail,
        evidence: [
          {
            id: "ev-1",
            source_url,
            source_title: "Example Security Bulletin",
            excerpt,
            created_at: "2026-01-01T00:00:00Z",
          },
        ],
      };
    }

    function stubDetailFetch(detail: unknown) {
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string) => {
          if (String(url).includes("/api/v1/users")) {
            return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
          }
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(detail) });
        }),
      );
    }

    it("renders formatted HTML (bold label, line break, real link) instead of literal tag text", async () => {
      seedSession("admin");
      stubDetailFetch(
        detailWithEvidence(
          '<p><b>Bulletin ID:</b> 2026-117-AWS <br /> <b>Scope:</b> AWS</p><p><a href="https://aws.amazon.com/security/security-bulletins/2026-117-aws/">View article</a></p>',
        ),
      );

      const { container } = renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      // The raw tag characters are never shown as literal text.
      expect(screen.queryByText(/<p>|<b>|&lt;p&gt;/)).not.toBeInTheDocument();
      expect(screen.getByText("Bulletin ID:")).toBeInTheDocument();
      expect(container.querySelector(".adm-evidence-list__excerpt")?.textContent).toContain(
        "Bulletin ID: 2026-117-AWS",
      );
      expect(container.querySelector(".adm-evidence-list__excerpt")?.textContent).toContain("Scope: AWS");
      const link = screen.getByRole("link", { name: "View article" });
      expect(link).toHaveAttribute("href", "https://aws.amazon.com/security/security-bulletins/2026-117-aws/");
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
    });

    it("never executes a <script> tag embedded in an excerpt", async () => {
      seedSession("admin");
      (window as unknown as { __xss?: boolean }).__xss = undefined;
      stubDetailFetch(detailWithEvidence("<p>safe</p><script>window.__xss = true;</script>"));

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByText("safe")).toBeInTheDocument();
      expect((window as unknown as { __xss?: boolean }).__xss).toBeUndefined();
    });

    it("never executes an onerror handler on a disallowed <img> tag embedded in an excerpt", async () => {
      seedSession("admin");
      (window as unknown as { __xss?: boolean }).__xss = undefined;
      stubDetailFetch(detailWithEvidence('<img src=x onerror="window.__xss = true">legit text'));

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByText("legit text")).toBeInTheDocument();
      expect((window as unknown as { __xss?: boolean }).__xss).toBeUndefined();
      expect(document.querySelector("img[onerror]")).toBeNull();
    });

    it("strips a javascript: link embedded in an excerpt rather than rendering a clickable one", async () => {
      seedSession("admin");
      stubDetailFetch(detailWithEvidence('<a href="javascript:alert(1)">Click me</a>'));

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByText("Click me")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "Click me" })).not.toBeInTheDocument();
    });

    it("neutralizes the \">script polyglot payload embedded in an excerpt", async () => {
      seedSession("admin");
      stubDetailFetch(detailWithEvidence("\"><script>alert('xss')</script>"));

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(document.querySelector("script")).toBeNull();
    });

    it("does not render a clickable source-title link for a javascript: source_url, same as before", async () => {
      seedSession("admin");
      stubDetailFetch(detailWithEvidence("<p>fine</p>", "javascript:alert(1)"));

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByText("Example Security Bulletin")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "Example Security Bulletin" })).not.toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "View article →" })).not.toBeInTheDocument();
    });
  });

  describe("editing", () => {
    it("shows an Edit button for a REVIEWER/ADMIN on a DRAFT signal, but not for a PUBLISHED one", async () => {
      seedSession("admin");
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string) =>
          String(url).includes("/users")
            ? Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })
            : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(draftDetail) }),
        ),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    });

    it("does not show an Edit button on a PUBLISHED signal", async () => {
      seedSession("admin");
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string) =>
          String(url).includes("/users")
            ? Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })
            : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(adminDetail) }),
        ),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    });

    it("does not show an Edit button for a VIEWER", async () => {
      seedSession("viewer");
      vi.stubGlobal(
        "fetch",
        vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(publicDetail) })),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    });

    it("entering edit mode shows a title input pre-filled with the current title, and lifecycle actions are hidden", async () => {
      seedSession("admin");
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string) =>
          String(url).includes("/users")
            ? Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })
            : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(draftDetail) }),
        ),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");
      fireEvent.click(screen.getByRole("button", { name: "Edit" }));

      const titleInput = screen.getByLabelText("Title") as HTMLInputElement;
      expect(titleInput.value).toBe("OAuth Audience Validation Bypass");
      expect(screen.queryByRole("button", { name: "Submit for approval" })).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Save changes" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
    });

    it("saving an edit sends only the changed fields plus the optimistic-lock token, then reloads", async () => {
      seedSession("admin");
      let patchBody: unknown = null;
      const fetchMock = vi.fn((url: string, init?: RequestInit) => {
        if (String(url).includes("/users")) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
        }
        if (init?.method === "PATCH" && !String(url).includes("/category")) {
          patchBody = JSON.parse(init.body as string);
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ...draftDetail, title: "New title" }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(draftDetail) });
      });
      vi.stubGlobal("fetch", fetchMock);

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");
      fireEvent.click(screen.getByRole("button", { name: "Edit" }));
      fireEvent.change(screen.getByLabelText("Title"), { target: { value: "New title" } });
      fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

      await waitFor(() => expect(patchBody).not.toBeNull());
      expect(patchBody).toEqual({ title: "New title", expected_updated_at: draftDetail.updated_at });

      expect(await screen.findByText('"New title" was updated.')).toBeInTheDocument();
    });

    it("a 409 conflict shows a specific message with a Reload action, instead of a generic error", async () => {
      seedSession("admin");
      const fetchMock = vi.fn((url: string, init?: RequestInit) => {
        if (String(url).includes("/users")) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
        }
        if (init?.method === "PATCH") {
          return Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve({ detail: "stale" }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(draftDetail) });
      });
      vi.stubGlobal("fetch", fetchMock);

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");
      fireEvent.click(screen.getByRole("button", { name: "Edit" }));
      fireEvent.change(screen.getByLabelText("Title"), { target: { value: "New title" } });
      fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

      expect(await screen.findByText(/changed by someone else/i)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    });
  });

  describe("visual deletion", () => {
    it("shows a Delete visual button only when a visual has actually been generated", async () => {
      seedSession("admin");
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string) =>
          String(url).includes("/users")
            ? Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })
            : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(adminDetail) }),
        ),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.getByRole("button", { name: "Delete visual" })).toBeInTheDocument();
    });

    it("does not show a Delete visual button when there is no generated visual", async () => {
      seedSession("viewer");
      vi.stubGlobal(
        "fetch",
        vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(publicDetail) })),
      );

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");

      expect(screen.queryByRole("button", { name: "Delete visual" })).not.toBeInTheDocument();
    });

    it("requires confirmation with the exact brief copy, and only deletes after confirming", async () => {
      seedSession("admin");
      const fetchMock = vi.fn((url: string, init?: RequestInit) => {
        if (String(url).includes("/users")) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
        }
        if (init?.method === "DELETE") {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ...adminDetail, visual_status: "none", visual_url: null }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(adminDetail) });
      });
      vi.stubGlobal("fetch", fetchMock);

      renderPage();
      await screen.findByText("OAuth Audience Validation Bypass");
      fireEvent.click(screen.getByRole("button", { name: "Delete visual" }));

      expect(screen.getByRole("dialog")).toHaveTextContent("Delete this visual?");
      expect(screen.getByRole("dialog")).toHaveTextContent(
        "This removes the current signal visual. It will not automatically regenerate.",
      );
      expect(fetchMock.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);

      const dialog = screen.getByRole("dialog");
      fireEvent.click(within(dialog).getByRole("button", { name: "Delete visual" }));

      await waitFor(() => expect(fetchMock.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(true));
    });
  });
});
