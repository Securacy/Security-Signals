import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { UsersPage } from "../../../src/admin/pages/UsersPage";

function WaitForSession({ children }: { children: ReactNode }) {
  const { isRestoring, isAuthenticated } = useAuth();
  if (isRestoring || !isAuthenticated) return null;
  return <>{children}</>;
}

function seedSession(id: string) {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id, username: "current-admin", email: "current-admin@test.local", role: "admin" },
    }),
  );
}

const currentAdmin = {
  id: "u-self",
  username: "current-admin",
  email: "current-admin@test.local",
  role: "admin",
  is_active: true,
  has_local_credential: true,
  entra_linked: false,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: null,
  last_login_at: "2026-01-05T00:00:00Z",
};

const otherReviewer = {
  id: "u-other",
  username: "another-reviewer",
  email: "reviewer@test.local",
  role: "reviewer",
  is_active: true,
  has_local_credential: true,
  entra_linked: false,
  created_at: "2026-01-02T00:00:00Z",
  updated_at: null,
  last_login_at: null,
};

const inactiveViewer = {
  id: "u-inactive",
  username: "old-viewer",
  email: "old-viewer@test.local",
  role: "viewer",
  is_active: false,
  has_local_credential: true,
  entra_linked: false,
  created_at: "2026-01-03T00:00:00Z",
  updated_at: null,
  last_login_at: null,
};

const entraOnlyUser = {
  id: "u-entra",
  username: "entra-person",
  email: "entra-person@example.test",
  role: "viewer",
  is_active: true,
  has_local_credential: false,
  entra_linked: true,
  created_at: "2026-01-04T00:00:00Z",
  updated_at: null,
  last_login_at: null,
};

function renderPage() {
  return render(
    <AuthProvider>
      <RouterProvider>
        <WaitForSession>
          <UsersPage />
        </WaitForSession>
      </RouterProvider>
    </AuthProvider>,
  );
}

describe("UsersPage", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("lists users with username, email, role, status, and never renders a password/hash field", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer, inactiveViewer]) }),
      ),
    );

    renderPage();

    expect(await screen.findByText("current-admin")).toBeInTheDocument();
    expect(screen.getByText("another-reviewer")).toBeInTheDocument();
    expect(screen.getByText("old-viewer")).toBeInTheDocument();
    expect(screen.getByText("reviewer@test.local")).toBeInTheDocument();
    expect(screen.getAllByText("Active").length).toBeGreaterThan(0);
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    // "Password managed" is a legitimate auth-method label, not a leaked
    // value - what must never appear is actual secret material: a bcrypt
    // hash or the raw password_hash field name/value.
    const list = screen.getByRole("list");
    expect(within(list).queryByText(/password_hash/i)).not.toBeInTheDocument();
    expect(within(list).queryByText(/\$2b\$/)).not.toBeInTheDocument();
  });

  it("shows an empty state when there are no users", async () => {
    seedSession("u-self");
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })));

    renderPage();

    expect(await screen.findByText("No users exist yet.")).toBeInTheDocument();
  });

  it("shows an error state when the list fails to load", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({ detail: "boom" }) })),
    );

    renderPage();

    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("does not show a Deactivate button for the current admin's own row (self-lockout prevention)", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) })),
    );

    renderPage();
    await screen.findByText("current-admin");

    const rows = screen.getAllByRole("listitem");
    const selfRow = rows.find((row) => row.textContent?.includes("current-admin"))!;
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;

    expect(within(selfRow).queryByRole("button", { name: "Deactivate" })).not.toBeInTheDocument();
    expect(within(otherRow).getByRole("button", { name: "Deactivate" })).toBeInTheDocument();
  });

  it("does not show a Deactivate button for an already-inactive user", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, inactiveViewer]) })),
    );

    renderPage();
    await screen.findByText("old-viewer");

    const rows = screen.getAllByRole("listitem");
    const inactiveRow = rows.find((row) => row.textContent?.includes("old-viewer"))!;
    expect(within(inactiveRow).queryByRole("button", { name: "Deactivate" })).not.toBeInTheDocument();
  });

  it("changing role requires confirmation and calls PATCH with the new role", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).includes("/users/u-other") && init?.method === "PATCH") {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ...otherReviewer, role: "admin" }) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("another-reviewer");

    const rows = screen.getAllByRole("listitem");
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    fireEvent.click(within(otherRow).getByRole("button", { name: "Change role" }));

    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Role"), { target: { value: "admin" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Change role" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/users/u-other") && c[1]?.method === "PATCH");
      expect(call).toBeDefined();
      expect(JSON.parse((call![1] as RequestInit).body as string)).toEqual({ role: "admin" });
    });
    expect(await screen.findByText("another-reviewer's role is now Admin.")).toBeInTheDocument();
  });

  it("the role-change confirm button is disabled when the selected role matches the current role", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) })),
    );

    renderPage();
    await screen.findByText("another-reviewer");

    const rows = screen.getAllByRole("listitem");
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    fireEvent.click(within(otherRow).getByRole("button", { name: "Change role" }));

    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Change role" })).toBeDisabled();
  });

  it("deactivating requires confirmation and calls the deactivate endpoint", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).includes("/deactivate")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ...otherReviewer, is_active: false }) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("another-reviewer");

    const rows = screen.getAllByRole("listitem");
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    fireEvent.click(within(otherRow).getByRole("button", { name: "Deactivate" }));

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("cannot be undone");
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));

    await waitFor(() =>
      expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/deactivate") && c[1]?.method === "POST")).toBe(true),
    );
  });

  it("creating a user shows the form, submits real fields, and reports server-side validation errors", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).endsWith("/api/v1/users") && init?.method === "POST") {
        return Promise.resolve({ ok: false, status: 400, json: () => Promise.resolve({ detail: "Password must be at least 12 characters" }) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("current-admin");

    fireEvent.click(screen.getByRole("button", { name: "New user" }));
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "new.reviewer" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new.reviewer@test.local" } });
    fireEvent.change(screen.getByLabelText("Temporary password"), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));

    expect(await screen.findByText("Password must be at least 12 characters")).toBeInTheDocument();
  });

  it("shows a readable message for a FastAPI 422 validation error (array-shaped detail), not '[object Object]'", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).endsWith("/api/v1/users") && init?.method === "POST") {
        return Promise.resolve({
          ok: false,
          status: 422,
          json: () =>
            Promise.resolve({
              detail: [
                {
                  type: "string_too_short",
                  loc: ["body", "password"],
                  msg: "String should have at least 12 characters",
                  input: "short",
                },
              ],
            }),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("current-admin");

    fireEvent.click(screen.getByRole("button", { name: "New user" }));
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "new.reviewer" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new.reviewer@test.local" } });
    fireEvent.change(screen.getByLabelText("Temporary password"), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));

    expect(await screen.findByText("String should have at least 12 characters")).toBeInTheDocument();
    expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
  });

  it("shows the real authentication method per user: local, Microsoft Entra, or both", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, entraOnlyUser]) })),
    );

    renderPage();
    await screen.findByText("current-admin");

    const rows = screen.getAllByRole("listitem");
    const localRow = rows.find((row) => row.textContent?.includes("current-admin"))!;
    const entraRow = rows.find((row) => row.textContent?.includes("entra-person"))!;

    expect(within(localRow).getByText("Password managed")).toBeInTheDocument();
    expect(within(localRow).queryByText("Microsoft Entra managed")).not.toBeInTheDocument();
    expect(within(entraRow).getByText("Microsoft Entra managed")).toBeInTheDocument();
    expect(within(entraRow).queryByText("Password managed")).not.toBeInTheDocument();
  });

  it("offers no local-password actions for an Entra-only user, and no self-reset for the current admin", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, entraOnlyUser]) })),
    );

    renderPage();
    await screen.findByText("current-admin");

    const rows = screen.getAllByRole("listitem");
    const selfRow = rows.find((row) => row.textContent?.includes("current-admin"))!;
    const entraRow = rows.find((row) => row.textContent?.includes("entra-person"))!;

    expect(within(selfRow).queryByRole("button", { name: "Reset password" })).not.toBeInTheDocument();
    expect(within(entraRow).queryByRole("button", { name: "Reset password" })).not.toBeInTheDocument();
  });

  it("resetting a password requires meeting every requirement and matching confirmation before it's enabled", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) })),
    );

    renderPage();
    await screen.findByText("another-reviewer");

    const rows = screen.getAllByRole("listitem");
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    fireEvent.click(within(otherRow).getByRole("button", { name: "Reset password" }));

    const dialog = screen.getByRole("dialog");
    const confirmButton = within(dialog).getByRole("button", { name: "Reset password" });
    expect(confirmButton).toBeDisabled();

    fireEvent.change(within(dialog).getByLabelText("New password"), { target: { value: "weak" } });
    expect(confirmButton).toBeDisabled();

    fireEvent.change(within(dialog).getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    expect(confirmButton).toBeDisabled(); // confirmation not filled in yet

    fireEvent.change(within(dialog).getByLabelText("Confirm new password"), { target: { value: "Different!Pw12" } });
    expect(confirmButton).toBeDisabled(); // mismatch

    fireEvent.change(within(dialog).getByLabelText("Confirm new password"), { target: { value: "Br4nd!NewPassword" } });
    expect(confirmButton).toBeEnabled();
  });

  it("resetting a password calls the reset endpoint with both fields and shows success feedback", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).includes("/reset-password")) {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(otherReviewer) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("another-reviewer");

    const rows = screen.getAllByRole("listitem");
    const otherRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    fireEvent.click(within(otherRow).getByRole("button", { name: "Reset password" }));

    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("New password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.change(within(dialog).getByLabelText("Confirm new password"), { target: { value: "Br4nd!NewPassword" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Reset password" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/reset-password"));
      expect(call).toBeDefined();
      expect(JSON.parse((call![1] as RequestInit).body as string)).toEqual({
        new_password: "Br4nd!NewPassword",
        confirm_password: "Br4nd!NewPassword",
      });
    });
    expect(await screen.findByText("another-reviewer's password was reset.")).toBeInTheDocument();
  });

  it("never shows a Remove button for an active user, only for an already-inactive one", async () => {
    seedSession("u-self");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, otherReviewer, inactiveViewer]) })),
    );

    renderPage();
    await screen.findByText("old-viewer");

    const rows = screen.getAllByRole("listitem");
    const activeRow = rows.find((row) => row.textContent?.includes("another-reviewer"))!;
    const inactiveRow = rows.find((row) => row.textContent?.includes("old-viewer"))!;

    expect(within(activeRow).queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(within(inactiveRow).getByRole("button", { name: "Remove" })).toBeInTheDocument();
  });

  it("permanently removing an inactive user requires confirmation and calls the delete endpoint", async () => {
    seedSession("u-self");
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (String(url).includes(`/api/v1/users/${inactiveViewer.id}`) && init?.method === "DELETE") {
        return Promise.resolve({ ok: true, status: 204, json: () => Promise.resolve(undefined) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([currentAdmin, inactiveViewer]) });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    await screen.findByText("old-viewer");

    const rows = screen.getAllByRole("listitem");
    const inactiveRow = rows.find((row) => row.textContent?.includes("old-viewer"))!;
    fireEvent.click(within(inactiveRow).getByRole("button", { name: "Remove" }));

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("permanently deleted");
    expect(dialog).toHaveTextContent("cannot be undone");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove permanently" }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          (c) => String(c[0]).includes(`/api/v1/users/${inactiveViewer.id}`) && c[1]?.method === "DELETE",
        ),
      ).toBe(true),
    );
    expect(await screen.findByText("old-viewer's account was permanently removed.")).toBeInTheDocument();
  });
});
