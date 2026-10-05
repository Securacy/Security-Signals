import { render, screen } from "@testing-library/react";
import { describe, it, expect, beforeEach } from "vitest";
import { AuthProvider } from "../../../src/admin/auth/AuthContext";
import { RouterProvider } from "../../../src/admin/router";
import { Sidebar } from "../../../src/admin/components/Sidebar";

function seedSession() {
  window.sessionStorage.setItem(
    "ss-admin-session",
    JSON.stringify({
      token: "test-token",
      user: { id: "u1", username: "tester", email: "tester@example.test", role: "admin" },
    }),
  );
}

describe("Sidebar", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    seedSession();
  });

  it("shows the Cyberscope wordmark as the brand link, not the old Security Signals name", () => {
    render(
      <AuthProvider>
        <RouterProvider>
          <Sidebar />
        </RouterProvider>
      </AuthProvider>,
    );

    const brand = screen.getByRole("link", { name: "Cyberscope" });
    expect(brand).toHaveAttribute("href", "/admin/");
    expect(screen.queryByText("Security Signals")).not.toBeInTheDocument();
  });
});
