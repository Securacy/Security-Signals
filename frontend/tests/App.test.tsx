import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import App from "../src/App";

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              {
                id: "sig-1",
                title: "Test Published Signal",
                summary: "Summary text",
                security_impact: "impact",
                principle: "principle",
                recommended_action: "action",
                published_at: new Date().toISOString(),
                categories: [],
                public_categories: [],
              },
            ]),
        }),
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the Cyberscope drawer", () => {
    render(<App />);
    expect(screen.getByRole("dialog", { name: "Cyberscope" })).toBeInTheDocument();
  });

  it("fetches and displays published signals end to end", async () => {
    render(<App />);

    await waitFor(() => expect(screen.getByText("Test Published Signal")).toBeInTheDocument());

    const calledUrl = (fetch as any).mock.calls[0][0] as string;
    expect(calledUrl).toContain("/api/v1/signals/published");
  });

  it("never calls any internal admin/reviewer/audit/auth endpoint", async () => {
    render(<App />);
    await waitFor(() => expect((fetch as any).mock.calls.length).toBeGreaterThan(0));

    const calledUrls = (fetch as any).mock.calls.map((call: any[]) => String(call[0]));
    for (const url of calledUrls) {
      expect(url).not.toMatch(/\/api\/v1\/(users|audit|auth)\b/);
      expect(url).not.toMatch(/\/signals\/draft\b/);
    }
  });
});
