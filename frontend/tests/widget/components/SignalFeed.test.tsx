import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SignalFeed } from "../../../src/widget/components/SignalFeed";
import * as api from "../../../src/widget/api";
import { ApiError } from "../../../src/widget/api";
import type { SignalSummary } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

function makeSignal(overrides: Partial<SignalSummary> = {}): SignalSummary {
  return {
    id: overrides.id ?? "sig-1",
    title: overrides.title ?? "Test Signal",
    summary: "A summary of the security development.",
    security_impact: "impact",
    principle: "principle",
    recommended_action: "action",
    published_at: new Date().toISOString(),
    categories: [],
    public_categories: [],
    ...overrides,
  };
}

describe("SignalFeed", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("shows a loading skeleton while the initial fetch is pending", async () => {
    let resolveFetch: (value: any) => void = () => {};
    vi.mocked(api.fetchPublishedSignals).mockReturnValue(
      new Promise((resolve) => {
        resolveFetch = resolve;
      }),
    );

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    expect(screen.getByLabelText("Loading security signals")).toBeInTheDocument();

    resolveFetch({ signals: [], hasMore: false });
    await waitFor(() => expect(screen.queryByLabelText("Loading security signals")).toBeNull());
  });

  it("renders signal cards on successful fetch", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal({ id: "a", title: "Signal A" }), makeSignal({ id: "b", title: "Signal B" })],
      hasMore: false,
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("Signal A")).toBeInTheDocument());
    expect(screen.getByText("Signal B")).toBeInTheDocument();
  });

  it("shows the empty state when there are no published signals", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("No published signals yet")).toBeInTheDocument());
  });

  it("shows an inline error with retry on fetch failure, and recovers on retry", async () => {
    vi.mocked(api.fetchPublishedSignals)
      .mockRejectedValueOnce(new ApiError("boom", 500))
      .mockResolvedValueOnce({ signals: [makeSignal({ title: "Recovered Signal" })], hasMore: false });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("Couldn't load security signals")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(screen.getByText("Recovered Signal")).toBeInTheDocument());
  });

  it("refetches with the category filter and resets the list", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal({ title: "IAM Signal" })],
      hasMore: false,
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await waitFor(() => expect(api.fetchPublishedSignals).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "cloud_identity_security" } });

    await waitFor(() => expect(api.fetchPublishedSignals).toHaveBeenCalledTimes(2));
    const lastCallArgs = vi.mocked(api.fetchPublishedSignals).mock.calls[1];
    expect(lastCallArgs[1]).toMatchObject({ category: "cloud_identity_security", skip: 0 });
  });

  it("shows an empty state tailored to the active filter", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "ransomware" } });

    await waitFor(() => expect(screen.getByText("No signals in this category yet")).toBeInTheDocument());
  });

  it("shows a 'Load more' button when a full page is returned, and appends the next page", async () => {
    vi.mocked(api.fetchPublishedSignals)
      .mockResolvedValueOnce({ signals: [makeSignal({ id: "p1", title: "Page 1 Signal" })], hasMore: true })
      .mockResolvedValueOnce({ signals: [makeSignal({ id: "p2", title: "Page 2 Signal" })], hasMore: false });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

    await waitFor(() => expect(screen.getByText("Page 1 Signal")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));

    await waitFor(() => expect(screen.getByText("Page 2 Signal")).toBeInTheDocument());
    expect(screen.getByText("Page 1 Signal")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("uses natural-language search instead of fetchPublishedSignals once a query is typed", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [makeSignal({ id: "s1", title: "CI/CD Pipeline Compromise" })],
      aiUnderstood: true,
      understoodPublicCategories: ["supply_chain"],
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    await waitFor(() => expect(api.fetchPublishedSignals).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText("Search"), {
      target: { value: "compromised CI/CD pipelines" },
    });

    await waitFor(() => expect(screen.getByText("CI/CD Pipeline Compromise")).toBeInTheDocument());
    expect(api.searchSignals).toHaveBeenCalledWith(
      "https://api.example.com",
      expect.objectContaining({ query: "compromised CI/CD pipelines" }),
    );
  });

  it("shows an 'Understood as' hint when AI search understood the query", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [makeSignal()],
      aiUnderstood: true,
      understoodPublicCategories: ["ransomware"],
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "recent ransomware attacks" } });

    await waitFor(() => expect(screen.getByText(/Understood as:/)).toBeInTheDocument());
  });

  it("shows a result count alongside the 'Understood as' hint", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [makeSignal({ id: "a" }), makeSignal({ id: "b" })],
      aiUnderstood: true,
      understoodPublicCategories: ["ai_security"],
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "AI agent abuse" } });

    await waitFor(() => expect(screen.getByText(/2 matching signals/)).toBeInTheDocument());
  });

  it("shows a helpful, non-generic empty state for a search with no matches", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [],
      aiUnderstood: true,
      understoodPublicCategories: ["data_privacy"],
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "recent data privacy breaches" } });

    await waitFor(() => expect(screen.getByText("No matching signals found")).toBeInTheDocument());
    expect(screen.queryByText("No news found.")).toBeNull();
  });

  it("shows a search-in-progress indicator on the search field while a search request is pending", async () => {
    let resolveSearch: (value: any) => void = () => {};
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockReturnValue(
      new Promise((resolve) => {
        resolveSearch = resolve;
      }),
    );

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "oauth" } });

    await waitFor(() => expect(document.querySelector(".ss-search-field__spinner")).not.toBeNull());

    resolveSearch({ signals: [], aiUnderstood: false, understoodPublicCategories: [] });
    await waitFor(() => expect(document.querySelector(".ss-search-field__spinner")).toBeNull());
  });

  it("falls back to the feed's normal error state when search itself fails", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });
    vi.mocked(api.searchSignals).mockRejectedValue(new ApiError("search unavailable", 503));

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "anything" } });

    await waitFor(() => expect(screen.getByText("Couldn't load security signals")).toBeInTheDocument());
  });

  it("clearing the search box returns to the paginated published feed", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal({ id: "p1", title: "Published Feed Signal" })],
      hasMore: false,
    });
    vi.mocked(api.searchSignals).mockResolvedValue({
      signals: [makeSignal({ id: "s1", title: "Search Result Signal" })],
      aiUnderstood: false,
      understoodPublicCategories: [],
    });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "something" } });
    await waitFor(() => expect(screen.getByText("Search Result Signal")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "" } });

    await waitFor(() => expect(screen.getByText("Published Feed Signal")).toBeInTheDocument());
  });

  describe("race-safety (search results must not disappear)", () => {
    it("a slow, stale initial published-feed fetch cannot overwrite an already-displayed search result", async () => {
      // Reproduces the reported bug exactly: the mount-time normal-feed
      // request is still in flight when the user types a query; the
      // search resolves first and is displayed; the stale published
      // fetch must NOT be allowed to overwrite it when it finally
      // resolves afterward.
      let resolvePublished: (value: any) => void = () => {};
      vi.mocked(api.fetchPublishedSignals).mockReturnValue(
        new Promise((resolve) => {
          resolvePublished = resolve;
        }),
      );
      vi.mocked(api.searchSignals).mockResolvedValue({
        signals: [makeSignal({ id: "s1", title: "OAuth2 Token Exchange Privilege Escalation" })],
        aiUnderstood: true,
        understoodPublicCategories: ["cloud_identity_security"],
      });

      render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

      // Type immediately, before the mount's published fetch has resolved.
      fireEvent.change(screen.getByLabelText("Search"), {
        target: { value: "OAuth2 token exchange privilege escalation" },
      });

      await waitFor(() =>
        expect(screen.getByText("OAuth2 Token Exchange Privilege Escalation")).toBeInTheDocument(),
      );

      // The stale mount-time fetch finally resolves, well after the search
      // result is already showing.
      resolvePublished({
        signals: [makeSignal({ id: "unrelated", title: "Unrelated Published Signal" })],
        hasMore: false,
      });

      // Give any (incorrect) state update a chance to happen, then assert
      // the search result is still what's displayed.
      await new Promise((r) => setTimeout(r, 50));
      expect(screen.getByText("OAuth2 Token Exchange Privilege Escalation")).toBeInTheDocument();
      expect(screen.queryByText("Unrelated Published Signal")).toBeNull();
    });

    it("only the latest of two rapid, overlapping search queries wins, regardless of resolution order", async () => {
      vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });

      let resolveFirst: (value: any) => void = () => {};
      const firstPromise = new Promise((resolve) => {
        resolveFirst = resolve;
      });
      vi.mocked(api.searchSignals)
        .mockReturnValueOnce(firstPromise as any)
        .mockResolvedValueOnce({
          signals: [makeSignal({ id: "b", title: "AI Agent Security Result" })],
          aiUnderstood: true,
          understoodPublicCategories: ["ai_security"],
        });

      render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

      fireEvent.change(screen.getByLabelText("Search"), { target: { value: "AI security" } });
      await waitFor(() => expect(api.searchSignals).toHaveBeenCalledTimes(1));

      fireEvent.change(screen.getByLabelText("Search"), { target: { value: "AI agent security" } });
      await waitFor(() => expect(api.searchSignals).toHaveBeenCalledTimes(2));

      await waitFor(() => expect(screen.getByText("AI Agent Security Result")).toBeInTheDocument());

      // The first (now-stale) request resolves after the second - it must
      // not overwrite the second, newer query's result.
      resolveFirst({
        signals: [makeSignal({ id: "a", title: "Stale AI Security Result" })],
        aiUnderstood: true,
        understoodPublicCategories: ["ai_security"],
      });
      await new Promise((r) => setTimeout(r, 50));

      expect(screen.getByText("AI Agent Security Result")).toBeInTheDocument();
      expect(screen.queryByText("Stale AI Security Result")).toBeNull();
    });

    it("a stale request's later failure does not show an error state once superseded", async () => {
      vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });

      let rejectFirst: (err: any) => void = () => {};
      const firstPromise = new Promise((_resolve, reject) => {
        rejectFirst = reject;
      });
      vi.mocked(api.searchSignals)
        .mockReturnValueOnce(firstPromise as any)
        .mockResolvedValueOnce({
          signals: [makeSignal({ id: "b", title: "Newer Search Result" })],
          aiUnderstood: false,
          understoodPublicCategories: [],
        });

      render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);

      fireEvent.change(screen.getByLabelText("Search"), { target: { value: "first query" } });
      await waitFor(() => expect(api.searchSignals).toHaveBeenCalledTimes(1));

      fireEvent.change(screen.getByLabelText("Search"), { target: { value: "second query" } });
      await waitFor(() => expect(api.searchSignals).toHaveBeenCalledTimes(2));
      await waitFor(() => expect(screen.getByText("Newer Search Result")).toBeInTheDocument());

      rejectFirst(new ApiError("stale request failed", 500));
      await new Promise((r) => setTimeout(r, 50));

      expect(screen.getByText("Newer Search Result")).toBeInTheDocument();
      expect(screen.queryByText("Couldn't load security signals")).toBeNull();
    });
  });

  it("calls onOpenSignal with the clicked signal's id", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({
      signals: [makeSignal({ id: "sig-xyz", title: "Clickable Signal" })],
      hasMore: false,
    });
    const onOpenSignal = vi.fn();

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={onOpenSignal} />);
    await waitFor(() => screen.getByText("Clickable Signal"));

    fireEvent.click(screen.getByRole("button", { name: /Open signal: Clickable Signal/ }));

    expect(onOpenSignal).toHaveBeenCalledWith("sig-xyz");
  });
});
