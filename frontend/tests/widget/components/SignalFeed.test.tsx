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

    fireEvent.click(screen.getByRole("button", { name: "IAM" }));

    await waitFor(() => expect(api.fetchPublishedSignals).toHaveBeenCalledTimes(2));
    const lastCallArgs = vi.mocked(api.fetchPublishedSignals).mock.calls[1];
    expect(lastCallArgs[1]).toMatchObject({ category: "iam", skip: 0 });
  });

  it("shows an empty state tailored to the active filter", async () => {
    vi.mocked(api.fetchPublishedSignals).mockResolvedValue({ signals: [], hasMore: false });

    render(<SignalFeed apiBaseUrl="https://api.example.com" onOpenSignal={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Ransomware" }));

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
