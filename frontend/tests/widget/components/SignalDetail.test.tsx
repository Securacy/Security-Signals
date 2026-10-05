import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SignalDetail } from "../../../src/widget/components/SignalDetail";
import * as api from "../../../src/widget/api";
import { ApiError } from "../../../src/widget/api";
import type { SignalDetail as SignalDetailType } from "../../../src/widget/types";

vi.mock("../../../src/widget/api");

const baseDetail: SignalDetailType = {
  id: "sig-1",
  title: "Critical Apache RCE disclosed",
  summary: "What happened text.",
  security_impact: "Why it matters text.",
  principle: "Defense in depth",
  recommended_action: "Patch immediately.",
  published_at: new Date().toISOString(),
  categories: [{ id: "cat-1", category: "insecure_design", subcategory: null }],
  public_categories: ["product_security"],
  visual_status: "generated",
  visual_url: "/media/signals/sig-1.png",
  evidence: [
    { id: "ev-1", source_url: "https://example.com/advisory", source_title: "Vendor Advisory", excerpt: "quote", created_at: null },
  ],
};

describe("SignalDetail", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // vi.mock("../api") auto-mocks every export, including the new
    // resolveMediaUrl - give it back its real (pure, deterministic)
    // behavior rather than the default undefined-returning stub.
    vi.mocked(api.resolveMediaUrl).mockImplementation(
      (base: string, path: string) => base.replace(/\/+$/, "") + path,
    );
  });

  it("shows a loading state before the fetch resolves", () => {
    vi.mocked(api.fetchSignalDetail).mockReturnValue(new Promise(() => {}));

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    expect(screen.getByLabelText("Loading signal")).toBeInTheDocument();
  });

  it("renders what happened, why it matters, principle, and recommended action", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    await waitFor(() => expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument());
    expect(screen.getByText("What happened text.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Would this affect you?" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Design principle" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "High-level mitigations" })).toBeInTheDocument();
    expect(screen.getByText("Why it matters text.")).toBeInTheDocument();
    expect(screen.getByText("Defense in depth")).toBeInTheDocument();
    expect(screen.getByText("Patch immediately.")).toBeInTheDocument();
  });

  it("renders a safe https evidence link with target=_blank and rel=noopener noreferrer", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    const link = await screen.findByRole("link", { name: "Vendor Advisory" });
    expect(link).toHaveAttribute("href", "https://example.com/advisory");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("does not render an unsafe evidence URL as a clickable link", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail,
      evidence: [{ id: "ev-2", source_url: "javascript:alert(1)", source_title: "Suspicious Source", excerpt: "x", created_at: null }],
    });

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    await screen.findByText("Suspicious Source");
    expect(screen.queryByRole("link", { name: "Suspicious Source" })).toBeNull();
  });

  it("shows an error state with retry on failure", async () => {
    vi.mocked(api.fetchSignalDetail)
      .mockRejectedValueOnce(new ApiError("boom", 500))
      .mockResolvedValueOnce(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    await waitFor(() => expect(screen.getByText("Couldn't load security signals")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(screen.getByText("Critical Apache RCE disclosed")).toBeInTheDocument());
  });


  it("renders a malicious-looking summary as plain text, never executes it", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail,
      summary: '<img src=x onerror="window.__xss=true">',
    });

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    await screen.findByText('<img src=x onerror="window.__xss=true">');
    expect((window as any).__xss).toBeUndefined();
  });

  it("renders a category icon with an accessible label near the timestamp", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

    await waitFor(() => expect(screen.getByRole("img", { name: "Product Security" })).toBeInTheDocument());
  });

  it("renders the signal's own generated visual when status is generated", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "image"));
    const img = container.querySelector(".ss-visual__image") as HTMLImageElement;
    expect(img.src).toBe("https://api.example.com/media/signals/sig-1.png");
    expect(img.getAttribute("loading")).toBe("lazy");
  });

  it("renders the category-based fallback when visual_status is pending", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail, visual_status: "pending", visual_url: null,
    });

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
    expect(container.querySelector(".ss-visual__image")).toBeNull();
  });

  it("renders the category-based fallback when visual_status is failed", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue({
      ...baseDetail, visual_status: "failed", visual_url: null,
    });

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
  });

  it("falls back to the category visual when the image fails to load client-side", async () => {
    vi.mocked(api.fetchSignalDetail).mockResolvedValue(baseDetail);

    const { container } = render(
      <SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />,
    );

    await waitFor(() => expect(container.querySelector(".ss-visual__image")).toBeInTheDocument());
    fireEvent.error(container.querySelector(".ss-visual__image") as HTMLImageElement);

    await waitFor(() => expect(container.querySelector(".ss-visual")).toHaveAttribute("data-state", "fallback"));
  });

  describe("editorial reading view", () => {
    function renderDetail(detail: SignalDetailType) {
      vi.mocked(api.fetchSignalDetail).mockResolvedValue(detail);
      return render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);
    }

    it("names the title for the dialog and shows the publisher hostname for each source", async () => {
      renderDetail(baseDetail);
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      expect(document.getElementById("reader-title")).toHaveTextContent("Critical Apache RCE disclosed");
      expect(screen.getByText("example.com")).toBeInTheDocument();
      expect(screen.getByRole("link", { name: /Read the original article/ })).toHaveAttribute(
        "href",
        "https://example.com/advisory",
      );
    });

    it("splits the semicolon-separated principle field into separate items", async () => {
      renderDetail({ ...baseDetail, principle: "Least Privilege; Defense in Depth;  " });
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      const items = Array.from(document.querySelectorAll(".ss-reader__principles li")).map((li) => li.textContent);
      expect(items).toEqual(["Least Privilege", "Defense in Depth"]);
    });

    it("omits optional sections that have no content, without breaking the rest", async () => {
      renderDetail({
        ...baseDetail,
        summary: "",
        security_impact: "",
        principle: "   ",
        recommended_action: "",
        published_at: null,
        public_categories: [],
        evidence: [],
        visual_status: "none",
        visual_url: null,
      });
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      expect(screen.queryByRole("heading", { name: "Would this affect you?" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "Design principle" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "High-level mitigations" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "Sources" })).not.toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Critical Apache RCE disclosed" })).toBeInTheDocument();
    });

    it("renders a source with an unsafe URL as plain text, never a link", async () => {
      renderDetail({
        ...baseDetail,
        evidence: [{ id: "ev-x", source_url: "javascript:alert(1)", source_title: "Sneaky Source", excerpt: "", created_at: null }],
      });
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      expect(screen.getByText("Sneaky Source")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /Sneaky Source/ })).not.toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /Read the original article/ })).not.toBeInTheDocument();
    });

    it("renders a malformed source URL as plain text without throwing", async () => {
      renderDetail({
        ...baseDetail,
        evidence: [{ id: "ev-m", source_url: "not a url at all", source_title: "Broken Link", excerpt: "", created_at: null }],
      });
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      expect(screen.getByText("Broken Link")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /Broken Link/ })).not.toBeInTheDocument();
    });

    it("never executes script or event-handler payloads placed in any reader field", async () => {
      (window as unknown as { __xss?: boolean }).__xss = undefined;
      renderDetail({
        ...baseDetail,
        title: "<script>window.__xss = true</script>Headline",
        summary: "<img src=x onerror=\"window.__xss = true\">Summary text",
        security_impact: "<a href=\"javascript:window.__xss = true\">Click me</a>",
        principle: "<b onclick=\"window.__xss = true\">Principle</b>",
        recommended_action: "\"><script>window.__xss = true</script>Action",
        evidence: [{ id: "ev-z", source_url: "https://example.com/z", source_title: "<img src=x onerror=\"window.__xss = true\">Title", excerpt: "", created_at: null }],
      });
      await waitFor(() => screen.getByText(/Headline/));
      expect((window as unknown as { __xss?: boolean }).__xss).toBeUndefined();
      expect(document.querySelector("script")).toBeNull();
      expect(document.querySelector("img[onerror]")).toBeNull();
      expect(document.querySelector("a[href^='javascript:']")).toBeNull();
      expect(document.querySelector("b[onclick]")).toBeNull();
      expect(screen.getByText(/Click me/)).toBeInTheDocument();
    });

    it("gives every external source link target=_blank and rel=noopener noreferrer", async () => {
      renderDetail(baseDetail);
      await waitFor(() => screen.getByText("Critical Apache RCE disclosed"));
      for (const link of screen.getAllByRole("link")) {
        if (link.getAttribute("href")?.startsWith("https://")) {
          expect(link).toHaveAttribute("target", "_blank");
          expect(link).toHaveAttribute("rel", "noopener noreferrer");
        }
      }
    });
  });

  describe("long content", () => {
    it("renders very long titles, summaries and URLs in full without truncating or failing", async () => {
      const longTitle = "Supercalifragilistic".repeat(12);
      const longSummary = "Long summary sentence that keeps going. ".repeat(40);
      const longUrl = "https://example.com/" + "a-very-long-path-segment-".repeat(20);
      vi.mocked(api.fetchSignalDetail).mockResolvedValue({
        ...baseDetail,
        title: longTitle,
        summary: longSummary,
        evidence: [{ id: "ev-long", source_url: longUrl, source_title: longTitle, excerpt: "", created_at: null }],
      });
      render(<SignalDetail apiBaseUrl="https://api.example.com" signalId="sig-1" titleId="reader-title" />);

      await waitFor(() => expect(screen.getByRole("heading", { name: longTitle })).toBeInTheDocument());
      expect(screen.getByText(longSummary.trim())).toBeInTheDocument();
      expect(screen.getByRole("link", { name: /Read the original article/ })).toHaveAttribute("href", longUrl);
    });
  });
});
