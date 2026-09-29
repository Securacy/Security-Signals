import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { VisualPreview } from "../../../src/admin/components/VisualPreview";

describe("VisualPreview", () => {
  it("shows the actual persisted, signal-specific image when generated", () => {
    render(<VisualPreview title="My Signal" status="generated" url="/media/signals/abc.png" requestedAt={null} />);

    const img = screen.getByRole("img", { name: "Generated illustration for My Signal" });
    expect(img).toHaveAttribute("src", expect.stringMatching(/\/media\/signals\/abc\.png$/));
  });

  it("shows an explicit 'Visual generating…' state while pending", () => {
    render(<VisualPreview title="T" status="pending" url={null} requestedAt={new Date().toISOString()} />);

    expect(screen.getByRole("status")).toHaveTextContent("Visual generating…");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("does not claim 'generating' forever: an abandoned pending visual reads as unavailable", () => {
    const twentyMinutesAgo = new Date(Date.now() - 20 * 60 * 1000).toISOString();
    render(<VisualPreview title="T" status="pending" url={null} requestedAt={twentyMinutesAgo} />);

    expect(screen.getByText("Visual unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Visual generating…")).not.toBeInTheDocument();
  });

  it("shows 'Visual unavailable' with the existing retry mechanism when generation failed - never an image", () => {
    render(<VisualPreview title="T" status="failed" url={null} requestedAt={null} />);

    expect(screen.getByText("Visual unavailable")).toBeInTheDocument();
    expect(screen.getByText(/regenerate_visuals\.py/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("says plainly that no visual exists for a signal that was never queued (no fake image or category icon)", () => {
    render(<VisualPreview title="T" status="none" url={null} requestedAt={null} />);

    expect(screen.getByText("No visual has been generated for this signal.")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("falls back to 'Visual unavailable' if the persisted image fails to load", () => {
    render(<VisualPreview title="T" status="generated" url="/media/signals/gone.png" requestedAt={null} />);

    fireEvent.error(screen.getByRole("img"));

    expect(screen.getByText("Visual unavailable")).toBeInTheDocument();
  });

  it("refuses a non-backend-relative URL (e.g. protocol-relative) instead of loading it", () => {
    render(<VisualPreview title="T" status="generated" url="//evil.example/x.png" requestedAt={null} />);

    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText("Visual unavailable")).toBeInTheDocument();
  });
});
