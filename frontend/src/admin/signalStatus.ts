import type { ComponentProps } from "react";
import type { AdminSignalStatus } from "./api/types";
import type { Badge } from "./components/Badge";

type BadgeTone = ComponentProps<typeof Badge>["tone"];

/** Single source of truth for how a Signal's lifecycle status reads across
 * the app (Dashboard, Signals, Review Queue) - was previously duplicated
 * per-page with drifting capitalization ("In review" vs "In Review").
 * Terms match the vocabulary used throughout the admin UI: Draft, In
 * Review, Approved, Published, Rejected. */
export const SIGNAL_STATUS_LABEL: Record<AdminSignalStatus, string> = {
  draft: "Draft",
  in_review: "In Review",
  approved: "Approved",
  rejected: "Rejected",
  published: "Published",
};

export const SIGNAL_STATUS_TONE: Record<AdminSignalStatus, BadgeTone> = {
  draft: "neutral",
  in_review: "info",
  approved: "success",
  rejected: "danger",
  published: "success",
};
