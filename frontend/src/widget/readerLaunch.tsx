import { createContext, useContext } from "react";
import type { SignalSummary } from "./types";

/**
 * Side channel for the feed -> reader "shared element" transition. Just
 * before a feed item calls onOpen(id), it hands the Drawer the summary it
 * already has (so the reader can paint its hero instantly, before the
 * detail fetch resolves) and the on-screen rect of its image (the FLIP
 * origin). Kept out of onOpen's signature on purpose: that stays a plain
 * (id) => void, and the feed works unchanged with no provider at all.
 */
export interface ReaderLaunch {
  signal: SignalSummary;
  originRect: DOMRect | null;
}

interface ReaderLaunchContextValue {
  prepare: (signal: SignalSummary, originEl: Element | null) => void;
}

const NOOP: ReaderLaunchContextValue = { prepare: () => undefined };

export const ReaderLaunchContext = createContext<ReaderLaunchContextValue>(NOOP);

export function useReaderLaunch(): ReaderLaunchContextValue {
  return useContext(ReaderLaunchContext);
}
