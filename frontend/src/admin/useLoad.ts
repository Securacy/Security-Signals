import { useEffect, useRef, useState } from "react";
import { ApiError } from "../widget/api";

export type LoadState<T> = { status: "loading" } | { status: "error"; message: string } | { status: "ready"; data: T };

/** Small shared data-loading hook: runs `load` whenever `deps` changes,
 * tracks loading/error/ready state, and ignores a stale response if a
 * newer load started before the previous one resolved. */
export function useLoad<T>(
  load: () => Promise<T>,
  deps: unknown[],
  options: { keepPrevious?: boolean } = {},
): LoadState<T> {
  const [state, setState] = useState<LoadState<T>>({ status: "loading" });
  const loadRef = useRef(load);
  loadRef.current = load;
  const keepPreviousRef = useRef(options.keepPrevious ?? false);
  keepPreviousRef.current = options.keepPrevious ?? false;

  useEffect(() => {
    let cancelled = false;
    // keepPrevious: on a reload, keep showing the last successfully loaded
    // data instead of flashing back to a loading state (used for
    // background refreshes like polling a pending visual).
    setState((prev) => (keepPreviousRef.current && prev.status === "ready" ? prev : { status: "loading" }));
    loadRef
      .current()
      .then((data) => {
        if (!cancelled) setState({ status: "ready", data });
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err instanceof ApiError ? err.message : "Something went wrong. Please try again.";
        // A failed background refresh must not blank out data already shown.
        setState((prev) => (keepPreviousRef.current && prev.status === "ready" ? prev : { status: "error", message }));
      });
    return () => {
      cancelled = true;
    };
    // deps is caller-controlled on purpose - this hook re-runs `load`
    // exactly when the caller's dependency list changes, not based on
    // `load`'s own identity (which would re-run on every render).
  }, deps);

  return state;
}
