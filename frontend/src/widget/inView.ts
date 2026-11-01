/** Start fetching a card's image a little before it scrolls into view -
 * on every side, since the feed deck scrolls horizontally. */
export const PREFETCH_MARGIN = "300px";

interface SharedObserver {
  observer: IntersectionObserver;
  /** Per observer, not global: one element is commonly watched by two
   * observers at once (reveal + prefetch), and a shared map would let one
   * registration overwrite the other's callback. */
  callbacks: WeakMap<Element, () => void>;
}

/** Keyed by root (null = the viewport), then rootMargin. */
const observers = new Map<Element | null, Map<string, SharedObserver>>();

/** The scroll container a feed item lives in (marked data-scroll-root in
 * Drawer.tsx), or null for the viewport. It must be the real scroller:
 * rootMargin only grows the ROOT's box, and an overflow container still
 * clips its children - so with the viewport as root, a "300px early"
 * prefetch could never see a card the drawer body hasn't scrolled to. */
export function scrollRootOf(el: Element | null): Element | null {
  return el?.closest("[data-scroll-root]") ?? null;
}

/** One shared IntersectionObserver per (root, rootMargin), rather than one
 * per card. */
function observerFor(root: Element | null, rootMargin: string): SharedObserver | null {
  if (typeof IntersectionObserver !== "function") return null;
  let byMargin = observers.get(root);
  if (!byMargin) {
    byMargin = new Map();
    observers.set(root, byMargin);
  }
  let shared = byMargin.get(rootMargin);
  if (!shared) {
    const callbacks = new WeakMap<Element, () => void>();
    const created = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          const el = entry.target;
          created.unobserve(el);
          const callback = callbacks.get(el);
          callbacks.delete(el);
          callback?.();
        }
      },
      { root, rootMargin },
    );
    shared = { observer: created, callbacks };
    byMargin.set(rootMargin, shared);
  }
  return shared;
}

/**
 * Run `callback` once, the first time `el` comes within `rootMargin` of
 * its scroll root (see scrollRootOf). Runs immediately when
 * IntersectionObserver is unavailable, so nothing waits forever. Returns a
 * cleanup that cancels a still-pending observation.
 */
export function observeOnce(el: Element | null, callback: () => void, rootMargin: string): () => void {
  const shared = el ? observerFor(scrollRootOf(el), rootMargin) : null;
  if (!el || !shared) {
    callback();
    return () => undefined;
  }
  const { observer, callbacks } = shared;
  callbacks.set(el, callback);
  observer.observe(el);
  return () => {
    if (callbacks.delete(el)) observer.unobserve(el);
  };
}
