/**
 * A short, friendly greeting for the dashboard header. Picked once per
 * LOGIN (see auth/AuthContext.tsx's completeSignIn), not once per render -
 * reading it again later in the same session (page refresh, navigating
 * around) always returns the same text; only a fresh sign-in picks a new
 * one. Stored in sessionStorage (same per-tab, cleared-on-close lifetime
 * as the session itself, under the existing "ss-admin-*" key convention),
 * never anything sensitive.
 */

const GREETING_STORAGE_KEY = "ss-admin-greeting";

const GREETINGS: string[] = [
  "Welcome back!",
  "Good to see you again ✨",
  "Hey there — let's dig in.",
  "You're back! Let's see what's new.",
  "Oh hey, right on time 👀",
  "Ready when you are.",
  "Back for more threat-hunting?",
  "Hiya! Let's get to work.",
  "Look who it is 👋",
  "Welcome back, scout.",
  "Let's see what's out there today.",
  "Nice to see you.",
  "Alright, let's check the signals.",
  "Hey hey, good timing.",
  "You're in. Let's look around.",
  "Back again — we like that.",
  "Hi! Here's what's happening.",
  "Onward, cyber sleuth 🔎",
];

interface StoredGreeting {
  text: string;
}

function readStored(): StoredGreeting | null {
  try {
    const raw = window.sessionStorage.getItem(GREETING_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredGreeting>;
    return typeof parsed.text === "string" ? (parsed as StoredGreeting) : null;
  } catch {
    return null;
  }
}

function persist(text: string): void {
  try {
    window.sessionStorage.setItem(GREETING_STORAGE_KEY, JSON.stringify({ text }));
  } catch {
    // sessionStorage unavailable - the greeting still works for this
    // render, it just won't be stable across a refresh.
  }
}

/** Picks a new random greeting (avoiding the immediately-previous one
 * where possible) and persists it for the rest of this session. Call this
 * exactly once per real login - see AuthContext.completeSignIn. */
export function pickAndPersistGreeting(): string {
  const previous = readStored()?.text;
  const pool = previous ? GREETINGS.filter((g) => g !== previous) : GREETINGS;
  const candidates = pool.length > 0 ? pool : GREETINGS;
  const text = candidates[Math.floor(Math.random() * candidates.length)];
  persist(text);
  return text;
}

/** Reads this session's greeting, picking and persisting a fresh one if
 * none exists yet (e.g. a dev reload that bypassed the normal sign-in
 * flow). Safe to call on every render/navigation - it never changes the
 * stored value once one exists. */
export function getSessionGreeting(): string {
  return readStored()?.text ?? pickAndPersistGreeting();
}

/** Clears this session's greeting - call on sign-out so the next login is
 * guaranteed a fresh pick rather than reusing a stale one. */
export function clearSessionGreeting(): void {
  try {
    window.sessionStorage.removeItem(GREETING_STORAGE_KEY);
  } catch {
    // ignore
  }
}
