import { describe, it, expect, beforeEach } from "vitest";
import { getSessionGreeting, pickAndPersistGreeting, clearSessionGreeting } from "../../src/admin/greeting";

describe("greeting", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("picks and persists a non-empty greeting", () => {
    const text = pickAndPersistGreeting();
    expect(typeof text).toBe("string");
    expect(text.length).toBeGreaterThan(0);
  });

  it("stays stable across repeated reads within the same session (no new login in between)", () => {
    const first = pickAndPersistGreeting();
    const readAgain1 = getSessionGreeting();
    const readAgain2 = getSessionGreeting();
    expect(readAgain1).toBe(first);
    expect(readAgain2).toBe(first);
  });

  it("getSessionGreeting picks and persists one on first read if none exists yet", () => {
    expect(window.sessionStorage.getItem("ss-admin-greeting")).toBeNull();
    const text = getSessionGreeting();
    expect(text.length).toBeGreaterThan(0);
    expect(getSessionGreeting()).toBe(text);
  });

  it("a fresh pick (simulating a new login) can change the greeting and avoids immediate repetition", () => {
    const first = pickAndPersistGreeting();
    // Run several times - with more than one phrase in the pool, at least
    // one of several fresh picks should differ from the immediately-
    // previous one (this also directly asserts the anti-repeat guarantee
    // holds for a single subsequent pick, deterministically).
    const second = pickAndPersistGreeting();
    expect(second).not.toBe(first);
  });

  it("clearSessionGreeting removes the stored value so the next read picks fresh", () => {
    pickAndPersistGreeting();
    expect(window.sessionStorage.getItem("ss-admin-greeting")).not.toBeNull();
    clearSessionGreeting();
    expect(window.sessionStorage.getItem("ss-admin-greeting")).toBeNull();
  });
});
