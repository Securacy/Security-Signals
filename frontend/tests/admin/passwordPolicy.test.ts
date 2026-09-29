import { describe, it, expect } from "vitest";
import { meetsAllRequirements, passwordMatchesIdentity, passwordRequirements } from "../../src/admin/passwordPolicy";

describe("passwordRequirements", () => {
  it("reports every rule as unmet for an empty password", () => {
    const reqs = passwordRequirements("");
    expect(reqs.every((r) => !r.met)).toBe(true);
  });

  it("reports every rule as met for a fully valid password", () => {
    const reqs = passwordRequirements("Str0ng!Passw0rd");
    expect(reqs.every((r) => r.met)).toBe(true);
  });

  it("flags a too-short password", () => {
    const reqs = passwordRequirements("Sh0rt!Pw");
    expect(reqs.find((r) => r.key === "length")!.met).toBe(false);
  });

  it("flags missing uppercase", () => {
    expect(passwordRequirements("str0ng!password").find((r) => r.key === "uppercase")!.met).toBe(false);
  });

  it("flags missing lowercase", () => {
    expect(passwordRequirements("STR0NG!PASSWORD").find((r) => r.key === "lowercase")!.met).toBe(false);
  });

  it("flags missing number", () => {
    expect(passwordRequirements("Strong!Password").find((r) => r.key === "number")!.met).toBe(false);
  });

  it("flags missing special character", () => {
    expect(passwordRequirements("Str0ngPassword12").find((r) => r.key === "special")!.met).toBe(false);
  });

  it("flags leading whitespace", () => {
    expect(passwordRequirements(" Str0ng!Password").find((r) => r.key === "whitespace")!.met).toBe(false);
  });

  it("flags trailing whitespace", () => {
    expect(passwordRequirements("Str0ng!Password ").find((r) => r.key === "whitespace")!.met).toBe(false);
  });
});

describe("meetsAllRequirements", () => {
  it("is false for an empty password", () => {
    expect(meetsAllRequirements("")).toBe(false);
  });

  it("is true only once every rule passes", () => {
    expect(meetsAllRequirements("Str0ngPassword")).toBe(false); // no special char
    expect(meetsAllRequirements("Str0ng!Passw0rd")).toBe(true);
  });
});

describe("passwordMatchesIdentity", () => {
  it("matches the username case-insensitively", () => {
    expect(passwordMatchesIdentity("Alice", "alice")).toBe(true);
    expect(passwordMatchesIdentity("alice", "ALICE")).toBe(true);
  });

  it("matches the full email case-insensitively", () => {
    expect(passwordMatchesIdentity("Alice@Example.com", undefined, "alice@example.com")).toBe(true);
  });

  it("matches the email local part alone", () => {
    expect(passwordMatchesIdentity("alice", undefined, "Alice@example.com")).toBe(true);
  });

  it("is false when the password matches neither", () => {
    expect(passwordMatchesIdentity("Str0ng!Passw0rd", "alice", "alice@example.com")).toBe(false);
  });

  it("is false when neither username nor email is provided", () => {
    expect(passwordMatchesIdentity("anything")).toBe(false);
  });
});
