import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  completeEntraSignIn,
  fetchAuthProviders,
  messageForSignInError,
  microsoftSignInUrl,
} from "../../../src/admin/auth/providers/entraProvider";

function respond(status: number, body: unknown) {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) })));
}

describe("entraProvider", () => {
  beforeEach(() => vi.unstubAllGlobals());

  it("links to the backend login endpoint - never directly to Microsoft", () => {
    const url = microsoftSignInUrl();
    expect(url).toMatch(/\/api\/v1\/auth\/entra\/login$/);
    expect(url).not.toContain("microsoftonline");
    expect(url).not.toContain("client_id");
  });

  describe("fetchAuthProviders", () => {
    it("returns only strict booleans", async () => {
      respond(200, { local: "yes", entra: 1 });
      expect(await fetchAuthProviders()).toEqual({ local: false, entra: false });
      respond(200, { local: true, entra: true, tenant: "ignored", secret: "ignored" });
      expect(await fetchAuthProviders()).toEqual({ local: true, entra: true });
    });

    it("throws a clear error when the backend is unreachable or fails", async () => {
      vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("offline"))));
      await expect(fetchAuthProviders()).rejects.toThrow("Network error");
      respond(500, {});
      await expect(fetchAuthProviders()).rejects.toThrow("500");
    });
  });

  describe("completeEntraSignIn", () => {
    it("maps a 401 to a user-facing 'could not be completed' error", async () => {
      respond(401, { detail: "No pending sign-in" });
      await expect(completeEntraSignIn()).rejects.toThrow("could not be completed");
    });

    it("returns the AuthSession from a valid backend response", async () => {
      respond(200, {
        access_token: "tok",
        user: { id: "1", username: "u", email: "e@x.test", role: "admin", has_local_credential: false, entra_linked: true },
      });
      expect(await completeEntraSignIn()).toEqual({
        token: "tok",
        user: { id: "1", username: "u", email: "e@x.test", role: "admin", hasLocalCredential: false, entraLinked: true },
      });
    });

    it("defaults hasLocalCredential/entraLinked when the backend response omits them (older mocks/back-compat)", async () => {
      respond(200, { access_token: "tok", user: { id: "1", username: "u", email: "e@x.test", role: "admin" } });
      const session = await completeEntraSignIn();
      expect(session.user.hasLocalCredential).toBe(true);
      expect(session.user.entraLinked).toBe(false);
    });

    it("refuses an unknown role value rather than passing it into the UI", async () => {
      respond(200, { access_token: "tok", user: { id: "1", username: "u", email: "e", role: "owner" } });
      await expect(completeEntraSignIn()).rejects.toThrow("invalid response");
    });
  });

  describe("messageForSignInError", () => {
    it("returns null when there is no error", () => {
      expect(messageForSignInError(null)).toBeNull();
      expect(messageForSignInError("")).toBeNull();
    });

    it("gives every backend code a specific message, and unknown codes the generic one", () => {
      const codes = ["access_denied", "invalid_state", "invalid_token", "not_provisioned", "account_disabled", "account_conflict"];
      const messages = new Set(codes.map((c) => messageForSignInError(c)));
      expect(messages.size).toBe(codes.length); // each is distinct
      expect(messageForSignInError("weird")).toBe(messageForSignInError("auth_failed"));
      expect(messageForSignInError("weird")).not.toContain("weird");
    });
  });
});
