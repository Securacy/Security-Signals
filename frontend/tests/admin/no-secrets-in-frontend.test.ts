import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : /\.(ts|tsx|css|html)$/.test(name) ? [path] : [];
  });
}

describe("frontend source never carries Entra secrets or configuration", () => {
  const files = [...sourceFiles(join(__dirname, "../../src")), join(__dirname, "../../admin/index.html")];

  it.each([
    ["a client secret", /client[_-]?secret/i],
    // ENTRA_LOGIN_SUCCESS is excluded: it's the backend's real audit_log
    // action constant (see EntraAuthService._audit), not a config/env var
    // name - the admin audit log legitimately matches on this exact string
    // to render a human-readable "Signed in with Microsoft Entra" entry.
    ["an ENTRA_* environment variable", /ENTRA_(?!LOGIN_SUCCESS\b)[A-Z_]+/],
    ["a Vite-exposed Entra/Microsoft setting", /VITE_[A-Z_]*(ENTRA|MICROSOFT|TENANT|AZURE)/i],
    ["a direct Microsoft login/token endpoint (the backend owns the OAuth flow)", /login\.microsoftonline\.com|oauth2\/v2\.0/i],
    ["a GUID literal (tenant/client/group IDs belong in backend config)", /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i],
  ])("contains no %s", (_label, pattern) => {
    const offenders = files.filter((f) => pattern.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });
});
