import { describe, it, expect } from "vitest";
import { sanitizeEvidenceHtml } from "../../src/admin/sanitizeHtml";

describe("sanitizeEvidenceHtml", () => {
  it("strips <script> tags entirely", () => {
    const out = sanitizeEvidenceHtml("<p>hello</p><script>alert('xss')</script>");
    expect(out).not.toContain("<script");
    expect(out).not.toContain("alert");
    expect(out).toContain("hello");
  });

  it("strips event-handler attributes on an otherwise-allowed tag", () => {
    const out = sanitizeEvidenceHtml('<p onclick="alert(1)">text</p>');
    expect(out).not.toContain("onclick");
    expect(out).toContain("text");
  });

  it("strips a disallowed tag (img) including its onerror handler", () => {
    const out = sanitizeEvidenceHtml('<img src=x onerror=alert(\'xss\')>safe text');
    expect(out).not.toContain("<img");
    expect(out).not.toContain("onerror");
    expect(out).toContain("safe text");
  });

  it("strips a javascript: href rather than letting it through", () => {
    const out = sanitizeEvidenceHtml('<a href="javascript:alert(\'xss\')">Click me</a>');
    expect(out).not.toContain("javascript:");
    expect(out).toContain("Click me");
  });

  it("strips a data: href", () => {
    const out = sanitizeEvidenceHtml('<a href="data:text/html,<script>alert(1)</script>">link</a>');
    expect(out).not.toContain("data:");
  });

  it("neutralizes the polyglot \"><script> payload", () => {
    const out = sanitizeEvidenceHtml('"><script>alert(\'xss\')</script>');
    expect(out).not.toContain("<script");
    expect(out).not.toContain("alert");
  });

  it("drops iframe/object/embed/form elements", () => {
    const out = sanitizeEvidenceHtml(
      '<iframe src="https://evil.example"></iframe><object data="x"></object><embed src="x"><form action="x"><input /></form>',
    );
    expect(out).not.toContain("<iframe");
    expect(out).not.toContain("<object");
    expect(out).not.toContain("<embed");
    expect(out).not.toContain("<form");
    expect(out).not.toContain("<input");
  });

  it("keeps the allowed formatting tags and forces safe link attributes on a legitimate https link", () => {
    const out = sanitizeEvidenceHtml(
      '<p><b>Bulletin ID:</b> 2026-117-AWS <br /> <b>Scope:</b> AWS</p><p><a href="https://aws.amazon.com/security/security-bulletins/2026-117-aws/">View article</a></p>',
    );
    expect(out).toContain("<b>Bulletin ID:</b>");
    expect(out).toContain("<br");
    expect(out).toContain("<b>Scope:</b>");
    expect(out).toContain('href="https://aws.amazon.com/security/security-bulletins/2026-117-aws/"');
    expect(out).toContain('target="_blank"');
    expect(out).toContain('rel="noopener noreferrer"');
    expect(out).toContain("View article");
  });

  it("keeps lists intact", () => {
    const out = sanitizeEvidenceHtml("<ul><li>one</li><li>two</li></ul>");
    expect(out).toBe("<ul><li>one</li><li>two</li></ul>");
  });

  it("leaves plain text untouched", () => {
    const out = sanitizeEvidenceHtml("Just plain prose, no markup at all.");
    expect(out).toBe("Just plain prose, no markup at all.");
  });
});
