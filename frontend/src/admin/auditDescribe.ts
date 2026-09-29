import type { AuditEntry } from "./api/types";
import { formatAction } from "./formatAction";

/**
 * Turns a raw audit_log row (action constant + its real `changes` JSON,
 * see the backend's _audit_signal_action/_audit_user_action/_audit call
 * sites for the exact shape each action writes) into a short, human-
 * readable title plus a handful of "label: value" lines - e.g. "Signal
 * approved" / "Amrutha VR approved..." / "Status changed: IN_REVIEW ->
 * APPROVED". Every value here is read straight from real audit data (the
 * actor/target names are resolved by the caller, best-effort, from the
 * admin's own user/signal lists) - nothing is invented, and nothing here
 * ever reads a password/hash/token field (none of the actions below ever
 * write one into `changes`).
 */

export interface AuditDetailLine {
  label: string;
  value: string;
}

export interface AuditDescription {
  title: string;
  lines: AuditDetailLine[];
}

const ROLE_DISPLAY: Record<string, string> = { admin: "Admin", reviewer: "Reviewer", viewer: "Viewer" };

function roleLabel(value: unknown): string {
  const s = String(value ?? "");
  return ROLE_DISPLAY[s] ?? s;
}

function str(value: unknown, fallback = "—"): string {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function isFromTo(value: unknown): value is { from?: unknown; to?: unknown } {
  return typeof value === "object" && value !== null && ("from" in value || "to" in value);
}

export function describeAuditEntry(
  entry: AuditEntry,
  actorName: string,
  signalTitle: string | null,
  targetUserName: string | null,
): AuditDescription {
  const c = entry.changes ?? {};
  const signal = signalTitle ?? `Signal #${entry.resource_id.slice(0, 8)}`;

  switch (entry.action) {
    case "SIGNAL_SUBMITTED_FOR_REVIEW":
      return {
        title: "Signal submitted for review",
        lines: [
          { label: "Signal", value: signal },
          { label: "Submitted by", value: actorName },
          { label: "Status changed", value: `${str(c.status_from)} → ${str(c.status_to)}` },
        ],
      };
    case "SIGNAL_APPROVED":
      return {
        title: "Signal approved",
        lines: [
          { label: "Signal", value: signal },
          { label: "Approved by", value: actorName },
          { label: "Status changed", value: `${str(c.status_from)} → ${str(c.status_to)}` },
        ],
      };
    case "SIGNAL_REJECTED":
      return {
        title: "Signal rejected",
        lines: [
          { label: "Signal", value: signal },
          { label: "Rejected by", value: actorName },
          { label: "Status changed", value: `${str(c.status_from)} → ${str(c.status_to)}` },
          ...(c.reason ? [{ label: "Review note", value: String(c.reason) }] : []),
        ],
      };
    case "SIGNAL_PUBLISHED":
      return {
        title: "Signal published",
        lines: [
          { label: "Signal", value: signal },
          { label: "Published by", value: actorName },
          { label: "Status changed", value: `${str(c.status_from)} → ${str(c.status_to)}` },
        ],
      };
    case "SIGNAL_RETIRED_FROM_CURRENT":
      return {
        title: "Signal retired (superseded)",
        lines: [
          { label: "Signal", value: signal },
          { label: "Category", value: str(c.category) },
        ],
      };
    case "USER_CREATED":
      return {
        title: "User created",
        lines: [
          { label: "Username", value: str(c.username) },
          { label: "Email", value: str(c.email) },
          { label: "Role", value: roleLabel(c.role) },
          { label: "Created by", value: actorName },
        ],
      };
    case "USER_UPDATED": {
      const roleChange = isFromTo(c.role) ? c.role : undefined;
      const emailChange = isFromTo(c.email) ? c.email : undefined;
      const lines: AuditDetailLine[] = [{ label: "Target", value: targetUserName ?? "—" }];
      if (roleChange) {
        lines.push({ label: "Previous", value: roleLabel(roleChange.from) });
        lines.push({ label: "New", value: roleLabel(roleChange.to) });
      }
      if (emailChange) {
        lines.push({ label: "Email changed", value: `${str(emailChange.from)} → ${str(emailChange.to)}` });
      }
      lines.push({ label: "Changed by", value: actorName });
      return { title: roleChange ? "User role updated" : "User updated", lines };
    }
    case "USER_DEACTIVATED":
      return {
        title: "User deactivated",
        lines: [
          { label: "Target", value: targetUserName ?? "—" },
          { label: "Deactivated by", value: actorName },
        ],
      };
    case "USER_PURGED":
      return {
        title: "User permanently removed",
        lines: [
          { label: "Username", value: str(c.username) },
          { label: "Email", value: str(c.email) },
          { label: "Role", value: roleLabel(c.role) },
          { label: "Removed by", value: actorName },
        ],
      };
    case "PASSWORD_CHANGED":
      return {
        title: "Password changed",
        lines: [
          { label: "Account", value: targetUserName ?? actorName },
          { label: "Method", value: "Self-service" },
        ],
      };
    case "PASSWORD_RESET_BY_ADMIN":
      return {
        title: "Password reset by admin",
        lines: [
          { label: "Target", value: targetUserName ?? "—" },
          { label: "Reset by", value: actorName },
        ],
      };
    case "LOGIN_SUCCESS":
      return {
        title: "Signed in",
        lines: [
          { label: "User", value: str(c.username, actorName) },
          { label: "Role", value: roleLabel(c.role) },
          { label: "Method", value: "Password" },
        ],
      };
    case "ENTRA_LOGIN_SUCCESS":
      return {
        title: "Signed in with Microsoft Entra",
        lines: [
          { label: "User", value: targetUserName ?? actorName },
          { label: "Role", value: roleLabel(c.role) },
          ...(c.linked ? [{ label: "Note", value: "Linked to an existing account by email" }] : []),
        ],
      };
    case "LOGOUT":
      return {
        title: "Signed out",
        lines: [{ label: "User", value: str(c.username, actorName) }],
      };
    default:
      return { title: formatAction(entry.action), lines: [{ label: "Actor", value: actorName }] };
  }
}
