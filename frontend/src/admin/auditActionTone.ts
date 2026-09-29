import type { ComponentProps } from "react";
import type { Badge } from "./components/Badge";

type BadgeTone = ComponentProps<typeof Badge>["tone"];

/** Consistent status color for an audit entry, derived purely from the
 * REAL action string the backend recorded (never a fabricated field) - so
 * approvals/publishes/logins read as positive, rejections/deactivations as
 * a warning, and everything else neutral. Every audited action already
 * succeeded (failures are never audited, per the atomic-or-rollback
 * design), so this is a semantic grouping, not a pass/fail indicator. */
export function auditActionTone(action: string): BadgeTone {
  if (/(APPROVED|PUBLISHED|CREATED|LOGIN_SUCCESS)$/.test(action)) return "success";
  if (/(REJECTED|DEACTIVATED)$/.test(action)) return "warning";
  if (action === "LOGOUT") return "neutral";
  return "info";
}
