/** Turns an audit action constant (e.g. "SIGNAL_APPROVED") into readable
 * text ("Signal approved") - shared by DashboardPage's recent-activity
 * section and AuditLogPage's full log. */
export function formatAction(action: string): string {
  return action
    .toLowerCase()
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
