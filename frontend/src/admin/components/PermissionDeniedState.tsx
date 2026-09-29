import { Link } from "../router";

/** Shown when a route guard blocks a role from a page it navigated to
 * directly (e.g. a typed URL) - the nav itself already hides links a role
 * can't use, so this is a backstop, not the primary defense. The backend's
 * require_admin/require_reviewer dependencies remain the real
 * authorization boundary regardless of what this page shows. */
export function PermissionDeniedState() {
  return (
    <div className="adm-empty-state" role="alert">
      <p className="adm-empty-state__message">You don't have access to this page.</p>
      <p className="adm-empty-state__hint">
        <Link to="/admin/">Return to the dashboard</Link>
      </p>
    </div>
  );
}
