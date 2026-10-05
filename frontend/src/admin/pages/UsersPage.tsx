import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import {
  adminResetPassword,
  createUser,
  deactivateUser,
  fetchUsers,
  purgeInactiveUser,
  updateUserRole,
} from "../api/client";
import type { AdminUser } from "../api/types";
import type { Role } from "../auth/types";
import { ROLE_LABEL, ROLE_TONE } from "../roleBadge";
import { formatRelativeTime } from "../../widget/formatRelativeTime";
import { useLoad } from "../useLoad";
import { ApiError } from "../../widget/api";
import { meetsAllRequirements, passwordMatchesIdentity } from "../passwordPolicy";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingState } from "../components/LoadingState";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { PasswordField } from "../components/PasswordField";
import { PasswordRequirementsChecklist } from "../components/PasswordRequirementsChecklist";

const ROLES: Role[] = ["admin", "reviewer", "viewer"];
const PAGE_SIZE = 50;

type RowAction =
  | { kind: "role"; user: AdminUser }
  | { kind: "deactivate"; user: AdminUser }
  | { kind: "reset-password"; user: AdminUser }
  | { kind: "purge"; user: AdminUser };

interface Feedback {
  tone: "success" | "error";
  message: string;
}

/**
 * ADMIN-only user management: list, create, change role, deactivate, reset
 * a local user's password, and permanently remove an already-inactive
 * account. Every mutation goes through the real /users API - the backend's
 * require_admin dependency remains the actual authorization boundary, and
 * this page only calls capabilities that API already supports.
 */
export function UsersPage() {
  const { user: currentUser } = useAuth();
  const authorizedFetch = useAuthorizedFetch();

  const [reloadToken, setReloadToken] = useState(0);
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [rowAction, setRowAction] = useState<RowAction | null>(null);
  const [selectedRole, setSelectedRole] = useState<Role>("viewer");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmittingAction, setIsSubmittingAction] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const usersState = useLoad(() => fetchUsers(authorizedFetch, { limit }), [authorizedFetch, limit, reloadToken]);
  const hasMore = usersState.status === "ready" && usersState.data.length === limit;

  function openRoleChange(user: AdminUser) {
    setFeedback(null);
    setActionError(null);
    setSelectedRole(user.role);
    setRowAction({ kind: "role", user });
  }

  function openDeactivate(user: AdminUser) {
    setFeedback(null);
    setActionError(null);
    setRowAction({ kind: "deactivate", user });
  }

  function openResetPassword(user: AdminUser) {
    setFeedback(null);
    setActionError(null);
    setNewPassword("");
    setConfirmPassword("");
    setRowAction({ kind: "reset-password", user });
  }

  function openPurge(user: AdminUser) {
    setFeedback(null);
    setActionError(null);
    setRowAction({ kind: "purge", user });
  }

  function closeRowAction() {
    if (isSubmittingAction) return;
    setRowAction(null);
    setActionError(null);
    setNewPassword("");
    setConfirmPassword("");
  }

  async function confirmRowAction() {
    if (!rowAction) return;
    setIsSubmittingAction(true);
    setActionError(null);
    try {
      if (rowAction.kind === "role") {
        await updateUserRole(authorizedFetch, rowAction.user.id, selectedRole);
        setFeedback({ tone: "success", message: `${rowAction.user.username}'s role is now ${ROLE_LABEL[selectedRole]}.` });
      } else if (rowAction.kind === "deactivate") {
        await deactivateUser(authorizedFetch, rowAction.user.id);
        setFeedback({ tone: "success", message: `${rowAction.user.username}'s account was deactivated.` });
      } else if (rowAction.kind === "reset-password") {
        await adminResetPassword(authorizedFetch, rowAction.user.id, newPassword, confirmPassword);
        setFeedback({ tone: "success", message: `${rowAction.user.username}'s password was reset.` });
      } else {
        await purgeInactiveUser(authorizedFetch, rowAction.user.id);
        setFeedback({ tone: "success", message: `${rowAction.user.username}'s account was permanently removed.` });
      }
      setRowAction(null);
      setNewPassword("");
      setConfirmPassword("");
      setReloadToken((n) => n + 1);
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "That action failed. Please try again.");
    } finally {
      setIsSubmittingAction(false);
    }
  }

  const roleChangeDisabled =
    rowAction?.kind === "role" && isSubmittingAction === false && selectedRole === rowAction.user.role;
  const resetPasswordIdentityConflict =
    rowAction?.kind === "reset-password" &&
    passwordMatchesIdentity(newPassword, rowAction.user.username, rowAction.user.email);
  // Mismatch warning text only shows once confirmation has been typed at
  // all, but enablement below requires an actual, non-empty match -
  // an untouched (empty) confirm field must never satisfy it.
  const resetPasswordMismatch = rowAction?.kind === "reset-password" && confirmPassword.length > 0 && newPassword !== confirmPassword;
  const resetPasswordConfirmed = newPassword.length > 0 && newPassword === confirmPassword;
  const resetPasswordDisabled =
    rowAction?.kind === "reset-password" &&
    (!meetsAllRequirements(newPassword) || resetPasswordIdentityConflict || !resetPasswordConfirmed);

  const confirmDisabled =
    isSubmittingAction ||
    roleChangeDisabled ||
    (rowAction?.kind === "reset-password" && resetPasswordDisabled);

  return (
    <div className="adm-page">
      <header className="adm-page__header">
        <h1>Users</h1>
        <p className="adm-page__subtitle">Manage admin console accounts, roles, and local passwords</p>
      </header>

      {feedback && (
        <div className={`adm-banner adm-banner--${feedback.tone}`} role="status">
          <span>{feedback.message}</span>
          <button type="button" className="adm-banner__dismiss" onClick={() => setFeedback(null)} aria-label="Dismiss">
            &times;
          </button>
        </div>
      )}

      <Card
        title="All users"
        action={
          <Button variant="primary" onClick={() => setIsCreateOpen((v) => !v)}>
            {isCreateOpen ? "Cancel" : "New user"}
          </Button>
        }
      >
        {isCreateOpen && (
          <CreateUserForm
            authorizedFetch={authorizedFetch}
            onCreated={(username) => {
              setIsCreateOpen(false);
              setFeedback({ tone: "success", message: `${username} was created.` });
              setReloadToken((n) => n + 1);
            }}
          />
        )}

        {usersState.status === "loading" && <LoadingState label="Loading users…" />}
        {usersState.status === "error" && <ErrorState message={usersState.message} />}
        {usersState.status === "ready" && usersState.data.length === 0 && (
          <EmptyState message="No users exist yet." hint="Create the first account above." />
        )}
        {usersState.status === "ready" && usersState.data.length > 0 && (
          <>
            <ul className="adm-user-list">
              {usersState.data.map((user) => {
                const isSelf = user.id === currentUser!.id;
                return (
                  <li key={user.id} className="adm-user-row">
                    <span className="adm-user-avatar" aria-hidden="true">
                      {user.username.slice(0, 1).toUpperCase()}
                    </span>
                    <div className="adm-user-row__main">
                      <span className="adm-user-row__name">{user.username}</span>
                      <span className="adm-user-row__email">{user.email}</span>
                      <span className="adm-user-row__meta">
                        Created {formatRelativeTime(user.created_at)}
                        {user.last_login_at ? ` · Last login ${formatRelativeTime(user.last_login_at)}` : " · Never logged in"}
                      </span>
                    </div>
                    <div className="adm-user-row__status">
                      <Badge tone={ROLE_TONE[user.role]}>{ROLE_LABEL[user.role]}</Badge>
                      <Badge tone={user.is_active ? "success" : "danger"}>{user.is_active ? "Active" : "Inactive"}</Badge>
                    </div>
                    <div className="adm-user-row__actions">
                      <Button variant="secondary" onClick={() => openRoleChange(user)}>
                        Change role
                      </Button>
                      {user.has_local_credential && !isSelf && (
                        <Button variant="secondary" onClick={() => openResetPassword(user)}>
                          Reset password
                        </Button>
                      )}
                      {user.is_active && !isSelf && (
                        <Button variant="danger" onClick={() => openDeactivate(user)}>
                          Deactivate
                        </Button>
                      )}
                      {!user.is_active && (
                        <Button variant="danger" onClick={() => openPurge(user)}>
                          Remove
                        </Button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
            {hasMore && (
              <div className="adm-load-more">
                <Button variant="secondary" onClick={() => setLimit((n) => n + PAGE_SIZE)}>
                  Load more
                </Button>
              </div>
            )}
          </>
        )}
      </Card>

      <ConfirmDialog
        open={rowAction !== null}
        title={
          rowAction?.kind === "role"
            ? "Change role?"
            : rowAction?.kind === "deactivate"
              ? "Deactivate this account?"
              : rowAction?.kind === "reset-password"
                ? "Reset password?"
                : "Permanently remove this account?"
        }
        description={
          rowAction?.kind === "role"
            ? `Change ${rowAction.user.username}'s role.`
            : rowAction?.kind === "deactivate"
              ? `${rowAction.user.username} will no longer be able to sign in. This cannot be undone through this interface.`
              : rowAction?.kind === "reset-password"
                ? `Set a new password for ${rowAction.user.username}. Their current password stops working immediately.`
                : rowAction?.kind === "purge"
                  ? `${rowAction.user.username}'s account will be permanently deleted. Their prior audit history is preserved. This cannot be undone.`
                  : undefined
        }
        confirmLabel={
          rowAction?.kind === "role"
            ? "Change role"
            : rowAction?.kind === "deactivate"
              ? "Deactivate"
              : rowAction?.kind === "reset-password"
                ? "Reset password"
                : "Remove permanently"
        }
        tone={rowAction?.kind === "deactivate" || rowAction?.kind === "purge" ? "danger" : "primary"}
        onConfirm={confirmRowAction}
        onCancel={closeRowAction}
        confirmDisabled={confirmDisabled}
      >
        {rowAction?.kind === "role" && (
          <div className="adm-field">
            <label htmlFor="adm-role-select" className="adm-field__label">
              Role
            </label>
            <select
              id="adm-role-select"
              className="adm-input"
              value={selectedRole}
              onChange={(event) => setSelectedRole(event.target.value as Role)}
            >
              {ROLES.map((role) => (
                <option key={role} value={role}>
                  {ROLE_LABEL[role]}
                </option>
              ))}
            </select>
          </div>
        )}
        {rowAction?.kind === "reset-password" && (
          <div className="adm-password-form">
            <PasswordField label="New password" value={newPassword} onChange={setNewPassword} autoComplete="new-password" autoFocus />
            <PasswordRequirementsChecklist password={newPassword} />
            {resetPasswordIdentityConflict && (
              <p className="adm-field__hint adm-field__hint--warning">
                The password can't be the user's username or email.
              </p>
            )}
            <PasswordField
              label="Confirm new password"
              value={confirmPassword}
              onChange={setConfirmPassword}
              autoComplete="new-password"
            />
            {resetPasswordMismatch && <p className="adm-field__hint adm-field__hint--warning">Passwords don't match yet.</p>}
          </div>
        )}
        {actionError && (
          <p role="alert" className="adm-form-error">
            {actionError}
          </p>
        )}
      </ConfirmDialog>
    </div>
  );
}

function CreateUserForm({
  authorizedFetch,
  onCreated,
}: {
  authorizedFetch: ReturnType<typeof useAuthorizedFetch>;
  onCreated: (username: string) => void;
}) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const created = await createUser(authorizedFetch, { username, email, role, password });
      setUsername("");
      setEmail("");
      setPassword("");
      setRole("viewer");
      onCreated(created.username);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to create the user. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form className="adm-create-user-form" onSubmit={handleSubmit} noValidate>
      <div className="adm-create-user-form__grid">
        <div className="adm-field">
          <label htmlFor="adm-new-username" className="adm-field__label">
            Username
          </label>
          <input
            id="adm-new-username"
            className="adm-input"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
        </div>
        <div className="adm-field">
          <label htmlFor="adm-new-email" className="adm-field__label">
            Email
          </label>
          <input
            id="adm-new-email"
            className="adm-input"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </div>
        <div className="adm-field">
          <label htmlFor="adm-new-role" className="adm-field__label">
            Role
          </label>
          <select
            id="adm-new-role"
            className="adm-input"
            value={role}
            onChange={(event) => setRole(event.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
        </div>
        <div className="adm-field">
          <label htmlFor="adm-new-password" className="adm-field__label">
            Temporary password
          </label>
          <input
            id="adm-new-password"
            className="adm-input"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
          <p className="adm-field__hint">At least 12 characters, with upper/lowercase, a number, and a symbol.</p>
        </div>
      </div>
      {error && (
        <p role="alert" className="adm-form-error">
          {error}
        </p>
      )}
      <Button type="submit" variant="primary" disabled={isSubmitting}>
        {isSubmitting ? "Creating…" : "Create user"}
      </Button>
    </form>
  );
}
