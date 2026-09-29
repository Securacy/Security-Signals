import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { useAuthorizedFetch } from "../auth/apiClient";
import { changeOwnPassword } from "../api/client";
import { ApiError } from "../../widget/api";
import { meetsAllRequirements, passwordMatchesIdentity } from "../passwordPolicy";
import { ConfirmDialog } from "./ConfirmDialog";
import { PasswordField } from "./PasswordField";
import { PasswordRequirementsChecklist } from "./PasswordRequirementsChecklist";

/**
 * Self-service password change for the currently authenticated LOCAL user.
 * On success, the change itself already invalidated every token (including
 * the one just used), so this signs the browser out immediately after and
 * sends the user back to the login page with a clear, friendly notice -
 * matching what would happen on their very next API call anyway.
 */
export function ChangePasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, signOut } = useAuth();
  const authorizedFetch = useAuthorizedFetch();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setError(null);
  }

  function handleClose() {
    if (isSubmitting) return;
    reset();
    onClose();
  }

  const identityConflict = user ? passwordMatchesIdentity(newPassword, user.username, user.email) : false;
  // Mismatch warning text only shows once confirmation has been typed at
  // all, but canSubmit below requires an actual, non-empty match - an
  // untouched (empty) confirm field must never satisfy it.
  const confirmMismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const confirmed = newPassword.length > 0 && newPassword === confirmPassword;
  const canSubmit = currentPassword.length > 0 && meetsAllRequirements(newPassword) && !identityConflict && confirmed;

  async function handleConfirm() {
    if (!canSubmit) return;
    setIsSubmitting(true);
    setError(null);
    try {
      await changeOwnPassword(authorizedFetch, currentPassword, newPassword, confirmPassword);
      reset();
      onClose();
      signOut("password_changed");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to change your password. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <ConfirmDialog
      open={open}
      title="Change your password"
      description="You'll be signed out and need to sign in again with your new password."
      confirmLabel={isSubmitting ? "Changing…" : "Change password"}
      onConfirm={handleConfirm}
      onCancel={handleClose}
      confirmDisabled={isSubmitting || !canSubmit}
    >
      <div className="adm-password-form">
        <PasswordField
          label="Current password"
          value={currentPassword}
          onChange={setCurrentPassword}
          autoComplete="current-password"
          autoFocus
        />
        <PasswordField label="New password" value={newPassword} onChange={setNewPassword} autoComplete="new-password" />
        <PasswordRequirementsChecklist password={newPassword} />
        {identityConflict && (
          <p className="adm-field__hint adm-field__hint--warning">Your password can't be your username or email.</p>
        )}
        <PasswordField
          label="Confirm new password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          autoComplete="new-password"
        />
        {confirmMismatch && <p className="adm-field__hint adm-field__hint--warning">Passwords don't match yet.</p>}
        {error && (
          <p role="alert" className="adm-form-error">
            {error}
          </p>
        )}
      </div>
    </ConfirmDialog>
  );
}
