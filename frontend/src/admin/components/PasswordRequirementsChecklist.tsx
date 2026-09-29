import { passwordRequirements } from "../passwordPolicy";

/**
 * Live checklist shown while typing a new password. Each requirement pairs
 * an icon with its own text label (Ok/Pending, not color alone) so the
 * state is never communicated by color alone. Uses aria-live="polite" so a
 * screen reader announces changes as the user types, without interrupting
 * mid-keystroke the way assertive would.
 */
export function PasswordRequirementsChecklist({ password }: { password: string }) {
  const requirements = passwordRequirements(password);
  return (
    <ul className="adm-password-requirements" aria-live="polite">
      {requirements.map((req) => (
        <li
          key={req.key}
          className={`adm-password-requirements__item${req.met ? " adm-password-requirements__item--met" : ""}`}
        >
          <span className="adm-password-requirements__icon" aria-hidden="true">
            {req.met ? "✓" : "○"}
          </span>
          <span>
            {req.label}
            <span className="adm-visually-hidden">{req.met ? " - met" : " - not met yet"}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}
