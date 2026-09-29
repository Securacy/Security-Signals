import { useId, useState } from "react";

interface PasswordFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: "current-password" | "new-password";
  autoFocus?: boolean;
}

/** A labeled password input with a show/hide toggle. The toggle is a
 * plain, unstyled button (not adm-btn) so it sits inline inside the input
 * rather than reading as a separate form action. */
export function PasswordField({ label, value, onChange, autoComplete, autoFocus }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);
  const id = useId();

  return (
    <div className="adm-field">
      <label htmlFor={id} className="adm-field__label">
        {label}
      </label>
      <div className="adm-password-field">
        <input
          id={id}
          className="adm-input"
          type={visible ? "text" : "password"}
          autoComplete={autoComplete}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoFocus={autoFocus}
          required
        />
        <button
          type="button"
          className="adm-password-field__toggle"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}
