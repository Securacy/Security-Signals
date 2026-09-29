/**
 * Client-side mirror of the ONE password policy enforced server-side in
 * app/auth/password.py::validate_password_strength. This is UX only - the
 * backend independently re-validates every rule and is the actual security
 * boundary, exactly as it does for every other input. Kept in sync by hand
 * since the two run in different languages; if the backend policy ever
 * changes, this must change with it.
 */

// Matches Python's string.punctuation exactly, so "special character"
// means the same set of characters on both sides.
const SPECIAL_CHARACTERS = /[!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~]/;

export interface PasswordRequirement {
  key: string;
  label: string;
  met: boolean;
}

/** The live checklist shown while typing - the six rules the UI mockup
 * calls out explicitly. Username/email-equality is validated separately
 * (see passwordMatchesIdentity) since it needs another value to compare
 * against and doesn't fit a single-password checklist item. */
export function passwordRequirements(password: string): PasswordRequirement[] {
  return [
    { key: "length", label: "12+ characters", met: password.length >= 12 },
    { key: "uppercase", label: "Uppercase letter", met: /[A-Z]/.test(password) },
    { key: "lowercase", label: "Lowercase letter", met: /[a-z]/.test(password) },
    { key: "number", label: "Number", met: /[0-9]/.test(password) },
    { key: "special", label: "Special character", met: SPECIAL_CHARACTERS.test(password) },
    { key: "whitespace", label: "No leading/trailing spaces", met: password.length > 0 && password === password.trim() },
  ];
}

export function meetsAllRequirements(password: string): boolean {
  return passwordRequirements(password).every((r) => r.met);
}

/** Mirrors the backend's identical-to-username / identical-to-email(local
 * part) rejection, so a doomed submission can be caught before the round
 * trip. Case-insensitive, matching the backend. */
export function passwordMatchesIdentity(password: string, username?: string, email?: string): boolean {
  const lower = password.toLowerCase();
  if (username && lower === username.toLowerCase()) return true;
  if (email) {
    const emailLower = email.toLowerCase();
    const localPart = emailLower.split("@", 1)[0];
    if (lower === emailLower || lower === localPart) return true;
  }
  return false;
}
