import { useEffect, useId, useRef, useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { useTheme, type ThemePreference } from "../theme";
import { ROLE_LABEL, ROLE_TONE } from "../roleBadge";
import { Badge } from "./Badge";
import { ChangePasswordDialog } from "./ChangePasswordDialog";

const THEME_OPTIONS: { value: ThemePreference; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "system", label: "System" },
  { value: "dark", label: "Dark" },
];

/**
 * Avatar/profile menu in the top-right, replacing a standalone "Change
 * password" button in the top bar. A lightweight accessible disclosure
 * (not a full modal): Escape closes and returns focus to the trigger,
 * clicking outside closes, every actionable entry is a real <button>
 * (native Tab order + the app's existing :focus-visible ring already
 * cover keyboard use without a hand-rolled roving-tabindex system).
 */
export function ProfileMenu() {
  const { user, signOut } = useAuth();
  const { preference, setPreference } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!isOpen) return undefined;

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setIsOpen(false);
        triggerRef.current?.focus();
      }
    }
    function onClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("mousedown", onClickOutside);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("mousedown", onClickOutside);
    };
  }, [isOpen]);

  if (!user) return null;

  const initials = user.username.slice(0, 2).toUpperCase();

  return (
    <div className="adm-profile-menu" ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        className="adm-profile-menu__trigger"
        aria-haspopup="menu"
        aria-expanded={isOpen}
        aria-controls={isOpen ? menuId : undefined}
        onClick={() => setIsOpen((v) => !v)}
      >
        <span className="adm-profile-menu__avatar" aria-hidden="true">
          {initials}
        </span>
        <span className="adm-profile-menu__trigger-name">{user.username}</span>
        <span className="adm-profile-menu__chevron" aria-hidden="true">
          ▾
        </span>
      </button>

      {isOpen && (
        <div id={menuId} role="menu" aria-label="Account" className="adm-profile-menu__panel">
          <div className="adm-profile-menu__summary">
            <span className="adm-profile-menu__avatar adm-profile-menu__avatar--large" aria-hidden="true">
              {initials}
            </span>
            <div>
              <p className="adm-profile-menu__summary-name">{user.username}</p>
              <p className="adm-profile-menu__summary-email">{user.email}</p>
              <div className="adm-profile-menu__summary-badges">
                <Badge tone={ROLE_TONE[user.role]}>{ROLE_LABEL[user.role]}</Badge>
                <Badge tone="neutral">{user.entraLinked ? "Microsoft Entra managed" : "Password managed"}</Badge>
              </div>
            </div>
          </div>

          <div className="adm-profile-menu__divider" role="separator" />

          {user.hasLocalCredential && (
            <button
              type="button"
              role="menuitem"
              className="adm-profile-menu__item"
              onClick={() => {
                setIsOpen(false);
                setIsChangingPassword(true);
              }}
            >
              Change password
            </button>
          )}

          <div className="adm-profile-menu__group">
            <span className="adm-profile-menu__group-label">Appearance</span>
            <div className="adm-profile-menu__theme-options">
              {THEME_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  role="menuitemradio"
                  aria-checked={preference === option.value}
                  className={`adm-profile-menu__theme-btn${preference === option.value ? " adm-profile-menu__theme-btn--active" : ""}`}
                  onClick={() => setPreference(option.value)}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div className="adm-profile-menu__divider" role="separator" />

          <button
            type="button"
            role="menuitem"
            className="adm-profile-menu__item"
            onClick={() => {
              setIsOpen(false);
              signOut();
            }}
          >
            Sign out
          </button>
        </div>
      )}

      <ChangePasswordDialog open={isChangingPassword} onClose={() => setIsChangingPassword(false)} />
    </div>
  );
}
