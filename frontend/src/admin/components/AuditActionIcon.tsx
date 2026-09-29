/**
 * One small, meaningful glyph per audit action category - same minimal
 * stroke-icon style as NavIcons.tsx (the project's existing hand-rolled
 * icon system), never the only way an entry's nature is conveyed (the
 * human-readable title/tone always carry the meaning too).
 */

interface IconProps {
  className?: string;
}

function CheckIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M4.5 12.5l4.5 4.5 10.5-11" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function XIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M6 6l12 12M18 6L6 18" strokeLinecap="round" />
    </svg>
  );
}

function SendIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M4 12l16-7-6.5 16-2.5-6.5L4 12z" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function PublishIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M12 16V5M7 9l5-5 5 5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4.5 15v3a2 2 0 002 2h11a2 2 0 002-2v-3" strokeLinecap="round" />
    </svg>
  );
}

function ArchiveIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="3.5" y="4.5" width="17" height="4" rx="1" />
      <path d="M5 8.5V18a1.5 1.5 0 001.5 1.5h11A1.5 1.5 0 0019 18V8.5" strokeLinecap="round" />
      <path d="M10 13h4" strokeLinecap="round" />
    </svg>
  );
}

function UserIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <circle cx="12" cy="8" r="3.4" />
      <path d="M5 20c1-4 4-6 7-6s6 2 7 6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function TrashIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M5 7h14M9.5 7V5a1 1 0 011-1h3a1 1 0 011 1v2" strokeLinecap="round" />
      <path d="M6.5 7l1 12.5A1.5 1.5 0 009 21h6a1.5 1.5 0 001.5-1.5L17.5 7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function KeyIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <circle cx="8" cy="15" r="3.4" />
      <path d="M10.4 12.6L18.5 4.5M15.5 7.5l2 2M13 10l2 2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function LoginIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M10 4H6.5A1.5 1.5 0 005 5.5v13A1.5 1.5 0 006.5 20H10M14 8l4 4-4 4M18 12H9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function LogoutIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M14 4h3.5A1.5 1.5 0 0119 5.5v13a1.5 1.5 0 01-1.5 1.5H14M10 8l-4 4 4 4M6 12h9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function DotIcon({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <circle cx="12" cy="12" r="3.5" />
    </svg>
  );
}

const ICON_BY_ACTION: Record<string, (props: IconProps) => JSX.Element> = {
  SIGNAL_SUBMITTED_FOR_REVIEW: SendIcon,
  SIGNAL_APPROVED: CheckIcon,
  SIGNAL_REJECTED: XIcon,
  SIGNAL_PUBLISHED: PublishIcon,
  SIGNAL_RETIRED_FROM_CURRENT: ArchiveIcon,
  USER_CREATED: UserIcon,
  USER_UPDATED: UserIcon,
  USER_DEACTIVATED: UserIcon,
  USER_PURGED: TrashIcon,
  PASSWORD_CHANGED: KeyIcon,
  PASSWORD_RESET_BY_ADMIN: KeyIcon,
  LOGIN_SUCCESS: LoginIcon,
  ENTRA_LOGIN_SUCCESS: LoginIcon,
  LOGOUT: LogoutIcon,
};

export function AuditActionIcon({ action, className }: { action: string; className?: string }) {
  const Icon = ICON_BY_ACTION[action] ?? DotIcon;
  return <Icon className={className} />;
}
