import { useAuth } from "../auth/AuthContext";
import { navStructureForRole } from "../auth/permissions";
import { Link, useRouter } from "../router";
import { NavIcon } from "./NavIcons";

export function Sidebar() {
  const { user } = useAuth();
  const { pathname } = useRouter();
  const entries = navStructureForRole(user?.role ?? null);

  return (
    <nav className="adm-sidebar" aria-label="Primary">
      <Link to="/admin/" className="adm-sidebar__brand">
        <svg className="adm-sidebar__brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <circle cx="11" cy="11" r="6.5" />
          <circle cx="11" cy="11" r="2.4" fill="currentColor" stroke="none" />
          <path d="M19.5 19.5 16 16" strokeLinecap="round" />
        </svg>
        <span className="adm-sidebar__brand-text">
          Cyber<span className="adm-sidebar__brand-accent">scope</span>
        </span>
      </Link>
      <ul className="adm-sidebar__list">
        {entries.map((entry) =>
          entry.kind === "leaf" ? (
            <li key={entry.item.key}>
              <Link
                to={entry.item.path}
                className="adm-nav-link"
                aria-current={pathname === entry.item.path ? "page" : undefined}
              >
                <NavIcon routeKey={entry.item.key} />
                {entry.item.label}
              </Link>
            </li>
          ) : (
            <li key={entry.group.label} className="adm-sidebar__group">
              <span className="adm-sidebar__group-label">{entry.group.label}</span>
              <ul className="adm-sidebar__group-list">
                {entry.group.items.map((item) => (
                  <li key={item.key}>
                    <Link
                      to={item.path}
                      className="adm-nav-link adm-nav-link--sub"
                      aria-current={pathname === item.path ? "page" : undefined}
                    >
                      <NavIcon routeKey={item.key} />
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </li>
          ),
        )}
      </ul>
    </nav>
  );
}
