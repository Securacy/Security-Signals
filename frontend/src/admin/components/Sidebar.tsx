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
