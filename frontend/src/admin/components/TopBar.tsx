import { useAuth } from "../auth/AuthContext";
import { ProfileMenu } from "./ProfileMenu";
import { Link } from "../router";

export function TopBar() {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <header className="adm-topbar">
      <Link to="/admin/" className="adm-topbar__brand">
        Security Signals <span className="adm-topbar__brand-suffix">Admin</span>
      </Link>
      <div className="adm-topbar__account">
        <ProfileMenu />
      </div>
    </header>
  );
}
