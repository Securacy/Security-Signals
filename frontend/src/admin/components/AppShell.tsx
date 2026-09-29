import type { ReactNode } from "react";
import { TopBar } from "./TopBar";
import { Sidebar } from "./Sidebar";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="adm-shell">
      <a href="#adm-main-content" className="adm-skip-link">
        Skip to main content
      </a>
      <TopBar />
      <div className="adm-shell__body">
        <Sidebar />
        <main id="adm-main-content" className="adm-shell__content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
