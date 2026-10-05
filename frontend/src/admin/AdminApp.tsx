import { useEffect } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { ThemeProvider } from "./theme";
import { RouterProvider, useRouter } from "./router";
import { canAccess } from "./auth/permissions";
import { AppShell } from "./components/AppShell";
import { LoadingState } from "./components/LoadingState";
import { PermissionDeniedState } from "./components/PermissionDeniedState";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { SignalListPage } from "./pages/SignalListPage";
import { SignalDetailPage } from "./pages/SignalDetailPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { UsersPage } from "./pages/UsersPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import "./admin.css";

export function AdminApp() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <RouterProvider>
          <AdminRoot />
        </RouterProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

function AdminRoot() {
  const { isAuthenticated, isRestoring, user } = useAuth();
  const { route } = useRouter();

  if (isRestoring) {
    return (
      <div className="adm-fullscreen-center">
        <LoadingState label="Loading Cyberscope…" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  if (route.key === "login") {
    return <RedirectToDashboard />;
  }

  const routeKey = route.key === "not-found" ? "dashboard" : route.key;

  if (!canAccess(user!.role, routeKey)) {
    return (
      <AppShell>
        <PermissionDeniedState />
      </AppShell>
    );
  }

  return <AppShell>{renderPage(routeKey, route.key === "signal-detail" ? route.params.id : undefined)}</AppShell>;
}

function RedirectToDashboard() {
  const { navigate } = useRouter();
  useEffect(() => {
    navigate("/admin/");
  }, [navigate]);
  return null;
}

function renderPage(routeKey: Exclude<ReturnType<typeof useRouter>["route"]["key"], "login" | "not-found">, signalId?: string) {
  switch (routeKey) {
    case "dashboard":
      return <DashboardPage />;
    case "signals-all":
      return <SignalListPage status="all" />;
    case "signals-draft":
      return <SignalListPage status="draft" />;
    case "signals-in-review":
      return <SignalListPage status="in_review" />;
    case "signals-approved":
      return <SignalListPage status="approved" />;
    case "signals-published":
      return <SignalListPage status="published" />;
    case "signals-rejected":
      return <SignalListPage status="rejected" />;
    case "signal-detail":
      return <SignalDetailPage signalId={signalId!} />;
    case "insights":
      return <AnalyticsPage />;
    case "users":
      return <UsersPage />;
    case "audit":
      return <AuditLogPage />;
  }
}
