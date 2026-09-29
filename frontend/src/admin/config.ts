/**
 * Runtime configuration for the admin app. Unlike the widget (which is
 * always cross-origin-embedded and must resolve its API base from a
 * loader-supplied query param, see widget/config.ts), the admin app is a
 * normal top-level page - it only ever needs a build-time API base URL.
 *
 * In production this is expected to be set to "" (empty string) so
 * requests go to same-origin relative paths (e.g. "/api/v1/...") and are
 * proxied to the backend by nginx (see nginx.conf.template's
 * `location /api/`). In local dev it defaults to the backend's default
 * port so `npm run dev` works standalone without any extra setup.
 */
export interface AdminConfig {
  apiBaseUrl: string;
}

export function getAdminConfig(): AdminConfig {
  const configured = import.meta.env.VITE_API_BASE_URL as string | undefined;
  const apiBaseUrl = configured !== undefined ? configured : "http://localhost:8000";
  return { apiBaseUrl: apiBaseUrl.replace(/\/+$/, "") };
}
