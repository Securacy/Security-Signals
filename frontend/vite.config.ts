import { resolve } from "path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// The widget always calls the Security Signals API at an absolute URL
// (resolved in src/widget/config.ts from either a loader-supplied
// `apiBase` query param or VITE_API_BASE_URL), since a cross-origin embed
// can't rely on a same-origin dev-server proxy rewrite. That means no
// `/api` proxy is needed here - the backend's CORS config is what allows
// the dev server's origin through instead.
//
// The admin app (src/admin/*) is a second, ordinary top-level SPA served
// at /admin/ in production behind nginx (see nginx.conf.template's
// `location /admin/` SPA fallback). This dev-only plugin mirrors that same
// fallback for `vite dev`: any /admin/* request for a route (not a real
// asset) is rewritten to admin.html, the same way nginx's
// `try_files ... /admin/index.html` behaves in production, so the admin
// router's client-side paths (e.g. /admin/signals) work on a hard refresh
// in dev too, not just via in-app <Link> navigation.
function adminSpaFallback(): Plugin {
  return {
    name: "admin-spa-fallback",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url && req.url.startsWith("/admin") && !req.url.includes(".") ) {
          req.url = "/admin/index.html";
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), adminSpaFallback()],
  server: {
    port: 5173,
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        admin: resolve(__dirname, "admin/index.html"),
      },
    },
  },
});
