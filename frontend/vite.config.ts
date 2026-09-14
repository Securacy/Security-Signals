import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The widget always calls the Security Signals API at an absolute URL
// (resolved in src/widget/config.ts from either a loader-supplied
// `apiBase` query param or VITE_API_BASE_URL), since a cross-origin embed
// can't rely on a same-origin dev-server proxy rewrite. That means no
// `/api` proxy is needed here - the backend's CORS config is what allows
// the dev server's origin through instead.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
