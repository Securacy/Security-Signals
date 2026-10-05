import React from "react";
import ReactDOM from "react-dom/client";
import { AdminApp } from "./AdminApp";
// Self-hosted (not a third-party Google Fonts request) - used only for the
// "Cyberscope" wordmark (see admin.css's .adm-sidebar__brand-text), never
// the app's body text. Two weights only, kept deliberately small.
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/700.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AdminApp />
  </React.StrictMode>,
);
