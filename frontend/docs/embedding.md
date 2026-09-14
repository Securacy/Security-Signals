# Embedding the Security Signals widget

This document is for whoever integrates the Security Signals widget into the
Securacy.AI website (or any other host page). It assumes **no knowledge** of
this repository's internals - React, Vite, FastAPI, the backend's
authentication/RBAC/audit system, none of it matters for integration. All you
need is the one script tag below.

Every domain/URL shown here is a **placeholder** (angle-bracketed,
`<LIKE-THIS>`). Replace each with your actual values - none of them are real
production URLs.

## 1. What you're embedding

A small floating launcher button that opens a drawer/panel showing recently
published security signals (title, why it matters, recommended action,
sources). Everything - the launcher, the drawer, and all its content - runs
inside a sandboxed `<iframe>`. Nothing in this widget touches your page's
React version, router, CSS, state management, or authentication. It cannot
see your page's DOM, and your page's styles cannot leak into it, and vice
versa - that's a structural guarantee of the iframe boundary, not a
convention either side has to maintain.

## 2. Script integration

Add this once, anywhere in your page (commonly just before `</body>`):

```html
<script
  type="module"
  src="https://<WIDGET-HOSTING-DOMAIN>/embed.js"
  data-widget-url="https://<WIDGET-HOSTING-DOMAIN>/"
  data-api-base="https://<SECURITY-SIGNALS-API-DOMAIN>"
  data-position="bottom-right"
></script>
```

That's the entire integration. No npm install, no build step, no framework
compatibility to check. `type="module"` is required (the loader is a
standard ES module).

### Attributes

| Attribute | Required | Default | Description |
|---|---|---|---|
| `data-widget-url` | No | The origin the script itself was loaded from | Where the widget's app page is hosted. Only needed if the widget app is hosted somewhere different from `embed.js` itself. |
| `data-api-base` | Yes (for real data) | none | Base URL of the Security Signals backend, e.g. `https://<SECURITY-SIGNALS-API-DOMAIN>`. |
| `data-position` | No | `bottom-right` | One of `bottom-right`, `bottom-left`, `top-right`, `top-left`. Controls where the launcher button (and the desktop drawer) is anchored. |

## 3. Position configuration

Set `data-position` to whichever corner fits your layout. On mobile
viewports (≤640px wide) the drawer always becomes a full-screen sheet
regardless of this setting - there's no meaningful "corner" at that size.

## 4. Versioning

Serve `embed.js` and the widget app at a versioned path if you want control
over when updates land, e.g.:

```
https://<WIDGET-HOSTING-DOMAIN>/v1/embed.js
```

Because the loader is the only thing your page includes directly, shipping
a new version is entirely a deploy on the Security Signals side - your page
never needs to change unless you deliberately bump the version in the
`<script src>`.

## 5. Required CORS configuration (backend)

The widget calls the Security Signals API directly from your page's origin
(cross-origin, from inside the iframe). The backend must allow that origin.
Set on the backend deployment:

```
CORS_ALLOWED_ORIGINS=https://<YOUR-SECURACY-DOMAIN>,https://<ANY-OTHER-TRUSTED-DOMAIN>
```

Comma-separated, no spaces needed. If unset, the backend falls back to its
single `FRONTEND_URL` value (fine for local development, not for a real
multi-domain deployment). No wildcard (`*`) origin is supported by design -
list the exact domain(s) that will embed the widget.

## 6. Required CSP configuration (widget hosting)

The widget's own page sets a `Content-Security-Policy: frame-ancestors`
header so that only domains you trust can iframe it (this prevents an
unrelated third-party site from embedding your Security Signals feed).
Configure this on the container/server that serves the widget app, via the
`WIDGET_FRAME_ANCESTORS` environment variable:

```
WIDGET_FRAME_ANCESTORS='self' https://<YOUR-SECURACY-DOMAIN>
```

**The default is `'self'` only** - meaning nobody can embed the widget until
you explicitly add your domain here. This is intentional: a safe-by-default
posture that requires deliberate configuration rather than an open policy
that happens to work everywhere. Do not set this to `*`.

## 7. Local development / testing

**Widget app alone** (no loader, no embedding - useful while working on the
feed/detail UI itself):

```bash
cd frontend
cp .env.example .env   # sets VITE_API_BASE_URL for standalone use
npm install
npm run dev
```

Open the printed localhost URL directly in a browser tab. The app falls back
to `VITE_API_BASE_URL` when there's no `apiBase` query param (i.e. no
loader involved), so this works without any iframe/loader setup at all.

**Full integration, including the loader**: build the widget, serve `dist/`
plus `loader/embed.js` from some local origin (e.g. `npm run build && npm run preview`,
or the provided `Dockerfile`), then create a throwaway HTML file on a
*different* local origin containing the script tag from Section 2, pointed
at your local build. This is the only way to genuinely exercise the
cross-origin iframe + postMessage behavior locally - opening the widget's
own page directly in a tab does not.

**Backend**: point `data-api-base` (or `VITE_API_BASE_URL`) at your local
Security Signals backend (e.g. `http://localhost:8000`), and make sure that
origin is in the backend's `CORS_ALLOWED_ORIGINS` (or matches its
`FRONTEND_URL`).

## 8. Public API contract

The widget calls exactly two endpoints, both public and unauthenticated.
This is the entire contract - nothing else, and nothing more will be added
to this widget without a corresponding update to this document.

### `GET /api/v1/signals/published`

Query params (all optional):

| Param | Type | Description |
|---|---|---|
| `skip` | integer | Pagination offset. Default `0`. |
| `limit` | integer | Page size, max `100`. Default `10`. |
| `category` | string | One of `vulnerability`, `cloud_security`, `iam`, `app_api`, `supply_chain`, `data_privacy`, `ransomware`, `threat_intel`, `ai_security`, `infrastructure`. Filters to signals tagged with that category. |

Response: a JSON array, each item shaped as:

```json
{
  "id": "uuid",
  "title": "string",
  "summary": "string",
  "security_impact": "string",
  "principle": "string",
  "recommended_action": "string",
  "published_at": "ISO 8601 timestamp or null",
  "categories": [{ "id": "uuid", "category": "string" }]
}
```

### `GET /api/v1/signals/published/{id}`

Same shape as above, plus an `evidence` array:

```json
{
  ...,
  "evidence": [
    {
      "id": "uuid",
      "source_url": "string (external URL)",
      "source_title": "string",
      "excerpt": "string",
      "created_at": "ISO 8601 timestamp or null"
    }
  ]
}
```

Returns `404` if the signal doesn't exist or isn't published (draft/in-review/
rejected signals are never reachable through this endpoint).

### What the widget will never call

No admin, reviewer, user-management, audit, or authentication endpoint is
ever called by this widget, and none of those require any configuration
here. If a future change to this widget appears to need one of those, that
is a sign the change belongs in a different, internal tool instead.
