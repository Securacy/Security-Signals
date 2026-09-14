# Multi-stage build for frontend

FROM node:20-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Serve with nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html

# The loader is a separate, dependency-free file that a host page includes
# directly - it is not bundled/transformed by Vite, just served as-is
# alongside the built widget app.
COPY loader/embed.js /usr/share/nginx/html/embed.js

# nginx.conf.template is processed by the official image's built-in
# envsubst-on-startup templating (files under /etc/nginx/templates/*.template
# are rendered into /etc/nginx/conf.d/ before nginx starts). This lets the
# frame-ancestors CSP value be supplied at deploy time via an environment
# variable instead of being baked into the image.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Safe-by-default: nobody can iframe this page until an operator sets
# WIDGET_FRAME_ANCESTORS to the real trusted host domain(s) at deploy time.
# NGINX_ENVSUBST_FILTER restricts envsubst to only this variable, so nginx's
# own request-time variables (`$host`, `$uri`, etc.) in the template are
# never touched by the substitution step.
ENV WIDGET_FRAME_ANCESTORS='self'
ENV NGINX_ENVSUBST_FILTER='WIDGET_FRAME_ANCESTORS'

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
