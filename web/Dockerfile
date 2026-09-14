# =============================================================================
# Thot Secure — dashboard React (SPA) : build Vite + service nginx.
#
# Construction (depuis le dossier `web/`) :
#   docker build -t thotsecure-web:0.1.0 .
#
# Exécution (l'API doit être joignable sous le nom `thotsecure:8080`) :
#   docker run --rm -p 8081:8080 --network thotsecure_default thotsecure-web:0.1.0
#
# RAPPEL DE POSITIONNEMENT : la console embarquée servie par l'API (`GET /`,
# Jinja2 + JS embarqués) reste la **référence** et ne nécessite aucun build Node.
# Cette image est l'interface riche **optionnelle**.
#
# Le build exige l'accès au registre npm (`npm ci`). Aucun secret n'est compilé
# dans l'artefact : les variables `VITE_*` sont publiques par nature.
# =============================================================================

# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Étape 1 — compilation TypeScript + bundle Vite
# -----------------------------------------------------------------------------
FROM node:26-alpine AS build

WORKDIR /app

# Couche de dépendances mise en cache séparément du code source.
# `npm ci` est utilisé dès qu'un verrou existe (reproductibilité) ; sinon on
# retombe sur `npm install`, faute de quoi l'image serait impossible à bâtir.
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

# Configuration de build (identique à celle utilisée en local).
COPY tsconfig.json tsconfig.node.json vite.config.ts tailwind.config.ts postcss.config.js index.html ./
COPY src ./src

# `npm run build` exécute `tsc --noEmit` **puis** `vite build` : une erreur de
# typage fait échouer l'image, aucune SPA non typée ne peut être publiée.
RUN npm run build

# -----------------------------------------------------------------------------
# Étape 2 — service statique + reverse proxy
# -----------------------------------------------------------------------------
FROM nginx:1.31-alpine AS runtime

LABEL org.opencontainers.image.title="Thot Secure — dashboard" \
      org.opencontainers.image.description="SPA React du dashboard Thot Secure (interface riche optionnelle) servie par nginx, avec proxy /api vers thotsecure:8080 et en-têtes de sécurité." \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

# La configuration par défaut (écoute sur 80, aucun en-tête de sécurité) est
# remplacée par `web/nginx.conf` (écoute sur 8080, CSP stricte, proxy API).
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# Artefacts statiques produits par Vite.
COPY --from=build /app/dist /usr/share/nginx/html

# Exécution en utilisateur non privilégié : le master nginx tourne sous `nginx`
# (le port 8080 est non privilégié, aucun CAP_NET_BIND_SERVICE n'est requis).
# `/tmp/nginx` porte le fichier de PID, `/var/cache/nginx` les tampons de proxy.
RUN mkdir -p /tmp/nginx /var/cache/nginx \
    && chown -R nginx:nginx /tmp/nginx /var/cache/nginx /usr/share/nginx/html

USER nginx

EXPOSE 8080

# Sonde de vie : la SPA doit répondre sur `/` (le proxy /api n'est pas sondé ici,
# l'API ayant ses propres sondes /healthz et /readyz).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
