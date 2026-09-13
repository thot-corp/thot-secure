# syntax=docker/dockerfile:1.7
# =============================================================================
# Thot Secure — image conteneur durcie (multi-étapes)
# =============================================================================
# SOAR/CSPM 100 % défensif. Licence Apache-2.0.
#
# Construction standard (avec accès réseau, pour résoudre les dépendances) :
#
#   docker build \
#     --build-arg BUILD_REVISION="$(git rev-parse --short HEAD)" \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     -t thotsecure:0.1.0 .
#
# -----------------------------------------------------------------------------
# CONSTRUCTION HORS-LIGNE (aucun accès réseau au registre PyPI)
# -----------------------------------------------------------------------------
# L'étape `builder` accepte `PIP_NO_INDEX` et `PIP_FIND_LINKS`. Pour construire
# sans réseau, préparez un « wheelhouse » (tous les wheels des dépendances
# runtime, y compris celles de `uvicorn[standard]`) puis :
#
#   docker build \
#     --build-arg PIP_NO_INDEX=1 \
#     --build-arg PIP_FIND_LINKS=/wheelhouse \
#     --build-arg PIP_TRUSTED_HOST= \
#     -v "${PWD}/wheelhouse:/wheelhouse:ro" \
#     -t thotsecure:0.1.0 .
#
# Le montage `-v` est un *build context* supplémentaire (BuildKit) : déclarez-le
# comme contexte nommé si votre version de BuildKit l'exige :
#
#   docker build --build-context wheelhouse=./wheelhouse ...
#   # puis, dans l'étape builder : RUN --mount=from=wheelhouse,...
#
# Alternative sans BuildKit : copiez le wheelhouse dans le contexte de build
# (`docker build --build-arg PIP_NO_INDEX=1 --build-arg PIP_FIND_LINKS=/src/wheelhouse .`)
# après avoir déposé les wheels dans `./wheelhouse` (pensez alors à retirer
# `wheelhouse/` du `.dockerignore`, ou à l'y autoriser explicitement).
#
# Remarque « pas de tini » : `tini` n'est pas présent dans `python:3.11-slim-bookworm`
# et ne peut pas être installé sans réseau. On n'en dépend donc pas :
#   * `docker run --init`  (ou `init: true` dans Compose) fournit un PID 1 minimal ;
#   * à défaut, le conteneur lance `uvicorn` directement en `exec` (ENTRYPOINT en
#     forme exec), qui gère proprement SIGTERM/SIGINT.
# =============================================================================

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

# -----------------------------------------------------------------------------
# Étape 1 — builder : venv isolé + installation du paquet
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

# Arguments d'offline-first : par défaut, comportement standard (index PyPI).
ARG PIP_NO_INDEX=0
ARG PIP_FIND_LINKS=
ARG PIP_TRUSTED_HOST=

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Outils de compilation : uniquement présents dans cette étape, jamais dans
# l'image finale (surface d'attaque réduite, image plus petite).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      libffi-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Le venv vit hors de /src pour survivre à la copie vers l'étape runtime.
ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"
RUN python -m venv "${VIRTUAL_ENV}"

# Couche de dépendances : on copie d'abord les métadonnées de build pour
# bénéficier du cache de couches quand seul le code source change.
# `pyproject.toml` est la propriété de l'équipe packaging applicatif : ce
# Dockerfile se contente de le consommer.
COPY pyproject.toml ./
COPY README.md ./
COPY LICENSE ./

# Mise à jour de l'outillage de packaging. En mode hors-ligne (PIP_NO_INDEX=1),
# la résolution se fait exclusivement depuis `PIP_FIND_LINKS` ; si l'outillage
# est déjà fourni par l'image de base (c'est le cas de `python:3.11-slim-bookworm`
# avec un pip récent), l'échec n'est pas bloquant : on le tolère explicitement.
RUN set -eux; \
    set -- ; \
    if [ "${PIP_NO_INDEX}" = "1" ]; then set -- "$@" --no-index; fi; \
    if [ -n "${PIP_FIND_LINKS}" ]; then set -- "$@" --find-links "${PIP_FIND_LINKS}"; fi; \
    if [ -n "${PIP_TRUSTED_HOST}" ]; then set -- "$@" --trusted-host "${PIP_TRUSTED_HOST}"; fi; \
    pip install "$@" --upgrade pip setuptools wheel || \
      pip install --upgrade pip setuptools wheel || \
      echo "Avertissement : outillage de packaging non mis à jour (mode hors-ligne)."

RUN set -eux; \
    set -- ; \
    if [ "${PIP_NO_INDEX}" = "1" ]; then set -- "$@" --no-index; fi; \
    if [ -n "${PIP_FIND_LINKS}" ]; then set -- "$@" --find-links "${PIP_FIND_LINKS}"; fi; \
    if [ -n "${PIP_TRUSTED_HOST}" ]; then set -- "$@" --trusted-host "${PIP_TRUSTED_HOST}"; fi; \
    pip install "$@" \
      "fastapi" \
      "uvicorn[standard]" \
      "pydantic" \
      "pydantic-settings" \
      "PyYAML" \
      "Jinja2"

# Code source applicatif (paquet `thotsecure` sous src/thotsecure/).
COPY src/ ./src/
COPY rules/ ./rules/
COPY policies/ ./policies/
COPY playbooks/ ./playbooks/

# Installation du projet dans le venv (`pip install .`). Le point d'entrée
# console `thotsecure` (thotsecure.cli:main) est créé dans /opt/venv/bin/thotsecure.
RUN set -eux; \
    set -- ; \
    if [ "${PIP_NO_INDEX}" = "1" ]; then set -- "$@" --no-index; fi; \
    if [ -n "${PIP_FIND_LINKS}" ]; then set -- "$@" --find-links "${PIP_FIND_LINKS}"; fi; \
    if [ -n "${PIP_TRUSTED_HOST}" ]; then set -- "$@" --trusted-host "${PIP_TRUSTED_HOST}"; fi; \
    pip install "$@" --no-deps .

# Vérification de build : le paquet et le point d'entrée ASGI doivent exister.
RUN set -eux; \
    /opt/venv/bin/python -c "import thotsecure, sys; print('thotsecure', thotsecure.__version__ if hasattr(thotsecure,'__version__') else 'n/a')"; \
    /opt/venv/bin/thotsecure --help >/dev/null

# -----------------------------------------------------------------------------
# Étape 2 — runtime : image minimale, non-root, sans outils de compilation
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ARG BUILD_DATE
ARG BUILD_REVISION=unknown
ARG THOT_VERSION=0.1.0
ARG THOT_UID=10001
ARG THOT_GID=10001

# Libellés OCI complets (https://github.com/opencontainers/image-spec).
LABEL org.opencontainers.image.title="Thot Secure" \
      org.opencontainers.image.description="SOAR/CSPM défensif multi-tenant : collecte, détection, scoring, décision, contre-mesure réversible." \
      org.opencontainers.image.version="${THOT_VERSION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/thot-corp/thot-secure" \
      org.opencontainers.image.url="https://github.com/thot-corp/thot-secure" \
      org.opencontainers.image.documentation="https://github.com/thot-corp/thot-secure/blob/main/deploy/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Thot Secure" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim-bookworm"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    THOT_ENV=prod \
    THOT_HOST=0.0.0.0 \
    THOT_PORT=8080 \
    THOT_DB_URL=sqlite:////var/lib/thotsecure/thotsecure.db \
    THOT_RULES_DIR=/etc/thotsecure/rules \
    THOT_POLICIES_DIR=/etc/thotsecure/policies \
    THOT_PLAYBOOKS_DIR=/etc/thotsecure/playbooks \
    THOT_TARGETS_FILE=/etc/thotsecure/targets.yaml \
    THOT_BUS=memory \
    THOT_NATS_URL=nats://nats:4222 \
    THOT_LOG_LEVEL=INFO \
    THOT_LOG_FORMAT=json \
    THOT_TLS_ENABLED=false \
    THOT_RATE_LIMIT_PER_MIN=600 \
    THOT_RETENTION_DAYS=30 \
    THOT_DRY_RUN=true \
    THOT_AUTONOMY=supervised

# -----------------------------------------------------------------------------
# AVERTISSEMENT DE SÛRETÉ
# Les deux variables ci-dessus sont les garde-fous du produit :
#   THOT_DRY_RUN=true      -> aucune action réelle n'est exécutée.
#   THOT_AUTONOMY=supervised -> toute action critique exige une approbation.
# Ne les modifiez JAMAIS dans une image de production : surchargez-les
# explicitement au déploiement (compose/env/Helm), et seulement après une
# procédure de validation humaine documentée (voir deploy/README.md).
# -----------------------------------------------------------------------------

# Utilisateur et groupe non privilégiés (UID/GID 10001), sans shell de login.
RUN set -eux; \
    groupadd --gid "${THOT_GID}" --system thotsecure; \
    useradd --uid "${THOT_UID}" --gid "${THOT_GID}" \
            --system --no-create-home --home-dir /var/lib/thotsecure \
            --shell /usr/sbin/nologin thotsecure; \
    install -d -o thotsecure -g thotsecure -m 0750 /var/lib/thotsecure; \
    install -d -o thotsecure -g thotsecure -m 0750 /var/lib/thotsecure/quarantine; \
    install -d -o root -g thotsecure -m 0750 /etc/thotsecure; \
    install -d -o root -g thotsecure -m 0750 /etc/thotsecure/rules; \
    install -d -o root -g thotsecure -m 0750 /etc/thotsecure/policies; \
    install -d -o root -g thotsecure -m 0750 /etc/thotsecure/playbooks; \
    install -d -o root -g thotsecure -m 0755 /opt/thotsecure; \
    install -d -o thotsecure -g thotsecure -m 1777 /tmp

# Venv applicatif + contenus livrés + cibles déclarées (périmètre autorisé).
COPY --from=builder --chown=root:thotsecure /opt/venv /opt/venv
COPY --from=builder --chown=root:thotsecure /src/src /opt/thotsecure/src
COPY --from=builder --chown=root:thotsecure /src/rules /etc/thotsecure/rules
COPY --from=builder --chown=root:thotsecure /src/policies /etc/thotsecure/policies
COPY --from=builder --chown=root:thotsecure /src/playbooks /etc/thotsecure/playbooks

# Squelette de périmètre : les cibles doivent être déclarées explicitement par le
# tenant (opt-in). Le fichier est écrasé par le montage en lecture seule.
RUN set -eux; \
    printf '%s\n' \
      '# Périmètre déclaré (opt-in). Seules les cibles possédées par le tenant' \
      '# doivent être listées ici. Aucune cible n'"'"'est active par défaut.' \
      'version: 1' \
      'tenants: {}' \
      > /etc/thotsecure/targets.yaml; \
    chown root:thotsecure /etc/thotsecure/targets.yaml; \
    chmod 0640 /etc/thotsecure/targets.yaml

WORKDIR /var/lib/thotsecure

USER 10001:10001

# 8080 : API REST /api/v1, console embarquée /, /healthz, /readyz, /metrics.
EXPOSE 8080

# HEALTHCHECK sans curl (absent de l'image) : urllib de la stdlib suffit.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]

# ENTRYPOINT en forme exec : uvicorn devient PID 1 et reçoit SIGTERM/SIGINT.
# Pour un vrai init (zombies, signaux), lancez avec `--init` / `init: true`.
ENTRYPOINT ["uvicorn", "thotsecure.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
CMD []
