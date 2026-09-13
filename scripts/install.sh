#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/install.sh
# -----------------------------------------------------------------------------
#  Installation en une commande :
#
#      curl -fsSL https://raw.githubusercontent.com/thot-corp/thot-secure/main/scripts/install.sh | sudo bash
#
#  Ce script est fait pour être LU avant d'être exécuté. Un `curl … | bash`
#  exécute du code distant avec vos privilèges : téléchargez-le, lisez-le,
#  vérifiez son origine, puis lancez-le. Il est également utilisable depuis un
#  clone du dépôt : `sudo ./scripts/install.sh`.
#
#  Ce que fait ce script, dans l'ordre :
#    1. détecte l'OS et l'architecture ;
#    2. interroge l'API GitHub pour résoudre la release (dernière, ou --version) ;
#    3. télécharge l'artefact ET ses preuves, puis VÉRIFIE :
#         - la signature Sigstore (`cosign verify-blob`, keyless OIDC ou par clé) ;
#         - le condensé SHA-256 (manifeste SHA256SUMS, sinon digest de l'API) ;
#       Si l'une des deux vérifications échoue, l'installation est REFUSÉE
#       (code de sortie 3) et les fichiers téléchargés sont supprimés.
#       Il n'existe AUCUNE option pour contourner cette étape, volontairement.
#    4. installe (archive binaire dans $PREFIX/bin, ou sdist/wheel dans un venv) ;
#    5. crée le compte système dédié et les répertoires
#       (/etc/thotsecure, /var/lib/thotsecure, /var/log/thotsecure) ;
#    6. écrit /etc/thotsecure/thotsecure.env (0600) avec une THOT_SECRET_KEY
#       générée localement — jamais affichée, jamais journalisée ;
#    7. installe l'unité systemd durcie (scripts/thotsecure.service) si elle est
#       disponible, puis initialise la base ;
#    8. affiche les étapes suivantes (doctor, tenant, clé).
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont les valeurs par
#    défaut. Ce script ne les inverse JAMAIS ; il se contente d'AVERTIR si le
#    fichier d'environnement les a été modifiées. Aucune action réelle n'est
#    exécutée tant que l'exploitant ne l'a pas décidé explicitement.
#
#  Conventions de chemins : identiques à deploy/ansible/roles/thotsecure
#  (utilisateur `thotsecure`, /etc/thotsecure, /var/lib/thotsecure, /opt/thotsecure).
#  Le renommage du produit (thotsecure → thotsecure) est en cours : les DEUX noms
#  de commande sont installés, le nom d'environnement `THOT_*` est conservé.
#
#  Codes de sortie (contrat §8) : 0 succès, 1 erreur, 2 usage, 3 vérification
#  négative (signature ou condensé invalide).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="install.sh"
readonly SCRIPT_VERSION="0.1.0"

# Couleurs sobres, uniquement si la sortie est un terminal et si NO_COLOR est absent.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi

log_info()  { printf '%s==>%s %s\n' "${C_BLUE}${C_BOLD}" "${C_RESET}" "$*"; }
log_ok()    { printf '%s  ok%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
log_warn()  { printf '%s[!]%s %s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}" "$*" >&2; }
log_error() { printf '%s[x]%s %s\n' "${C_RED}${C_BOLD}" "${C_RESET}" "$*" >&2; }
log_step()  { printf '    %s%s%s\n' "${C_DIM}" "$*" "${C_RESET}"; }

# Journalise une commande sans jamais l'exécuter (mode --dry-run).
log_dry() {
  printf '    %s[dry-run]%s' "${C_DIM}" "${C_RESET}"
  printf ' %q' "$@"
  printf '\n'
}

# Exécute une commande, ou l'affiche seulement en mode --dry-run.
# Toutes les opérations qui MODIFIENT le système passent par ici.
run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry "$@"
    return 0
  fi
  "$@"
}

die() {
  local code="${2:-1}"
  log_error "$1"
  exit "${code}"
}

# Piège d'erreur : indique la ligne fautive, puis nettoie.
on_error() {
  local line="$1"
  local status="$2"
  log_error "Échec de ${SCRIPT_NAME} à la ligne ${line} (code ${status})."
  log_error "Aucune modification n'a été appliquée au-delà de l'étape en cours."
  exit "${status}"
}
trap 'on_error "${LINENO}" "$?"' ERR

# -----------------------------------------------------------------------------
# 2. Constantes (miroir de deploy/ansible/roles/thotsecure/defaults/main.yml)
# -----------------------------------------------------------------------------
readonly REPO_DEFAULT="thot-corp/thot-secure"
readonly SERVICE_NAME="thotsecure"        # nom de service et de commande cible
readonly LEGACY_NAME="thotsecure"           # nom technique actuel (renommage en cours)
readonly SERVICE_USER="thotsecure"
readonly SERVICE_GROUP="thotsecure"
readonly ETC_DIR="/etc/thotsecure"
readonly DATA_DIR="/var/lib/thotsecure"
readonly LOG_DIR="/var/log/thotsecure"
readonly INSTALL_DIR="/opt/thotsecure"
readonly VENV_DIR="${INSTALL_DIR}/venv"
readonly ENV_FILE="${ETC_DIR}/thotsecure.env"
readonly DB_URL="sqlite:////var/lib/thotsecure/thotsecure.db"
readonly UNIT_NAME="thotsecure.service"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3

# -----------------------------------------------------------------------------
# 3. Options (surchargeables par variable d'environnement pour l'automatisation)
# -----------------------------------------------------------------------------
DRY_RUN="false"
VERSION_TAG="${THOT_INSTALL_VERSION:-}"
REPO="${THOT_INSTALL_REPO:-${REPO_DEFAULT}}"
PREFIX="${THOT_INSTALL_PREFIX:-/usr/local}"
INSTALL_SERVICE="true"
INIT_DB="true"
CONTENT_DIR=""
UNIT_FILE=""
WHEELHOUSE=""

usage() {
  cat <<'AIDE'
Thot Secure — installation en une commande (Linux et macOS).

USAGE
    sudo ./scripts/install.sh [options]
    curl -fsSL <url>/scripts/install.sh | sudo bash -s -- [options]

OPTIONS
    --version <tag>      Installer une version précise (ex. v0.1.0 ou 0.1.0).
                         Par défaut : la dernière release publiée.
    --repo <owner/name> Dépôt GitHub source (défaut : thot-corp/thot-secure).
    --prefix <chemin>   Préfixe d'installation des binaires (défaut : /usr/local).
    --content-dir <dir> Copier rules/, policies/, playbooks/ et config/ vers
                         /etc/thotsecure depuis ce répertoire (défaut : la racine
                         du dépôt si le script est lancé depuis un clone).
    --unit-file <path>  Unité systemd à installer (défaut : scripts/thotsecure.service
                         à côté de ce script, si présent).
    --wheelhouse <dir>  Installer les dépendances Python hors ligne depuis ce
                         répertoire (ajoute --no-index --find-links à pip).
    --no-service        Ne pas installer ni activer l'unité systemd.
    --no-init-db        Ne pas exécuter « thotsecure init-db ».
    --dry-run           Résoudre la release, télécharger et VÉRIFIER les
                         artefacts dans un répertoire temporaire, afficher le
                         plan d'installation, puis s'arrêter sans rien modifier.
    -h, --help          Afficher cette aide.

SÛRETÉ
    * La vérification Sigstore (cosign verify-blob) et le contrôle SHA-256 sont
      OBLIGATOIRES. Il n'existe volontairement AUCUNE option pour les
      contourner : un artefact non vérifié n'est jamais installé (sortie 3).
    * THOT_DRY_RUN=true et THOT_AUTONOMY=supervised restent les valeurs
      par défaut du fichier d'environnement ; ce script ne les inverse pas.
    * Thot Secure est strictement défensif : aucune capacité offensive.
    * Lisez ce script avant de l'exécuter en root.

EXEMPLES
    sudo ./scripts/install.sh --dry-run --version v0.1.0
    sudo ./scripts/install.sh --prefix /usr/local --content-dir /opt/thotsecure/src
    curl -fsSL https://raw.githubusercontent.com/thot-corp/thot-secure/main/scripts/install.sh \
      | sudo bash -s -- --dry-run
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        [[ $# -ge 2 ]] || die "--version exige un tag (ex. v0.1.0)." "${EXIT_USAGE}"
        VERSION_TAG="$2"; shift 2 ;;
      --repo)
        [[ $# -ge 2 ]] || die "--repo exige « owner/name »." "${EXIT_USAGE}"
        REPO="$2"; shift 2 ;;
      --prefix)
        [[ $# -ge 2 ]] || die "--prefix exige un chemin." "${EXIT_USAGE}"
        PREFIX="$2"; shift 2 ;;
      --content-dir)
        [[ $# -ge 2 ]] || die "--content-dir exige un chemin." "${EXIT_USAGE}"
        CONTENT_DIR="$2"; shift 2 ;;
      --unit-file)
        [[ $# -ge 2 ]] || die "--unit-file exige un chemin." "${EXIT_USAGE}"
        UNIT_FILE="$2"; shift 2 ;;
      --wheelhouse)
        [[ $# -ge 2 ]] || die "--wheelhouse exige un chemin." "${EXIT_USAGE}"
        WHEELHOUSE="$2"; shift 2 ;;
      --no-service) INSTALL_SERVICE="false"; shift ;;
      --no-init-db) INIT_DB="false"; shift ;;
      --dry-run)    DRY_RUN="true"; shift ;;
      -h|--help)    usage; exit 0 ;;
      *)            log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  if [[ ! "${REPO}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    die "--repo attend la forme « owner/name » (reçu : ${REPO})." "${EXIT_USAGE}"
  fi
  if [[ -n "${VERSION_TAG}" && ! "${VERSION_TAG}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-_A-Za-z0-9.]+)?$ ]]; then
    die "--version attend un tag SemVer, ex. v0.1.0 (reçu : ${VERSION_TAG})." "${EXIT_USAGE}"
  fi
  # Les chemins absolus sont attendus : on refuse un chemin relatif ambigu.
  if [[ "${PREFIX}" != /* ]]; then
    die "--prefix attend un chemin absolu (reçu : ${PREFIX})." "${EXIT_USAGE}"
  fi
}

# -----------------------------------------------------------------------------
# 4. Prérequis et détection de la plateforme
# -----------------------------------------------------------------------------
require_root() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : les privilèges root ne sont pas nécessaires."
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    die "Cette installation écrit dans ${ETC_DIR}, ${DATA_DIR} et ${PREFIX} : relancez avec sudo." 1
  fi
}

# `command -v` uniquement : jamais de `which`, jamais d'`eval`.
need_cmd() {
  local cmd="$1" hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Commande requise absente : ${cmd}"
    log_step "${hint}"
    return 1
  fi
  return 0
}

http_get() {
  # http_get <url> <fichier_de_sortie>
  local url="$1" out="$2"
  local -a auth=()
  # Jeton facultatif : évite le quota anonyme de l'API GitHub. Jamais journalisé.
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  if command -v curl >/dev/null 2>&1; then
    # ${auth[@]+...} : garde la compatibilité bash 3.2 (macOS) sous « set -u ».
    curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
         ${auth[@]+"${auth[@]}"} --output "${out}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    if [[ ${#auth[@]} -gt 0 ]]; then
      wget --quiet --tries=3 --output-document="${out}" \
           --header "Authorization: Bearer ${GITHUB_TOKEN}" "${url}"
    else
      wget --quiet --tries=3 --output-document="${out}" "${url}"
    fi
  else
    die "curl ou wget est requis pour télécharger la release." 1
  fi
}

detect_platform() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"
  case "${uname_s}" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) die "Système non supporté : ${uname_s}. Utilisez Docker, ou les instructions manuelles de docs/installation.md." 1 ;;
  esac
  case "${uname_m}" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "Architecture non supportée : ${uname_m}." 1 ;;
  esac
  log_ok "Plateforme détectée : ${OS}/${ARCH}"
}

sha256_of() {
  # sha256_of <fichier> → condensé hexadécimal en minuscules.
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "${file}" | awk '{print tolower($NF)}'
  else
    die "Aucun outil SHA-256 disponible (sha256sum, shasum ou openssl)." 1
  fi
}

check_prerequisites() {
  local missing=0
  need_cmd python3 "Installez Python 3.11 ou plus récent (paquet python3)." || missing=1
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    log_error "Commande requise absente : curl (ou wget)"
    log_step "Installez curl : apt-get install curl | dnf install curl"
    missing=1
  fi
  if ! command -v sha256sum >/dev/null 2>&1 \
     && ! command -v shasum >/dev/null 2>&1 \
     && ! command -v openssl >/dev/null 2>&1; then
    log_error "Aucun outil de condensé SHA-256 (sha256sum / shasum / openssl)."
    missing=1
  fi
  [[ "${missing}" -eq 0 ]] || die "Prérequis manquants : corrigez-les puis relancez." 1

  # Le plancher est 3.11 (pyproject: requires-python = ">=3.11"). Un Python plus
  # ancien reste utilisable pour l'analyse JSON, mais l'installation échouera.
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
      log_warn "Python 3.11+ est requis par le paquet (requires-python = \">=3.11\")."
      log_warn "Version détectée : $(python3 -V 2>&1)"
    fi
  fi

  # cosign est OBLIGATOIRE : la signature est vérifiée avant toute installation.
  if ! command -v cosign >/dev/null 2>&1; then
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_warn "cosign est absent : en --dry-run, la vérification de signature est ignorée."
      log_warn "Une installation RÉELLE refusera de continuer sans cosign."
    else
      log_error "Commande requise absente : cosign (Sigstore)."
      log_step "La vérification de signature est obligatoire et ne peut pas être contournée."
      log_step "Installez cosign depuis https://github.com/sigstore/cosign/releases,"
      log_step "ou via votre gestionnaire de paquets (apt/dnf/brew), puis relancez."
      die "cosign est requis pour vérifier la release avant installation." 1
    fi
  fi
  if [[ -z "${WHEELHOUSE}" ]] && ! command -v tar >/dev/null 2>&1; then
    log_warn "tar est absent : les archives ne pourront pas être extraites."
  fi
}

# -----------------------------------------------------------------------------
# 5. Résolution de la release via l'API GitHub
# -----------------------------------------------------------------------------
fetch_release() {
  local api_url
  if [[ -n "${VERSION_TAG}" ]]; then
    local tag="${VERSION_TAG}"
    [[ "${tag}" == v* ]] || tag="v${tag}"
    api_url="https://api.github.com/repos/${REPO}/releases/tags/${tag}"
    log_info "Résolution de la release ${tag} sur ${REPO}…"
    if ! http_get "${api_url}" "${TMP_DIR}/release.json" 2>/dev/null; then
      # Certaines releases sont étiquetées sans le préfixe « v ».
      api_url="https://api.github.com/repos/${REPO}/releases/tags/${VERSION_TAG}"
      log_warn "Tag « ${tag} » introuvable, nouvel essai avec « ${VERSION_TAG} »."
      http_get "${api_url}" "${TMP_DIR}/release.json" \
        || die "Release introuvable : ${REPO}@${VERSION_TAG}." 1
    fi
  else
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    log_info "Résolution de la dernière release de ${REPO}…"
    http_get "${api_url}" "${TMP_DIR}/release.json" \
      || die "Aucune release publiée lisible sur ${REPO} (vérifiez le nom du dépôt)." 1
  fi

  # L'analyse JSON est faite par Python (pas de jq requis, pas d'eval).
  cat > "${TMP_DIR}/pick_assets.py" <<'PY'
"""Choisit l'artefact, son manifeste de condensés et ses preuves Sigstore.

Sortie : lignes « CLE=valeur » consommées par install.sh.
Le script échoue (sortie 1) si aucun artefact exploitable n'est trouvé.
"""
from __future__ import annotations

import json
import pathlib
import sys

release_path, os_name, arch, version = sys.argv[1:5]
release = json.loads(pathlib.Path(release_path).read_text(encoding="utf-8"))
assets = release.get("assets") or []
tag = release.get("tag_name") or ""
semver = (version or tag).lstrip("v")

by_name = {asset.get("name", ""): asset for asset in assets}


def find(*predicates):
    """Premier asset dont le nom satisfait un des prédicats (ordre = priorité)."""
    for predicate in predicates:
        for name, asset in by_name.items():
            if predicate(name):
                return asset
    return None


def pick_artifact():
    # 1. Archive binaire autonome, telle que documentée dans docs/installation.md :
    #    thotsecure_0.1.0_linux_amd64.tar.gz / thotsecure_0.1.0_linux_amd64.tar.gz
    for prefix in ("thotsecure", "thotsecure"):
        for candidate in (f"{prefix}_{semver}_{os_name}_{arch}.tar.gz",
                          f"{prefix}-{semver}-{os_name}-{arch}.tar.gz",
                          f"{prefix}_{semver}_{os_name}_{arch}.zip"):
            if candidate in by_name:
                return by_name[candidate], "archive"
    # 2. Distribution Python (ce que produit .github/workflows/release.yml).
    wheel = find(lambda n: n.endswith(".whl") and semver.replace(".", "") in n.replace(".", ""),
                 lambda n: n.endswith(".whl"))
    if wheel is not None:
        return wheel, "wheel"
    sdist = find(lambda n: n.endswith(".tar.gz") and semver in n)
    if sdist is not None:
        return sdist, "sdist"
    return None, ""


artifact, kind = pick_artifact()
if artifact is None:
    names = ", ".join(sorted(by_name)) or "(aucun)"
    print(f"::error::aucun artefact installable dans la release {tag}; assets: {names}",
          file=sys.stderr)
    raise SystemExit(1)

lines = {
    "RELEASE_TAG": tag,
    "RELEASE_VERSION": semver,
    "ASSET_KIND": kind,
    "ASSET_NAME": artifact.get("name", ""),
    "ASSET_URL": artifact.get("browser_download_url", ""),
    "ASSET_DIGEST": artifact.get("digest") or "",
}
sums = find(lambda n: n.upper() in {"SHA256SUMS", "SHA256SUMS.TXT", "CHECKSUMS.TXT"},
            lambda n: "sha256" in n.lower() and n.lower().endswith((".txt", ".sums", ".sha256")))
if sums is not None:
    lines["SUMS_NAME"] = sums.get("name", "")
    lines["SUMS_URL"] = sums.get("browser_download_url", "")
# Preuves Sigstore : bundle keyless produit par release.yml, sinon .sig + certificat.
bundle = by_name.get(f"{artifact['name']}.sigstore.json")
if bundle is not None:
    lines["BUNDLE_NAME"] = bundle.get("name", "")
    lines["BUNDLE_URL"] = bundle.get("browser_download_url", "")
for suffix, key in ((".sig", "SIG_URL"), (".pem", "CERT_URL")):
    proof = by_name.get(f"{artifact['name']}{suffix}")
    if proof is not None:
        lines[f"{key}_NAME"] = proof.get("name", "")
        lines[key] = proof.get("browser_download_url", "")
pub = by_name.get("cosign.pub")
if pub is not None:
    lines["PUB_NAME"] = "cosign.pub"
    lines["PUB_URL"] = pub.get("browser_download_url", "")

for key in ("RELEASE_TAG", "RELEASE_VERSION", "ASSET_KIND", "ASSET_NAME", "ASSET_URL",
            "ASSET_DIGEST", "SUMS_NAME", "SUMS_URL", "BUNDLE_NAME", "BUNDLE_URL",
            "SIG_URL_NAME", "SIG_URL", "CERT_URL_NAME", "CERT_URL", "PUB_NAME", "PUB_URL"):
    print(f"{key}={lines.get(key, '')}")
PY

  local assets_file="${TMP_DIR}/assets.env"
  if ! python3 "${TMP_DIR}/pick_assets.py" "${TMP_DIR}/release.json" \
        "${OS}" "${ARCH}" "${VERSION_TAG#v}" > "${assets_file}"; then
    die "Impossible de sélectionner un artefact dans la release (assets absents ou renommés)." 1
  fi

  # Relecture des paires CLE=valeur (aucune évaluation de code).
  while IFS='=' read -r key value; do
    case "${key}" in
      RELEASE_TAG)     RELEASE_TAG="${value}" ;;
      RELEASE_VERSION) RELEASE_VERSION="${value}" ;;
      ASSET_KIND)      ASSET_KIND="${value}" ;;
      ASSET_NAME)      ASSET_NAME="${value}" ;;
      ASSET_URL)       ASSET_URL="${value}" ;;
      ASSET_DIGEST)    ASSET_DIGEST="${value}" ;;
      SUMS_NAME)       SUMS_NAME="${value}" ;;
      SUMS_URL)        SUMS_URL="${value}" ;;
      BUNDLE_NAME)     BUNDLE_NAME="${value}" ;;
      BUNDLE_URL)      BUNDLE_URL="${value}" ;;
      SIG_URL_NAME)    SIG_URL_NAME="${value}" ;;
      SIG_URL)         SIG_URL="${value}" ;;
      CERT_URL_NAME)   CERT_URL_NAME="${value}" ;;
      CERT_URL)        CERT_URL="${value}" ;;
      PUB_NAME)        PUB_NAME="${value}" ;;
      PUB_URL)         PUB_URL="${value}" ;;
      *) : ;;
    esac
  done < "${assets_file}"

  [[ -n "${ASSET_URL}" ]] || die "La release ne contient aucun artefact téléchargeable." 1
  log_ok "Release ${RELEASE_TAG} — artefact retenu : ${ASSET_NAME} (${ASSET_KIND})"
}

# -----------------------------------------------------------------------------
# 6. Téléchargement et VÉRIFICATION (étape non contournable)
# -----------------------------------------------------------------------------
verify_checksum() {
  local file="$1" expected="" actual=""

  if [[ -n "${SUMS_URL}" ]]; then
    log_info "Contrôle du condensé SHA-256 (manifeste ${SUMS_NAME})…"
    http_get "${SUMS_URL}" "${TMP_DIR}/${SUMS_NAME}" \
      || die "Manifeste de condensés illisible : ${SUMS_NAME}." "${EXIT_VERIFY}"
    expected="$(awk -v target="${ASSET_NAME}" \
      '$2 == target || $2 == "*" target { print tolower($1); exit }' \
      "${TMP_DIR}/${SUMS_NAME}")"
    [[ -n "${expected}" ]] \
      || die "${ASSET_NAME} est absent du manifeste ${SUMS_NAME} : refus d'installer." "${EXIT_VERIFY}"
  elif [[ -n "${ASSET_DIGEST}" ]]; then
    log_info "Contrôle du condensé SHA-256 (digest publié par l'API GitHub)…"
    expected="${ASSET_DIGEST#sha256:}"
    expected="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
  else
    die "Aucun condensé SHA-256 disponible (ni SHA256SUMS, ni digest d'API) : refus d'installer." "${EXIT_VERIFY}"
  fi

  actual="$(sha256_of "${file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    log_error "Condensé SHA-256 INVALIDE pour ${ASSET_NAME}."
    log_step "attendu : ${expected}"
    log_step "obtenu  : ${actual}"
    return 1
  fi
  log_ok "Condensé SHA-256 vérifié : ${actual}"
  return 0
}

verify_signature() {
  local file="$1"

  if [[ -n "${BUNDLE_URL}" ]]; then
    # Signature keyless (Sigstore/Fulcio) : la preuve est le bundle .sigstore.json
    # produit par .github/workflows/release.yml (cosign sign-blob --bundle).
    log_info "Vérification de la signature Sigstore (bundle keyless)…"
    http_get "${BUNDLE_URL}" "${TMP_DIR}/${BUNDLE_NAME}" \
      || die "Bundle de signature illisible : ${BUNDLE_NAME}." "${EXIT_VERIFY}"
    cosign verify-blob \
      --bundle "${TMP_DIR}/${BUNDLE_NAME}" \
      --certificate-identity-regexp "^https://github.com/${REPO}/" \
      --certificate-oidc-issuer "${OIDC_ISSUER}" \
      "${file}" \
      || die "Signature Sigstore invalide : REFUS D'INSTALLER ${ASSET_NAME}." "${EXIT_VERIFY}"
    log_ok "Signature Sigstore vérifiée (identité OIDC du dépôt ${REPO})."
    return 0
  fi

  if [[ -n "${SIG_URL}" && ( -n "${PUB_URL}" || -n "${CERT_URL}" ) ]]; then
    # Signature par clé publiée : la clé doit être vérifiée par un canal
    # indépendant avant d'être utilisée (docs/installation.md §5.3).
    log_info "Vérification de la signature Sigstore (clé publiée)…"
    http_get "${SIG_URL}" "${TMP_DIR}/${SIG_URL_NAME}" \
      || die "Signature illisible : ${SIG_URL_NAME}." "${EXIT_VERIFY}"
    local -a args=(--signature "${TMP_DIR}/${SIG_URL_NAME}")
    if [[ -n "${PUB_URL}" ]]; then
      http_get "${PUB_URL}" "${TMP_DIR}/cosign.pub" \
        || die "Clé publique illisible : cosign.pub." "${EXIT_VERIFY}"
      args+=(--key "${TMP_DIR}/cosign.pub")
    fi
    if [[ -n "${CERT_URL}" ]]; then
      http_get "${CERT_URL}" "${TMP_DIR}/${CERT_URL_NAME}" \
        || die "Certificat illisible : ${CERT_URL_NAME}." "${EXIT_VERIFY}"
      args+=(--certificate "${TMP_DIR}/${CERT_URL_NAME}")
    fi
    log_warn "Vérifiez l'empreinte de cosign.pub par un canal indépendant avant de faire confiance à cette clé."
    cosign verify-blob "${args[@]}" "${file}" \
      || die "Signature Sigstore invalide : REFUS D'INSTALLER ${ASSET_NAME}." "${EXIT_VERIFY}"
    log_ok "Signature Sigstore vérifiée."
    return 0
  fi

  die "Aucune preuve de signature Sigstore dans la release : REFUS D'INSTALLER." "${EXIT_VERIFY}"
}

download_and_verify() {
  local artifact="${TMP_DIR}/${ASSET_NAME}"
  log_info "Téléchargement de ${ASSET_NAME}…"
  http_get "${ASSET_URL}" "${artifact}" \
    || die "Téléchargement impossible : ${ASSET_URL}." 1
  log_ok "Téléchargé : $(basename "${artifact}") ($(wc -c < "${artifact}" | tr -d ' ') octets)"

  local failed=0
  verify_checksum "${artifact}" || failed=1
  verify_signature "${artifact}" || failed=1

  if [[ "${failed}" -ne 0 ]]; then
    # Refus net : on ne laisse pas traîner un artefact non vérifié.
    rm -f "${artifact}"
    log_error "VÉRIFICATION ÉCHOUÉE — AUCUNE INSTALLATION N'A ÉTÉ EFFECTUÉE."
    log_error "Supprimez les fichiers téléchargés, ne réutilisez pas cet artefact,"
    log_error "et signalez l'incident via le canal indiqué dans SECURITY.md."
    exit "${EXIT_VERIFY}"
  fi
  ARTIFACT_PATH="${artifact}"
}

# -----------------------------------------------------------------------------
# 7. Installation de l'artefact
# -----------------------------------------------------------------------------
install_archive() {
  local artifact="$1"
  need_cmd tar "Installez tar pour extraire l'archive de release." || die "tar est requis." 1
  local workdir="${TMP_DIR}/extract"
  mkdir -p "${workdir}"
  run tar -xzf "${artifact}" -C "${workdir}" --no-same-owner

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry find "${workdir}" -maxdepth 3 -type f -name "${SERVICE_NAME}" -o -name "${LEGACY_NAME}"
    log_dry install -o root -g root -m 0755 "<binaire>" "${PREFIX}/bin/${SERVICE_NAME}"
    return 0
  fi

  local binary=""
  while IFS= read -r candidate; do
    binary="${candidate}"
    break
  done < <(find "${workdir}" -maxdepth 4 -type f \
             \( -name "${SERVICE_NAME}" -o -name "${LEGACY_NAME}" \) -print)
  [[ -n "${binary}" ]] || die "Aucun exécutable « ${SERVICE_NAME} » dans l'archive ${ASSET_NAME}." 1

  run install -d -o root -g root -m 0755 "${PREFIX}/bin"
  run install -o root -g root -m 0755 "${binary}" "${PREFIX}/bin/${SERVICE_NAME}"
  run ln -sfn "${SERVICE_NAME}" "${PREFIX}/bin/${LEGACY_NAME}"
  # Licences et notices : conservées à côté de l'installation, jamais modifiées.
  run install -d -o root -g root -m 0755 "${INSTALL_DIR}/share"
  while IFS= read -r doc; do
    run install -o root -g root -m 0644 "${doc}" "${INSTALL_DIR}/share/"
  done < <(find "${workdir}" -maxdepth 2 -type f \( -name 'LICENSE*' -o -name 'NOTICE*' \) -print)
  log_ok "Binaire installé : ${PREFIX}/bin/${SERVICE_NAME}"
}

install_python_dist() {
  local artifact="$1"
  need_cmd python3 "Python 3.11+ est requis pour créer l'environnement virtuel." \
    || die "python3 est requis." 1
  log_info "Création de l'environnement virtuel dans ${VENV_DIR}…"
  run install -d -o root -g root -m 0755 "${INSTALL_DIR}"
  run python3 -m venv "${VENV_DIR}"
  run "${VENV_DIR}/bin/python" -m pip install --upgrade pip

  local -a pip_args=(install)
  if [[ -n "${WHEELHOUSE}" ]]; then
    pip_args=(install --no-index --find-links "${WHEELHOUSE}")
    log_info "Installation hors ligne depuis ${WHEELHOUSE}."
  fi
  run "${VENV_DIR}/bin/python" -m pip "${pip_args[@]}" "${artifact}"
  write_wrapper
}

write_wrapper() {
  # Le renommage thotsecure → thotsecure étant en cours, on installe un lanceur
  # stable qui pointe vers le point d'entrée réellement présent dans le venv.
  local entry=""
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry write "${PREFIX}/bin/${SERVICE_NAME}" "→ ${VENV_DIR}/bin/<thotsecure|thotsecure>"
    return 0
  fi
  local candidate
  for candidate in "${VENV_DIR}/bin/${SERVICE_NAME}" "${VENV_DIR}/bin/${LEGACY_NAME}"; do
    if [[ -x "${candidate}" ]]; then entry="${candidate}"; break; fi
  done
  [[ -n "${entry}" ]] || die "Point d'entrée introuvable dans ${VENV_DIR}/bin." 1

  run install -d -o root -g root -m 0755 "${PREFIX}/bin"
  cat > "${PREFIX}/bin/${SERVICE_NAME}" <<WRAPPER
#!/usr/bin/env bash
# Lanceur généré par ${SCRIPT_NAME} — pointe vers le venv ${VENV_DIR}.
# Modifiez l'environnement dans ${ENV_FILE}, pas ici.
exec "${entry}" "\$@"
WRAPPER
  chmod 0755 "${PREFIX}/bin/${SERVICE_NAME}"
  run ln -sfn "${SERVICE_NAME}" "${PREFIX}/bin/${LEGACY_NAME}"
  log_ok "Commande installée : ${PREFIX}/bin/${SERVICE_NAME} (alias : ${LEGACY_NAME})"
}

install_content() {
  # Contenu déclaratif (règles, politiques, playbooks, cibles) : copié en
  # lecture seule vers /etc/thotsecure. Jamais écrasé sans sauvegarde.
  local src="${CONTENT_DIR}"
  if [[ -z "${src}" ]]; then
    if [[ -n "${SCRIPT_DIR}" && -d "${SCRIPT_DIR}/../rules" ]]; then
      src="${SCRIPT_DIR}/.."
    else
      log_warn "Aucun --content-dir : les règles, politiques et playbooks ne sont pas installés."
      log_warn "Récupérez-les depuis le dépôt (répertoires rules/, policies/, playbooks/)"
      log_warn "ou laissez THOT_RULES_DIR pointer vers votre propre bibliothèque."
      return 0
    fi
  fi
  [[ -d "${src}" ]] || die "--content-dir introuvable : ${src}." 1

  local name
  for name in rules policies playbooks config; do
    if [[ -d "${src}/${name}" ]]; then
      log_step "Copie de ${name}/ vers ${ETC_DIR}/${name}/"
      run install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${ETC_DIR}/${name}"
      # Pas de --delete : on n'efface jamais la configuration de l'exploitant.
      run cp -R "${src}/${name}/." "${ETC_DIR}/${name}/"
      run chown -R root:"${SERVICE_GROUP}" "${ETC_DIR}/${name}"
      run chmod -R u=rwX,g=rX,o= "${ETC_DIR}/${name}"
    fi
  done
}

# -----------------------------------------------------------------------------
# 8. Compte système, répertoires et fichier d'environnement
# -----------------------------------------------------------------------------
ensure_service_account() {
  log_info "Compte de service ${SERVICE_USER} (jamais root)…"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry groupadd --system "${SERVICE_GROUP}"
    log_dry useradd --system --gid "${SERVICE_GROUP}" --home-dir "${DATA_DIR}" \
      --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    return 0
  fi
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    run groupadd --system "${SERVICE_GROUP}"
  else
    log_step "Groupe ${SERVICE_GROUP} déjà présent (inchangé)."
  fi
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    run useradd --system --gid "${SERVICE_GROUP}" --home-dir "${DATA_DIR}" \
      --no-create-home --shell /usr/sbin/nologin \
      --comment "Thot Secure service account" "${SERVICE_USER}"
  else
    log_step "Utilisateur ${SERVICE_USER} déjà présent (inchangé)."
  fi
  log_ok "Compte de service prêt."
}

ensure_directories() {
  log_info "Répertoires de configuration, de données et de journaux…"
  # /etc/thotsecure : lisible par root seul + groupe de service (0750).
  run install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${ETC_DIR}"
  # /var/lib/thotsecure : base SQLite + journal d'audit chaîné (données du client).
  run install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${DATA_DIR}"
  run install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${LOG_DIR}"
  run install -d -o root -g root -m 0755 "${INSTALL_DIR}"
  log_ok "Répertoires créés ou conservés."
}

generate_secret() {
  # 32 octets aléatoires (64 caractères hexadécimaux). Jamais journalisé.
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  fi
}

env_file_has() {
  [[ -f "${ENV_FILE}" ]] && grep -qE "^${1}=.+" "${ENV_FILE}"
}

write_env_file() {
  log_info "Fichier d'environnement ${ENV_FILE} (0600)…"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry write "${ENV_FILE}" "(THOT_SECRET_KEY générée localement, jamais affichée)"
    return 0
  fi

  local secret_key="" bootstrap_key=""
  if env_file_has "THOT_SECRET_KEY"; then
    log_step "THOT_SECRET_KEY existante conservée (jamais réécrite automatiquement)."
  else
    secret_key="$(generate_secret)"
  fi
  if env_file_has "THOT_BOOTSTRAP_API_KEY"; then
    log_step "THOT_BOOTSTRAP_API_KEY existante conservée."
  else
    bootstrap_key="ao_$(generate_secret)"
  fi

  umask 077
  local tmp_env="${TMP_DIR}/thotsecure.env"
  if [[ -f "${ENV_FILE}" ]]; then
    cp -p "${ENV_FILE}" "${tmp_env}"
  else
    : > "${tmp_env}"
    cat >> "${tmp_env}" <<EOF
# =============================================================================
#  Thot Secure — environnement du service (généré par ${SCRIPT_NAME})
#  Fichier protégé : 0600 root:${SERVICE_GROUP}. Ne le versionnez JAMAIS.
#  Il est lu par systemd (EnvironmentFile) avant l'abandon des privilèges.
# =============================================================================
THOT_ENV=prod
THOT_HOST=127.0.0.1
THOT_PORT=8080
THOT_DB_URL=${DB_URL}
THOT_BUS=sqlite
THOT_RULES_DIR=${ETC_DIR}/rules
THOT_POLICIES_DIR=${ETC_DIR}/policies
THOT_PLAYBOOKS_DIR=${ETC_DIR}/playbooks
THOT_TARGETS_FILE=${ETC_DIR}/targets.yaml
THOT_LOG_LEVEL=INFO
THOT_LOG_FORMAT=json
THOT_RETENTION_DAYS=30
# --- SÛRETÉ : valeurs par défaut du projet, NE PAS INVERSER ------------------
# THOT_DRY_RUN=true : aucune action réelle, tout est simulé et journalisé.
# THOT_AUTONOMY=supervised : une action critique exige une approbation humaine.
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised
EOF
  fi

  if [[ -n "${secret_key}" ]]; then
    printf 'THOT_SECRET_KEY=%s\n' "${secret_key}" >> "${tmp_env}"
  fi
  if [[ -n "${bootstrap_key}" ]]; then
    printf 'THOT_BOOTSTRAP_API_KEY=%s\n' "${bootstrap_key}" >> "${tmp_env}"
  fi

  run install -o root -g "${SERVICE_GROUP}" -m 0600 "${tmp_env}" "${ENV_FILE}"
  unset secret_key bootstrap_key
  log_ok "Environnement écrit en 0600 (secrets non affichés)."
}

warn_if_unsafe_defaults() {
  # Le script ne touche pas à ces deux réglages : il avertit s'ils ont été
  # modifiés, quelle que soit l'origine de la modification.
  local dry_run autonomy
  dry_run="$(sed -n 's/^THOT_DRY_RUN=//p' "${ENV_FILE}" 2>/dev/null | tail -n 1)"
  autonomy="$(sed -n 's/^THOT_AUTONOMY=//p' "${ENV_FILE}" 2>/dev/null | tail -n 1)"
  dry_run="${dry_run:-true}"
  autonomy="${autonomy:-supervised}"

  if [[ "${dry_run}" != "true" ]]; then
    log_warn "AVERTISSEMENT : THOT_DRY_RUN=${dry_run} dans ${ENV_FILE}."
    log_warn "Les contre-mesures peuvent désormais MODIFIER des systèmes réels."
    log_warn "Le passage à false doit être une décision écrite et datée, jamais un défaut."
  fi
  if [[ "${autonomy}" != "supervised" && "${autonomy}" != "manual" ]]; then
    log_warn "AVERTISSEMENT : THOT_AUTONOMY=${autonomy} dans ${ENV_FILE}."
    log_warn "Le mode « auto » exécute des actions sans approbation humaine."
    log_warn "Ce script ne recommande ni ne pose cette valeur."
  fi
  if [[ "${dry_run}" == "true" && ( "${autonomy}" == "supervised" || "${autonomy}" == "manual" ) ]]; then
    log_ok "Défauts de sûreté confirmés : dry_run=true, autonomy=${autonomy}."
  fi
}

# -----------------------------------------------------------------------------
# 9. Service systemd et initialisation de la base
# -----------------------------------------------------------------------------
install_service_unit() {
  [[ "${INSTALL_SERVICE}" == "true" ]] || { log_step "--no-service : unité systemd non installée."; return 0; }

  if ! command -v systemctl >/dev/null 2>&1; then
    log_warn "systemd est absent : installez et activez le service manuellement."
    return 0
  fi

  local unit="${UNIT_FILE}"
  if [[ -z "${unit}" && -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/${UNIT_NAME}" ]]; then
    unit="${SCRIPT_DIR}/${UNIT_NAME}"
  fi
  if [[ -z "${unit}" || ! -f "${unit}" ]]; then
    log_warn "Unité systemd introuvable (${UNIT_NAME}) : service non installé."
    log_warn "Récupérez scripts/${UNIT_NAME} dans le dépôt, puis :"
    log_step "install -m 0644 ${UNIT_NAME} /etc/systemd/system/${UNIT_NAME}"
    log_step "systemctl daemon-reload && systemctl enable --now ${SERVICE_NAME}"
    return 0
  fi

  log_info "Installation de l'unité systemd ${UNIT_NAME}…"
  run install -o root -g root -m 0644 "${unit}" "/etc/systemd/system/${UNIT_NAME}"
  run systemctl daemon-reload
  run systemctl enable --now "${SERVICE_NAME}"
  if [[ "${DRY_RUN}" != "true" ]]; then
    systemctl is-active --quiet "${SERVICE_NAME}" \
      && log_ok "Service ${SERVICE_NAME} actif." \
      || log_warn "Le service ${SERVICE_NAME} n'est pas encore actif : consultez « journalctl -u ${SERVICE_NAME} »."
  fi
}

init_database() {
  [[ "${INIT_DB}" == "true" ]] || { log_step "--no-init-db : initialisation ignorée."; return 0; }

  local cli=""
  if [[ "${ASSET_KIND}" == "archive" ]]; then
    cli="${PREFIX}/bin/${SERVICE_NAME}"
  else
    cli="${VENV_DIR}/bin/${SERVICE_NAME}"
    [[ -x "${cli}" ]] || cli="${VENV_DIR}/bin/${LEGACY_NAME}"
  fi

  log_info "Initialisation de la base SQLite…"
  # La CLI est exécutée en tant que compte de service : la base et le journal
  # d'audit lui appartiennent. THOT_SECRET_KEY n'est délibérément PAS passée
  # en argument (elle serait visible dans « ps ») : init-db n'en a pas besoin.
  local -a as_user=()
  if [[ "${EUID}" -eq 0 && "${DRY_RUN}" != "true" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      as_user=(runuser -u "${SERVICE_USER}" --)
    elif command -v sudo >/dev/null 2>&1; then
      as_user=(sudo -u "${SERVICE_USER}" --)
    else
      log_warn "runuser/sudo indisponible : init-db sera exécuté en root."
    fi
  fi

  local -a env_args=(
    "THOT_ENV=prod"
    "THOT_DB_URL=${DB_URL}"
    "THOT_RULES_DIR=${ETC_DIR}/rules"
    "THOT_POLICIES_DIR=${ETC_DIR}/policies"
    "THOT_PLAYBOOKS_DIR=${ETC_DIR}/playbooks"
    "THOT_DRY_RUN=true"
    "THOT_AUTONOMY=supervised"
  )
  run "${as_user[@]+"${as_user[@]}"}" env "${env_args[@]}" "${cli}" init-db \
    || log_warn "init-db a échoué : relancez-le après avoir vérifié ${ENV_FILE} et les droits de ${DATA_DIR}."
  log_ok "Base initialisée (ou déjà à jour)."
}

# -----------------------------------------------------------------------------
# 10. Étapes suivantes
# -----------------------------------------------------------------------------
print_next_steps() {
  local bootstrap_hint="sudo grep '^THOT_BOOTSTRAP_API_KEY=' ${ENV_FILE}"
  cat <<EOF

${C_BOLD}Installation terminée.${C_RESET}

${C_BOLD}1. Diagnostic de l'installation${C_RESET}
    sudo -u ${SERVICE_USER} ${PREFIX}/bin/${SERVICE_NAME} doctor
    (ou, si le service est actif : systemctl status ${SERVICE_NAME} ; journalctl -u ${SERVICE_NAME} -f)

${C_BOLD}2. Créer un tenant${C_RESET}
    sudo -u ${SERVICE_USER} ${PREFIX}/bin/${SERVICE_NAME} tenant create --id acme --name "ACME SAS" --mode supervised

${C_BOLD}3. Créer une clé API (affichée UNE SEULE FOIS)${C_RESET}
    sudo -u ${SERVICE_USER} ${PREFIX}/bin/${SERVICE_NAME} key create --tenant acme --role responder --label ci

${C_BOLD}4. Console et API${C_RESET}
    http://127.0.0.1:8080/            console embarquée (aucun build Node)
    http://127.0.0.1:8080/healthz     sonde de vie  ;  /readyz : DB + bus + règles
    Clé d'amorçage (à changer, puis à révoquer) :
      ${bootstrap_hint}

${C_BOLD}SÛRETÉ — à ne pas perdre de vue${C_RESET}
    * Thot Secure est STRICTEMENT DÉFENSIF : aucune capacité offensive, jamais.
    * THOT_DRY_RUN=true et THOT_AUTONOMY=supervised restent les valeurs
      par défaut de ${ENV_FILE}. Ce script ne les a pas inversées.
    * Toute action réelle est réversible et journalisée dans une chaîne d'audit
      chaînée par hash : vérifiez-la avec « ${SERVICE_NAME} audit verify ».
    * Secrets : uniquement dans ${ENV_FILE} (0600). Ne les mettez jamais dans un
      dépôt Git, une ligne de commande ou un ticket.

${C_DIM}Prochaines lectures : docs/installation.md, docs/configuration.md,
docs/operations/deployment.md, et SECURITY.md (canal de signalement).${C_RESET}
EOF
}

# -----------------------------------------------------------------------------
# 11. Point d'entrée
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter en root : un « curl | bash » exécute du code distant."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "MODE --dry-run : le système ne sera pas modifié (téléchargement et vérification en répertoire temporaire)."
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/thotsecure-install.XXXXXX")"
  # shellcheck disable=SC2064  # expansion volontaire à la définition du piège
  trap "rm -rf '${TMP_DIR}'" EXIT

  require_root
  check_prerequisites
  detect_platform
  fetch_release
  download_and_verify

  log_info "Plan d'installation :"
  log_step "artefact    : ${ASSET_NAME} (${ASSET_KIND})"
  log_step "version     : ${RELEASE_VERSION} (${RELEASE_TAG})"
  log_step "binaire     : ${PREFIX}/bin/${SERVICE_NAME} (+ alias ${LEGACY_NAME})"
  log_step "environnement : ${ENV_FILE} (0600, secrets générés localement)"
  log_step "données     : ${DATA_DIR} (utilisateur ${SERVICE_USER})"
  log_step "service     : ${UNIT_NAME} (systemd, durci)"

  case "${ASSET_KIND}" in
    archive) install_archive "${ARTIFACT_PATH}" ;;
    wheel|sdist) install_python_dist "${ARTIFACT_PATH}" ;;
    *) die "Type d'artefact non géré : ${ASSET_KIND}." 1 ;;
  esac

  ensure_service_account
  ensure_directories
  write_env_file
  install_content
  warn_if_unsafe_defaults
  install_service_unit
  init_database
  print_next_steps

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : aucune modification n'a été appliquée."
  fi
}

# Répertoire du script : vide quand le script est fourni sur l'entrée standard
# (« curl … | bash »), auquel cas on retombe sur le répertoire courant.
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && "${BASH_SOURCE[0]}" != "-" ]]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
fi

main "$@"
