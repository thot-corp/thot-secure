#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/audit-export.sh
# -----------------------------------------------------------------------------
#  Export périodique du JOURNAL D'AUDIT CHAÎNÉ vers un SIEM ou un disque hors ligne.
#
#  Source de données : l'API REST du produit (contrat §4.7)
#      GET /api/v1/audit/export?format=cef|jsonl     en-tête X-API-Key
#  Aucun accès direct à la base n'est fait ici : l'export passe par l'API, donc
#  par les mêmes contrôles d'autorisation et d'isolation de tenant que le reste
#  du produit.
#
#  Ce que fait ce script, dans l'ordre :
#    1. VÉRIFIE LA CHAÎNE D'AUDIT AVANT D'EXPORTER (CLI « thotsecure audit verify »,
#       sinon GET /api/v1/audit/verify) : on n'exporte jamais un journal douteux
#       en silence. Chaîne rompue → sortie 3, sauf --allow-broken-chain, qui
#       exporte alors sous un nom .SUSPECT et le dit très fort ;
#    2. récupère l'export par l'API, en écrivant dans un fichier temporaire ;
#    3. contrôle le résultat : fichier non vide, et chaque ligne JSONL analysable
#       (une réponse d'erreur HTML collée dans un export SIEM est un piège réel) ;
#    4. horodate l'archive (nom + fiche .meta) et écrit un condensé SHA-256 ;
#    5. applique la rotation (--keep, défaut 30) : la suppression est listée puis
#       confirmée (--yes pour l'automatisation planifiée) ;
#    6. affiche comment brancher un collecteur de fichiers (Vector, Filebeat,
#       rsyslog) — ce script NE pousse RIEN sur le réseau lui-même : il n'a jamais
#       à connaître les identifiants de votre SIEM, et c'est voulu.
#
#  SECRETS
#    La clé API n'est JAMAIS acceptée en argument de ligne de commande (elle
#    apparaîtrait dans « ps » et dans l'historique du shell). Elle est lue :
#      * dans --api-key-file <fichier> (0600), ou
#      * dans la variable d'environnement THOT_API_KEY, ou
#      * à défaut, dans THOT_BOOTSTRAP_API_KEY de /etc/thotsecure/thotsecure.env
#        (clé d'amorçage : DÉCONSEILLÉ en production, un avertissement le rappelle).
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    Ce script ne modifie JAMAIS THOT_DRY_RUN ni THOT_AUTONOMY, n'exécute aucune
#    contre-mesure et ne contacte que l'API locale du produit.
#
#  Codes de sortie (contrat §8) : 0 succès, 1 erreur, 2 usage,
#  3 vérification négative (chaîne d'audit rompue ou export non conforme).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation (mêmes conventions qu'install.sh)
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="audit-export.sh"
readonly SCRIPT_VERSION="0.1.0"

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

log_dry() {
  printf '    %s[dry-run]%s' "${C_DIM}" "${C_RESET}"
  printf ' %q' "$@"
  printf '\n'
}

run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry "$@"
    return 0
  fi
  "$@"
}

die() {
  local message="$1"
  local code="${2:-1}"
  log_error "${message}"
  exit "${code}"
}

on_error() {
  log_error "Échec de ${SCRIPT_NAME} à la ligne ${1} (code ${2})."
  log_error "Aucun export partiel n'a été conservé : les exports sont écrits dans un"
  log_error "fichier temporaire puis renommés seulement après contrôle."
  exit "${2}"
}
trap 'on_error "${LINENO}" "$?"' ERR

# -----------------------------------------------------------------------------
# 2. Constantes (miroir de deploy/ansible/roles/thotsecure/defaults/main.yml)
# -----------------------------------------------------------------------------
readonly SERVICE_NAME="thotsecure"
readonly SERVICE_USER="thotsecure"
readonly ETC_DIR="/etc/thotsecure"
readonly INSTALL_DIR="/opt/thotsecure"
readonly VENV_DIR="${INSTALL_DIR}/venv"
readonly ENV_FILE="${ETC_DIR}/thotsecure.env"
readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3
readonly DEFAULT_KEEP=30
readonly DEFAULT_TIMEOUT=30

# -----------------------------------------------------------------------------
# 3. Options
# -----------------------------------------------------------------------------
DRY_RUN="false"
ASSUME_YES="false"
TENANT=""
FORMAT="jsonl"
OUT_DIR="${THOT_AUDIT_EXPORT_DIR:-/var/backups/thotsecure/audit}"
API_URL="${THOT_API_URL:-http://127.0.0.1:8080}"
API_KEY_FILE=""
TIMEOUT="${DEFAULT_TIMEOUT}"
KEEP="${THOT_AUDIT_EXPORT_KEEP:-${DEFAULT_KEEP}}"
VERIFY_CHAIN="true"
ALLOW_BROKEN_CHAIN="false"
SYNC_AFTER="false"
CLI_BIN=""
CHAIN_STATUS="inconnu"     # ok | broken | unverified | unchecked
API_KEY=""
TMP_DIR=""
EXPORT_FILE=""

usage() {
  cat <<'AIDE'
Thot Secure — export du journal d'audit vers un SIEM ou un disque hors ligne.

USAGE
    sudo scripts/audit-export.sh --tenant <id> [options]

OPTIONS
    --tenant <id>          Tenant à exporter (obligatoire : le nom sert aussi au
                           fichier et à la vérification de la chaîne).
    --format <cef|jsonl>   Format d'export (défaut : jsonl).
                             jsonl : une ligne JSON par enregistrement d'audit
                             cef   : format ArcSight CEF, pour les SIEM classiques
    --out <dir>            Répertoire de destination (défaut : /var/backups/thotsecure/audit,
                           surchargeable par THOT_AUDIT_EXPORT_DIR). Peut pointer
                           vers un disque amovible monté : c'est l'usage « hors ligne ».
    --api-url <url>        Base de l'API (défaut : http://127.0.0.1:8080,
                           surchargeable par THOT_API_URL).
    --api-key-file <fichier>  Fichier (0600) contenant la clé API sur une seule
                           ligne. À préférer en production.
                           Alternative : variable d'environnement THOT_API_KEY.
                           La clé n'est JAMAIS acceptée en argument de commande.
    --timeout <s>          Délai réseau maximal (défaut : 30 s).
    --keep <N>             Nombre d'exports conservés par (tenant, format)
                           (défaut : 30 ; 0 = illimité).
    --no-verify            Ne pas vérifier la chaîne d'audit avant export
                           (DÉCONSEILLÉ : l'export ne serait pas une preuve).
    --allow-broken-chain   Exporter MALGRÉ une chaîne rompue, sous un nom
                           « .SUSPECT », et sortir en code 3. L'export reste
                           possible pour l'analyse, mais jamais discret.
    --sync                 Appeler « sync » après écriture (utile pour un disque
                           amovible que l'on veut pouvoir retirer aussitôt).
    --cli <chemin>         Binaire de la CLI (défaut : détection automatique).
    --yes                  Ne poser aucune question (exports planifiés).
    --dry-run              Afficher les opérations sans rien exporter ni supprimer.
    -h, --help             Afficher cette aide.

CODES DE SORTIE
    0 réussite · 1 erreur · 2 usage · 3 vérification négative
    (chaîne d'audit rompue, ou export non conforme).

SÛRETÉ
    * La chaîne d'audit est vérifiée AVANT l'export. Un journal dont la chaîne de
      hash est rompue signale une falsification : c'est un incident (SECURITY.md),
      pas un détail d'exploitation.
    * Aucune clé n'est passée en argument de ligne de commande, et aucun identifiant
      de SIEM n'est stocké ici : le transfert est confié à un collecteur de
      fichiers côté SIEM.
    * Thot Secure est strictement défensif ; lisez ce script avant de l'exécuter
      en root.

EXEMPLES
    sudo scripts/audit-export.sh --tenant acme --format cef --out /var/backups/thotsecure/audit
    sudo scripts/audit-export.sh --tenant acme --out /mnt/coffre/audit --sync --yes
    THOT_API_KEY="$(sudo grep '^THOT_BOOTSTRAP_API_KEY=' /etc/thotsecure/thotsecure.env | cut -d= -f2)" \\
        scripts/audit-export.sh --tenant demo --dry-run
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tenant)
        [[ $# -ge 2 ]] || die "--tenant exige un identifiant." "${EXIT_USAGE}"
        TENANT="$2"; shift 2 ;;
      --format)
        [[ $# -ge 2 ]] || die "--format exige cef ou jsonl." "${EXIT_USAGE}"
        FORMAT="$2"; shift 2 ;;
      --out)
        [[ $# -ge 2 ]] || die "--out exige un répertoire." "${EXIT_USAGE}"
        OUT_DIR="$2"; shift 2 ;;
      --api-url)
        [[ $# -ge 2 ]] || die "--api-url exige une URL." "${EXIT_USAGE}"
        API_URL="$2"; shift 2 ;;
      --api-key-file)
        [[ $# -ge 2 ]] || die "--api-key-file exige un chemin." "${EXIT_USAGE}"
        API_KEY_FILE="$2"; shift 2 ;;
      --timeout)
        [[ $# -ge 2 ]] || die "--timeout exige un nombre de secondes." "${EXIT_USAGE}"
        TIMEOUT="$2"; shift 2 ;;
      --keep)
        [[ $# -ge 2 ]] || die "--keep exige un nombre." "${EXIT_USAGE}"
        KEEP="$2"; shift 2 ;;
      --no-verify)          VERIFY_CHAIN="false"; shift ;;
      --allow-broken-chain) ALLOW_BROKEN_CHAIN="true"; shift ;;
      --sync)               SYNC_AFTER="true"; shift ;;
      --cli)
        [[ $# -ge 2 ]] || die "--cli exige un chemin." "${EXIT_USAGE}"
        CLI_BIN="$2"; shift 2 ;;
      --yes)     ASSUME_YES="true"; shift ;;
      --dry-run) DRY_RUN="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  [[ -n "${TENANT}" ]] || die "--tenant est obligatoire (nom du fichier et vérification de la chaîne)." "${EXIT_USAGE}"
  case "${FORMAT}" in
    cef|jsonl) : ;;
    *) die "--format attend cef ou jsonl (reçu : ${FORMAT})." "${EXIT_USAGE}" ;;
  esac
  [[ "${TENANT}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "--tenant accepte lettres, chiffres, point, tiret et souligné (reçu : ${TENANT})." "${EXIT_USAGE}"
  if [[ ! "${KEEP}" =~ ^[0-9]+$ ]]; then
    die "--keep attend un entier positif ou nul." "${EXIT_USAGE}"
  fi
  if [[ ! "${TIMEOUT}" =~ ^[0-9]+$ ]]; then
    die "--timeout attend un entier (secondes)." "${EXIT_USAGE}"
  fi
}

# -----------------------------------------------------------------------------
# 4. Prérequis, confirmation, CLI
# -----------------------------------------------------------------------------
need_cmd() {
  local cmd="$1" hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Commande requise absente : ${cmd}"
    log_step "${hint}"
    return 1
  fi
  return 0
}

check_prerequisites() {
  # python3 assure le transport HTTP : la clé API n'apparaît alors jamais dans la
  # ligne de commande (contrairement à un « curl -H "X-API-Key: …" »).
  need_cmd python3 "Python 3.11+ est requis (transport HTTP et contrôle de l'export)." \
    || die "python3 est requis." 1
  if ! command -v sha256sum >/dev/null 2>&1 \
     && ! command -v shasum >/dev/null 2>&1 \
     && ! command -v openssl >/dev/null 2>&1; then
    die "Aucun outil SHA-256 disponible (sha256sum, shasum ou openssl)." 1
  fi
}

sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print tolower($1)}'
  else
    openssl dgst -sha256 "${file}" | awk '{print tolower($NF)}'
  fi
}

ensure_private_dir() {
  # ensure_private_dir <répertoire> [mode]
  # Crée un répertoire privé : un export d'audit contient des acteurs, des cibles
  # et des décisions — il ne doit pas être lisible par d'autres comptes.
  local dir="$1" mode="${2:-0700}"
  if [[ -d "${dir}" ]]; then
    return 0
  fi
  if [[ "${EUID}" -eq 0 ]]; then
    run install -d -o root -g root -m "${mode}" "${dir}"
  else
    # Cas du disque amovible monté par l'exploitant : on ne peut pas changer le
    # propriétaire, on se contente donc de restreindre les droits.
    log_warn "Exécution sans root : ${dir} sera créé avec les droits de $(id -un)."
    log_step "Vérifiez les droits du support avant d'y déposer un journal d'audit."
    run mkdir -p "${dir}"
    run chmod "${mode}" "${dir}"
  fi
}

confirm() {
  local prompt="$1"
  if [[ "${ASSUME_YES}" == "true" ]]; then
    log_warn "${prompt} → confirmé par --yes."
    return 0
  fi
  if [[ ! -t 0 ]]; then
    log_error "${prompt} : aucune confirmation possible (entrée non interactive)."
    log_step "Relancez avec --yes si l'opération est réellement voulue."
    return 1
  fi
  local answer=""
  printf '%s [oui/non] ' "${prompt}"
  read -r answer || true
  case "${answer}" in
    oui|OUI|o|O|yes|YES|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

run_as_service() {
  if [[ "${EUID}" -eq 0 ]] && id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "${SERVICE_USER}" -- "$@"
      return $?
    elif command -v sudo >/dev/null 2>&1; then
      sudo -n -u "${SERVICE_USER}" -- "$@"
      return $?
    fi
  fi
  "$@"
}

resolve_cli() {
  if [[ -n "${CLI_BIN}" ]]; then
    [[ -x "${CLI_BIN}" ]] || die "CLI introuvable ou non exécutable : ${CLI_BIN}." 1
    printf '%s\n' "${CLI_BIN}"
    return 0
  fi
  local candidate
  for candidate in "${VENV_DIR}/bin/${SERVICE_NAME}" "/usr/local/bin/${SERVICE_NAME}"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  candidate="$(command -v "${SERVICE_NAME}" 2>/dev/null || true)"
  [[ -n "${candidate}" ]] || return 1
  printf '%s\n' "${candidate}"
}

# -----------------------------------------------------------------------------
# 5. Clé API (jamais en argument de ligne de commande)
# -----------------------------------------------------------------------------
resolve_api_key() {
  # Publie la clé dans la variable globale API_KEY (jamais sur la sortie standard :
  # un « api_key="$(resolve_api_key)" » la ferait passer par une capture de
  # commande, où le moindre message lisible se mélangerait à la clé).
  if [[ -n "${API_KEY_FILE}" ]]; then
    [[ -r "${API_KEY_FILE}" ]] || die "Fichier de clé API illisible : ${API_KEY_FILE}." 1
    local mode=""
    mode="$(stat -c '%a' "${API_KEY_FILE}" 2>/dev/null || stat -f '%Lp' "${API_KEY_FILE}" 2>/dev/null || true)"
    if [[ "${mode}" != "600" ]]; then
      log_warn "Le fichier de clé ${API_KEY_FILE} n'est pas en 0600 (mode ${mode:-inconnu})."
      log_step "Remédiation : chmod 600 ${API_KEY_FILE}"
    fi
    API_KEY="$(tr -d '\r\n' < "${API_KEY_FILE}")"
    return 0
  fi

  if [[ -n "${THOT_API_KEY:-}" ]]; then
    API_KEY="${THOT_API_KEY}"
    return 0
  fi

  # Dernier recours : clé d'amorçage du fichier d'environnement du service.
  if [[ -r "${ENV_FILE}" ]]; then
    local bootstrap=""
    bootstrap="$(sed -n 's/^THOT_BOOTSTRAP_API_KEY=//p' "${ENV_FILE}" | tail -n 1)"
    if [[ -n "${bootstrap}" ]]; then
      log_warn "Clé d'amorçage utilisée (THOT_BOOTSTRAP_API_KEY de ${ENV_FILE})."
      log_step "Créez une clé dédiée en lecture d'audit : thotsecure key create --tenant ${TENANT} --role analyst --label siem"
      API_KEY="${bootstrap}"
      return 0
    fi
  fi

  die "Aucune clé API disponible : utilisez --api-key-file <fichier 0600> ou la variable THOT_API_KEY." 1
}

# -----------------------------------------------------------------------------
# 6. Vérification PRÉALABLE de la chaîne d'audit
# -----------------------------------------------------------------------------
verify_chain_via_cli() {
  local cli=""
  cli="$(resolve_cli)" || return 2
  local -a args=(audit verify --tenant "${TENANT}")
  local output_file="${TMP_DIR}/audit-verify.out"
  local rc=0
  set +e
  run_as_service "${cli}" "${args[@]}" > "${output_file}" 2>&1
  rc=$?
  set -e
  case "${rc}" in
    0) log_step "$(tail -n 1 "${output_file}" 2>/dev/null || true)"; return 0 ;;
    3) while IFS= read -r line; do log_step "${line}"; done < "${output_file}"; return 1 ;;
    *) return 2 ;;
  esac
}

verify_chain_via_api() {
  # GET /api/v1/audit/verify — repli si la CLI n'est pas installée sur cet hôte.
  local key="$1"
  THOT_EXPORT_API_KEY="${key}" python3 - "${API_URL}" "${TIMEOUT}" <<'PY'
"""Interroge GET /api/v1/audit/verify et conclut sur l'intégrité de la chaîne."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

base, timeout = sys.argv[1], float(sys.argv[2])
url = f"{base.rstrip('/')}/api/v1/audit/verify"
request = urllib.request.Request(
    url, headers={"X-API-Key": os.environ.get("THOT_EXPORT_API_KEY", "")}
)
try:
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL locale
        payload = json.loads(response.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as exc:
    print(f"HTTP {exc.code} : {exc.read(200).decode('utf-8', 'replace')}", file=sys.stderr)
    raise SystemExit(2)
except (urllib.error.URLError, OSError, ValueError) as exc:
    print(f"API injoignable : {exc}", file=sys.stderr)
    raise SystemExit(2)

if payload.get("valid"):
    print(f"chaîne intègre : {payload.get('records', '?')} enregistrement(s)")
    raise SystemExit(0)
print(
    f"chaîne ROMPUE au seq {payload.get('broken_at')} : {payload.get('reason', 'sans détail')}"
)
raise SystemExit(1)
PY
}

verify_chain() {
  local key="$1" rc=0
  if [[ "${VERIFY_CHAIN}" != "true" ]]; then
    log_warn "Vérification de la chaîne désactivée (--no-verify) : l'export ne prouve rien."
    log_warn "Consignez cette décision : un export d'audit non vérifié reste un export."
    CHAIN_STATUS="unchecked"
    return 0
  fi

  log_info "Vérification de la chaîne d'audit du tenant « ${TENANT} »…"
  set +e
  verify_chain_via_cli
  rc=$?
  set -e
  if [[ "${rc}" -eq 2 ]]; then
    log_step "CLI indisponible : repli sur l'API ${API_URL}/api/v1/audit/verify"
    set +e
    verify_chain_via_api "${key}"
    rc=$?
    set -e
  fi

  case "${rc}" in
    0)
      log_ok "Chaîne d'audit intègre."
      CHAIN_STATUS="ok"
      ;;
    1)
      CHAIN_STATUS="broken"
      printf '\n' >&2
      log_error "==================================================================="
      log_error " CHAÎNE D'AUDIT ROMPUE — EXPORT D'UN JOURNAL FALSIFIÉ"
      log_error "==================================================================="
      log_error "La chaîne de hash ne vérifie pas : des enregistrements ont été"
      log_error "modifiés, supprimés, insérés ou rejoués après coup."
      log_step "1. Traitez cela comme un INCIDENT DE SÉCURITÉ (SECURITY.md)."
      log_step "2. Préservez la base, ses sauvegardes et les journaux système."
      log_step "3. N'effacez rien, ne « reconstruisez » pas la chaîne d'audit."
      log_step "4. Exportez uniquement pour analyse, avec --allow-broken-chain"
      log_step "   (le fichier portera alors le suffixe .SUSPECT)."
      printf '\n' >&2
      if [[ "${ALLOW_BROKEN_CHAIN}" != "true" ]]; then
        die "Export REFUSÉ : la chaîne d'audit est rompue (utilisez --allow-broken-chain pour exporter malgré tout)." "${EXIT_VERIFY}"
      fi
      log_warn "--allow-broken-chain : l'export sera marqué .SUSPECT."
      ;;
    *)
      CHAIN_STATUS="unverified"
      log_warn "Impossible de vérifier la chaîne d'audit (CLI absente et API injoignable)."
      log_warn "L'export sera produit et marqué .UNVERIFIED : ne le présentez pas comme une preuve."
      if [[ "${ALLOW_BROKEN_CHAIN}" != "true" ]]; then
        if ! confirm "Exporter un journal dont la chaîne n'a PAS pu être vérifiée ?"; then
          die "Export annulé : chaîne d'audit non vérifiée." "${EXIT_VERIFY}"
        fi
      fi
      ;;
  esac
}

# -----------------------------------------------------------------------------
# 7. Récupération de l'export via l'API
# -----------------------------------------------------------------------------
fetch_export() {
  # fetch_export <clé_api> <fichier_temporaire>
  local key="$1" target="$2"
  local url="${API_URL%/}/api/v1/audit/export?format=${FORMAT}"
  log_info "Récupération de l'export (${FORMAT}) sur ${url}…"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry python3 "<GET ${url} avec en-tête X-API-Key (clé non affichée)>" "${target}"
    return 0
  fi

  # La clé est transmise par l'ENVIRONNEMENT du processus enfant : elle
  # n'apparaît donc pas dans « ps », seulement dans /proc/<pid>/environ,
  # lisible par le même utilisateur (ou root).
  THOT_EXPORT_API_KEY="${key}" python3 - "${url}" "${target}" "${TIMEOUT}" <<'PY'
"""Télécharge l'export d'audit vers un fichier temporaire (aucune clé en argv)."""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

url, target, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
request = urllib.request.Request(
    url,
    headers={
        "X-API-Key": os.environ.get("THOT_EXPORT_API_KEY", ""),
        "Accept": "application/x-ndjson, application/json, text/plain;q=0.9, */*;q=0.5",
        "User-Agent": "thotsecure-audit-export/0.1.0",
    },
)
try:
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL locale
        status = response.status
        payload = response.read()
except urllib.error.HTTPError as exc:
    detail = exc.read(300).decode("utf-8", "replace")
    raise SystemExit(f"HTTP {exc.code} : {detail}")
except (urllib.error.URLError, OSError) as exc:
    raise SystemExit(f"API injoignable ({url}) : {exc}")

if status != 200:
    raise SystemExit(f"réponse inattendue : HTTP {status}")

with open(target, "wb") as handle:
    handle.write(payload)
print(len(payload))
PY
}

validate_export() {
  # validate_export <fichier> : non vide, et (en jsonl) chaque ligne analysable.
  local file="$1"
  [[ -s "${file}" ]] || die "Export vide : l'API a répondu sans contenu (droits insuffisants, tenant vide ou erreur masquée)." "${EXIT_VERIFY}"

  if [[ "${FORMAT}" != "jsonl" ]]; then
    log_ok "Export reçu : $(wc -c < "${file}" | tr -d ' ') octets (format ${FORMAT} : contrôle ligne à ligne non applicable)."
    return 0
  fi

  local rc=0 count=""
  set +e
  count="$(python3 - "${file}" <<'PY'
"""Contrôle qu'un export JSONL ne contient que des objets JSON valides."""
from __future__ import annotations

import json
import sys

path = sys.argv[1]
total = 0
with open(path, encoding="utf-8") as handle:
    for number, line in enumerate(handle, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        total += 1
        try:
            json.loads(stripped)
        except ValueError as exc:
            raise SystemExit(f"ligne {number} : JSON invalide ({exc})")
        if total == 1 and stripped.lstrip().startswith("<"):
            raise SystemExit("le contenu ressemble à du HTML : ce n'est pas un export JSONL")
print(total)
PY
)"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    die "Export NON CONFORME (le fichier n'est pas un JSONL valide) : il n'a pas été conservé." "${EXIT_VERIFY}"
  fi
  log_ok "Export JSONL conforme : ${count} enregistrement(s) analysable(s)."
  return 0
}

# -----------------------------------------------------------------------------
# 8. Scellés, horodatage et rotation
# -----------------------------------------------------------------------------
finalize_export() {
  # finalize_export <fichier_temporaire> → écrit le chemin final dans EXPORT_FILE
  local temp="$1"
  local stamp="" base="" suffix=""
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"

  case "${CHAIN_STATUS}" in
    broken)     suffix=".SUSPECT" ;;
    unverified) suffix=".UNVERIFIED" ;;
    *)          suffix="" ;;
  esac

  base="${OUT_DIR}/thotsecure-audit-${TENANT}-${stamp}.${FORMAT}${suffix}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry mv -f "${temp}" "${base}"
    log_dry write "${base}.sha256" "${base}.meta"
    EXPORT_FILE="${base}"
    return 0
  fi

  mv -f "${temp}" "${base}"
  chmod 0600 "${base}"

  local digest="" records=""
  digest="$(sha256_of "${base}")"
  records="$(wc -l < "${base}" | tr -d ' ')"
  printf '%s  %s\n' "${digest}" "$(basename "${base}")" > "${base}.sha256"
  chmod 0600 "${base}.sha256"

  {
    printf 'export=%s\n' "$(basename "${base}")"
    printf 'sha256=%s\n' "${digest}"
    printf 'tenant=%s\n' "${TENANT}"
    printf 'format=%s\n' "${FORMAT}"
    printf 'records_lignes=%s\n' "${records}"
    printf 'bytes=%s\n' "$(wc -c < "${base}" | tr -d ' ')"
    printf 'exported_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'api_url=%s\n' "${API_URL}"
    printf 'audit_chain=%s\n' "${CHAIN_STATUS}"
    printf 'host=%s\n' "$(hostname 2>/dev/null || printf 'inconnu')"
    printf 'script_version=%s\n' "${SCRIPT_VERSION}"
    printf "# Fiche d'export d'audit Thot Secure. Aucun secret, aucune clé API.\n"
  } > "${base}.meta"
  chmod 0600 "${base}.meta"

  log_ok "Export écrit : ${base} (${records} ligne(s))"
  log_ok "Scellés : $(basename "${base}").sha256, $(basename "${base}").meta"
  EXPORT_FILE="${base}"

  if [[ "${SYNC_AFTER}" == "true" ]]; then
    sync
    log_ok "« sync » exécuté : le disque peut être retiré sans perte de données."
  fi
}

rotate_exports() {
  if [[ "${KEEP}" == "0" ]]; then
    log_step "Rotation illimitée (--keep 0) : aucun export supprimé."
    return 0
  fi

  local -a all=()
  local line=""
  while IFS= read -r line; do
    [[ -n "${line}" ]] && all+=("${line}")
  done < <(find "${OUT_DIR}" -maxdepth 1 -type f \
             -name "thotsecure-audit-${TENANT}-*.${FORMAT}*" \
             ! -name '*.sha256' ! -name '*.meta' -print 2>/dev/null \
           | LC_ALL=C sort -r || true)

  local total="${#all[@]}"
  if [[ "${total}" -le "${KEEP}" ]]; then
    log_ok "Rotation : ${total} export(s) pour une limite de ${KEEP} — rien à supprimer."
    return 0
  fi

  local -a doomed=()
  local index=0
  for (( index = KEEP; index < total; index++ )); do
    doomed+=("${all[index]}")
  done

  log_warn "Rotation : ${#doomed[@]} export(s) au-delà de la limite de ${KEEP} :"
  local file=""
  for file in "${doomed[@]}"; do
    log_step "$(basename "${file}")"
  done

  if [[ "${DRY_RUN}" == "true" ]]; then
    for file in "${doomed[@]}"; do
      log_dry rm -f "${file}" "${file}.sha256" "${file}.meta"
    done
    return 0
  fi

  if ! confirm "Supprimer DÉFINITIVEMENT ces ${#doomed[@]} export(s) (et leurs scellés) ?"; then
    log_warn "Rotation annulée : tous les exports sont conservés."
    return 0
  fi
  for file in "${doomed[@]}"; do
    run rm -f "${file}" "${file}.sha256" "${file}.meta"
    log_step "Supprimé : $(basename "${file}")"
  done
  log_ok "Rotation terminée : ${KEEP} export(s) conservé(s)."
}

# -----------------------------------------------------------------------------
# 9. Intégration SIEM et disque hors ligne (documentation opérationnelle)
# -----------------------------------------------------------------------------
print_siem_hints() {
  cat <<EOF

${C_BOLD}Brancher un SIEM${C_RESET} — ce script n'ouvre AUCUNE connexion vers votre SIEM :
    il dépose des fichiers, et c'est le collecteur du SIEM qui les transporte.
    C'est volontaire : aucun identifiant de SIEM n'a besoin d'exister sur cet hôte.

    Vector (recommandé, léger) :
        [sources.thotsecure_audit]
        type = "file"
        include = ["${OUT_DIR}/thotsecure-audit-*.${FORMAT}"]
        read_from = "beginning"
        [sinks.siem]
        type = "http"        # ou "elasticsearch", "splunk_hec", "syslog"…
        inputs = ["thotsecure_audit"]
        # les identifiants du SIEM vivent dans la configuration du SIEM, pas ici

    Filebeat :
        filebeat.inputs:
          - type: filestream
            paths: ["${OUT_DIR}/thotsecure-audit-*.${FORMAT}"]

    rsyslog (envoi syslog) :
        module(load="imfile")
        input(type="imfile" File="${OUT_DIR}/thotsecure-audit-*.${FORMAT}" Tag="thotsecure-audit")

${C_BOLD}Disque hors ligne${C_RESET}
    Montez le support, ciblez-le avec --out, ajoutez --sync, démontez proprement :
        sudo mount /dev/sdX1 /mnt/coffre
        sudo scripts/audit-export.sh --tenant ${TENANT} --out /mnt/coffre/audit --sync --yes
        sudo umount /mnt/coffre
    Vérifiez ensuite le condensé sur un autre poste : le scellé .sha256 accompagne
    chaque export et permet de détecter une altération du support.
EOF
}

# -----------------------------------------------------------------------------
# 10. Point d'entrée
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter en root."
  log_info "Thot Secure est strictement défensif : aucun export ne quitte cet hôte sans votre collecteur."

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/thotsecure-audit-export.XXXXXX")"
  # shellcheck disable=SC2064  # expansion volontaire à la définition du piège
  trap "rm -rf '${TMP_DIR}'" EXIT

  check_prerequisites

  # La clé est publiée dans la variable globale API_KEY : elle n'est jamais
  # affichée, jamais passée en argument de commande, et effacée dès que possible.
  resolve_api_key
  [[ -n "${API_KEY}" ]] || die "Clé API vide : vérifiez --api-key-file ou THOT_API_KEY." 1

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry install -d -o root -g root -m 0700 "${OUT_DIR}"
  else
    # 0700 : un export d'audit est une pièce sensible (acteurs, cibles, décisions).
    ensure_private_dir "${OUT_DIR}" "0700"
  fi

  verify_chain "${API_KEY}"

  local temp="${TMP_DIR}/export-${TENANT}.${FORMAT}"
  fetch_export "${API_KEY}" "${temp}"
  API_KEY=""   # la clé n'est plus nécessaire : on la retire de la mémoire du shell

  if [[ "${DRY_RUN}" != "true" ]]; then
    validate_export "${temp}"
  fi

  finalize_export "${temp}"
  rotate_exports
  print_siem_hints

  if [[ "${CHAIN_STATUS}" == "broken" ]]; then
    log_error "Export .SUSPECT produit : la chaîne d'audit est ROMPUE — incident à traiter."
    exit "${EXIT_VERIFY}"
  fi
  if [[ "${CHAIN_STATUS}" == "unverified" ]]; then
    log_warn "Export .UNVERIFIED produit : la chaîne d'audit n'a pas pu être vérifiée."
    exit "${EXIT_VERIFY}"
  fi
  log_ok "Export d'audit terminé et vérifié."
}

main "$@"
