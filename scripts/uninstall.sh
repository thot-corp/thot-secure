#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique : « thotsecure ») — scripts/uninstall.sh
# -----------------------------------------------------------------------------
#  Désinstallation propre et RÉVERSIBLE par défaut.
#
#  Ce que fait ce script, dans l'ordre :
#    1. arrête et désactive le service (thotsecure.service, et l'alias
#       thotsecure.service s'il existe — le renommage est en cours) ;
#    2. propose une SAUVEGARDE de la base (cohérente : API .backup de SQLite,
#       jamais une copie brute d'un fichier en cours d'écriture) ;
#    3. supprime l'unité systemd, le binaire/lanceur et l'environnement virtuel ;
#    4. CONSERVE les données par défaut : /var/lib/thotsecure (base + journal
#       d'audit chaîné) et /etc/thotsecure (règles, politiques, secrets).
#       Seul « --purge » les supprime, et il demande alors une confirmation
#       explicite (sauf --yes, réservé à l'automatisation).
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    Le journal d'audit chaîné par hash et la base contiennent l'historique des
#    décisions : ils ont une valeur légale et post-incident. Ce script ne les
#    détruit jamais sans le dire, ne désactive jamais un garde-fou, et ne
#    modifie aucune variable THOT_* (THOT_DRY_RUN, THOT_AUTONOMY).
#
#  Codes de sortie : 0 succès, 1 erreur, 2 usage, 3 vérification négative.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="uninstall.sh"

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

log_dry() { printf '    %s[dry-run]%s' "${C_DIM}" "${C_RESET}"; printf ' %q' "$@"; printf '\n'; }

# Toute opération destructive passe par ici : jamais exécutée en --dry-run.
run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry "$@"
    return 0
  fi
  "$@"
}

die() { log_error "$1"; exit "${2:-1}"; }

on_error() {
  log_error "Échec de ${SCRIPT_NAME} à la ligne ${1} (code ${2})."
  log_error "La désinstallation est partielle : relancez le script après correction."
  exit "${2}"
}
trap 'on_error "${LINENO}" "$?"' ERR

# -----------------------------------------------------------------------------
# Constantes (miroir de deploy/ansible/roles/thotsecure/defaults/main.yml)
# -----------------------------------------------------------------------------
readonly SERVICE_NAME="thotsecure"
readonly LEGACY_NAME="thotsecure"
readonly SERVICE_USER="thotsecure"
readonly SERVICE_GROUP="thotsecure"
readonly ETC_DIR="/etc/thotsecure"
readonly DATA_DIR="/var/lib/thotsecure"
readonly LOG_DIR="/var/log/thotsecure"
readonly INSTALL_DIR="/opt/thotsecure"
readonly VENV_DIR="/opt/thotsecure/venv"
readonly ENV_FILE="${ETC_DIR}/thotsecure.env"
readonly DB_FILE="${DATA_DIR}/thotsecure.db"
readonly BACKUP_DIR="${THOT_BACKUP_DIR:-/var/backups/thotsecure}"
readonly UNIT_DIR="/etc/systemd/system"
readonly EXIT_USAGE=2

DRY_RUN="false"
PURGE="false"
DO_BACKUP="ask"
ASSUME_YES="false"
KEEP_USER="false"
PREFIX="${THOT_INSTALL_PREFIX:-/usr/local}"

usage() {
  cat <<'AIDE'
Thot Secure — désinstallation (les données sont CONSERVÉES par défaut).

USAGE
    sudo ./scripts/uninstall.sh [options]

OPTIONS
    --purge             Supprimer AUSSI les données : /var/lib/thotsecure (base
                        SQLite + journal d'audit) et /etc/thotsecure (règles,
                        politiques, secret). Demande une confirmation explicite.
    --backup            Sauvegarder la base avant toute suppression (défaut :
                        proposé interactivement si la base existe).
    --no-backup         Ne pas sauvegarder la base (déconseillé).
    --backup-dir <dir>  Répertoire des sauvegardes (défaut : /var/backups/thotsecure).
    --keep-user         Ne pas supprimer le compte système `thotsecure`.
    --prefix <chemin>   Préfixe où les binaires ont été installés (défaut : /usr/local).
    --dry-run           Afficher les opérations sans rien modifier.
    --yes               Ne poser aucune question (automatisation). À utiliser
                        uniquement si vous savez exactement ce qui sera supprimé.
    -h, --help          Afficher cette aide.

CE QUI EST CONSERVÉ PAR DÉFAUT
    /var/lib/thotsecure   base SQLite, journal d'audit chaîné, sauvegardes locales
    /etc/thotsecure       règles, politiques, playbooks, thotsecure.env (0600)

AVANT DE DÉCOMMISSIONNER
    1. Exportez le journal d'audit :  scripts/audit-export.sh
    2. Révoquez les clés API :        thotsecure key revoke --key-id <id>
    3. Sauvegardez la base :          scripts/backup.sh
    Ces trois étapes sont irréversibles si vous lancez --purge ensuite.

SÛRETÉ
    Thot Secure est strictement défensif. Ce script ne modifie jamais
    THOT_DRY_RUN ni THOT_AUTONOMY, et ne supprime rien sans le dire.
    Lisez ce script avant de l'exécuter en root.
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge)     PURGE="true"; shift ;;
      --backup)    DO_BACKUP="yes"; shift ;;
      --no-backup) DO_BACKUP="no"; shift ;;
      --backup-dir)
        [[ $# -ge 2 ]] || die "--backup-dir exige un chemin." "${EXIT_USAGE}"
        BACKUP_DIR="$2"; shift 2 ;;
      --keep-user) KEEP_USER="true"; shift ;;
      --prefix)
        [[ $# -ge 2 ]] || die "--prefix exige un chemin." "${EXIT_USAGE}"
        PREFIX="$2"; shift 2 ;;
      --dry-run)   DRY_RUN="true"; shift ;;
      --yes)       ASSUME_YES="true"; shift ;;
      -h|--help)   usage; exit 0 ;;
      *)           log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done
  [[ "${PREFIX}" == /* ]] || die "--prefix attend un chemin absolu." "${EXIT_USAGE}"
  if [[ "${PURGE}" == "true" && "${DO_BACKUP}" == "no" && "${ASSUME_YES}" == "true" ]]; then
    log_warn "--purge --no-backup --yes : les données seront détruites SANS sauvegarde."
  fi
}

# -----------------------------------------------------------------------------
# Prérequis et confirmation
# -----------------------------------------------------------------------------
require_root() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : aucune modification ne sera appliquée."
    return 0
  fi
  [[ "${EUID}" -eq 0 ]] || die "La désinstallation modifie ${ETC_DIR} et ${DATA_DIR} : relancez avec sudo." 1
}

# Demande une confirmation explicite. Renvoie 0 si l'utilisateur accepte.
confirm() {
  local prompt="$1"
  if [[ "${ASSUME_YES}" == "true" ]]; then
    log_warn "${prompt} → confirmé par --yes."
    return 0
  fi
  if [[ ! -t 0 ]]; then
    # Pas de terminal : on ne détruit rien par défaut. C'est volontaire.
    log_error "${prompt} : aucune confirmation possible (entrée non interactive)."
    log_step "Relancez avec --yes si la suppression est réellement voulue."
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

# -----------------------------------------------------------------------------
# 1. Arrêt du service
# -----------------------------------------------------------------------------
stop_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log_warn "systemd absent : arrêtez le processus manuellement si nécessaire."
    return 0
  fi

  local unit
  # Deux noms possibles : le renommage thotsecure → thotsecure est en cours.
  for unit in "${SERVICE_NAME}.service" "${LEGACY_NAME}.service"; do
    if systemctl list-unit-files "${unit}" >/dev/null 2>&1 \
       && [[ -n "$(systemctl list-unit-files --type=service --no-legend "${unit}" 2>/dev/null)" ]]; then
      log_info "Arrêt et désactivation de ${unit}…"
      run systemctl stop "${unit}" || log_warn "Arrêt de ${unit} : échec (déjà arrêté ?)."
      run systemctl disable "${unit}" || log_warn "Désactivation de ${unit} : échec (déjà désactivé ?)."
      run rm -f "${UNIT_DIR}/${unit}"
    else
      log_step "${unit} : non installé."
    fi
  done

  run systemctl daemon-reload
  run systemctl reset-failed || true
  log_ok "Service arrêté (le processus ne tourne plus)."
}

# -----------------------------------------------------------------------------
# 2. Sauvegarde facultative de la base
# -----------------------------------------------------------------------------
backup_database() {
  if [[ ! -f "${DB_FILE}" ]]; then
    log_step "Aucune base à sauvegarder (${DB_FILE} absent)."
    return 0
  fi

  if [[ "${DO_BACKUP}" == "ask" ]]; then
    if confirm "Sauvegarder la base avant désinstallation ?"; then
      DO_BACKUP="yes"
    else
      DO_BACKUP="no"
      log_warn "Sauvegarde refusée : la base ne sera PAS conservée en lieu sûr."
    fi
  fi
  [[ "${DO_BACKUP}" == "yes" ]] || return 0

  local stamp target
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  target="${BACKUP_DIR}/thotsecure-uninstall-${stamp}.db"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry mkdir -p "${BACKUP_DIR}"
    log_dry python3 "<sauvegarde cohérente SQLite>" "${DB_FILE}" "${target}"
    return 0
  fi

  run install -d -o root -g root -m 0700 "${BACKUP_DIR}"
  # Sauvegarde COHÉRENTE : API `.backup` de SQLite (module standard sqlite3).
  # Une simple copie de fichier serait incohérente si une écriture est en cours
  # (WAL/journal), ce qui produirait une base potentiellement corrompue.
  python3 - "${DB_FILE}" "${target}" <<'PY'
import sqlite3
import sys

source, destination = sys.argv[1], sys.argv[2]
# Ouverture en lecture seule de la source : on ne modifie jamais l'original.
with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src, \
        sqlite3.connect(destination) as dst:
    src.backup(dst)
    row = dst.execute("PRAGMA integrity_check").fetchone()
    if not row or row[0] != "ok":
        raise SystemExit(f"integrity_check a échoué : {row}")
print(f"Sauvegarde cohérente et intègre : {destination}")
PY
  run chmod 0600 "${target}"
  log_ok "Base sauvegardée : ${target}"
}

# -----------------------------------------------------------------------------
# 3. Suppression des binaires et du lanceur
# -----------------------------------------------------------------------------
remove_binaries() {
  log_info "Suppression des binaires…"
  local name
  for name in "${SERVICE_NAME}" "${LEGACY_NAME}"; do
    if [[ -e "${PREFIX}/bin/${name}" || -L "${PREFIX}/bin/${name}" ]]; then
      run rm -f "${PREFIX}/bin/${name}"
      log_step "Supprimé : ${PREFIX}/bin/${name}"
    fi
  done

  if [[ -d "${VENV_DIR}" ]]; then
    # L'environnement virtuel ne contient aucune donnée : suppression sûre.
    run rm -rf "${VENV_DIR}"
    log_step "Supprimé : ${VENV_DIR}"
  fi
  if [[ -d "${INSTALL_DIR}" && -z "$(ls -A "${INSTALL_DIR}" 2>/dev/null || true)" ]]; then
    run rmdir "${INSTALL_DIR}"
  elif [[ -d "${INSTALL_DIR}" ]]; then
    log_warn "Conservé : ${INSTALL_DIR} (contient encore des fichiers : $(ls -A "${INSTALL_DIR}" | tr '\n' ' '))."
  fi
  log_ok "Binaires retirés (les données ne sont pas concernées)."
}

# -----------------------------------------------------------------------------
# 4. Données : conservées par défaut, purgées sur demande explicite
# -----------------------------------------------------------------------------
report_kept_data() {
  cat <<EOF

${C_BOLD}Données CONSERVÉES${C_RESET} (suppression uniquement avec --purge) :
    ${DATA_DIR}    base SQLite, journal d'audit chaîné
    ${ETC_DIR}     règles, politiques, playbooks, ${ENV_FILE} (0600)

${C_BOLD}À faire avant tout --purge${C_RESET} :
    1. exporter l'audit        : scripts/audit-export.sh --out /chemin/sur
    2. révoquer les clés API   : thotsecure key revoke --key-id <id>
    3. sauvegarder la base     : scripts/backup.sh
    4. vérifier la chaîne      : thotsecure audit verify   (sortie 3 = corrompue)
EOF
}

purge_data() {
  log_warn "MODE --purge : les données suivantes seront DÉTRUITES :"
  log_step "${DATA_DIR}  (base SQLite + journal d'audit chaîné — irremplaçable)"
  log_step "${ETC_DIR}   (règles, politiques, ${ENV_FILE} et donc THOT_SECRET_KEY)"
  if [[ "${KEEP_USER}" != "true" ]]; then
    log_step "compte système ${SERVICE_USER} et groupe ${SERVICE_GROUP}"
  fi

  if ! confirm "Confirmez-vous la DESTRUCTION DÉFINITIVE de ces données ?"; then
    log_warn "Purge annulée : rien n'a été supprimé."
    report_kept_data
    return 0
  fi

  if [[ -d "${DATA_DIR}" ]]; then
    run rm -rf "${DATA_DIR}"
    log_step "Supprimé : ${DATA_DIR}"
  fi
  if [[ -d "${ETC_DIR}" ]]; then
    run rm -rf "${ETC_DIR}"
    log_step "Supprimé : ${ETC_DIR}"
  fi
  if [[ -d "${LOG_DIR}" ]]; then
    run rm -rf "${LOG_DIR}"
    log_step "Supprimé : ${LOG_DIR}"
  fi

  # Jamais de suppression de compte sans le demander : un compte système
  # supprimé laisse des fichiers orphelins, et une réinstallation changerait
  # les UID/GID (sauvegardes, NFS, SELinux).
  if [[ "${KEEP_USER}" != "true" && "${DRY_RUN}" != "true" ]]; then
    if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
      run userdel "${SERVICE_USER}" 2>/dev/null || log_warn "Compte ${SERVICE_USER} non supprimé (encore référencé ?)."
    fi
    if getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
      run groupdel "${SERVICE_GROUP}" 2>/dev/null || log_warn "Groupe ${SERVICE_GROUP} non supprimé."
    fi
  fi

  log_ok "Purge terminée. Les sauvegardes de ${BACKUP_DIR} restent disponibles."
}

# -----------------------------------------------------------------------------
# Point d'entrée
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter en root."
  log_info "Thot Secure est strictement défensif : aucune donnée n'est détruite sans confirmation."

  require_root
  stop_service
  backup_database
  remove_binaries

  if [[ "${PURGE}" == "true" ]]; then
    purge_data
  else
    report_kept_data
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : aucune modification n'a été appliquée."
  else
    log_ok "Désinstallation terminée."
  fi
}

main "$@"
