#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/restore.sh
# -----------------------------------------------------------------------------
#  Restauration d'une sauvegarde produite par scripts/backup.sh, avec filets
#  de sécurité à chaque étape.
#
#  Ce que fait ce script, dans l'ordre :
#    1. choisit l'archive (--archive, ou la plus récente de --from) ;
#    2. VÉRIFIE SON CONDENSÉ SHA-256 contre le scellé « <archive>.sha256 » :
#       une archive altérée n'est JAMAIS restaurée. Il n'existe volontairement
#       aucune option pour contourner ce contrôle sans le dire explicitement ;
#    3. déchiffre l'archive si elle est en .age / .gpg (clé privée fournie par
#       --identity pour age, trousseau GPG de l'opérateur pour gpg) ;
#    4. contrôle son intégrité (PRAGMA integrity_check) AVANT d'écraser quoi que
#       ce soit — et signale si la fiche .meta déclarait une chaîne d'audit rompue ;
#    5. affiche un récapitulatif et demande UNE confirmation explicite ;
#    6. arrête le service (sauf --no-service) pour éviter d'écrire sous les
#       pieds d'un processus qui tient la base ouverte ;
#    7. SAUVEGARDE LA BASE COURANTE avant écrasement
#       (/var/backups/thotsecure/thotsecure-prerestore-<horodatage>.db) : une
#       restauration est elle-même une opération risquée, elle doit être annulable ;
#    8. restaure de façon ATOMIQUE (copie vers « <base>.incoming », puis
#       renommage) et supprime les fichiers -wal / -shm de l'ancienne base, qui
#       ne correspondent plus à rien et corrompraient la base restaurée ;
#    9. redémarre le service, puis VÉRIFIE : sonde /healthz, « thotsecure doctor »
#       et « thotsecure audit verify » (code de sortie 3 si la chaîne est rompue).
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    Ce script ne modifie JAMAIS THOT_DRY_RUN ni THOT_AUTONOMY : restaurer une
#    base peut ramener un état antérieur, jamais allumer l'automatisation.
#
#  Codes de sortie (contrat §8) : 0 succès, 1 erreur, 2 usage,
#  3 vérification négative (condensé invalide, base corrompue, chaîne rompue).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation (mêmes conventions qu'install.sh)
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="restore.sh"
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

# Toute opération qui MODIFIE le système passe par ici : jamais exécutée en
# --dry-run. Les vérifications, elles, s'exécutent réellement.
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
  log_error "La restauration est INCOMPLÈTE : la base courante a été sauvegardée"
  log_error "avant écrasement (voir le chemin « prerestore » ci-dessus) — ne relancez"
  log_error "pas le service avant d'avoir compris l'échec."
  exit "${2}"
}
trap 'on_error "${LINENO}" "$?"' ERR

# -----------------------------------------------------------------------------
# 2. Constantes (miroir de deploy/ansible/roles/thotsecure/defaults/main.yml)
# -----------------------------------------------------------------------------
readonly SERVICE_NAME="thotsecure"
readonly SERVICE_USER="thotsecure"
readonly SERVICE_GROUP="thotsecure"
readonly ETC_DIR="/etc/thotsecure"
readonly DATA_DIR="/var/lib/thotsecure"
readonly INSTALL_DIR="/opt/thotsecure"
readonly VENV_DIR="${INSTALL_DIR}/venv"
readonly ENV_FILE="${ETC_DIR}/thotsecure.env"
readonly DB_DEFAULT="${DATA_DIR}/thotsecure.db"
readonly SERVICE_WORKDIR="${DATA_DIR}"
readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3

# -----------------------------------------------------------------------------
# 3. Options
# -----------------------------------------------------------------------------
DRY_RUN="false"
ASSUME_YES="false"
FORCE="false"
ARCHIVE=""
FROM_DIR="${THOT_BACKUP_DIR:-/var/backups/thotsecure}"
BACKUP_DIR="${THOT_BACKUP_DIR:-/var/backups/thotsecure}"
DB_FILE=""
CHECKSUM=""
IDENTITY="${THOT_BACKUP_IDENTITY:-}"
STOP_SERVICE="true"
CLI_BIN=""
HEALTH_URL="${THOT_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
HEALTH_TIMEOUT="20"
PRE_RESTORE_FILE=""
TMP_DIR=""

usage() {
  cat <<'AIDE'
Thot Secure — restauration d'une sauvegarde (avec sauvegarde de sécurité).

USAGE
    sudo scripts/restore.sh [options]

OPTIONS
    --archive <fichier>   Archive à restaurer (.db, .db.age ou .db.gpg).
                          Sans option, la plus récente de --from est utilisée.
    --from <dir>          Répertoire des archives (défaut : /var/backups/thotsecure,
                          surchargeable par THOT_BACKUP_DIR).
    --backup-dir <dir>    Où écrire la sauvegarde de sécurité de la base courante
                          (défaut : /var/backups/thotsecure).
    --db <fichier>        Base cible à écraser. Par défaut : THOT_DB_URL lue dans
                          /etc/thotsecure/thotsecure.env, sinon
                          /var/lib/thotsecure/thotsecure.db.
    --checksum <hex>      Condensé SHA-256 attendu, si l'archive n'a pas de
                          scellé « <archive>.sha256 » (archive externe, coffre…).
    --identity <fichier>  Clé privée age pour déchiffrer une archive .age
                          (surchargeable par THOT_BACKUP_IDENTITY).
    --no-service          Ne pas arrêter ni redémarrer le service.
                          À n'utiliser que si le service est déjà arrêté.
    --health-url <url>    Sonde de vie après redémarrage
                          (défaut : http://127.0.0.1:8080/healthz).
    --health-timeout <s>  Durée maximale d'attente de la sonde (défaut : 20 s).
    --cli <chemin>        Binaire de la CLI (défaut : détection automatique).
    --force               Continuer si la sauvegarde de sécurité de la base
                          courante échoue (dangereux : confirmation demandée).
    --yes                 Ne poser aucune question (automatisation encadrée).
    --dry-run             Tout vérifier et tout afficher, sans rien modifier.
    -h, --help            Afficher cette aide.

CODES DE SORTIE
    0 réussite · 1 erreur · 2 usage · 3 vérification négative
    (condensé invalide, base corrompue ou chaîne d'audit rompue).

SÛRETÉ
    * Le condensé SHA-256 est vérifié AVANT toute écriture. Si le scellé est
      absent, la restauration exige une confirmation explicite et le signale.
    * La base courante est TOUJOURS copiée (API .backup de SQLite) avant
      écrasement : une restauration reste ainsi annulable.
    * Après restauration, « thotsecure doctor » et « thotsecure audit verify »
      sont exécutés : une chaîne d'audit rompue fait sortir en code 3.
    * Thot Secure est strictement défensif ; lisez ce script avant de l'exécuter
      en root, et ne restaurez jamais une base douteuse sur une production sans
      décision écrite.

EXEMPLES
    sudo scripts/restore.sh --archive /var/backups/thotsecure/thotsecure-backup-20260214T033000Z.db --dry-run
    sudo scripts/restore.sh --from /mnt/coffre/daily --yes
    sudo scripts/restore.sh --archive sauvegarde.db.age --identity /root/age.key
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --archive)
        [[ $# -ge 2 ]] || die "--archive exige un chemin de fichier." "${EXIT_USAGE}"
        ARCHIVE="$2"; shift 2 ;;
      --from)
        [[ $# -ge 2 ]] || die "--from exige un répertoire." "${EXIT_USAGE}"
        FROM_DIR="$2"; shift 2 ;;
      --backup-dir)
        [[ $# -ge 2 ]] || die "--backup-dir exige un répertoire." "${EXIT_USAGE}"
        BACKUP_DIR="$2"; shift 2 ;;
      --db)
        [[ $# -ge 2 ]] || die "--db exige un chemin de fichier." "${EXIT_USAGE}"
        DB_FILE="$2"; shift 2 ;;
      --checksum)
        [[ $# -ge 2 ]] || die "--checksum exige un condensé SHA-256 hexadécimal." "${EXIT_USAGE}"
        CHECKSUM="$2"; shift 2 ;;
      --identity)
        [[ $# -ge 2 ]] || die "--identity exige un chemin de fichier." "${EXIT_USAGE}"
        IDENTITY="$2"; shift 2 ;;
      --no-service)  STOP_SERVICE="false"; shift ;;
      --health-url)
        [[ $# -ge 2 ]] || die "--health-url exige une URL." "${EXIT_USAGE}"
        HEALTH_URL="$2"; shift 2 ;;
      --health-timeout)
        [[ $# -ge 2 ]] || die "--health-timeout exige un nombre de secondes." "${EXIT_USAGE}"
        HEALTH_TIMEOUT="$2"; shift 2 ;;
      --cli)
        [[ $# -ge 2 ]] || die "--cli exige un chemin." "${EXIT_USAGE}"
        CLI_BIN="$2"; shift 2 ;;
      --force)   FORCE="true"; shift ;;
      --yes)     ASSUME_YES="true"; shift ;;
      --dry-run) DRY_RUN="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  if [[ -n "${CHECKSUM}" && ! "${CHECKSUM}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    die "--checksum attend 64 caractères hexadécimaux." "${EXIT_USAGE}"
  fi
  if [[ ! "${HEALTH_TIMEOUT}" =~ ^[0-9]+$ ]]; then
    die "--health-timeout attend un entier (secondes)." "${EXIT_USAGE}"
  fi
}

# Le compte de service doit exister : la base restaurée lui appartient, sinon le
# service ne pourrait pas l'ouvrir en écriture après redémarrage.
require_service_account() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    return 0
  fi
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    die "Compte de service « ${SERVICE_USER} » absent : installez d'abord le service (scripts/install.sh)." 1
  fi
}

# -----------------------------------------------------------------------------
# 4. Prérequis et utilitaires
# -----------------------------------------------------------------------------
require_root() {
  # Une restauration écrit dans /var/lib/thotsecure et arrête un service :
  # c'est une opération d'administration, jamais une opération d'utilisateur.
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : les privilèges root ne sont pas nécessaires."
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    die "La restauration remplace ${DB_FILE} et pilote le service ${SERVICE_NAME} : relancez avec sudo." 1
  fi
}

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
  local missing=0
  need_cmd python3 "Python 3.11+ est requis (module standard sqlite3 : contrôle d'intégrité)." \
    || missing=1
  if ! command -v sha256sum >/dev/null 2>&1 \
     && ! command -v shasum >/dev/null 2>&1 \
     && ! command -v openssl >/dev/null 2>&1; then
    log_error "Aucun outil SHA-256 disponible (sha256sum, shasum ou openssl)."
    missing=1
  fi
  [[ "${missing}" -eq 0 ]] || die "Prérequis manquants : corrigez-les puis relancez." 1
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

sizeof_human() {
  printf '%s octets' "$(wc -c < "$1" | tr -d ' ')"
}

# Confirmation EXPLICITE : aucune opération destructive sans un « oui » lisible.
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
# 5. Base cible et sélection de l'archive
# -----------------------------------------------------------------------------
db_url_from_env_file() {
  [[ -r "${ENV_FILE}" ]] || return 1
  local url
  url="$(sed -n 's/^THOT_DB_URL=//p' "${ENV_FILE}" 2>/dev/null | tail -n 1)"
  [[ -n "${url}" ]] || return 1
  printf '%s\n' "${url}"
}

sqlite_path_from_url() {
  local url="$1" rest=""
  [[ "${url}" == sqlite://* ]] || return 1
  rest="${url#sqlite://}"
  rest="${rest#/}"
  [[ -n "${rest}" ]] || return 1
  printf '%s\n' "${rest}"
}

resolve_db_file() {
  if [[ -n "${DB_FILE}" ]]; then
    log_step "Base cible imposée par --db : ${DB_FILE}"
    return 0
  fi
  local url="" path=""
  if url="$(db_url_from_env_file)"; then
    log_step "THOT_DB_URL lue dans ${ENV_FILE} : ${url}"
    if ! path="$(sqlite_path_from_url "${url}")"; then
      die "THOT_DB_URL n'est pas une URL SQLite (${url}).
Ce script ne restaure que des bases SQLite ; pour PostgreSQL/TimescaleDB,
utilisez pg_restore selon docs/operations/deployment.md." "${EXIT_USAGE}"
    fi
  else
    path="${DB_DEFAULT}"
    log_step "Aucune THOT_DB_URL lisible : base par défaut ${DB_DEFAULT}"
    log_warn "Si ${ENV_FILE} existe mais n'est pas lisible, relancez avec sudo."
  fi
  if [[ "${path}" != /* ]]; then
    log_step "Chemin relatif : résolu depuis ${SERVICE_WORKDIR} (WorkingDirectory du service)."
    path="${SERVICE_WORKDIR}/${path#./}"
  fi
  DB_FILE="${path}"
}

select_archive() {
  if [[ -n "${ARCHIVE}" ]]; then
    [[ -f "${ARCHIVE}" ]] || die "Archive introuvable : ${ARCHIVE}." 1
    log_step "Archive imposée par --archive : ${ARCHIVE}"
    return 0
  fi

  [[ -d "${FROM_DIR}" ]] || die "Répertoire d'archives introuvable : ${FROM_DIR}." 1
  local newest=""
  # Le nom contient l'horodatage UTC : l'ordre lexicographique inverse donne
  # l'archive la plus récente. Les scellés (.sha256, .meta) sont exclus.
  # awk (et non « head -n 1 ») : awk consomme toute l'entrée, donc aucun SIGPIPE
  # ne vient faire échouer la conduite sous « set -o pipefail ».
  newest="$(find "${FROM_DIR}" -maxdepth 1 -type f -name 'thotsecure-backup-*' \
              ! -name '*.sha256' ! -name '*.meta' -print 2>/dev/null \
            | LC_ALL=C sort -r | awk 'NR == 1 { print }')"
  [[ -n "${newest}" ]] \
    || die "Aucune archive « thotsecure-backup-* » dans ${FROM_DIR}. Précisez --archive." 1
  ARCHIVE="${newest}"
  log_info "Archive la plus récente retenue : $(basename "${ARCHIVE}")"
}

# -----------------------------------------------------------------------------
# 6. Vérification du condensé (étape non contournable sans le dire explicitement)
# -----------------------------------------------------------------------------
verify_checksum() {
  local file="$1" expected="${CHECKSUM}" actual=""

  if [[ -z "${expected}" ]]; then
    local seal="${file}.sha256"
    if [[ -r "${seal}" ]]; then
      # Format « sha256sum -c » : « <condensé>  <nom> ».
      expected="$(awk 'NF >= 1 { print tolower($1); exit }' "${seal}")"
      log_info "Condensé de référence lu dans $(basename "${seal}")."
    fi
  fi

  if [[ -z "${expected}" ]]; then
    log_error "AUCUN CONDENSÉ DE RÉFÉRENCE pour $(basename "${file}")."
    log_step "Sans scellé, rien ne prouve que l'archive n'a pas été altérée."
    log_step "Fournissez --checksum <hex> (condensé obtenu par un canal fiable) :"
    log_step "la restauration refusera de continuer sans confirmation explicite."
    if ! confirm "Restaurer une archive NON VÉRIFIÉE $(basename "${file}") ?"; then
      die "Restauration refusée : archive non vérifiée." "${EXIT_VERIFY}"
    fi
    log_warn "Vous avez explicitement accepté de restaurer une archive sans condensé."
    log_warn "Cette restauration n'est PAS prouvée saine : consignez cette décision."
    return 0
  fi

  actual="$(sha256_of "${file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    log_error "CONDENSÉ SHA-256 INVALIDE pour $(basename "${file}")."
    log_step "attendu : ${expected}"
    log_step "obtenu  : ${actual}"
    log_error "REFUS DE RESTAURER : l'archive a été altérée, tronquée ou remplacée."
    log_error "Utilisez une autre archive, ou récupérez-la depuis le support d'origine."
    exit "${EXIT_VERIFY}"
  fi
  log_ok "Condensé SHA-256 vérifié : ${actual}"
}

# -----------------------------------------------------------------------------
# 7. Déchiffrement facultatif
# -----------------------------------------------------------------------------
decrypt_if_needed() {
  # decrypt_if_needed <archive> → écrit le chemin utilisable dans ARCHIVE_PLAIN
  local archive="$1"
  # Deux déclarations distinctes : dans « local a=… b="${a}" », l'expansion de
  # ${a} a lieu AVANT l'affectation (et échouerait sous « set -u »).
  local effective="${archive}"

  # Une archive produite par backup.sh peut porter un marqueur d'incertitude APRÈS
  # son extension (ex. « …backup-…Z.db.age.SUSPECT »). On raisonne donc sur le nom
  # sans ce marqueur pour choisir le bon outil de déchiffrement.
  case "${effective}" in
    *.SUSPECT)    effective="${effective%.SUSPECT}" ;;
    *.UNVERIFIED) effective="${effective%.UNVERIFIED}" ;;
    *) : ;;
  esac

  case "${effective}" in
    *.age)
      need_cmd age "Installez age (age-encryption.org) pour déchiffrer cette archive." \
        || die "age est requis pour déchiffrer ${archive}." 1
      [[ -n "${IDENTITY}" ]] \
        || die "Archive .age : fournissez la clé privée avec --identity <fichier>." "${EXIT_USAGE}"
      [[ -r "${IDENTITY}" ]] || die "Clé age illisible : ${IDENTITY}." 1
      ARCHIVE_PLAIN="${TMP_DIR}/archive-restauree.db"
      log_info "Déchiffrement age (clé : ${IDENTITY})…"
      run age --decrypt --identity "${IDENTITY}" --output "${ARCHIVE_PLAIN}" "${archive}"
      ;;
    *.gpg)
      need_cmd gpg "Installez GnuPG pour déchiffrer cette archive." \
        || die "gpg est requis pour déchiffrer ${archive}." 1
      ARCHIVE_PLAIN="${TMP_DIR}/archive-restauree.db"
      log_info "Déchiffrement GPG (trousseau de l'opérateur)…"
      run gpg --batch --yes --no-tty --output "${ARCHIVE_PLAIN}" --decrypt "${archive}"
      ;;
    *)
      ARCHIVE_PLAIN="${archive}"
      ;;
  esac

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry test -s "${ARCHIVE_PLAIN}"
    return 0
  fi
  [[ -s "${ARCHIVE_PLAIN}" ]] || die "Déchiffrement impossible : ${ARCHIVE_PLAIN} est vide." 1
  chmod 0600 "${ARCHIVE_PLAIN}"
  log_ok "Archive exploitable : ${ARCHIVE_PLAIN} ($(sizeof_human "${ARCHIVE_PLAIN}"))"
}

# -----------------------------------------------------------------------------
# 8. Contrôles préalables à l'écrasement
# -----------------------------------------------------------------------------
check_archive_integrity() {
  # Contrôle sur une copie en LECTURE SEULE : l'archive n'est jamais modifiée.
  local file="$1" rc=0
  if [[ ! -f "${file}" ]]; then
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_warn "Mode --dry-run : contrôle d'intégrité de l'archive déchiffrée impossible."
      return 0
    fi
    die "Archive exploitable introuvable : ${file}." 1
  fi
  log_info "Contrôle d'intégrité de l'archive (PRAGMA integrity_check)…"
  set +e
  python3 - "${file}" <<'PY'
"""Vérifie qu'un fichier est bien une base SQLite intègre (lecture seule)."""
from __future__ import annotations

import sqlite3
import sys

path = sys.argv[1]
header = b""
try:
    with open(path, "rb") as handle:
        header = handle.read(16)
except OSError as exc:
    raise SystemExit(f"lecture impossible ({path}) : {exc}")

if header[:15] != b"SQLite format 3":
    raise SystemExit(f"ce fichier n'est pas une base SQLite ({path})")

try:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
except sqlite3.Error as exc:
    raise SystemExit(f"ouverture impossible ({path}) : {exc}")
try:
    # Sur une base réellement corrompue, SQLite LÈVE une erreur au lieu de
    # renvoyer un résultat : on la traite comme un échec d'intégrité, sans
    # laisser remonter une trace Python illisible pour l'exploitant.
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        row = (f"erreur SQLite : {exc}",)
finally:
    conn.close()

if not row or row[0] != "ok":
    raise SystemExit(f"integrity_check a échoué : {row[0] if row else 'aucun résultat'}")
print("base SQLite intègre")
PY
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log_error "L'ARCHIVE N'EST PAS UNE BASE SAINE : restauration refusée."
    log_error "Une base corrompue écraserait une base peut-être encore exploitable."
    exit "${EXIT_VERIFY}"
  fi
  log_ok "Archive saine : base SQLite intègre."
}

report_archive_meta() {
  # La fiche .meta (écrite par backup.sh) dit ce que l'on s'apprête à restaurer.
  local meta="${ARCHIVE}.meta"
  if [[ ! -r "${meta}" ]]; then
    log_step "Pas de fiche .meta à côté de l'archive (archive externe ou ancienne)."
    return 0
  fi
  local chain=""
  chain="$(sed -n 's/^audit_chain=//p' "${meta}" | tail -n 1)"
  log_info "Fiche de sauvegarde ($(basename "${meta}")) :"
  while IFS= read -r line; do
    if [[ "${line}" == \#* || -z "${line}" ]]; then
      continue
    fi
    log_step "${line}"
  done < "${meta}"

  case "${chain}" in
    ok) : ;;
    chain_broken)
      log_error "LA CHAÎNE D'AUDIT ÉTAIT DÉJÀ ROMPUE au moment de cette sauvegarde."
      log_error "Restaurer cette base réintroduit un journal d'audit falsifié."
      log_error "Traitez l'incident AVANT toute restauration (SECURITY.md)."
      if ! confirm "Restaurer MALGRÉ une chaîne d'audit rompue enregistrée ?"; then
        die "Restauration refusée : chaîne d'audit compromise." "${EXIT_VERIFY}"
      fi
      ;;
    skipped|inconclusive)
      log_warn "Chaîne d'audit NON vérifiée lors de cette sauvegarde (${chain})."
      log_warn "La restauration se poursuit, mais la valeur probante n'est pas démontrée."
      ;;
    *) : ;;
  esac
}

# -----------------------------------------------------------------------------
# 9. Service : arrêt et redémarrage
# -----------------------------------------------------------------------------
have_systemd() { command -v systemctl >/dev/null 2>&1; }

stop_service() {
  [[ "${STOP_SERVICE}" == "true" ]] || { log_step "--no-service : service non arrêté."; return 0; }
  if ! have_systemd; then
    log_warn "systemd absent : assurez-vous qu'aucun processus n'utilise ${DB_FILE}."
    log_step "Vérifiez avec : lsof ${DB_FILE}   (ou fuser -v ${DB_FILE})"
    return 0
  fi
  log_info "Arrêt du service ${SERVICE_NAME}…"
  run systemctl stop "${SERVICE_NAME}" || log_warn "Arrêt : échec ou service déjà arrêté."
  if [[ "${DRY_RUN}" != "true" ]] && systemctl is-active --quiet "${SERVICE_NAME}"; then
    die "Le service est toujours actif : arrêtez-le manuellement avant de restaurer." 1
  fi
  log_ok "Service arrêté : plus aucun processus n'écrit dans la base."
}

start_service() {
  [[ "${STOP_SERVICE}" == "true" ]] || { log_step "--no-service : service non redémarré."; return 0; }
  if ! have_systemd; then
    log_warn "systemd absent : redémarrez le service à la main, puis lancez « thotsecure doctor »."
    return 0
  fi
  log_info "Redémarrage du service ${SERVICE_NAME}…"
  run systemctl start "${SERVICE_NAME}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry systemctl is-active "${SERVICE_NAME}"
    return 0
  fi
  local waited=0
  while [[ "${waited}" -lt "${HEALTH_TIMEOUT}" ]]; do
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
      log_ok "Service actif."
      return 0
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  log_warn "Le service n'est pas actif après ${HEALTH_TIMEOUT}s : consultez « journalctl -u ${SERVICE_NAME} »."
}

# -----------------------------------------------------------------------------
# 10. Sauvegarde de sécurité de la base courante
# -----------------------------------------------------------------------------
pre_restore_backup() {
  # Une restauration écrase un état courant : cet état doit rester récupérable.
  local stamp="" target=""
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  target="${BACKUP_DIR}/thotsecure-prerestore-${stamp}.db"
  PRE_RESTORE_FILE="${target}"

  if [[ ! -f "${DB_FILE}" ]]; then
    log_step "Aucune base courante à sauvegarder (${DB_FILE} absent) : rien à préserver."
    PRE_RESTORE_FILE=""
    return 0
  fi

  log_info "Sauvegarde de sécurité de la base courante → $(basename "${target}")"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry install -d -o root -g root -m 0700 "${BACKUP_DIR}"
    log_dry python3 "<copie cohérente .backup()>" "${DB_FILE}" "${target}"
    return 0
  fi

  run install -d -o root -g root -m 0700 "${BACKUP_DIR}"

  local rc=0
  set +e
  python3 - "${DB_FILE}" "${target}" <<'PY'
"""Sauvegarde cohérente de la base courante (API .backup de SQLite)."""
from __future__ import annotations

import sqlite3
import sys

source, destination = sys.argv[1], sys.argv[2]
try:
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
except sqlite3.Error as exc:
    raise SystemExit(f"ouverture en lecture seule impossible ({source}) : {exc}")
dst = sqlite3.connect(destination)
try:
    try:
        with dst:
            src.backup(dst)
    except sqlite3.Error as exc:
        # Base courante corrompue ou illisible : la copie cohérente est
        # impossible. L'appelant bascule alors sur une copie brute, signalée.
        raise SystemExit(f"copie cohérente impossible ({source}) : {exc}")
finally:
    dst.close()
    src.close()
print("ok")
PY
  rc=$?
  set -e

  if [[ "${rc}" -ne 0 ]]; then
    # La copie cohérente est impossible : base courante illisible ou corrompue.
    # Une copie brute reste préférable à aucune trace — mais elle est signalée.
    log_warn "Copie cohérente impossible : copie brute du fichier (peut être incohérente)."
    if [[ -f "${DB_FILE}" ]] && run cp -p "${DB_FILE}" "${target}" && [[ -s "${target}" ]]; then
      rc=0
      if [[ -f "${DB_FILE}-wal" ]]; then
        run cp -p "${DB_FILE}-wal" "${target}-wal" || true
      fi
    fi
    if [[ "${rc}" -ne 0 || ! -s "${target}" ]]; then
      if [[ "${FORCE}" == "true" ]]; then
        log_warn "--force : restauration sans sauvegarde de sécurité de la base courante."
        if ! confirm "Continuer SANS filet de sécurité sur la base courante ?"; then
          die "Restauration annulée : aucune sauvegarde de sécurité obtenue." 1
        fi
        PRE_RESTORE_FILE=""
        return 0
      fi
      die "Sauvegarde de sécurité impossible : restauration ANNULÉE (utilisez --force en connaissance de cause)." 1
    fi
  fi

  run chmod 0600 "${target}"
  printf '%s  %s\n' "$(sha256_of "${target}")" "$(basename "${target}")" > "${target}.sha256"
  run chmod 0600 "${target}.sha256"
  log_ok "Base courante préservée : ${target} ($(sizeof_human "${target}"))"
}

# -----------------------------------------------------------------------------
# 11. Restauration atomique
# -----------------------------------------------------------------------------
install_database() {
  local source="$1" incoming="${DB_FILE}.incoming"
  local db_dir=""
  db_dir="$(dirname -- "${DB_FILE}")"

  log_info "Restauration vers ${DB_FILE}…"
  run install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${db_dir}"

  # 1) copie vers un fichier temporaire situé DANS le même répertoire : le
  #    renommage final est ainsi atomique (même système de fichiers).
  run cp -f "${source}" "${incoming}"
  run chown "${SERVICE_USER}:${SERVICE_GROUP}" "${incoming}"
  run chmod 0600 "${incoming}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry rm -f "${DB_FILE}-wal" "${DB_FILE}-shm"
    log_dry mv -f "${incoming}" "${DB_FILE}"
    return 0
  fi

  # 2) les fichiers -wal et -shm appartiennent à l'ANCIENNE base : les laisser
  #    en place reviendrait à rejouer un journal étranger sur la base restaurée.
  rm -f "${DB_FILE}-wal" "${DB_FILE}-shm"
  # 3) bascule atomique : soit l'ancienne base, soit la nouvelle, jamais un mélange.
  mv -f "${incoming}" "${DB_FILE}"
  # 4) contexte SELinux (si la distribution en utilise un) : un fichier déplacé
  #    conserve son étiquette d'origine, qui peut interdire l'accès au service.
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "${DB_FILE}" || log_warn "restorecon a échoué : vérifiez le contexte SELinux de ${DB_FILE}."
  fi
  log_ok "Base restaurée : ${DB_FILE} ($(sizeof_human "${DB_FILE}"), mode 0600, ${SERVICE_USER}:${SERVICE_GROUP})"
}

# -----------------------------------------------------------------------------
# 12. Vérifications post-restauration
# -----------------------------------------------------------------------------
post_restore_checks() {
  local failures=0

  log_info "Vérification d'intégrité de la base restaurée…"
  local rc=0
  set +e
  python3 - "${DB_FILE}" <<'PY'
from __future__ import annotations

import sqlite3
import sys

conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        row = (f"erreur SQLite : {exc}",)
finally:
    conn.close()
if not row or row[0] != "ok":
    raise SystemExit(f"integrity_check a échoué : {row[0] if row else 'aucun résultat'}")
print("ok")
PY
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    log_ok "Base restaurée intègre."
  else
    log_error "La base restaurée ÉCHOUE à PRAGMA integrity_check."
    failures=$(( failures + 1 ))
  fi

  local cli=""
  if ! cli="$(resolve_cli)"; then
    log_warn "CLI thotsecure introuvable : vérifications applicatives ignorées."
    log_step "Indiquez son chemin avec --cli, puis lancez « thotsecure doctor » à la main."
    return "${failures}"
  fi

  log_info "Diagnostic applicatif (${cli} doctor)…"
  set +e
  run_as_service "${cli}" doctor
  rc=$?
  set -e
  case "${rc}" in
    0) log_ok "« doctor » : aucune anomalie critique." ;;
    3) log_error "« doctor » signale au moins une anomalie CRITIQUE."; failures=$(( failures + 1 )) ;;
    *) log_warn "« doctor » s'est terminé avec le code ${rc}." ;;
  esac

  log_info "Vérification de la chaîne d'audit (${cli} audit verify)…"
  set +e
  run_as_service "${cli}" audit verify
  rc=$?
  set -e
  case "${rc}" in
    0) log_ok "Chaîne d'audit intègre sur la base restaurée." ;;
    3)
      log_error "CHAÎNE D'AUDIT ROMPUE APRÈS RESTAURATION (sortie 3)."
      log_error "Vous avez peut-être restauré une base falsifiée, ou tronqué l'historique."
      log_error "INCIDENT DE SÉCURITÉ : voir SECURITY.md, ne « réparez » pas la chaîne."
      failures=$(( failures + 1 ))
      ;;
    *) log_warn "« audit verify » non concluant (code ${rc})." ;;
  esac

  if [[ "${STOP_SERVICE}" == "true" ]] && command -v python3 >/dev/null 2>&1; then
    log_info "Sonde de vie ${HEALTH_URL}…"
    set +e
    python3 - "${HEALTH_URL}" <<'PY'
from __future__ import annotations

import sys
import urllib.error
import urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - URL locale connue
        print(f"HTTP {response.status}")
        raise SystemExit(0 if response.status == 200 else 1)
except (urllib.error.URLError, OSError) as exc:
    print(f"sonde injoignable : {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 ]]; then
      log_ok "Sonde de vie : 200."
    else
      log_warn "Sonde de vie injoignable (le service démarre peut-être encore)."
      log_step "Vérifiez : systemctl status ${SERVICE_NAME} ; journalctl -u ${SERVICE_NAME} -n 50"
    fi
  fi

  return "${failures}"
}

# -----------------------------------------------------------------------------
# 13. Point d'entrée
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter en root : il REMPLACE une base de données."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "MODE --dry-run : tout est vérifié, rien n'est modifié."
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/thotsecure-restore.XXXXXX")"
  # shellcheck disable=SC2064  # expansion volontaire à la définition du piège
  trap "rm -rf '${TMP_DIR}'" EXIT

  check_prerequisites
  require_root
  require_service_account
  resolve_db_file
  select_archive
  verify_checksum "${ARCHIVE}"

  ARCHIVE_PLAIN="${ARCHIVE}"
  decrypt_if_needed "${ARCHIVE}"
  check_archive_integrity "${ARCHIVE_PLAIN}"
  report_archive_meta

  printf '\n'
  log_info "Opérations qui vont être effectuées :"
  log_step "1. arrêt du service        : ${STOP_SERVICE}"
  log_step "2. sauvegarde de sécurité  : ${BACKUP_DIR}/thotsecure-prerestore-<horodatage>.db"
  log_step "3. remplacement de la base : ${DB_FILE} (mode 0600, ${SERVICE_USER})"
  log_step "4. redémarrage + vérifs    : doctor, audit verify, ${HEALTH_URL}"

  if [[ "${DRY_RUN}" != "true" ]]; then
    if ! confirm "Restaurer $(basename "${ARCHIVE}") sur ${DB_FILE} ?"; then
      log_warn "Restauration annulée : rien n'a été modifié."
      exit 0
    fi
  fi

  stop_service
  pre_restore_backup
  install_database "${ARCHIVE_PLAIN}"
  start_service

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : aucune modification n'a été appliquée."
    return 0
  fi

  local failures=0
  post_restore_checks || failures=$?

  printf '\n'
  if [[ "${failures}" -ne 0 ]]; then
    log_error "Restauration effectuée, mais ${failures} vérification(s) en échec."
    log_error "N'activez rien d'autre avant d'avoir traité ces points."
    [[ -n "${PRE_RESTORE_FILE}" ]] && log_step "Retour arrière possible : sudo scripts/restore.sh --archive ${PRE_RESTORE_FILE}"
    exit "${EXIT_VERIFY}"
  fi

  log_ok "Restauration terminée et vérifiée."
  [[ -n "${PRE_RESTORE_FILE}" ]] && log_step "Base précédente conservée : ${PRE_RESTORE_FILE}"
  log_step "Déclarez l'opération dans votre journal d'exploitation (qui, quoi, pourquoi, quand)."
  log_step "Rejouez ensuite les écritures postérieures à la sauvegarde, si vous en avez."
}

main "$@"
