#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/backup.sh
# -----------------------------------------------------------------------------
#  Sauvegarde COHÉRENTE de la base SQLite et du journal d'audit chaîné.
#
#  Ce que fait ce script, dans l'ordre :
#    1. résout la base réelle (option --db, sinon THOT_DB_URL lue dans
#       /etc/thotsecure/thotsecure.env) — jamais une supposition silencieuse ;
#    2. copie la base avec l'API `.backup()` de SQLite (module standard
#       `sqlite3`), sur une connexion en LECTURE SEULE :
#         → cohérent même si le service écrit en ce moment (mode WAL, journal,
#           transaction en cours). Une simple `cp` d'un fichier en écriture
#           produit, elle, une base potentiellement corrompue ;
#    3. contrôle `PRAGMA integrity_check` sur la copie (et signale un original
#       déjà endommagé) ;
#    4. VÉRIFIE LA CHAÎNE D'AUDIT (`thotsecure audit verify`) : si l'intégrité
#       est compromise, l'archive est marquée « SUSPECT », le script le signale
#       bruyamment et sort en code 3 — une sauvegarde d'un journal falsifié doit
#       être un incident visible, jamais un fichier discret ;
#    5. écrit un condensé SHA-256 et une fiche de métadonnées à côté de l'archive
#       (nécessaires à scripts/restore.sh pour refuser une archive altérée) ;
#    6. chiffre l'archive si `age` ou `gpg` est disponible ET qu'un destinataire
#       est fourni (--recipient) ;
#    7. applique la rotation : conserve les N archives les plus récentes
#       (--keep, défaut 14). La suppression est DESTRUCTIVE : elle est listée
#       puis confirmée (--yes pour l'automatisation, --dry-run pour observer).
#
#  PLANIFICATION (systemd timer ou cron)
#      sudo scripts/backup.sh --keep 14 --yes        # 03:30, compte de service
#      (deploy/ansible/roles/thotsecure utilise thotsecure_backup_dir et
#       thotsecure_backup_on_calendar = « *-*-* 03:30:00 »)
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    Ce script ne modifie JAMAIS THOT_DRY_RUN ni THOT_AUTONOMY, ne
#    contacte aucun service externe, et n'efface rien sans confirmation.
#
#  Codes de sortie (contrat §8) : 0 succès, 1 erreur, 2 usage,
#  3 vérification négative (intégrité ou chaîne d'audit compromise).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation (mêmes conventions qu'install.sh)
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="backup.sh"
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

# Affiche une commande sans l'exécuter (mode --dry-run).
log_dry() {
  printf '    %s[dry-run]%s' "${C_DIM}" "${C_RESET}"
  printf ' %q' "$@"
  printf '\n'
}

# Toute opération qui MODIFIE le système passe par ici : jamais exécutée en
# --dry-run. Les vérifications (lecture seule) ne passent PAS par ici : elles
# doivent s'exécuter réellement pour avoir une valeur.
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
  log_error "Aucune rotation n'a été appliquée : les archives existantes sont intactes."
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
# Répertoire de travail déclaré dans scripts/thotsecure.service : une URL SQLite
# relative y est résolue par le service, on applique donc la même règle ici.
readonly SERVICE_WORKDIR="${DATA_DIR}"
readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3
readonly DEFAULT_KEEP=14

# -----------------------------------------------------------------------------
# 3. Options
# -----------------------------------------------------------------------------
DRY_RUN="false"
ASSUME_YES="false"
BACKUP_DIR="${THOT_BACKUP_DIR:-/var/backups/thotsecure}"
DB_FILE=""
KEEP="${THOT_BACKUP_KEEP:-${DEFAULT_KEEP}}"
ENCRYPT="auto"            # auto | none | age | gpg
RECIPIENT="${THOT_BACKUP_RECIPIENT:-}"
AUDIT_VERIFY="true"
AUDIT_TENANT=""
CLI_BIN=""
VERIFY_STATUS="ok"        # ok | skipped | inconclusive | chain_broken
INTEGRITY_STATUS="ok"     # ok | original_corrompu
ARCHIVE_PATH=""
ARCHIVE_GLOB="thotsecure-backup-*"
SEAL_DIGEST=""
TMP_DIR=""

usage() {
  cat <<'AIDE'
Thot Secure — sauvegarde cohérente de la base et du journal d'audit.

USAGE
    sudo scripts/backup.sh [options]

OPTIONS
    --db <fichier>        Base SQLite à sauvegarder. Par défaut : la valeur de
                          THOT_DB_URL lue dans /etc/thotsecure/thotsecure.env,
                          sinon /var/lib/thotsecure/thotsecure.db.
    --backup-dir <dir>    Répertoire des archives (défaut : /var/backups/thotsecure,
                          surchargeable par THOT_BACKUP_DIR).
    --keep <N>            Nombre d'archives conservées (défaut : 14 ; 0 = illimité).
    --encrypt <mode>      Chiffrement de l'archive : auto | age | gpg | none
                          (défaut : auto — chiffre si un outil ET un destinataire
                          sont disponibles, sinon le signale).
    --recipient <id>      Destinataire du chiffrement : clé publique age, ou
                          empreinte/identifiant de clé GPG. À VÉRIFIER par un
                          canal indépendant avant tout usage réel.
    --no-encrypt          Raccourci pour --encrypt none (archive en clair, 0600).
    --audit-tenant <id>   Limiter la vérification de la chaîne à un tenant.
    --no-audit-verify     Ne pas vérifier la chaîne d'audit (déconseillé : la
                          sauvegarde ne serait plus une preuve d'intégrité).
    --cli <chemin>        Binaire de la CLI (défaut : détection automatique).
    --yes                 Ne poser aucune question (automatisation : rotation).
    --dry-run             Afficher les opérations sans rien créer ni supprimer.
    -h, --help            Afficher cette aide.

CODES DE SORTIE
    0 réussite · 1 erreur · 2 usage · 3 vérification négative
    (intégrité de la base ou chaîne d'audit compromise).

SÛRETÉ
    * La copie utilise l'API .backup() de SQLite : jamais un « cp » d'un fichier
      en cours d'écriture.
    * Si la chaîne d'audit est rompue, l'archive est marquée « SUSPECT », le
      script le signale BRUYAMMENT et sort en code 3. Conservez-la (c'est une
      pièce à conviction) et traitez l'incident.
    * Thot Secure est strictement défensif : ce script ne modifie aucune variable
      THOT_DRY_RUN / THOT_AUTONOMY. Lisez-le avant de l'exécuter en root.

EXEMPLES
    sudo scripts/backup.sh --dry-run
    sudo scripts/backup.sh --keep 30 --recipient age1qy... --yes
    sudo scripts/backup.sh --db ./data/thotsecure.db --backup-dir ./backups
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db)
        [[ $# -ge 2 ]] || die "--db exige un chemin de fichier." "${EXIT_USAGE}"
        DB_FILE="$2"; shift 2 ;;
      --backup-dir)
        [[ $# -ge 2 ]] || die "--backup-dir exige un chemin." "${EXIT_USAGE}"
        BACKUP_DIR="$2"; shift 2 ;;
      --keep)
        [[ $# -ge 2 ]] || die "--keep exige un nombre." "${EXIT_USAGE}"
        KEEP="$2"; shift 2 ;;
      --encrypt)
        [[ $# -ge 2 ]] || die "--encrypt exige un mode (auto|age|gpg|none)." "${EXIT_USAGE}"
        ENCRYPT="$2"; shift 2 ;;
      --recipient)
        [[ $# -ge 2 ]] || die "--recipient exige un identifiant de destinataire." "${EXIT_USAGE}"
        RECIPIENT="$2"; shift 2 ;;
      --no-encrypt)     ENCRYPT="none"; shift ;;
      --audit-tenant)
        [[ $# -ge 2 ]] || die "--audit-tenant exige un identifiant de tenant." "${EXIT_USAGE}"
        AUDIT_TENANT="$2"; shift 2 ;;
      --no-audit-verify) AUDIT_VERIFY="false"; shift ;;
      --cli)
        [[ $# -ge 2 ]] || die "--cli exige un chemin." "${EXIT_USAGE}"
        CLI_BIN="$2"; shift 2 ;;
      --yes)     ASSUME_YES="true"; shift ;;
      --dry-run) DRY_RUN="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  case "${ENCRYPT}" in
    auto|none|age|gpg) : ;;
    *) die "--encrypt attend auto, age, gpg ou none (reçu : ${ENCRYPT})." "${EXIT_USAGE}" ;;
  esac
  if [[ ! "${KEEP}" =~ ^[0-9]+$ ]]; then
    die "--keep attend un entier positif ou nul (reçu : ${KEEP})." "${EXIT_USAGE}"
  fi
  if [[ "${ENCRYPT}" =~ ^(age|gpg)$ && -z "${RECIPIENT}" ]]; then
    die "--encrypt ${ENCRYPT} exige --recipient (clé publique ou empreinte GPG)." "${EXIT_USAGE}"
  fi
}

# -----------------------------------------------------------------------------
# 4. Prérequis et utilitaires
# -----------------------------------------------------------------------------
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

check_prerequisites() {
  local missing=0
  need_cmd python3 "Python 3.11+ est requis (module standard sqlite3 pour la copie cohérente)." \
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
  # sha256_of <fichier> → condensé hexadécimal en minuscules.
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
  # Crée un répertoire privé. En root, propriété root:root ; sinon (sauvegarde
  # lancée par le compte de service, ou vers un disque amovible monté par
  # l'exploitant) on se contente de restreindre les droits.
  local dir="$1" mode="${2:-0700}"
  if [[ -d "${dir}" ]]; then
    return 0
  fi
  if [[ "${EUID}" -eq 0 ]]; then
    run install -d -o root -g root -m "${mode}" "${dir}"
  else
    log_warn "Exécution sans root : ${dir} sera créé avec les droits de $(id -un)."
    log_step "Vérifiez que ce répertoire n'est pas lisible par d'autres comptes (chmod ${mode})."
    run mkdir -p "${dir}"
    run chmod "${mode}" "${dir}"
  fi
}

file_mode() {
  # file_mode <chemin> → mode octal (ex. 600). Portable Linux/macOS.
  local path="$1" mode=""
  mode="$(stat -c '%a' "${path}" 2>/dev/null || true)"
  if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
    mode="$(stat -f '%Lp' "${path}" 2>/dev/null || true)"
  fi
  printf '%s\n' "${mode:-inconnu}"
}

file_owner() {
  local path="$1" owner=""
  owner="$(stat -c '%U:%G' "${path}" 2>/dev/null || true)"
  if [[ -z "${owner}" ]]; then
    owner="$(stat -f '%Su:%Sg' "${path}" 2>/dev/null || true)"
  fi
  printf '%s\n' "${owner:-inconnu}"
}

sizeof_human() {
  local file="$1" bytes=""
  bytes="$(wc -c < "${file}" | tr -d ' ')"
  printf '%s octets' "${bytes}"
}

# Demande une confirmation EXPLICITE avant toute opération destructive.
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

# Exécute la CLI applicative en tant que compte de service lorsqu'on est root :
# la base et le journal d'audit appartiennent à `thotsecure`, pas à root.
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
  # Cherche la CLI réelle. Un seul nom de commande est installé (« thotsecure ») ;
  # le nom historique n'est plus posé par install.sh depuis le renommage global.
  if [[ -n "${CLI_BIN}" ]]; then
    [[ -x "${CLI_BIN}" ]] || die "CLI introuvable ou non exécutable : ${CLI_BIN}." 1
    printf '%s\n' "${CLI_BIN}"
    return 0
  fi
  local candidate
  for candidate in \
      "${VENV_DIR}/bin/${SERVICE_NAME}" \
      "/usr/local/bin/${SERVICE_NAME}"
  do
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
# 5. Résolution de la base à sauvegarder
# -----------------------------------------------------------------------------
db_url_from_env_file() {
  [[ -r "${ENV_FILE}" ]] || return 1
  local url
  # Aucune évaluation de code : simple extraction textuelle de la dernière ligne.
  url="$(sed -n 's/^THOT_DB_URL=//p' "${ENV_FILE}" 2>/dev/null | tail -n 1)"
  [[ -n "${url}" ]] || return 1
  printf '%s\n' "${url}"
}

# sqlite:///./data/thotsecure.db     → ./data/thotsecure.db
# sqlite:////var/lib/thotsecure/x.db → /var/lib/thotsecure/x.db
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
    log_step "Base imposée par --db : ${DB_FILE}"
    return 0
  fi

  local url="" path=""
  if url="$(db_url_from_env_file)"; then
    log_step "THOT_DB_URL lue dans ${ENV_FILE} : ${url}"
    if ! path="$(sqlite_path_from_url "${url}")"; then
      die "THOT_DB_URL n'est pas une URL SQLite (${url}).
Pour PostgreSQL/TimescaleDB, utilisez pg_dump + pg_restore (documenté dans
docs/operations/deployment.md) ; ce script ne gère que SQLite (MVP)." 1
    fi
  else
    path="${DB_DEFAULT}"
    log_step "Aucune THOT_DB_URL lisible : base par défaut ${DB_DEFAULT}"
    log_warn "Si ${ENV_FILE} existe mais n'est pas lisible, relancez avec sudo (sinon la mauvaise base sera sauvegardée)."
  fi

  # Le service résout une URL relative depuis /var/lib/thotsecure (WorkingDirectory
  # de l'unité systemd) : on applique exactement la même règle.
  if [[ "${path}" != /* ]]; then
    log_step "Chemin relatif : résolu depuis ${SERVICE_WORKDIR} (WorkingDirectory du service)."
    path="${SERVICE_WORKDIR}/${path#./}"
  fi
  DB_FILE="${path}"
}

# -----------------------------------------------------------------------------
# 6. Copie cohérente et contrôle d'intégrité
# -----------------------------------------------------------------------------
coherent_backup() {
  # coherent_backup <source> <destination>
  # Sortie : 0 copie cohérente et intègre · 1 copie impossible ou corrompue ·
  #          3 copie produite MAIS base source déjà endommagée.
  local source="$1" destination="$2"
  local report="" rc=0
  [[ -f "${source}" ]] || die "Base introuvable : ${source}. Vérifiez THOT_DB_URL." 1

  # L'API .backup() de SQLite copie une base COHÉRENTE même sous écritures
  # concurrentes (elle rejoue les pages dans une transaction). La source est
  # ouverte en lecture seule : elle n'est jamais modifiée, même en cas d'erreur.
  set +e
  report="$(python3 - "${source}" "${destination}" <<'PY'
"""Copie cohérente d'une base SQLite (API .backup) + contrôle d'intégrité.

Sortie (paires CLE=valeur relues par backup.sh) :
    original_integrity_ok / copie_brute / copie_integrity_ok

Codes : 0 copie cohérente et intègre · 1 rien d'exploitable n'a été écrit ·
        3 copie produite, mais base source endommagée (archive à marquer SUSPECT).
"""
from __future__ import annotations

import shutil
import sqlite3
import sys

source, destination = sys.argv[1], sys.argv[2]

# Contrôle du MAGIC d'abord : SQLite ouvre sans broncher un fichier court ou sans
# en-tête valide (il le considère comme une base vide) — on ne veut pas
# sauvegarder « une base vide » alors que le fichier est en réalité illisible.
try:
    with open(source, "rb") as handle:
        magic = handle.read(16)
except OSError as exc:
    raise SystemExit(f"lecture impossible ({source}) : {exc}")
if magic[:15] != b"SQLite format 3":
    raise SystemExit(f"ce fichier n'est pas une base SQLite ({source}) : sauvegarde refusée")

try:
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
except sqlite3.Error as exc:  # pragma: no cover - dépend de l'environnement
    raise SystemExit(f"ouverture en lecture seule impossible ({source}) : {exc}")

source_ok = True
raw_copy = False
detail = ""

dst = sqlite3.connect(destination)
try:
    try:
        # Contrôle préalable de l'ORIGINAL : une base déjà corrompue doit être
        # signalée avant d'être recopiée, sinon on archive un problème en silence.
        row = src.execute("PRAGMA integrity_check").fetchone()
        source_ok = bool(row) and row[0] == "ok"
        with dst:
            src.backup(dst)
    except sqlite3.Error as exc:
        # Base illisible ou corrompue : la copie cohérente est impossible. On
        # conserve alors les OCTETS BRUTS, en le disant clairement : en réponse à
        # incident, perdre la donnée serait pire qu'en garder une copie imparfaite.
        source_ok = False
        raw_copy = True
        detail = str(exc)
        print(f"copie_brute_raison={exc}", file=sys.stderr)
finally:
    dst.close()
    src.close()

if raw_copy:
    shutil.copyfile(source, destination)
    copy_ok = False
else:
    probe = sqlite3.connect(destination)
    try:
        row = probe.execute("PRAGMA integrity_check").fetchone()
        copy_ok = bool(row) and row[0] == "ok"
        detail = row[0] if row else "aucun résultat"
    except sqlite3.Error as exc:
        copy_ok = False
        detail = str(exc)
    finally:
        probe.close()

print(f"original_integrity_ok={'oui' if source_ok else 'NON'}")
print(f"copie_brute={'oui' if raw_copy else 'non'}")
print(f"copie_integrity_ok={'oui' if copy_ok else 'NON'}")
if raw_copy:
    raise SystemExit(3)
if not copy_ok:
    print(f"copie_detail={detail}", file=sys.stderr)
    raise SystemExit(1)
if not source_ok:
    raise SystemExit(3)
PY
)"
  rc=$?
  set -e

  # Relecture des paires CLE=valeur : aucune évaluation de code.
  while IFS='=' read -r key value; do
    case "${key}" in
      original_integrity_ok) log_step "intégrité de la base source : ${value}" ;;
      copie_brute)           log_step "copie brute (non cohérente) : ${value}" ;;
      copie_integrity_ok)    log_step "intégrité de la copie       : ${value}" ;;
      *) : ;;
    esac
  done <<< "${report}"

  return "${rc}"
}

# -----------------------------------------------------------------------------
# 7. Vérification de la chaîne d'audit (AVANT de considérer l'archive fiable)
# -----------------------------------------------------------------------------
verify_audit_chain() {
  if [[ "${AUDIT_VERIFY}" != "true" ]]; then
    log_warn "Vérification de la chaîne d'audit désactivée (--no-audit-verify)."
    log_warn "L'archive ne constitue plus une preuve d'intégrité : conservez ce choix par écrit."
    VERIFY_STATUS="skipped"
    return 0
  fi

  local cli=""
  if ! cli="$(resolve_cli)"; then
    log_warn "CLI thotsecure introuvable : impossible de vérifier la chaîne d'audit."
    log_step "Indiquez son chemin avec --cli, ou installez-la (scripts/install.sh)."
    VERIFY_STATUS="inconclusive"
    return 0
  fi

  local -a args=(audit verify)
  if [[ -n "${AUDIT_TENANT}" ]]; then
    args+=(--tenant "${AUDIT_TENANT}")
  fi

  local output_file="${TMP_DIR}/audit-verify.out"
  local rc=0
  log_info "Vérification de la chaîne d'audit (${cli} ${args[*]})…"
  # Vérification en LECTURE SEULE : elle s'exécute réellement, même en --dry-run.
  set +e
  run_as_service "${cli}" "${args[@]}" > "${output_file}" 2>&1
  rc=$?
  set -e

  case "${rc}" in
    0)
      log_ok "Chaîne d'audit intègre."
      log_step "$(tail -n 1 "${output_file}" 2>/dev/null || true)"
      VERIFY_STATUS="ok"
      ;;
    3)
      log_error "CHAÎNE D'AUDIT ROMPUE (sortie 3) : la piste d'audit a été modifiée, tronquée ou rejouée."
      while IFS= read -r line; do log_step "${line}"; done < "${output_file}"
      log_error "INCIDENT DE SÉCURITÉ : traitez-le comme tel (SECURITY.md), ne « réparez » pas la chaîne."
      VERIFY_STATUS="chain_broken"
      ;;
    *)
      log_warn "Vérification de la chaîne d'audit non concluante (code ${rc})."
      while IFS= read -r line; do log_step "${line}"; done < "${output_file}"
      VERIFY_STATUS="inconclusive"
      ;;
  esac
}

# -----------------------------------------------------------------------------
# 8. Chiffrement facultatif (age / gpg) et scellés
# -----------------------------------------------------------------------------
encrypt_archive() {
  # encrypt_archive <archive_en_clair> → chemin final écrit dans ARCHIVE_PATH
  local plain="$1" mode="${ENCRYPT}"

  if [[ "${mode}" == "auto" ]]; then
    if [[ -z "${RECIPIENT}" ]]; then
      log_warn "Aucun --recipient : archive NON chiffrée (mode 0600)."
      log_step "Pour chiffrer : --encrypt age --recipient <clé publique age> (recommandé)."
      ARCHIVE_PATH="${plain}"
      return 0
    fi
    if command -v age >/dev/null 2>&1; then
      mode="age"
    elif command -v gpg >/dev/null 2>&1; then
      mode="gpg"
    else
      log_warn "Aucun outil de chiffrement (age, gpg) : archive NON chiffrée (mode 0600)."
      ARCHIVE_PATH="${plain}"
      return 0
    fi
  fi

  if [[ "${mode}" == "none" ]]; then
    log_warn "Chiffrement désactivé : la sauvegarde est en clair (0600).
Une sauvegarde en clair contient la base ET le journal d'audit : traitez-la comme un secret."
    ARCHIVE_PATH="${plain}"
    return 0
  fi

  local target="${plain}.${mode}"
  case "${mode}" in
    age)
      need_cmd age "Installez age (age-encryption.org) ou utilisez --encrypt gpg." \
        || die "age est requis." 1
      log_info "Chiffrement age → ${target}"
      # -r : clé publique du destinataire. L'empreinte doit être vérifiée par un
      # canal indépendant : une clé substituée rend la sauvegarde illisible.
      run age --encrypt --recipient "${RECIPIENT}" --output "${target}" "${plain}"
      ;;
    gpg)
      need_cmd gpg "Installez GnuPG ou utilisez --encrypt age." || die "gpg est requis." 1
      log_warn "GPG : la clé « ${RECIPIENT} » doit être vérifiée (empreinte) avant tout usage réel."
      log_info "Chiffrement GPG → ${target}"
      # --trust-model always : nécessaire pour une clé non signée localement.
      # Sans vérification d'empreinte hors bande, ce choix n'apporte aucune garantie.
      run gpg --batch --yes --no-tty --trust-model always \
        --recipient "${RECIPIENT}" --output "${target}" --encrypt "${plain}"
      ;;
  esac

  if [[ "${DRY_RUN}" == "true" ]]; then
    ARCHIVE_PATH="${target}"
    return 0
  fi
  [[ -s "${target}" ]] || die "Chiffrement échoué : ${target} est vide ou absent." 1
  chmod 0600 "${target}"
  # L'archive en clair ne doit pas subsister : on efface le temporaire.
  rm -f "${plain}"
  log_ok "Archive chiffrée : $(basename "${target}") ($(sizeof_human "${target}"))"
  ARCHIVE_PATH="${target}"
}

write_seals() {
  # write_seals <archive> : condensé SHA-256 + fiche de métadonnées (sans secret).
  # Le condensé est publié par la variable globale SEAL_DIGEST, jamais sur la
  # sortie standard : les messages lisibles y sont déjà écrits, et une capture
  # « digest="$(write_seals …)" » mélangerait les deux (bug classique de bash).
  local archive="$1"
  local digest=""
  digest="$(sha256_of "${archive}")"
  local name=""
  name="$(basename "${archive}")"
  SEAL_DIGEST="${digest}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry write "${archive}.sha256" "« ${digest}  ${name} »"
    log_dry write "${archive}.meta"
    return 0
  fi

  # Format compatible « sha256sum -c » : scripts/restore.sh s'en sert tel quel.
  printf '%s  %s\n' "${digest}" "${name}" > "${archive}.sha256"
  chmod 0600 "${archive}.sha256"

  {
    printf 'archive=%s\n' "${name}"
    printf 'sha256=%s\n' "${digest}"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'host=%s\n' "$(hostname 2>/dev/null || printf 'inconnu')"
    printf 'source_db=%s\n' "${DB_FILE}"
    printf 'bytes=%s\n' "$(wc -c < "${archive}" | tr -d ' ')"
    printf 'integrity_check=%s\n' "${INTEGRITY_STATUS}"
    printf 'audit_chain=%s\n' "${VERIFY_STATUS}"
    printf 'encryption=%s\n' "${ENCRYPTION_USED}"
    printf 'script_version=%s\n' "${SCRIPT_VERSION}"
    printf '# Fiche de métadonnées de sauvegarde Thot Secure. Aucun secret.\n'
  } > "${archive}.meta"
  chmod 0600 "${archive}.meta"

  log_ok "Scellés écrits : $(basename "${archive}").sha256, $(basename "${archive}").meta"
}

# -----------------------------------------------------------------------------
# 9. Rotation (destructive → listée puis confirmée)
# -----------------------------------------------------------------------------
list_archives() {
  # Liste les archives du plus récent au plus ancien. Le nom contient
  # l'horodatage UTC : l'ordre lexicographique est donc l'ordre chronologique.
  local candidate=""
  if [[ ! -d "${BACKUP_DIR}" ]]; then
    return 0
  fi
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    printf '%s\n' "${candidate}"
  done < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -name "${ARCHIVE_GLOB}" \
             ! -name '*.sha256' ! -name '*.meta' -print 2>/dev/null | LC_ALL=C sort -r)
}

rotate_archives() {
  if [[ "${KEEP}" == "0" ]]; then
    log_step "Rotation illimitée (--keep 0) : aucune archive supprimée."
    return 0
  fi

  local -a all=()
  while IFS= read -r line; do
    [[ -n "${line}" ]] && all+=("${line}")
  done < <(list_archives)

  local total="${#all[@]}"
  if [[ "${total}" -le "${KEEP}" ]]; then
    log_ok "Rotation : ${total} archive(s) pour une limite de ${KEEP} — rien à supprimer."
    return 0
  fi

  local -a doomed=()
  local index
  for (( index = KEEP; index < total; index++ )); do
    doomed+=("${all[index]}")
  done

  log_warn "Rotation : ${#doomed[@]} archive(s) au-delà de la limite de ${KEEP} :"
  local file
  for file in "${doomed[@]}"; do
    log_step "$(basename "${file}")  ($(sizeof_human "${file}"), mode $(file_mode "${file}"))"
  done

  if [[ "${DRY_RUN}" == "true" ]]; then
    for file in "${doomed[@]}"; do
      log_dry rm -f "${file}" "${file}.sha256" "${file}.meta"
    done
    return 0
  fi

  if ! confirm "Supprimer DÉFINITIVEMENT ces ${#doomed[@]} archive(s) (et leurs scellés) ?"; then
    log_warn "Rotation annulée : toutes les archives sont conservées."
    return 0
  fi

  for file in "${doomed[@]}"; do
    run rm -f "${file}" "${file}.sha256" "${file}.meta"
    log_step "Supprimée : $(basename "${file}")"
  done
  log_ok "Rotation terminée : ${KEEP} archive(s) conservée(s)."
}

# -----------------------------------------------------------------------------
# 10. Rapport final
# -----------------------------------------------------------------------------
report_suspect() {
  # Message BRUYANT : un journal d'audit compromis est un incident, pas un détail.
  printf '\n' >&2
  log_error "==================================================================="
  log_error " SAUVEGARDE SUSPECTE — INTÉGRITÉ COMPROMISE"
  log_error "==================================================================="
  log_error "La chaîne d'audit chaînée par hash NE VÉRIFIE PAS sur cette base."
  log_error "Conséquences : le journal a peut-être été modifié, tronqué ou rejoué"
  log_error "après coup. La valeur probante de cette archive est NULLE."
  log_step "1. NE supprimez rien : l'archive ${ARCHIVE_PATH:-?} est une pièce à conviction."
  log_step "2. Isolez l'hôte et préservez les journaux (journalctl, syslog)."
  log_step "3. Appliquez la procédure de réponse à incident (SECURITY.md)."
  log_step "4. Ne « reconstruisez » jamais la chaîne : la rupture est l'information."
  log_step "5. Ne restaurez PAS cette base sur une production sans décision explicite."
  printf '\n' >&2
}

main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter en root."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "MODE --dry-run : aucune archive ne sera créée, aucune rotation appliquée."
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/thotsecure-backup.XXXXXX")"
  # shellcheck disable=SC2064  # expansion volontaire à la définition du piège
  trap "rm -rf '${TMP_DIR}'" EXIT

  check_prerequisites
  resolve_db_file

  # Archives de CE script uniquement : on ne touche jamais aux sauvegardes
  # produites ailleurs (uninstall.sh, sauvegardes manuelles, archives du SIEM).
  ARCHIVE_GLOB="thotsecure-backup-*"

  local stamp=""
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local base="${BACKUP_DIR}/thotsecure-backup-${stamp}.db"

  log_info "Plan de sauvegarde :"
  log_step "base source  : ${DB_FILE} (mode $(file_mode "${DB_FILE}" 2>/dev/null || printf 'inconnu'))"
  log_step "destination  : ${base}"
  log_step "rotation     : ${KEEP} archive(s) conservée(s)"
  log_step "chiffrement  : ${ENCRYPT}${RECIPIENT:+ (destinataire : ${RECIPIENT})}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry install -d -o root -g root -m 0700 "${BACKUP_DIR}"
    log_dry python3 "<copie cohérente .backup()>" "${DB_FILE}" "${base}"
    log_dry "${AUDIT_VERIFY:+thotsecure audit verify}"
    log_dry write "${base}.sha256" "${base}.meta"
  else
    # 0700 : la sauvegarde contient les données client ET la piste d'audit.
    ensure_private_dir "${BACKUP_DIR}" "0700"
    # Refus d'écraser une archive existante (horodatage identique = relance dans
    # la même seconde) : on ne perd jamais une sauvegarde par accident.
    [[ ! -e "${base}" ]] || die "L'archive ${base} existe déjà : relancez dans une seconde." 1
  fi

  INTEGRITY_STATUS="ok"
  local rc=0
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry python3 - "${DB_FILE}" "${base}"
  else
    log_info "Copie cohérente de la base (API .backup de SQLite)…"
    set +e
    coherent_backup "${DB_FILE}" "${base}"
    rc=$?
    set -e
    case "${rc}" in
      0) log_ok "Copie cohérente : $(basename "${base}") ($(sizeof_human "${base}"))" ;;
      3)
        INTEGRITY_STATUS="original_corrompu"
        log_error "La base SOURCE est endommagée : elle échoue à PRAGMA integrity_check."
        log_warn "Une copie a été produite malgré tout (cohérente si possible, brute sinon),"
        log_warn "pour analyse post-incident : elle est marquée SUSPECT et le script sortira en 3."
        ;;
      *)
        die "Copie de la base impossible : ${DB_FILE} est peut-être en cours de reconstruction. Aucune archive fiable n'a été écrite." 1
        ;;
    esac
  fi

  verify_audit_chain

  local digest=""
  ENCRYPTION_USED="aucun"
  if [[ "${DRY_RUN}" == "true" ]]; then
    ARCHIVE_PATH="${base}"
    write_seals "${base}"
  else
    chmod 0600 "${base}"
    encrypt_archive "${base}"
    case "${ARCHIVE_PATH}" in
      *.age) ENCRYPTION_USED="age" ;;
      *.gpg) ENCRYPTION_USED="gpg" ;;
      *)     ENCRYPTION_USED="aucun" ;;
    esac

    # Une archive DÉMONTRÉE douteuse est renommée : impossible de la confondre
    # avec une sauvegarde saine lors d'une restauration d'urgence. Une archive
    # simplement NON vérifiée (CLI absente, --no-audit-verify) garde son nom :
    # elle n'est pas suspecte, elle est non prouvée — et son .meta le dit.
    if [[ "${VERIFY_STATUS}" == "chain_broken" || "${INTEGRITY_STATUS}" != "ok" ]]; then
      local suspect="${ARCHIVE_PATH}.SUSPECT"
      mv -f "${ARCHIVE_PATH}" "${suspect}"
      ARCHIVE_PATH="${suspect}"
      log_warn "Archive renommée : $(basename "${ARCHIVE_PATH}")"
    fi

    write_seals "${ARCHIVE_PATH}"
    digest="${SEAL_DIGEST}"
    # Contrôle final : l'archive est relue et son condensé recomparé.
    local recheck=""
    recheck="$(sha256_of "${ARCHIVE_PATH}")"
    [[ "${recheck}" == "${digest}" ]] \
      || die "Le condensé de l'archive ne se relit pas à l'identique : sauvegarde NON fiable." "${EXIT_VERIFY}"
    log_ok "Condensé vérifié après écriture : ${digest}"
  fi

  rotate_archives

  if [[ "${VERIFY_STATUS}" == "chain_broken" || "${INTEGRITY_STATUS}" != "ok" ]]; then
    report_suspect
    exit "${EXIT_VERIFY}"
  fi

  printf '\n'
  log_ok "Sauvegarde terminée : ${ARCHIVE_PATH}"
  log_step "Restauration  : sudo scripts/restore.sh --archive ${ARCHIVE_PATH}"
  log_step "Vérification  : sudo scripts/restore.sh --archive ${ARCHIVE_PATH} --dry-run"
  case "${VERIFY_STATUS}" in
    skipped)
      log_warn "Chaîne d'audit NON vérifiée sur demande (--no-audit-verify) :"
      log_warn "l'archive existe, mais aucune preuve d'intégrité de la piste d'audit n'y est attachée."
      ;;
    inconclusive)
      log_warn "Chaîne d'audit NON vérifiée : la CLI « thotsecure » est absente ou en erreur."
      log_warn "Corrigez l'installation (« thotsecure doctor ») puis relancez la sauvegarde."
      exit 1
      ;;
  esac
}

main "$@"
