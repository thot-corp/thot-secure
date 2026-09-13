#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/hardening-check.sh
# -----------------------------------------------------------------------------
#  CONTRÔLE DE DURCISSEMENT DE L'HÔTE (et non de l'application).
#
#  Le diagnostic applicatif, c'est « thotsecure doctor » : il regarde la base,
#  les règles, les politiques, les connecteurs et la chaîne d'audit. Ce script-ci
#  regarde la MACHINE : permissions des données, secrets, compte de service,
#  exposition réseau, unité systemd, absence de fuite de secret dans les journaux.
#
#  Aucune correction n'est appliquée : le script ne fait que constater et
#  proposer une remédiation. Un outil qui « répare » tout seul un durcissement
#  d'hôte sans revue préalable est un outil qui casse des serveurs en production.
#
#  INSPIRATION : recommandations CIS Benchmarks (distribution Linux, services)
#  et guides ANSSI (hygiène informatique, recommandations de sécurité relatives
#  à un serveur GNU/Linux). Ce script NE PRÉTEND À AUCUNE CERTIFICATION ni à une
#  conformité complète à un référentiel : c'est une aide au diagnostic, et le
#  jugement de l'exploitant reste la référence.
#
#  Codes de sortie (contrat §8) : 0 succès, 1 erreur, 2 usage,
#  3 vérification négative (au moins un contrôle CRITIQUE en échec).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation (mêmes conventions qu'install.sh)
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="hardening-check.sh"
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

die() {
  log_error "${1}"
  exit "${2:-1}"
}

on_error() {
  log_error "Échec de ${SCRIPT_NAME} à la ligne ${1} (code ${2})."
  log_error "Le contrôle est incomplet : le résultat ne doit pas être considéré comme concluant."
  exit "${2}"
}
trap 'on_error "${LINENO}" "$?"' ERR

# -----------------------------------------------------------------------------
# 2. Constantes (miroir de deploy/ansible/roles/thotsecure/defaults/main.yml)
# -----------------------------------------------------------------------------
readonly SERVICE_NAME="thotsecure"
readonly SERVICE_USER="thotsecure"
readonly SERVICE_GROUP="thotsecure"
readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3
#: Clé d'amorçage publique livrée en développement : présente en production = alerte.
readonly DEV_BOOTSTRAP_KEY="thot_BOOTSTRAP_changemebeforefirstuse"

# -----------------------------------------------------------------------------
# 3. Options
# -----------------------------------------------------------------------------
ETC_DIR="/etc/thotsecure"
DATA_DIR="/var/lib/thotsecure"
LOG_DIR="/var/log/thotsecure"
ENV_FILE="/etc/thotsecure/thotsecure.env"
BACKUP_DIR="${THOT_BACKUP_DIR:-/var/backups/thotsecure}"
UNIT_FILE="/etc/systemd/system/thotsecure.service"
JSON_OUT="false"
QUIET="false"
VERBOSE="false"
ENV_FILE_SET="false"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
RESULTS=()

usage() {
  cat <<'AIDE'
Thot Secure — contrôle de durcissement de l'hôte (diagnostic, sans correction).

USAGE
    sudo scripts/hardening-check.sh [options]

OPTIONS
    --etc-dir <dir>       Répertoire de configuration (défaut : /etc/thotsecure).
    --env-file <fichier>  Fichier d'environnement contenant THOT_SECRET_KEY
                          (défaut : /etc/thotsecure/thotsecure.env).
    --data-dir <dir>      Répertoire de données (défaut : /var/lib/thotsecure).
    --log-dir <dir>       Répertoire de journaux (défaut : /var/log/thotsecure).
    --backup-dir <dir>    Répertoire des sauvegardes (défaut : /var/backups/thotsecure).
    --unit <fichier>      Unité systemd à contrôler (défaut : /etc/systemd/system/thotsecure.service).
    --json                Sortie JSON (automatisation, CI).
    --quiet               N'afficher que les avertissements et les échecs.
    --verbose             Afficher aussi le détail des contrôles réussis.
    -h, --help            Afficher cette aide.

CONTRÔLES
    HOST-01  permissions du répertoire de données            (critique)
    HOST-02  permissions de la base SQLite et de ses -wal/-shm (critique)
    HOST-03  fichier d'environnement : présence, propriétaire, 0600 (critique)
    HOST-04  secrets : THOT_SECRET_KEY définie, clé d'amorçage remplacée (critique)
    HOST-05  compte de service dédié, non-root, sans shell de connexion (critique)
    HOST-06  processus du service : propriétaire réel non-root      (critique)
    HOST-07  aucun secret en clair dans les journaux               (critique)
    HOST-08  exposition réseau : pas de 0.0.0.0 en clair sans TLS ni proxy (critique)
    HOST-09  unité systemd durcie (directives de confinement)       (critique)
    HOST-10  /etc/thotsecure non inscriptible par le service / le monde (critique)
    HOST-11  répertoire de sauvegardes privé (0700)                 (avertissement)
    HOST-12  sauvegardes planifiées (timer systemd ou cron)         (avertissement)
    HOST-13  chiffrement au repos (disque ou sauvegardes chiffrées) (avertissement)
    HOST-14  durcissement noyau (sysctl : dmesg, kptr, ASLR, symlinks) (avertissement)
    HOST-15  journalisation systemd persistante                     (avertissement)
    HOST-16  état des garde-fous du service (simulation / autonomie) (information)

CODES DE SORTIE
    0 aucun échec critique · 1 erreur · 2 usage · 3 au moins un contrôle
    CRITIQUE en échec (les avertissements ne font pas échouer le script).

AVERTISSEMENT
    Inspiré des recommandations CIS et ANSSI ; ne constitue PAS une certification
    ni une preuve de conformité. Aucun contrôle n'est corrigé automatiquement :
    chaque remédiation doit être revue avant d'être appliquée à un serveur en
    production. Lisez ce script avant de l'exécuter en root.
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --etc-dir)
        [[ $# -ge 2 ]] || die "--etc-dir exige un chemin." "${EXIT_USAGE}"
        ETC_DIR="$2"; shift 2 ;;
      --env-file)
        [[ $# -ge 2 ]] || die "--env-file exige un chemin." "${EXIT_USAGE}"
        ENV_FILE="$2"; ENV_FILE_SET="true"; shift 2 ;;
      --data-dir)
        [[ $# -ge 2 ]] || die "--data-dir exige un chemin." "${EXIT_USAGE}"
        DATA_DIR="$2"; shift 2 ;;
      --log-dir)
        [[ $# -ge 2 ]] || die "--log-dir exige un chemin." "${EXIT_USAGE}"
        LOG_DIR="$2"; shift 2 ;;
      --backup-dir)
        [[ $# -ge 2 ]] || die "--backup-dir exige un chemin." "${EXIT_USAGE}"
        BACKUP_DIR="$2"; shift 2 ;;
      --unit)
        [[ $# -ge 2 ]] || die "--unit exige un chemin." "${EXIT_USAGE}"
        UNIT_FILE="$2"; shift 2 ;;
      --json)    JSON_OUT="true"; shift ;;
      --quiet)   QUIET="true"; shift ;;
      --verbose) VERBOSE="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  # Si --etc-dir a été fourni sans --env-file, le fichier d'environnement est
  # attendu DANS ce répertoire : sinon un contrôle sur une installation déplacée
  # regarderait /etc/thotsecure et conclurait à tort que rien n'est configuré.
  if [[ "${ENV_FILE_SET}" != "true" ]]; then
    ENV_FILE="${ETC_DIR}/thotsecure.env"
  fi
}

# -----------------------------------------------------------------------------
# 4. Utilitaires de constat
# -----------------------------------------------------------------------------
json_escape() {
  # Les détails peuvent contenir des retours à la ligne (tableaux joints par IFS)
  # ou des tabulations : on les ramène à des espaces, sinon la sortie JSON serait
  # invalide (une chaîne JSON n'accepte pas de saut de ligne littéral).
  printf '%s' "$1" | tr '\n\t' '  ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g'
}

record() {
  # record <OK|WARN|FAIL> <identifiant> <libellé> <détail>
  local status="$1" id="$2" label="$3" detail="$4"
  local colour="${C_GREEN}" marker=" OK "

  case "${status}" in
    OK)   PASS_COUNT=$(( PASS_COUNT + 1 )); colour="${C_GREEN}";  marker=" OK " ;;
    WARN) WARN_COUNT=$(( WARN_COUNT + 1 )); colour="${C_YELLOW}"; marker="WARN" ;;
    FAIL) FAIL_COUNT=$(( FAIL_COUNT + 1 )); colour="${C_RED}";    marker="FAIL" ;;
    *) die "Statut interne inconnu : ${status}" 1 ;;
  esac

  RESULTS+=("${status}|${id}|${label}|${detail}")

  if [[ "${JSON_OUT}" == "true" ]]; then
    return 0
  fi
  if [[ "${QUIET}" == "true" && "${status}" == "OK" ]]; then
    return 0
  fi
  if [[ "${VERBOSE}" != "true" && "${status}" == "OK" ]]; then
    printf '  %s%s%s %-8s %s\n' "${colour}${C_BOLD}" "[ OK ]" "${C_RESET}" "${id}" "${label}"
    return 0
  fi
  printf '%s%s%s %-8s %s\n' "${colour}${C_BOLD}" "[${marker}]" "${C_RESET}" "${id}" "${label}"
  printf '        %s%s%s\n' "${C_DIM}" "${detail}" "${C_RESET}"
}

file_mode() {
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

# perm_group/perm_other extraient les chiffres de droits (compatibles mode 4 chiffres).
perm_group() { local m="$1"; [[ "${m}" =~ ^[0-7]{3,4}$ ]] || { printf '?' ; return; }; printf '%s' "${m: -2:1}"; }
perm_other() { local m="$1"; [[ "${m}" =~ ^[0-7]{3,4}$ ]] || { printf '?' ; return; }; printf '%s' "${m: -1}"; }

# Vrai si le chiffre de droits contient une permission d'écriture.
# Une comparaison de motifs (case) plutôt qu'une expression régulière : c'est
# plus lisible et cela évite toute ambiguïté de citation dans « [[ ]] ».
digit_writable() {
  case "$1" in
    *[2367]*) return 0 ;;
    *) return 1 ;;
  esac
}
# Vrai si le chiffre de droits contient une permission de lecture.
digit_readable() {
  case "$1" in
    *[4567]*) return 0 ;;
    *) return 1 ;;
  esac
}

env_value() {
  # env_value <variable> : dernière valeur déclarée dans le fichier d'environnement.
  local key="$1"
  [[ -r "${ENV_FILE}" ]] || return 1
  local value
  value="$(sed -n "s/^${key}=//p" "${ENV_FILE}" 2>/dev/null | tail -n 1)"
  [[ -n "${value}" ]] || return 1
  printf '%s\n' "${value}"
}

sysctl_value() {
  # sysctl_value <clé> : valeur lue dans /proc/sys (lecture directe, sans sysctl).
  local key="$1" path=""
  path="/proc/sys/$(printf '%s' "${key}" | tr '.' '/')"
  [[ -r "${path}" ]] || return 1
  tr -d ' \n' < "${path}"
}

unit_value() {
  # unit_value <directive> [fichier] : dernière valeur déclarée dans un fichier
  # d'unité systemd. Aucune évaluation de code, simple extraction textuelle.
  local key="$1" file="${2:-${UNIT_FILE}}" value=""
  [[ -r "${file}" ]] || return 0
  value="$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "${file}" 2>/dev/null | tail -n 1)"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s\n' "${value}"
}

is_boolean_yes() {
  # systemd accepte plusieurs écritures pour un booléen : « yes », « true », « 1 »,
  # « on ». Les comparer littéralement à « yes » produirait de faux échecs.
  case "$1" in
    yes|YES|true|TRUE|1|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

# -----------------------------------------------------------------------------
# 5. HOST-01 / HOST-02 : données et base
# -----------------------------------------------------------------------------
check_data_dir() {
  local id="HOST-01"
  if [[ ! -e "${DATA_DIR}" ]]; then
    record "FAIL" "${id}" "Répertoire de données absent" \
      "${DATA_DIR} n'existe pas : l'installation n'est pas terminée (scripts/install.sh)."
    return 0
  fi
  local mode owner detail=""
  mode="$(file_mode "${DATA_DIR}")"
  owner="$(file_owner "${DATA_DIR}")"
  detail="${DATA_DIR}  mode ${mode}  propriétaire ${owner}"

  if [[ "${mode}" == "inconnu" ]]; then
    record "WARN" "${id}" "Permissions du répertoire de données illisibles" \
      "${detail} — relancez en root pour un contrôle fiable."
    return 0
  fi
  local group other
  group="$(perm_group "${mode}")"
  other="$(perm_other "${mode}")"

  if digit_writable "${other}"; then
    record "FAIL" "${id}" "Répertoire de données inscriptible par TOUT LE MONDE" \
      "${detail} — remédiation : chmod o-w ${DATA_DIR} (les données client et la piste d'audit y vivent)."
    return 0
  fi
  if digit_writable "${group}"; then
    record "FAIL" "${id}" "Répertoire de données inscriptible par le groupe" \
      "${detail} — remédiation : chmod g-w ${DATA_DIR} ; seuls root et ${SERVICE_USER} doivent écrire."
    return 0
  fi
  if digit_readable "${other}"; then
    record "WARN" "${id}" "Répertoire de données lisible par tous" \
      "${detail} — remédiation : chmod 0750 ${DATA_DIR} (les noms de fichiers révèlent déjà des informations)."
    return 0
  fi
  if [[ "${mode}" != "750" && "${mode}" != "700" && "${mode}" != "2750" ]]; then
    record "WARN" "${id}" "Permissions du répertoire de données inhabituelles" \
      "${detail} — attendu : 0750 ${SERVICE_USER}:${SERVICE_GROUP}."
    return 0
  fi
  if [[ "${owner}" != "${SERVICE_USER}:${SERVICE_GROUP}" ]]; then
    record "WARN" "${id}" "Propriétaire du répertoire de données inattendu" \
      "${detail} — attendu : ${SERVICE_USER}:${SERVICE_GROUP}."
    return 0
  fi
  record "OK" "${id}" "Permissions du répertoire de données" "${detail}"
}

check_database() {
  local id="HOST-02" db="" mode="" owner="" found=0
  # La base peut porter plusieurs noms selon la version : on contrôle tous les
  # fichiers .db du répertoire de données plutôt que de parier sur un seul nom.
  local candidate=""
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    found=1
    mode="$(file_mode "${candidate}")"
    owner="$(file_owner "${candidate}")"
    if [[ "${mode}" != "600" ]]; then
      record "FAIL" "${id}" "Base SQLite non privée : $(basename "${candidate}")" \
        "mode ${mode} (attendu 600), propriétaire ${owner} — remédiation : chmod 600 ${candidate}"
      continue
    fi
    if [[ "${owner}" != "${SERVICE_USER}:${SERVICE_GROUP}" ]]; then
      record "WARN" "${id}" "Base SQLite : propriétaire inattendu pour $(basename "${candidate}")" \
        "mode ${mode}, propriétaire ${owner} — attendu ${SERVICE_USER}:${SERVICE_GROUP}."
      continue
    fi
    record "OK" "${id}" "Base SQLite privée : $(basename "${candidate}")" \
      "${candidate}  mode ${mode}  propriétaire ${owner}"
    # Les fichiers -wal / -shm contiennent les mêmes données : ils doivent
    # hériter du même niveau de protection.
    local sidecar=""
    for sidecar in "${candidate}-wal" "${candidate}-shm"; do
      if [[ -f "${sidecar}" ]]; then
        local smode=""
        smode="$(file_mode "${sidecar}")"
        if [[ "${smode}" != "600" ]]; then
          record "FAIL" "${id}" "Fichier annexe de base non privé : $(basename "${sidecar}")" \
            "mode ${smode} (attendu 600) — il contient les mêmes données que la base."
        fi
      fi
    done
  done < <(find "${DATA_DIR}" -maxdepth 1 -type f \( -name '*.db' -o -name '*.sqlite*' \) -print 2>/dev/null || true)

  if [[ "${found}" -eq 0 ]]; then
    record "WARN" "${id}" "Aucune base SQLite trouvée" \
      "aucun fichier .db dans ${DATA_DIR} — base absente, déplacée, ou déploiement PostgreSQL (voir docs/operations/deployment.md)."
  fi
}

# -----------------------------------------------------------------------------
# 6. HOST-03 / HOST-04 : fichier d'environnement et secrets
# -----------------------------------------------------------------------------
check_env_file() {
  local id="HOST-03"
  if [[ ! -e "${ENV_FILE}" ]]; then
    record "FAIL" "${id}" "Fichier d'environnement absent" \
      "${ENV_FILE} n'existe pas : aucun secret n'est provisionné (voir scripts/install.sh, étape 6)."
    return 0
  fi
  local mode owner detail=""
  mode="$(file_mode "${ENV_FILE}")"
  owner="$(file_owner "${ENV_FILE}")"
  detail="${ENV_FILE}  mode ${mode}  propriétaire ${owner}"

  if [[ "${mode}" == "inconnu" ]]; then
    record "WARN" "${id}" "Permissions du fichier d'environnement illisibles" \
      "${detail} — relancez en root pour un contrôle fiable."
    return 0
  fi
  if [[ "${mode}" != "600" ]]; then
    record "FAIL" "${id}" "Fichier d'environnement non privé (secrets exposés)" \
      "${detail} — remédiation : chown root:${SERVICE_GROUP} ${ENV_FILE} && chmod 600 ${ENV_FILE}"
    return 0
  fi
  if [[ "${owner}" != root:* ]]; then
    record "WARN" "${id}" "Fichier d'environnement : propriétaire non root" \
      "${detail} — un compte non privilégié qui possède ce fichier peut le réécrire (donc changer la clé)."
    return 0
  fi
  record "OK" "${id}" "Fichier d'environnement privé" "${detail}"
}

check_secrets() {
  local id="HOST-04"

  local secret=""
  secret="$(env_value "THOT_SECRET_KEY" || true)"
  if [[ -z "${secret}" ]]; then
    # La clé peut aussi être persistée dans <data_dir>/secret.key (config.py).
    local keyfile="${DATA_DIR}/secret.key"
    if [[ -f "${keyfile}" ]]; then
      local kmode=""
      kmode="$(file_mode "${keyfile}")"
      if [[ "${kmode}" != "600" ]]; then
        record "FAIL" "${id}" "Clé de signature persistée non privée" \
          "${keyfile}  mode ${kmode} (attendu 600) — remédiation : chmod 600 ${keyfile}"
      else
        record "OK" "${id}" "Clé de signature persistée, privée" "${keyfile}  mode ${kmode}"
      fi
      return 0
    fi
    record "FAIL" "${id}" "Aucune clé de signature (THOT_SECRET_KEY)" \
      "définissez THOT_SECRET_KEY dans ${ENV_FILE} (openssl rand -hex 32) : sans elle, une clé éphémère est générée à chaque démarrage et toutes les clés API sont invalidées."
    return 0
  fi

  if [[ "${#secret}" -lt 32 ]]; then
    record "FAIL" "${id}" "THOT_SECRET_KEY trop courte" \
      "longueur ${#secret} caractères — attendu au moins 32 (openssl rand -hex 32 en produit 64)."
    return 0
  fi
  case "${secret}" in
    change*me*|*changeme*|secret|test|demo*)
      record "FAIL" "${id}" "THOT_SECRET_KEY est une valeur d'exemple" \
        "cette clé signe les sessions et poivre les clés API : regénérez-la (openssl rand -hex 32)."
      return 0 ;;
  esac
  record "OK" "${id}" "THOT_SECRET_KEY définie" "longueur ${#secret} caractères (valeur jamais affichée)"

  local bootstrap=""
  if bootstrap="$(env_value "THOT_BOOTSTRAP_API_KEY")"; then
    if [[ "${bootstrap}" == "${DEV_BOOTSTRAP_KEY}" ]]; then
      record "FAIL" "${id}" "Clé d'amorçage de développement encore active" \
        "THOT_BOOTSTRAP_API_KEY vaut la valeur publique livrée avec le projet : créez une clé dédiée (thotsecure key create) puis remplacez-la et révoquez l'ancienne."
    else
      record "OK" "${id}" "Clé d'amorçage personnalisée" "valeur non publique (jamais affichée)"
    fi
  else
    record "WARN" "${id}" "Aucune clé d'amorçage déclarée" \
      "THOT_BOOTSTRAP_API_KEY absente : vérifiez qu'une clé administrateur dédiée existe et qu'aucune clé publique ne traîne."
  fi
}

# -----------------------------------------------------------------------------
# 7. HOST-05 / HOST-06 : compte de service et processus
# -----------------------------------------------------------------------------
check_service_account() {
  local id="HOST-05"
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    record "FAIL" "${id}" "Compte de service « ${SERVICE_USER} » absent" \
      "créez-le (scripts/install.sh, étape 5) : le service ne doit PAS tourner en root."
    return 0
  fi

  local uid="" shell="" groups=""
  uid="$(id -u "${SERVICE_USER}")"
  shell="$(getent passwd "${SERVICE_USER}" | awk -F: '{print $7}')"
  groups="$(id -nG "${SERVICE_USER}" 2>/dev/null | tr ' ' ',')"

  if [[ "${uid}" -eq 0 ]]; then
    record "FAIL" "${id}" "Le compte de service a l'UID 0 (root)" \
      "uid=${uid}, groupes=${groups} — recréez un compte système non privilégié (useradd --system)."
    return 0
  fi
  case "${shell}" in
    */nologin|*/false|"")
      record "OK" "${id}" "Compte de service non privilégié, sans shell de connexion" \
        "uid=${uid}  shell=${shell:-aucun}  groupes=${groups}" ;;
    *)
      record "WARN" "${id}" "Le compte de service possède un shell de connexion" \
        "shell=${shell} — remédiation : usermod -s /usr/sbin/nologin ${SERVICE_USER} (surface d'attaque réduite)." ;;
  esac

  local privileged=""
  for privileged in sudo wheel adm docker root; do
    if id -nG "${SERVICE_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx "${privileged}"; then
      record "FAIL" "${id}" "Le compte de service appartient au groupe privilégié « ${privileged} »" \
        "groupes=${groups} — un service compromis obtiendrait des droits d'administration : gpasswd -d ${SERVICE_USER} ${privileged}."
    fi
  done
}

check_service_process() {
  local id="HOST-06"
  if ! command -v systemctl >/dev/null 2>&1; then
    record "WARN" "${id}" "systemd absent : propriétaire du processus non vérifiable" \
      "sur un hôte sans systemd, vérifiez à la main : ps -o user,pid,cmd -C uvicorn"
    return 0
  fi
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    record "WARN" "${id}" "Service ${SERVICE_NAME} inactif" \
      "le processus n'a pas pu être contrôlé (service arrêté ou installé autrement)."
    return 0
  fi

  local main_pid="" user=""
  main_pid="$(systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || true)"
  if [[ -z "${main_pid}" || "${main_pid}" == "0" ]]; then
    record "WARN" "${id}" "PID principal introuvable" "systemctl show -p MainPID n'a rien renvoyé."
    return 0
  fi
  user="$(ps -o user= -p "${main_pid}" 2>/dev/null | tr -d ' ' || true)"
  if [[ -z "${user}" ]]; then
    record "WARN" "${id}" "Propriétaire du processus illisible" \
      "PID ${main_pid} : lecture impossible (relancez en root)."
    return 0
  fi
  if [[ "${user}" == "root" ]]; then
    record "FAIL" "${id}" "Le service tourne en ROOT" \
      "PID ${main_pid} appartient à root — remédiation : User=${SERVICE_USER} dans ${UNIT_FILE}, puis systemctl daemon-reload && systemctl restart ${SERVICE_NAME}."
    return 0
  fi
  record "OK" "${id}" "Le service tourne sous un compte non privilégié" "PID ${main_pid} → ${user}"
}

# -----------------------------------------------------------------------------
# 8. HOST-07 : aucune fuite de secret dans les journaux
# -----------------------------------------------------------------------------
check_log_secrets() {
  local id="HOST-07"
  local -a sources=()
  local hits=0

  if [[ -d "${LOG_DIR}" ]]; then
    while IFS= read -r file; do
      [[ -n "${file}" ]] && sources+=("${file}")
    done < <(find "${LOG_DIR}" -maxdepth 2 -type f \( -name '*.log' -o -name '*.jsonl' -o -name '*.txt' \) -print 2>/dev/null)
  fi

  # Journal systemd : lecture directe, sans passer par un shell intermédiaire.
  local journal_dump=""
  if command -v journalctl >/dev/null 2>&1; then
    journal_dump="$(journalctl -u "${SERVICE_NAME}" --no-pager -n 5000 -o cat 2>/dev/null || true)"
  fi

  if [[ "${#sources[@]}" -eq 0 && -z "${journal_dump}" ]]; then
    record "WARN" "${id}" "Aucune source de journal exploitable" \
      "ni ${LOG_DIR}, ni journalctl -u ${SERVICE_NAME} : la recherche de fuite de secret n'a pas pu être menée (relancez en root)."
    return 0
  fi

  local secret=""
  secret="$(env_value "THOT_SECRET_KEY" || true)"
  local bootstrap=""
  bootstrap="$(env_value "THOT_BOOTSTRAP_API_KEY" || true)"

  # Motifs génériques : ne jamais recopier un secret dans la sortie du contrôle.
  local -a patterns=(
    'THOT_SECRET_KEY=[^[:space:]]'
    'THOT_BOOTSTRAP_API_KEY=[^[:space:]]'
    'Authorization: Bearer [A-Za-z0-9._-]{10}'
    'X-API-Key: ao_[A-Za-z0-9_-]{10}'
  )
  # Valeurs réelles : la comparaison littérale est la seule preuve fiable.
  if [[ -n "${secret}" && "${#secret}" -ge 16 ]]; then
    patterns+=("$(printf '%s' "${secret}" | sed -e 's/[.[\*^$]/\\&/g')")
  fi
  if [[ -n "${bootstrap}" && "${#bootstrap}" -ge 16 ]]; then
    patterns+=("$(printf '%s' "${bootstrap}" | sed -e 's/[.[\*^$]/\\&/g')")
  fi

  local pattern="" file=""
  for pattern in "${patterns[@]}"; do
    for file in "${sources[@]+"${sources[@]}"}"; do
      if grep -Eq -- "${pattern}" "${file}" 2>/dev/null; then
        hits=$(( hits + 1 ))
        record "FAIL" "${id}" "Secret potentiellement présent dans un journal" \
          "$(basename "${file}") contient un motif de secret (motif non affiché) — remédiation : THOT_LOG_LEVEL=INFO, THOT_LOG_FORMAT=json, purger le journal concerné, puis RÉVOQUER et régénérer le secret exposé."
      fi
    done
    if [[ -n "${journal_dump}" ]] && printf '%s\n' "${journal_dump}" | grep -Eq -- "${pattern}"; then
      hits=$(( hits + 1 ))
      record "FAIL" "${id}" "Secret potentiellement présent dans le journal systemd" \
        "journalctl -u ${SERVICE_NAME} contient un motif de secret (motif non affiché) — remédiation : purger le journal exposé, puis RÉVOQUER et régénérer le secret."
    fi
  done

  if [[ "${hits}" -eq 0 ]]; then
    record "OK" "${id}" "Aucun secret en clair détecté dans les journaux" \
      "${#sources[@]} fichier(s) de journal et journalctl -u ${SERVICE_NAME} analysés."
  fi
}

# -----------------------------------------------------------------------------
# 9. HOST-08 : exposition réseau
# -----------------------------------------------------------------------------
proxy_evidence() {
  # Cherche une configuration de reverse-proxy qui redirige vers le port du service.
  # Retourne une description (« fichier:ligne ») sur la sortie standard, ou rien.
  local port="$1" dir="" file=""
  for dir in /etc/nginx /etc/caddy /etc/traefik /etc/apache2 /etc/httpd; do
    [[ -d "${dir}" ]] || continue
    while IFS= read -r file; do
      [[ -n "${file}" ]] || continue
      if grep -Eqn "(proxy_pass|ProxyPass|reverse_proxy|to[[:space:]]+https?://[^[:space:]]*:${port})" \
           "${file}" 2>/dev/null | grep -Eq ":${port}|proxy_pass|ProxyPass|reverse_proxy"; then
        printf '%s\n' "${file}"
        return 0
      fi
    done < <(find "${dir}" -maxdepth 3 -type f \( -name '*.conf' -o -name 'Caddyfile' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' \) -print 2>/dev/null)
  done
  return 1
}

firewall_evidence() {
  # Sortie : une ligne de preuve UNIQUEMENT si un pare-feu est réellement actif.
  # Un pare-feu installé mais inactif ne protège rien : il n'est pas une preuve.
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    printf '%s\n' "ufw actif"
    return 0
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then
    printf '%s\n' "firewalld actif"
    return 0
  fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input'; then
    printf '%s\n' "nftables : chaîne input présente"
    return 0
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -qE '^-A (INPUT|DOCKER-USER)'; then
    printf '%s\n' "iptables : règles INPUT présentes"
    return 0
  fi
  return 1
}

check_network_exposure() {
  local id="HOST-08"
  local host="0.0.0.0" port="8080" tls="false"
  host="$(env_value "THOT_HOST" || printf '0.0.0.0')"
  port="$(env_value "THOT_PORT" || printf '8080')"
  tls="$(env_value "THOT_TLS_ENABLED" || printf 'false')"

  # Trace factuelle : sur quoi le processus écoute RÉELLEMENT.
  local listening=""
  if command -v ss >/dev/null 2>&1; then
    listening="$(ss -lntH 2>/dev/null | awk -v p=":${port}" '$4 ~ p { print $4 }' | paste -sd ',' - || true)"
  elif command -v netstat >/dev/null 2>&1; then
    listening="$(netstat -lnt 2>/dev/null | awk -v p=":${port}" '$4 ~ p { print $4 }' | paste -sd ',' - || true)"
  fi
  local detail="THOT_HOST=${host}  THOT_PORT=${port}  THOT_TLS_ENABLED=${tls}"
  if [[ -n "${listening}" ]]; then
    detail="${detail}  écoute réelle : ${listening}"
  else
    detail="${detail}  écoute réelle : non déterminée (ss/netstat indisponible ou service arrêté)"
  fi

  if [[ "${tls}" == "true" ]]; then
    record "OK" "${id}" "TLS activé en direct sur le service" \
      "${detail} — vérifiez la date d'expiration du certificat et son renouvellement automatique."
    return 0
  fi

  local proxy="" firewall=""
  proxy="$(proxy_evidence "${port}" || true)"
  firewall="$(firewall_evidence || true)"

  case "${host}" in
    127.0.0.1|::1|localhost)
      record "OK" "${id}" "Écoute limitée à la boucle locale" \
        "${detail} — aucun accès réseau direct : c'est la configuration la plus sûre sans TLS."
      return 0 ;;
  esac

  if [[ -n "${proxy}" ]]; then
    record "OK" "${id}" "Exposition publique couverte par un reverse-proxy" \
      "${detail}  proxy détecté : ${proxy}${firewall:+  pare-feu : ${firewall}}"
    record "WARN" "${id}" "Vérifiez HTTPS de bout en bout derrière le proxy" \
      "assurez-vous que le proxy force HTTPS, transmet X-Forwarded-Proto et restreint l'accès direct au port ${port} (pare-feu ou écoute 127.0.0.1)."
    return 0
  fi

  if [[ -n "${firewall}" ]]; then
    record "WARN" "${id}" "Écoute sur ${host} sans TLS, protégée uniquement par le pare-feu" \
      "${detail}  pare-feu : ${firewall} — les clés API circulent alors en clair sur le réseau autorisé. Ajoutez un reverse-proxy HTTPS (défense en profondeur)."
    return 0
  fi

  case "${host}" in
    0.0.0.0|::|"*"|"")
      record "FAIL" "${id}" "Le service écoute sur TOUTES les interfaces, sans TLS ni reverse-proxy" \
        "${detail} — les clés API (en-tête X-API-Key) circulent alors en clair. Remédiation : THOT_HOST=127.0.0.1 dans ${ENV_FILE}, OU placez un reverse-proxy HTTPS devant, OU restreignez le port par pare-feu. Ne l'exposez jamais tel quel sur Internet."
      ;;
    *)
      record "WARN" "${id}" "Écoute sur une interface précise sans TLS" \
        "${detail} — aucune preuve de reverse-proxy ni de pare-feu actif. Vérifiez que cette interface est bien sur un réseau de confiance, ou activez TLS."
      ;;
  esac
}

# -----------------------------------------------------------------------------
# 10. HOST-09 : unité systemd durcie
# -----------------------------------------------------------------------------
check_unit_hardening() {
  local id="HOST-09"
  local -a required=(
    "NoNewPrivileges=yes"
    "ProtectSystem=strict"
    "ProtectHome=yes"
    "PrivateTmp=yes"
    "PrivateDevices=yes"
    "ProtectKernelTunables=yes"
    "ProtectControlGroups=yes"
    "RestrictNamespaces=yes"
    "LockPersonality=yes"
    "MemoryDenyWriteExecute=yes"
    "RestrictRealtime=yes"
    "RestrictSUIDSGID=yes"
  )
  local -a missing=()

  # systemd sait ce qui est RÉELLEMENT appliqué (y compris les valeurs par défaut
  # et les fichiers de surcharge drop-in) : on l'interroge en priorité.
  local use_systemd="false"
  if command -v systemctl >/dev/null 2>&1 \
     && systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1 \
     && [[ -n "$(systemctl list-unit-files --type=service --no-legend "${SERVICE_NAME}.service" 2>/dev/null)" ]]; then
    use_systemd="true"
  fi

  if [[ "${use_systemd}" == "true" ]]; then
    local property="" value="" directive="" expected=""
    for directive in "${required[@]}"; do
      property="${directive%%=*}"
      expected="${directive#*=}"
      value="$(systemctl show -p "${property}" --value "${SERVICE_NAME}" 2>/dev/null || true)"
      case "${property}" in
        ProtectSystem) [[ "${value}" == "strict" || "${value}" == "full" ]] || missing+=("${directive}") ;;
        *) is_boolean_yes "${value}" || missing+=("${directive}") ;;
      esac
    done

    local user="" rw=""
    user="$(systemctl show -p User --value "${SERVICE_NAME}" 2>/dev/null || true)"
    rw="$(systemctl show -p ReadWritePaths --value "${SERVICE_NAME}" 2>/dev/null || true)"
    [[ "${user}" == "${SERVICE_USER}" ]] || missing+=("User=${SERVICE_USER} (actuel : ${user:-root})")
    [[ "${rw}" == *"${DATA_DIR}"* ]] || missing+=("ReadWritePaths=${DATA_DIR} (actuel : ${rw:-aucun})")

    local raf=""
    raf="$(systemctl show -p RestrictAddressFamilies --value "${SERVICE_NAME}" 2>/dev/null || true)"
    [[ "${raf}" == *AF_INET* ]] || missing+=("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX (actuel : ${raf:-aucun})")

    if [[ "${#missing[@]}" -eq 0 ]]; then
      record "OK" "${id}" "Unité systemd durcie (valeurs réellement appliquées)" \
        "contrôlé via systemctl show : confinement complet, User=${user}, ReadWritePaths=${rw}"
      return 0
    fi
    record "FAIL" "${id}" "Unité systemd insuffisamment durcie (${#missing[@]} directive(s))" \
      "à corriger dans ${UNIT_FILE} ou un drop-in /etc/systemd/system/${SERVICE_NAME}.service.d/ : ${missing[*]}"
    return 0
  fi

  # Repli : lecture du fichier d'unité (hôte sans systemd, ou unité absente).
  # Attention à la syntaxe : dans un FICHIER d'unité, les booléens s'écrivent
  # aussi bien « yes » que « true » (systemd accepte les deux). Comparer
  # littéralement à « yes » produirait de faux échecs sur une unité correcte.
  if [[ ! -r "${UNIT_FILE}" ]]; then
    # Un fichier d'unité peut aussi être fourni par le paquet ailleurs.
    local candidate=""
    for candidate in "/lib/systemd/system/${SERVICE_NAME}.service" "/usr/lib/systemd/system/${SERVICE_NAME}.service"; do
      if [[ -r "${candidate}" ]]; then
        UNIT_FILE="${candidate}"
        break
      fi
    done
  fi
  if [[ ! -r "${UNIT_FILE}" ]]; then
    record "WARN" "${id}" "Unité systemd introuvable" \
      "aucun fichier ${SERVICE_NAME}.service trouvé : le confinement systemd n'a pas pu être vérifié (déploiement conteneurisé ou service géré autrement)."
    return 0
  fi

  local line="" directive="" expected="" actual=""
  for line in "${required[@]}"; do
    directive="${line%%=*}"
    expected="${line#*=}"
    actual="$(unit_value "${directive}" "${UNIT_FILE}")"
    if [[ -z "${actual}" ]]; then
      missing+=("${line}")
      continue
    fi
    if [[ "${directive}" == "ProtectSystem" ]]; then
      case "${actual}" in
        strict|full) : ;;
        *) missing+=("${line} (actuel : ${actual})") ;;
      esac
      continue
    fi
    is_boolean_yes "${actual}" || missing+=("${line} (actuel : ${actual})")
  done
  actual="$(unit_value "User" "${UNIT_FILE}")"
  [[ "${actual}" == "${SERVICE_USER}" ]] || missing+=("User=${SERVICE_USER} (actuel : ${actual:-aucun})")
  actual="$(unit_value "ReadWritePaths" "${UNIT_FILE}")"
  [[ "${actual}" == *"${DATA_DIR}"* ]] || missing+=("ReadWritePaths=${DATA_DIR} (actuel : ${actual:-aucun})")
  actual="$(unit_value "RestrictAddressFamilies" "${UNIT_FILE}")"
  [[ "${actual}" == *AF_INET* ]] || missing+=("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX (actuel : ${actual:-aucun})")

  if [[ "${#missing[@]}" -eq 0 ]]; then
    record "OK" "${id}" "Unité systemd durcie (lecture du fichier)" \
      "${UNIT_FILE} contient les directives de confinement attendues."
    return 0
  fi
  record "FAIL" "${id}" "Unité systemd insuffisamment durcie (${#missing[@]} directive(s))" \
    "${UNIT_FILE} — manquant : ${missing[*]}"
}

# -----------------------------------------------------------------------------
# 11. HOST-10 : configuration non modifiable par le service
# -----------------------------------------------------------------------------
check_etc_permissions() {
  local id="HOST-10"
  if [[ ! -e "${ETC_DIR}" ]]; then
    record "FAIL" "${id}" "Répertoire de configuration absent" "${ETC_DIR} n'existe pas."
    return 0
  fi
  local mode owner group other
  mode="$(file_mode "${ETC_DIR}")"
  owner="$(file_owner "${ETC_DIR}")"
  group="$(perm_group "${mode}")"
  other="$(perm_other "${mode}")"

  if digit_writable "${other}"; then
    record "FAIL" "${id}" "${ETC_DIR} inscriptible par tout le monde" \
      "mode ${mode}, propriétaire ${owner} — un utilisateur local pourrait modifier les règles, les politiques et les playbooks : chmod o-w ${ETC_DIR}"
    return 0
  fi
  if digit_writable "${group}"; then
    record "FAIL" "${id}" "${ETC_DIR} inscriptible par le groupe ${SERVICE_GROUP}" \
      "mode ${mode}, propriétaire ${owner} — le service pourrait réécrire ses propres règles : chmod g-w ${ETC_DIR} (le compte de service doit LIRE, pas écrire)."
    return 0
  fi
  local sub="" subowner=""
  for sub in rules policies playbooks; do
    if [[ -d "${ETC_DIR}/${sub}" ]]; then
      subowner="$(file_owner "${ETC_DIR}/${sub}")"
      if [[ "${subowner}" == "${SERVICE_USER}:"* ]]; then
        record "WARN" "${id}" "${ETC_DIR}/${sub} appartient au compte de service" \
          "propriétaire ${subowner} — un service compromis pourrait modifier ses règles de détection : chown -R root:${SERVICE_GROUP} ${ETC_DIR}/${sub}"
      fi
    fi
  done
  record "OK" "${id}" "Répertoire de configuration protégé" \
    "${ETC_DIR}  mode ${mode}  propriétaire ${owner}"
}

# -----------------------------------------------------------------------------
# 12. HOST-11 / HOST-12 / HOST-13 : sauvegardes et chiffrement au repos
# -----------------------------------------------------------------------------
check_backup_dir() {
  local id="HOST-11"
  if [[ ! -e "${BACKUP_DIR}" ]]; then
    record "WARN" "${id}" "Répertoire de sauvegardes absent" \
      "${BACKUP_DIR} n'existe pas : aucune sauvegarde locale n'est prévue (scripts/backup.sh)."
    return 0
  fi
  local mode owner other
  mode="$(file_mode "${BACKUP_DIR}")"
  owner="$(file_owner "${BACKUP_DIR}")"
  other="$(perm_other "${mode}")"
  if digit_readable "${other}"; then
    record "FAIL" "${id}" "Répertoire de sauvegardes lisible par tous" \
      "mode ${mode} — une sauvegarde contient la base ET le journal d'audit : chmod 700 ${BACKUP_DIR}."
    return 0
  fi
  if [[ "${mode}" != "700" ]]; then
    record "WARN" "${id}" "Permissions du répertoire de sauvegardes" \
      "${BACKUP_DIR}  mode ${mode}  propriétaire ${owner} — recommandé : 0700 root:root."
    return 0
  fi
  record "OK" "${id}" "Répertoire de sauvegardes privé" "${BACKUP_DIR}  mode ${mode}  propriétaire ${owner}"
}

check_backup_schedule() {
  local id="HOST-12" evidence=""
  if command -v systemctl >/dev/null 2>&1; then
    evidence="$(systemctl list-timers --all --no-legend 2>/dev/null | grep -Ei 'backup|thotsecure' || true)"
  fi
  if [[ -z "${evidence}" && -d /etc/cron.d ]]; then
    evidence="$(grep -rEl 'thotsecure|backup' /etc/cron.d /etc/crontab 2>/dev/null || true)"
  fi
  if [[ -z "${evidence}" && -d /etc/cron.daily ]]; then
    evidence="$(grep -rEl 'thotsecure|backup' /etc/cron.daily 2>/dev/null || true)"
  fi
  if [[ -n "${evidence}" ]]; then
    record "OK" "${id}" "Sauvegardes planifiées détectées" "${evidence}"
    return 0
  fi
  record "WARN" "${id}" "Aucune sauvegarde planifiée détectée" \
    "planifiez scripts/backup.sh (timer systemd ou cron) : une sauvegarde manuelle oubliée n'est pas une sauvegarde."
}

check_encryption_at_rest() {
  local id="HOST-13" detail=""
  local device="" fstype=""
  if command -v lsblk >/dev/null 2>&1; then
    # df -P est POSIX : on évite « --output », propre à GNU coreutils.
    device="$(df -P "${DATA_DIR}" 2>/dev/null | awk 'NR == 2 { print $1 }' || true)"
    fstype="$(lsblk -no FSTYPE "${device}" 2>/dev/null | awk 'NR == 1 { print $1 }' || true)"
    if [[ "${fstype}" == "crypto_LUKS" || "${fstype}" == "crypt" ]]; then
      record "OK" "${id}" "Chiffrement au repos : volume chiffré" \
        "${DATA_DIR} est sur ${device} (${fstype})."
      return 0
    fi
    detail="${DATA_DIR} → ${device:-inconnu} (${fstype:-système de fichiers inconnu})"
  else
    detail="${DATA_DIR} (lsblk indisponible)"
  fi

  local encrypted_backups=0
  if [[ -d "${BACKUP_DIR}" ]] && find "${BACKUP_DIR}" -maxdepth 1 -type f \( -name '*.age' -o -name '*.gpg' \) -print -quit 2>/dev/null | grep -q .; then
    encrypted_backups=1
  fi
  if [[ "${encrypted_backups}" -eq 1 ]]; then
    record "OK" "${id}" "Sauvegardes chiffrées détectées" \
      "${BACKUP_DIR} contient des archives .age/.gpg — chiffrez aussi le volume des données pour une couverture complète."
    return 0
  fi

  record "WARN" "${id}" "Chiffrement au repos non démontré" \
    "${detail} — ni volume chiffré (LUKS) ni archive de sauvegarde chiffrée détectés. La documentation produit (§10) demande un disque chiffré documenté, ou des sauvegardes chiffrées : scripts/backup.sh --encrypt age --recipient <clé>."
}

# -----------------------------------------------------------------------------
# 13. HOST-14 / HOST-15 : noyau et journalisation
# -----------------------------------------------------------------------------
check_kernel_hardening() {
  local id="HOST-14"
  local -a expectations=(
    "kernel.dmesg_restrict:1"
    "kernel.kptr_restrict:1"
    "kernel.randomize_va_space:2"
    "fs.protected_hardlinks:1"
    "fs.protected_symlinks:1"
    "net.ipv4.conf.all.rp_filter:1"
    "kernel.yama.ptrace_scope:1"
  )
  local -a weak=()
  local -a unreadable=()
  local item="" key="" expected="" actual=""

  for item in "${expectations[@]}"; do
    key="${item%%:*}"
    expected="${item##*:}"
    if ! actual="$(sysctl_value "${key}")"; then
      unreadable+=("${key}")
      continue
    fi
    case "${key}" in
      kernel.kptr_restrict|kernel.yama.ptrace_scope)
        # Ces réglages sont des SEUILS : toute valeur supérieure ou égale suffit.
        if [[ "${actual}" -lt "${expected}" ]] 2>/dev/null; then
          weak+=("${key}=${actual} (attendu ≥ ${expected})")
        fi ;;
      net.ipv4.conf.all.rp_filter)
        # 1 = strict, 2 = lâche : les deux filtrent, on accepte les deux.
        if [[ "${actual}" != "1" && "${actual}" != "2" ]]; then
          weak+=("${key}=${actual} (attendu 1 ou 2)")
        fi ;;
      *)
        if [[ "${actual}" != "${expected}" ]]; then
          weak+=("${key}=${actual} (attendu ${expected})")
        fi ;;
    esac
  done

  if [[ "${#weak[@]}" -eq 0 && "${#unreadable[@]}" -eq 0 ]]; then
    record "OK" "${id}" "Réglages noyau conformes aux recommandations" \
      "dmesg restreint, pointeurs masqués, ASLR complet, liens protégés, filtrage des routes inverses, ptrace restreint."
    return 0
  fi
  if [[ "${#weak[@]}" -eq 0 ]]; then
    record "WARN" "${id}" "Réglages noyau partiellement illisibles" \
      "non lus : ${unreadable[*]} — relancez en root pour un contrôle complet."
    return 0
  fi
  record "WARN" "${id}" "Réglages noyau à durcir (${#weak[@]})" \
    "à corriger dans /etc/sysctl.d/99-thotsecure.conf puis « sysctl --system » : ${weak[*]}${unreadable[*]:+ ; non lus : ${unreadable[*]}}"
}

check_journald() {
  local id="HOST-15" detail="" storage=""
  if [[ -r /etc/systemd/journald.conf ]]; then
    storage="$(sed -n 's/^[[:space:]]*Storage[[:space:]]*=[[:space:]]*//p' /etc/systemd/journald.conf | tail -n 1)"
  fi
  if [[ -d /var/log/journal ]]; then
    local mode=""
    mode="$(file_mode /var/log/journal)"
    if digit_readable "$(perm_other "${mode}")"; then
      record "WARN" "${id}" "Journal systemd lisible par tous" \
        "/var/log/journal mode ${mode} — les journaux peuvent contenir des métadonnées sensibles : chmod -R o-rwx /var/log/journal (et lisible par le groupe systemd-journal)."
      return 0
    fi
    record "OK" "${id}" "Journal systemd persistant" \
      "/var/log/journal présent (mode ${mode}${storage:+, Storage=${storage}}) — la piste d'audit survit au redémarrage."
    return 0
  fi
  record "WARN" "${id}" "Journal systemd non persistant" \
    "Storage=${storage:-défaut} et /var/log/journal absent : après redémarrage, les journaux du service sont perdus. Recommandation : Storage=persistent dans /etc/systemd/journald.conf."
}

# -----------------------------------------------------------------------------
# 14. HOST-16 : garde-fous du service (information, jamais bloquant)
# -----------------------------------------------------------------------------
check_safety_switches() {
  local id="HOST-16"
  local dry_run="" autonomy=""
  dry_run="$(env_value "THOT_DRY_RUN" || printf 'true')"
  autonomy="$(env_value "THOT_AUTONOMY" || printf 'supervised')"

  if [[ "${dry_run}" == "true" ]]; then
    record "OK" "${id}" "Simulation active (THOT_DRY_RUN=true)" \
      "aucune contre-mesure n'a d'effet réel — état recommandé tant que la validation n'est pas écrite."
  else
    record "WARN" "${id}" "Simulation DÉSACTIVÉE (THOT_DRY_RUN=${dry_run})" \
      "les contre-mesures peuvent modifier des systèmes réels. Vérifiez que la décision est écrite, datée, approuvée — et que les playbooks ont été testés en simulation."
  fi

  case "${autonomy}" in
    manual|supervised)
      record "OK" "${id}" "Autonomie sous contrôle humain (THOT_AUTONOMY=${autonomy})" \
        "une action critique exige une approbation (manual) ou une supervision (supervised)." ;;
    auto)
      record "WARN" "${id}" "Autonomie AUTOMATIQUE (THOT_AUTONOMY=auto)" \
        "des actions seront exécutées sans approbation humaine sur les cibles non protégées. Exigez une revue périodique des actions et des rollbacks, et vérifiez protected_targets." ;;
    *)
      record "WARN" "${id}" "Valeur d'autonomie inattendue (THOT_AUTONOMY=${autonomy})" \
        "valeurs attendues : manual | supervised | auto." ;;
  esac
}

# -----------------------------------------------------------------------------
# 15. Rapport
# -----------------------------------------------------------------------------
print_json_report() {
  printf '{\n'
  printf '  "script": "%s",\n' "$(json_escape "${SCRIPT_NAME}")"
  printf '  "version": "%s",\n' "$(json_escape "${SCRIPT_VERSION}")"
  printf '  "host": "%s",\n' "$(json_escape "$(hostname 2>/dev/null || printf 'inconnu')")"
  printf '  "checked_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "critical_failures": %d,\n' "${FAIL_COUNT}"
  printf '  "warnings": %d,\n' "${WARN_COUNT}"
  printf '  "passed": %d,\n' "${PASS_COUNT}"
  printf '  "checks": [\n'
  local index=0 entry="" status="" id="" label="" detail=""
  for entry in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    status="${entry%%|*}"
    entry="${entry#*|}"
    id="${entry%%|*}"
    entry="${entry#*|}"
    label="${entry%%|*}"
    detail="${entry#*|}"
    index=$(( index + 1 ))
    printf '    {"id": "%s", "status": "%s", "label": "%s", "detail": "%s"}%s\n' \
      "$(json_escape "${id}")" "$(json_escape "${status}")" \
      "$(json_escape "${label}")" "$(json_escape "${detail}")" \
      "$([[ "${index}" -lt "${#RESULTS[@]}" ]] && printf ',' || true)"
  done
  printf '  ]\n'
  printf '}\n'
}

print_verdict() {
  printf '\n'
  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    log_error "${FAIL_COUNT} contrôle(s) CRITIQUE(S) en échec, ${WARN_COUNT} avertissement(s), ${PASS_COUNT} contrôle(s) réussi(s)."
    log_error "L'hôte n'est PAS dans l'état attendu pour un déploiement en production."
    log_step "Corrigez les points marqués [FAIL] ci-dessus, puis relancez ce script."
  else
    log_ok "Aucun échec critique : ${PASS_COUNT} contrôle(s) réussi(s), ${WARN_COUNT} avertissement(s)."
    log_step "Les avertissements ne sont pas des échecs : ce sont des décisions à assumer par écrit."
  fi
  printf '\n'
  printf '%sInspiration CIS/ANSSI — aide au diagnostic, SANS valeur de certification.%s\n' \
    "${C_DIM}" "${C_RESET}"
  printf "%sLe durcissement de l'application se contrôle avec : thotsecure doctor%s\n" \
    "${C_DIM}" "${C_RESET}"
  printf '%sRappel : Thot Secure est strictement défensif ; aucun contrôle ne modifie le système.%s\n' \
    "${C_DIM}" "${C_RESET}"
}

main() {
  parse_args "$@"

  if [[ "${JSON_OUT}" == "true" ]]; then
    # En --json, la sortie standard ne doit contenir QUE du JSON : le bandeau
    # part sur la sortie d'erreur, pour rester consommable par un outil (jq, CI).
    printf '%s\n' "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" >&2
  else
    printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
    log_info "Contrôle du durcissement de l'hôte (aucune modification appliquée)."
    if [[ "${EUID}" -ne 0 ]]; then
      log_warn "Exécution sans root : certains contrôles seront « WARN » faute d'accès en lecture."
      log_step "Pour un contrôle complet : sudo scripts/${SCRIPT_NAME}"
    fi
    printf '\n'
  fi

  check_data_dir
  check_database
  check_env_file
  check_secrets
  check_service_account
  check_service_process
  check_log_secrets
  check_network_exposure
  check_unit_hardening
  check_etc_permissions
  check_backup_dir
  check_backup_schedule
  check_encryption_at_rest
  check_kernel_hardening
  check_journald
  check_safety_switches

  if [[ "${JSON_OUT}" == "true" ]]; then
    print_json_report
  else
    print_verdict
  fi

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit "${EXIT_VERIFY}"
  fi
}

main "$@"
