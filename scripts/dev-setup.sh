#!/usr/bin/env bash
# =============================================================================
#  Thot Secure (nom technique du paquet : « thotsecure ») — scripts/dev-setup.sh
# -----------------------------------------------------------------------------
#  Prépare un environnement de DÉVELOPPEMENT complet, en local, sans privilège :
#
#      ./scripts/dev-setup.sh                 # tout : venv, dépendances, base, démo, doctor
#      ./scripts/dev-setup.sh --offline       # sans réseau (dépendances déjà présentes)
#
#  Ce que fait ce script, dans l'ordre :
#    1. vérifie qu'on est bien à la racine du dépôt et que Python ≥ 3.11 est présent ;
#    2. crée (ou RÉUTILISE) l'environnement virtuel .venv ;
#    3. installe le paquet en mode éditable avec les outils de développement :
#         pip install -e ".[dev]"
#       et, SI LE RÉSEAU EST INDISPONIBLE, se replie automatiquement sur
#         pip install -e . --no-deps --no-build-isolation
#       en annonçant clairement ce que l'on perd (pytest, ruff, mypy, httpx) ;
#    4. crée un fichier .env local avec les valeurs de DÉVELOPPEMENT sûres
#       (jamais écrasé s'il existe) et copie config/targets.example.yaml vers
#       config/targets.yaml si le périmètre n'est pas encore déclaré ;
#    5. initialise la base locale        : thotsecure init-db
#    6. crée le tenant de démonstration  : thotsecure tenant create --id demo …
#    7. injecte le jeu de démonstration  : thotsecure demo --tenant demo
#    8. termine par le diagnostic        : thotsecure doctor
#
#  IDEMPOTENT : relançable sans rien casser. L'environnement virtuel existant est
#  conservé, la base est mise à jour et non recréée, le .env n'est jamais écrasé,
#  la démonstration est rejouable (les findings sont regroupés par règle et par clé).
#  Seul --recreate (avec confirmation) supprime quelque chose.
#
#  SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
#    * Ce script pose THOT_DRY_RUN=true et THOT_AUTONOMY=supervised pour TOUTES
#      les commandes qu'il exécute, et il ne les inverse JAMAIS ;
#    * s'il constate que vous les avez modifiés (environnement ou .env), il le dit
#      très explicitement : passer en réel est une décision, pas un raccourci de
#      développement ;
#    * aucun secret n'est écrit en dur : le .env de développement contient
#      uniquement des valeurs locales, et il est ignoré par Git (.gitignore).
#
#  Codes de sortie : 0 succès, 1 erreur, 2 usage, 3 vérification négative
#  (c'est le code de « thotsecure doctor » lorsqu'un contrôle critique échoue).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# 1. Présentation, couleurs et journalisation (mêmes conventions qu'install.sh)
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="dev-setup.sh"
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

# Toute opération qui MODIFIE le dépôt passe par ici : jamais en --dry-run.
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
  log_error "Rien n'est cassé : relancez le script après avoir corrigé le point ci-dessus."
  log_error "L'environnement virtuel et la base existants sont conservés."
  exit "${2}"
}
trap 'on_error "${LINENO}" "$?"' ERR

readonly EXIT_USAGE=2
readonly EXIT_VERIFY=3
readonly MIN_PYTHON_MAJOR=3
readonly MIN_PYTHON_MINOR=11

# -----------------------------------------------------------------------------
# 2. Options
# -----------------------------------------------------------------------------
VENV_DIR=".venv"
PYTHON_BIN="${THOT_DEV_PYTHON:-python3}"
TENANT="demo"
OFFLINE="false"
RECREATE="false"
WRITE_ENV="true"
RUN_DEMO="true"
ASSUME_YES="false"
DRY_RUN="false"
INSTALL_MODE=""          # dev | no-deps | source
VENV_PYTHON=""

usage() {
  cat <<'AIDE'
Thot Secure — préparation d'un environnement de développement local.

USAGE
    ./scripts/dev-setup.sh [options]

OPTIONS
    --venv <dir>        Répertoire de l'environnement virtuel (défaut : .venv).
    --python <cmd>      Interpréteur à utiliser (défaut : python3 ;
                        surchargeable par la variable THOT_DEV_PYTHON).
    --tenant <id>       Identifiant du tenant de démonstration (défaut : demo).
    --offline           Ne pas tenter d'accéder au réseau : installation directe
                        avec --no-deps (les dépendances doivent déjà être là).
    --no-demo           Ne pas injecter le jeu de démonstration.
    --no-env-file       Ne pas créer de fichier .env local.
    --recreate          Supprimer puis recréer l'environnement virtuel
                        (demande une confirmation : c'est destructif).
    --yes               Ne poser aucune question (automatisation).
    --dry-run           Afficher les opérations sans rien modifier.
    -h, --help          Afficher cette aide.

APRÈS CE SCRIPT
    make serve          # API + console sur http://127.0.0.1:8080/ (simulation active)
    make test           # suite de tests (unittest, stdlib uniquement)
    make lint           # ruff (si les outils de développement ont pu être installés)
    make doctor         # diagnostic applicatif

SÛRETÉ
    * THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont IMPOSÉS à toutes les
      commandes lancées ici : une démonstration ne déclenche aucune action réelle.
    * Ce script n'active JAMAIS THOT_DRY_RUN=false ni THOT_AUTONOMY=auto ; s'il
      les détecte dans votre environnement ou votre .env, il vous le signale.
    * Thot Secure est strictement défensif : aucune capacité offensive.
    * Lisez ce script avant de l'exécuter : il modifie le dépôt (venv, base locale,
      .env, config/targets.yaml).
AIDE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --venv)
        [[ $# -ge 2 ]] || die "--venv exige un chemin." "${EXIT_USAGE}"
        VENV_DIR="$2"; shift 2 ;;
      --python)
        [[ $# -ge 2 ]] || die "--python exige une commande." "${EXIT_USAGE}"
        PYTHON_BIN="$2"; shift 2 ;;
      --tenant)
        [[ $# -ge 2 ]] || die "--tenant exige un identifiant." "${EXIT_USAGE}"
        TENANT="$2"; shift 2 ;;
      --offline)      OFFLINE="true"; shift ;;
      --no-demo)      RUN_DEMO="false"; shift ;;
      --no-env-file)  WRITE_ENV="false"; shift ;;
      --recreate)     RECREATE="true"; shift ;;
      --yes)          ASSUME_YES="true"; shift ;;
      --dry-run)      DRY_RUN="true"; shift ;;
      -h|--help)      usage; exit 0 ;;
      *) log_error "Option inconnue : $1"; usage; exit "${EXIT_USAGE}" ;;
    esac
  done

  [[ "${TENANT}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "--tenant accepte lettres, chiffres, point, tiret et souligné (reçu : ${TENANT})." "${EXIT_USAGE}"
  [[ "${VENV_DIR}" == /* || "${VENV_DIR}" != *..* ]] \
    || die "--venv refuse un chemin contenant « .. » (sécurité)." "${EXIT_USAGE}"
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

# -----------------------------------------------------------------------------
# 3. Racine du dépôt et prérequis
# -----------------------------------------------------------------------------
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && "${BASH_SOURCE[0]}" != "-" ]]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
fi

locate_repo_root() {
  local candidate=""
  if [[ -n "${SCRIPT_DIR}" ]]; then
    candidate="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
  else
    candidate="$(pwd -P)"
  fi
  [[ -f "${candidate}/pyproject.toml" ]] \
    || die "pyproject.toml introuvable dans ${candidate} : lancez ce script depuis un clone du dépôt." 1
  [[ -d "${candidate}/src/thotsecure" ]] \
    || die "src/thotsecure introuvable dans ${candidate} : dépôt incomplet." 1
  REPO_ROOT="${candidate}"
  cd -- "${REPO_ROOT}"
  log_step "Racine du dépôt : ${REPO_ROOT}"
}

check_python() {
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 \
    || die "Interpréteur introuvable : ${PYTHON_BIN}. Installez Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ ou utilisez --python." 1
  local version=""
  version="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
  [[ -n "${version}" ]] || die "Impossible d'interroger ${PYTHON_BIN} -V." 1
  if ! "${PYTHON_BIN}" -c "import sys; raise SystemExit(0 if sys.version_info >= (${MIN_PYTHON_MAJOR}, ${MIN_PYTHON_MINOR}) else 1)"; then
    die "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ est requis (pyproject : requires-python = \">=${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}\") ; détecté : ${version}." 1
  fi
  log_ok "Interpréteur : ${PYTHON_BIN} (Python ${version})"
}

# -----------------------------------------------------------------------------
# 4. Sûreté : valeurs imposées et avertissement si l'utilisateur les a modifiées
# -----------------------------------------------------------------------------
warn_if_unsafe_settings() {
  # Le script ne modifie pas ces réglages : il les SIGNALE. Un environnement de
  # développement n'a aucune raison d'exécuter des contre-mesures réelles.
  local dry_run="${THOT_DRY_RUN:-true}"
  local autonomy="${THOT_AUTONOMY:-supervised}"

  if [[ "${dry_run}" != "true" ]]; then
    log_warn "AVERTISSEMENT : THOT_DRY_RUN=${dry_run} dans votre environnement."
    log_warn "Un environnement de développement ne doit pas exécuter d'action réelle."
    log_warn "Ce script impose THOT_DRY_RUN=true aux commandes qu'il lance, mais votre"
    log_warn "shell (et « make serve ») utiliserait la valeur ci-dessus."
  fi
  if [[ "${autonomy}" != "supervised" && "${autonomy}" != "manual" ]]; then
    log_warn "AVERTISSEMENT : THOT_AUTONOMY=${autonomy} dans votre environnement."
    log_warn "Le mode « auto » exécute des actions sans approbation humaine ; ce script"
    log_warn "ne le recommande ni ne le pose, et l'impose à « supervised » pour ses commandes."
  fi

  if [[ -f ".env" ]]; then
    local file_dry_run="" file_autonomy=""
    file_dry_run="$(sed -n 's/^THOT_DRY_RUN=//p' .env 2>/dev/null | tail -n 1)"
    file_autonomy="$(sed -n 's/^THOT_AUTONOMY=//p' .env 2>/dev/null | tail -n 1)"
    if [[ -n "${file_dry_run}" && "${file_dry_run}" != "true" ]]; then
      log_warn "AVERTISSEMENT : .env contient THOT_DRY_RUN=${file_dry_run}."
      log_warn "Toute commande lancée sans ce script utilisera cette valeur."
      log_warn "Vérifiez que c'est un choix écrit et daté, pas un reste de manipulation."
    fi
    if [[ -n "${file_autonomy}" && "${file_autonomy}" != "supervised" && "${file_autonomy}" != "manual" ]]; then
      log_warn "AVERTISSEMENT : .env contient THOT_AUTONOMY=${file_autonomy}."
      log_warn "Le mode automatique ne doit pas être un défaut de développement."
    fi
  fi

  log_ok "Garde-fous imposés pour ce script : THOT_DRY_RUN=true, THOT_AUTONOMY=supervised."
}

# -----------------------------------------------------------------------------
# 5. Environnement virtuel
# -----------------------------------------------------------------------------
ensure_venv() {
  if [[ "${RECREATE}" == "true" && -d "${VENV_DIR}" ]]; then
    log_warn "--recreate : l'environnement virtuel ${VENV_DIR} va être SUPPRIMÉ puis recréé."
    log_step "Aucune donnée utilisateur n'y est stockée : la base locale est dans ./data."
    if ! confirm "Supprimer ${VENV_DIR} et le recréer ?"; then
      log_warn "Recréation refusée : l'environnement existant est conservé."
      RECREATE="false"
    fi
    if [[ "${RECREATE}" == "true" ]]; then
      run rm -rf "${VENV_DIR}"
    fi
  fi

  if [[ -x "${VENV_DIR}/bin/python" ]]; then
    VENV_PYTHON="${VENV_DIR}/bin/python"
    log_ok "Environnement virtuel réutilisé : ${VENV_DIR} ($("${VENV_PYTHON}" -V 2>&1))"
    return 0
  fi

  log_info "Création de l'environnement virtuel (${VENV_DIR})…"
  run "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    VENV_PYTHON="${VENV_DIR}/bin/python"
    return 0
  fi
  [[ -x "${VENV_DIR}/bin/python" ]] || die "python -m venv n'a pas produit ${VENV_DIR}/bin/python." 1
  VENV_PYTHON="${VENV_DIR}/bin/python"
  log_ok "Environnement virtuel créé : ${VENV_DIR}"
}

# -----------------------------------------------------------------------------
# 6. Dépendances (avec repli hors ligne)
# -----------------------------------------------------------------------------
install_package() {
  log_info "Mise à jour de pip (best effort)…"
  if [[ "${OFFLINE}" == "true" ]]; then
    log_step "--offline : mise à jour de pip ignorée (elle exigerait le réseau)."
  else
    run "${VENV_PYTHON}" -m pip install --upgrade pip || \
      log_warn "pip n'a pas pu être mis à jour (réseau indisponible ?) : on continue."
  fi

  if [[ "${OFFLINE}" == "true" ]]; then
    INSTALL_MODE="no-deps"
    log_info "Installation hors ligne : « pip install -e . --no-deps --no-build-isolation »…"
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_dry "${VENV_PYTHON}" -m pip install -e . --no-deps --no-build-isolation
    else
      "${VENV_PYTHON}" -m pip install -e . --no-deps --no-build-isolation \
        || die "Installation hors ligne impossible : les dépendances (fastapi, pydantic, PyYAML…) ne sont pas disponibles dans ce venv.
Solution : créez le venv avec accès réseau une première fois, ou installez les dépendances depuis un wheelhouse local (pip install --no-index --find-links <dir>)." 1
    fi
    report_install_mode
    return 0
  fi

  log_info "Installation du paquet en mode éditable avec les outils de développement…"
  log_step "commande : pip install -e \".\" [dev]   (pytest, ruff, mypy, httpx)"
  local rc=0
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry "${VENV_PYTHON}" -m pip install -e ".[dev]"
  else
    set +e
    "${VENV_PYTHON}" -m pip install -e ".[dev]"
    rc=$?
    set -e
  fi

  if [[ "${rc}" -eq 0 ]]; then
    INSTALL_MODE="dev"
    report_install_mode
    return 0
  fi

  # REPLI : le réseau est souvent indisponible en environnement cloisonné. On
  # installe alors le paquet sans ses dépendances : c'est utilisable si elles
  # sont déjà présentes dans le venv (ou fournies par ailleurs), et surtout cela
  # ne laisse pas le développeur devant un « ça ne marche pas ».
  log_warn "L'installation avec les outils de développement a échoué (réseau indisponible ?)."
  log_warn "REPLI hors ligne : « pip install -e . --no-deps --no-build-isolation »."
  INSTALL_MODE="no-deps"
  set +e
  "${VENV_PYTHON}" -m pip install -e . --no-deps --no-build-isolation
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    INSTALL_MODE="source"
    log_error "Le repli a également échoué : le paquet n'a pas pu être installé."
    log_step "Vérifiez les dépendances déjà présentes ou utilisez un wheelhouse local."
  fi
  report_install_mode
}

report_install_mode() {
  case "${INSTALL_MODE}" in
    dev)
      log_ok "Installation complète : paquet éditable + outils de développement."
      ;;
    no-deps)
      log_warn "Installation SANS dépendances : le paquet est en mode éditable, mais"
      log_warn "les outils de développement (pytest, ruff, mypy, httpx) peuvent manquer."
      log_step "« make test » utilise unittest (stdlib) et reste exécutable."
      log_step "Pour obtenir les outils plus tard, avec réseau :"
      log_step "${VENV_PYTHON} -m pip install -e \".[dev]\""
      ;;
    source)
      log_warn "Le paquet n'est pas installé : les commandes passeront par PYTHONPATH=src."
      log_step "C'est suffisant pour « python -m thotsecure.cli », à condition que les"
      log_step "dépendances d'exécution (fastapi, uvicorn, pydantic, PyYAML, Jinja2) soient présentes."
      ;;
  esac
}

verify_importable() {
  # Contrôle minimal : si le paquet et ses dépendances ne s'importent pas, il est
  # inutile d'enchaîner init-db, demo et doctor — le message d'erreur serait obscur.
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry "${VENV_PYTHON}" -c "import thotsecure, pydantic, yaml"
    return 0
  fi
  local rc=0
  set +e
  PYTHONPATH="src" "${VENV_PYTHON}" -c "import thotsecure, pydantic, yaml" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    log_ok "Paquet et dépendances d'exécution importables."
    return 0
  fi
  log_error "Le paquet ou ses dépendances ne s'importent pas dans ${VENV_DIR}."
  log_step "Dépendances d'exécution requises : fastapi, uvicorn, pydantic, pydantic-settings, PyYAML, Jinja2."
  log_step "Avec réseau :     ${VENV_PYTHON} -m pip install -e \".[dev]\""
  log_step "Hors ligne :      ${VENV_PYTHON} -m pip install --no-index --find-links ./wheelhouse -e \".[dev]\""
  log_step "Détail de l'erreur :"
  PYTHONPATH="src" "${VENV_PYTHON}" -c "import thotsecure, pydantic, yaml" 2>&1 | tail -n 5 | while IFS= read -r line; do log_step "${line}"; done || true
  die "Environnement incomplet : corrigez les dépendances puis relancez ${SCRIPT_NAME}." 1
}

# -----------------------------------------------------------------------------
# 7. Fichiers locaux : .env et périmètre déclaré
# -----------------------------------------------------------------------------
write_local_env() {
  if [[ "${WRITE_ENV}" != "true" ]]; then
    log_step "--no-env-file : aucun fichier .env local créé."
    return 0
  fi
  if [[ -f ".env" ]]; then
    log_ok ".env existant conservé (jamais écrasé par ce script)."
    return 0
  fi

  log_info "Création du fichier .env local (développement, ignoré par Git)…"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry write "${REPO_ROOT}/.env"
    return 0
  fi

  umask 077
  cat > .env <<'ENV'
# =============================================================================
#  Thot Secure — environnement de DÉVELOPPEMENT local (généré par dev-setup.sh)
#  Ce fichier est ignoré par Git (.gitignore) et ne doit JAMAIS être versionné.
#  Il ne contient aucun secret partagé : uniquement des réglages locaux.
# =============================================================================
THOT_ENV=dev
THOT_HOST=127.0.0.1
THOT_PORT=8080
THOT_DB_URL=sqlite:///./data/thotsecure.db
THOT_BUS=memory
THOT_LOG_LEVEL=INFO
THOT_LOG_FORMAT=console
THOT_RETENTION_DAYS=30

# --- SÛRETÉ : valeurs par défaut du projet, NE PAS INVERSER -------------------
# THOT_DRY_RUN=true      : aucune contre-mesure n'a d'effet réel.
# THOT_AUTONOMY=supervised : une action critique exige une approbation humaine.
# Le passage au mode réel est une décision d'exploitation écrite et datée, jamais
# un réglage de confort de développement.
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised
ENV
  chmod 0600 .env
  log_ok ".env créé (0600) avec les valeurs de sûreté par défaut."
}

ensure_targets_file() {
  if [[ -f "config/targets.yaml" ]]; then
    log_ok "Périmètre déclaré déjà présent : config/targets.yaml"
    return 0
  fi
  if [[ ! -f "config/targets.example.yaml" ]]; then
    log_warn "config/targets.example.yaml absent : périmètre non déclaré."
    log_step "« thotsecure doctor » signalera l'absence de périmètre (contrôle non critique)."
    return 0
  fi
  log_info "Déclaration initiale du périmètre : copie de l'exemple…"
  run cp -p "config/targets.example.yaml" "config/targets.yaml"
  log_ok "config/targets.yaml créé (ignoré par Git)."
  log_warn "ÉDITEZ-LE : c'est la SEULE source de vérité sur ce que Thot Secure a le"
  log_warn "droit d'observer et de modifier. Aucune cible n'est devinée automatiquement."
}

# -----------------------------------------------------------------------------
# 8. CLI applicative
# -----------------------------------------------------------------------------
resolve_cli() {
  # La commande console « thotsecure » est créée par pip dans le venv. Si
  # l'installation a échoué, on retombe sur « python -m thotsecure.cli ».
  if [[ -x "${VENV_DIR}/bin/thotsecure" ]]; then
    printf '%s\n' "${VENV_DIR}/bin/thotsecure"
    return 0
  fi
  return 1
}

run_cli() {
  # En --dry-run, la CLI n'est PAS exécutée : init-db, tenant create et demo
  # écrivent tous dans la base locale, et un mode « simulation » qui écrit quand
  # même ne serait pas une simulation honnête.
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_dry thotsecure "$@"
    return 0
  fi
  # Toutes les commandes sont lancées avec les GARDE-FOUS explicitement posés :
  # même si votre shell ou le .env disent le contraire, la simulation est active.
  local cli=""
  if cli="$(resolve_cli)"; then
    PYTHONPATH="src" THOT_DRY_RUN="true" THOT_AUTONOMY="supervised" "${cli}" "$@"
  else
    PYTHONPATH="src" THOT_DRY_RUN="true" THOT_AUTONOMY="supervised" \
      "${VENV_PYTHON}" -m thotsecure.cli "$@"
  fi
}

init_database() {
  log_info "Initialisation de la base locale…"
  run_cli init-db
  log_ok "Base prête (idempotent : relancer ne détruit rien)."
}

create_demo_tenant() {
  log_info "Tenant de démonstration « ${TENANT} »…"
  # --mode supervised et simulations actives : le tenant de démonstration ne peut
  # pas déclencher d'action réelle, et ses cibles protégées sont explicites.
  run_cli tenant create \
    --id "${TENANT}" \
    --name "Démonstration locale (${TENANT})" \
    --mode supervised \
    --protected 10.0.0.1 10.0.0.0/24
  log_ok "Tenant « ${TENANT} » enregistré ou mis à jour (upsert, donc idempotent)."
}

run_demo() {
  if [[ "${RUN_DEMO}" != "true" ]]; then
    log_step "--no-demo : jeu de démonstration non injecté."
    return 0
  fi
  log_info "Injection du jeu de démonstration (événements → findings → actions simulées)…"
  run_cli demo --tenant "${TENANT}"
  log_ok "Démonstration rejouable : les occurrences sont regroupées par règle et par clé."
}

run_doctor() {
  log_info "Diagnostic applicatif (thotsecure doctor)…"
  local rc=0
  set +e
  run_cli doctor
  rc=$?
  set -e
  case "${rc}" in
    0) log_ok "Doctor : aucun contrôle critique en échec." ;;
    3)
      log_warn "Doctor : au moins un contrôle CRITIQUE est en échec (ci-dessus)."
      log_step "C'est fréquent sur un dépôt fraîchement cloné : périmètre non déclaré,"
      log_step "politiques absentes, ou base non initialisée."
      ;;
    *) log_warn "Doctor s'est terminé avec le code ${rc}." ;;
  esac
  return "${rc}"
}

# -----------------------------------------------------------------------------
# 9. Récapitulatif
# -----------------------------------------------------------------------------
print_summary() {
  cat <<EOF

${C_BOLD}Environnement de développement prêt.${C_RESET}

${C_BOLD}Commandes utiles${C_RESET}
    make serve                 API + console : http://127.0.0.1:8080/
                               (sonde de vie : /healthz, prête : /readyz, métriques : /metrics)
    make demo                  rejouer le jeu de démonstration
    make test                  suite de tests (unittest, sans dépendance externe)
    make lint / make fmt       ruff (si les outils de développement ont pu être installés)
    make doctor                diagnostic applicatif
    make audit-verify          intégrité de la chaîne d'audit (code 3 si rompue)

${C_BOLD}En ligne de commande${C_RESET}
    ${VENV_DIR}/bin/thotsecure findings list --tenant ${TENANT}
    ${VENV_DIR}/bin/thotsecure key create --tenant ${TENANT} --role responder --label dev
    ${VENV_DIR}/bin/thotsecure audit tail --tenant ${TENANT}
    (si le lanceur n'existe pas : PYTHONPATH=src ${VENV_PYTHON} -m thotsecure.cli …)

${C_BOLD}Fichiers créés ou réutilisés${C_RESET}
    ${VENV_DIR}/                  environnement virtuel (ignoré par Git)
    .env                       réglages locaux (0600, ignoré par Git)
    config/targets.yaml        périmètre déclaré — À ÉDITER (ignoré par Git)
    data/thotsecure.db         base SQLite locale (ignorée par Git)

${C_BOLD}SÛRETÉ — à ne pas perdre de vue${C_RESET}
    * THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont les valeurs par défaut.
      Ce script ne les a PAS inversées : aucune action réelle n'est possible.
    * Pour observer un comportement réel, ne désactivez pas la simulation en
      développement : utilisez un environnement de recette dédié, une décision
      écrite, et des cibles que vous possédez (config/targets.yaml).
    * Thot Secure est STRICTEMENT DÉFENSIF : aucune capacité offensive, jamais.
      Ne l'utilisez que sur des actifs que vous exploitez, et avec autorisation.
    * Le journal d'audit est chaîné par hash : vérifiez-le avant et après toute
      manipulation de données (thotsecure audit verify).

${C_DIM}Prochaines lectures : docs/quickstart.md, docs/configuration.md,
docs/architecture/api-contract.md (contrat gelé), CONTRIBUTING.md.${C_RESET}
EOF
}

# -----------------------------------------------------------------------------
# 10. Point d'entrée
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s%s%s\n' "${C_BOLD}" "Thot Secure — ${SCRIPT_NAME} ${SCRIPT_VERSION}" "${C_RESET}"
  log_warn "Lisez ce script avant de l'exécuter : il modifie le dépôt (venv, .env, base locale)."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "MODE --dry-run : rien ne sera modifié."
  fi

  locate_repo_root
  check_python
  warn_if_unsafe_settings

  ensure_venv
  install_package
  verify_importable
  write_local_env
  ensure_targets_file

  init_database
  create_demo_tenant
  run_demo

  local doctor_rc=0
  run_doctor || doctor_rc=$?

  print_summary

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "Mode --dry-run : aucune modification n'a été appliquée."
    return 0
  fi
  if [[ "${doctor_rc}" -eq "${EXIT_VERIFY}" ]]; then
    log_warn "Environnement fonctionnel, mais le diagnostic signale un point critique (voir ci-dessus)."
    return "${EXIT_VERIFY}"
  fi
  log_ok "Terminé."
}

main "$@"
