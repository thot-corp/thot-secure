"""Persistance PostgreSQL / TimescaleDB — cible de production.

Ce module est la seconde implémentation de ``storage.base.StoreProtocol`` : la suite
``tests/test_storage_conformance.py`` exécute le **même** corpus de tests contre SQLite et contre
une vraie base TimescaleDB (job ``postgres`` de la CI).

Décisions de conception
-----------------------

**Pilote importé paresseusement.** ``psycopg`` (v3) est préféré, ``psycopg2`` sert de repli.
L'import a lieu à la **première connexion**, jamais à l'import du paquet : ``import thotsecure``
et ``create_store()`` fonctionnent donc sans qu'aucun pilote PostgreSQL ne soit installé. Si aucun
pilote n'est présent, l'erreur est explicite et contient la commande à exécuter.

**Verrou du chaînage d'audit.** ``append_audit`` doit lire le dernier maillon et écrire le
suivant sans qu'un autre processus ne s'intercale. Le verrou retenu est un **verrou consultatif
de transaction** (``pg_advisory_xact_lock(hashtext('thotsecure.audit_log'))``) :

* il est **global** à la base — ``hashtext`` produit une clé stable de 32 bits, donc tous les
  processus qui audite la même base se sérialisent, y compris ceux d'une autre version du code ;
* il est **relâché automatiquement** à la fin de la transaction (``COMMIT`` comme ``ROLLBACK``),
  y compris si le processus meurt brutalement : aucun risque de verrou orphelin, contrairement à
  ``pg_advisory_lock`` (verrou de session) ;
* il ne bloque **que** les autres écritures d'audit, pendant la microseconde que dure la
  transaction, et jamais une lecture d'événements.

``SELECT ... ORDER BY seq DESC LIMIT 1 FOR UPDATE`` a été écarté : sur une table vide il n'y a
aucune ligne à verrouiller, et PostgreSQL ne pose pas de verrou « de trou » (contrairement à
``SELECT ... FOR UPDATE`` sur index en répétition sérialisable). Deux processus transactant en
parallèle chaîneraient donc tous les deux sur le genesis. Le verrou consultatif est le seul
primitif qui couvre le cas « table vide » et le cas « dernier maillon en cours d'écriture ».

Le ``seq`` provient de la séquence ``audit_log_seq`` : il est **connu avant l'insertion**, ce qui
permet de calculer l'empreinte (qui porte sur ``seq``) en une seule instruction ``INSERT``. Une
colonne ``IDENTITY`` obligerait à insérer puis à mettre à jour, ce qui interdit tout durcissement
« append-only » ultérieur.

**Rejeu multi-processus.** ``pending_events`` utilise ``FOR UPDATE SKIP LOCKED`` dans une
transaction courte : deux rejeux simultanés ne lisent pas le même lot. La fenêtre de traitement
n'est pas couverte pour autant (le pipeline traite les événements hors transaction) ;
``mark_events_processed`` reste l'arbitre (son ``UPDATE ... WHERE processed = FALSE`` est atomique)
et ``claim_pending_events`` offre une réservation par **bail** pour un rejeu multi-nœuds strict.

**Rétention.** ``purge`` procède par lots bornés : sur une hypertable compressée, la suppression
passe par ``drop_chunks`` (seule opération possible sur des chunks compressés) ; ailleurs, par
``DELETE`` successifs de ``PURGE_BATCH_SIZE`` lignes maximum, indexées par ``ctid`` — jamais un
``DELETE`` monolithique qui verrouillerait la table entière.

**Sécurité du DSN.** Le mot de passe n'est jamais journalisé : tous les messages et tous les
journaux passent par :func:`mask_dsn` (``postgresql://user:***@host/db``). ``sslmode`` est
toujours explicite (``prefer`` hors production, ``require`` en production). Aucune valeur n'est
concaténée dans le SQL : les paramètres sont liés, et les seuls fragments interpolés sont des
**noms de tables et de colonnes issus de constantes internes**.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import re
import threading
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import ModuleType
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..audit.hashchain import GENESIS_HASH, record_fingerprint
from ..core.errors import ConflictError, NotFoundError, StorageError
from ..core.logging_setup import get_logger
from ..core.models import (
    Action,
    ApiKeyRecord,
    AuditRecord,
    CollectorStatus,
    Event,
    Finding,
    StatsOverview,
    Tenant,
)
from ..core.util import chunked, iso_z, new_id, now_iso, parse_dt, safe_float, safe_int, utcnow
from .base import (
    FEATURE_COMPRESSION,
    FEATURE_CONTINUOUS_AGGREGATES,
    FEATURE_JSONB,
    FEATURE_NATIVE_RETENTION,
    FEATURE_PENDING_CLAIM,
    FEATURE_SKIP_LOCKED,
    StoreProtocol,
)
from .schema import POSTGRES_CORE_DDL, POSTGRES_TIMESCALE_SECTIONS, SCHEMA_VERSION
from .store import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    Store,
    _decode_cursor,
    _encode_cursor,
)

log = get_logger("storage.postgres")

# --------------------------------------------------------------------------------------
# Constantes de dimensionnement
# --------------------------------------------------------------------------------------

#: Nombre de lignes insérées par instruction (``execute_values`` ou ``executemany``). 1000 est le
#: compromis retenu : au-delà, la requête devient longue à planifier et la mémoire du client
#: monte ; en deçà, la latence réseau domine.
INSERT_BATCH_SIZE = 1000

#: Nombre maximum de lignes supprimées par transaction de purge.
PURGE_BATCH_SIZE = 5000

#: Garde-fou : nombre maximal de lots traités par une purge (au-delà, on s'arrête et on
#: journalise — une purge qui ne converge pas est un incident, pas une boucle infinie).
MAX_PURGE_BATCHES = 2000

#: Code SQLSTATE d'une violation de contrainte d'unicité (mappée en ``ConflictError``).
UNIQUE_VIOLATION = "23505"

#: Verrou consultatif de transaction protégeant le chaînage du journal d'audit.
#: ``hashtext`` rend la clé auto-documentée et stable ; le verrou est relâché au COMMIT/ROLLBACK.
AUDIT_CHAIN_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext('thotsecure.audit_log'))"

#: Dernier maillon de la chaîne (lu **sous** le verrou consultatif ci-dessus).
AUDIT_TAIL_SQL = "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1"

#: Numéro du prochain maillon. Une séquence dédiée (et non ``IDENTITY``) parce que l'empreinte
#: porte sur ``seq`` : elle doit être connue **avant** l'insertion. Une valeur consommée puis
#: annulée laisse un trou, jamais un doublon — c'est la garantie attendue d'un journal chaîné.
AUDIT_SEQ_SQL = "SELECT nextval('audit_log_seq') AS seq"

#: Message d'installation affiché quand aucun pilote n'est disponible. Actionnable : il dit
#: quoi installer, pourquoi, et comment rester en SQLite sans rien installer.
DRIVER_INSTALL_HINT = (
    'pip install "thotsecure[postgres]"  (ou directement : pip install "psycopg[binary]")'
)

#: Schémas de DSN acceptés et réécrits vers ``postgresql://``.
_SUPPORTED_DSN_SUFFIXES = frozenset({"", "psycopg", "psycopg2"})

#: ``sslmode`` par défaut selon l'environnement. En production, l'absence de TLS entre
#: l'application et la base est un incident : ``require`` est le défaut, jamais ``disable``.
SSLMODE_BY_ENV: dict[str, str] = {"dev": "prefer", "staging": "prefer", "prod": "require"}

# --------------------------------------------------------------------------------------
# Mappage des types : quelles colonnes exigent un cast explicite
# --------------------------------------------------------------------------------------

#: Colonnes ``JSONB`` : la valeur est envoyée en texte et castée par le serveur
#: (``%s::jsonb``). Le cast explicite est indispensable pour fonctionner avec psycopg 3 (qui
#: annonce le paramètre comme ``text``) **et** avec psycopg2 (paramètre non typé).
JSONB_COLUMNS: dict[str, frozenset[str]] = {
    "tenants": frozenset({"autonomy_allowlist", "protected_targets"}),
    "events": frozenset({"labels", "payload"}),
    "findings": frozenset({"tags", "mitre", "evidence", "event_ids"}),
    "actions": frozenset({"params", "target", "result", "rollback"}),
    "audit_log": frozenset({"target", "before", "after", "context"}),
    "collector_runs": frozenset({"detail"}),
}

#: Colonnes ``TIMESTAMPTZ`` : les horodatages circulent en ISO-8601 UTC (format du contrat
#: §3.1) et sont castés par le serveur (``%s::timestamptz``).
TIMESTAMPTZ_COLUMNS: dict[str, frozenset[str]] = {
    "tenants": frozenset({"created_at", "updated_at"}),
    "api_keys": frozenset({"created_at", "last_used_at", "revoked_at"}),
    "events": frozenset({"ts", "ingested_at", "processed_at", "claimed_at"}),
    "findings": frozenset({"first_seen", "last_seen", "created_at", "updated_at"}),
    "actions": frozenset(
        {"requested_at", "approved_at", "rejected_at", "executed_at", "expires_at"}
    ),
    "audit_log": frozenset({"ts"}),
    "collector_runs": frozenset({"started_at", "finished_at"}),
    "suppressions": frozenset({"created_at", "expires_at"}),
}

# --------------------------------------------------------------------------------------
# Utilitaires de DSN — aucune valeur secrète ne doit sortir d'ici
# --------------------------------------------------------------------------------------

_DSN_PASSWORD_IN_TEXT = re.compile(r"(\w+://[^\s:/@]+:)[^\s:/@]+(@)")
_KEYWORD_PASSWORD = re.compile(r"(?i)\b(password|passfile|sslpassword)\s*=\s*\S+")
_QUERY_PASSWORD = re.compile(r"(?i)((?:password|passfile|sslpassword)=)[^&;\s]+")


def mask_dsn(dsn: str) -> str:
    """Retourne le DSN débarrassé de tout secret, pour les journaux et les erreurs.

    >>> mask_dsn("postgresql://thot:s3cr3t@db:5432/thot?sslmode=require")
    'postgresql://thot:***@db:5432/thot?sslmode=require'

    Traite les trois formes possibles : URL (``user:secret@``), paramètres d'URL
    (``?password=…``) et chaîne ``clé=valeur`` de libpq (``password=…``).
    """
    text = str(dsn or "")
    if not text:
        return ""
    if "://" in text:
        scheme, rest = text.split("://", 1)
        if "@" in rest:
            credentials, host = rest.rsplit("@", 1)
            if ":" in credentials:
                user = credentials.split(":", 1)[0]
                rest = f"{user}:***@{host}"
        rest = _QUERY_PASSWORD.sub(r"\1***", rest)
        return f"{scheme}://{rest}"
    return _KEYWORD_PASSWORD.sub(r"\1=***", text)


def redact_dsn_in_text(text: str) -> str:
    """Masque un DSN qui apparaîtrait **dans un message** (erreur de pilote, par exemple).

    Un pilote qui échoue peut recopier sa chaîne de connexion dans son message d'erreur : sans
    ce filtre, un mot de passe finirait dans les journaux du service via le champ ``error``.
    """
    return _DSN_PASSWORD_IN_TEXT.sub(r"\1***\2", str(text or ""))


def normalize_dsn(url: str) -> str:
    """Normalise un DSN vers la forme ``postgresql://`` comprise par ``psycopg``/``psycopg2``.

    Accepte ``postgres://`` et les formes qualifiées ``postgresql+psycopg://`` /
    ``postgresql+psycopg2://`` (convention SQLAlchemy utilisée par ``THOT_DB_URL``). Les autres
    pilotes (``asyncpg``, ``pg8000``…) sont **refusés explicitement** : l'adaptateur est
    synchrone et n'utilise que psycopg.

    Une chaîne ``clé=valeur`` de libpq (``host=… dbname=…``) est retournée telle quelle : elle est
    valide pour les deux pilotes, seul le traitement de ``sslmode`` s'y applique différemment.

    Erreurs : ``StorageError`` si le DSN est vide ou si le pilote demandé n'est pas supporté.
    """
    text = str(url or "").strip()
    if not text:
        raise StorageError(
            "DSN PostgreSQL vide : renseignez THOT_DB_URL (par exemple "
            "postgresql://thot:motdepasse@127.0.0.1:5432/thotsecure)"
        )
    if "://" not in text:
        return text
    scheme, rest = text.split("://", 1)
    base, _, driver = scheme.partition("+")
    if base.lower() not in {"postgres", "postgresql"}:
        raise StorageError(
            f"schéma de DSN non supporté : {scheme!r}. Attendu 'postgresql://' "
            "(ou 'postgres://', 'postgresql+psycopg://', 'postgresql+psycopg2://').",
            details={"scheme": scheme},
        )
    if driver.lower() not in _SUPPORTED_DSN_SUFFIXES:
        raise StorageError(
            f"pilote PostgreSQL non supporté : {driver!r}. L'adaptateur est synchrone et "
            "n'utilise que psycopg (v3) ou psycopg2 : utilisez 'postgresql://'.",
            details={"driver": driver},
        )
    return f"postgresql://{rest}"


def with_query_params(dsn: str, params: Mapping[str, Any]) -> str:
    """Ajoute des paramètres de connexion **sans écraser** ceux déjà présents dans le DSN."""
    if not params:
        return dsn
    defaults = {str(key): str(value) for key, value in params.items() if value is not None}
    if not defaults:
        return dsn
    if "://" not in dsn:  # forme clé=valeur : on complète les paramètres absents
        present = {part.split("=", 1)[0].strip().lower() for part in dsn.split() if "=" in part}
        extra = [f"{key}={value}" for key, value in defaults.items() if key.lower() not in present]
        return " ".join([dsn, *extra]) if extra else dsn
    parts = urlsplit(dsn)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in defaults.items():
        query.setdefault(key, value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def build_dsn(
    url: str,
    *,
    env: str = "dev",
    sslmode: str | None = None,
    application_name: str = "thotsecure",
    connect_timeout: int = 10,
) -> str:
    """Construit le DSN effectif : normalisation, ``sslmode`` explicite, délais, nom d'application.

    ``sslmode`` n'est **jamais** implicite : ``prefer`` hors production (le développement local
    n'exige pas de certificat), ``require`` en production. Un ``sslmode`` déjà présent dans le
    DSN est conservé — l'exploitant reste maître de sa politique TLS, y compris
    ``verify-full`` avec une autorité de certification interne.

    ``application_name`` apparaît dans ``pg_stat_activity`` : sans lui, diagnostiquer un pic de
    connexions sur une base partagée revient à deviner.
    """
    dsn = normalize_dsn(url)
    default_sslmode = SSLMODE_BY_ENV.get(str(env or "dev").lower(), SSLMODE_BY_ENV["dev"])
    dsn = with_query_params(dsn, {"sslmode": sslmode or default_sslmode})
    if sslmode:
        # Une valeur explicite remplace celle du DSN (elle vient de l'appelant, pas d'un défaut).
        dsn = _force_query_param(dsn, "sslmode", sslmode)
    dsn = with_query_params(
        dsn,
        {
            "application_name": application_name,
            "connect_timeout": connect_timeout,
        },
    )
    return dsn


def _force_query_param(dsn: str, key: str, value: str) -> str:
    if "://" not in dsn:
        text = re.sub(rf"(?i)\b{re.escape(key)}\s*=\s*\S+", f"{key}={value}", dsn)
        return text if re.search(rf"(?i)\b{re.escape(key)}=", text) else f"{dsn} {key}={value}"
    parts = urlsplit(dsn)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


# --------------------------------------------------------------------------------------
# Construction de SQL : découpage et placeholders typés
# --------------------------------------------------------------------------------------


def split_sql_statements(sql: str) -> list[str]:
    """Découpe un script SQL en instructions, en respectant littéraux et commentaires.

    Pourquoi ne pas appeler ``cursor.execute(ddl)`` avec le script complet : un échec devient
    alors un message d'erreur global (« erreur dans le DDL ») au lieu de l'instruction fautive,
    et les pilotes ne se comportent pas tous pareil face à plusieurs instructions. Ici, chaque
    instruction est exécutée séparément et la coupable est nommée dans l'erreur.

    Gère : commentaires ``--`` et ``/* */``, littéraux ``'…'`` (avec ``''`` échappé),
    identifiants ``"…"`` et chaînes « dollar-quoted » (``$$ … $$``, ``$tag$ … $tag$``).
    """
    statements: list[str] = []
    buffer: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char == "-" and sql.startswith("--", index):
            end = sql.find("\n", index)
            index = length if end == -1 else end
            continue
        if char == "/" and sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char == "'":
            cursor = index + 1
            while cursor < length:
                if sql[cursor] == "'":
                    if cursor + 1 < length and sql[cursor + 1] == "'":
                        cursor += 2
                        continue
                    cursor += 1
                    break
                cursor += 1
            buffer.append(sql[index:cursor])
            index = cursor
            continue
        if char == '"':
            end = sql.find('"', index + 1)
            end = length if end == -1 else end + 1
            buffer.append(sql[index:end])
            index = end
            continue
        if char == "$":
            tag_match = re.match(r"\$[A-Za-z_0-9]*\$", sql[index:])
            if tag_match:
                tag = tag_match.group(0)
                end = sql.find(tag, index + len(tag))
                if end == -1:
                    buffer.append(sql[index:])
                    index = length
                    continue
                cursor = end + len(tag)
                buffer.append(sql[index:cursor])
                index = cursor
                continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    tail = "".join(buffer).strip()
    if tail:
        statements.append(tail)
    return statements


def placeholders(count: int) -> str:
    """``n`` placeholders liés, séparés par des virgules (``%s, %s, %s``)."""
    return ", ".join(["%s"] * max(0, int(count)))


def in_clause(column: str, count: int) -> str:
    """Clause ``IN`` paramétrée (``kind IN (%s, %s)``).

    ``column`` provient toujours d'une constante interne (jamais d'une entrée utilisateur) ;
    les **valeurs**, elles, ne sont jamais concaténées : ce sont des paramètres liés.
    """
    return f"{column} IN ({placeholders(count)})"


def column_placeholder(table: str, column: str) -> str:
    """Placeholder typé d'une colonne : ``%s::jsonb``, ``%s::timestamptz`` ou ``%s``.

    C'est ce qui permet de lier des ``dict``/listes Python (sérialisés en texte) et des
    horodatages ISO-8601 sans dépendre des adaptateurs propres à chaque pilote : le cast est
    explicite dans la requête, donc identique avec psycopg 3 et psycopg2.
    """
    if column in JSONB_COLUMNS.get(table, frozenset()):
        return "%s::jsonb"
    if column in TIMESTAMPTZ_COLUMNS.get(table, frozenset()):
        return "%s::timestamptz"
    return "%s"


def json_document(value: Any) -> str:
    """Sérialise une valeur Python destinée à une colonne ``JSONB``.

    ``ensure_ascii=False`` conserve les accents lisibles (comme SQLite) et ``default=str`` évite
    qu'un objet non sérialisable (``datetime``, ``Decimal``) ne fasse échouer une ingestion :
    une preuve dégradée vaut mieux qu'un événement perdu.
    """
    return json.dumps(value, ensure_ascii=False, default=str)


def load_document(value: Any, default: Any) -> Any:
    """Désérialise une colonne JSON : le code appelant manipule des ``dict``, jamais des chaînes.

    Les deux pilotes rendent déjà un objet Python pour ``jsonb`` ; la fonction reste tolérante
    (chaîne JSON, ``None``, valeur déjà décodée) pour ne pas dépendre de ce comportement.
    """
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------------------
# Pilote : psycopg (v3) puis psycopg2
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DriverHandle:
    """Ce que l'adaptateur utilise réellement d'un pilote, et rien de plus.

    Cette indirection (plutôt que des appels directs à ``psycopg``) rend le module testable
    **hors ligne** : les tests substituent une poignée enregistreuse à :func:`import_driver` et
    vérifient le SQL émis sans qu'aucun serveur PostgreSQL n'existe.
    """

    #: ``"psycopg"`` (v3) ou ``"psycopg2"``.
    name: str
    #: Module du pilote (accès à ``Error``, ``connect``, ``extras``…).
    module: ModuleType
    #: Fabrique de curseurs rendant des lignes accessibles par nom de colonne.
    row_factory: Any = None
    #: ``psycopg2.extras.execute_values`` si disponible (insertion par lots rapide).
    execute_values: Any = None

    @property
    def supports_execute_values(self) -> bool:
        return callable(self.execute_values)


_DRIVER_LOCK = threading.Lock()
_DRIVER_HANDLE: DriverHandle | None = None


def import_driver(*, refresh: bool = False) -> DriverHandle:
    """Importe le pilote PostgreSQL disponible : ``psycopg`` (v3), puis ``psycopg2``.

    L'import est **paresseux** (premier appel) et mis en cache : ``import thotsecure`` ne dépend
    donc d'aucun pilote PostgreSQL, et une installation SQLite n'a rien à installer.

    Erreurs : ``StorageError`` si aucun des deux pilotes n'est présent, avec la commande exacte
    à exécuter et le rappel que SQLite reste disponible sans dépendance.
    """
    global _DRIVER_HANDLE
    with _DRIVER_LOCK:
        if _DRIVER_HANDLE is not None and not refresh:
            return _DRIVER_HANDLE
        handle = _load_driver()
        _DRIVER_HANDLE = handle
        return handle


def _load_driver() -> DriverHandle:
    try:  # psycopg 3, pilote recommandé
        psycopg = importlib.import_module("psycopg")
        rows = importlib.import_module("psycopg.rows")
    except ImportError:
        pass
    else:
        log.debug("pilote PostgreSQL retenu", extra={"driver": "psycopg"})
        return DriverHandle(name="psycopg", module=psycopg, row_factory=rows.dict_row)
    try:  # repli : psycopg2, fourni par la plupart des distributions
        psycopg2 = importlib.import_module("psycopg2")
        extras = importlib.import_module("psycopg2.extras")
    except ImportError as exc:
        raise StorageError(
            "aucun pilote PostgreSQL installé : PostgreSQL/TimescaleDB est un extra optionnel "
            f"d'Thot Secure. Installez-le avec `{DRIVER_INSTALL_HINT}`, puis relancez. "
            "Aucune dépendance n'est nécessaire pour SQLite "
            "(THOT_DB_URL=sqlite:///./data/thotsecure.db).",
            details={"packages": ["psycopg", "psycopg2"], "missing": "psycopg, psycopg2"},
        ) from exc
    log.debug("pilote PostgreSQL retenu", extra={"driver": "psycopg2"})
    return DriverHandle(
        name="psycopg2",
        module=psycopg2,
        row_factory=extras.DictCursor,
        execute_values=extras.execute_values,
    )


def sqlstate(exc: BaseException) -> str | None:
    """Code SQLSTATE d'une erreur de pilote, quel que soit le pilote.

    psycopg2 expose ``pgcode``, psycopg 3 expose ``sqlstate``. Passer par cet accesseur évite
    d'importer les classes d'erreur de l'un ou de l'autre — et donc de dépendre d'un pilote
    précis pour distinguer une violation d'unicité (``23505``) d'une panne de connexion.
    """
    for attribute in ("sqlstate", "pgcode"):
        value = getattr(exc, attribute, None)
        if isinstance(value, str) and value:
            return value
    return None


# --------------------------------------------------------------------------------------
# Pool de connexions
# --------------------------------------------------------------------------------------


class SimpleConnectionPool:
    """Pool de connexions minimal, thread-safe et **paresseux**.

    Pourquoi un pool maison : ``psycopg_pool`` n'existe que pour ``psycopg`` v3, alors que
    ``psycopg2`` (souvent déjà présent sur un serveur) n'en fournit aucun — et ouvrir une
    connexion par requête coûte plusieurs millisecondes, ce qui est inacceptable sur le chemin
    d'ingestion.

    Aucune connexion n'est ouverte à la construction : ``create_store()`` ne doit jamais exiger
    un serveur joignable (une CLI qui échoue au démarrage parce que la base est momentanément
    indisponible est un mauvais diagnostic). Le plafond ``max_size`` est une limite **dure** :
    au-delà, ``acquire`` attend puis lève plutôt que d'écraser la base sous les connexions.
    """

    def __init__(self, connect: Any, *, max_size: int = 8, timeout: float = 30.0) -> None:
        self._connect = connect
        self._max_size = max(1, int(max_size))
        self._timeout = max(1.0, float(timeout))
        self._idle: list[Any] = []
        self._in_use = 0
        self._closed = False
        self._condition = threading.Condition()

    @property
    def stats(self) -> dict[str, int]:
        with self._condition:
            return {"idle": len(self._idle), "in_use": self._in_use, "max": self._max_size}

    def acquire(self) -> Any:
        with self._condition:
            deadline = time.monotonic() + self._timeout
            while True:
                if self._closed:
                    raise StorageError("le pool de connexions PostgreSQL est fermé")
                while self._idle:
                    connection = self._idle.pop()
                    if not _connection_is_open(connection):
                        _close_quietly(connection)
                        continue
                    self._in_use += 1
                    return connection
                if self._in_use < self._max_size:
                    self._in_use += 1
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StorageError(
                        "pool de connexions PostgreSQL saturé : aucune connexion libre avant "
                        f"{self._timeout:.0f} s. Augmentez max_size ou réduisez la concurrence.",
                        details=dict(self.stats),
                    )
                self._condition.wait(remaining)
        try:
            return self._connect()
        except Exception:
            with self._condition:
                self._in_use -= 1
                self._condition.notify()
            raise

    def release(self, connection: Any) -> None:
        if connection is None:
            return
        with self._condition:
            self._in_use = max(0, self._in_use - 1)
            if self._closed or not _connection_is_open(connection):
                keep = False
            else:
                keep = True
                self._idle.append(connection)
            self._condition.notify()
        if not keep:
            _close_quietly(connection)

    def close(self) -> None:
        with self._condition:
            self._closed = True
            idle, self._idle = self._idle, []
            self._condition.notify_all()
        for connection in idle:
            _close_quietly(connection)


def _connection_is_open(connection: Any) -> bool:
    return not bool(getattr(connection, "closed", False))


def _close_quietly(connection: Any) -> None:
    with contextlib.suppress(Exception):
        connection.close()


# --------------------------------------------------------------------------------------
# Magasin PostgreSQL
# --------------------------------------------------------------------------------------


class PostgresStore:
    """Magasin PostgreSQL/TimescaleDB — implémentation de ``storage.base.StoreProtocol``.

    Une instance par processus, connexion épinglée par thread (comme l'implémentation SQLite :
    le pipeline, l'API et les tests appellent le magasin depuis plusieurs threads).

    Le DSN n'est **jamais** journalisé en clair : ``safe_dsn`` en donne la forme masquée, utilisée
    partout dans les messages.
    """

    backend_name: ClassVar[str] = "postgresql"

    def __init__(
        self,
        dsn: str,
        *,
        env: str = "dev",
        sslmode: str | None = None,
        min_size: int = 1,
        max_size: int = 8,
        timeout: float = 30.0,
        statement_timeout_ms: int = 60_000,
        application_name: str = "thotsecure",
        connect_timeout: int = 10,
        batch_size: int = INSERT_BATCH_SIZE,
        purge_batch_size: int = PURGE_BATCH_SIZE,
        driver: DriverHandle | None = None,
        pool: Any = None,
        use_driver_pool: bool = True,
    ) -> None:
        """Prépare l'accès à une base PostgreSQL **sans s'y connecter**.

        :param dsn: ``postgresql://user:motdepasse@hote:5432/base`` (ou ``postgres://``, ou une
            forme ``clé=valeur`` de libpq). Le mot de passe n'est jamais journalisé.
        :param env: ``dev`` | ``staging`` | ``prod`` — pilote le ``sslmode`` par défaut
            (``prefer`` hors production, ``require`` en production).
        :param sslmode: force une valeur (``require``, ``verify-full``…). Prioritaire sur ``env``.
        :param min_size: taille minimale du pool (honorée par ``psycopg_pool`` ; le pool maison
            ouvre ses connexions à la demande, jamais à la construction).
        :param max_size: limite **dure** du nombre de connexions simultanées.
        :param timeout: attente maximale d'une connexion libre, en secondes.
        :param statement_timeout_ms: garde-fou serveur (``statement_timeout``) : une requête qui
            dérape est interrompue par le serveur au lieu de tenir un verrou indéfiniment.
        :param batch_size: lignes par instruction lors d'une insertion par lots.
        :param purge_batch_size: lignes supprimées par transaction lors d'une purge.
        :param driver: poignée de pilote (injection réservée aux tests hors ligne).
        :param pool: pool de connexions déjà construit (injection réservée aux tests).
        :param use_driver_pool: si ``False``, force le pool maison (utile quand
            ``psycopg_pool`` est installé mais qu'un pool explicite est fourni, ou en test).

        Erreurs : ``StorageError`` si le DSN est vide ou non supporté. **Aucune** connexion n'est
        tentée ici : un DSN valide mais un serveur éteint ne se manifeste qu'au premier appel
        (``health()`` retourne alors ``False``).
        """
        self.dsn = build_dsn(
            dsn,
            env=env,
            sslmode=sslmode,
            application_name=application_name,
            connect_timeout=connect_timeout,
        )
        self.safe_dsn = mask_dsn(self.dsn)
        self.env = env
        self.min_size = max(1, int(min_size))
        self.max_size = max(1, int(max_size))
        self.timeout = float(timeout)
        self.statement_timeout_ms = max(0, int(statement_timeout_ms))
        self.batch_size = max(1, int(batch_size))
        self.purge_batch_size = max(1, int(purge_batch_size))
        self._driver = driver
        self._local = threading.local()
        self._closed = False
        self._features: frozenset[str] = frozenset(
            {FEATURE_JSONB, FEATURE_SKIP_LOCKED, FEATURE_PENDING_CLAIM}
        )
        self._timescaledb = False
        self.connect_timeout = max(1, int(connect_timeout))
        self._use_driver_pool = bool(use_driver_pool)
        # Le pool — et donc le pilote — ne sont sollicités qu'à la première connexion : construire
        # un magasin ne doit jamais exiger qu'un pilote soit installé ni qu'un serveur réponde.
        self._pool = pool
        self._pool_lock = threading.Lock()

    # ----------------------------------------------------------------------------------
    # Connexions
    # ----------------------------------------------------------------------------------

    @property
    def driver(self) -> DriverHandle:
        """Poignée du pilote (``psycopg`` puis ``psycopg2``), importée à la première demande."""
        if self._driver is None:
            self._driver = import_driver()
        return self._driver

    @property
    def pool(self) -> Any:
        """Pool de connexions, construit au premier besoin (jamais à la construction)."""
        if self._pool is None:
            with self._pool_lock:
                if self._pool is None:
                    self._pool = self._create_pool()
        return self._pool

    def _create_pool(self) -> Any:
        """Construit le pool : ``psycopg_pool`` s'il est là, sinon le pool maison."""
        module = self.driver.name
        if module == "psycopg" and self._use_driver_pool:
            try:
                pool_module = importlib.import_module("psycopg_pool")
            except ImportError:
                pool_module = None
            if pool_module is not None:
                log.debug("pool de connexions psycopg_pool retenu", extra={"dsn": self.safe_dsn})
                return _PsycopgPoolAdapter(
                    pool_module.ConnectionPool,
                    self.dsn,
                    min_size=self.min_size,
                    max_size=self.max_size,
                    timeout=self.timeout,
                    connect_kwargs=self._connect_kwargs(),
                )
        log.debug("pool de connexions maison retenu", extra={"dsn": self.safe_dsn})
        return SimpleConnectionPool(self._connect, max_size=self.max_size, timeout=self.timeout)

    def _connect_kwargs(self) -> dict[str, Any]:
        options = (
            f"-c statement_timeout={self.statement_timeout_ms}" if self.statement_timeout_ms else ""
        )
        kwargs: dict[str, Any] = {"connect_timeout": self.connect_timeout}
        if options:
            kwargs["options"] = options
        return kwargs

    def _connect(self) -> Any:
        """Ouvre une connexion réelle (autocommit : les transactions sont explicites)."""
        try:
            connection = self.driver.module.connect(self.dsn, **self._connect_kwargs())
            connection.autocommit = True
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                f"connexion PostgreSQL impossible ({self.safe_dsn})",
                details={"error": redact_dsn_in_text(str(exc)), "sqlstate": sqlstate(exc)},
            ) from exc
        return connection

    @property
    def connection(self) -> Any:
        """Connexion épinglée du thread courant (le pool n'est sollicité qu'une fois par thread)."""
        connection = getattr(self._local, "conn", None)
        if connection is not None and not _connection_is_open(connection):
            connection = None
            self._local.conn = None
        if connection is None:
            if self._closed:
                raise StorageError("le stockage est fermé")
            connection = self.pool.acquire()
            self._local.conn = connection
        return connection

    def close(self) -> None:
        """Libère la connexion du thread et ferme le pool. Idempotent."""
        connection = getattr(self._local, "conn", None)
        pool = self._pool
        if connection is not None:
            self._local.conn = None
            if pool is not None:
                with contextlib.suppress(Exception):
                    pool.release(connection)
            else:
                _close_quietly(connection)
        self._closed = True
        if pool is not None:
            with contextlib.suppress(Exception):
                pool.close()
        log.debug("stockage PostgreSQL fermé", extra={"dsn": self.safe_dsn})

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """Transaction explicite (``BEGIN``/``COMMIT``), ré-entrante via points de sauvegarde.

        La connexion est en ``autocommit`` : chaque instruction isolée est donc validée
        immédiatement, et une transaction n'existe que si l'appelant en ouvre une — exactement le
        comportement de l'implémentation SQLite (``isolation_level=None`` + ``BEGIN`` explicite).

        Un appel imbriqué (par exemple une méthode du magasin à l'intérieur d'une transaction
        ouverte par l'appelant) utilise un ``SAVEPOINT`` : une erreur interne n'annule que le
        travail imbriqué, pas la transaction externe.
        """
        depth = int(getattr(self._local, "tx_depth", 0))
        connection = self.connection
        if depth:
            savepoint = f"thot_sp_{depth}"
            self._raw(connection, f"SAVEPOINT {savepoint}")
            self._local.tx_depth = depth + 1
            try:
                yield connection
            except Exception:
                self._raw(connection, f"ROLLBACK TO SAVEPOINT {savepoint}")
                raise
            else:
                self._raw(connection, f"RELEASE SAVEPOINT {savepoint}")
            finally:
                self._local.tx_depth = depth
            return
        self._raw(connection, "BEGIN")
        self._local.tx_depth = 1
        try:
            yield connection
        except Exception:
            self._raw(connection, "ROLLBACK")
            raise
        else:
            self._raw(connection, "COMMIT")
        finally:
            self._local.tx_depth = 0

    def _raw(self, connection: Any, sql: str) -> None:
        cursor = self._cursor_on(connection)
        try:
            cursor.execute(sql)
        finally:
            _close_quietly(cursor)

    # ----------------------------------------------------------------------------------
    # Cycle de vie
    # ----------------------------------------------------------------------------------

    def init_schema(self, *, timescale: bool = True) -> None:
        """Applique le DDL PostgreSQL, section par section (idempotent).

        Le schéma logique (``POSTGRES_CORE_DDL``) est appliqué dans sa propre transaction : son
        échec est **fatal** (``StorageError``). Les sections TimescaleDB (extension, hypertable,
        compression, rétention native, agrégats continus) sont appliquées **chacune dans sa propre
        transaction** et leur échec est **non fatal** : un PostgreSQL nu reste parfaitement
        fonctionnel, il perd seulement les capacités avancées — consignées dans
        ``supports_backend_features()``.

        Ce découpage évite le piège classique du « tout dans une transaction » : une instruction
        optionnelle qui échoue (extension absente, compression refusée) met la transaction en
        échec et ferait silencieusement perdre **tout** le DDL au ``COMMIT``.
        """
        applied = self._apply_ddl_section("core", POSTGRES_CORE_DDL, required=True)
        features: set[str] = {FEATURE_JSONB, FEATURE_SKIP_LOCKED, FEATURE_PENDING_CLAIM}
        self._timescaledb = False
        if timescale and applied:
            self._timescaledb = True
            for section, ddl in POSTGRES_TIMESCALE_SECTIONS:
                if section == "compression":
                    # Isolée : selon la version et les contraintes d'unicité de l'hypertable,
                    # TimescaleDB peut refuser la compression. On perd de l'espace disque, jamais
                    # la correction — et la capacité n'est alors pas annoncée.
                    ok = self._apply_ddl_section(section, ddl, required=False)
                    if ok:
                        features.add(FEATURE_COMPRESSION)
                    continue
                ok = self._apply_ddl_section(section, ddl, required=False)
                if not ok:
                    if section in {"extension", "hypertable"}:
                        self._timescaledb = False
                        log.warning(
                            "TimescaleDB indisponible : l'adaptateur poursuit sur un PostgreSQL "
                            "standard (rétention applicative, pas de compression)",
                            extra={"dsn": self.safe_dsn, "section": section},
                        )
                        break
                    continue
                if section == "retention":
                    features.add(FEATURE_NATIVE_RETENTION)
                elif section == "aggregates":
                    features.add(FEATURE_CONTINUOUS_AGGREGATES)
        self._features = frozenset(features)
        log.info(
            "schéma PostgreSQL initialisé",
            extra={
                "dsn": self.safe_dsn,
                "schema_version": SCHEMA_VERSION,
                "timescaledb": self._timescaledb,
                "features": sorted(self._features),
            },
        )

    def _apply_ddl_section(self, section: str, ddl: str, *, required: bool) -> bool:
        statements = split_sql_statements(ddl)
        if not statements:
            return True
        try:
            with self.transaction() as connection:
                cursor = self._cursor_on(connection)
                try:
                    for statement in statements:
                        cursor.execute(statement)
                finally:
                    _close_quietly(cursor)
        except Exception as exc:
            if required:
                raise StorageError(
                    f"application du DDL PostgreSQL impossible (section « {section} », "
                    f"{self.safe_dsn})",
                    details={
                        "section": section,
                        "error": redact_dsn_in_text(str(exc)),
                        "sqlstate": sqlstate(exc),
                    },
                ) from exc
            log.warning(
                "section de DDL PostgreSQL non appliquée",
                extra={
                    "section": section,
                    "dsn": self.safe_dsn,
                    "error": redact_dsn_in_text(str(exc)),
                    "sqlstate": sqlstate(exc),
                },
            )
            return False
        return True

    def health(self) -> bool:
        """``SELECT 1`` réel : la seule réponse honnête à « la base répond-elle ? ».

        Retourne ``False`` (sans lever) si la base est fermée, injoignable, en cours de
        redémarrage ou si le pilote est absent. ``/readyz`` et ``thotsecure doctor`` s'appuient
        dessus : cette méthode ne doit jamais faire tomber le service.
        """
        try:
            self._fetchone("SELECT 1 AS ok")
        except Exception:
            return False
        return True

    def supports_backend_features(self) -> frozenset[str]:
        """Capacités constatées au dernier ``init_schema()`` (voir ``storage.base``).

        Avant ``init_schema()``, seules les capacités intrinsèques à PostgreSQL sont annoncées
        (JSONB, ``SKIP LOCKED``, réservation par bail) : TimescaleDB n'est jamais supposé présent.
        """
        return self._features

    @property
    def timescaledb(self) -> bool:
        """Vrai si l'extension TimescaleDB a été détectée (et l'hypertable appliquée)."""
        return self._timescaledb

    @property
    def pool_stats(self) -> dict[str, Any]:
        """État du pool (connexions libres/utilisées) — exploité par les diagnostics."""
        stats = getattr(self._pool, "stats", None)
        return dict(stats) if isinstance(stats, dict) else {}

    # ----------------------------------------------------------------------------------
    # Exécution bas niveau
    # ----------------------------------------------------------------------------------

    def _cursor_on(self, connection: Any) -> Any:
        if self.driver.name == "psycopg":
            return connection.cursor(row_factory=self.driver.row_factory)
        return connection.cursor(cursor_factory=self.driver.row_factory)

    def _cursor(self) -> Any:
        return self._cursor_on(self.connection)

    def _storage_error(self, operation: str, exc: BaseException) -> StorageError:
        return StorageError(
            f"échec de l'opération « {operation} » sur PostgreSQL ({self.safe_dsn})",
            details={"sqlstate": sqlstate(exc), "error": redact_dsn_in_text(str(exc))},
        )

    @contextmanager
    def _guard(self, operation: str) -> Iterator[None]:
        """Traduit toute erreur de pilote en ``StorageError`` : aucune fuite de type brut.

        Le message contient le DSN **masqué** et le texte du pilote expurgé de tout mot de passe
        (un pilote qui échoue recopie volontiers sa chaîne de connexion dans son message).
        """
        try:
            yield
        except (StorageError, ConflictError, NotFoundError):
            raise
        except Exception as exc:
            raise self._storage_error(operation, exc) from exc

    def _fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        return self._fetchall_on(self.connection, sql, params)

    def _fetchall_on(
        self, connection: Any, sql: str, params: Sequence[Any] = ()
    ) -> list[dict[str, Any]]:
        with self._guard("lecture"):
            cursor = self._cursor_on(connection)
            try:
                cursor.execute(sql, tuple(params))
                rows = cursor.fetchall()
            finally:
                _close_quietly(cursor)
        return [dict(row) for row in (rows or [])]

    def _fetchone(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        return self._fetchone_on(self.connection, sql, params)

    def _fetchone_on(
        self, connection: Any, sql: str, params: Sequence[Any] = ()
    ) -> dict[str, Any] | None:
        rows = self._fetchall_on(connection, sql, params)
        return rows[0] if rows else None

    def _scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self._fetchone(sql, params)
        if not row:
            return None
        return next(iter(row.values()), None)

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        return self._execute_on(self.connection, sql, params)

    def _execute_on(self, connection: Any, sql: str, params: Sequence[Any] = ()) -> int:
        with self._guard("écriture"):
            cursor = self._cursor_on(connection)
            try:
                cursor.execute(sql, tuple(params))
                rowcount = cursor.rowcount
            finally:
                _close_quietly(cursor)
        return max(0, safe_int(rowcount, 0))

    # ----------------------------------------------------------------------------------
    # Tenants
    # ----------------------------------------------------------------------------------

    def upsert_tenant(self, tenant: Tenant, *, replace: bool = True) -> Tenant:
        now = now_iso()
        payload = (
            tenant.tenant_id,
            tenant.name,
            tenant.mode,
            bool(tenant.dry_run),
            json_document(tenant.autonomy_allowlist),
            json_document(tenant.protected_targets),
            tenant.max_actions_per_hour,
            tenant.cooldown_seconds,
            tenant.asset_criticality,
            iso_z(tenant.created_at) if tenant.created_at else now,
            now,
        )
        sql = """
            INSERT INTO tenants (tenant_id, name, mode, dry_run, autonomy_allowlist,
                                 protected_targets, max_actions_per_hour, cooldown_seconds,
                                 asset_criticality, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s::timestamptz,%s::timestamptz)
            ON CONFLICT (tenant_id) DO UPDATE SET
                name = EXCLUDED.name,
                mode = EXCLUDED.mode,
                dry_run = EXCLUDED.dry_run,
                autonomy_allowlist = EXCLUDED.autonomy_allowlist,
                protected_targets = EXCLUDED.protected_targets,
                max_actions_per_hour = EXCLUDED.max_actions_per_hour,
                cooldown_seconds = EXCLUDED.cooldown_seconds,
                asset_criticality = EXCLUDED.asset_criticality,
                updated_at = EXCLUDED.updated_at
        """
        self._execute(sql, payload)
        created = self.get_tenant(tenant.tenant_id)
        if created is None:  # pragma: no cover - ne peut arriver qu'en cas de corruption
            raise StorageError(
                "tenant introuvable après écriture", details={"tenant_id": tenant.tenant_id}
            )
        return created

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        row = self._fetchone("SELECT * FROM tenants WHERE tenant_id = %s", (tenant_id,))
        return Store._row_to_tenant(row) if row else None

    def require_tenant(self, tenant_id: str) -> Tenant:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFoundError(f"tenant inconnu: {tenant_id}", details={"tenant_id": tenant_id})
        return tenant

    def list_tenants(self) -> list[Tenant]:
        rows = self._fetchall("SELECT * FROM tenants ORDER BY tenant_id")
        return [Store._row_to_tenant(row) for row in rows]

    def update_tenant(self, tenant_id: str, **fields: Any) -> Tenant:
        allowed = {
            "name",
            "mode",
            "dry_run",
            "autonomy_allowlist",
            "protected_targets",
            "max_actions_per_hour",
            "cooldown_seconds",
            "asset_criticality",
        }
        updates: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in allowed or value is None:
                continue
            if key in JSONB_COLUMNS["tenants"]:
                updates[key] = json_document(value)
            elif key == "dry_run":
                updates[key] = bool(value)
            else:
                updates[key] = value
        if not updates:
            return self.require_tenant(tenant_id)
        assignments = ", ".join(f"{key} = {column_placeholder('tenants', key)}" for key in updates)
        sql = (
            f"UPDATE tenants SET {assignments}, updated_at = now() "  # noqa: S608 - clés filtrées
            "WHERE tenant_id = %s"
        )
        changed = self._execute(sql, [*updates.values(), tenant_id])
        if changed == 0:
            raise NotFoundError(f"tenant inconnu: {tenant_id}")
        return self.require_tenant(tenant_id)

    # ----------------------------------------------------------------------------------
    # Clés API
    # ----------------------------------------------------------------------------------

    def insert_api_key(self, record: ApiKeyRecord) -> ApiKeyRecord:
        sql = """
            INSERT INTO api_keys (key_id, tenant_id, label, role, key_hash, key_prefix,
                                  created_at, last_used_at, revoked_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz)
        """
        try:
            self._execute(
                sql,
                (
                    record.key_id,
                    record.tenant_id,
                    record.label,
                    record.role,
                    record.key_hash,
                    record.key_prefix,
                    iso_z(record.created_at),
                    iso_z(record.last_used_at) if record.last_used_at else None,
                    iso_z(record.revoked_at) if record.revoked_at else None,
                ),
            )
        except StorageError as exc:
            if str(exc.details.get("sqlstate")) == UNIQUE_VIOLATION:
                raise ConflictError(
                    "clé API déjà enregistrée (key_id ou empreinte en doublon)",
                    details={"key_id": record.key_id},
                ) from exc
            raise
        return record

    def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        row = self._fetchone("SELECT * FROM api_keys WHERE key_id = %s", (key_id,))
        return Store._row_to_api_key(row) if row else None

    def find_api_key_by_hash(self, key_hash: str) -> ApiKeyRecord | None:
        row = self._fetchone(
            "SELECT * FROM api_keys WHERE key_hash = %s AND revoked_at IS NULL", (key_hash,)
        )
        return Store._row_to_api_key(row) if row else None

    def list_api_keys(self, tenant_id: str) -> list[ApiKeyRecord]:
        rows = self._fetchall(
            "SELECT * FROM api_keys WHERE tenant_id = %s ORDER BY created_at DESC", (tenant_id,)
        )
        return [Store._row_to_api_key(row) for row in rows]

    def revoke_api_key(self, key_id: str, *, tenant_id: str | None = None) -> bool:
        sql = (
            "UPDATE api_keys SET revoked_at = %s::timestamptz "
            "WHERE key_id = %s AND revoked_at IS NULL"
        )
        params: list[Any] = [now_iso(), key_id]
        if tenant_id:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        return self._execute(sql, params) > 0

    def touch_api_key(self, key_id: str) -> None:
        self._execute(
            "UPDATE api_keys SET last_used_at = %s::timestamptz WHERE key_id = %s",
            (now_iso(), key_id),
        )

    # ----------------------------------------------------------------------------------
    # Événements
    # ----------------------------------------------------------------------------------

    #: Colonnes de l'insertion d'un événement (constante interne : jamais construite depuis
    #: une entrée utilisateur).
    EVENT_COLUMNS = (
        "(event_id, tenant_id, ts, kind, source_type, source_name, source_host, severity_hint,"
        " labels, payload, raw_ref, ingested_at, processed)"
    )

    #: Gabarit d'une ligne d'événement, casts compris (voir ``column_placeholder``).
    EVENT_ROW_TEMPLATE = (
        "(%s,%s,%s::timestamptz,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s::timestamptz,FALSE)"
    )

    def _event_row(self, event: Event, stamp: str) -> tuple[Any, ...]:
        return (
            event.event_id,
            event.tenant_id,
            iso_z(event.ts),
            event.kind,
            event.source.type,
            event.source.name,
            event.source.host,
            event.severity_hint,
            json_document(event.labels),
            json_document(event.payload),
            event.raw_ref,
            stamp,
        )

    def insert_event(self, event: Event) -> bool:
        """Insère un événement ; ``False`` si ``event_id`` (au même horodatage) existe déjà.

        ``ON CONFLICT DO NOTHING`` couvre la clé primaire ``(tenant_id, event_id, ts)`` : un rejeu
        du **même** événement (même identifiant, même horodatage) est ignoré, sans erreur.
        """
        sql = (
            f"INSERT INTO events {self.EVENT_COLUMNS} VALUES {self.EVENT_ROW_TEMPLATE} "
            "ON CONFLICT DO NOTHING RETURNING event_id"
        )
        rows = self._fetchall(sql, self._event_row(event, now_iso()))
        return bool(rows)

    def insert_events(self, events: Sequence[Event]) -> int:
        """Insertion par lots : une transaction, des instructions de ``batch_size`` lignes.

        ``execute_values`` (psycopg2) est utilisé quand il est disponible : une seule instruction
        pour 1000 lignes, soit un aller-retour réseau au lieu de mille. Avec psycopg 3, le repli
        ``executemany`` regroupe les envois en pipeline. Le compte retourné est celui des lignes
        **réellement insérées** (les doublons ignorés ne sont pas comptés).
        """
        if not events:
            return 0
        stamp = now_iso()
        rows = [self._event_row(event, stamp) for event in events]
        inserted = 0
        with self._guard("insertion par lots d'événements"), self.transaction() as connection:
            for batch in chunked(rows, self.batch_size):
                inserted += self._insert_event_batch(connection, batch)
        return inserted

    def _insert_event_batch(self, connection: Any, batch: list[tuple[Any, ...]]) -> int:
        cursor = self._cursor_on(connection)
        try:
            if self.driver.supports_execute_values:
                sql = (
                    f"INSERT INTO events {self.EVENT_COLUMNS} VALUES %s "
                    "ON CONFLICT DO NOTHING RETURNING 1"
                )
                result = self.driver.execute_values(
                    cursor,
                    sql,
                    batch,
                    template=self.EVENT_ROW_TEMPLATE,
                    page_size=len(batch),
                    fetch=True,
                )
                return len(result or [])
            sql = (
                f"INSERT INTO events {self.EVENT_COLUMNS} VALUES {self.EVENT_ROW_TEMPLATE} "
                "ON CONFLICT DO NOTHING"
            )
            cursor.executemany(sql, batch)
            return max(0, safe_int(cursor.rowcount, 0))
        finally:
            _close_quietly(cursor)

    def get_event(self, tenant_id: str, event_id: str) -> Event | None:
        row = self._fetchone(
            "SELECT * FROM events WHERE event_id = %s AND tenant_id = %s", (event_id, tenant_id)
        )
        return Store._row_to_event(row) if row else None

    #: Recherche textuelle : SQLite interroge le JSON sérialisé (``LIKE``), PostgreSQL interroge
    #: la représentation texte de ``jsonb`` en insensible à la casse (``ILIKE``). La sémantique
    #: exacte de ``q`` n'étant pas figée par le contrat §4.3, l'écart est documenté.
    TEXT_SEARCH_SQL = "(labels::text ILIKE %s OR payload::text ILIKE %s)"

    def query_events(
        self,
        tenant_id: str,
        *,
        kinds: Sequence[str] | None = None,
        source_types: Sequence[str] | None = None,
        since: Any = None,
        until: Any = None,
        q: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[Event], str | None]:
        limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        sql, params = self._query_events_sql(
            tenant_id,
            kinds=kinds,
            source_types=source_types,
            since=since,
            until=until,
            q=q,
            limit=limit,
            cursor=cursor,
        )
        rows = self._fetchall(sql, params)
        events = [Store._row_to_event(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit and events:
            last = events[-1]
            next_cursor = _encode_cursor(iso_z(last.ts), last.event_id)
        return events, next_cursor

    def _query_events_sql(
        self,
        tenant_id: str,
        *,
        kinds: Sequence[str] | None,
        source_types: Sequence[str] | None,
        since: Any,
        until: Any,
        q: str | None,
        limit: int,
        cursor: str | None,
    ) -> tuple[str, list[Any]]:
        """Construit la requête paginée (fonction pure : testable sans base)."""
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if kinds:
            where.append(in_clause("kind", len(kinds)))
            params.extend(kinds)
        if source_types:
            where.append(in_clause("source_type", len(source_types)))
            params.extend(source_types)
        if since:
            where.append("ts >= %s::timestamptz")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("ts <= %s::timestamptz")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if q:
            where.append(self.TEXT_SEARCH_SQL)
            params.extend([f"%{q}%", f"%{q}%"])
        if cursor:
            primary, identifier = _decode_cursor(cursor)
            where.append("(ts < %s::timestamptz OR (ts = %s::timestamptz AND event_id < %s))")
            params.extend([primary, primary, identifier])
        sql = (
            f"SELECT * FROM events WHERE {' AND '.join(where)} "  # noqa: S608 - clauses constantes
            "ORDER BY ts DESC, event_id DESC LIMIT %s"
        )
        params.append(limit + 1)
        return sql, params

    def pending_events(self, *, limit: int = 500) -> list[Event]:
        """Événements non traités, avec ``FOR UPDATE SKIP LOCKED``.

        Deux rejeux simultanés (deux processus, deux réplicas) ne se partagent pas le même lot :
        le second saute les lignes verrouillées par le premier au lieu d'attendre. Le verrou est
        relâché au ``COMMIT`` de cette transaction courte — il ne couvre donc **pas** la durée du
        traitement, qui se déroule hors transaction : ``mark_events_processed`` reste l'arbitre
        (son ``UPDATE ... WHERE processed = FALSE`` ne transitionne une ligne qu'une fois), et
        ``claim_pending_events`` offre une réservation par bail pour un rejeu strictement
        multi-nœuds.
        """
        limit = max(1, int(limit))
        sql = (
            "SELECT * FROM events WHERE processed = FALSE ORDER BY ts ASC LIMIT %s "
            "FOR UPDATE SKIP LOCKED"
        )
        with self.transaction() as connection:
            rows = self._fetchall_on(connection, sql, (limit,))
        return [Store._row_to_event(row) for row in rows]

    def claim_pending_events(
        self, *, limit: int = 500, lease_seconds: int = 300, worker: str | None = None
    ) -> list[Event]:
        """Réserve atomiquement un lot d'événements à rejouer (bail renouvelable).

        Capacité propre à PostgreSQL (``FEATURE_PENDING_CLAIM``) : ``pending_events`` peut
        retourner le même lot à deux processus, ce qui est acceptable pour le pipeline (il
        revérifie l'existence des findings) mais pas pour un rejeu strictement parallèle.

        Une seule instruction ``UPDATE ... WHERE (clé) IN (SELECT ... FOR UPDATE SKIP LOCKED)`` :
        la réservation est **persistée** dans ``events.claimed_by``/``claimed_at``, donc elle
        survit à la fin de la transaction (contrairement à un verrou). Un bail expiré
        (``claimed_at`` plus vieux que ``lease_seconds``) redevient réclamable : un worker tué ne
        bloque jamais définitivement un événement.

        :param worker: identifiant du réclamant (nom d'hôte, PID, nom de réplica) — apparaît dans
            la colonne ``claimed_by`` pour le diagnostic.
        :returns: les événements réservés pour ce worker.
        """
        limit = max(1, int(limit))
        lease = max(1, int(lease_seconds))
        claimant = worker or f"{self.backend_name}:{new_id('w_')[:12]}"
        sql = """
            UPDATE events SET claimed_by = %s, claimed_at = now()
            WHERE (tenant_id, event_id, ts) IN (
                SELECT tenant_id, event_id, ts FROM events
                WHERE processed = FALSE
                  AND (claimed_at IS NULL OR claimed_at < now() - make_interval(secs => %s))
                ORDER BY ts ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
        """
        rows = self._fetchall(sql, (claimant, lease, limit))
        return [Store._row_to_event(row) for row in rows]

    def mark_events_processed(self, event_ids: Sequence[str]) -> int:
        """Marque les événements comme traités et libère leur réservation éventuelle.

        Le filtre ``processed = FALSE`` est l'arbitre du rejeu : il garantit qu'un événement n'est
        transitionné qu'une fois, même si deux processus l'ont lu. Le compte retourné est celui des
        lignes **effectivement** transitionnées.
        """
        if not event_ids:
            return 0
        stamp = now_iso()
        total = 0
        with self._guard("marquage des événements traités"), self.transaction() as connection:
            for batch in chunked(list(event_ids), 400):
                sql = (
                    "UPDATE events SET processed = TRUE, processed_at = %s::timestamptz, "
                    "claimed_by = NULL, claimed_at = NULL "
                    f"WHERE event_id IN ({placeholders(len(batch))}) AND processed = FALSE"
                )
                total += self._execute_on(connection, sql, [stamp, *batch])
        return total

    def count_events(self, tenant_id: str, *, since: Any = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM events WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= %s::timestamptz"
            params.append(iso_z(parse_dt(since) or utcnow()))
        return safe_int(self._scalar(sql, params))

    def events_by_kind(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        sql = "SELECT kind, COUNT(*) AS n FROM events WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= %s::timestamptz"
            params.append(iso_z(parse_dt(since) or utcnow()))
        sql += " GROUP BY kind ORDER BY n DESC"
        return {row["kind"]: safe_int(row["n"]) for row in self._fetchall(sql, params)}

    # ----------------------------------------------------------------------------------
    # Findings
    # ----------------------------------------------------------------------------------

    def insert_finding(self, finding: Finding) -> Finding:
        sql = """
            INSERT INTO findings (finding_id, tenant_id, rule_id, rule_name, severity,
                risk_score, confidence, status, title, description, remediation, tags,
                mitre, evidence, first_seen, last_seen, count, event_ids, dedup_key,
                resolution, comment, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,
                    %s::timestamptz,%s::timestamptz,%s,%s::jsonb,%s,%s,%s,
                    %s::timestamptz,%s::timestamptz)
        """
        try:
            self._execute(sql, self._finding_params(finding))
        except StorageError as exc:
            if str(exc.details.get("sqlstate")) == UNIQUE_VIOLATION:
                raise ConflictError(
                    "finding déjà enregistré", details={"finding_id": finding.finding_id}
                ) from exc
            raise
        return finding

    def _finding_params(self, finding: Finding) -> tuple[Any, ...]:
        return (
            finding.finding_id,
            finding.tenant_id,
            finding.rule_id,
            finding.rule_name,
            finding.severity,
            finding.risk_score,
            finding.confidence,
            finding.status,
            finding.title,
            finding.description,
            finding.remediation,
            json_document(finding.tags),
            json_document(finding.mitre),
            json_document(finding.evidence),
            iso_z(finding.first_seen),
            iso_z(finding.last_seen),
            finding.count,
            json_document(finding.event_ids),
            finding.dedup_key,
            finding.resolution,
            finding.comment,
            iso_z(finding.created_at),
            iso_z(finding.updated_at),
        )

    def update_finding(self, tenant_id: str, finding_id: str, **fields: Any) -> Finding:
        allowed = {
            "severity",
            "risk_score",
            "confidence",
            "status",
            "title",
            "description",
            "remediation",
            "tags",
            "mitre",
            "evidence",
            "last_seen",
            "count",
            "event_ids",
            "resolution",
            "comment",
            "dedup_key",
        }
        updates: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in allowed or value is None:
                continue
            if key in JSONB_COLUMNS["findings"]:
                updates[key] = json_document(value)
            elif key == "last_seen":
                updates[key] = iso_z(parse_dt(value) or utcnow())
            else:
                updates[key] = value
        updates["updated_at"] = now_iso()
        assignments = ", ".join(f"{key} = {column_placeholder('findings', key)}" for key in updates)
        sql = (
            f"UPDATE findings SET {assignments} "  # noqa: S608
            "WHERE finding_id = %s AND tenant_id = %s"
        )
        changed = self._execute(sql, [*updates.values(), finding_id, tenant_id])
        if changed == 0:
            raise NotFoundError(f"finding introuvable: {finding_id}")
        result = self.get_finding(tenant_id, finding_id)
        if result is None:  # pragma: no cover
            raise StorageError("finding introuvable après mise à jour")
        return result

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding | None:
        row = self._fetchone(
            "SELECT * FROM findings WHERE finding_id = %s AND tenant_id = %s",
            (finding_id, tenant_id),
        )
        return Store._row_to_finding(row) if row else None

    def find_open_finding(self, tenant_id: str, rule_id: str, dedup_key: str) -> Finding | None:
        row = self._fetchone(
            """
            SELECT * FROM findings
            WHERE tenant_id = %s AND rule_id = %s AND dedup_key = %s
              AND status IN ('open','acked')
            ORDER BY last_seen DESC LIMIT 1
            """,
            (tenant_id, rule_id, dedup_key),
        )
        return Store._row_to_finding(row) if row else None

    def list_findings(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None = None,
        severity: Sequence[str] | None = None,
        rule_id: str | None = None,
        since: Any = None,
        until: Any = None,
        min_risk: float | None = None,
        q: str | None = None,
        sort: str = "risk_score",
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[Finding], str | None]:
        limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        sql, params, primary = self._list_findings_sql(
            tenant_id,
            status=status,
            severity=severity,
            rule_id=rule_id,
            since=since,
            until=until,
            min_risk=min_risk,
            q=q,
            sort=sort,
            limit=limit,
            cursor=cursor,
        )
        rows = self._fetchall(sql, params)
        findings = [Store._row_to_finding(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit and findings:
            last = findings[-1]
            if primary == "risk_score":
                next_cursor = _encode_cursor(safe_float(last.risk_score), last.finding_id)
            else:
                next_cursor = _encode_cursor(iso_z(last.last_seen), last.finding_id)
        return findings, next_cursor

    def _list_findings_sql(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None,
        severity: Sequence[str] | None,
        rule_id: str | None,
        since: Any,
        until: Any,
        min_risk: float | None,
        q: str | None,
        sort: str,
        limit: int,
        cursor: str | None,
    ) -> tuple[str, list[Any], str]:
        primary = "risk_score" if sort == "risk_score" else "last_seen"
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if status:
            where.append(in_clause("status", len(status)))
            params.extend(status)
        if severity:
            where.append(in_clause("severity", len(severity)))
            params.extend(severity)
        if rule_id:
            where.append("rule_id = %s")
            params.append(rule_id)
        if since:
            where.append("last_seen >= %s::timestamptz")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("last_seen <= %s::timestamptz")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if min_risk is not None:
            where.append("risk_score >= %s")
            params.append(float(min_risk))
        if q:
            where.append("(title ILIKE %s OR description ILIKE %s OR rule_id ILIKE %s)")
            params.extend([f"%{q}%"] * 3)
        if cursor:
            cursor_primary, identifier = _decode_cursor(cursor)
            if primary == "risk_score":
                where.append("(risk_score < %s OR (risk_score = %s AND finding_id < %s))")
                value = safe_float(cursor_primary)
                params.extend([value, value, identifier])
            else:
                where.append(
                    "(last_seen < %s::timestamptz OR (last_seen = %s::timestamptz"
                    " AND finding_id < %s))"
                )
                params.extend([cursor_primary, cursor_primary, identifier])
        sql = (
            f"SELECT * FROM findings WHERE {' AND '.join(where)} "  # noqa: S608
            f"ORDER BY {primary} DESC, finding_id DESC LIMIT %s"
        )
        params.append(limit + 1)
        return sql, params, primary

    def count_findings(self, tenant_id: str, *, since: Any = None) -> dict[str, Any]:
        since_iso = iso_z(parse_dt(since) or utcnow()) if since else None
        clause = "AND last_seen >= %s::timestamptz" if since_iso else ""
        params: list[Any] = [tenant_id]
        if since_iso:
            params.append(since_iso)
        by_severity = {
            row["severity"]: safe_int(row["n"])
            for row in self._fetchall(
                f"SELECT severity, COUNT(*) AS n FROM findings "  # noqa: S608
                f"WHERE tenant_id = %s {clause} GROUP BY severity",
                params,
            )
        }
        by_status = {
            row["status"]: safe_int(row["n"])
            for row in self._fetchall(
                f"SELECT status, COUNT(*) AS n FROM findings "  # noqa: S608
                f"WHERE tenant_id = %s {clause} GROUP BY status",
                params,
            )
        }
        top_rules = [
            {
                "rule_id": row["rule_id"],
                "count": safe_int(row["n"]),
                "max_risk": safe_float(row["max_risk"]),
            }
            for row in self._fetchall(
                f"""
                SELECT rule_id, COUNT(*) AS n, MAX(risk_score) AS max_risk
                FROM findings WHERE tenant_id = %s {clause}
                GROUP BY rule_id ORDER BY n DESC LIMIT 10
                """,  # noqa: S608 - clause constante
                params,
            )
        ]
        return {"by_severity": by_severity, "by_status": by_status, "top_rules": top_rules}

    # ----------------------------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------------------------

    def insert_action(self, action: Action) -> Action:
        sql = """
            INSERT INTO actions (action_id, tenant_id, finding_id, policy_id, playbook,
                status, mode, dry_run, params, target, requested_by, requested_at,
                approved_by, approved_at, rejected_by, rejected_at, executed_at,
                expires_at, result, rollback, idempotency_key, audit_seq, reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s::timestamptz,
                    %s,%s::timestamptz,%s,%s::timestamptz,%s::timestamptz,
                    %s::timestamptz,%s::jsonb,%s::jsonb,%s,%s,%s)
        """
        try:
            self._execute(sql, self._action_params(action))
        except StorageError as exc:
            if str(exc.details.get("sqlstate")) == UNIQUE_VIOLATION:
                existing = self.find_action_by_idempotency(action.idempotency_key)
                raise ConflictError(
                    "une action identique existe déjà (idempotence)",
                    details={"action_id": existing.action_id if existing else None},
                ) from exc
            raise
        return action

    def _action_params(self, action: Action) -> tuple[Any, ...]:
        return (
            action.action_id,
            action.tenant_id,
            action.finding_id,
            action.policy_id,
            action.playbook,
            action.status,
            action.mode,
            bool(action.dry_run),
            json_document(action.params),
            json_document(action.target.model_dump()),
            action.requested_by,
            iso_z(action.requested_at),
            action.approved_by,
            iso_z(action.approved_at) if action.approved_at else None,
            action.rejected_by,
            iso_z(action.rejected_at) if action.rejected_at else None,
            iso_z(action.executed_at) if action.executed_at else None,
            iso_z(action.expires_at) if action.expires_at else None,
            json_document(action.result) if action.result else None,
            json_document(action.rollback.model_dump(mode="json")),
            action.idempotency_key,
            action.audit_seq,
            action.reason,
        )

    def update_action(self, action: Action) -> Action:
        sql = """
            UPDATE actions SET status = %s, approved_by = %s, approved_at = %s::timestamptz,
                rejected_by = %s, rejected_at = %s::timestamptz, executed_at = %s::timestamptz,
                result = %s::jsonb, rollback = %s::jsonb, audit_seq = %s, reason = %s
            WHERE action_id = %s AND tenant_id = %s
        """
        changed = self._execute(
            sql,
            (
                action.status,
                action.approved_by,
                iso_z(action.approved_at) if action.approved_at else None,
                action.rejected_by,
                iso_z(action.rejected_at) if action.rejected_at else None,
                iso_z(action.executed_at) if action.executed_at else None,
                json_document(action.result) if action.result else None,
                json_document(action.rollback.model_dump(mode="json")),
                action.audit_seq,
                action.reason,
                action.action_id,
                action.tenant_id,
            ),
        )
        if changed == 0:
            raise NotFoundError(f"action introuvable: {action.action_id}")
        return action

    def get_action(self, tenant_id: str, action_id: str) -> Action | None:
        row = self._fetchone(
            "SELECT * FROM actions WHERE action_id = %s AND tenant_id = %s", (action_id, tenant_id)
        )
        return Store._row_to_action(row) if row else None

    def find_action_by_idempotency(self, idempotency_key: str) -> Action | None:
        row = self._fetchone("SELECT * FROM actions WHERE idempotency_key = %s", (idempotency_key,))
        return Store._row_to_action(row) if row else None

    def list_actions(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None = None,
        playbook: str | None = None,
        finding_id: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[Action], str | None]:
        limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        sql, params = self._list_actions_sql(
            tenant_id,
            status=status,
            playbook=playbook,
            finding_id=finding_id,
            limit=limit,
            cursor=cursor,
        )
        rows = self._fetchall(sql, params)
        actions = [Store._row_to_action(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit and actions:
            last = actions[-1]
            next_cursor = _encode_cursor(iso_z(last.requested_at), last.action_id)
        return actions, next_cursor

    def _list_actions_sql(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None,
        playbook: str | None,
        finding_id: str | None,
        limit: int,
        cursor: str | None,
    ) -> tuple[str, list[Any]]:
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if status:
            where.append(in_clause("status", len(status)))
            params.extend(status)
        if playbook:
            where.append("playbook = %s")
            params.append(playbook)
        if finding_id:
            where.append("finding_id = %s")
            params.append(finding_id)
        if cursor:
            primary, identifier = _decode_cursor(cursor)
            where.append(
                "(requested_at < %s::timestamptz OR (requested_at = %s::timestamptz"
                " AND action_id < %s))"
            )
            params.extend([primary, primary, identifier])
        sql = (
            f"SELECT * FROM actions WHERE {' AND '.join(where)} "  # noqa: S608 - clauses constantes
            "ORDER BY requested_at DESC, action_id DESC LIMIT %s"
        )
        params.append(limit + 1)
        return sql, params

    def count_actions_since(
        self,
        tenant_id: str,
        since: Any,
        *,
        playbook: str | None = None,
        exclude_failed: bool = True,
    ) -> int:
        sql = (
            "SELECT COUNT(*) AS n FROM actions "
            "WHERE tenant_id = %s AND requested_at >= %s::timestamptz"
        )
        params: list[Any] = [tenant_id, iso_z(parse_dt(since) or utcnow())]
        if playbook:
            sql += " AND playbook = %s"
            params.append(playbook)
        if exclude_failed:
            sql += " AND status NOT IN ('rejected','failed')"
        return safe_int(self._scalar(sql, params))

    def last_action_for(self, tenant_id: str, playbook: str, target_value: str) -> Action | None:
        """Dernière action non négative sur une cible — calcul du cooldown.

        ``target`` est un ``jsonb`` : la recherche s'appuie sur sa représentation texte, où la
        valeur apparaît entre guillemets (``{"type": "ip", "value": "203.0.113.9"}``). Le motif
        reste un **paramètre lié**, jamais une concaténation.
        """
        row = self._fetchone(
            """
            SELECT * FROM actions
            WHERE tenant_id = %s AND playbook = %s AND target::text LIKE %s
              AND status IN ('succeeded','executing','approved')
            ORDER BY requested_at DESC LIMIT 1
            """,
            (tenant_id, playbook, f'%"{target_value}"%'),
        )
        return Store._row_to_action(row) if row else None

    def actions_by_status(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        sql = "SELECT status, COUNT(*) AS n FROM actions WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND requested_at >= %s::timestamptz"
            params.append(iso_z(parse_dt(since) or utcnow()))
        sql += " GROUP BY status"
        return {row["status"]: safe_int(row["n"]) for row in self._fetchall(sql, params)}

    def actions_for_finding(self, tenant_id: str, finding_id: str) -> list[Action]:
        rows = self._fetchall(
            "SELECT * FROM actions WHERE tenant_id = %s AND finding_id = %s "
            "ORDER BY requested_at DESC",
            (tenant_id, finding_id),
        )
        return [Store._row_to_action(row) for row in rows]

    # ----------------------------------------------------------------------------------
    # Audit
    # ----------------------------------------------------------------------------------

    def append_audit(
        self,
        *,
        tenant_id: str,
        actor: str,
        action: str,
        actor_role: str = "system",
        target: dict[str, Any] | None = None,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        ts: Any = None,
    ) -> AuditRecord:
        """Ajoute un maillon, sous verrou consultatif de transaction.

        Séquence **dans une seule transaction** : (1) verrou consultatif global — seul un
        écrivain d'audit à la fois, quelle que soit l'instance applicative ; (2) lecture du dernier
        ``hash`` ; (3) numéro tiré de la séquence dédiée ; (4) calcul de l'empreinte ; (5)
        insertion. Le verrou est libéré au ``COMMIT``, y compris en cas de mort du processus.

        Conséquence recherchée : deux processus concurrents produisent deux maillons correctement
        chaînés, jamais deux maillons pointant sur le même prédécesseur. Le coût est une
        sérialisation de quelques dizaines de microsecondes par enregistrement d'audit — négligeable
        devant le fait de perdre l'intégrité de la preuve.
        """
        stamp = iso_z(parse_dt(ts) or utcnow())
        target = target or {}
        before = before or {}
        after = after or {}
        context = context or {}
        with self._guard("ajout d'un enregistrement d'audit"):
            with self.transaction() as connection:
                self._execute_on(connection, AUDIT_CHAIN_LOCK_SQL)
                row = self._fetchone_on(connection, AUDIT_TAIL_SQL)
                prev_hash = row["hash"] if row else GENESIS_HASH
                seq = safe_int(self._scalar_on(connection, AUDIT_SEQ_SQL), 0)
                if seq <= 0:
                    raise StorageError(
                        "séquence d'audit indisponible (audit_log_seq) : exécutez init_schema()",
                        details={"dsn": self.safe_dsn},
                    )
                digest = record_fingerprint(
                    seq=seq,
                    ts=stamp,
                    tenant_id=tenant_id,
                    actor=actor,
                    actor_role=actor_role,
                    action=action,
                    target=target,
                    before=before,
                    after=after,
                    prev_hash=prev_hash,
                )
                self._execute_on(
                    connection,
                    """
                    INSERT INTO audit_log (seq, ts, tenant_id, actor, actor_role, action,
                                           target, before, after, context, prev_hash, hash)
                    VALUES (%s,%s::timestamptz,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,
                            %s::jsonb,%s,%s)
                    """,
                    (
                        seq,
                        stamp,
                        tenant_id,
                        actor,
                        actor_role,
                        action,
                        json_document(target),
                        json_document(before),
                        json_document(after),
                        json_document(context),
                        prev_hash,
                        digest,
                    ),
                )
        return AuditRecord(
            seq=seq,
            ts=parse_dt(stamp) or utcnow(),
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            action=action,
            target=target,
            before=before,
            after=after,
            context=context,
            prev_hash=prev_hash,
            hash=digest,
        )

    def _scalar_on(self, connection: Any, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self._fetchone_on(connection, sql, params)
        if not row:
            return None
        return next(iter(row.values()), None)

    def list_audit(
        self,
        tenant_id: str,
        *,
        action: str | None = None,
        actor: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[AuditRecord], str | None]:
        limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        sql, params = self._list_audit_sql(
            tenant_id,
            action=action,
            actor=actor,
            since=since,
            until=until,
            limit=limit,
            cursor=cursor,
        )
        rows = self._fetchall(sql, params)
        records = [Store._row_to_audit(row) for row in rows[:limit]]
        next_cursor = str(records[-1].seq) if len(rows) > limit and records else None
        return records, next_cursor

    def _list_audit_sql(
        self,
        tenant_id: str,
        *,
        action: str | None,
        actor: str | None,
        since: Any,
        until: Any,
        limit: int,
        cursor: str | None,
    ) -> tuple[str, list[Any]]:
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if action:
            where.append("action = %s")
            params.append(action)
        if actor:
            where.append("actor = %s")
            params.append(actor)
        if since:
            where.append("ts >= %s::timestamptz")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("ts <= %s::timestamptz")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if cursor:
            where.append("seq < %s")
            params.append(safe_int(cursor, 0))
        sql = (
            f"SELECT * FROM audit_log WHERE {' AND '.join(where)} "  # noqa: S608
            "ORDER BY seq DESC LIMIT %s"
        )
        params.append(limit + 1)
        return sql, params

    def iter_audit(self, *, tenant_id: str | None = None) -> Iterator[AuditRecord]:
        if tenant_id:
            rows = self._fetchall(
                "SELECT * FROM audit_log WHERE tenant_id = %s ORDER BY seq ASC", (tenant_id,)
            )
        else:
            rows = self._fetchall("SELECT * FROM audit_log ORDER BY seq ASC")
        for row in rows:
            yield Store._row_to_audit(row)

    def count_audit(self, tenant_id: str, *, since: Any = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM audit_log WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= %s::timestamptz"
            params.append(iso_z(parse_dt(since) or utcnow()))
        return safe_int(self._scalar(sql, params))

    # ----------------------------------------------------------------------------------
    # Collecteurs et suppressions
    # ----------------------------------------------------------------------------------

    def record_collector_run(
        self,
        *,
        tenant_id: str,
        collector: str,
        status: str,
        started_at: Any,
        finished_at: Any = None,
        events: int = 0,
        findings: int = 0,
        errors: int = 0,
        detail: dict[str, Any] | None = None,
    ) -> str:
        run_id = new_id("run_")
        sql = """
            INSERT INTO collector_runs (run_id, tenant_id, collector, started_at, finished_at,
                status, events, findings, errors, detail)
            VALUES (%s,%s,%s,%s::timestamptz,%s::timestamptz,%s,%s,%s,%s,%s::jsonb)
        """
        self._execute(
            sql,
            (
                run_id,
                tenant_id,
                collector,
                iso_z(parse_dt(started_at) or utcnow()),
                iso_z(parse_dt(finished_at)) if finished_at else None,
                status,
                events,
                findings,
                errors,
                json_document(detail or {}),
            ),
        )
        return run_id

    def collector_stats(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        """Statistiques par collecteur — horodatages rendus en ISO-8601, comme en SQLite.

        Le contrat de ``list_suppressions``/``collector_stats`` impose une forme identique d'un
        backend à l'autre : sans cette normalisation, la console afficherait un ``datetime``
        Python ici et une chaîne là, pour la même table.
        """
        rows = self._fetchall(
            """
            SELECT collector,
                   COUNT(*) AS runs,
                   MAX(started_at) AS last_run,
                   SUM(events) AS events,
                   SUM(findings) AS findings,
                   SUM(errors) AS errors,
                   MAX(status) AS last_status
            FROM collector_runs WHERE tenant_id = %s
            GROUP BY collector
            """,
            (tenant_id,),
        )
        stats: dict[str, dict[str, Any]] = {}
        for row in rows:
            last = self._fetchone(
                "SELECT status, detail FROM collector_runs WHERE tenant_id = %s AND collector = %s"
                " ORDER BY started_at DESC LIMIT 1",
                (tenant_id, row["collector"]),
            )
            # Un horodatage rendu en ISO-8601, comme en SQLite : la console ne doit pas afficher
            # un ``datetime`` Python ici et une chaîne là, pour la même table.
            last_run = row["last_run"]
            if isinstance(last_run, datetime):
                last_run = iso_z(last_run)
            stats[row["collector"]] = {
                "runs": safe_int(row["runs"]),
                "last_run": last_run,
                "last_status": (last["status"] if last else "never"),
                "events": safe_int(row["events"]),
                "findings": safe_int(row["findings"]),
                "errors": safe_int(row["errors"]),
                "detail": load_document(last["detail"], {}) if last else {},
            }
        return stats

    def add_suppression(
        self,
        *,
        tenant_id: str,
        rule_id: str,
        dedup_key: str,
        reason: str,
        expires_at: Any,
        created_by: str = "system",
    ) -> str:
        suppression_id = new_id("sp_")
        sql = """
            INSERT INTO suppressions (suppression_id, tenant_id, rule_id, dedup_key, reason,
                created_by, created_at, expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)
        """
        self._execute(
            sql,
            (
                suppression_id,
                tenant_id,
                rule_id,
                dedup_key,
                reason,
                created_by,
                now_iso(),
                iso_z(parse_dt(expires_at) or (utcnow() + timedelta(days=1))),
            ),
        )
        return suppression_id

    def is_suppressed(self, tenant_id: str, rule_id: str, dedup_key: str) -> bool:
        row = self._fetchone(
            """
            SELECT 1 AS present FROM suppressions
            WHERE tenant_id = %s AND rule_id = %s AND (dedup_key = %s OR dedup_key = '')
              AND expires_at > %s::timestamptz LIMIT 1
            """,
            (tenant_id, rule_id, dedup_key, now_iso()),
        )
        return row is not None

    def list_suppressions(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT * FROM suppressions WHERE tenant_id = %s AND expires_at > %s::timestamptz"
            " ORDER BY expires_at",
            (tenant_id, now_iso()),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            for key in ("created_at", "expires_at"):
                if isinstance(entry.get(key), datetime):
                    entry[key] = iso_z(entry[key])
            result.append(entry)
        return result

    # ----------------------------------------------------------------------------------
    # Statistiques
    # ----------------------------------------------------------------------------------

    def stats_overview(
        self,
        tenant_id: str,
        *,
        window_hours: int = 24,
        collectors: Sequence[CollectorStatus] | None = None,
    ) -> StatsOverview:
        since = utcnow() - timedelta(hours=window_hours)
        tenant = self.get_tenant(tenant_id)
        findings = self.count_findings(tenant_id, since=since)
        actions = self.actions_by_status(tenant_id, since=since)

        # MTTD / MTTR : ``EXTRACT(EPOCH FROM …)`` remplace ``julianday`` de SQLite — même
        # grandeur, même unité (secondes), calcul faite par le serveur.
        mttd = self._scalar(
            "SELECT AVG(EXTRACT(EPOCH FROM (f.created_at - f.first_seen))) AS mttd "
            "FROM findings f WHERE f.tenant_id = %s AND f.created_at >= %s::timestamptz",
            (tenant_id, iso_z(since)),
        )
        mttr = self._scalar(
            "SELECT AVG(EXTRACT(EPOCH FROM (f.updated_at - f.created_at))) AS mttr "
            "FROM findings f WHERE f.tenant_id = %s AND f.status = 'closed' "
            "AND f.updated_at >= %s::timestamptz",
            (tenant_id, iso_z(since)),
        )
        auto_count = safe_int(
            self._scalar(
                "SELECT COUNT(*) AS n FROM actions WHERE tenant_id = %s AND mode = 'auto' "
                "AND requested_at >= %s::timestamptz",
                (tenant_id, iso_z(since)),
            )
        )
        manual_count = safe_int(
            self._scalar(
                "SELECT COUNT(*) AS n FROM actions WHERE tenant_id = %s AND mode = 'manual' "
                "AND requested_at >= %s::timestamptz",
                (tenant_id, iso_z(since)),
            )
        )
        return StatsOverview(
            tenant_id=tenant_id,
            window_hours=window_hours,
            events_total=self.count_events(tenant_id, since=since),
            events_by_kind=self.events_by_kind(tenant_id, since=since),
            findings_total=sum(findings["by_status"].values()),
            findings_open=findings["by_status"].get("open", 0),
            findings_by_severity=findings["by_severity"],
            findings_by_status=findings["by_status"],
            top_rules=findings["top_rules"],
            actions_total=sum(actions.values()),
            actions_by_status=actions,
            actions_auto=auto_count,
            actions_manual=manual_count,
            actions_rolled_back=actions.get("rolled_back", 0),
            actions_failed=actions.get("failed", 0),
            mttd_seconds=safe_float(mttd) if mttd is not None else None,
            mttr_seconds=safe_float(mttr) if mttr is not None else None,
            autonomy=tenant.mode if tenant else "supervised",
            dry_run=tenant.dry_run if tenant else True,
            audit_records=self.count_audit(tenant_id),
            collectors=list(collectors or []),
        )

    # ----------------------------------------------------------------------------------
    # Rétention
    # ----------------------------------------------------------------------------------

    def purge(self, *, retention_days: int = 30, audit_retention_days: int = 365) -> dict[str, int]:
        """Applique la rétention par lots bornés. Voir ``storage.base`` pour le contrat.

        Trois différences assumées avec SQLite, toutes documentées :

        * sous TimescaleDB, la suppression des événements passe par ``drop_chunks`` (seule
          opération possible sur un chunk compressé) : elle libère des chunks **entiers** plus
          vieux que le seuil, ce qui est plus efficace mais ne supprime pas les quelques lignes
          anciennes d'un chunk encore actif ;
        * ailleurs, la suppression se fait par ``DELETE`` successifs bornés à
          ``purge_batch_size`` lignes, indexés par ``ctid`` — chaque lot est une transaction
          courte, et un ``DELETE`` monolithique ne verrouille jamais la table entière ;
        * le journal d'audit n'est supprimé que si ``audit_retention_days < 3650`` (invariant du
          produit : l'audit est la preuve).
        """
        events = self._purge_events(iso_z(utcnow() - timedelta(days=retention_days)))
        suppressions = self._delete_batched(
            "suppressions", "expires_at < %s::timestamptz", (now_iso(),)
        )
        audit = 0
        if audit_retention_days < 3650:
            audit = self._delete_batched(
                "audit_log",
                "ts < %s::timestamptz",
                (iso_z(utcnow() - timedelta(days=audit_retention_days)),),
            )
        result = {
            "events": max(0, events),
            "suppressions": max(0, suppressions),
            "audit": max(0, audit),
        }
        if any(result.values()):
            log.info("purge de rétention effectuée", extra={"result": result, "dsn": self.safe_dsn})
        return result

    def _purge_events(self, cutoff: str) -> int:
        """Purge des événements : ``drop_chunks`` si l'hypertable est active, sinon par lots."""
        if self._timescaledb:
            before = safe_int(
                self._scalar(
                    "SELECT COUNT(*) AS n FROM events WHERE ts < %s::timestamptz", (cutoff,)
                )
            )
            if not before:
                return 0
            with self._guard("purge des chunks d'événements"):
                self._fetchall(
                    "SELECT drop_chunks('events', older_than => %s::timestamptz)", (cutoff,)
                )
            after = safe_int(
                self._scalar(
                    "SELECT COUNT(*) AS n FROM events WHERE ts < %s::timestamptz", (cutoff,)
                )
            )
            return max(0, before - after)
        return self._delete_batched("events", "ts < %s::timestamptz", (cutoff,))

    def _delete_batched(self, table: str, where: str, params: Sequence[Any]) -> int:
        """Supprime les lignes satisfaisant ``where`` par lots de ``purge_batch_size``.

        ``table`` provient d'une constante interne du module ; ``where`` contient uniquement des
        placeholders typés. Le ``ctid`` (adresse physique de la ligne) sert à borner chaque lot
        sans tri ni curseur : c'est l'équivalent PostgreSQL d'un ``DELETE ... LIMIT``.
        """
        sql = (
            f"DELETE FROM {table} WHERE ctid IN "  # noqa: S608 - nom de table issu d'une constante
            f"(SELECT ctid FROM {table} WHERE {where} LIMIT %s)"
        )
        deleted = 0
        for _ in range(MAX_PURGE_BATCHES):
            batch = self._execute(sql, [*params, self.purge_batch_size])
            deleted += batch
            if batch < self.purge_batch_size:
                return deleted
        log.warning(
            "purge interrompue : limite de lots atteinte",
            extra={"table": table, "deleted": deleted, "max_batches": MAX_PURGE_BATCHES},
        )
        return deleted

    def vacuum(self) -> None:
        """``VACUUM (ANALYZE)`` — hors transaction, comme l'exige PostgreSQL."""
        with self._guard("compactage (VACUUM)"):
            self._raw(self.connection, "VACUUM (ANALYZE)")
        log.info("VACUUM (ANALYZE) exécuté", extra={"dsn": self.safe_dsn})

    #: Tables du schéma logique, dans l'ordre inverse des dépendances.
    LOGICAL_TABLES: ClassVar[tuple[str, ...]] = (
        "suppressions",
        "collector_runs",
        "audit_log",
        "actions",
        "findings",
        "api_keys",
        "events",
        "tenants",
    )

    def reset_database(self) -> None:
        """Vide toutes les tables du schéma logique — **réservé aux tests et aux labos**.

        ``TRUNCATE ... RESTART IDENTITY CASCADE`` plutôt qu'une série de ``DELETE`` : une seule
        instruction, les séquences repartent de zéro (``audit_log_seq`` est attachée à
        ``audit_log.seq``) et aucune clé étrangère ne résiste. Sur une hypertable, TimescaleDB
        tronque l'ensemble des chunks.

        Cette méthode n'est **jamais** appelée par le service : elle sert à repartir d'une base
        propre entre deux tests de conformité, ou à réinitialiser une instance de démonstration.
        Elle est refusée si le magasin est fermé.
        """
        if self._closed:
            raise StorageError("le stockage est fermé")
        tables = ", ".join(self.LOGICAL_TABLES)  # noms de tables issus d'une constante interne
        with self._guard("réinitialisation de la base"):
            self._execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
        log.info(
            "base PostgreSQL réinitialisée (toutes les tables vidées)",
            extra={"dsn": self.safe_dsn, "tables": list(self.LOGICAL_TABLES)},
        )


class _PsycopgPoolAdapter:
    """Adaptateur minimal au-dessus de ``psycopg_pool.ConnectionPool``.

    Le pool du pilote gère la reprise après incident, la validation des connexions mortes et la
    maintenance en tâche de fond : c'est mieux que le pool maison, mais il n'existe que pour
    ``psycopg`` v3. Il est donc utilisé **si disponible**, sans que le code appelant ait à le
    savoir (même interface ``acquire``/``release``/``close``).

    Le pool est ouvert **paresseusement** (``open=False``) : construire un ``PostgresStore`` ne
    doit jamais ouvrir de connexion, sans quoi un diagnostic échouerait avant même d'avoir pu
    dire ce qui ne va pas.
    """

    def __init__(
        self,
        pool_class: Any,
        conninfo: str,
        *,
        min_size: int,
        max_size: int,
        timeout: float,
        connect_kwargs: Mapping[str, Any],
    ) -> None:
        self._timeout = float(timeout)
        self._pool = pool_class(
            conninfo,
            min_size=int(min_size),
            max_size=int(max_size),
            open=False,
            kwargs=dict(connect_kwargs),
        )

    @property
    def stats(self) -> dict[str, Any]:
        get_stats = getattr(self._pool, "get_stats", None)
        if not callable(get_stats):
            return {}
        snapshot = get_stats()
        return {
            "idle": getattr(snapshot, "pool_available", None),
            "in_use": getattr(snapshot, "pool_in_use", None),
            "max": getattr(snapshot, "pool_max", None),
        }

    def acquire(self) -> Any:
        if getattr(self._pool, "closed", False):
            raise StorageError("le pool de connexions PostgreSQL est fermé")
        self._pool.open()
        try:
            return self._pool.getconn(timeout=self._timeout)
        except Exception as exc:
            raise StorageError(
                "connexion PostgreSQL indisponible (pool psycopg_pool)",
                details={"error": redact_dsn_in_text(str(exc)), "sqlstate": sqlstate(exc)},
            ) from exc

    def release(self, connection: Any) -> None:
        with contextlib.suppress(Exception):
            self._pool.putconn(connection)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._pool.close()


# --------------------------------------------------------------------------------------
# Enregistrement dans le contrat
# --------------------------------------------------------------------------------------

#: Convertisseurs ligne → modèle : ce sont ceux de ``storage/store.py``, importés plus haut
#: (``Store._row_to_*``). **Le mappage du schéma logique n'existe qu'à un seul endroit.**
#: Le dupliquer ici garantirait qu'une colonne ajoutée d'un côté soit oubliée de l'autre — c'est
#: exactement le genre d'écart qu'une suite de conformité met des mois à révéler. Ces
#: convertisseurs n'utilisent que l'accès par nom de colonne, commun à ``sqlite3.Row``, à
#: ``DictRow`` (psycopg2) et à ``dict`` (psycopg 3).
StoreProtocol.register(PostgresStore)


def stream_batches(items: Sequence[Any], size: int = INSERT_BATCH_SIZE) -> Iterable[list[Any]]:
    """Découpe une séquence en lots de ``size`` (utilitaire public, testable hors ligne)."""
    return chunked(list(items), max(1, int(size)))


__all__ = [
    "AUDIT_CHAIN_LOCK_SQL",
    "AUDIT_SEQ_SQL",
    "AUDIT_TAIL_SQL",
    "DRIVER_INSTALL_HINT",
    "INSERT_BATCH_SIZE",
    "JSONB_COLUMNS",
    "MAX_PURGE_BATCHES",
    "PURGE_BATCH_SIZE",
    "SSLMODE_BY_ENV",
    "TIMESTAMPTZ_COLUMNS",
    "DriverHandle",
    "PostgresStore",
    "SimpleConnectionPool",
    "build_dsn",
    "column_placeholder",
    "import_driver",
    "in_clause",
    "json_document",
    "load_document",
    "mask_dsn",
    "normalize_dsn",
    "placeholders",
    "redact_dsn_in_text",
    "split_sql_statements",
    "sqlstate",
    "stream_batches",
    "with_query_params",
]
