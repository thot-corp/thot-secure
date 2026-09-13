"""Couche de persistance d'Thot Secure.

``Store`` (SQLite) et ``PostgresStore`` (PostgreSQL/TimescaleDB) sont les deux implémentations du
contrat ``StoreProtocol``. Aucun autre module ne doit ouvrir de connexion directement : c'est ce
qui garantit le filtrage systématique par ``tenant_id`` et la chaîne d'audit transactionnelle.

La fabrique :func:`create_store` choisit le backend d'après le schéma de ``THOT_DB_URL`` :

* ``sqlite://…`` → ``Store`` (défaut, aucune dépendance externe) ;
* ``postgresql://…`` (ou ``postgres://``, ``postgresql+psycopg://``) → ``PostgresStore``, qui
  exige l'extra optionnel ``postgres`` (``pip install "thotsecure[postgres]"``) ;
* tout autre schéma → ``ConfigError`` explicite, jamais un repli silencieux sur SQLite.

Exemple d'assemblage (le service suit exactement ce chemin) ::

    from thotsecure.core.config import get_settings
    from thotsecure.storage import create_store

    store = create_store(get_settings())
"""

from __future__ import annotations

from typing import Any

from ..core.errors import ConfigError
from ..core.logging_setup import get_logger
from .base import (
    FEATURE_COMPRESSION,
    FEATURE_CONTINUOUS_AGGREGATES,
    FEATURE_JSONB,
    FEATURE_NATIVE_RETENTION,
    FEATURE_PENDING_CLAIM,
    FEATURE_ROW_LEVEL_SECURITY,
    FEATURE_SKIP_LOCKED,
    StoreProtocol,
    store_interface_methods,
)
from .postgres import PostgresStore, mask_dsn
from .schema import (
    POSTGRES_CORE_DDL,
    POSTGRES_DDL,
    POSTGRES_TIMESCALE_AGGREGATES_DDL,
    POSTGRES_TIMESCALE_COMPRESSION_DDL,
    POSTGRES_TIMESCALE_DDL,
    POSTGRES_TIMESCALE_EXTENSION_DDL,
    POSTGRES_TIMESCALE_HYPERTABLE_DDL,
    POSTGRES_TIMESCALE_RETENTION_DDL,
    POSTGRES_TIMESCALE_SECTIONS,
    SCHEMA_VERSION,
    SQLITE_DDL,
    ddl_for,
)
from .store import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    SQLITE_BACKEND_FEATURES,
    Store,
)

log = get_logger("storage")

#: Schémas d'URL acceptés pour ``THOT_DB_URL`` (les suffixes de pilote ``+psycopg``/``+psycopg2``
#: sont tolérés puis normalisés ; les autres pilotes sont refusés, l'adaptateur étant synchrone).
SUPPORTED_DB_SCHEMES: tuple[str, ...] = ("sqlite", "postgresql", "postgres")

#: Suffixes de pilote acceptés sur un schéma PostgreSQL (convention SQLAlchemy de ``THOT_DB_URL``).
SUPPORTED_DSN_DRIVERS: tuple[str, ...] = ("psycopg", "psycopg2")

#: Schémas explicitement refusés, avec la raison : ils apparaissent dans des exemples de
#: déploiement et méritent un message qui dit quoi faire plutôt qu'un « non supporté » sec.
KNOWN_UNSUPPORTED_DB_SCHEMES: dict[str, str] = {
    "postgresql+asyncpg": (
        "l'adaptateur est synchrone et n'utilise que psycopg : utilisez « postgresql://… » "
        "(le suffixe « +asyncpg » n'est pas nécessaire, la même base est visée)"
    ),
    "mysql": "seuls SQLite (défaut) et PostgreSQL/TimescaleDB sont pris en charge",
    "mariadb": "seuls SQLite (défaut) et PostgreSQL/TimescaleDB sont pris en charge",
}


def backend_for_url(db_url: Any) -> str:
    """Détermine le backend d'un ``THOT_DB_URL`` sans rien instancier.

    :returns: ``"sqlite"`` ou ``"postgresql"``.
    :raises ConfigError: si l'URL est vide, sans schéma, ou si le schéma n'est pas supporté.
        Le message nomme le schéma fautif et les schémas acceptés — un backend non supporté doit
        être **refusé**, jamais remplacé silencieusement par SQLite (l'exploitant croirait écrire
        dans sa base de production alors que les données partent dans un fichier local).
    """
    text = str(db_url or "").strip()
    if not text:
        raise ConfigError(
            "THOT_DB_URL est vide : indiquez 'sqlite:///./data/thotsecure.db' (défaut) ou un DSN "
            "'postgresql://…'",
            details={"db_url": ""},
        )
    if "://" not in text:
        raise ConfigError(
            f"THOT_DB_URL n'est pas une URL reconnue : {mask_dsn(text)!r}. Format attendu "
            "'<schéma>://<reste>', par exemple 'sqlite:///./data/thotsecure.db'.",
            details={"db_url": mask_dsn(text)},
        )
    scheme = text.split("://", 1)[0].strip().lower()
    known = KNOWN_UNSUPPORTED_DB_SCHEMES.get(scheme)
    if known:
        raise ConfigError(
            f"schéma de base de données non supporté : {scheme!r} ({known}).",
            details={"db_url": mask_dsn(text), "scheme": scheme},
        )
    base, _, driver = scheme.partition("+")
    if base == "sqlite":
        return "sqlite"
    if base in {"postgres", "postgresql"}:
        if driver and driver not in SUPPORTED_DSN_DRIVERS:
            raise ConfigError(
                f"pilote PostgreSQL non supporté : {driver!r}. L'adaptateur est synchrone et "
                "n'utilise que psycopg (v3) ou psycopg2 : utilisez 'postgresql://' — la même base "
                "est visée, sans suffixe de pilote.",
                details={"db_url": mask_dsn(text), "driver": driver},
            )
        return "postgresql"
    hint = f" ({known})" if known else ""
    raise ConfigError(
        f"schéma de base de données non supporté : {scheme!r}{hint}. Schémas acceptés : "
        + ", ".join(f"'{name}://'" for name in SUPPORTED_DB_SCHEMES)
        + ". PostgreSQL/TimescaleDB est un extra optionnel : "
        'pip install "thotsecure[postgres]".',
        details={"db_url": mask_dsn(text), "scheme": scheme},
    )


def create_store(settings: Any = None, *, init_schema: bool = True) -> StoreProtocol:
    """Fabrique le magasin adapté à la configuration.

    C'est le **seul** point de construction à utiliser : le service, la CLI et les tests passent
    tous par ici, ce qui évite qu'un déploiement PostgreSQL se retrouve avec un magasin SQLite
    dans un coin (ou l'inverse).

    :param settings: objet de configuration (``thotsecure.core.config.Settings``) ; les attributs
        lus sont ``db_url``, ``env`` et le cas échéant ``db_path`` (SQLite). Passer ``None``
        revient à ``get_settings()``.
    :param init_schema: applique le schéma (``init_schema()``) avant de retourner le magasin.
        Idempotent, donc sans risque si l'appelant le rappelle.
    :returns: un objet conforme à ``StoreProtocol`` — ``Store`` ou ``PostgresStore``.
    :raises ConfigError: schéma non supporté ou DSN inexploitable.
    :raises StorageError: schéma non applicable (droits insuffisants, base injoignable…).
    """
    if settings is None:  # import paresseux : ``create_store()`` sans argument reste utilisable
        from ..core.config import get_settings

        settings = get_settings()

    db_url = str(getattr(settings, "db_url", "") or "")
    backend = backend_for_url(db_url)
    env = str(getattr(settings, "env", "dev") or "dev")

    store: StoreProtocol
    if backend == "sqlite":
        db_path = settings.db_path  # lève ConfigError si l'URL n'est pas SQLite
        store = Store(db_path)
        location = str(db_path)
    else:
        store = PostgresStore(
            db_url,
            env=env,
            sslmode=getattr(settings, "db_sslmode", None) or None,
            max_size=int(getattr(settings, "db_pool_max_size", 8) or 8),
        )
        # Le DSN est masqué : un mot de passe ne doit jamais atterrir dans les journaux.
        location = store.safe_dsn  # type: ignore[attr-defined]

    log.info(
        "backend de persistance retenu",
        extra={
            "backend": store.backend_name,
            "target": location,
            "env": env,
            "features": sorted(store.supports_backend_features()),
        },
    )
    if init_schema:
        store.init_schema()
    return store


def store_location(store: StoreProtocol) -> str:
    """Décrit **où** un magasin écrit, sans supposer SQLite.

    Utile à la journalisation, à ``thotsecure doctor`` et à ``thotsecure init-db`` : ces commandes
    affichent aujourd'hui ``settings.db_path``, dont la résolution lève une erreur dès que
    ``THOT_DB_URL`` n'est pas SQLite. Remplacez cet appel par
    ``store_location(store)`` : chemin de fichier pour SQLite, DSN **masqué** pour PostgreSQL.

    :returns: le chemin de la base SQLite, le DSN masqué du serveur PostgreSQL, ou à défaut le nom
        du backend — jamais un secret.
    """
    dsn = getattr(store, "safe_dsn", None)
    if isinstance(dsn, str) and dsn:
        return dsn
    path = getattr(store, "db_path", None)
    if path is not None:
        return str(path)
    return str(getattr(store, "backend_name", "inconnu"))


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "FEATURE_COMPRESSION",
    "FEATURE_CONTINUOUS_AGGREGATES",
    "FEATURE_JSONB",
    "FEATURE_NATIVE_RETENTION",
    "FEATURE_PENDING_CLAIM",
    "FEATURE_ROW_LEVEL_SECURITY",
    "FEATURE_SKIP_LOCKED",
    "KNOWN_UNSUPPORTED_DB_SCHEMES",
    "MAX_PAGE_SIZE",
    "POSTGRES_CORE_DDL",
    "POSTGRES_DDL",
    "POSTGRES_TIMESCALE_AGGREGATES_DDL",
    "POSTGRES_TIMESCALE_COMPRESSION_DDL",
    "POSTGRES_TIMESCALE_DDL",
    "POSTGRES_TIMESCALE_EXTENSION_DDL",
    "POSTGRES_TIMESCALE_HYPERTABLE_DDL",
    "POSTGRES_TIMESCALE_RETENTION_DDL",
    "POSTGRES_TIMESCALE_SECTIONS",
    "PostgresStore",
    "SCHEMA_VERSION",
    "SQLITE_BACKEND_FEATURES",
    "SQLITE_DDL",
    "SUPPORTED_DB_SCHEMES",
    "SUPPORTED_DSN_DRIVERS",
    "Store",
    "StoreProtocol",
    "backend_for_url",
    "create_store",
    "ddl_for",
    "store_interface_methods",
    "store_location",
]
