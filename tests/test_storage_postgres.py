"""Tests PostgreSQL **exécutables hors ligne** — aucun serveur, aucun pilote requis.

Ce fichier couvre tout ce qui ne dépend pas d'une base réelle :

* construction, normalisation et **masquage** du DSN (un mot de passe ne doit jamais être
  journalisé) ;
* détection du backend par ``create_store`` et refus explicite des schémas non supportés ;
* message d'erreur actionnable quand aucun pilote n'est installé (import monkeypatché), et
  sélection ``psycopg`` → ``psycopg2`` ;
* présence des tables, index, hypertable, compression et rétention dans le DDL PostgreSQL, et
  découpage du script en instructions exécutables une par une ;
* conversion des placeholders (``%s`` typés : ``::jsonb``, ``::timestamptz``) et sérialisation
  JSONB ;
* découpage des lots d'insertion (1000 lignes) et usage d'``execute_values`` quand il existe ;
* **choix du verrou d'audit** : le verrou consultatif de transaction est bien pris *avant* la
  lecture du dernier maillon ;
* rétention par lots bornés, ``drop_chunks`` sous TimescaleDB, santé, conflits d'unicité.

Le pilote factice ``FakePostgres`` enregistre le SQL réellement émis : il permet de vérifier des
propriétés d'ordonnancement et de transactionnalité qui, sinon, ne seraient démontrables qu'avec
un serveur — ce qui les rendrait invérifiables en l'absence de PostgreSQL.

Les cas qui exigent une vraie base (conformité complète, réservation atomique) vivent dans
``tests/test_storage_conformance.py`` et sont ignorés sans ``THOT_TEST_POSTGRES_DSN``.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from thotsecure.core.config import Settings
from thotsecure.core.errors import ConfigError, ConflictError, StorageError
from thotsecure.core.models import (
    Action,
    ApiKeyRecord,
    Event,
    EventSource,
    Finding,
    Tenant,
)
from thotsecure.core.util import utcnow
from thotsecure.storage import (
    POSTGRES_CORE_DDL,
    POSTGRES_DDL,
    POSTGRES_TIMESCALE_DDL,
    POSTGRES_TIMESCALE_SECTIONS,
    PostgresStore,
    Store,
    backend_for_url,
    create_store,
    ddl_for,
    store_interface_methods,
    store_location,
)
from thotsecure.storage import postgres as pg

#: DSN d'exemple : le mot de passe est un marqueur, jamais un secret réel.
EXAMPLE_DSN = "postgresql://thot:s3cr3t-Pa55@db.interne:5432/thotsecure"

#: DSN pointant sur un port fermé : « joignable mais rien qui écoute », sans DNS ni attente.
UNREACHABLE_DSN = "postgresql://thot:motdepasse@127.0.0.1:1/thotsecure"


def make_settings(root: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "root_dir": str(root),
        "secret_key": "cle-de-test-uniquement-0123456789abcdefghijklmnop",
        "bootstrap_api_key": "thot_TEST_notThePublicDefault1234",
        "log_level": "WARNING",
        "log_format": "console",
    }
    base.update(overrides)
    return Settings(**base)


# --------------------------------------------------------------------------------------
# Pilote factice : enregistre le SQL émis, rend des réponses scriptées
# --------------------------------------------------------------------------------------


class FakePostgresError(Exception):
    """Erreur de pilote factice, avec un ``sqlstate`` comme les vrais pilotes."""

    def __init__(self, message: str, *, sqlstate: str | None = None) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


class FakeCursor:
    """Curseur factice : rend des dictionnaires (comme ``dict_row``)."""

    def __init__(self, database: FakePostgres, connection: Any) -> None:
        self._database = database
        self._connection = connection
        self._rows: list[dict[str, Any]] = []
        self.rowcount = -1
        self.closed = False

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        result = self._database._record("execute", sql, params)
        self._apply(result)
        return self

    def executemany(self, sql: str, seq_of_params: Any) -> FakeCursor:
        result = self._database._record("executemany", sql, list(seq_of_params or []))
        self._apply(result)
        return self

    def _apply(self, result: Any) -> None:
        if isinstance(result, int):
            self.rowcount = result
            self._rows = []
        else:
            self._rows = [dict(row) for row in (result or [])]
            self.rowcount = len(self._rows)

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._rows)

    def fetchone(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    """Connexion factice : ``autocommit`` comme le magasin l'exige."""

    def __init__(self, database: FakePostgres) -> None:
        self._database = database
        self.autocommit = False
        self.closed = False

    def cursor(self, **kwargs: Any) -> FakeCursor:
        return FakeCursor(self._database, self)

    def close(self) -> None:
        self.closed = True


class FakePostgres:
    """Pilote factice : journalise chaque instruction et répond selon un script.

    ``responder(sql, params)`` retourne soit une liste de lignes, soit un entier (``rowcount``).
    Il peut lever : c'est ainsi qu'on simule une extension TimescaleDB absente ou une violation
    d'unicité, sans serveur.
    """

    def __init__(self, responder: Any = None) -> None:
        self.responder = responder or (lambda sql, params: [])
        self.statements: list[tuple[str, str, Any]] = []
        self.executed: list[str] = []
        self.connect_calls: list[tuple[str, dict[str, Any]]] = []
        self.connections: list[FakeConnection] = []
        self.fail_connect: BaseException | None = None

    # -- journalisation ---------------------------------------------------------------
    def _record(self, kind: str, sql: str, params: Any) -> Any:
        self.statements.append((kind, sql, params))
        self.executed.append(sql)
        return self.responder(sql, params)

    @property
    def statements_in_order(self) -> list[str]:
        """Suites d'instructions normalisées (premier mot-clé + fragment distinctif)."""
        return [_normalize(sql) for _, sql, _ in self.statements]

    def params_for(self, fragment: str) -> Any:
        for _, sql, params in self.statements:
            if fragment in sql:
                return params
        raise AssertionError(f"aucune instruction ne contient {fragment!r}")

    # -- API de pilote ---------------------------------------------------------------
    def connect(self, dsn: str, **kwargs: Any) -> FakeConnection:
        if self.fail_connect is not None:
            raise self.fail_connect
        self.connect_calls.append((dsn, kwargs))
        connection = FakeConnection(self)
        self.connections.append(connection)
        return connection


def _normalize(sql: str) -> str:
    compact = " ".join(sql.split())
    return compact[:90]


def fake_driver(
    database: FakePostgres, *, with_execute_values: bool = False, name: str = "psycopg"
) -> pg.DriverHandle:
    """Poignée de pilote pointant sur le factice (remplace ``psycopg``/``psycopg2``)."""

    class _Module:
        Error = FakePostgresError

        @staticmethod
        def connect(dsn: str, **kwargs: Any) -> Any:
            return database.connect(dsn, **kwargs)

    def execute_values(
        cursor: FakeCursor,
        sql: str,
        argslist: Any,
        template: str | None = None,
        page_size: int | None = None,
        fetch: bool = False,
    ) -> Any:
        rows = list(argslist)
        cursor._database.statements.append(
            ("execute_values", sql, {"rows": rows, "template": template, "page_size": page_size})
        )
        cursor._database.executed.append(sql)
        cursor.rowcount = len(rows)
        return list(range(len(rows))) if fetch else None

    return pg.DriverHandle(
        name=name,
        module=_Module,  # type: ignore[arg-type]
        row_factory=dict,
        execute_values=execute_values if with_execute_values else None,
    )


def make_store(
    database: FakePostgres, *, with_execute_values: bool = False, **kwargs: Any
) -> PostgresStore:
    """Magasin câblé sur le pilote factice (aucun serveur, aucun pilote réel)."""
    return PostgresStore(
        EXAMPLE_DSN,
        driver=fake_driver(database, with_execute_values=with_execute_values),
        use_driver_pool=False,
        **kwargs,
    )


def sample_event(index: int = 0, tenant_id: str = "acme") -> Event:
    return Event(
        event_id=f"ev_{index:04d}",
        tenant_id=tenant_id,
        ts=utcnow(),
        kind="http.request",
        source=EventSource(type="log_tail", name="collecteur", host="shop.acme.fr"),
        labels={"src_ip": "203.0.113.9"},
        payload={"status": 403, "index": index},
    )


# --------------------------------------------------------------------------------------
# 1. DSN : masquage, normalisation, sslmode
# --------------------------------------------------------------------------------------


class DsnSecurityTest(unittest.TestCase):
    """Le DSN ne doit jamais laisser fuiter un mot de passe."""

    def test_mask_dsn_hides_the_password_in_every_form(self) -> None:
        self.assertEqual(
            "postgresql://thot:***@db.interne:5432/thotsecure", pg.mask_dsn(EXAMPLE_DSN)
        )
        self.assertEqual(
            "postgresql://thot:***@h/db?sslmode=require",
            pg.mask_dsn("postgresql://thot:secret@h/db?sslmode=require"),
        )
        self.assertEqual(
            "postgresql://h/db?password=***&sslmode=require",
            pg.mask_dsn("postgresql://h/db?password=s3cr3t&sslmode=require"),
        )
        self.assertEqual(
            "host=db password=*** dbname=thot", pg.mask_dsn("host=db password=s3cr3t dbname=thot")
        )
        self.assertEqual("", pg.mask_dsn(""))
        self.assertEqual("sqlite:///./data/x.db", pg.mask_dsn("sqlite:///./data/x.db"))

    def test_mask_dsn_keeps_the_information_needed_to_diagnose(self) -> None:
        masked = pg.mask_dsn(EXAMPLE_DSN)
        self.assertIn("db.interne", masked)
        self.assertIn("5432", masked)
        self.assertIn("thot", masked)
        self.assertNotIn("s3cr3t", masked)

    def test_redact_dsn_in_driver_message(self) -> None:
        """Un pilote qui recopie son DSN dans son message ne doit pas fuiter le mot de passe."""
        message = f'connection to "{EXAMPLE_DSN}" failed: FATAL: authentification échouée'
        cleaned = pg.redact_dsn_in_text(message)
        self.assertNotIn("s3cr3t-Pa55", cleaned)
        self.assertIn("thot:***@db.interne", cleaned)

    def test_normalize_dsn_accepts_the_supported_schemes(self) -> None:
        for url in (
            "postgresql://u@h/db",
            "postgres://u@h/db",
            "postgresql+psycopg://u@h/db",
            "postgresql+psycopg2://u@h/db",
        ):
            self.assertTrue(pg.normalize_dsn(url).startswith("postgresql://"), url)

    def test_normalize_dsn_refuses_other_drivers_and_empty_dsn(self) -> None:
        with self.assertRaises(StorageError) as raised:
            pg.normalize_dsn("postgresql+asyncpg://u@h/db")
        self.assertIn("asyncpg", raised.exception.message)
        with self.assertRaises(StorageError):
            pg.normalize_dsn("")
        with self.assertRaises(StorageError):
            pg.normalize_dsn("mysql://u@h/db")

    def test_sslmode_default_depends_on_environment(self) -> None:
        """``prefer`` hors production, ``require`` en production : jamais d'implicite."""
        self.assertIn("sslmode=prefer", pg.build_dsn(EXAMPLE_DSN, env="dev"))
        self.assertIn("sslmode=prefer", pg.build_dsn(EXAMPLE_DSN, env="staging"))
        self.assertIn("sslmode=require", pg.build_dsn(EXAMPLE_DSN, env="prod"))

    def test_sslmode_already_present_is_preserved_and_can_be_forced(self) -> None:
        dsn = f"{EXAMPLE_DSN}?sslmode=verify-full"
        self.assertIn("sslmode=verify-full", pg.build_dsn(dsn, env="dev"))
        self.assertIn("sslmode=verify-full", pg.build_dsn(dsn, env="prod"))
        forced = pg.build_dsn(EXAMPLE_DSN, env="dev", sslmode="require")
        self.assertIn("sslmode=require", forced)

    def test_build_dsn_adds_observability_parameters(self) -> None:
        dsn = pg.build_dsn(EXAMPLE_DSN, env="dev", application_name="thotsecure-api")
        self.assertIn("application_name=thotsecure-api", dsn)
        self.assertIn("connect_timeout=10", dsn)
        # Un paramètre fourni par l'exploitant n'est jamais écrasé.
        custom = pg.build_dsn(f"{EXAMPLE_DSN}?application_name=equipe-soc", env="dev")
        self.assertIn("application_name=equipe-soc", custom)


# --------------------------------------------------------------------------------------
# 2. Chargement du pilote
# --------------------------------------------------------------------------------------


class DriverLoadingTest(unittest.TestCase):
    """Le pilote est importé paresseusement, avec un message actionnable s'il manque."""

    def test_missing_driver_raises_an_actionable_error(self) -> None:
        class _NoModules:
            @staticmethod
            def import_module(name: str) -> Any:
                raise ImportError(f"pas de module {name}")

        with (
            mock.patch.object(pg, "importlib", _NoModules),
            self.assertRaises(StorageError) as raised,
        ):
            pg.import_driver(refresh=True)
        message = raised.exception.message
        self.assertIn('pip install "thotsecure[postgres]"', message)
        self.assertIn("psycopg", message)
        self.assertIn("sqlite", message.lower())
        self.assertEqual(["psycopg", "psycopg2"], raised.exception.details.get("packages"))

    def test_psycopg2_is_used_as_fallback(self) -> None:
        psycopg2_module = mock.MagicMock(name="psycopg2")
        extras_module = mock.MagicMock(name="psycopg2.extras")
        extras_module.DictCursor = "dict-cursor"
        extras_module.execute_values = lambda *args, **kwargs: None

        def import_module(name: str) -> Any:
            if name == "psycopg":
                raise ImportError("psycopg absent")
            if name == "psycopg2":
                return psycopg2_module
            if name == "psycopg2.extras":
                return extras_module
            raise ImportError(name)

        with mock.patch.object(pg, "importlib", mock.Mock(import_module=import_module)):
            handle = pg.import_driver(refresh=True)
        self.assertEqual("psycopg2", handle.name)
        self.assertTrue(handle.supports_execute_values)
        self.assertEqual("dict-cursor", handle.row_factory)

    def test_psycopg3_is_preferred_and_has_no_execute_values(self) -> None:
        psycopg_module = mock.MagicMock(name="psycopg")
        rows_module = mock.MagicMock(name="psycopg.rows")
        rows_module.dict_row = "dict-row"

        def import_module(name: str) -> Any:
            if name == "psycopg":
                return psycopg_module
            if name == "psycopg.rows":
                return rows_module
            raise ImportError(f"psycopg2 ne devrait pas être sollicité ({name})")

        with mock.patch.object(pg, "importlib", mock.Mock(import_module=import_module)):
            handle = pg.import_driver(refresh=True)
        self.assertEqual("psycopg", handle.name)
        self.assertFalse(handle.supports_execute_values)
        self.assertEqual("dict-row", handle.row_factory)

    def test_constructing_a_store_does_not_import_the_driver(self) -> None:
        """``create_store()`` doit fonctionner même sans pilote : la connexion est paresseuse."""
        store = PostgresStore(EXAMPLE_DSN)
        self.assertIsNone(store._driver)
        self.assertIsNone(store._pool)
        self.assertEqual("postgresql", store.backend_name)

    def test_health_is_false_when_nothing_can_connect(self) -> None:
        """``health()`` retourne ``False`` au lieu de lever (contrat de ``/readyz``)."""
        store = PostgresStore(UNREACHABLE_DSN, connect_timeout=2, timeout=2.0)
        try:
            self.assertFalse(store.health())
        finally:
            store.close()


# --------------------------------------------------------------------------------------
# 3. Fabrique ``create_store``
# --------------------------------------------------------------------------------------


class CreateStoreTest(unittest.TestCase):
    """La fabrique choisit le backend et refuse les schémas non supportés."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="thot-pg-test-", ignore_cleanup_errors=True)
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_backend_for_url(self) -> None:
        self.assertEqual("sqlite", backend_for_url("sqlite:///./data/thot.db"))
        self.assertEqual("postgresql", backend_for_url(EXAMPLE_DSN))
        self.assertEqual("postgresql", backend_for_url("postgres://u@h/db"))

    def test_unsupported_scheme_is_refused_with_a_clear_message(self) -> None:
        for url, expected in (
            ("mysql://u@h/db", "mysql"),
            ("postgresql+asyncpg://u@h/db", "asyncpg"),
            ("mongodb://u@h/db", "non supporté"),
        ):
            with self.assertRaises(ConfigError) as raised:
                backend_for_url(url)
            self.assertIn(expected, raised.exception.message)
        with self.assertRaises(ConfigError):
            backend_for_url("")
        with self.assertRaises(ConfigError):
            backend_for_url("pas-une-url")

    def test_refused_message_never_contains_the_password(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            backend_for_url("mysql://thot:s3cr3t-Pa55@h/db")
        self.assertNotIn("s3cr3t-Pa55", raised.exception.message)
        self.assertNotIn("s3cr3t-Pa55", str(raised.exception.details))

    def test_create_store_builds_a_sqlite_store(self) -> None:
        settings = make_settings(self.root, db_url="sqlite:///./data/thot.db")
        store = create_store(settings)
        try:
            self.assertEqual("sqlite", store.backend_name)
            self.assertEqual(frozenset(), store.supports_backend_features())
            self.assertTrue(store.health())
        finally:
            store.close()

    def test_create_store_builds_a_postgres_store_without_connecting(self) -> None:
        settings = make_settings(self.root, db_url=EXAMPLE_DSN)
        store = create_store(settings, init_schema=False)
        self.assertIsInstance(store, PostgresStore)
        self.assertEqual("postgresql", store.backend_name)
        # Aucune connexion n'a été tentée : le pilote n'est même pas importé.
        self.assertIsNone(store._driver)
        self.assertIn("sslmode=prefer", store.dsn)

    def test_create_store_refuses_an_unsupported_dsn(self) -> None:
        settings = make_settings(self.root, db_url="sqlite:///./data/x.db")
        object.__setattr__(settings, "db_url", "mysql://u@h/db")
        with self.assertRaises(ConfigError):
            create_store(settings)

    def test_create_store_logs_the_backend_and_masks_the_dsn(self) -> None:
        settings = make_settings(self.root, db_url=EXAMPLE_DSN, log_level="INFO")
        with self.assertLogs("thotsecure.storage", level="INFO") as captured:
            create_store(settings, init_schema=False)
        record = captured.records[0]
        self.assertEqual("postgresql", record.backend)
        self.assertIn("***", record.target, "le DSN journalisé est masqué")
        self.assertNotIn("s3cr3t-Pa55", str(record.__dict__), "aucun secret dans le journal")
        self.assertNotIn("s3cr3t-Pa55", "\n".join(captured.output))

    def test_every_interface_method_exists_on_the_postgres_store(self) -> None:
        store = PostgresStore(EXAMPLE_DSN)
        missing = [
            name for name in store_interface_methods() if not callable(getattr(store, name, None))
        ]
        self.assertEqual([], missing)

    def test_store_location_never_reveals_a_password(self) -> None:
        """Les commandes d'exploitation affichent la cible : jamais le mot de passe."""
        postgres = PostgresStore(EXAMPLE_DSN)
        self.assertIn("***", store_location(postgres))
        self.assertNotIn("s3cr3t-Pa55", store_location(postgres))

        sqlite = Store(self.root / "location.db")
        sqlite.init_schema()
        try:
            self.assertEqual(str(self.root / "location.db"), store_location(sqlite))
        finally:
            sqlite.close()


# --------------------------------------------------------------------------------------
# 4. DDL
# --------------------------------------------------------------------------------------


class PostgresDdlTest(unittest.TestCase):
    """Le DDL livré décrit le schéma logique complet et les capacités TimescaleDB."""

    LOGICAL_TABLES = (
        "tenants",
        "api_keys",
        "events",
        "findings",
        "actions",
        "audit_log",
        "collector_runs",
        "suppressions",
    )

    def test_every_logical_table_is_created(self) -> None:
        for table in self.LOGICAL_TABLES:
            self.assertIn(
                f"CREATE TABLE IF NOT EXISTS {table}",
                POSTGRES_CORE_DDL,
                f"table manquante dans le DDL PostgreSQL : {table}",
            )

    def test_indexes_are_created(self) -> None:
        for index in (
            "idx_api_keys_tenant",
            "idx_events_tenant_ts",
            "idx_events_pending",
            "idx_findings_tenant_status",
            "idx_findings_dedup",
            "idx_actions_tenant_status",
            "idx_actions_cooldown",
            "idx_audit_tenant",
            "idx_collector_runs",
            "idx_suppressions_active",
        ):
            self.assertIn(f"CREATE INDEX IF NOT EXISTS {index}", POSTGRES_CORE_DDL)

    def test_jsonb_gin_index_does_not_require_timescaledb(self) -> None:
        """L'index GIN sur ``labels`` est dans le bloc principal : il profite à tout PostgreSQL."""
        self.assertIn("USING gin (labels jsonb_path_ops)", POSTGRES_CORE_DDL)
        self.assertNotIn("USING gin", POSTGRES_TIMESCALE_DDL)

    def test_timescale_sections_cover_hypertable_compression_retention_and_aggregates(self) -> None:
        self.assertIn("create_hypertable('events', 'ts'", POSTGRES_DDL)
        self.assertIn("timescaledb.compress", POSTGRES_DDL)
        self.assertIn("add_compression_policy('events'", POSTGRES_DDL)
        self.assertIn("add_retention_policy('events'", POSTGRES_DDL)
        self.assertIn("timescaledb.continuous", POSTGRES_DDL)
        self.assertIn("add_continuous_aggregate_policy('events_per_hour'", POSTGRES_DDL)

    def test_timescale_sections_are_named_and_ordered(self) -> None:
        """L'extension et l'hypertable précèdent ce qui en dépend."""
        names = [name for name, _ in POSTGRES_TIMESCALE_SECTIONS]
        self.assertEqual(
            ["extension", "hypertable", "compression", "retention", "aggregates"], names
        )
        self.assertEqual(
            POSTGRES_TIMESCALE_DDL, "".join(section for _, section in POSTGRES_TIMESCALE_SECTIONS)
        )

    def test_hypertable_primary_key_contains_the_partition_column(self) -> None:
        """TimescaleDB l'exige : la PK d'une hypertable contient la colonne de temps."""
        self.assertIn("PRIMARY KEY (tenant_id, event_id, ts)", POSTGRES_CORE_DDL)

    def test_events_carry_the_claim_columns(self) -> None:
        self.assertIn("ADD COLUMN IF NOT EXISTS claimed_by TEXT", POSTGRES_CORE_DDL)
        self.assertIn("ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ", POSTGRES_CORE_DDL)

    def test_audit_log_uses_a_dedicated_sequence(self) -> None:
        """L'empreinte porte sur ``seq`` : il faut le connaître **avant** l'insertion."""
        self.assertIn("CREATE SEQUENCE IF NOT EXISTS audit_log_seq", POSTGRES_CORE_DDL)
        self.assertIn("nextval('audit_log_seq')", POSTGRES_CORE_DDL)
        self.assertIn("OWNED BY audit_log.seq", POSTGRES_CORE_DDL)
        self.assertIn("nextval('audit_log_seq')", pg.AUDIT_SEQ_SQL)

    def test_json_columns_are_jsonb_and_timestamps_are_timestamptz(self) -> None:
        for table, columns in (
            ("events", ("labels", "payload")),
            ("findings", ("tags", "mitre", "evidence", "event_ids")),
            ("actions", ("params", "target", "result", "rollback")),
            ("audit_log", ("target", "before", "after", "context")),
            ("collector_runs", ("detail",)),
            ("tenants", ("autonomy_allowlist", "protected_targets")),
        ):
            body = self._table_body(table)
            for column in columns:
                self.assertRegex(
                    body,
                    rf"(?m)^\s+{column}\s+JSONB\b",
                    f"{table}.{column} doit être JSONB (le code appelant manipule des dict)",
                )
        for table, columns in (
            ("events", ("ts", "ingested_at", "processed_at")),
            ("findings", ("first_seen", "last_seen", "created_at", "updated_at")),
            ("actions", ("requested_at", "expires_at")),
            ("api_keys", ("created_at", "last_used_at", "revoked_at")),
        ):
            body = self._table_body(table)
            for column in columns:
                self.assertRegex(body, rf"(?m)^\s+{column}\s+TIMESTAMPTZ\b")
        self.assertRegex(self._table_body("events"), r"(?m)^\s+processed\s+BOOLEAN\b")
        self.assertRegex(self._table_body("tenants"), r"(?m)^\s+dry_run\s+BOOLEAN\b")
        self.assertRegex(self._table_body("findings"), r"(?m)^\s+risk_score\s+DOUBLE PRECISION\b")

    @staticmethod
    def _table_body(table: str) -> str:
        """Corps de la définition d'une table (pour vérifier les types colonne par colonne)."""
        match = re.search(
            rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\n\);", POSTGRES_CORE_DDL, re.DOTALL
        )
        assert match is not None, f"table absente du DDL : {table}"
        return match.group(1)

    def test_ddl_is_idempotent_by_construction(self) -> None:
        """Aucune instruction de création sans ``IF NOT EXISTS`` : ``init-db`` est rejouable."""
        prefixes = (
            "create table",
            "create index",
            "create unique index",
            "create sequence",
            "create materialized view",
        )
        for statement in pg.split_sql_statements(POSTGRES_DDL):
            head = statement.split("\n", 1)[0].strip().lower()
            if head.startswith(prefixes):
                self.assertIn("if not exists", head, statement[:120])

    def test_ddl_for_selects_the_right_script(self) -> None:
        self.assertEqual(POSTGRES_DDL, ddl_for("postgresql"))
        self.assertEqual(POSTGRES_DDL, ddl_for("postgres"))
        self.assertNotIn("create_hypertable", ddl_for("sqlite"))

    def test_split_sql_statements_handles_comments_and_literals(self) -> None:
        script = """
        -- commentaire de ligne avec un ; piégeux
        CREATE TABLE t (a TEXT DEFAULT '; pas une fin'); -- fin de ligne
        /* bloc ; avec ; des ; points-virgules */
        INSERT INTO t VALUES ('l''itéral');
        DO $$ BEGIN RAISE NOTICE 'dans un bloc; ok'; END $$;
        """
        statements = pg.split_sql_statements(script)
        self.assertEqual(3, len(statements))
        self.assertIn("'; pas une fin'", statements[0])
        self.assertIn("'l''itéral'", statements[1])
        self.assertIn("$$", statements[2])
        self.assertNotIn("commentaire", " ".join(statements))
        # Le point-virgule **à l'intérieur** d'un littéral puis d'un bloc dollar-quoted n'est
        # jamais un séparateur d'instructions.
        self.assertIn("'; pas une fin'", statements[0])
        self.assertIn("dans un bloc; ok", statements[2])
        self.assertEqual(3, len(statements), "aucun découpage à l'intérieur d'un littéral")

    def test_real_ddl_splits_into_executable_statements(self) -> None:
        statements = pg.split_sql_statements(POSTGRES_DDL)
        self.assertGreaterEqual(len(statements), 30)
        for statement in statements:
            self.assertTrue(statement.strip())
            self.assertFalse(statement.strip().startswith("--"))
            self.assertNotIn(";\n", statement)


# --------------------------------------------------------------------------------------
# 5. Construction de SQL : placeholders, casts, JSON
# --------------------------------------------------------------------------------------


class SqlBuildingTest(unittest.TestCase):
    """Les valeurs sont **liées**, jamais concaténées ; les casts sont explicites."""

    def test_placeholders_and_in_clause(self) -> None:
        self.assertEqual("%s", pg.placeholders(1))
        self.assertEqual("%s, %s, %s", pg.placeholders(3))
        self.assertEqual("", pg.placeholders(0))
        self.assertEqual("kind IN (%s, %s)", pg.in_clause("kind", 2))

    def test_column_placeholder_adds_the_required_cast(self) -> None:
        self.assertEqual("%s::jsonb", pg.column_placeholder("events", "labels"))
        self.assertEqual("%s::jsonb", pg.column_placeholder("findings", "evidence"))
        self.assertEqual("%s::timestamptz", pg.column_placeholder("findings", "last_seen"))
        self.assertEqual("%s", pg.column_placeholder("events", "kind"))
        self.assertEqual("%s", pg.column_placeholder("findings", "risk_score"))

    def test_query_builders_use_native_placeholders_and_never_inline_values(self) -> None:
        """Aucun ``?`` ne subsiste, et aucune valeur utilisateur n'entre dans le texte SQL."""
        store = PostgresStore(EXAMPLE_DSN)
        sql, params = store._query_events_sql(
            "acme",
            kinds=["http.request", "log.line"],
            source_types=["log_tail"],
            since="2026-01-01T00:00:00Z",
            until="2026-02-01T00:00:00Z",
            q="union select",
            limit=10,
            cursor=None,
        )
        self.assertIn("%s", sql)
        self.assertNotIn("?", sql)
        self.assertNotIn("acme", sql)
        self.assertNotIn("union select", sql)
        self.assertNotIn("2026-01-01", sql)
        self.assertIn("::timestamptz", sql)
        self.assertIn("ILIKE", sql)
        self.assertIn("ORDER BY ts DESC, event_id DESC", sql)
        self.assertEqual(
            11, params[-1], "la limite demandée est augmentée de 1 pour détecter la suite"
        )
        self.assertIn("acme", params)
        self.assertIn("%union select%", params)

    def test_findings_query_builder_handles_both_sort_orders(self) -> None:
        store = PostgresStore(EXAMPLE_DSN)
        sql, params, primary = store._list_findings_sql(
            "acme",
            status=["open"],
            severity=["high"],
            rule_id="AO-WEB-001",
            since=None,
            until=None,
            min_risk=70.0,
            q="injection",
            sort="risk_score",
            limit=5,
            cursor=None,
        )
        self.assertEqual("risk_score", primary)
        self.assertIn("ORDER BY risk_score DESC, finding_id DESC", sql)
        self.assertEqual(70.0, params[4])
        sql_seen, _, primary_seen = store._list_findings_sql(
            "acme",
            status=None,
            severity=None,
            rule_id=None,
            since=None,
            until=None,
            min_risk=None,
            q=None,
            sort="last_seen",
            limit=5,
            cursor=None,
        )
        self.assertEqual("last_seen", primary_seen)
        self.assertIn("ORDER BY last_seen DESC, finding_id DESC", sql_seen)

    def test_audit_query_builder_paginates_by_sequence(self) -> None:
        store = PostgresStore(EXAMPLE_DSN)
        sql, params = store._list_audit_sql(
            "acme",
            action="action.execute",
            actor="api-key:ci",
            since=None,
            until=None,
            limit=3,
            cursor="42",
        )
        self.assertIn("seq < %s", sql)
        self.assertIn("ORDER BY seq DESC LIMIT %s", sql)
        self.assertEqual(42, params[-2])
        self.assertEqual(4, params[-1])

    def test_jsonb_round_trip_preserves_content(self) -> None:
        """Le code appelant manipule des ``dict`` ; la colonne ne contient que du JSON."""
        payload = {"samples": [{"ts": "2026-02-14T10:00:00Z", "labels": {"src_ip": "203.0.113.9"}}]}
        serialized = pg.json_document(payload)
        self.assertIsInstance(serialized, str)
        self.assertEqual(payload, json.loads(serialized))
        self.assertEqual(payload, pg.load_document(serialized, {}))
        self.assertEqual(payload, pg.load_document(payload, {}))
        self.assertEqual({}, pg.load_document(None, {}))
        self.assertEqual([], pg.load_document("pas du json", []))
        # Les accents ne sont pas échappés : les preuves restent lisibles en base.
        self.assertIn("é", pg.json_document({"msg": "échec"}))

    def test_stream_batches_splits_by_thousand(self) -> None:
        batches = list(pg.stream_batches([sample_event(index) for index in range(2500)], 1000))
        self.assertEqual([1000, 1000, 500], [len(batch) for batch in batches])
        self.assertEqual([], list(pg.stream_batches([])))

    def test_sqlstate_reads_both_driver_conventions(self) -> None:
        self.assertEqual("23505", pg.sqlstate(FakePostgresError("dup", sqlstate="23505")))
        pgcode_error = Exception("dup")
        pgcode_error.pgcode = "23505"  # type: ignore[attr-defined]
        self.assertEqual("23505", pg.sqlstate(pgcode_error))
        self.assertIsNone(pg.sqlstate(Exception("rien")))


# --------------------------------------------------------------------------------------
# 6. Comportement du magasin avec un pilote factice
# --------------------------------------------------------------------------------------


class PostgresStoreBehaviourTest(unittest.TestCase):
    """Propriétés vérifiables sans serveur : lots, verrou d'audit, purge, santé, conflits."""

    def setUp(self) -> None:
        self.database = FakePostgres()
        self.store = make_store(self.database)

    def tearDown(self) -> None:
        self.store.close()

    # -- insertion -------------------------------------------------------------------
    def test_insert_events_is_chunked_into_thousand_row_statements(self) -> None:
        events = [sample_event(index) for index in range(2500)]
        self.database.responder = lambda sql, params: 1000 if "INSERT INTO events" in sql else []
        inserted = self.store.insert_events(events)
        inserts = [sql for sql in self.database.executed if "INSERT INTO events" in sql]
        self.assertEqual(3, len(inserts), "2500 lignes doivent produire 3 instructions")
        self.assertEqual(3000, inserted, "le compte rapporté est la somme des lignes insérées")
        batch_sizes = [
            len(params) for kind, sql, params in self.database.statements if kind == "executemany"
        ]
        self.assertEqual([1000, 1000, 500], batch_sizes)
        # ``BEGIN``/``COMMIT`` encadrent bien le lot : une insertion partielle est impossible.
        self.assertIn("BEGIN", self.database.executed[0])
        self.assertIn("COMMIT", self.database.executed[-1])

    def test_insert_events_uses_execute_values_when_the_driver_provides_it(self) -> None:
        """``execute_values`` (psycopg2) regroupe 1000 lignes en une seule instruction."""
        database = FakePostgres()
        store = make_store(database, with_execute_values=True)
        try:
            inserted = store.insert_events([sample_event(index) for index in range(1500)])
        finally:
            store.close()
        calls = [entry for entry in database.statements if entry[0] == "execute_values"]
        self.assertEqual(2, len(calls), "1500 lignes = 2 appels (1000 puis 500)")
        sql, payload = calls[0][1], calls[0][2]
        self.assertIn("VALUES %s", sql)
        self.assertIn("ON CONFLICT DO NOTHING", sql)
        self.assertIn("RETURNING 1", sql)
        self.assertIn("::jsonb", payload["template"])
        self.assertIn("::timestamptz", payload["template"])
        self.assertEqual(1000, payload["page_size"])
        self.assertEqual(1500, inserted, "le compte vient des lignes réellement renvoyées")

    def test_insert_event_deduplication_is_reported_as_false(self) -> None:
        self.database.responder = lambda sql, params: []
        self.assertFalse(self.store.insert_event(sample_event()))
        self.database.responder = lambda sql, params: (
            [{"event_id": "ev_0000"}] if "RETURNING event_id" in sql else []
        )
        self.assertTrue(self.store.insert_event(sample_event()))

    def test_event_insert_carries_jsonb_and_timestamptz_casts(self) -> None:
        self.store.insert_event(sample_event())
        sql = self.database.executed[0]
        self.assertIn("::jsonb", sql)
        self.assertIn("::timestamptz", sql)
        params = self.database.statements[0][2]
        self.assertIsInstance(params[8], str, "les labels sont sérialisés en texte avant le cast")

    # -- audit -----------------------------------------------------------------------
    def test_append_audit_takes_the_lock_before_reading_the_tail(self) -> None:
        """Le verrou consultatif doit précéder la lecture du dernier maillon : c'est l'invariant."""
        previous_hash = "sha256:" + "a" * 64
        self.database.responder = lambda sql, params: (
            [{"hash": previous_hash}]
            if "FROM audit_log ORDER BY seq DESC" in sql
            else [{"seq": 7}]
            if "nextval" in sql
            else []
        )
        record = self.store.append_audit(
            tenant_id="acme", actor="api-key:ci", actor_role="responder", action="action.execute"
        )
        order = self.database.statements_in_order
        lock_index = next(
            index for index, sql in enumerate(order) if "pg_advisory_xact_lock" in sql
        )
        tail_index = next(
            index for index, sql in enumerate(order) if "FROM audit_log ORDER BY seq DESC" in sql
        )
        insert_index = next(
            index for index, sql in enumerate(order) if "INSERT INTO audit_log" in sql
        )
        self.assertLess(lock_index, tail_index, "le verrou doit être pris avant de lire le maillon")
        self.assertLess(tail_index, insert_index)
        self.assertEqual("BEGIN", order[0])
        self.assertEqual(7, record.seq)
        self.assertEqual(previous_hash, record.prev_hash)
        self.assertIn("sha256:", record.hash)

    def test_append_audit_starts_from_genesis_on_an_empty_log(self) -> None:
        self.database.responder = lambda sql, params: [{"seq": 1}] if "nextval" in sql else []
        record = self.store.append_audit(tenant_id="acme", actor="system", action="system.start")
        self.assertEqual("sha256:genesis", record.prev_hash)
        params = self.database.params_for("INSERT INTO audit_log")
        self.assertEqual("sha256:genesis", params[-2])
        self.assertEqual(record.hash, params[-1])

    def test_append_audit_reports_a_missing_sequence(self) -> None:
        """Sans séquence (schéma incomplet), l'erreur doit être explicite et actionnable."""
        self.database.responder = lambda sql, params: []
        with self.assertRaises(StorageError) as raised:
            self.store.append_audit(tenant_id="acme", actor="system", action="system.start")
        self.assertIn("init_schema", raised.exception.message)

    def test_audit_lock_sql_is_documented_and_transaction_scoped(self) -> None:
        self.assertIn("pg_advisory_xact_lock", pg.AUDIT_CHAIN_LOCK_SQL)
        self.assertIn("hashtext", pg.AUDIT_CHAIN_LOCK_SQL)
        self.assertIsNotNone(PostgresStore.append_audit.__doc__)
        self.assertIn("verrou consultatif", PostgresStore.append_audit.__doc__ or "")

    # -- rejeu multi-processus --------------------------------------------------------
    def test_pending_events_uses_skip_locked(self) -> None:
        """Deux rejeux concurrents ne se partagent pas le même lot (verrou court, non bloquant)."""
        self.store.pending_events(limit=10)
        statements = self.database.statements
        self.assertEqual("BEGIN", statements[0][1])
        self.assertEqual("COMMIT", statements[-1][1])
        sql = next(sql for _, sql, _ in statements if "FROM events" in sql)
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("processed = FALSE", sql)
        self.assertIn("ORDER BY ts ASC", sql)
        params = next(params for _, sql, params in statements if "FOR UPDATE SKIP LOCKED" in sql)
        self.assertEqual((10,), params)

    def test_claim_pending_events_is_a_single_statement(self) -> None:
        """La réservation est atomique : une seule instruction, pas de fenêtre de course."""
        self.store.claim_pending_events(limit=5, lease_seconds=120, worker="worker-1")
        statements = [sql for sql in self.database.executed if "UPDATE events" in sql]
        self.assertEqual(1, len(statements))
        sql = statements[0]
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("make_interval", sql)
        self.assertIn("RETURNING *", sql)
        self.assertEqual(("worker-1", 120, 5), self.database.params_for("UPDATE events"))

    def test_mark_events_processed_clears_the_claim(self) -> None:
        self.database.responder = lambda sql, params: 2 if "UPDATE events" in sql else []
        count = self.store.mark_events_processed(["ev_1", "ev_2"])
        self.assertEqual(2, count)
        sql = next(sql for sql in self.database.executed if "UPDATE events" in sql)
        self.assertIn("claimed_by = NULL", sql)
        self.assertIn("processed = FALSE", sql)

    def test_mark_events_processed_is_chunked(self) -> None:
        self.database.responder = lambda sql, params: 400 if "UPDATE events" in sql else []
        self.store.mark_events_processed([f"ev_{index}" for index in range(900)])
        updates = [sql for sql in self.database.executed if "UPDATE events" in sql]
        self.assertEqual(3, len(updates))

    # -- schéma ----------------------------------------------------------------------
    def test_init_schema_applies_the_core_ddl_statement_by_statement(self) -> None:
        self.store.init_schema(timescale=False)
        self.assertGreaterEqual(len(self.database.executed), 30)
        self.assertFalse(self.store.timescaledb)
        self.assertEqual(
            frozenset({pg.FEATURE_JSONB, pg.FEATURE_SKIP_LOCKED, pg.FEATURE_PENDING_CLAIM}),
            self.store.supports_backend_features(),
        )

    def test_init_schema_reports_timescaledb_features_when_available(self) -> None:
        self.store.init_schema()
        features = self.store.supports_backend_features()
        self.assertTrue(self.store.timescaledb)
        self.assertIn(pg.FEATURE_COMPRESSION, features)
        self.assertIn(pg.FEATURE_NATIVE_RETENTION, features)
        self.assertIn(pg.FEATURE_CONTINUOUS_AGGREGATES, features)
        self.assertIn("create_hypertable", " ".join(self.database.executed))
        self.assertIn("add_retention_policy", " ".join(self.database.executed))

    def test_init_schema_survives_a_missing_extension(self) -> None:
        """Sans TimescaleDB, le schéma logique s'applique quand même : rien n'est perdu."""

        def responder(sql: str, params: Any) -> Any:
            if "CREATE EXTENSION" in sql:
                raise FakePostgresError(
                    'extension "timescaledb" is not available', sqlstate="0A000"
                )
            return []

        self.database.responder = responder
        with self.assertLogs("thotsecure.storage.postgres", level="WARNING") as captured:
            self.store.init_schema()
        self.assertFalse(self.store.timescaledb)
        features = self.store.supports_backend_features()
        self.assertNotIn(pg.FEATURE_COMPRESSION, features)
        self.assertNotIn(pg.FEATURE_CONTINUOUS_AGGREGATES, features)
        self.assertIn("TimescaleDB indisponible", "\n".join(captured.output))
        # Le schéma logique a bien été appliqué (les tables sont créées avant l'extension).
        self.assertIn("CREATE TABLE IF NOT EXISTS tenants", " ".join(self.database.executed))
        self.assertNotIn("create_hypertable", " ".join(self.database.executed))

    def test_init_schema_tolerates_a_refused_compression(self) -> None:
        """Compression refusée (contrainte d'unicité) : non fatal, et la capacité n'est pas promise."""

        def responder(sql: str, params: Any) -> Any:
            if "timescaledb.compress" in sql:
                raise FakePostgresError(
                    "cannot enable compression: unique constraint does not include all "
                    "segmentby columns",
                    sqlstate="0A000",
                )
            return []

        self.database.responder = responder
        with self.assertLogs("thotsecure.storage.postgres", level="WARNING"):
            self.store.init_schema()
        features = self.store.supports_backend_features()
        self.assertNotIn(pg.FEATURE_COMPRESSION, features)
        self.assertIn(pg.FEATURE_NATIVE_RETENTION, features, "la rétention reste applicable")
        self.assertIn("add_retention_policy", " ".join(self.database.executed))

    def test_init_schema_failure_of_the_core_ddl_is_fatal(self) -> None:
        def responder(sql: str, params: Any) -> Any:
            if "CREATE TABLE IF NOT EXISTS actions" in sql:
                raise FakePostgresError("permission denied for schema public", sqlstate="42501")
            return []

        self.database.responder = responder
        with self.assertRaises(StorageError) as raised:
            self.store.init_schema()
        self.assertIn("core", raised.exception.message)
        self.assertEqual("42501", raised.exception.details.get("sqlstate"))

    def test_init_schema_error_message_masks_the_dsn(self) -> None:
        def responder(sql: str, params: Any) -> Any:
            raise FakePostgresError(f'connexion refusée pour "{EXAMPLE_DSN}"')

        self.database.responder = responder
        with self.assertRaises(StorageError) as raised:
            self.store.init_schema()
        self.assertNotIn("s3cr3t-Pa55", raised.exception.message)
        self.assertNotIn("s3cr3t-Pa55", str(raised.exception.details))

    # -- rétention -------------------------------------------------------------------
    def test_purge_deletes_by_bounded_batches(self) -> None:
        """La purge supprime par lots bornés : jamais un ``DELETE`` qui verrouille la table."""
        store = make_store(self.database, purge_batch_size=5)
        try:
            store.init_schema(timescale=False)
            batches = [5, 5, 2]
            calls = {"count": 0}

            def responder(sql: str, params: Any) -> Any:
                if "DELETE FROM events" in sql:
                    value = batches[min(calls["count"], len(batches) - 1)]
                    calls["count"] += 1
                    return value
                if "DELETE FROM suppressions" in sql:
                    return 1
                return []

            self.database.responder = responder
            result = store.purge(retention_days=30, audit_retention_days=365)
        finally:
            store.close()
        self.assertEqual(12, result["events"])
        self.assertEqual(1, result["suppressions"])
        self.assertEqual(0, result["audit"])
        deletes = [sql for sql in self.database.executed if "DELETE FROM events" in sql]
        self.assertEqual(3, len(deletes), "le lot incomplet termine la boucle")
        for sql in deletes:
            self.assertIn("ctid", sql, "un DELETE monolithique verrouillerait la table entière")
            self.assertIn("LIMIT %s", sql)
        params = self.database.params_for("DELETE FROM events")
        self.assertEqual(5, params[-1], "la taille de lot est un paramètre lié")
        audit_deletes = [sql for sql in self.database.executed if "DELETE FROM audit_log" in sql]
        self.assertEqual(1, len(audit_deletes), "la purge d'audit reste possible sous 3650 jours")
        self.assertIn("ctid", audit_deletes[0])

    def test_purge_uses_drop_chunks_on_a_hypertable(self) -> None:
        """Sous TimescaleDB, seuls les chunks peuvent être supprimés (compression)."""
        self.store.init_schema()
        counts = {"count": 0}

        def responder(sql: str, params: Any) -> Any:
            if "COUNT(*) AS n FROM events" in sql:
                counts["count"] += 1
                return [{"n": 40}] if counts["count"] == 1 else [{"n": 0}]
            if "DELETE FROM suppressions" in sql:
                return 0
            return []

        self.database.responder = responder
        result = self.store.purge(retention_days=30)
        self.assertEqual(40, result["events"])
        joined = " ".join(self.database.executed)
        self.assertIn("drop_chunks('events'", joined)
        self.assertNotIn("DELETE FROM events", joined)

    def test_purge_of_audit_requires_an_explicit_short_retention(self) -> None:
        self.store.init_schema(timescale=False)
        self.database.responder = lambda sql, params: 0
        self.store.purge(retention_days=30, audit_retention_days=3650)
        self.assertNotIn("DELETE FROM audit_log", " ".join(self.database.executed))
        self.store.purge(retention_days=30, audit_retention_days=30)
        self.assertIn("DELETE FROM audit_log", " ".join(self.database.executed))

    # -- erreurs et cycle de vie -----------------------------------------------------
    def test_unique_violation_becomes_a_conflict_error(self) -> None:
        existing_action_row = {
            "action_id": "ac_existant",
            "tenant_id": "acme",
            "finding_id": None,
            "policy_id": None,
            "playbook": "block-source-ip",
            "status": "succeeded",
            "mode": "manual",
            "dry_run": True,
            "params": {},
            "target": {},
            "requested_by": "system",
            "requested_at": None,
            "approved_by": None,
            "approved_at": None,
            "rejected_by": None,
            "rejected_at": None,
            "executed_at": None,
            "expires_at": None,
            "result": None,
            "rollback": {},
            "idempotency_key": "clef",
            "audit_seq": None,
            "reason": "",
        }

        def responder(sql: str, params: Any) -> Any:
            if "INSERT INTO actions" in sql:
                raise FakePostgresError(
                    'duplicate key value violates unique constraint "actions_idempotency_key_key"',
                    sqlstate=pg.UNIQUE_VIOLATION,
                )
            if "idempotency_key" in sql:
                return [existing_action_row]
            return []

        self.database.responder = responder
        action = Action(
            action_id="ac_nouveau",
            tenant_id="acme",
            playbook="block-source-ip",
            idempotency_key="clef",
        )
        with self.assertRaises(ConflictError) as raised:
            self.store.insert_action(action)
        self.assertEqual("ac_existant", raised.exception.details.get("action_id"))

    def test_health_is_false_when_the_connection_fails(self) -> None:
        self.database.fail_connect = FakePostgresError(f'could not connect to "{EXAMPLE_DSN}"')
        self.assertFalse(self.store.health())

    def test_health_is_true_when_the_query_succeeds(self) -> None:
        self.database.responder = lambda sql, params: [{"ok": 1}]
        self.assertTrue(self.store.health())

    def test_closed_store_refuses_operations(self) -> None:
        self.store.close()
        with self.assertRaises(StorageError):
            self.store.list_tenants()

    def test_connection_options_include_a_statement_timeout(self) -> None:
        """Un garde-fou serveur : une requête qui dérape est interrompue, pas infinie."""
        store = make_store(self.database, statement_timeout_ms=1234, connect_timeout=3)
        try:
            store.health()
        finally:
            store.close()
        _, kwargs = self.database.connect_calls[0]
        self.assertEqual("-c statement_timeout=1234", kwargs["options"])
        self.assertEqual(3, kwargs["connect_timeout"])

    def test_rollback_on_error_inside_a_transaction(self) -> None:
        """Une erreur dans une transaction explicite provoque un ``ROLLBACK``."""
        self.database.responder = lambda sql, params: []
        with self.assertRaises(RuntimeError), self.store.transaction():
            raise RuntimeError("échec métier")
        self.assertIn("ROLLBACK", self.database.executed)

    def test_nested_transaction_uses_a_savepoint(self) -> None:
        self.database.responder = lambda sql, params: []
        with self.store.transaction(), self.store.transaction():
            pass
        joined = " ".join(self.database.executed)
        self.assertIn("SAVEPOINT thot_sp_1", joined)
        self.assertIn("RELEASE SAVEPOINT thot_sp_1", joined)
        self.assertEqual(1, self.database.executed.count("COMMIT"))

    def test_reset_database_truncates_every_logical_table(self) -> None:
        self.store.reset_database()
        sql = next(sql for sql in self.database.executed if "TRUNCATE" in sql)
        for table in PostgresStore.LOGICAL_TABLES:
            self.assertIn(table, sql)
        self.assertIn("RESTART IDENTITY CASCADE", sql)


# --------------------------------------------------------------------------------------
# 7. Pool de connexions maison
# --------------------------------------------------------------------------------------


class ConnectionPoolTest(unittest.TestCase):
    """Le pool maison borne la concurrence, réutilise les connexions et ne se bloque pas."""

    def test_pool_reuses_connections_and_bounds_concurrency(self) -> None:
        created: list[FakeConnection] = []

        def connect() -> FakeConnection:
            connection = FakeConnection(FakePostgres())
            created.append(connection)
            return connection

        pool = pg.SimpleConnectionPool(connect, max_size=2, timeout=1.0)
        first = pool.acquire()
        second = pool.acquire()
        self.assertEqual(2, len(created))
        self.assertEqual({"idle": 0, "in_use": 2, "max": 2}, pool.stats)

        with self.assertRaises(StorageError) as raised:
            pool.acquire()
        self.assertIn("saturé", raised.exception.message)

        pool.release(first)
        third = pool.acquire()
        self.assertIs(first, third, "une connexion libérée doit être réutilisée")
        self.assertEqual(2, len(created))
        pool.release(second)
        pool.release(third)
        self.assertEqual({"idle": 2, "in_use": 0, "max": 2}, pool.stats)
        pool.close()
        self.assertEqual(0, pool.stats["idle"])

    def test_pool_discards_a_dead_connection(self) -> None:
        pool = pg.SimpleConnectionPool(lambda: FakeConnection(FakePostgres()), max_size=1)
        connection = pool.acquire()
        connection.closed = True
        pool.release(connection)
        self.assertEqual({"idle": 0, "in_use": 0, "max": 1}, pool.stats)

    def test_pool_refuses_to_serve_after_close(self) -> None:
        pool = pg.SimpleConnectionPool(lambda: FakeConnection(FakePostgres()), max_size=1)
        pool.close()
        with self.assertRaises(StorageError):
            pool.acquire()

    def test_pool_is_usable_from_several_threads(self) -> None:
        pool = pg.SimpleConnectionPool(lambda: FakeConnection(FakePostgres()), max_size=4)
        seen: list[int] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                connection = pool.acquire()
                seen.append(id(connection))
                time.sleep(0.01)
                pool.release(connection)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual([], [str(error) for error in errors])
        self.assertEqual(8, len(seen))
        self.assertLessEqual(len(set(seen)), 4, "le plafond du pool doit être respecté")
        pool.close()

    def test_store_uses_the_pool_for_its_thread_connection(self) -> None:
        database = FakePostgres()
        store = make_store(database, max_size=3)
        try:
            self.assertTrue(store.health())
            self.assertEqual(
                1, len(database.connect_calls), "une connexion par thread, pas par requête"
            )
            self.assertTrue(store.health())
            self.assertEqual(1, len(database.connect_calls))
            self.assertEqual(1, store.pool_stats.get("in_use"))
        finally:
            store.close()


# --------------------------------------------------------------------------------------
# 8. Arité du SQL : chaque ``%s`` doit avoir son paramètre
# --------------------------------------------------------------------------------------


class SqlArityTest(unittest.TestCase):
    """Vérifie mécaniquement que ``nombre de %s == nombre de paramètres`` sur **tout** le SQL.

    C'est le contrôle décisif de ce fichier : une colonne ajoutée à un ``INSERT`` sans son
    paramètre (ou l'inverse) ne se voit **ni** à la lecture, **ni** à l'import, **ni** dans les
    tests hors ligne qui ne font que construire des requêtes. Elle ne se manifeste qu'à l'exécution,
    contre un vrai serveur — c'est-à-dire en CI, ou en production. En pilotant chaque écriture via
    le pilote factice, on force ce contrôle à chaque exécution locale.
    """

    TENANT_ROW = {
        "tenant_id": "acme",
        "name": "ACME SAS",
        "mode": "supervised",
        "dry_run": True,
        "autonomy_allowlist": [],
        "protected_targets": [],
        "max_actions_per_hour": 20,
        "cooldown_seconds": 300,
        "asset_criticality": 1.0,
        "created_at": None,
        "updated_at": None,
    }

    FINDING_ROW = {
        "finding_id": "fi_1",
        "tenant_id": "acme",
        "rule_id": "AO-WEB-001",
        "rule_name": "Injection SQL",
        "severity": "high",
        "risk_score": 78.5,
        "confidence": 0.85,
        "status": "open",
        "title": "Tentative d'injection",
        "description": "",
        "remediation": "",
        "tags": [],
        "mitre": [],
        "evidence": {},
        "first_seen": None,
        "last_seen": None,
        "count": 1,
        "event_ids": [],
        "dedup_key": "203.0.113.9",
        "resolution": None,
        "comment": None,
        "created_at": None,
        "updated_at": None,
    }

    ACTION_ROW = {
        "action_id": "ac_1",
        "tenant_id": "acme",
        "finding_id": "fi_1",
        "policy_id": None,
        "playbook": "block-source-ip",
        "status": "planned",
        "mode": "manual",
        "dry_run": True,
        "params": {},
        "target": {},
        "requested_by": "system",
        "requested_at": None,
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "executed_at": None,
        "expires_at": None,
        "result": None,
        "rollback": {},
        "idempotency_key": "clef",
        "audit_seq": None,
        "reason": "",
    }

    EVENT_ROW = {
        "event_id": "ev_0000",
        "tenant_id": "acme",
        "ts": None,
        "kind": "http.request",
        "source_type": "log_tail",
        "source_name": "collecteur",
        "source_host": "shop.acme.fr",
        "severity_hint": "medium",
        "labels": {},
        "payload": {},
        "raw_ref": None,
    }

    #: Ligne « fourre-tout » des requêtes d'agrégation : elle porte **toutes** les clés
    #: susceptibles d'être lues (`n`, `severity`, `status`, `kind`, `rule_id`, `max_risk`,
    #: `collector`, `runs`, `last_run`, `last_status`…), ce qui évite de multiplier les cas
    #: particuliers dans la doublure de test.
    AGGREGATE_ROW = {
        "n": 1,
        "runs": 1,
        "severity": "high",
        "status": "open",
        "kind": "http.request",
        "rule_id": "AO-WEB-001",
        "max_risk": 78.5,
        "collector": "web_probe",
        "last_run": None,
        "last_status": "ok",
        "events": 1,
        "findings": 1,
        "errors": 0,
    }

    def setUp(self) -> None:
        self.database = FakePostgres(self._responder)
        self.store = make_store(self.database, with_execute_values=False)

    def tearDown(self) -> None:
        self.store.close()

    def _responder(self, sql: str, params: Any) -> Any:
        """Réponses scriptées : chaque lecture rend une ligne complète et plausible."""
        if "RETURNING event_id" in sql:
            return [{"event_id": "ev_existant"}]
        if "RETURNING *" in sql:
            return [self.EVENT_ROW]
        if "FROM tenants" in sql:
            return [self.TENANT_ROW]
        if "COUNT(*) AS" in sql:
            return [self.AGGREGATE_ROW]
        if "AVG(" in sql:
            return [{"mttd": None, "mttr": None}]
        if "FROM findings" in sql:
            return [self.FINDING_ROW]
        if "FROM actions" in sql:
            return [self.ACTION_ROW]
        if "FROM audit_log ORDER BY seq DESC" in sql:
            return [{"hash": "sha256:" + "b" * 64}]
        if "nextval" in sql:
            return [{"seq": 12}]
        if "INSERT INTO" in sql or "UPDATE " in sql or "DELETE FROM" in sql:
            return 1
        return []

    def _exercises(self) -> None:
        """Déroule chaque écriture du contrat, une fois, à travers le pilote factice."""
        tenant = Tenant(tenant_id="acme", name="ACME SAS")
        self.store.upsert_tenant(tenant)
        self.store.update_tenant("acme", mode="auto", dry_run=False)

        self.store.insert_api_key(
            ApiKeyRecord(
                key_id="key_1",
                tenant_id="acme",
                label="ci",
                role="admin",
                key_hash="scrypt$test$hash",
                key_prefix="ao_x",
            )
        )
        self.store.revoke_api_key("key_1")
        self.store.touch_api_key("key_1")

        self.store.insert_event(sample_event())
        self.store.insert_events([sample_event(index) for index in range(3)])
        self.store.mark_events_processed(["ev_0001", "ev_0002"])
        self.store.pending_events(limit=5)
        self.store.claim_pending_events(limit=5, worker="w")
        self.store.count_events("acme", since="2026-01-01T00:00:00Z")
        self.store.events_by_kind("acme")
        self.store.query_events("acme", kinds=["generic"], q="x", limit=5)
        self.store.get_event("acme", "ev_1")

        finding = Finding(
            finding_id="fi_1",
            tenant_id="acme",
            rule_id="AO-WEB-001",
            severity="high",
            risk_score=50.0,
        )
        self.store.insert_finding(finding)
        self.store.update_finding("acme", "fi_1", status="acked", comment="vu", tags=["web"])
        self.store.find_open_finding("acme", "AO-WEB-001", "cle")
        self.store.list_findings("acme", status=["open"], min_risk=1.0, q="inj", sort="last_seen")
        self.store.count_findings("acme", since="2026-01-01T00:00:00Z")

        action = Action(
            action_id="ac_1",
            tenant_id="acme",
            playbook="block-source-ip",
            status="planned",
            idempotency_key="clef",
            finding_id="fi_1",
        )
        self.store.insert_action(action)
        self.store.update_action(action)
        self.store.find_action_by_idempotency("clef")
        self.store.list_actions("acme", status=["planned"], playbook="block-source-ip")
        self.store.count_actions_since("acme", "2026-01-01T00:00:00Z")
        self.store.last_action_for("acme", "block-source-ip", "203.0.113.9")
        self.store.actions_by_status("acme")
        self.store.actions_for_finding("acme", "fi_1")

        self.store.append_audit(tenant_id="acme", actor="api-key:ci", action="action.execute")
        self.store.list_audit("acme", action="action.execute", actor="api-key:ci")
        self.store.count_audit("acme", since="2026-01-01T00:00:00Z")

        self.store.record_collector_run(
            tenant_id="acme", collector="web_probe", status="ok", started_at="2026-01-01T00:00:00Z"
        )
        self.store.collector_stats("acme")
        self.store.add_suppression(
            tenant_id="acme",
            rule_id="AO-WEB-001",
            dedup_key="",
            reason="bruit",
            expires_at="2026-01-02T00:00:00Z",
        )
        self.store.is_suppressed("acme", "AO-WEB-001", "x")
        self.store.list_suppressions("acme")
        self.store.stats_overview("acme")
        self.store.purge(retention_days=30)
        self.store.reset_database()

    def test_every_stmt_has_exactly_as_many_parameters_as_placeholders(self) -> None:
        self._exercises()
        mismatches: list[str] = []
        checked = 0
        for kind, sql, params in self.database.statements:
            if params is None:
                counted_placeholder = sql.count("%s")
                if counted_placeholder:
                    mismatches.append(f"{counted_placeholder} placeholders sans paramètres : {sql}")
                continue
            if kind == "executemany":
                for row in params:
                    checked += 1
                    if sql.count("%s") != len(row):
                        mismatches.append(f"executemany {sql.count('%s')} != {len(row)} : {sql}")
                continue
            if kind == "execute_values":
                continue
            if not isinstance(params, (list, tuple)):
                continue
            checked += 1
            if sql.count("%s") != len(params):
                mismatches.append(
                    f"{sql.count('%s')} placeholders != {len(params)} paramètres : {sql}"
                )
        self.assertEqual([], mismatches)
        self.assertGreater(checked, 50, "l'exercice doit couvrir l'essentiel des écritures")

    def test_every_insert_lists_as_many_columns_as_values(self) -> None:
        """Pour chaque ``INSERT``, chaque colonne doit recevoir une valeur (liée ou littérale).

        Le cas ``events.processed`` reçoit le littéral ``FALSE`` : c'est délibéré (la colonne est
        toujours positionnée à l'insertion, jamais héritée d'un défaut). Le contrôle porte donc sur
        le **nombre d'éléments de la liste VALUES**, pas sur le seul nombre de ``%s``.
        """
        self._exercises()
        checked = 0
        for _, sql, _ in self.database.statements:
            compact = " ".join(sql.split())
            if not compact.upper().startswith("INSERT INTO"):
                continue
            columns = compact[compact.index("(") + 1 : compact.index(")")]
            everything_after_values = compact[compact.rindex("VALUES") + len("VALUES") :]
            values = everything_after_values.split("ON CONFLICT")[0].split("RETURNING")[0].strip()
            if values == "%s":  # gabarit ``execute_values`` : vérifié par le test d'arité
                continue
            items = [item.strip() for item in values.strip().strip("()").split(",")]
            column_names = [column.strip() for column in columns.split(",") if column.strip()]
            self.assertEqual(
                len(column_names),
                len(items),
                f"colonnes et valeurs désalignées : {compact[:140]}",
            )
            for item in items:
                self.assertTrue(
                    "%s" in item or item.upper() in {"FALSE", "TRUE", "NULL"},
                    f"valeur non liée ni littérale booléenne : {item}",
                )
            checked += 1
        self.assertGreaterEqual(checked, 7, "les 7 tables métier doivent être couvertes")

    def test_the_exercise_covers_the_whole_interface(self) -> None:
        """Garde-fou : l'exercice ne doit pas se vider silencieusement de son sens."""
        self._exercises()
        executed = " ".join(self.database.executed).upper()
        for keyword in (
            "INSERT INTO TENANTS",
            "INSERT INTO API_KEYS",
            "INSERT INTO EVENTS",
            "INSERT INTO FINDINGS",
            "INSERT INTO ACTIONS",
            "INSERT INTO AUDIT_LOG",
            "INSERT INTO COLLECTOR_RUNS",
            "INSERT INTO SUPPRESSIONS",
            "UPDATE EVENTS",
            "UPDATE FINDINGS",
            "UPDATE ACTIONS",
            "DELETE FROM",
            "TRUNCATE",
        ):
            self.assertIn(keyword, executed, f"l'exercice n'exécute pas : {keyword}")


# --------------------------------------------------------------------------------------
# 9. Journalisation
# --------------------------------------------------------------------------------------


class LoggingTest(unittest.TestCase):
    def test_driver_absence_is_logged_without_raising_at_import(self) -> None:
        """L'import du paquet ne dépend jamais d'un pilote : le module s'importe sans lui."""
        self.assertTrue(hasattr(pg, "PostgresStore"))
        self.assertIsInstance(pg.DRIVER_INSTALL_HINT, str)
        self.assertIn("pip install", pg.DRIVER_INSTALL_HINT)

    def test_logger_name_matches_the_package(self) -> None:
        self.assertEqual("thotsecure.storage.postgres", pg.log.name)
        self.assertIsInstance(pg.log, logging.Logger)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
