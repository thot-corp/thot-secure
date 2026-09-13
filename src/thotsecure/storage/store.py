"""Persistance SQLite (stdlib ``sqlite3``) — aucune dépendance externe.

Choix assumé pour le MVP : SQLite est parfaitement adapté jusqu'à quelques centaines
d'événements par seconde, ne demande aucun service externe, et se sauvegarde par simple
copie de fichier. La cible de production est PostgreSQL/TimescaleDB (voir
``storage/schema.py`` et ``docs/architecture/data-model.md``).

Garanties offertes par cette couche :

* **isolation multi-tenant** : chaque lecture filtre ``tenant_id`` (aucune méthode ne
  retourne une ligne d'un autre tenant sans le demander explicitement) ;
* **audit chaîné** : l'ajout d'un enregistrement d'audit est transactionnel
  (``BEGIN IMMEDIATE``) pour qu'aucune écriture concurrente ne casse la chaîne ;
* **idempotence** : ``event_id`` et ``idempotency_key`` sont uniques.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

from ..audit.hashchain import GENESIS_HASH, record_fingerprint
from ..core.errors import ConflictError, NotFoundError, StorageError
from ..core.logging_setup import get_logger
from ..core.models import (
    Action,
    ApiKeyRecord,
    AuditRecord,
    CollectorStatus,
    Event,
    EventSource,
    Finding,
    SeverityCounts,
    StatsOverview,
    Tenant,
)
from ..core.util import iso_z, new_id, now_iso, parse_dt, safe_float, safe_int, utcnow
from .base import StoreProtocol
from .schema import SCHEMA_VERSION, SQLITE_DDL

log = get_logger("storage.sqlite")

#: Limites dures : une requête ne doit jamais pouvoir épuiser la mémoire du serveur.
MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100

#: SQLite n'apporte **aucune** capacité optionnelle du contrat ``storage.base`` : pas de
#: compression de chunks, pas d'agrégats continus, pas de rétention native, pas de réservation
#: atomique multi-processus (un seul écrivain de toute façon). Les appelants qui testent
#: ``supports_backend_features()`` obtiennent donc un ensemble vide et prennent le chemin de
#: repli — c'est exactement ce que fait l'API pour les statistiques.
SQLITE_BACKEND_FEATURES: frozenset[str] = frozenset()


def _encode_cursor(primary: Any, identifier: str) -> str:
    raw = f"{primary}|{identifier}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        primary, identifier = raw.split("|", 1)
        return primary, identifier
    except Exception as exc:  # noqa: BLE001 - tout curseur invalide est un 400
        raise StorageError("curseur de pagination invalide", details={"cursor": cursor}) from exc


def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class Store:
    """Accès aux données. Une instance par processus ; connexions par thread."""

    #: Nom du backend exposé par ``storage.base.StoreProtocol``.
    backend_name: ClassVar[str] = "sqlite"

    def __init__(self, db_path: str | Path, *, timeout: float = 30.0) -> None:
        self.db_path = Path(db_path)
        self.timeout = timeout
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._closed = False
        #: Toutes les connexions ouvertes, tous threads confondus : ``close()`` doit libérer les
        #: descripteurs de fichier de **tous** les threads, sinon la base reste verrouillée après
        #: l'arrêt du service (Windows refuse alors de supprimer ou de déplacer le fichier).
        self._connections: set[sqlite3.Connection] = set()
        self._registry_lock = threading.Lock()

    # ----------------------------------------------------------------------------------
    # Connexion
    # ----------------------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.db_path),
            timeout=self.timeout,
            isolation_level=None,  # autocommit : les transactions sont explicites
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        with self._registry_lock:
            self._connections.add(connection)
        return connection

    @property
    def connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self._closed:
                raise StorageError("le stockage est fermé")
            conn = self._connect()
            self._local.conn = conn
        return conn

    def init_schema(self) -> None:
        """Crée le schéma si nécessaire (idempotent)."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock:
            conn = self.connection
            conn.executescript(SQLITE_DDL)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        log.info("schéma initialisé", extra={"db": str(self.db_path), "schema_version": SCHEMA_VERSION})

    def close(self) -> None:
        """Ferme **toutes** les connexions (tous threads confondus) et marque le magasin fermé.

        Un service qui s'arrête doit rendre les descripteurs de fichier qu'il détient : sans cela,
        la base reste verrouillée et une sauvegarde ou un remplacement de fichier échoue. Les
        connexions des threads de travail sont donc suivies et fermées ici.
        """
        with self._registry_lock:
            connections, self._connections = self._connections, set()
        for connection in connections:
            with suppress(sqlite3.Error):
                connection.close()
        self._local.conn = None
        self._closed = True

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Transaction d'écriture sérialisée (SQLite n'accepte qu'un écrivain à la fois)."""
        with self._write_lock:
            conn = self.connection
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def health(self) -> bool:
        """Vérifie réellement que la base répond (``SELECT 1``), sans jamais lever.

        Retourne ``False`` si la base est injoignable, verrouillée ou si le magasin est fermé :
        ``/readyz`` et ``thotsecure doctor`` s'appuient dessus, et un diagnostic qui lève une
        exception n'est pas un diagnostic.
        """
        try:
            self.connection.execute("SELECT 1").fetchone()
        except (sqlite3.Error, StorageError):
            return False
        return True

    # ----------------------------------------------------------------------------------
    # Tenants
    # ----------------------------------------------------------------------------------

    def upsert_tenant(self, tenant: Tenant, *, replace: bool = True) -> Tenant:
        now = now_iso()
        payload = (
            tenant.tenant_id,
            tenant.name,
            tenant.mode,
            int(tenant.dry_run),
            json.dumps(tenant.autonomy_allowlist),
            json.dumps(tenant.protected_targets),
            tenant.max_actions_per_hour,
            tenant.cooldown_seconds,
            tenant.asset_criticality,
            iso_z(tenant.created_at) if tenant.created_at else now,
            now,
        )
        with self._write_lock:
            self.connection.execute(
                """
                INSERT INTO tenants (tenant_id, name, mode, dry_run, autonomy_allowlist,
                                     protected_targets, max_actions_per_hour, cooldown_seconds,
                                     asset_criticality, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    name=excluded.name,
                    mode=excluded.mode,
                    dry_run=excluded.dry_run,
                    autonomy_allowlist=excluded.autonomy_allowlist,
                    protected_targets=excluded.protected_targets,
                    max_actions_per_hour=excluded.max_actions_per_hour,
                    cooldown_seconds=excluded.cooldown_seconds,
                    asset_criticality=excluded.asset_criticality,
                    updated_at=excluded.updated_at
                """,
                payload,
            )
        created = self.get_tenant(tenant.tenant_id)
        if created is None:  # pragma: no cover - ne peut arriver qu'en cas de corruption
            raise StorageError("tenant introuvable après écriture", details={"tenant_id": tenant.tenant_id})
        return created

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        row = self.connection.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return self._row_to_tenant(row) if row else None

    def require_tenant(self, tenant_id: str) -> Tenant:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFoundError(f"tenant inconnu: {tenant_id}", details={"tenant_id": tenant_id})
        return tenant

    def list_tenants(self) -> list[Tenant]:
        rows = self.connection.execute("SELECT * FROM tenants ORDER BY tenant_id").fetchall()
        return [self._row_to_tenant(row) for row in rows]

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
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.require_tenant(tenant_id)
        if "autonomy_allowlist" in updates:
            updates["autonomy_allowlist"] = json.dumps(updates["autonomy_allowlist"])
        if "protected_targets" in updates:
            updates["protected_targets"] = json.dumps(updates["protected_targets"])
        if "dry_run" in updates:
            updates["dry_run"] = int(bool(updates["dry_run"]))
        assignments = ", ".join(f"{key} = ?" for key in updates)
        values = [*updates.values(), now_iso(), tenant_id]
        with self._write_lock:
            cursor = self.connection.execute(
                f"UPDATE tenants SET {assignments}, updated_at = ? WHERE tenant_id = ?",  # noqa: S608 - clés filtrées par allowlist
                values,
            )
        if cursor.rowcount == 0:
            raise NotFoundError(f"tenant inconnu: {tenant_id}")
        return self.require_tenant(tenant_id)

    @staticmethod
    def _row_to_tenant(row: sqlite3.Row) -> Tenant:
        return Tenant(
            tenant_id=row["tenant_id"],
            name=row["name"],
            mode=row["mode"],
            dry_run=bool(row["dry_run"]),
            autonomy_allowlist=_loads(row["autonomy_allowlist"], []),
            protected_targets=_loads(row["protected_targets"], []),
            max_actions_per_hour=row["max_actions_per_hour"],
            cooldown_seconds=row["cooldown_seconds"],
            asset_criticality=row["asset_criticality"],
            created_at=parse_dt(row["created_at"]) or utcnow(),
            updated_at=parse_dt(row["updated_at"]) or utcnow(),
        )

    # ----------------------------------------------------------------------------------
    # Clés API
    # ----------------------------------------------------------------------------------

    def insert_api_key(self, record: ApiKeyRecord) -> ApiKeyRecord:
        """Insère une clé API **hachée** (``key_hash`` scrypt ; la clé en clair n'est jamais
        persistée).

        L'erreur d'intégrité est traduite en ``ConflictError`` (409) plutôt que laissée remonter
        brute : c'est le même contrat que l'implémentation PostgreSQL, et une collision de clé est
        un conflit métier, pas une panne interne.
        """
        try:
            with self._write_lock:
                self.connection.execute(
                    """
                    INSERT INTO api_keys (key_id, tenant_id, label, role, key_hash, key_prefix,
                                          created_at, last_used_at, revoked_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
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
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "clé API déjà enregistrée (key_id ou empreinte en doublon)",
                details={"key_id": record.key_id},
            ) from exc
        return record

    def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        row = self.connection.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
        return self._row_to_api_key(row) if row else None

    def find_api_key_by_hash(self, key_hash: str) -> ApiKeyRecord | None:
        row = self.connection.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", (key_hash,)
        ).fetchone()
        return self._row_to_api_key(row) if row else None

    def list_api_keys(self, tenant_id: str) -> list[ApiKeyRecord]:
        rows = self.connection.execute(
            "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
        ).fetchall()
        return [self._row_to_api_key(row) for row in rows]

    def revoke_api_key(self, key_id: str, *, tenant_id: str | None = None) -> bool:
        sql = "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL"
        params: list[Any] = [now_iso(), key_id]
        if tenant_id:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        with self._write_lock:
            cursor = self.connection.execute(sql, params)
        return cursor.rowcount > 0

    def touch_api_key(self, key_id: str) -> None:
        with self._write_lock:
            self.connection.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now_iso(), key_id)
            )

    @staticmethod
    def _row_to_api_key(row: sqlite3.Row) -> ApiKeyRecord:
        return ApiKeyRecord(
            key_id=row["key_id"],
            tenant_id=row["tenant_id"],
            label=row["label"],
            role=row["role"],
            key_hash=row["key_hash"],
            key_prefix=row["key_prefix"],
            created_at=parse_dt(row["created_at"]) or utcnow(),
            last_used_at=parse_dt(row["last_used_at"]),
            revoked_at=parse_dt(row["revoked_at"]),
        )

    # ----------------------------------------------------------------------------------
    # Événements
    # ----------------------------------------------------------------------------------

    def insert_event(self, event: Event) -> bool:
        """Insère un événement. Retourne ``False`` si l'``event_id`` existe déjà (idempotence)."""
        with self._write_lock:
            cursor = self.connection.execute(
                """
                INSERT OR IGNORE INTO events (event_id, tenant_id, ts, kind, source_type,
                    source_name, source_host, severity_hint, labels, payload, raw_ref,
                    ingested_at, processed)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    iso_z(event.ts),
                    event.kind,
                    event.source.type,
                    event.source.name,
                    event.source.host,
                    event.severity_hint,
                    json.dumps(event.labels, ensure_ascii=False),
                    json.dumps(event.payload, ensure_ascii=False, default=str),
                    event.raw_ref,
                    now_iso(),
                ),
            )
        return cursor.rowcount > 0

    def insert_events(self, events: Sequence[Event]) -> int:
        """Insertion par lots (une seule transaction : bien plus rapide et atomique)."""
        if not events:
            return 0
        rows = [
            (
                event.event_id,
                event.tenant_id,
                iso_z(event.ts),
                event.kind,
                event.source.type,
                event.source.name,
                event.source.host,
                event.severity_hint,
                json.dumps(event.labels, ensure_ascii=False),
                json.dumps(event.payload, ensure_ascii=False, default=str),
                event.raw_ref,
                now_iso(),
            )
            for event in events
        ]
        with self._write_lock:
            conn = self.connection
            conn.execute("BEGIN IMMEDIATE")
            try:
                before = conn.total_changes
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO events (event_id, tenant_id, ts, kind, source_type,
                        source_name, source_host, severity_hint, labels, payload, raw_ref,
                        ingested_at, processed)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)
                    """,
                    rows,
                )
                inserted = conn.total_changes - before
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return inserted

    def get_event(self, tenant_id: str, event_id: str) -> Event | None:
        row = self.connection.execute(
            "SELECT * FROM events WHERE event_id = ? AND tenant_id = ?", (event_id, tenant_id)
        ).fetchone()
        return self._row_to_event(row) if row else None

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
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if kinds:
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            params.extend(kinds)
        if source_types:
            where.append(f"source_type IN ({','.join('?' * len(source_types))})")
            params.extend(source_types)
        if since:
            where.append("ts >= ?")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("ts <= ?")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if q:
            where.append("(labels LIKE ? OR payload LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if cursor:
            primary, identifier = _decode_cursor(cursor)
            where.append("(ts < ? OR (ts = ? AND event_id < ?))")
            params.extend([primary, primary, identifier])
        sql = (
            f"SELECT * FROM events WHERE {' AND '.join(where)} "  # noqa: S608 - clauses construites
            "ORDER BY ts DESC, event_id DESC LIMIT ?"
        )
        params.append(limit + 1)
        rows = self.connection.execute(sql, params).fetchall()
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_cursor(last["ts"], last["event_id"])
        return [self._row_to_event(row) for row in rows], next_cursor

    def pending_events(self, *, limit: int = 500) -> list[Event]:
        """Événements jamais passés dans le pipeline (reprise après redémarrage)."""
        rows = self.connection.execute(
            "SELECT * FROM events WHERE processed = 0 ORDER BY ts ASC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def mark_events_processed(self, event_ids: Sequence[str]) -> int:
        if not event_ids:
            return 0
        stamp = now_iso()
        with self._write_lock:
            conn = self.connection
            conn.execute("BEGIN IMMEDIATE")
            try:
                total = 0
                for chunk in _chunks(list(event_ids), 400):
                    placeholders = ",".join("?" * len(chunk))
                    cursor = conn.execute(
                        f"UPDATE events SET processed = 1, processed_at = ? "  # noqa: S608
                        f"WHERE event_id IN ({placeholders}) AND processed = 0",
                        [stamp, *chunk],
                    )
                    total += cursor.rowcount
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return total

    def count_events(self, tenant_id: str, *, since: Any = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= ?"
            params.append(iso_z(parse_dt(since) or utcnow()))
        row = self.connection.execute(sql, params).fetchone()
        return safe_int(row["n"] if row else 0)

    def events_by_kind(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        sql = "SELECT kind, COUNT(*) AS n FROM events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= ?"
            params.append(iso_z(parse_dt(since) or utcnow()))
        sql += " GROUP BY kind ORDER BY n DESC"
        return {row["kind"]: row["n"] for row in self.connection.execute(sql, params).fetchall()}

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            tenant_id=row["tenant_id"],
            ts=parse_dt(row["ts"]) or utcnow(),
            kind=row["kind"],
            source=EventSource(
                type=row["source_type"], name=row["source_name"], host=row["source_host"]
            ),
            severity_hint=row["severity_hint"],
            labels=_loads(row["labels"], {}),
            payload=_loads(row["payload"], {}),
            raw_ref=row["raw_ref"],
        )

    # ----------------------------------------------------------------------------------
    # Findings
    # ----------------------------------------------------------------------------------

    def insert_finding(self, finding: Finding) -> Finding:
        with self._write_lock:
            self.connection.execute(
                """
                INSERT INTO findings (finding_id, tenant_id, rule_id, rule_name, severity,
                    risk_score, confidence, status, title, description, remediation, tags,
                    mitre, evidence, first_seen, last_seen, count, event_ids, dedup_key,
                    resolution, comment, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                self._finding_params(finding),
            )
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
            json.dumps(finding.tags, ensure_ascii=False),
            json.dumps(finding.mitre, ensure_ascii=False),
            json.dumps(finding.evidence, ensure_ascii=False, default=str),
            iso_z(finding.first_seen),
            iso_z(finding.last_seen),
            finding.count,
            json.dumps(finding.event_ids, ensure_ascii=False),
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
            if key in {"tags", "mitre", "evidence", "event_ids"}:
                updates[key] = json.dumps(value, ensure_ascii=False, default=str)
            elif key == "last_seen":
                updates[key] = iso_z(parse_dt(value) or utcnow())
            else:
                updates[key] = value
        updates["updated_at"] = now_iso()
        assignments = ", ".join(f"{key} = ?" for key in updates)
        values = [*updates.values(), finding_id, tenant_id]
        with self._write_lock:
            cursor = self.connection.execute(
                f"UPDATE findings SET {assignments} WHERE finding_id = ? AND tenant_id = ?",  # noqa: S608
                values,
            )
        if cursor.rowcount == 0:
            raise NotFoundError(f"finding introuvable: {finding_id}")
        result = self.get_finding(tenant_id, finding_id)
        if result is None:  # pragma: no cover
            raise StorageError("finding introuvable après mise à jour")
        return result

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding | None:
        row = self.connection.execute(
            "SELECT * FROM findings WHERE finding_id = ? AND tenant_id = ?", (finding_id, tenant_id)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    def find_open_finding(self, tenant_id: str, rule_id: str, dedup_key: str) -> Finding | None:
        """Finding ouvert (ou acquitté) correspondant à la clé de déduplication."""
        row = self.connection.execute(
            """
            SELECT * FROM findings
            WHERE tenant_id = ? AND rule_id = ? AND dedup_key = ?
              AND status IN ('open','acked')
            ORDER BY last_seen DESC LIMIT 1
            """,
            (tenant_id, rule_id, dedup_key),
        ).fetchone()
        return self._row_to_finding(row) if row else None

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
        primary = "risk_score" if sort == "risk_score" else "last_seen"
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if status:
            where.append(f"status IN ({','.join('?' * len(status))})")
            params.extend(status)
        if severity:
            where.append(f"severity IN ({','.join('?' * len(severity))})")
            params.extend(severity)
        if rule_id:
            where.append("rule_id = ?")
            params.append(rule_id)
        if since:
            where.append("last_seen >= ?")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("last_seen <= ?")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if min_risk is not None:
            where.append("risk_score >= ?")
            params.append(float(min_risk))
        if q:
            where.append("(title LIKE ? OR description LIKE ? OR rule_id LIKE ?)")
            params.extend([f"%{q}%"] * 3)
        if cursor:
            cursor_primary, identifier = _decode_cursor(cursor)
            if primary == "risk_score":
                where.append("(risk_score < ? OR (risk_score = ? AND finding_id < ?))")
                params.extend([safe_float(cursor_primary), safe_float(cursor_primary), identifier])
            else:
                where.append("(last_seen < ? OR (last_seen = ? AND finding_id < ?))")
                params.extend([cursor_primary, cursor_primary, identifier])
        sql = (
            f"SELECT * FROM findings WHERE {' AND '.join(where)} "  # noqa: S608 - clauses construites
            f"ORDER BY {primary} DESC, finding_id DESC LIMIT ?"
        )
        params.append(limit + 1)
        rows = self.connection.execute(sql, params).fetchall()
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_cursor(last[primary], last["finding_id"])
        return [self._row_to_finding(row) for row in rows], next_cursor

    def count_findings(self, tenant_id: str, *, since: Any = None) -> dict[str, Any]:
        since_iso = iso_z(parse_dt(since) or utcnow()) if since else None
        clause = "AND last_seen >= ?" if since_iso else ""
        params: list[Any] = [tenant_id]
        if since_iso:
            params.append(since_iso)
        by_severity: dict[str, int] = {}
        for row in self.connection.execute(
            f"SELECT severity, COUNT(*) AS n FROM findings WHERE tenant_id = ? {clause} GROUP BY severity",  # noqa: S608
            params,
        ).fetchall():
            by_severity[row["severity"]] = row["n"]
        by_status: dict[str, int] = {}
        for row in self.connection.execute(
            f"SELECT status, COUNT(*) AS n FROM findings WHERE tenant_id = ? {clause} GROUP BY status",  # noqa: S608
            params,
        ).fetchall():
            by_status[row["status"]] = row["n"]
        top_rules = [
            {"rule_id": row["rule_id"], "count": row["n"], "max_risk": row["max_risk"]}
            for row in self.connection.execute(
                f"""
                SELECT rule_id, COUNT(*) AS n, MAX(risk_score) AS max_risk
                FROM findings WHERE tenant_id = ? {clause}
                GROUP BY rule_id ORDER BY n DESC LIMIT 10
                """,  # noqa: S608
                params,
            ).fetchall()
        ]
        return {"by_severity": by_severity, "by_status": by_status, "top_rules": top_rules}

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=row["finding_id"],
            tenant_id=row["tenant_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            risk_score=safe_float(row["risk_score"]),
            confidence=safe_float(row["confidence"], 0.5),
            status=row["status"],
            title=row["title"],
            description=row["description"],
            remediation=row["remediation"],
            tags=_loads(row["tags"], []),
            mitre=_loads(row["mitre"], []),
            evidence=_loads(row["evidence"], {}),
            first_seen=parse_dt(row["first_seen"]) or utcnow(),
            last_seen=parse_dt(row["last_seen"]) or utcnow(),
            count=safe_int(row["count"], 1),
            event_ids=_loads(row["event_ids"], []),
            dedup_key=row["dedup_key"],
            resolution=row["resolution"],
            comment=row["comment"],
            created_at=parse_dt(row["created_at"]) or utcnow(),
            updated_at=parse_dt(row["updated_at"]) or utcnow(),
        )

    # ----------------------------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------------------------

    def insert_action(self, action: Action) -> Action:
        try:
            with self._write_lock:
                self.connection.execute(
                    """
                    INSERT INTO actions (action_id, tenant_id, finding_id, policy_id, playbook,
                        status, mode, dry_run, params, target, requested_by, requested_at,
                        approved_by, approved_at, rejected_by, rejected_at, executed_at,
                        expires_at, result, rollback, idempotency_key, audit_seq, reason)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    self._action_params(action),
                )
        except sqlite3.IntegrityError as exc:
            if "idempotency_key" in str(exc):
                existing = self.find_action_by_idempotency(action.idempotency_key)
                raise ConflictError(
                    "une action identique existe déjà (idempotence)",
                    details={"action_id": existing.action_id if existing else None},
                ) from exc
            raise ConflictError(f"conflit d'intégrité: {exc}") from exc
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
            int(action.dry_run),
            json.dumps(action.params, ensure_ascii=False, default=str),
            json.dumps(action.target.model_dump(), ensure_ascii=False),
            action.requested_by,
            iso_z(action.requested_at),
            action.approved_by,
            iso_z(action.approved_at) if action.approved_at else None,
            action.rejected_by,
            iso_z(action.rejected_at) if action.rejected_at else None,
            iso_z(action.executed_at) if action.executed_at else None,
            iso_z(action.expires_at) if action.expires_at else None,
            json.dumps(action.result, ensure_ascii=False, default=str) if action.result else None,
            json.dumps(action.rollback.model_dump(mode="json"), ensure_ascii=False),
            action.idempotency_key,
            action.audit_seq,
            action.reason,
        )

    def update_action(self, action: Action) -> Action:
        with self._write_lock:
            cursor = self.connection.execute(
                """
                UPDATE actions SET status=?, approved_by=?, approved_at=?, rejected_by=?,
                    rejected_at=?, executed_at=?, result=?, rollback=?, audit_seq=?, reason=?
                WHERE action_id=? AND tenant_id=?
                """,
                (
                    action.status,
                    action.approved_by,
                    iso_z(action.approved_at) if action.approved_at else None,
                    action.rejected_by,
                    iso_z(action.rejected_at) if action.rejected_at else None,
                    iso_z(action.executed_at) if action.executed_at else None,
                    json.dumps(action.result, ensure_ascii=False, default=str) if action.result else None,
                    json.dumps(action.rollback.model_dump(mode="json"), ensure_ascii=False),
                    action.audit_seq,
                    action.reason,
                    action.action_id,
                    action.tenant_id,
                ),
            )
        if cursor.rowcount == 0:
            raise NotFoundError(f"action introuvable: {action.action_id}")
        return action

    def get_action(self, tenant_id: str, action_id: str) -> Action | None:
        row = self.connection.execute(
            "SELECT * FROM actions WHERE action_id = ? AND tenant_id = ?", (action_id, tenant_id)
        ).fetchone()
        return self._row_to_action(row) if row else None

    def find_action_by_idempotency(self, idempotency_key: str) -> Action | None:
        row = self.connection.execute(
            "SELECT * FROM actions WHERE idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        return self._row_to_action(row) if row else None

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
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if status:
            where.append(f"status IN ({','.join('?' * len(status))})")
            params.extend(status)
        if playbook:
            where.append("playbook = ?")
            params.append(playbook)
        if finding_id:
            where.append("finding_id = ?")
            params.append(finding_id)
        if cursor:
            primary, identifier = _decode_cursor(cursor)
            where.append("(requested_at < ? OR (requested_at = ? AND action_id < ?))")
            params.extend([primary, primary, identifier])
        sql = (
            f"SELECT * FROM actions WHERE {' AND '.join(where)} "  # noqa: S608
            "ORDER BY requested_at DESC, action_id DESC LIMIT ?"
        )
        params.append(limit + 1)
        rows = self.connection.execute(sql, params).fetchall()
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_cursor(last["requested_at"], last["action_id"])
        return [self._row_to_action(row) for row in rows], next_cursor

    def count_actions_since(
        self, tenant_id: str, since: Any, *, playbook: str | None = None, exclude_failed: bool = True
    ) -> int:
        sql = "SELECT COUNT(*) AS n FROM actions WHERE tenant_id = ? AND requested_at >= ?"
        params: list[Any] = [tenant_id, iso_z(parse_dt(since) or utcnow())]
        if playbook:
            sql += " AND playbook = ?"
            params.append(playbook)
        if exclude_failed:
            sql += " AND status NOT IN ('rejected','failed')"
        row = self.connection.execute(sql, params).fetchone()
        return safe_int(row["n"] if row else 0)

    def last_action_for(
        self, tenant_id: str, playbook: str, target_value: str
    ) -> Action | None:
        """Dernière action réussie sur une cible donnée — sert au calcul du cooldown."""
        row = self.connection.execute(
            """
            SELECT * FROM actions
            WHERE tenant_id = ? AND playbook = ? AND target LIKE ? 
              AND status IN ('succeeded','executing','approved')
            ORDER BY requested_at DESC LIMIT 1
            """,
            (tenant_id, playbook, f'%"{target_value}"%'),
        ).fetchone()
        return self._row_to_action(row) if row else None

    def actions_by_status(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        sql = "SELECT status, COUNT(*) AS n FROM actions WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND requested_at >= ?"
            params.append(iso_z(parse_dt(since) or utcnow()))
        sql += " GROUP BY status"
        return {row["status"]: row["n"] for row in self.connection.execute(sql, params).fetchall()}

    def actions_for_finding(self, tenant_id: str, finding_id: str) -> list[Action]:
        rows = self.connection.execute(
            "SELECT * FROM actions WHERE tenant_id = ? AND finding_id = ? ORDER BY requested_at DESC",
            (tenant_id, finding_id),
        ).fetchall()
        return [self._row_to_action(row) for row in rows]

    @staticmethod
    def _row_to_action(row: sqlite3.Row) -> Action:
        action = Action(
            action_id=row["action_id"],
            tenant_id=row["tenant_id"],
            finding_id=row["finding_id"],
            policy_id=row["policy_id"],
            playbook=row["playbook"],
            status=row["status"],
            mode=row["mode"],
            dry_run=bool(row["dry_run"]),
            params=_loads(row["params"], {}),
            requested_by=row["requested_by"],
            requested_at=parse_dt(row["requested_at"]) or utcnow(),
            approved_by=row["approved_by"],
            approved_at=parse_dt(row["approved_at"]),
            rejected_by=row["rejected_by"],
            rejected_at=parse_dt(row["rejected_at"]),
            executed_at=parse_dt(row["executed_at"]),
            expires_at=parse_dt(row["expires_at"]),
            result=_loads(row["result"], None) if row["result"] else None,
            idempotency_key=row["idempotency_key"],
            audit_seq=row["audit_seq"],
            reason=row["reason"],
        )
        target = _loads(row["target"], {})
        if target:
            from ..core.models import ActionTarget

            action.target = ActionTarget(**target)
        rollback = _loads(row["rollback"], {})
        if rollback:
            from ..core.models import ActionRollback

            action.rollback = ActionRollback(**rollback)
        return action

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
        """Ajoute un enregistrement chaîné. Transactionnel : la chaîne ne peut pas se rompre."""
        stamp = iso_z(parse_dt(ts) or utcnow())
        target = target or {}
        before = before or {}
        after = after or {}
        context = context or {}
        with self._write_lock:
            conn = self.connection
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                prev_hash = row["hash"] if row else GENESIS_HASH
                cursor = conn.execute(
                    "INSERT INTO audit_log (ts, tenant_id, actor, actor_role, action, target,"
                    " before, after, context, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,'')",
                    (
                        stamp,
                        tenant_id,
                        actor,
                        actor_role,
                        action,
                        json.dumps(target, ensure_ascii=False, default=str),
                        json.dumps(before, ensure_ascii=False, default=str),
                        json.dumps(after, ensure_ascii=False, default=str),
                        json.dumps(context, ensure_ascii=False, default=str),
                        prev_hash,
                    ),
                )
                seq = int(cursor.lastrowid or 0)
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
                conn.execute("UPDATE audit_log SET hash = ? WHERE seq = ?", (digest, seq))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
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
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if action:
            where.append("action = ?")
            params.append(action)
        if actor:
            where.append("actor = ?")
            params.append(actor)
        if since:
            where.append("ts >= ?")
            params.append(iso_z(parse_dt(since) or utcnow()))
        if until:
            where.append("ts <= ?")
            params.append(iso_z(parse_dt(until) or utcnow()))
        if cursor:
            seq = safe_int(cursor, 0)
            where.append("seq < ?")
            params.append(seq)
        sql = (
            f"SELECT * FROM audit_log WHERE {' AND '.join(where)} "  # noqa: S608
            "ORDER BY seq DESC LIMIT ?"
        )
        params.append(limit + 1)
        rows = self.connection.execute(sql, params).fetchall()
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = str(rows[-1]["seq"])
        return [self._row_to_audit(row) for row in rows], next_cursor

    def iter_audit(self, *, tenant_id: str | None = None) -> Iterator[AuditRecord]:
        """Itère la chaîne complète dans l'ordre des ``seq`` (vérification d'intégrité)."""
        if tenant_id:
            rows = self.connection.execute(
                "SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY seq ASC", (tenant_id,)
            ).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        for row in rows:
            yield self._row_to_audit(row)

    def count_audit(self, tenant_id: str, *, since: Any = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM audit_log WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if since:
            sql += " AND ts >= ?"
            params.append(iso_z(parse_dt(since) or utcnow()))
        row = self.connection.execute(sql, params).fetchone()
        return safe_int(row["n"] if row else 0)

    @staticmethod
    def _row_to_audit(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            seq=safe_int(row["seq"]),
            ts=parse_dt(row["ts"]) or utcnow(),
            tenant_id=row["tenant_id"],
            actor=row["actor"],
            actor_role=row["actor_role"],
            action=row["action"],
            target=_loads(row["target"], {}),
            before=_loads(row["before"], {}),
            after=_loads(row["after"], {}),
            context=_loads(row["context"], {}),
            prev_hash=row["prev_hash"],
            hash=row["hash"],
        )

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
        with self._write_lock:
            self.connection.execute(
                """
                INSERT INTO collector_runs (run_id, tenant_id, collector, started_at, finished_at,
                    status, events, findings, errors, detail)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
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
                    json.dumps(detail or {}, ensure_ascii=False, default=str),
                ),
            )
        return run_id

    def collector_stats(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT collector,
                   COUNT(*) AS runs,
                   MAX(started_at) AS last_run,
                   SUM(events) AS events,
                   SUM(findings) AS findings,
                   SUM(errors) AS errors,
                   MAX(status) AS last_status
            FROM collector_runs WHERE tenant_id = ?
            GROUP BY collector
            """,
            (tenant_id,),
        ).fetchall()
        stats: dict[str, dict[str, Any]] = {}
        for row in rows:
            last = self.connection.execute(
                "SELECT status, detail FROM collector_runs WHERE tenant_id=? AND collector=?"
                " ORDER BY started_at DESC LIMIT 1",
                (tenant_id, row["collector"]),
            ).fetchone()
            stats[row["collector"]] = {
                "runs": safe_int(row["runs"]),
                "last_run": row["last_run"],
                "last_status": (last["status"] if last else "never"),
                "events": safe_int(row["events"]),
                "findings": safe_int(row["findings"]),
                "errors": safe_int(row["errors"]),
                "detail": _loads(last["detail"], {}) if last else {},
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
        with self._write_lock:
            self.connection.execute(
                """
                INSERT INTO suppressions (suppression_id, tenant_id, rule_id, dedup_key, reason,
                    created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)
                """,
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
        row = self.connection.execute(
            """
            SELECT 1 FROM suppressions
            WHERE tenant_id = ? AND rule_id = ? AND (dedup_key = ? OR dedup_key = '')
              AND expires_at > ? LIMIT 1
            """,
            (tenant_id, rule_id, dedup_key, now_iso()),
        ).fetchone()
        return row is not None

    def list_suppressions(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM suppressions WHERE tenant_id = ? AND expires_at > ? ORDER BY expires_at",
            (tenant_id, now_iso()),
        ).fetchall()
        return [dict(row) for row in rows]

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
        severity = SeverityCounts()
        for name, value in findings["by_severity"].items():
            severity.add(name, value)

        # MTTD : délai entre le premier événement et la création du finding (sur la fenêtre).
        mttd_rows = self.connection.execute(
            """
            SELECT AVG((julianday(f.created_at) - julianday(f.first_seen)) * 86400.0) AS mttd
            FROM findings f WHERE f.tenant_id = ? AND f.created_at >= ?
            """,
            (tenant_id, iso_z(since)),
        ).fetchone()
        # MTTR : délai entre création et fermeture.
        mttr_rows = self.connection.execute(
            """
            SELECT AVG((julianday(f.updated_at) - julianday(f.created_at)) * 86400.0) AS mttr
            FROM findings f WHERE f.tenant_id = ? AND f.status = 'closed' AND f.updated_at >= ?
            """,
            (tenant_id, iso_z(since)),
        ).fetchone()
        auto_count = safe_int(
            self.connection.execute(
                "SELECT COUNT(*) AS n FROM actions WHERE tenant_id = ? AND mode = 'auto' AND requested_at >= ?",
                (tenant_id, iso_z(since)),
            ).fetchone()["n"]
        )
        manual_count = safe_int(
            self.connection.execute(
                "SELECT COUNT(*) AS n FROM actions WHERE tenant_id = ? AND mode = 'manual' AND requested_at >= ?",
                (tenant_id, iso_z(since)),
            ).fetchone()["n"]
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
            mttd_seconds=safe_float(mttd_rows["mttd"]) if mttd_rows and mttd_rows["mttd"] else None,
            mttr_seconds=safe_float(mttr_rows["mttr"]) if mttr_rows and mttr_rows["mttr"] else None,
            autonomy=tenant.mode if tenant else "supervised",
            dry_run=tenant.dry_run if tenant else True,
            audit_records=self.count_audit(tenant_id),
            collectors=list(collectors or []),
        )

    # ----------------------------------------------------------------------------------
    # Rétention
    # ----------------------------------------------------------------------------------

    def purge(self, *, retention_days: int = 30, audit_retention_days: int = 365) -> dict[str, int]:
        """Supprime les données au-delà de la rétention.

        Le journal d'audit n'est **jamais** purgé au même rythme que les événements : il
        constitue la preuve. Sa rétention est configurable séparément et sa suppression est
        un événement audité en soi.
        """
        events_cutoff = iso_z(utcnow() - timedelta(days=retention_days))
        audit_cutoff = iso_z(utcnow() - timedelta(days=audit_retention_days))
        with self._write_lock:
            conn = self.connection
            conn.execute("BEGIN IMMEDIATE")
            try:
                events = conn.execute("DELETE FROM events WHERE ts < ?", (events_cutoff,)).rowcount
                suppressions = conn.execute(
                    "DELETE FROM suppressions WHERE expires_at < ?", (now_iso(),)
                ).rowcount
                # Purge de l'audit : interdit par défaut (audit_retention_days élevé).
                audit = 0
                if audit_retention_days < 3650:
                    audit = conn.execute("DELETE FROM audit_log WHERE ts < ?", (audit_cutoff,)).rowcount
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        result = {"events": max(0, events), "suppressions": max(0, suppressions), "audit": max(0, audit)}
        if any(result.values()):
            log.info("purge de rétention effectuée", extra={"result": result})
        return result

    def vacuum(self) -> None:
        with self._write_lock:
            self.connection.execute("VACUUM")

    def supports_backend_features(self) -> frozenset[str]:
        """Capacités optionnelles du backend — voir ``storage.base``.

        SQLite n'en apporte aucune : la rétention est applicative, il n'y a ni compression ni
        agrégat continu. L'ensemble est donc **toujours** vide, ce qui laisse la couche
        appelante emprunter le chemin de repli (calcul des statistiques par requêtes).
        """
        return SQLITE_BACKEND_FEATURES


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


# ``Store`` est l'implémentation de référence du contrat : on l'enregistre comme sous-classe
# virtuelle de l'ABC plutôt que de l'y faire hériter (aucun risque de casser l'héritage, la
# signature ou l'ordre d'initialisation du magasin historique).
StoreProtocol.register(Store)

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "SQLITE_BACKEND_FEATURES",
    "Store",
]
