"""Schéma de base de données — SQLite (MVP) et PostgreSQL/TimescaleDB (production).

Le DDL est centralisé ici pour qu'``init-db``, les tests et les migrations PostgreSQL
décrivent **la même** structure logique. Toute évolution doit être répercutée dans
``migrations/002_*.sql`` (SQLite) et dans ``migrations/postgresql/``.
"""

from __future__ import annotations

#: Version du schéma, inscrite dans ``PRAGMA user_version``.
SCHEMA_VERSION = 1

SQLITE_DDL = """
-- ---------------------------------------------------------------------------------
-- Tenants : frontière d'isolation. Toute table porte tenant_id.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id            TEXT PRIMARY KEY,
    name                 TEXT NOT NULL DEFAULT '',
    mode                 TEXT NOT NULL DEFAULT 'supervised'
                         CHECK (mode IN ('manual','supervised','auto')),
    dry_run              INTEGER NOT NULL DEFAULT 1 CHECK (dry_run IN (0,1)),
    autonomy_allowlist   TEXT NOT NULL DEFAULT '[]',
    protected_targets    TEXT NOT NULL DEFAULT '[]',
    max_actions_per_hour INTEGER NOT NULL DEFAULT 20 CHECK (max_actions_per_hour > 0),
    cooldown_seconds     INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_seconds >= 0),
    asset_criticality    REAL NOT NULL DEFAULT 1.0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

-- ---------------------------------------------------------------------------------
-- Clés API : jamais stockées en clair (scrypt + pepper).
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    label        TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'viewer'
                 CHECK (role IN ('viewer','analyst','responder','admin')),
    key_hash     TEXT NOT NULL,
    key_prefix   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);

-- ---------------------------------------------------------------------------------
-- Événements bruts (immuables, purgés par rétention).
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    ts            TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'generic',
    source_type   TEXT NOT NULL DEFAULT 'manual',
    source_name   TEXT,
    source_host   TEXT,
    severity_hint TEXT,
    labels        TEXT NOT NULL DEFAULT '{}',
    payload       TEXT NOT NULL DEFAULT '{}',
    raw_ref       TEXT,
    ingested_at   TEXT NOT NULL,
    processed     INTEGER NOT NULL DEFAULT 0 CHECK (processed IN (0,1)),
    processed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts   ON events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant_kind ON events(tenant_id, kind, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_pending     ON events(processed, ts) WHERE processed = 0;

-- ---------------------------------------------------------------------------------
-- Findings : agrégats produits par le moteur de détection.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'medium'
                 CHECK (severity IN ('info','low','medium','high','critical')),
    risk_score   REAL NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence   REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
    status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','acked','closed','suppressed')),
    title        TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    remediation  TEXT NOT NULL DEFAULT '',
    tags         TEXT NOT NULL DEFAULT '[]',
    mitre        TEXT NOT NULL DEFAULT '[]',
    evidence     TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1 CHECK (count > 0),
    event_ids    TEXT NOT NULL DEFAULT '[]',
    dedup_key    TEXT NOT NULL DEFAULT '',
    resolution   TEXT,
    comment      TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status   ON findings(tenant_id, status, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_lastseen ON findings(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_dedup           ON findings(tenant_id, rule_id, dedup_key, status);

-- ---------------------------------------------------------------------------------
-- Actions : cycle de vie complet, idempotence, rollback.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actions (
    action_id       TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
    policy_id       TEXT,
    playbook        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'planned'
                    CHECK (status IN ('planned','pending_approval','approved','rejected',
                                      'executing','succeeded','failed','expired','rolled_back')),
    mode            TEXT NOT NULL DEFAULT 'manual' CHECK (mode IN ('auto','manual')),
    dry_run         INTEGER NOT NULL DEFAULT 1 CHECK (dry_run IN (0,1)),
    params          TEXT NOT NULL DEFAULT '{}',
    target          TEXT NOT NULL DEFAULT '{}',
    requested_by    TEXT NOT NULL DEFAULT 'system',
    requested_at    TEXT NOT NULL,
    approved_by     TEXT,
    approved_at     TEXT,
    rejected_by     TEXT,
    rejected_at     TEXT,
    executed_at     TEXT,
    expires_at      TEXT,
    result          TEXT,
    rollback        TEXT NOT NULL DEFAULT '{}',
    idempotency_key TEXT NOT NULL UNIQUE,
    audit_seq       INTEGER,
    reason          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions(tenant_id, status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_time   ON actions(tenant_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_finding       ON actions(finding_id);
CREATE INDEX IF NOT EXISTS idx_actions_cooldown      ON actions(tenant_id, playbook, requested_at DESC);

-- ---------------------------------------------------------------------------------
-- Journal d'audit append-only, chaîné par hash. Aucun UPDATE/DELETE applicatif.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    actor_role TEXT NOT NULL DEFAULT 'system',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '{}',
    before     TEXT NOT NULL DEFAULT '{}',
    after      TEXT NOT NULL DEFAULT '{}',
    context    TEXT NOT NULL DEFAULT '{}',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);

-- ---------------------------------------------------------------------------------
-- Exécutions de collecteurs (observabilité) et suppressions de bruit.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collector_runs (
    run_id       TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    collector    TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'running'
                 CHECK (status IN ('running','ok','partial','error')),
    events       INTEGER NOT NULL DEFAULT 0,
    findings     INTEGER NOT NULL DEFAULT 0,
    errors       INTEGER NOT NULL DEFAULT 0,
    detail       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_collector_runs ON collector_runs(tenant_id, collector, started_at DESC);

CREATE TABLE IF NOT EXISTS suppressions (
    suppression_id  TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    dedup_key       TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT 'system',
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_active ON suppressions(tenant_id, rule_id, expires_at);
"""

#: DDL PostgreSQL/TimescaleDB — cible de production. Non exécuté par le MVP.
POSTGRES_DDL = """
-- Extension TimescaleDB requise pour la compression et les agrégats continus.
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id            TEXT PRIMARY KEY,
    name                 TEXT NOT NULL DEFAULT '',
    mode                 TEXT NOT NULL DEFAULT 'supervised'
                         CHECK (mode IN ('manual','supervised','auto')),
    dry_run              BOOLEAN NOT NULL DEFAULT TRUE,
    autonomy_allowlist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    protected_targets    JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_actions_per_hour INTEGER NOT NULL DEFAULT 20 CHECK (max_actions_per_hour > 0),
    cooldown_seconds     INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_seconds >= 0),
    asset_criticality    REAL NOT NULL DEFAULT 1.0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT NOT NULL,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    ts            TIMESTAMPTZ NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'generic',
    source_type   TEXT NOT NULL DEFAULT 'manual',
    source_name   TEXT,
    source_host   TEXT,
    severity_hint TEXT,
    labels        JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_ref       TEXT,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed     BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at  TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, event_id, ts)
);

-- Hypertable partitionnée par le temps : indispensable au-delà de quelques millions
-- d'événements, et prérequis aux politiques de rétention natives.
SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day',
                         if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_events_tenant_kind ON events(tenant_id, kind, ts DESC);
-- JSONB : les règles interrogent labels->>'src_ip' sans index dédié dans le MVP.
CREATE INDEX IF NOT EXISTS idx_events_labels_src_ip ON events USING gin (labels jsonb_path_ops);

-- Compression des chunks de plus de 7 jours (÷10 sur le stockage en pratique).
ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'tenant_id');
SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);
-- Rétention : 30 jours par défaut, aligné sur THOT_RETENTION_DAYS.
SELECT add_retention_policy('events', INTERVAL '30 days', if_not_exists => TRUE);

-- Agrégat continu : volumétrie par règle et par heure, pour le tableau de bord.
CREATE MATERIALIZED VIEW IF NOT EXISTS events_per_hour
WITH (timescaledb.continuous) AS
SELECT tenant_id, time_bucket(INTERVAL '1 hour', ts) AS bucket, kind, count(*) AS total
FROM events GROUP BY tenant_id, bucket, kind;
SELECT add_continuous_aggregate_policy('events_per_hour',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => TRUE);

-- Les tables findings, actions, audit_log, api_keys, collector_runs et suppressions sont
-- identiques à la version SQLite (types TEXT/REAL convertis en TEXT/DOUBLE PRECISION et
-- JSON en JSONB). Voir migrations/postgresql/001_init.sql pour le DDL complet.
"""


def ddl_for(backend: str) -> str:
    return POSTGRES_DDL if backend.startswith("postgres") else SQLITE_DDL


__all__ = ["POSTGRES_DDL", "SCHEMA_VERSION", "SQLITE_DDL", "ddl_for"]
