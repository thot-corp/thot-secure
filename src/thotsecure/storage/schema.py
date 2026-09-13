"""Schéma de base de données — SQLite (défaut) et PostgreSQL/TimescaleDB (production).

Le DDL est centralisé ici pour qu'``init-db``, les tests et les migrations PostgreSQL
décrivent **la même** structure logique. Toute évolution doit être répercutée dans
``migrations/002_*.sql`` (SQLite) et dans ``migrations/postgresql/``.

Le DDL PostgreSQL est découpé en sections **appliquées séparément** par
``thotsecure.storage.postgres.PostgresStore`` (c'est ce qui permet de retomber proprement sur
un PostgreSQL nu quand TimescaleDB n'est pas installé) :

* ``POSTGRES_CORE_DDL`` — tables et index, identiques au schéma logique SQLite. **Obligatoire** ;
* ``POSTGRES_TIMESCALE_*_DDL`` — extension, hypertable, compression, rétention native, agrégats
  continus. **Optionnels**, chacun dans sa propre transaction : un échec sur l'un n'empêche pas
  les autres de s'appliquer, et n'entraîne jamais la perte du DDL principal.

``POSTGRES_DDL`` reste la concaténation complète (utile pour la relecture, la comparaison avec
``migrations/postgresql/`` ou une application manuelle par ``psql``).
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

#: Tables et index PostgreSQL — **obligatoires**. Mêmes colonnes que ``SQLITE_DDL`` (le mappage
#: ligne → modèle est partagé par les deux implémentations), avec les types natifs : ``JSONB``
#: pour les documents, ``TIMESTAMPTZ`` pour les horodatages, ``BOOLEAN`` pour les drapeaux,
#: ``DOUBLE PRECISION`` pour les scores (parité exacte avec le ``REAL`` de SQLite, qui est un
#: flottant 8 octets : un ``numeric(5,2)`` arrondirait et casserait les curseurs de pagination).
POSTGRES_CORE_DDL = """

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
    asset_criticality    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
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
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys (key_hash);

-- ---------------------------------------------------------------------------------
-- Événements bruts (immuables, purgés par rétention).
-- ---------------------------------------------------------------------------------
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
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts   ON events (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant_kind ON events (tenant_id, kind, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_pending     ON events (ts) WHERE processed = FALSE;
CREATE INDEX IF NOT EXISTS idx_events_claims      ON events (claimed_at) WHERE claimed_at IS NOT NULL;
-- JSONB : les règles interrogent ``labels->>'src_ip'`` sans index dédié dans le MVP. L'index
-- GIN ne dépend pas de TimescaleDB : il est créé même sur un PostgreSQL nu.
CREATE INDEX IF NOT EXISTS idx_events_labels_src_ip ON events USING gin (labels jsonb_path_ops);

-- Réservation atomique d'un lot d'événements à rejouer (``claim_pending_events``) : deux
-- processus ne peuvent pas réclamer la même ligne, et un bail expiré redevient réclamable.
-- Ces deux colonnes n'existent qu'en PostgreSQL : SQLite n'a qu'un écrivain, donc pas besoin
-- de bail. ``ADD COLUMN IF NOT EXISTS`` rend la mise à jour d'une base existante idempotente.
ALTER TABLE events ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

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
    risk_score   DOUBLE PRECISION NOT NULL DEFAULT 0
                 CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0.5
                 CHECK (confidence >= 0 AND confidence <= 1),
    status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','acked','closed','suppressed')),
    title        TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    remediation  TEXT NOT NULL DEFAULT '',
    tags         JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitre        JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence     JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1 CHECK (count > 0),
    event_ids    JSONB NOT NULL DEFAULT '[]'::jsonb,
    dedup_key    TEXT NOT NULL DEFAULT '',
    resolution   TEXT,
    comment      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status   ON findings (tenant_id, status, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_lastseen ON findings (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_dedup           ON findings (tenant_id, rule_id, dedup_key, status);

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
    dry_run         BOOLEAN NOT NULL DEFAULT TRUE,
    params          JSONB NOT NULL DEFAULT '{}'::jsonb,
    target          JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by    TEXT NOT NULL DEFAULT 'system',
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    rejected_by     TEXT,
    rejected_at     TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    result          JSONB,
    rollback        JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key TEXT NOT NULL UNIQUE,
    audit_seq       BIGINT,
    reason          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions (tenant_id, status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_time   ON actions (tenant_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_finding       ON actions (finding_id);
CREATE INDEX IF NOT EXISTS idx_actions_cooldown      ON actions (tenant_id, playbook, requested_at DESC);

-- ---------------------------------------------------------------------------------
-- Journal d'audit append-only, chaîné par hash.
--
-- ``seq`` provient d'une séquence dédiée : le chaînage exige de connaître ``seq`` **avant**
-- l'insertion, puisque l'empreinte porte sur ``seq``. Une colonne ``IDENTITY`` classique
-- obligerait à insérer puis à mettre à jour la ligne — inutile et incompatible avec un
-- durcissement « append-only » (trigger interdisant UPDATE). La séquence n'est jamais
-- réutilisée : un ``seq`` annulé laisse un trou, jamais un doublon.
-- ---------------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS audit_log_seq;
CREATE TABLE IF NOT EXISTS audit_log (
    seq        BIGINT NOT NULL DEFAULT nextval('audit_log_seq') PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    tenant_id  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    actor_role TEXT NOT NULL DEFAULT 'system',
    action     TEXT NOT NULL,
    target     JSONB NOT NULL DEFAULT '{}'::jsonb,
    before     JSONB NOT NULL DEFAULT '{}'::jsonb,
    after      JSONB NOT NULL DEFAULT '{}'::jsonb,
    context    JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
ALTER SEQUENCE audit_log_seq OWNED BY audit_log.seq;
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log (tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log (ts);

-- ---------------------------------------------------------------------------------
-- Exécutions de collecteurs (observabilité) et suppressions de bruit.
-- ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collector_runs (
    run_id       TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    collector    TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'running'
                 CHECK (status IN ('running','ok','partial','error')),
    events       INTEGER NOT NULL DEFAULT 0,
    findings     INTEGER NOT NULL DEFAULT 0,
    errors       INTEGER NOT NULL DEFAULT 0,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_collector_runs ON collector_runs (tenant_id, collector, started_at DESC);

CREATE TABLE IF NOT EXISTS suppressions (
    suppression_id  TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    dedup_key       TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_active ON suppressions (tenant_id, rule_id, expires_at);
"""

#: Extension TimescaleDB. Isolée : sans elle, tout le reste du DDL reste applicable et
#: l'adaptateur fonctionne sur un PostgreSQL nu (seule la rétention native est perdue).
POSTGRES_TIMESCALE_EXTENSION_DDL = """
CREATE EXTENSION IF NOT EXISTS timescaledb;
"""

#: Hypertable partitionnée par le temps : indispensable au-delà de quelques millions
#: d'événements, et prérequis aux politiques de rétention natives.
#:
#: Note : TimescaleDB exige que toute clé primaire ou contrainte d'unicité d'une hypertable
#: contienne la colonne de partitionnement. C'est la raison de la PK ``(tenant_id, event_id, ts)``
#: du DDL ci-dessus (et non ``event_id`` seul comme en SQLite).
POSTGRES_TIMESCALE_HYPERTABLE_DDL = """
SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day',
                         if_not_exists => TRUE);
"""

#: Compression des chunks de plus de 7 jours. Appliquée dans **sa propre transaction** : selon
#: la version de TimescaleDB et les contraintes d'unicité de l'hypertable, l'activation peut
#: être refusée (les colonnes d'une contrainte d'unicité doivent figurer dans
#: ``compress_segmentby``). Dans ce cas, l'adaptateur journalise l'avertissement, continue sans
#: compression et ne déclare pas la capacité ``compression`` : la perte est uniquement
#: l'espace disque, jamais la correction.
POSTGRES_TIMESCALE_COMPRESSION_DDL = """
ALTER TABLE events SET (timescaledb.compress,
                        timescaledb.compress_segmentby = 'tenant_id',
                        timescaledb.compress_orderby = 'ts DESC');
SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);
"""

#: Rétention native (30 jours, aligné sur ``THOT_RETENTION_DAYS``). Elle complète la purge
#: applicative ``purge()``, qui continue de fonctionner : la suppression des chunks anciens
#: (§8.3) est la seule opération possible sur une plage compressée.
POSTGRES_TIMESCALE_RETENTION_DDL = """
SELECT add_retention_policy('events', INTERVAL '30 days', if_not_exists => TRUE);
"""

#: Agrégat continu : volumétrie par type d'événement et par heure, pour le tableau de bord.
#: Défini **sur l'hypertable** uniquement (un agrégat continu sur une table ordinaire n'est pas
#: portable d'une version de TimescaleDB à l'autre). Voir ``data-model.md`` §8.3 : les agrégats
#: sur ``findings`` et ``actions`` restent une cible documentée, non installée.
POSTGRES_TIMESCALE_AGGREGATES_DDL = """
CREATE MATERIALIZED VIEW IF NOT EXISTS events_per_hour
WITH (timescaledb.continuous) AS
SELECT tenant_id, time_bucket(INTERVAL '1 hour', ts) AS bucket, kind, count(*) AS total
FROM events GROUP BY tenant_id, bucket, kind;
SELECT add_continuous_aggregate_policy('events_per_hour',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => TRUE);
"""

#: Sections optionnelles dans l'ordre d'application (les suivantes dépendent des précédentes).
POSTGRES_TIMESCALE_SECTIONS: tuple[tuple[str, str], ...] = (
    ("extension", POSTGRES_TIMESCALE_EXTENSION_DDL),
    ("hypertable", POSTGRES_TIMESCALE_HYPERTABLE_DDL),
    ("compression", POSTGRES_TIMESCALE_COMPRESSION_DDL),
    ("retention", POSTGRES_TIMESCALE_RETENTION_DDL),
    ("aggregates", POSTGRES_TIMESCALE_AGGREGATES_DDL),
)

#: DDL TimescaleDB complet (toutes sections concaténées).
POSTGRES_TIMESCALE_DDL = "".join(section for _, section in POSTGRES_TIMESCALE_SECTIONS)

#: DDL PostgreSQL **complet**, tel qu'un opérateur peut le passer à ``psql`` : schéma logique
#: puis hypertable, compression, rétention et agrégats continus.
POSTGRES_DDL = POSTGRES_CORE_DDL + POSTGRES_TIMESCALE_DDL


def ddl_for(backend: str) -> str:
    """DDL correspondant à un backend (``postgres*`` → PostgreSQL, sinon SQLite)."""
    return POSTGRES_DDL if backend.startswith("postgres") else SQLITE_DDL


__all__ = [
    "POSTGRES_CORE_DDL",
    "POSTGRES_DDL",
    "POSTGRES_TIMESCALE_AGGREGATES_DDL",
    "POSTGRES_TIMESCALE_COMPRESSION_DDL",
    "POSTGRES_TIMESCALE_DDL",
    "POSTGRES_TIMESCALE_EXTENSION_DDL",
    "POSTGRES_TIMESCALE_HYPERTABLE_DDL",
    "POSTGRES_TIMESCALE_RETENTION_DDL",
    "POSTGRES_TIMESCALE_SECTIONS",
    "SCHEMA_VERSION",
    "SQLITE_DDL",
    "ddl_for",
]

