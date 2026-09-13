"""Configuration d'Thot Secure — défauts **sûrs par construction**.

Deux valeurs par défaut protègent l'utilisateur contre lui-même :

* ``THOT_DRY_RUN=true``  → aucune contre-mesure n'a d'effet réel ;
* ``THOT_AUTONOMY=supervised`` → toute action non triviale exige une approbation humaine.

Les désactiver est possible, mais l'application émet un avertissement explicite au démarrage
et la console affiche un bandeau permanent.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigError

Autonomy = Literal["manual", "supervised", "auto"]
BusBackend = Literal["memory", "sqlite", "nats"]
LogFormat = Literal["json", "console"]

#: Clé d'amorçage documentée : **développement uniquement**. Elle est refusée en prod.
#:
#: Le format n'est pas décoratif : l'authentification découpe la clé en
#: ``thot_<identifiant>_<secret>`` (exactement trois segments séparés par ``_``, secret d'au
#: moins 16 caractères) pour retrouver l'enregistrement par identifiant. La valeur précédente,
#: ``ao_dev_local_change_me``, ne respectait pas ce format : elle était donc stockée à
#: l'amorçage puis **systématiquement refusée** en 401 « format de clé API invalide ». Le
#: premier parcours documenté (créer un tenant, appeler l'API) ne fonctionnait pas.
DEV_BOOTSTRAP_KEY = "thot_BOOTSTRAP_changemebeforefirstuse"

DEFAULT_TENANT_SETTINGS: dict[str, Any] = {
    "mode": "supervised",
    "dry_run": True,
    "autonomy_allowlist": [],
    "max_actions_per_hour": 20,
    "cooldown_seconds": 300,
}


class Settings(BaseSettings):
    """Configuration globale, surchargeable par variables d'environnement ``THOT_*``."""

    model_config = SettingsConfigDict(
        env_prefix="THOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Identité / environnement -------------------------------------------------------
    env: Literal["dev", "staging", "prod"] = "dev"
    instance_name: str = "thotsecure"
    base_url: str = "http://127.0.0.1:8080"

    # -- Écoute ------------------------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 1

    # -- Secrets -----------------------------------------------------------------------
    #: Clé de signature (poivre des clés API, signature des sessions).
    #:
    #: Résolution en trois temps — voir ``_resolve_secret_key`` :
    #:   1. ``THOT_SECRET_KEY`` si définie (recommandé : Vault, SOPS, systemd
    #:      ``EnvironmentFile``) ;
    #:   2. sinon une clé **persistée** dans ``<data_dir>/secret.key`` (permissions 0600),
    #:      créée au premier démarrage : la CLI, le serveur et le service systemd partagent
    #:      alors la même clé, ce qui est indispensable pour que les clés API créées en CLI
    #:      fonctionnent côté serveur ;
    #:   3. en dernier recours une clé éphémère (système de fichiers en lecture seule), avec un
    #:      avertissement explicite : les clés API et les sessions ne survivront pas au
    #:      redémarrage.
    secret_key: str = ""
    #: Origine de la clé de signature : ``env`` | ``file`` | ``ephemeral`` (calculée).
    secret_key_source: Literal["env", "file", "ephemeral"] = "ephemeral"  # noqa: S105 - origine
    bootstrap_api_key: str = DEV_BOOTSTRAP_KEY
    session_ttl_seconds: int = 8 * 3600

    # -- Persistance -------------------------------------------------------------------
    #: Racine du projet : les chemins relatifs (règles, politiques, base) sont résolus
    #: depuis ce répertoire et **jamais** depuis le répertoire courant du processus. Un
    #: service systemd démarre avec un CWD arbitraire : s'y fier produirait une base vide
    #: et un jeu de règles absent, sans erreur visible.
    root_dir: str = "."
    db_url: str = "sqlite:///./data/thotsecure.db"
    #: `sslmode` explicite du DSN PostgreSQL. Vide = choix automatique par environnement
    #: (`prefer` en dev/staging, `require` en prod) : jamais `disable` par défaut, car une
    #: base qui reçoit des journaux d'audit ne doit pas circuler en clair. `verify-full` est
    #: la seule valeur qui vérifie aussi le nom d'hôte du certificat serveur.
    db_sslmode: str = ""
    #: Taille maximale du pool de connexions PostgreSQL. Un pool trop grand ne rend pas le
    #: service plus rapide : il sature le serveur de base, qui est le goulot réel.
    db_pool_max_size: int = 8

    # -- Contenus (règles, politiques, playbooks, cibles, connecteurs) ------------------
    rules_dir: str = "./rules"
    policies_dir: str = "./policies"
    playbooks_dir: str = "./playbooks"
    targets_file: str = "./config/targets.yaml"
    connectors_file: str = "./config/connectors.yaml"
    data_dir: str = "./data"

    # -- Bus d'événements --------------------------------------------------------------
    bus: BusBackend = "memory"
    nats_url: str = "nats://127.0.0.1:4222"
    bus_queue_size: int = 5000
    bus_subject_prefix: str = "thotsecure.events"

    # -- Sûreté ------------------------------------------------------------------------
    autonomy: Autonomy = "supervised"
    dry_run: bool = True
    require_target_declaration: bool = True
    max_actions_per_hour: int = 20
    default_cooldown_seconds: int = 300
    approve_ttl_seconds: int = 3600
    #: Un finding dont le score atteint ce seuil ne part **jamais** en automatique
    #: sans politique explicite : garde-fou anti-catastrophe.
    critical_score_threshold: float = 85.0

    # -- Détection d'anomalie (statistique) --------------------------------------------
    #: Désactivée par défaut, volontairement : un détecteur statistique mal réglé produit du
    #: bruit, et du bruit en sécurité coûte plus cher que pas de détection. La procédure
    #: recommandée est de l'activer en observation, de relever ses signaux pendant quelques
    #: jours, puis d'ajuster les seuils avant de la laisser créer des findings.
    anomaly_enabled: bool = False
    #: Durée d'un intervalle d'observation (une « case » de la moyenne mobile).
    anomaly_bucket_seconds: int = 60
    #: Nombre d'intervalles observés avant d'émettre quoi que ce soit : sans période de
    #: chauffe, la première minute d'un déploiement serait entièrement « anormale ».
    anomaly_warmup_samples: int = 30
    #: Seuil de déclenchement, en écarts-types.
    anomaly_zscore_threshold: float = 4.0
    #: Volume minimal dans l'intervalle, pour ne pas signaler un écart statistiquement
    #: significatif mais opérationnellement insignifiant (3 événements au lieu de 1).
    anomaly_min_observed: int = 20
    #: Champs servant d'identité de suivi, par ordre de priorité.
    anomaly_entity_fields: list[str] = Field(default_factory=lambda: ["labels.src_ip"])
    #: Borne mémoire : au-delà, les entités les plus anciennes sont évincées.
    anomaly_max_entities: int = 20_000
    #: Durée de conservation d'une entité silencieuse (0 = illimité).
    anomaly_entity_ttl_seconds: int = 86_400
    #: Signaler la première apparition d'une entité (source, hôte, compte).
    anomaly_detect_new_sources: bool = True

    # -- Collecteurs -------------------------------------------------------------------
    collectors_enabled: bool = False
    collector_interval_seconds: int = 300
    http_probe_timeout_seconds: float = 8.0
    http_probe_max_targets: int = 200
    #: Délai minimal entre deux requêtes d'un audit de surface. On n'inonde pas un site en
    #: production avec nos propres vérifications : un outil défensif ne devient pas un
    #: générateur de charge.
    http_probe_delay_seconds: float = 0.2
    #: Écoute syslog UDP embarquée. Désactivée par défaut : on n'ouvre pas un port sans une
    #: décision explicite de l'exploitant.
    syslog_enabled: bool = False
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    #: Intervalle de la tâche de maintenance (rétention, expiration des approbations,
    #: rollbacks programmés).
    maintenance_interval_seconds: int = 60

    # -- API ---------------------------------------------------------------------------
    rate_limit_per_min: int = 600
    max_ingest_batch: int = 500
    max_body_bytes: int = 2 * 1024 * 1024
    cors_origins: list[str] = Field(default_factory=list)

    # -- Observabilité -----------------------------------------------------------------
    log_level: str = "INFO"
    log_format: LogFormat = "json"
    otel_endpoint: str | None = None

    # -- Rétention ---------------------------------------------------------------------
    retention_days: int = 30
    audit_retention_days: int = 365

    # -- Extensions --------------------------------------------------------------------
    opa_bin: str | None = None
    tls_enabled: bool = False
    tls_cert_file: str | None = None
    tls_key_file: str | None = None

    # -- Divers ------------------------------------------------------------------------
    demo_tenant: str = "demo"

    # ----------------------------------------------------------------------------------
    # Validation
    # ----------------------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"niveau de log invalide: {value}")
        return level

    @field_validator("port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("port hors bornes (1-65535)")
        return value

    @field_validator("db_url")
    @classmethod
    def _validate_db_url(cls, value: str) -> str:
        """Refuse ici ce que l'adaptateur refuserait plus tard, avec un message clair.

        La liste est alignée sur `thotsecure.storage` : SQLite, puis PostgreSQL avec les
        suffixes de pilote synchrones `+psycopg` / `+psycopg2`. Les pilotes **asynchrones**
        (`+asyncpg`) sont refusés explicitement : l'adaptateur est synchrone, et un DSN
        accepté ici pour échouer au premier accès à la base serait un piège.
        """
        scheme, _, rest = value.partition("://")
        if scheme == "sqlite":
            return value
        base, _, driver = scheme.partition("+")
        if base in {"postgresql", "postgres"}:
            if driver in {"", "psycopg", "psycopg2"}:
                return value
            raise ValueError(
                f"THOT_DB_URL : pilote PostgreSQL '{driver}' non supporté (adaptateur "
                "synchrone) ; utilisez 'postgresql://', 'postgresql+psycopg://' ou "
                "'postgresql+psycopg2://'"
            )
        raise ValueError(
            "THOT_DB_URL doit commencer par 'sqlite://' (défaut, aucune dépendance) ou "
            "'postgresql://' (backend PostgreSQL/TimescaleDB, extra 'postgres')"
            + (f" — reçu : '{rest[:24]}'" if rest else "")
        )

    @field_validator("bootstrap_api_key")
    @classmethod
    def _validate_bootstrap_key(cls, value: str) -> str:
        """Refuse ici une clé d'amorçage qui ne pourrait pas s'authentifier.

        L'authentification découpe la clé présentée en ``thot_<identifiant>_<secret>`` pour
        retrouver l'enregistrement : exactement trois segments, et un secret d'au moins 16
        caractères. Une clé d'amorçage d'un autre format est stockée à l'initialisation puis
        refusée en 401 à chaque appel — l'exploitant voit un « format de clé API invalide »
        alors que la valeur vient de sa propre configuration.

        Mieux vaut un refus au démarrage, avec le format attendu, qu'un 401 inexplicable au
        premier appel.
        """
        parts = (value or "").split("_")
        if len(parts) != 3 or parts[0] != "thot":
            raise ConfigError(
                "THOT_BOOTSTRAP_API_KEY doit être au format 'thot_<identifiant>_<secret>' "
                "(exactement deux caractères de soulignement), p. ex. "
                "'thot_BOOTSTRAP_unSecretDeSeizeCaracteres'"
            )
        if len(parts[2]) < 16:
            raise ConfigError(
                "THOT_BOOTSTRAP_API_KEY : le secret doit faire au moins 16 caractères "
                "(contrainte du format de clé API)"
            )
        return value

    @field_validator("db_sslmode")
    @classmethod
    def _validate_db_sslmode(cls, value: str) -> str:
        allowed = {"", "disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
        if value not in allowed:
            raise ValueError(
                "THOT_DB_SSLMODE doit être vide (choix automatique) ou l'une de : "
                "disable, allow, prefer, require, verify-ca, verify-full"
            )
        return value

    @field_validator("db_pool_max_size")
    @classmethod
    def _validate_db_pool(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("THOT_DB_POOL_MAX_SIZE doit être strictement positif")
        return value

    @field_validator("nats_url")
    @classmethod
    def _validate_nats_url(cls, value: str) -> str:
        if value and not value.startswith(("nats://", "tls://")):
            raise ValueError("THOT_NATS_URL doit commencer par 'nats://' ou 'tls://'")
        return value

    @field_validator("rate_limit_per_min", "max_ingest_batch", "retention_days")
    @classmethod
    def _validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("la valeur doit être strictement positive")
        return value

    @model_validator(mode="after")
    def _validate_coherence(self) -> Settings:
        if self.env == "prod":
            if self.bootstrap_api_key == DEV_BOOTSTRAP_KEY:
                raise ConfigError(
                    "En production, THOT_BOOTSTRAP_API_KEY doit être remplacée : "
                    "la clé de développement est publique et donc compromise."
                )
            if self.tls_enabled and not (self.tls_cert_file and self.tls_key_file):
                raise ConfigError(
                    "THOT_TLS_ENABLED=true exige THOT_TLS_CERT_FILE et THOT_TLS_KEY_FILE."
                )
        if self.bus == "nats" and not self.nats_url:
            raise ConfigError("THOT_BUS=nats exige THOT_NATS_URL.")
        if self.critical_score_threshold <= 0 or self.critical_score_threshold > 100:
            raise ConfigError("THOT_CRITICAL_SCORE_THRESHOLD doit être dans ]0, 100].")
        # La clé de signature est résolue ici pour que toute instance de configuration (CLI,
        # serveur, tests) partage la même clé que les autres processus du même déploiement.
        self._resolve_secret_key()
        return self

    # ----------------------------------------------------------------------------------
    # Chemins
    # ----------------------------------------------------------------------------------

    @property
    def root_path(self) -> Path:
        return Path(self.root_dir).expanduser().resolve()

    def resolve_path(self, value: str | os.PathLike[str]) -> Path:
        """Résout un chemin relatif depuis ``root_dir`` (absolu : inchangé)."""
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.root_path / candidate
        return candidate.resolve()

    @property
    def db_path(self) -> Path:
        """Chemin du fichier SQLite.

        N'a de sens **que** si `THOT_DB_URL` désigne SQLite : sur PostgreSQL, cette propriété
        lève une `ConfigError`, volontairement, pour qu'aucun code n'utilise un chemin de
        fichier là où il n'y a pas de fichier. Pour décrire l'emplacement réel du magasin
        (SQLite ou PostgreSQL), utilisez
        [`store_location()`][thotsecure.storage.store_location].

        Convention SQLAlchemy respectée : ``sqlite:///relatif.db`` est relatif à la racine
        du projet, ``sqlite:////absolu/chemin.db`` est absolu.
        """
        if not self.db_url.startswith("sqlite://"):
            raise ConfigError(
                "THOT_DB_URL n'est pas SQLite : utilisez store_location(store) pour décrire "
                "l'emplacement réel du magasin."
            )
        raw = self.db_url[len("sqlite://") :]
        if raw.startswith("//"):  # sqlite:////chemin/absolu
            return Path(raw[1:]).expanduser().resolve()
        candidate = Path(raw.lstrip("/"))
        if candidate.is_absolute():  # sqlite:///C:/data/thotsecure.db (Windows)
            return candidate.expanduser().resolve()
        return (self.root_path / candidate).resolve()

    @property
    def rules_path(self) -> Path:
        return self.resolve_path(self.rules_dir)

    @property
    def policies_path(self) -> Path:
        return self.resolve_path(self.policies_dir)

    @property
    def playbooks_path(self) -> Path:
        return self.resolve_path(self.playbooks_dir)

    @property
    def targets_path(self) -> Path:
        return self.resolve_path(self.targets_file)

    @property
    def connectors_path(self) -> Path:
        return self.resolve_path(self.connectors_file)

    @property
    def data_path(self) -> Path:
        return self.resolve_path(self.data_dir)

    @property
    def quarantine_path(self) -> Path:
        return self.data_path / "quarantine"

    def ensure_directories(self) -> None:
        """Crée les répertoires nécessaires (base SQLite, quarantaine, données).

        Le répertoire de la base n'est créé **que** si `THOT_DB_URL` désigne SQLite : sur
        PostgreSQL la base est distante, et `db_path` lève volontairement une erreur. Sans ce
        test, un déploiement PostgreSQL échouerait au démarrage sur la création d'un
        répertoire sans rapport avec lui.
        """
        if self.db_url.startswith("sqlite://"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.data_path.mkdir(parents=True, exist_ok=True)
        self.quarantine_path.mkdir(parents=True, exist_ok=True)

    # ----------------------------------------------------------------------------------
    # Sûreté
    # ----------------------------------------------------------------------------------

    @property
    def secret_key_file(self) -> Path:
        """Emplacement de la clé de signature persistée (permissions 0600)."""
        return self.data_path / "secret.key"

    def _resolve_secret_key(self) -> None:
        """Détermine la clé de signature : variable d'environnement, fichier, ou éphémère.

        Pourquoi persister une clé générée : sans cela, **chaque processus génère la sienne**
        et les clés API créées par la CLI ne sont plus vérifiables par le serveur (le poivre
        diffère). Ce n'est pas une gêne théorique : c'est le premier obstacle rencontré par un
        utilisateur qui suit le démarrage rapide.
        """
        if self.secret_key:
            self.secret_key_source = "env"  # noqa: S105 - origine de la clé, pas un secret
            return

        path = self.secret_key_file
        try:
            if path.exists():
                stored = path.read_text(encoding="utf-8").strip()
                if stored:
                    self.secret_key = stored
                    self.secret_key_source = "file"  # noqa: S105 - origine de la clé, pas un secret
                    return
            path.parent.mkdir(parents=True, exist_ok=True)
            generated = secrets.token_urlsafe(48)
            path.write_text(generated, encoding="utf-8")
            with contextlib.suppress(OSError):
                # Permissions restrictives : la clé de signature ne doit pas être lisible par
                # les autres utilisateurs de la machine (sans effet sur les systèmes non POSIX).
                path.chmod(0o600)
            self.secret_key = generated
            self.secret_key_source = "file"  # noqa: S105 - origine de la clé, pas un secret
        except OSError:
            # Système de fichiers en lecture seule (conteneur durci) : on continue avec une clé
            # éphémère, mais l'avertissement de sûreté le signalera explicitement.
            self.secret_key = secrets.token_urlsafe(48)
            self.secret_key_source = "ephemeral"  # noqa: S105 - origine de la clé, pas un secret

    @property
    def secret_key_is_ephemeral(self) -> bool:
        """Vrai si la clé de signature a été générée au vol : les clés API et les sessions ne
        survivront pas au redémarrage, et ne sont pas partagées entre processus."""
        return self.secret_key_source == "ephemeral"  # noqa: S105 - origine, pas un secret

    @property
    def bootstrap_key_is_dev(self) -> bool:
        return self.bootstrap_api_key == DEV_BOOTSTRAP_KEY

    def safety_warnings(self) -> list[str]:
        """Avertissements affichés au démarrage et par ``thotsecure doctor``."""
        warnings: list[str] = []
        if not self.dry_run:
            warnings.append(
                "THOT_DRY_RUN=false : les contre-mesures ont un EFFET RÉEL. "
                "Vérifiez vos playbooks, vos cibles déclarées et votre capacité de rollback."
            )
        if self.autonomy == "auto":
            warnings.append(
                "THOT_AUTONOMY=auto : des actions peuvent être exécutées sans approbation "
                "humaine. Chaque action reste réversible et auditée."
            )
        if self.secret_key_is_ephemeral:
            warnings.append(
                "THOT_SECRET_KEY n'est pas définie et aucune clé n'a pu être persistée "
                f"({self.secret_key_file}) : une clé éphémère a été générée. Les clés API et les "
                "sessions ne seront pas partagées entre processus et seront invalidées au "
                "redémarrage. Définissez THOT_SECRET_KEY."
            )
        elif self.secret_key_source == "file":  # noqa: S105 - origine de la clé, pas un secret
            warnings.append(
                f"Clé de signature persistée dans {self.secret_key_file} (permissions 0600). "
                "Pour un déploiement multi-nœuds ou un conteneur sans volume persistant, "
                "définissez THOT_SECRET_KEY explicitement."
            )
        if self.bootstrap_key_is_dev:
            warnings.append(
                "THOT_BOOTSTRAP_API_KEY utilise la valeur de développement publique. "
                "Créez une clé dédiée puis supprimez celle-ci."
            )
        if self.secret_key_is_ephemeral and self.env != "dev":
            warnings.append(
                "En environnement non-dev, définir THOT_SECRET_KEY est obligatoire "
                "pour la stabilité de l'authentification."
            )
        if self.bus == "memory":
            warnings.append(
                "THOT_BUS=memory : les événements en cours de traitement sont perdus "
                "au redémarrage. Utilisez 'sqlite' ou 'nats' en production."
            )
        if not self.require_target_declaration:
            warnings.append(
                "THOT_REQUIRE_TARGET_DECLARATION=false : les actions ne sont plus "
                "limitées à votre périmètre déclaré. Fortement déconseillé."
            )
        return warnings

    def public_summary(self) -> dict[str, Any]:
        """Résumé exposable (jamais de secret) : utilisé par ``/version`` et ``/readyz``."""
        return {
            "env": self.env,
            "instance": self.instance_name,
            "autonomy": self.autonomy,
            "dry_run": self.dry_run,
            "bus": self.bus,
            "collectors_enabled": self.collectors_enabled,
            "retention_days": self.retention_days,
            "tls_enabled": self.tls_enabled,
            "require_target_declaration": self.require_target_declaration,
            "unsafe_defaults": self.safety_warnings(),
        }


@dataclass(slots=True)
class SettingsOverrides:
    """Surcharges explicites utilisées par les tests et la CLI (jamais de fuite d'état)."""

    values: dict[str, Any] = field(default_factory=dict)


_settings_cache: Settings | None = None


def get_settings(*, refresh: bool = False, **overrides: Any) -> Settings:
    """Retourne la configuration (mise en cache) ; ``overrides`` court-circuite le cache."""
    global _settings_cache
    if overrides:
        base = get_settings().model_dump()
        base.update(overrides)
        return Settings(**base)
    if _settings_cache is None or refresh:
        _settings_cache = Settings()
    return _settings_cache


def set_settings(settings: Settings | None) -> None:
    """Force la configuration courante (tests, CLI, serveur embarquant une config explicite)."""
    global _settings_cache
    _settings_cache = settings


__all__ = [
    "DEFAULT_TENANT_SETTINGS",
    "DEV_BOOTSTRAP_KEY",
    "Autonomy",
    "BusBackend",
    "Settings",
    "SettingsOverrides",
    "get_settings",
    "set_settings",
]
