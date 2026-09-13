"""Assemblage du service : un seul endroit qui construit et relie tous les composants.

L'API, la CLI, la console et les tests utilisent tous ``build_service()``. Cela garantit qu'un
comportement observé en test est bien celui du service réel — et évite la dérive classique où
la CLI et le serveur finissent par diverger.

Le service expose aussi les tâches de fond :

* **maintenance** : rétention, expiration des approbations, rollbacks programmés ;
* **bus** : consommation des événements publiés (rejeu après redémarrage, multi-nœuds) ;
* **collecteurs** : planification périodique et écoute syslog.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .actions.engine import ActionEngine
from .actions.executor import PlaybookExecutor
from .actions.playbook_loader import PlaybookLoadError, load_playbooks_from_dir
from .actions.registry import ConnectorRegistry
from .observability.metrics import MetricsRegistry, register_catalog
from .observability.ratelimit import RateLimiter
from .audit.chain import AuditChain
from .bus.base import EventBus
from .bus import create_bus
from .collectors.registry import CollectorRegistry, default_registry
from .collectors.runner import CollectorRunner
from .core.config import Settings, get_settings
from .core.logging_setup import configure_logging, get_logger
from .core.models import RuleDiagnostic
from .core.util import iso_z, utcnow
from .decision.engine import DecisionEngine
from .decision.opa import OpaEvaluator
from .decision.policy_loader import load_policies_from_dir
from .detection.engine import DetectionEngine
from .detection.anomaly import build_detector
from .detection.rule_loader import load_rules_from_dir
from .pipeline import Pipeline
from .scope import TargetRegistry
from .storage import StoreProtocol, create_store
from .tenancy.auth import ApiKeyService

log = get_logger("service")

#: Intervalle de purge de rétention (la purge n'a pas besoin d'être fréquente).
PURGE_INTERVAL_SECONDS = 3600


@dataclass
class Service:
    """Conteneur de services applicatifs."""

    settings: Settings
    store: StoreProtocol
    audit: AuditChain
    targets: TargetRegistry
    connectors: ConnectorRegistry
    playbooks: dict[str, Any]
    policies: list[Any]
    rules: list[Any]
    detection: DetectionEngine
    decision: DecisionEngine
    actions: ActionEngine
    pipeline: Pipeline
    keys: ApiKeyService
    collectors: CollectorRunner
    collector_registry: CollectorRegistry
    bus: EventBus
    metrics: MetricsRegistry
    rate_limiter: RateLimiter
    opa: OpaEvaluator
    started_at: Any = field(default_factory=utcnow)
    rule_diagnostics: list[RuleDiagnostic] = field(default_factory=list)
    policy_diagnostics: list[RuleDiagnostic] = field(default_factory=list)
    playbook_diagnostics: list[RuleDiagnostic] = field(default_factory=list)
    _tasks: list[asyncio.Task[None]] = field(default_factory=list)
    _stop_event: asyncio.Event | None = None
    _last_purge: Any = None

    # ----------------------------------------------------------------------------------
    # Rechargements à chaud
    # ----------------------------------------------------------------------------------

    def reload_rules(self) -> tuple[int, list[RuleDiagnostic]]:
        rules, diagnostics = load_rules_from_dir(self.settings.rules_path)
        self.rules = rules
        self.rule_diagnostics = diagnostics
        self.detection.reload(rules)
        return len(rules), diagnostics

    def reload_policies(self) -> tuple[int, list[RuleDiagnostic]]:
        policies, diagnostics = load_policies_from_dir(
            self.settings.policies_path, known_playbooks=set(self.playbooks)
        )
        self.policies = policies
        self.policy_diagnostics = diagnostics
        self.decision.reload(policies)
        return len(policies), diagnostics

    def reload_playbooks(self) -> tuple[int, list[RuleDiagnostic]]:
        playbooks, diagnostics = load_playbooks_from_dir(self.settings.playbooks_path)
        self.playbooks = playbooks
        self.playbook_diagnostics = diagnostics
        self.actions.playbooks = playbooks
        # Les politiques référencent des playbooks : on les recharge pour détecter les
        # références devenues invalides.
        self.reload_policies()
        return len(playbooks), diagnostics

    def reload_connectors(self) -> ConnectorRegistry:
        self.connectors = ConnectorRegistry.from_file(
            self.settings.connectors_path, dry_run=self.settings.dry_run
        )
        self.actions.connectors = self.connectors
        self.actions.executor.connectors = self.connectors
        return self.connectors

    def reload_targets(self) -> TargetRegistry:
        self.targets = TargetRegistry.from_file(self.settings.targets_path)
        self.decision.registry = self.targets
        self.actions.registry = self.targets
        self.collectors.targets = self.targets
        return self.targets

    def reload_all(self) -> dict[str, Any]:
        rules, rule_diags = self.reload_rules()
        playbooks, playbook_diags = self.reload_playbooks()
        policies, policy_diags = self.reload_policies()
        self.reload_connectors()
        self.reload_targets()
        return {
            "rules": rules,
            "playbooks": playbooks,
            "policies": policies,
            "diagnostics": {
                "rules": [d.model_dump() for d in rule_diags],
                "playbooks": [d.model_dump() for d in playbook_diags],
                "policies": [d.model_dump() for d in policy_diags],
            },
        }

    # ----------------------------------------------------------------------------------
    # Cycle de vie
    # ----------------------------------------------------------------------------------

    async def start(self) -> None:
        self._stop_event = asyncio.Event()
        await self.bus.start()
        self.keys.bootstrap()
        self._record_startup_audit()

        self._tasks.append(asyncio.create_task(self.pipeline.run_worker(), name="thotsecure-pipeline"))
        self._tasks.append(
            asyncio.create_task(self._maintenance_loop(), name="thotsecure-maintenance")
        )
        if self.settings.collectors_enabled:
            self._tasks.append(
                asyncio.create_task(self._scheduler_loop(), name="thotsecure-collectors")
            )
        self._tasks.extend(await self.collectors.start_streamers(self._stop_event))
        log.info(
            "service démarré",
            extra={
                "rules": len(self.rules),
                "playbooks": len(self.playbooks),
                "policies": len(self.policies),
                "bus": self.bus.name,
                "dry_run": self.settings.dry_run,
                "autonomy": self.settings.autonomy,
            },
        )

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        await self.bus.stop()
        self.audit.record(
            tenant_id=self._primary_tenant(),
            actor="system",
            actor_role="system",
            action="system.stop",
            target={"type": "service", "id": self.settings.instance_name},
            after={"uptime_seconds": self.uptime_seconds},
        )
        log.info("service arrêté")

    def close(self) -> None:
        self.store.close()

    @property
    def uptime_seconds(self) -> float:
        return (utcnow() - self.started_at).total_seconds()

    # ----------------------------------------------------------------------------------
    # Tâches de fond
    # ----------------------------------------------------------------------------------

    async def _maintenance_loop(self) -> None:
        interval = max(10, self.settings.maintenance_interval_seconds)
        while True:
            try:
                await asyncio.sleep(interval)
                if self._stop_event is not None and self._stop_event.is_set():
                    return
                await asyncio.to_thread(self._maintenance_pass)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - boucle de fond : on journalise et continue
                log.error("erreur de maintenance", extra={"error": str(exc)})

    def _maintenance_pass(self) -> dict[str, Any]:
        """Une passe de maintenance : rollbacks programmés, expirations, rétention."""
        result: dict[str, Any] = {}
        try:
            result["actions"] = self.actions.reap()
        except Exception as exc:  # noqa: BLE001
            log.error("échec de l'expiration des actions", extra={"error": str(exc)})
        if self._last_purge is None or (utcnow() - self._last_purge) > timedelta(
            seconds=PURGE_INTERVAL_SECONDS
        ):
            try:
                result["purge"] = self.pipeline.purge_expired()
                self._last_purge = utcnow()
            except Exception as exc:  # noqa: BLE001
                log.error("échec de la purge de rétention", extra={"error": str(exc)})
        self.refresh_metrics()
        return result

    async def _scheduler_loop(self) -> None:
        assert self._stop_event is not None
        try:
            await self.collectors.scheduler(self._stop_event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("planificateur de collecte arrêté sur erreur", extra={"error": str(exc)})

    # ----------------------------------------------------------------------------------
    # Métriques
    # ----------------------------------------------------------------------------------

    def refresh_metrics(self) -> None:
        """Met à jour les jauges à partir de l'état réel (appelé à chaque scrape)."""
        metrics = self.metrics
        try:
            tenants = self.store.list_tenants()
        except Exception:  # noqa: BLE001 - le scrape ne doit jamais échouer
            return
        total_open = 0
        total_pending = 0
        total_findings = 0
        for tenant in tenants:
            findings = self.store.count_findings(tenant.tenant_id)
            total_open += findings["by_status"].get("open", 0)
            total_findings += sum(findings["by_status"].values())
            for severity, count in findings["by_severity"].items():
                metrics.set("thotsecure_findings_total", count, tenant=tenant.tenant_id, severity=severity)
            actions = self.store.actions_by_status(tenant.tenant_id)
            total_pending += actions.get("pending_approval", 0)
            for status, count in actions.items():
                metrics.set("thotsecure_actions_total", count, tenant=tenant.tenant_id, status=status)
            metrics.set("thotsecure_dry_run", 1 if (self.settings.dry_run or tenant.dry_run) else 0, tenant=tenant.tenant_id)

        metrics.set("thotsecure_findings_open", total_open)
        metrics.set("thotsecure_actions_pending_approval", total_pending)
        metrics.set("thotsecure_up", 1)
        metrics.set("thotsecure_start_time_seconds", self.started_at.timestamp())
        metrics.set("thotsecure_audit_records_total", self.store.count_audit(self._primary_tenant()))
        try:
            verdict = self.audit.verify()
            metrics.set("thotsecure_audit_chain_valid", 1 if verdict.valid else 0)
            if not verdict.valid:
                log.error("chaîne d'audit invalide détectée au scrape", extra={"broken_at": verdict.broken_at})
        except Exception:  # noqa: BLE001
            metrics.set("thotsecure_audit_chain_valid", 0)
        for key, value in self.bus.stats().items():
            if isinstance(value, (int, float)):
                metrics.set(f"thotsecure_bus_{key}", float(value))
        metrics.set("thotsecure_findings_total_all", total_findings)

    def record_pipeline_metrics(self) -> None:
        stats = self.pipeline.stats()
        detection = stats.get("detection", {})
        self.metrics.set("thotsecure_rule_eval_seconds_avg_ms", float(detection.get("avg_eval_ms", 0.0)))
        self.metrics.set("thotsecure_pipeline_processed_total", float(stats.get("processed_events", 0)))

    # ----------------------------------------------------------------------------------
    # Introspection
    # ----------------------------------------------------------------------------------

    def safety_report(self) -> dict[str, Any]:
        """Résumé de sûreté exposé par ``/version`` et la console."""
        return {
            "env": self.settings.env,
            "dry_run": self.settings.dry_run,
            "autonomy": self.settings.autonomy,
            "autonomy_global": self.settings.autonomy,
            "require_target_declaration": self.settings.require_target_declaration,
            "unsafe_defaults": self.settings.safety_warnings(),
            "connectors": {name: conn.driver for name, conn in (
                (name, self.connectors.get(name)) for name in sorted(self.connectors.configuration)
            )},
            "simulated_connectors_only": self.connectors.stats().get("simulated_only", True),
            "protected_scope_configured": bool(self.targets.tenants()),
        }

    def stats(self) -> dict[str, Any]:
        return {
            "uptime_seconds": round(self.uptime_seconds, 1),
            "tenants": len(self.store.list_tenants()),
            "rules": len(self.rules),
            "policies": len(self.policies),
            "playbooks": len(self.playbooks),
            "collectors": len(self.collector_registry),
            "bus": self.bus.stats(),
            "detection": self.detection.stats(),
            "decision": self.decision.stats(),
            "pipeline": self.pipeline.stats(),
            "api": {"rate_limiter": self.rate_limiter.stats()},
            "opa": self.opa.stats(),
            "started_at": iso_z(self.started_at),
        }

    def collections_summary(self) -> dict[str, Any]:
        return {
            "rule_diagnostics": [d.model_dump() for d in self.rule_diagnostics],
            "policy_diagnostics": [d.model_dump() for d in self.policy_diagnostics],
            "playbook_diagnostics": [d.model_dump() for d in self.playbook_diagnostics],
        }

    # ----------------------------------------------------------------------------------

    def _primary_tenant(self) -> str:
        """Tenant utilisé pour les événements système (le premier tenant connu)."""
        tenants = self.store.list_tenants()
        return tenants[0].tenant_id if tenants else "system"

    def _record_startup_audit(self) -> None:
        tenant_id = self._primary_tenant()
        self.audit.record(
            tenant_id=tenant_id,
            actor="system",
            actor_role="system",
            action="system.start",
            target={"type": "service", "id": self.settings.instance_name},
            after={
                "rules": len(self.rules),
                "playbooks": len(self.playbooks),
                "policies": len(self.policies),
                "bus": self.bus.name,
                "env": self.settings.env,
            },
        )
        warnings = self.settings.safety_warnings()
        if warnings:
            # Un réglage non sûr est un **événement d'audit**, pas seulement une ligne de log :
            # c'est ce qui permet de répondre à « depuis quand le dry-run est-il désactivé ? ».
            self.audit.record(
                tenant_id=tenant_id,
                actor="system",
                actor_role="system",
                action="system.unsafe_default",
                target={"type": "configuration", "id": "startup"},
                after={
                    "dry_run": self.settings.dry_run,
                    "autonomy": self.settings.autonomy,
                    "warnings": warnings,
                },
            )
            for warning in warnings:
                log.warning(warning)


def build_service(settings: Settings | None = None) -> Service:
    """Construit le service complet à partir de la configuration."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    settings.ensure_directories()

    # Le magasin est choisi par la fabrique, d'après `THOT_DB_URL` : SQLite par défaut,
    # PostgreSQL/TimescaleDB si l'URL le demande. Le schéma est appliqué par `create_store`
    # (idempotent) : il n'y a donc **aucun** endroit où un déploiement PostgreSQL pourrait se
    # retrouver silencieusement avec un magasin SQLite.
    store = create_store(settings)
    audit = AuditChain(store)
    targets = TargetRegistry.from_file(settings.targets_path)
    connectors = ConnectorRegistry.from_file(
        settings.connectors_path, dry_run=settings.dry_run, root_dir=settings.root_path
    )

    rules, rule_diagnostics = load_rules_from_dir(settings.rules_path)
    playbooks, playbook_diagnostics = load_playbooks_from_dir(settings.playbooks_path)
    policies, policy_diagnostics = load_policies_from_dir(
        settings.policies_path, known_playbooks=set(playbooks)
    )
    for diagnostic in [*rule_diagnostics, *playbook_diagnostics, *policy_diagnostics]:
        log.error("élément de configuration rejeté", extra={"path": diagnostic.path, "error": diagnostic.error})

    detection = DetectionEngine(rules)
    #: Détecteur d'anomalie statistique : construit uniquement s'il est activé. Il complète
    #: les règles déterministes (motifs connus) par la détection d'écarts de volume, de
    #: sources nouvelles et d'attaques distribuées — sans changer le chemin de traitement.
    anomaly = build_detector(settings)
    if anomaly is not None:
        log.info(
            "détection d'anomalie activée",
            extra={
                "bucket_seconds": anomaly.bucket_seconds,
                "warmup_samples": anomaly.warmup_samples,
                "zscore_threshold": anomaly.zscore_threshold,
                "entity_fields": anomaly.entity_fields,
            },
        )
    decision = DecisionEngine(store, policies, settings=settings, registry=targets)
    executor = PlaybookExecutor(connectors, dry_run=settings.dry_run)
    actions = ActionEngine(
        store,
        audit,
        playbooks,
        executor,
        settings=settings,
        registry=targets,
        connectors=connectors,
    )
    keys = ApiKeyService(store, settings, audit)
    bus = create_bus(settings, store)
    pipeline = Pipeline(
        store,
        audit,
        detection,
        decision,
        actions,
        settings=settings,
        bus=bus,
        anomaly=anomaly,
    )

    metrics = MetricsRegistry()
    register_catalog(metrics)
    rate_limiter = RateLimiter(per_minute=settings.rate_limit_per_min)
    collector_registry = default_registry()
    collectors = CollectorRunner(
        collector_registry, pipeline, store, audit, targets, settings=settings
    )
    opa = OpaEvaluator(settings.opa_bin, rego_dir=settings.policies_path / "rego")

    service = Service(
        settings=settings,
        store=store,
        audit=audit,
        targets=targets,
        connectors=connectors,
        playbooks=playbooks,
        policies=policies,
        rules=rules,
        detection=detection,
        decision=decision,
        actions=actions,
        pipeline=pipeline,
        keys=keys,
        collectors=collectors,
        collector_registry=collector_registry,
        bus=bus,
        metrics=metrics,
        rate_limiter=rate_limiter,
        opa=opa,
        rule_diagnostics=rule_diagnostics,
        policy_diagnostics=policy_diagnostics,
        playbook_diagnostics=playbook_diagnostics,
    )
    metrics.register_collector(lambda registry: service.refresh_metrics())
    return service


__all__ = ["PURGE_INTERVAL_SECONDS", "Service", "build_service"]
