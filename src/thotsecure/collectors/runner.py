"""Exécution et planification des collecteurs.

Le *runner* est le seul composant qui relie un collecteur au reste du produit : il construit le
contexte (périmètre déclaré, tenant, réglages), exécute la collecte, **persiste les événements
via le pipeline** (donc détection, scoring, décision et action comprises), enregistre la trace
d'exécution et l'audit.

Conséquence importante : un collecteur ne peut pas contourner le moteur de décision. Il n'y a
pas de chemin « collecte → action » direct.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from ..audit.chain import AuditChain
from ..core.config import Settings
from ..core.errors import NotFoundError
from ..core.logging_setup import bind_context, get_logger
from ..core.models import CollectorStatus, Event
from ..core.util import iso_z, new_id, parse_dt, utcnow
from ..pipeline import Pipeline
from ..scope import TargetRegistry
from ..storage import StoreProtocol
from .base import CollectorContext, CollectorResult
from .registry import CollectorRegistry

log = get_logger("collectors.runner")

#: Nombre maximal de cycles de collecte en parallèle (bornage de charge).
MAX_CONCURRENT_COLLECTORS = 4


class CollectorRunner:
    """Exécute les collecteurs et alimente le pipeline."""

    def __init__(
        self,
        registry: CollectorRegistry,
        pipeline: Pipeline,
        store: StoreProtocol,
        audit: AuditChain,
        targets: TargetRegistry,
        *,
        settings: Settings,
    ) -> None:
        self.registry = registry
        self.pipeline = pipeline
        self.store = store
        self.audit = audit
        self.targets = targets
        self.settings = settings
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_COLLECTORS)

    # ----------------------------------------------------------------------------------
    # Exécution synchrone (CLI, API)
    # ----------------------------------------------------------------------------------

    def run(
        self,
        collector_name: str,
        tenant_id: str,
        *,
        actor: str = "system:scheduler",
        actor_role: str = "system",
    ) -> CollectorResult:
        """Exécute un collecteur pour un tenant et ingère les événements produits."""
        collector = self.registry.require(collector_name)
        tenant = self.store.get_tenant(tenant_id)
        if tenant is None:
            raise NotFoundError(f"tenant inconnu: {tenant_id}", details={"tenant_id": tenant_id})

        scope = self.targets.for_tenant(tenant_id)
        allowed, reason = collector.enabled(self.settings, scope)
        if not allowed:
            result = CollectorResult(
                collector=collector.name, status="skipped", detail={"reason": reason}
            )
            self._record_run(tenant_id, collector.name, result)
            return result

        run_id = new_id("run_")
        produced: list[Event] = []

        def emit(**kwargs: Any) -> Event:
            event = context.make_event(**kwargs)
            produced.append(event)
            return event

        context = CollectorContext(
            tenant=tenant,
            scope=scope,
            settings=self.settings,
            run_id=run_id,
            emit=emit,
        )

        bind_context(tenant_id=tenant_id, collector=collector.name, run_id=run_id)
        log.info("collecte démarrée", extra={"collector": collector.name, "tenant_id": tenant_id})
        try:
            result = collector.collect(context)
        except Exception as exc:
            result = CollectorResult(collector=collector.name, status="error")
            result.add_error(f"{type(exc).__name__}: {exc}")
            log.error(
                "collecte en échec",
                extra={"collector": collector.name, "tenant_id": tenant_id, "error": str(exc)},
                exc_info=True,
            )

        # Les collecteurs émettent via ``context.emit`` : on fusionne les deux sources en
        # dédupliquant par identifiant d'événement.
        events = _merge_events(result.events, produced)
        result.events = events
        result.finished_at = result.finished_at or utcnow()

        findings = 0
        if events:
            outcome = self.pipeline.ingest(
                events, actor=f"collector:{collector.name}", actor_role="system"
            )
            findings = len(outcome.findings)
            result.detail["findings"] = findings
            result.detail["accepted"] = outcome.result.accepted
            if outcome.result.rejected:
                result.detail["rejected"] = outcome.result.rejected

        self._record_run(tenant_id, collector.name, result, findings=findings)
        if result.errors:
            for error in result.errors[:5]:
                log.warning(
                    "erreur de collecte",
                    extra={"collector": collector.name, "tenant_id": tenant_id, "error": error},
                )
        return result

    def run_all(
        self, tenant_id: str, *, actor: str = "system:scheduler"
    ) -> dict[str, CollectorResult]:
        """Exécute tous les collecteurs activés pour un tenant."""
        results: dict[str, CollectorResult] = {}
        for collector in self.registry.all():
            if collector.default_interval_seconds <= 0:
                # Collecteurs en mode écoute : pas de passe périodique.
                continue
            results[collector.name] = self.run(collector.name, tenant_id, actor=actor)
        return results

    # ----------------------------------------------------------------------------------
    # Planification
    # ----------------------------------------------------------------------------------

    async def scheduler(
        self,
        stop_event: asyncio.Event,
        *,
        tenants: list[str] | None = None,
    ) -> None:
        """Boucle de planification : exécute chaque collecteur à son intervalle.

        Les collecteurs sont décalés dans le temps (au lieu de partir tous ensemble) pour
        éviter un pic de charge périodique sur l'infrastructure surveillée.
        """
        tenant_ids = tenants or [tenant.tenant_id for tenant in self.store.list_tenants()]
        if not tenant_ids:
            log.warning("planificateur démarré sans aucun tenant")
            return

        offsets: dict[tuple[str, str], float] = {}
        intervals: dict[tuple[str, str], int] = {}
        for tenant_id in tenant_ids:
            for collector in self.registry.all():
                if collector.default_interval_seconds <= 0:
                    continue
                key = (tenant_id, collector.name)
                intervals[key] = collector.default_interval_seconds
                # Décalage initial réparti sur l'intervalle (0 à 90 s).
                offsets[key] = 90.0 * (len(offsets) % 10) / 10.0

        log.info(
            "planificateur démarré",
            extra={"tenants": len(tenant_ids), "collectors": len(self.registry)},
        )
        while not stop_event.is_set():
            now = utcnow().timestamp()
            for key, interval in intervals.items():
                tenant_id, collector_name = key
                due = offsets[key] + interval
                if now < due:
                    continue
                offsets[key] = now
                if self._semaphore.locked():
                    log.debug("collecte reportée : limite de parallélisme atteinte")
                    continue
                asyncio.create_task(  # noqa: RUF006 - tâche volontairement détachée
                    self._run_scheduled(tenant_id, collector_name)
                )
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=5.0)
        log.info("planificateur arrêté")

    async def _run_scheduled(self, tenant_id: str, collector_name: str) -> None:
        async with self._semaphore:
            try:
                # L'exécution est synchrone (urllib, fichiers) : on la sort de la boucle
                # d'événements pour ne pas bloquer le service HTTP.
                await asyncio.to_thread(
                    self.run, collector_name, tenant_id, actor="system:scheduler"
                )
            except Exception as exc:
                log.error(
                    "collecte planifiée en échec",
                    extra={"tenant_id": tenant_id, "collector": collector_name, "error": str(exc)},
                )

    async def start_streamers(
        self, stop_event: asyncio.Event, *, tenants: list[str] | None = None
    ) -> list[asyncio.Task[None]]:
        """Démarre les collecteurs en mode écoute (syslog) si activés."""
        tasks: list[asyncio.Task[None]] = []
        tenant_ids = tenants or [tenant.tenant_id for tenant in self.store.list_tenants()]
        for collector in self.registry.all():
            serve = getattr(collector, "serve", None)
            if serve is None or not tenant_ids:
                continue
            tenant = self.store.get_tenant(tenant_ids[0])
            if tenant is None:
                continue
            allowed, reason = collector.enabled(
                self.settings, self.targets.for_tenant(tenant.tenant_id)
            )
            if not allowed:
                log.info(
                    "collecteur en écoute non démarré",
                    extra={"collector": collector.name, "reason": reason},
                )
                continue
            context = CollectorContext(
                tenant=tenant,
                scope=self.targets.for_tenant(tenant.tenant_id),
                settings=self.settings,
                run_id=new_id("run_"),
                emit=lambda **kwargs: self._emit_streamed(collector.name, tenant.tenant_id, kwargs),
            )
            tasks.append(
                asyncio.create_task(
                    serve(context, stop_event), name=f"thotsecure-collector-{collector.name}"
                )
            )
        return tasks

    def _emit_streamed(self, collector_name: str, tenant_id: str, kwargs: dict[str, Any]) -> Event:
        """Émission temps réel d'un collecteur en écoute (syslog) : traitement immédiat."""
        tenant = self.store.get_tenant(tenant_id)
        if tenant is None:
            raise NotFoundError(f"tenant inconnu: {tenant_id}")
        context = CollectorContext(
            tenant=tenant,
            scope=self.targets.for_tenant(tenant_id),
            settings=self.settings,
            run_id="stream",
            emit=lambda **_: None,
        )
        event = context.make_event(**kwargs)
        self.pipeline.ingest([event], actor=f"collector:{collector_name}", actor_role="system")
        return event

    # ----------------------------------------------------------------------------------
    # État
    # ----------------------------------------------------------------------------------

    def status(self, tenant_id: str) -> list[CollectorStatus]:
        """État des collecteurs : description statique + statistiques d'exécution réelles."""
        stats = self.store.collector_stats(tenant_id)
        scope = self.targets.for_tenant(tenant_id)
        statuses: list[CollectorStatus] = []
        for collector in self.registry.all():
            observed = stats.get(collector.name, {})
            allowed, reason = collector.enabled(self.settings, scope)
            targets: list[str] = []
            if collector.name == "web_probe" or collector.name == "tls_cert":
                targets = [url for asset in scope.assets for url in asset.urls]
            elif collector.name == "log_tail":
                targets = [source.path for source in scope.log_sources]
            elif collector.name == "dependency_scan":
                targets = list(scope.manifests)
            elif collector.name == "config_audit":
                targets = [item.path for item in scope.config_files]

            statuses.append(
                CollectorStatus(
                    name=collector.name,
                    source_type=collector.source_type,
                    description=collector.description,
                    enabled=allowed,
                    interval_seconds=collector.default_interval_seconds,
                    last_run=parse_dt(observed.get("last_run")),
                    last_status=_normalize_status(observed.get("last_status")),
                    last_error=reason if not allowed else None,
                    events_emitted=int(observed.get("events", 0) or 0),
                    findings_emitted=int(observed.get("findings", 0) or 0),
                    runs=int(observed.get("runs", 0) or 0),
                    targets=targets,
                )
            )
        return statuses

    def stats(self) -> dict[str, Any]:
        return {
            "collectors": len(self.registry),
            "names": self.registry.names(),
            "streamers": [
                collector.name for collector in self.registry.all() if hasattr(collector, "serve")
            ],
        }

    # ----------------------------------------------------------------------------------

    def _record_run(
        self,
        tenant_id: str,
        collector_name: str,
        result: CollectorResult,
        *,
        findings: int = 0,
    ) -> None:
        try:
            self.store.record_collector_run(
                tenant_id=tenant_id,
                collector=collector_name,
                status=result.status,
                started_at=result.started_at or utcnow(),
                finished_at=result.finished_at or utcnow(),
                events=result.event_count,
                findings=findings,
                errors=len(result.errors),
                detail=result.detail,
            )
            self.audit.record(
                tenant_id=tenant_id,
                actor="system:collector-runner",
                actor_role="system",
                action="collector.run",
                target={"type": "collector", "id": collector_name},
                after={
                    "status": result.status,
                    "events": result.event_count,
                    "findings": findings,
                    "errors": len(result.errors),
                },
                context={"detail": result.detail},
            )
        except Exception as exc:
            log.error("enregistrement de collecte impossible", extra={"error": str(exc)})


# --------------------------------------------------------------------------------------


def _merge_events(primary: list[Event], secondary: list[Event]) -> list[Event]:
    seen: set[str] = set()
    merged: list[Event] = []
    for event in [*primary, *secondary]:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        merged.append(event)
    return merged


def _normalize_status(value: Any) -> Any:
    return value if value in {"ok", "partial", "error", "never"} else "never"


def _iso(value: Any) -> str | None:
    parsed = parse_dt(value)
    return iso_z(parsed) if parsed else None


__all__ = ["MAX_CONCURRENT_COLLECTORS", "CollectorRunner"]
