"""Pipeline d'ingestion : ingérer → détecter → scorer → décider → agir → auditer.

C'est le cœur fonctionnel du produit, et il est **synchrone**. Un pipeline asynchrone
distribué serait plus élégant sur un diagramme ; il serait aussi beaucoup plus difficile à
raisonner en incident (« où est passé cet événement ? »). Ici, ``ingest()`` retourne la liste
exacte des findings, décisions et actions produits par le lot ingéré : c'est directement
exploitable en test, en CLI et dans la réponse HTTP.

Le bus sert à la **distribution** (rejeu après redémarrage, plusieurs nœuds, temps réel vers
la console), pas à la correction : un événement persisté mais non traité est rejoué.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .actions.engine import ActionEngine
from .audit.chain import AuditChain
from .bus.base import EventBus
from .core.config import Settings
from .core.logging_setup import bind_context, get_logger
from .core.models import Action, Decision, Event, Finding, IngestResult, Tenant
from .core.util import iso_z, utcnow
from .decision.engine import DecisionContext, DecisionEngine, extract_targets
from .detection.engine import DetectionEngine
from .storage import StoreProtocol

log = get_logger("pipeline")

#: Nombre maximal d'événements traités par lot (garde-fou anti-emballement).
MAX_BATCH = 500


@dataclass(slots=True)
class ProcessResult:
    """Résultat du traitement d'un événement."""

    event_id: str
    findings: list[Finding] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class IngestOutcome:
    """Résultat d'une ingestion (persisté, publié, traité)."""

    result: IngestResult = field(default_factory=IngestResult)
    findings: list[Finding] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)


class Pipeline:
    """Orchestrateur du traitement des événements."""

    def __init__(
        self,
        store: StoreProtocol,
        audit: AuditChain,
        engine: DetectionEngine,
        decision_engine: DecisionEngine,
        action_engine: ActionEngine,
        *,
        settings: Settings,
        bus: EventBus | None = None,
        anomaly: Any | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.engine = engine
        self.decision_engine = decision_engine
        self.action_engine = action_engine
        self.settings = settings
        self.bus = bus
        #: Détecteur d'anomalie statistique, ou ``None`` s'il est désactivé (défaut).
        self.anomaly = anomaly
        self.processed_events = 0
        self.created_findings = 0
        self.updated_findings = 0
        self.triggered_actions = 0
        self.anomaly_events = 0
        self.errors = 0
        self._worker_task: asyncio.Task[None] | None = None

    # ----------------------------------------------------------------------------------
    # Ingestion
    # ----------------------------------------------------------------------------------

    def ingest(
        self,
        events: list[Event],
        *,
        actor: str = "system",
        actor_role: str = "analyst",
        process: bool = True,
    ) -> IngestOutcome:
        """Persiste un lot d'événements, le publie sur le bus et le traite."""
        outcome = IngestOutcome()
        if not events:
            return outcome
        if len(events) > MAX_BATCH:
            outcome.result.errors.append(
                {"error": "batch_too_large", "message": f"maximum {MAX_BATCH} événements par lot"}
            )
            events = events[:MAX_BATCH]

        accepted: list[Event] = []
        known_tenants: dict[str, Tenant | None] = {}
        for event in events:
            tenant = known_tenants.get(event.tenant_id)
            if event.tenant_id not in known_tenants:
                tenant = self.store.get_tenant(event.tenant_id)
                known_tenants[event.tenant_id] = tenant
            if tenant is None:
                # On refuse plutôt que de créer un tenant implicitement : un collecteur mal
                # configuré ne doit pas pouvoir fabriquer une frontière d'isolation.
                outcome.result.rejected += 1
                outcome.result.errors.append(
                    {
                        "error": "unknown_tenant",
                        "message": f"tenant inconnu: {event.tenant_id}",
                        "event_id": event.event_id,
                    }
                )
                continue
            accepted.append(event)

        if not accepted:
            return outcome

        inserted = self.store.insert_events(accepted)
        outcome.result.accepted = inserted
        outcome.result.rejected += len(accepted) - inserted
        outcome.result.event_ids = [event.event_id for event in accepted]

        if self.audit is not None and inserted:
            # Un enregistrement d'audit par **lot**, pas par événement : sur un flux de
            # 10 000 événements/minute, un audit par événement noierait la piste d'audit
            # utile (qui a fait quoi) sous le bruit de collecte.
            by_tenant: dict[str, int] = {}
            for event in accepted:
                by_tenant[event.tenant_id] = by_tenant.get(event.tenant_id, 0) + 1
            for tenant_id, count in by_tenant.items():
                self.audit.record(
                    tenant_id=tenant_id,
                    actor=actor,
                    actor_role=actor_role,
                    action="event.ingest",
                    target={"type": "event_batch", "id": f"batch:{iso_z(utcnow())}"},
                    after={"accepted": count},
                )

        if process:
            # Une règle à seuil qui matche N événements produit N évaluations du **même**
            # finding : `outcome.findings` en listait donc N copies, avec N `count`
            # intermédiaires — 200 événements donnaient 200 entrées pour un seul finding.
            # Un appelant qui lit cette liste croit à 200 findings et peut lire le `count`
            # d'un état intermédiaire. On garde donc **le dernier état par finding**, dans
            # l'ordre de première apparition.
            #
            # `Decision` ne porte pas d'identifiant de finding : l'appariement se fait par
            # index, comme dans `_react_to`, qui ajoute un finding et une décision par match.
            states: dict[str, tuple[Finding, Decision | None]] = {}
            for event in accepted:
                result = self.process_event(event)
                for index, finding in enumerate(result.findings):
                    decision = result.decisions[index] if index < len(result.decisions) else None
                    states[finding.finding_id] = (finding, decision)
                outcome.actions.extend(result.actions)

            outcome.findings = [finding for finding, _ in states.values()]
            outcome.decisions = [decision for _, decision in states.values() if decision is not None]
            for finding, decision in states.values():
                outcome.result.findings.append(
                    {
                        "finding_id": finding.finding_id,
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "risk_score": finding.risk_score,
                        "status": finding.status,
                        "count": finding.count,
                        "decision": decision.decision if decision else None,
                        "playbook": decision.playbook if decision else None,
                        "guards": list(decision.guards) if decision else [],
                    }
                )

        self._publish(accepted)
        return outcome

    def _publish(self, events: list[Event]) -> None:
        """Publication sur le bus. Non bloquante : le pipeline est déjà synchrone."""
        if self.bus is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Appel hors boucle asyncio (CLI) : la diffusion temps réel est simplement ignorée,
            # le traitement a déjà eu lieu.
            return
        for event in events:
            loop.create_task(self.bus.publish(event))  # noqa: RUF006 - tâche volontairement détachée

    # ----------------------------------------------------------------------------------
    # Traitement d'un événement
    # ----------------------------------------------------------------------------------

    def process_event(self, event: Event) -> ProcessResult:
        """Détecte, score, décide et agit pour un événement.

        Ordre volontaire : les règles déterministes d'abord, l'analyse statistique ensuite.
        Une détection certaine (motif d'attaque identifié) ne doit pas attendre un calcul de
        moyenne mobile, et un signal d'anomalie ne doit jamais retarder une règle.
        """
        result = ProcessResult(event_id=event.event_id)
        bind_context(tenant_id=event.tenant_id, event_id=event.event_id)
        try:
            tenant = self.store.get_tenant(event.tenant_id)
            if tenant is None:
                result.error = f"tenant inconnu: {event.tenant_id}"
                return result

            self._react_to(event, tenant, result)
            self._process_anomalies(event, tenant, result)

            self.processed_events += 1
            self.store.mark_events_processed([event.event_id])
        except Exception as exc:
            self.errors += 1
            result.error = f"{type(exc).__name__}: {exc}"
            log.error(
                "erreur de traitement d'événement",
                extra={"event_id": event.event_id, "error": str(exc)},
                exc_info=True,
            )
        return result

    def _react_to(self, event: Event, tenant: Tenant, result: ProcessResult) -> None:
        """Applique le moteur de règles à un événement, puis décide et agit.

        Cette méthode est partagée entre l'événement d'origine et les événements d'anomalie :
        un signal statistique suit donc **exactement** le même chemin (règle → scoring →
        décision → garde-fous → audit) qu'un événement de journal. Aucune voie parallèle,
        aucun garde-fou contourné.
        """
        for match in self.engine.evaluate(event):
            finding = self._upsert_finding(match, tenant)
            result.findings.append(finding)

            decision = self._decide(finding, tenant)
            result.decisions.append(decision)

            action = self.action_engine.from_decision(
                tenant=tenant,
                finding=finding,
                decision=decision,
            )
            if action is not None:
                result.actions.append(action)
                self.triggered_actions += 1

    def _process_anomalies(self, event: Event, tenant: Tenant, result: ProcessResult) -> None:
        """Analyse statistique de l'événement et traitement des signaux produits.

        Le détecteur est optionnel (désactivé par défaut) et ne lève jamais. Les événements
        d'anomalie sont **persistés** au même titre que les autres : un signal qui n'existe
        que dans la mémoire du processus n'est pas une preuve, et l'analyste doit pouvoir
        reconstituer ce que le détecteur a vu.
        """
        if self.anomaly is None:
            return
        # Une anomalie ne s'analyse pas elle-même : cela créerait une boucle de rétroaction
        # (une anomalie de cardinalité en engendrerait d'autres indéfiniment).
        if event.source.type == "baseline" or event.kind == "anomaly":
            return

        for signal in self.anomaly.observe(event):
            anomaly_event = signal.to_event(source_event=event)
            if not self.store.insert_event(anomaly_event):
                continue
            self.anomaly_events += 1
            self.audit.record(
                tenant_id=tenant.tenant_id,
                actor="system:anomaly-detector",
                actor_role="system",
                action="anomaly.detected",
                target={"type": "event", "id": anomaly_event.event_id},
                after={
                    "check": signal.check,
                    "entity": signal.entity,
                    "observed": round(signal.observed, 3),
                    "expected": round(signal.expected, 3),
                    "zscore": round(signal.zscore, 3),
                    "severity_hint": signal.severity_hint,
                },
                context={"source_event_id": event.event_id, "method": "ewma_zscore"},
            )
            self._react_to(anomaly_event, tenant, result)

    def _upsert_finding(self, match: Any, tenant: Tenant) -> Finding:
        """Crée ou rafraîchit le finding correspondant à une correspondance de règle."""
        rule = match.rule
        existing = self.store.find_open_finding(tenant.tenant_id, rule.id, match.dedup_key)
        if existing is not None:
            age = (utcnow() - existing.last_seen).total_seconds()
            if age > rule.dedup.ttl_seconds:
                # Fenêtre de déduplication dépassée : on clôt l'ancien et on en ouvre un
                # nouveau. Sans cela, un finding « ouvert » le resterait éternellement et
                # fausserait le MTTR.
                self.store.update_finding(
                    tenant.tenant_id,
                    existing.finding_id,
                    status="closed",
                    resolution="auto_closed_expired_dedup_window",
                    comment=f"fenêtre de déduplication de {rule.dedup.ttl_seconds}s dépassée",
                )
                existing = None

        if existing is not None:
            finding = self.engine.build_finding(
                match, tenant, history=existing, existing_count=existing.count
            )
            finding.count = existing.count + 1
            self.store.update_finding(
                tenant.tenant_id,
                finding.finding_id,
                severity=finding.severity,
                risk_score=finding.risk_score,
                confidence=finding.confidence,
                title=finding.title,
                description=finding.description,
                remediation=finding.remediation,
                tags=finding.tags,
                mitre=finding.mitre,
                evidence=finding.evidence,
                last_seen=finding.last_seen,
                count=finding.count,
                event_ids=finding.event_ids,
            )
            self.updated_findings += 1
            refreshed = self.store.get_finding(tenant.tenant_id, finding.finding_id) or finding
            if existing.risk_score < refreshed.risk_score:
                self.audit.record(
                    tenant_id=tenant.tenant_id,
                    actor="system:pipeline",
                    actor_role="system",
                    action="finding.update",
                    target={"type": "finding", "id": refreshed.finding_id},
                    before={"risk_score": existing.risk_score, "count": existing.count},
                    after={"risk_score": refreshed.risk_score, "count": refreshed.count},
                    context={"rule_id": rule.id, "reason": "aggravation du score de risque"},
                )
            return refreshed

        finding = self.engine.build_finding(match, tenant)
        self.store.insert_finding(finding)
        self.created_findings += 1
        self.audit.record(
            tenant_id=tenant.tenant_id,
            actor="system:pipeline",
            actor_role="system",
            action="finding.create",
            target={"type": "finding", "id": finding.finding_id},
            after={
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "title": finding.title,
            },
            context={"event_id": match.event.event_id, "dedup_key": match.dedup_key},
        )
        return finding

    def _decide(self, finding: Finding, tenant: Tenant) -> Decision:
        asset_host, target_value = extract_targets(finding)
        decision = self.decision_engine.decide(
            DecisionContext(
                finding=finding,
                tenant=tenant,
                environment=self.settings.env,
                settings=self.settings,
                asset_host=asset_host,
                target_value=target_value,
            )
        )
        self.audit.record(
            tenant_id=tenant.tenant_id,
            actor="system:policy-engine",
            actor_role="system",
            action="decision.evaluate",
            target={"type": "finding", "id": finding.finding_id},
            after={
                "decision": decision.decision,
                "policy_id": decision.policy_id,
                "playbook": decision.playbook,
                "dry_run": decision.dry_run,
            },
            context={"reason": decision.reason[:800], "guards": decision.guards},
        )
        return decision

    # ----------------------------------------------------------------------------------
    # Consommateur de bus (temps réel / rejeu)
    # ----------------------------------------------------------------------------------

    async def run_worker(self, *, stop_event: asyncio.Event | None = None) -> None:
        """Consomme les événements publiés sur le bus et les traite.

        Utilisé lorsque les événements arrivent d'un autre processus (bus SQLite partagé ou
        NATS) et n'ont donc pas été traités en ligne.
        """
        if self.bus is None:
            return
        queue = self.bus.subscribe()
        log.info("consommateur de bus démarré", extra={"bus": self.bus.name})
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    continue
                except asyncio.CancelledError:
                    raise
                event_processed = self.store.get_event(event.tenant_id, event.event_id)
                if event_processed is not None:
                    # Déjà traité en ligne lors de l'ingestion : on évite le double traitement.
                    continue
                self.process_event(event)
        except asyncio.CancelledError:
            log.info("consommateur de bus arrêté")
            raise
        finally:
            self.bus.unsubscribe(queue)

    async def replay_pending(self) -> int:
        """Traite les événements persistés mais jamais traités (reprise après incident)."""
        pending = self.store.pending_events(limit=MAX_BATCH)
        processed = 0
        for event in pending:
            self.process_event(event)
            processed += 1
        if processed:
            log.warning("événements en attente traités", extra={"count": processed})
        return processed

    # ----------------------------------------------------------------------------------
    # Maintenance
    # ----------------------------------------------------------------------------------

    def purge_expired(self) -> dict[str, int]:
        """Purge de rétention (events) — appelée par la tâche de maintenance."""
        result = self.store.purge(
            retention_days=self.settings.retention_days,
            audit_retention_days=self.settings.audit_retention_days,
        )
        if any(result.values()):
            for tenant in self.store.list_tenants():
                self.audit.record(
                    tenant_id=tenant.tenant_id,
                    actor="system:retention",
                    actor_role="system",
                    action="retention.purge",
                    target={"type": "retention", "id": "purge"},
                    after=result,
                    context={"retention_days": self.settings.retention_days},
                )
                break
        return result

    def stats(self) -> dict[str, Any]:
        return {
            "processed_events": self.processed_events,
            "created_findings": self.created_findings,
            "updated_findings": self.updated_findings,
            "triggered_actions": self.triggered_actions,
            "anomaly_events": self.anomaly_events,
            "errors": self.errors,
            "detection": self.engine.stats(),
            "decision": self.decision_engine.stats(),
            "anomaly": self.anomaly.stats() if self.anomaly is not None else {"enabled": False},
            "max_batch": MAX_BATCH,
        }

    # ----------------------------------------------------------------------------------

    def stop_worker(self) -> None:
        if self._worker_task is not None:
            self._worker_task.cancel()
            self._worker_task = None


__all__ = ["MAX_BATCH", "IngestOutcome", "Pipeline", "ProcessResult"]
