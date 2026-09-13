"""Service du journal d'audit : écriture chaînée, vérification d'intégrité, export SIEM."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..core.logging_setup import get_logger
from ..core.models import AuditRecord, AuditVerifyResult
from ..core.util import iso_z, parse_dt, utcnow
from ..storage import StoreProtocol
from .hashchain import GENESIS_HASH, to_cef, verify_record

log = get_logger("audit.chain")

#: Actions d'audit normalisées. Un journal d'audit n'est exploitable que si les noms
#: d'action sont stables : les SIEM et les rapports s'appuient dessus.
AUDIT_ACTIONS: dict[str, str] = {
    "tenant.create": "Création d'un tenant",
    "tenant.update": "Modification d'un tenant (mode d'autonomie, dry-run, allowlist)",
    "key.create": "Création d'une clé API",
    "key.revoke": "Révocation d'une clé API",
    "event.ingest": "Ingestion d'événements",
    "finding.create": "Création d'un finding",
    "finding.update": "Mise à jour d'un finding",
    "finding.ack": "Acquittement d'un finding",
    "finding.close": "Clôture d'un finding",
    "finding.suppress": "Suppression (exception de bruit) d'un finding",
    "decision.evaluate": "Évaluation d'une politique de décision",
    "action.plan": "Planification d'une action",
    "action.approve": "Approbation d'une action",
    "action.reject": "Rejet d'une action",
    "action.execute": "Exécution d'une action",
    "action.rollback": "Annulation (rollback) d'une action",
    "action.fail": "Échec d'une action",
    "rules.reload": "Rechargement de la bibliothèque de règles",
    "policies.reload": "Rechargement des politiques",
    "anomaly.detected": "Anomalie statistique détectée (volume, cardinalité, source nouvelle)",
    "collector.run": "Exécution d'un collecteur",
    "auth.failure": "Échec d'authentification",
    "auth.success": "Authentification réussie",
    "retention.purge": "Purge de rétention",
    "system.start": "Démarrage du service",
    "system.stop": "Arrêt du service",
    "system.unsafe_default": "Activation d'un réglage non sûr",
}


class AuditChain:
    """Façade d'audit adossée au stockage.

    Toute action sensible passe par ici : jamais d'écriture directe dans ``audit_log``.
    """

    def __init__(self, store: StoreProtocol) -> None:
        self.store = store

    # ----------------------------------------------------------------------------------
    # Écriture
    # ----------------------------------------------------------------------------------

    def record(
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
        record = self.store.append_audit(
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            action=action,
            target=target or {},
            before=before or {},
            after=after or {},
            context=context or {},
            ts=ts,
        )
        log.debug(
            "audit",
            extra={
                "tenant_id": tenant_id,
                "actor": actor,
                "action": action,
                "audit_seq": record.seq,
            },
        )
        return record

    def record_state_change(
        self,
        *,
        tenant_id: str,
        actor: str,
        actor_role: str,
        action: str,
        target: dict[str, Any],
        before: dict[str, Any],
        after: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Enregistre une transition d'état avec l'avant/après : c'est ce qui rend un
        audit exploitable en investigation (« qui a désactivé le dry-run, quand, et
        quelle était la valeur précédente ? »)."""
        return self.record(
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            action=action,
            target=target,
            before=before,
            after=after,
            context=context,
        )

    # ----------------------------------------------------------------------------------
    # Lecture
    # ----------------------------------------------------------------------------------

    def tail(self, tenant_id: str, *, limit: int = 50) -> list[AuditRecord]:
        records, _ = self.store.list_audit(tenant_id, limit=limit)
        return records

    def count(self, tenant_id: str) -> int:
        return self.store.count_audit(tenant_id)

    # ----------------------------------------------------------------------------------
    # Vérification
    # ----------------------------------------------------------------------------------

    def verify(self, *, tenant_id: str | None = None) -> AuditVerifyResult:
        """Recalcule la chaîne complète.

        La vérification porte **toujours** sur la chaîne globale : les empreintes relient
        tous les tenants entre eux. Filtrer par tenant ne vérifierait qu'un sous-ensemble et
        laisserait passer une suppression ciblée sur un autre tenant.
        """
        expected_prev = GENESIS_HASH
        counted = 0
        total = 0
        for record in self.store.iter_audit():
            total += 1
            if tenant_id and record.tenant_id == tenant_id:
                counted += 1
            payload = {
                "seq": record.seq,
                "ts": iso_z(record.ts),
                "tenant_id": record.tenant_id,
                "actor": record.actor,
                "actor_role": record.actor_role,
                "action": record.action,
                "target": record.target,
                "before": record.before,
                "after": record.after,
                "prev_hash": record.prev_hash,
                "hash": record.hash,
            }
            valid, reason = verify_record(payload, expected_prev_hash=expected_prev)
            if not valid:
                log.error(
                    "INTÉGRITÉ DE L'AUDIT COMPROMISE",
                    extra={
                        "audit_seq": record.seq,
                        "reason": reason,
                        "tenant_id": record.tenant_id,
                    },
                )
                return AuditVerifyResult(
                    valid=False,
                    records=total,
                    broken_at=record.seq,
                    reason=reason,
                    checked_at=utcnow(),
                )
            expected_prev = record.hash
        return AuditVerifyResult(
            valid=True,
            records=counted if tenant_id else total,
            checked_at=utcnow(),
        )

    # ----------------------------------------------------------------------------------
    # Export
    # ----------------------------------------------------------------------------------

    def export(
        self,
        tenant_id: str,
        *,
        fmt: str = "jsonl",
        limit: int = 10_000,
        since: Any = None,
        until: Any = None,
    ) -> Iterator[str]:
        """Exporte vers un SIEM. ``jsonl`` conserve la chaîne (``prev_hash``/``hash``),
        ``cef`` est directement ingérable par ArcSight/QRadar/Splunk."""
        records, _ = self.store.list_audit(
            tenant_id, limit=min(limit, 10_000), since=since, until=until
        )
        for record in reversed(records):  # ordre chronologique pour un SIEM
            payload = {
                "seq": record.seq,
                "ts": iso_z(record.ts),
                "tenant_id": record.tenant_id,
                "actor": record.actor,
                "actor_role": record.actor_role,
                "action": record.action,
                "target": record.target,
                "before": record.before,
                "after": record.after,
                "context": record.context,
                "prev_hash": record.prev_hash,
                "hash": record.hash,
            }
            if fmt == "cef":
                yield to_cef(payload)
            else:
                import json

                yield json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def integrity_summary(self, tenant_id: str) -> dict[str, Any]:
        """Résumé destiné à la console et aux rapports de conformité."""
        result = self.verify(tenant_id=tenant_id)
        last = self.tail(tenant_id, limit=1)
        return {
            "valid": result.valid,
            "records": result.records,
            "broken_at": result.broken_at,
            "reason": result.reason,
            "last_record_at": iso_z(parse_dt(last[0].ts) or utcnow()) if last else None,
            "last_hash": last[0].hash if last else None,
            "checked_at": iso_z(result.checked_at),
        }


__all__ = ["AUDIT_ACTIONS", "AuditChain"]
