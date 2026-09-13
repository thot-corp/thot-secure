"""Moteur de détection : évaluation des règles, agrégation par seuil, déduplication.

Le moteur est **synchrone et sans entrée/sortie** : il prend un événement, retourne des
correspondances. C'est volontaire — la détection doit être testable en isolation, rejouable
sur un fichier d'événements, et jamais dépendante de la disponibilité de la base.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from ..core.logging_setup import get_logger
from ..core.models import Event, Finding, Rule, Tenant
from ..core.util import iso_z, stable_hash, utcnow
from ..scoring.risk import compute_risk
from .matchers import evaluate_condition
from .rule_loader import validate_rule

log = get_logger("detection.engine")

#: Garde-fou mémoire : au-delà de cette taille, une fenêtre de seuil est tronquée.
MAX_WINDOW_ENTRIES = 10_000

#: Nombre maximal d'identifiants d'événements conservés dans un finding. Un finding est une
#: synthèse, pas un journal : au-delà, on garde un échantillon et le compteur.
MAX_EVIDENCE_EVENTS = 25


@dataclass(slots=True)
class CompiledRule:
    """Règle pré-compilée : les conditions sont regroupées pour un parcours en une passe."""

    rule: Rule
    source_types: frozenset[str] = field(default_factory=frozenset)
    kinds: frozenset[str] = field(default_factory=frozenset)
    dedup_fields: tuple[str, ...] = ()
    group_fields: tuple[str, ...] = ()
    threshold_count: int = 1
    window_seconds: int = 60

    def applies_to(self, event: Event) -> bool:
        """Filtre d'entrée bon marché : source et type d'événement."""
        if self.source_types and event.source.type not in self.source_types:
            return False
        return not (self.kinds and event.kind not in self.kinds)


@dataclass(slots=True)
class MatchResult:
    """Correspondance d'une règle sur un événement."""

    rule: Rule
    event: Event
    dedup_key: str
    group_key: str
    threshold_count: int
    matched_at: float

    @property
    def is_threshold_match(self) -> bool:
        return self.threshold_count > 1


class DetectionEngine:
    """Applique la bibliothèque de règles aux flux d'événements."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._compiled: list[CompiledRule] = []
        self._by_id: dict[str, CompiledRule] = {}
        self._windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.evaluated = 0
        self.matched = 0
        self.threshold_suppressed = 0
        self.eval_seconds_total = 0.0
        self.reload(rules or [])

    # ----------------------------------------------------------------------------------
    # Cycle de vie
    # ----------------------------------------------------------------------------------

    def reload(self, rules: list[Rule]) -> None:
        """Remplace la bibliothèque active. Les fenêtres de seuil sont réinitialisées
        (une fenêtre partielle après rechargement produirait des déclenchements fantômes)."""
        compiled: list[CompiledRule] = []
        by_id: dict[str, CompiledRule] = {}
        rejected = 0
        for rule in rules:
            problems = validate_rule(rule)
            if problems:
                rejected += 1
                log.error(
                    "règle écartée du moteur",
                    extra={"rule_id": rule.id, "problems": problems},
                )
                continue
            entry = CompiledRule(
                rule=rule,
                source_types=frozenset(rule.source_types),
                kinds=frozenset(rule.kinds),
                dedup_fields=tuple(rule.dedup.key),
                group_fields=tuple(rule.match.threshold.group_by) if rule.match.threshold else (),
                threshold_count=rule.match.threshold.count if rule.match.threshold else 1,
                window_seconds=rule.match.threshold.window_seconds if rule.match.threshold else 60,
            )
            compiled.append(entry)
            by_id[rule.id] = entry
        # Tri par sévérité décroissante : en cas de budget d'évaluation limité, les
        # détections les plus graves passent d'abord.
        compiled.sort(key=lambda item: (-_severity_weight(item.rule.severity), item.rule.id))
        self._compiled = compiled
        self._by_id = by_id
        self._windows.clear()
        log.info(
            "moteur de détection rechargé",
            extra={"rules": len(compiled), "rejected": rejected},
        )

    @property
    def rules(self) -> list[Rule]:
        return [entry.rule for entry in self._compiled]

    def get_rule(self, rule_id: str) -> Rule | None:
        entry = self._by_id.get(rule_id.upper())
        return entry.rule if entry else None

    # ----------------------------------------------------------------------------------
    # Évaluation
    # ----------------------------------------------------------------------------------

    def evaluate(self, event: Event, *, now: float | None = None) -> list[MatchResult]:
        """Évalue un événement contre toutes les règles actives."""
        started = time.perf_counter()
        context = event.model_dump(mode="python")
        now = now if now is not None else utcnow().timestamp()
        results: list[MatchResult] = []

        for entry in self._compiled:
            rule = entry.rule
            if not rule.enabled:
                continue
            if not entry.applies_to(event):
                continue
            if not self._matches(rule, context):
                continue

            group_key = self._group_key(entry, event)
            threshold_count = self._register_hit(entry, group_key, now)
            if threshold_count == 0:
                # Seuil non atteint : on compte la correspondance mais on n'émet rien.
                self.threshold_suppressed += 1
                continue

            self.matched += 1
            results.append(
                MatchResult(
                    rule=rule,
                    event=event,
                    dedup_key=self._dedup_key(entry, event),
                    group_key=group_key,
                    threshold_count=threshold_count,
                    matched_at=now,
                )
            )

        self.evaluated += 1
        self.eval_seconds_total += time.perf_counter() - started
        return results

    @staticmethod
    def _matches(rule: Rule, context: dict[str, Any]) -> bool:
        spec = rule.match
        for condition in spec.all:
            if not evaluate_condition(condition, context):
                return False
        if spec.any and not any(evaluate_condition(condition, context) for condition in spec.any):
            return False
        return all(not evaluate_condition(condition, context) for condition in spec.not_)

    def _register_hit(self, entry: CompiledRule, group_key: str, now: float) -> int:
        """Enregistre une correspondance et retourne le compte dans la fenêtre.

        Retourne ``0`` si le seuil n'est pas encore atteint (la correspondance est comptée
        mais aucune détection n'est émise).
        """
        count = entry.threshold_count
        if count <= 1:
            return 1
        key = (entry.rule.id, group_key)
        window = self._windows[key]
        cutoff = now - entry.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        window.append(now)
        if len(window) > MAX_WINDOW_ENTRIES:
            while len(window) > MAX_WINDOW_ENTRIES:
                window.popleft()
        if len(window) >= count:
            return len(window)
        return 0

    @staticmethod
    def _group_key(entry: CompiledRule, event: Event) -> str:
        if not entry.group_fields:
            return "-"
        context = event.model_dump(mode="python")
        values = {field_name: _dig(context, field_name) for field_name in entry.group_fields}
        return stable_hash(values)[:16]

    @staticmethod
    def _dedup_key(entry: CompiledRule, event: Event) -> str:
        """Clé de regroupement d'un finding.

        Sans clé explicite, on regroupe par ``(règle, tenant)`` : un seul finding par règle
        et par tenant, ce qui évite d'inonder la file d'un analyste avec 10 000 lignes
        identiques. Avec clé, on distingue par entité (IP source, hôte, paquet…).
        """
        if not entry.dedup_fields:
            return "tenant"
        context = event.model_dump(mode="python")
        values = {field_name: _dig(context, field_name) for field_name in entry.dedup_fields}
        return stable_hash(values)[:24]

    # ----------------------------------------------------------------------------------
    # Construction d'un finding
    # ----------------------------------------------------------------------------------

    def build_finding(
        self,
        match: MatchResult,
        tenant: Tenant,
        *,
        history: Finding | None = None,
        existing_count: int = 0,
    ) -> Finding:
        """Construit (ou rafraîchit) un finding avec son score de risque explicable."""
        rule = match.rule
        event = match.event
        effective_count = max(1, existing_count + 1, match.threshold_count)
        breakdown = compute_risk(rule, tenant, count=effective_count)

        evidence_samples = _extract_evidence(rule, event)
        if history is not None:
            previous = list(history.evidence.get("samples") or [])
            event_ids = list(history.event_ids)
            samples = (previous + evidence_samples)[-MAX_EVIDENCE_EVENTS:]
            event_ids = _append_unique(event_ids, event.event_id, limit=200)
            first_seen = history.first_seen
            created_at = history.created_at
        else:
            samples = evidence_samples[-MAX_EVIDENCE_EVENTS:]
            event_ids = [event.event_id]
            first_seen = event.ts
            created_at = utcnow()

        title = _render_title(rule, event)
        payload: dict[str, Any] = {
            "tenant_id": tenant.tenant_id,
            "rule_id": rule.id,
            "rule_name": rule.title,
            "severity": rule.severity,
            "risk_score": breakdown.final,
            "confidence": rule.confidence,
            "status": history.status if history else "open",
            "title": title,
            "description": rule.description,
            "remediation": rule.remediation,
            "tags": list(rule.tags),
            "mitre": [tag.split(":", 1)[1] for tag in rule.tags if tag.startswith("mitre:")],
            "evidence": {
                "samples": samples,
                "risk": breakdown.model_dump(),
                "group_key": match.group_key,
                "threshold": {
                    "count": rule.match.threshold.count if rule.match.threshold else 1,
                    "window_seconds": rule.match.threshold.window_seconds
                    if rule.match.threshold
                    else 0,
                    "observed": match.threshold_count,
                },
                "rule": {"id": rule.id, "title": rule.title, "path": rule.path},
                "false_positives": list(rule.false_positives),
            },
            "first_seen": first_seen,
            "last_seen": max(event.ts, first_seen),
            "count": effective_count,
            "event_ids": event_ids,
            "created_at": created_at,
            "updated_at": utcnow(),
            "dedup_key": match.dedup_key,
        }
        # On conserve l'identifiant existant pour que le finding reste le même objet aux yeux
        # de l'analyste (et des tickets déjà ouverts).
        if history is not None:
            payload["finding_id"] = history.finding_id
        return Finding(**payload)

    # ----------------------------------------------------------------------------------
    # Observabilité
    # ----------------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "rules_loaded": len(self._compiled),
            "rules_enabled": sum(1 for entry in self._compiled if entry.rule.enabled),
            "evaluated": self.evaluated,
            "matched": self.matched,
            "threshold_suppressed": self.threshold_suppressed,
            "avg_eval_ms": round(
                (self.eval_seconds_total / self.evaluated * 1000) if self.evaluated else 0.0, 3
            ),
            "active_windows": len(self._windows),
        }

    def summaries(self) -> list[dict[str, Any]]:
        return [entry.rule.summary() for entry in self._compiled]


# --------------------------------------------------------------------------------------
# Aides internes
# --------------------------------------------------------------------------------------


def _dig(context: dict[str, Any], path: str) -> Any:
    from ..core.util import deep_get

    return deep_get(context, path)


def _append_unique(values: list[str], value: str, *, limit: int = 200) -> list[str]:
    if value in values:
        return values
    values.append(value)
    if len(values) > limit:
        del values[: len(values) - limit]
    return values


def _extract_evidence(rule: Rule, event: Event) -> list[dict[str, Any]]:
    """Extrait un échantillon lisible pour l'analyste.

    On ne stocke **pas** la charge utile complète : les preuves sont potentiellement
    porteuses de données personnelles (RGPD) et de secrets. On conserve uniquement les
    champs utiles à la compréhension, avec les valeurs sensibles masquées.
    """
    from ..core.util import redact_secrets, truncate

    sample: dict[str, Any] = {
        "ts": iso_z(event.ts),
        "event_id": event.event_id,
        "kind": event.kind,
        "source": {"type": event.source.type, "host": event.source.host, "name": event.source.name},
    }
    label_keys = sorted(event.labels)[:12]
    sample["labels"] = {
        key: truncate(redact_secrets(str(event.labels[key])), 200) for key in label_keys
    }
    payload_keys = sorted(event.payload)[:12]
    sample["payload"] = {
        key: truncate(redact_secrets(str(event.payload[key])), 300) for key in payload_keys
    }
    sample["matched_rule"] = rule.id
    return [sample]


def _render_title(rule: Rule, event: Event) -> str:
    """Titre orienté analyste : règle + entité concernée.

    Un titre « SQL injection attempt » oblige l'analyste à ouvrir le finding pour savoir qui
    est visé. On préfère « Tentative d'injection SQL depuis 203.0.113.9 sur /login ».
    """
    parts = [rule.title]
    src = event.labels.get("src_ip")
    if src:
        parts.append(f"depuis {src}")
    elif event.source.host:
        parts.append(f"sur {event.source.host}")
    path = event.labels.get("path")
    if path:
        parts.append(f"({path})")
    elif event.labels.get("host"):
        parts.append(f"({event.labels['host']})")
    return " ".join(parts)[:300]


def _severity_weight(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 2)


__all__ = [
    "MAX_EVIDENCE_EVENTS",
    "MAX_WINDOW_ENTRIES",
    "CompiledRule",
    "DetectionEngine",
    "MatchResult",
]
