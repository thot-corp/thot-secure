"""Détection d'anomalie statistique — le complément des règles déterministes.

Une règle déterministe répond à « ce motif est-il présent ? ». Elle ne peut pas répondre à
« ce volume est-il *anormal pour cet actif* » : c'est une question de **contexte**, et c'est
précisément le terrain des attaques lentes et distribuées (bourrage d'identifiants étalé sur
des heures, balayage à faible intensité, pic de sources multiples).

Ce module fournit une détection à base de **moyenne mobile exponentielle (EWMA)** et d'un
**z-score**, choisie pour quatre raisons :

1. **Explicable** — on peut écrire à l'analyste « 412 événements observés, 18 attendus,
   écart de 9,3 écarts-types ». Un modèle opaque produirait une alerte qu'on ne peut ni
   contester ni régler.
2. **Sans dépendance** — quelques dizaines de lignes de statistiques, pas de bibliothèque
   d'apprentissage. Un SOC doit pouvoir auditer son propre outil.
3. **En ligne et bon marché** — coût constant par événement, état borné : la détection ne
   devient pas le goulot d'étranglement du pipeline.
4. **Silencieuse par défaut** — `THOT_ANOMALY_ENABLED=false`. Un détecteur statistique mal
   réglé produit du bruit, et du bruit en sécurité coûte plus cher que pas de détection.

Un signal d'anomalie est émis comme un **événement ordinaire** (`kind: anomaly`,
`source.type: baseline`). Il traverse donc le moteur de règles, le scoring, la décision et
l'audit comme n'importe quel autre événement : aucune voie parallèle, aucun contournement des
garde-fous. Les règles livrées dans ``rules/anomaly/`` décident de ce qui mérite une alerte.

Aucune capacité offensive n'est évidemment concernée : ce module **observe** le flux qui
arrive, il ne génère aucun trafic.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from ..core.logging_setup import get_logger
from ..core.models import Event, EventSource, Severity
from ..core.util import deep_get

log = get_logger("detection.anomaly")

#: Écart minimal de variance : sans ce plancher, une série parfaitement régulière produit un
#: z-score infini au premier écart (division par ~0) et déclenche sur un hoquet normal.
VARIANCE_FLOOR = 1.0

#: Types de signal émis. Les valeurs sont stables : les règles de détection s'appuient dessus.
CHECK_RATE = "rate_anomaly"
CHECK_NEW_SOURCE = "new_source"
CHECK_CARDINALITY = "source_cardinality_anomaly"


@dataclass(slots=True)
class EntityStats:
    """État statistique d'une entité (adresse source, hôte, compte…)."""

    entity: str
    buckets_seen: int = 0
    count_in_bucket: int = 0
    bucket_start: float = 0.0
    rate_mean: float = 0.0
    rate_variance: float = 0.0
    total_events: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def zscore(self, observed: float) -> float:
        """Nombre d'écarts-types entre l'observation et la moyenne connue."""
        deviation = math.sqrt(max(self.rate_variance, VARIANCE_FLOOR))
        return (observed - self.rate_mean) / deviation


@dataclass(slots=True)
class AnomalySignal:
    """Anomalie détectée, avec de quoi la justifier auprès d'un analyste."""

    tenant_id: str
    check: str
    entity: str
    observed: float
    expected: float
    zscore: float
    severity_hint: Severity
    detail: str
    entity_field: str = "labels.src_ip"
    bucket_seconds: int = 60
    extra: dict[str, Any] = field(default_factory=dict)

    def to_event(self, *, source_event: Event | None = None) -> Event:
        """Convertit le signal en événement normalisé, traité par le pipeline habituel."""
        labels: dict[str, Any] = {
            "check": self.check,
            "entity": self.entity,
            "entity_field": self.entity_field,
            "observed": round(self.observed, 3),
            "expected": round(self.expected, 3),
            "zscore": round(self.zscore, 3),
            "bucket_seconds": self.bucket_seconds,
            "method": "ewma_zscore",
            "detector": "anomaly",
        }
        # On recopie les champs d'identification de l'événement d'origine lorsqu'ils existent :
        # sans cela, une anomalie de débit sur une adresse source perdrait l'IP, et le playbook
        # `rate-limit-source` n'aurait plus de cible exploitable.
        if source_event is not None:
            for key in ("src_ip", "host", "method", "path", "user", "status"):
                value = source_event.labels.get(key)
                if value is not None and key not in labels:
                    labels[key] = value
            labels.setdefault("host", source_event.source.host)
        labels.update(self.extra.get("labels", {}))

        return Event(
            tenant_id=self.tenant_id,
            kind="anomaly",
            source=EventSource(
                type="baseline",
                name="anomaly_detector",
                host=source_event.source.host if source_event else None,
            ),
            severity_hint=self.severity_hint,
            labels=labels,
            payload={
                "explanation": self.detail,
                "baseline": {
                    "mean": round(self.expected, 3),
                    "observed": round(self.observed, 3),
                    "zscore": round(self.zscore, 3),
                    "model": "EWMA + z-score (variance plancher appliquée)",
                },
                **self.extra.get("payload", {}),
            },
        )


@dataclass(slots=True)
class _TenantCardinality:
    """Suivi du nombre d'entités distinctes par tenant (détection d'attaque distribuée)."""

    bucket_start: float = 0.0
    current: set[str] = field(default_factory=set)
    buckets_seen: int = 0
    mean: float = 0.0
    variance: float = 0.0
    processed_events: int = 0
    known_entities: set[str] = field(default_factory=set)

    def zscore(self, observed: float) -> float:
        deviation = math.sqrt(max(self.variance, VARIANCE_FLOOR))
        return (observed - self.mean) / deviation


class AnomalyDetector:
    """Détecteur en ligne : EWMA par entité, cardinalité par tenant, sources nouvelles.

    Le détecteur est **synchrone et sans entrée/sortie** : on lui donne un événement et un
    horodatage, il retourne des signaux. Il est donc testable de façon déterministe, ce qui
    est indispensable pour un composant dont le défaut coûteux est le faux positif.
    """

    def __init__(
        self,
        *,
        bucket_seconds: int = 60,
        warmup_samples: int = 30,
        zscore_threshold: float = 4.0,
        min_observed: int = 20,
        entity_fields: list[str] | None = None,
        max_entities: int = 20_000,
        entity_ttl_seconds: int = 86_400,
        detect_new_sources: bool = True,
        alpha_span: int = 15,
        clock: Any | None = None,
    ) -> None:
        self.bucket_seconds = max(1, int(bucket_seconds))
        self.warmup_samples = max(1, int(warmup_samples))
        self.zscore_threshold = float(zscore_threshold)
        self.min_observed = max(1, int(min_observed))
        self.entity_fields = [field for field in (entity_fields or ["labels.src_ip"]) if field]
        self.max_entities = max(1, int(max_entities))
        self.entity_ttl_seconds = max(0, int(entity_ttl_seconds))
        self.detect_new_sources = detect_new_sources
        #: Horloge injectable. Elle existe pour une raison précise : sans elle, tester le
        #: franchissement d'un intervalle de 60 s exigerait d'attendre 60 s, et une détection
        #: qu'on ne peut pas tester vite finit par ne plus être testée du tout.
        self._clock = clock or time.time

        span = max(1, int(alpha_span))
        self.alpha = 2.0 / (span + 1.0)

        self._entities: OrderedDict[tuple[str, str, str], EntityStats] = OrderedDict()
        self._tenants: dict[str, _TenantCardinality] = {}

        self.observed_events = 0
        self.signals_emitted = 0
        self.evicted_entities = 0

    # ----------------------------------------------------------------------------------
    # Observation
    # ----------------------------------------------------------------------------------

    def observe(self, event: Event, *, now: float | None = None) -> list[AnomalySignal]:
        """Analyse un événement et retourne les anomalies détectées.

        Ne lève jamais : un détecteur d'anomalie ne doit pas pouvoir interrompre le pipeline
        (une exception ici créerait un angle mort exploitable en émettant des événements
        malformés).
        """
        try:
            timestamp = now if now is not None else self._clock()
            self.observed_events += 1
            signals: list[AnomalySignal] = []

            # Compteur de tenant incrémenté à CHAQUE événement (et non à chaque nouvelle
            # entité) : c'est lui qui décide de la fin de la période de chauffe. Le confondre
            # avec le nombre d'entités inédites rendait la chauffe plus longue qu'annoncée sur
            # un trafic à faible cardinalité, et invisible sur un trafic à forte cardinalité.
            tenant_state = self._tenants.setdefault(event.tenant_id, _TenantCardinality())
            tenant_state.processed_events += 1

            for field_name in self.entity_fields:
                entity = _entity_value(event, field_name)
                if entity is None:
                    continue
                signals.extend(self._observe_entity(event, entity, field_name, timestamp))

            signals.extend(self._observe_cardinality(event, timestamp))
            self.signals_emitted += len(signals)
            return signals
        except Exception as exc:
            log.error("erreur du détecteur d'anomalie", extra={"error": str(exc)}, exc_info=True)
            return []

    # ----------------------------------------------------------------------------------
    # Détection par entité
    # ----------------------------------------------------------------------------------

    def _observe_entity(
        self, event: Event, entity: str, field_name: str, timestamp: float
    ) -> list[AnomalySignal]:
        key = (event.tenant_id, field_name, entity)
        stats = self._entities.get(key)
        signals: list[AnomalySignal] = []

        if stats is None:
            stats = EntityStats(
                entity=entity,
                bucket_start=_bucket_start(timestamp, self.bucket_seconds),
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self._entities[key] = stats
            if self.detect_new_sources and self._is_new_source(event.tenant_id, entity):
                signals.append(
                    AnomalySignal(
                        tenant_id=event.tenant_id,
                        check=CHECK_NEW_SOURCE,
                        entity=entity,
                        observed=1.0,
                        expected=0.0,
                        zscore=0.0,
                        severity_hint="low",
                        detail=(
                            f"Première observation de '{entity}' sur {field_name} pour ce tenant. "
                            "À confirmer : nouvelle source légitime (partenaire, nouvel utilisateur) "
                            "ou signe de reconnaissance."
                        ),
                        entity_field=field_name,
                        bucket_seconds=self.bucket_seconds,
                        extra={
                            "labels": {"first_seen": True},
                            "payload": {"warmup_completed": True},
                        },
                    )
                )
        self._close_stale_buckets(stats, timestamp)

        stats.count_in_bucket += 1
        stats.total_events += 1
        stats.last_seen = timestamp

        # Le verdict porte sur le **bucket précédent**, une fois complet : on ne peut pas
        # juger un volume en cours de constitution sans déclencher sur le premier événement
        # venu. C'est aussi ce qui rend le détecteur déterministe.
        if timestamp - stats.bucket_start >= self.bucket_seconds:
            completed = (
                stats.count_in_bucket - 1
            )  # l'événement courant appartient au nouveau bucket
            signals.extend(self._evaluate_bucket(event, stats, completed, field_name))
            stats.bucket_start = _bucket_start(timestamp, self.bucket_seconds)
            stats.count_in_bucket = 1

        self._enforce_limits(timestamp)
        return signals

    def _close_stale_buckets(self, stats: EntityStats, timestamp: float) -> None:
        """Comble les buckets vides d'une entité silencieuse.

        Sans cela, une entité qui se tait pendant une heure garderait sa moyenne « comme si »
        elle avait été active, et son retour à la normale serait vu comme une anomalie. Le
        temps qui passe doit compter autant que les événements.
        """
        if stats.bucket_start == 0.0:
            stats.bucket_start = _bucket_start(timestamp, self.bucket_seconds)
            return
        elapsed_buckets = int((timestamp - stats.bucket_start) // self.bucket_seconds)
        if elapsed_buckets <= 1:
            return
        for _ in range(min(elapsed_buckets - 1, self.warmup_samples * 4)):
            self._update_model(stats, 0)
            stats.buckets_seen += 1

    def _evaluate_bucket(
        self, event: Event, stats: EntityStats, observed: int, field_name: str
    ) -> list[AnomalySignal]:
        signals: list[AnomalySignal] = []
        if stats.buckets_seen >= self.warmup_samples and observed >= self.min_observed:
            zscore = stats.zscore(observed)
            if zscore >= self.zscore_threshold:
                signals.append(
                    AnomalySignal(
                        tenant_id=event.tenant_id,
                        check=CHECK_RATE,
                        entity=stats.entity,
                        observed=float(observed),
                        expected=stats.rate_mean,
                        zscore=zscore,
                        severity_hint=_severity_for(zscore),
                        detail=(
                            f"{observed} événements en {self.bucket_seconds}s pour '{stats.entity}', "
                            f"contre {stats.rate_mean:.1f} attendus (écart de {zscore:.1f} écarts-types, "
                            f"base de {stats.buckets_seen} intervalles observés)."
                        ),
                        entity_field=field_name,
                        bucket_seconds=self.bucket_seconds,
                        extra={
                            "payload": {
                                "baseline_samples": stats.buckets_seen,
                                "total_events_seen": stats.total_events,
                            }
                        },
                    )
                )
        self._update_model(stats, observed)
        stats.buckets_seen += 1
        return signals

    def _update_model(self, stats: EntityStats, observed: int) -> None:
        previous_mean = stats.rate_mean
        stats.rate_mean = self.alpha * observed + (1 - self.alpha) * stats.rate_mean
        # Variance EWMA : on utilise l'écart à la moyenne **précédente**, pour ne pas mélanger
        # la nouvelle observation avec elle-même (ce qui sous-estimerait la variance).
        deviation = observed - previous_mean
        stats.rate_variance = self.alpha * (deviation**2) + (1 - self.alpha) * stats.rate_variance

    def _is_new_source(self, tenant_id: str, entity: str) -> bool:
        """Vrai si l'entité n'a jamais été vue pour ce tenant, une fois la chauffe terminée."""
        state = self._tenants.setdefault(tenant_id, _TenantCardinality())
        if state.processed_events <= self.warmup_samples * 2:
            # Période de chauffe : sur une installation neuve, tout est « nouveau ». Signaler
            # chaque source pendant les premières minutes rendrait le produit inutilisable.
            state.known_entities.add(entity)
            return False
        if entity in state.known_entities:
            return False
        state.known_entities.add(entity)
        return True

    # ----------------------------------------------------------------------------------
    # Cardinalité (attaque distribuée)
    # ----------------------------------------------------------------------------------

    def _observe_cardinality(self, event: Event, timestamp: float) -> list[AnomalySignal]:
        state = self._tenants.setdefault(event.tenant_id, _TenantCardinality())
        entity = _entity_value(event, self.entity_fields[0]) if self.entity_fields else None
        if state.bucket_start == 0.0:
            state.bucket_start = _bucket_start(timestamp, self.bucket_seconds)
        if entity is not None:
            state.current.add(entity)

        if timestamp - state.bucket_start < self.bucket_seconds:
            return []

        observed = len(state.current)
        signals: list[AnomalySignal] = []
        if state.buckets_seen >= self.warmup_samples and observed >= self.min_observed:
            zscore = state.zscore(observed)
            if zscore >= self.zscore_threshold:
                signals.append(
                    AnomalySignal(
                        tenant_id=event.tenant_id,
                        check=CHECK_CARDINALITY,
                        entity=event.tenant_id,
                        observed=float(observed),
                        expected=state.mean,
                        zscore=zscore,
                        severity_hint="high",
                        detail=(
                            f"{observed} sources distinctes en {self.bucket_seconds}s pour ce tenant, "
                            f"contre {state.mean:.1f} habituellement (écart de {zscore:.1f} écarts-types). "
                            "Schéma compatible avec une attaque distribuée ou un balayage réparti."
                        ),
                        entity_field=self.entity_fields[0]
                        if self.entity_fields
                        else "labels.src_ip",
                        bucket_seconds=self.bucket_seconds,
                        extra={
                            "labels": {"distinct_sources": observed},
                            "payload": {"baseline_samples": state.buckets_seen},
                        },
                    )
                )

        previous_mean = state.mean
        state.mean = self.alpha * observed + (1 - self.alpha) * state.mean
        state.variance = (
            self.alpha * ((observed - previous_mean) ** 2) + (1 - self.alpha) * state.variance
        )
        state.buckets_seen += 1
        state.current = set()
        state.bucket_start = _bucket_start(timestamp, self.bucket_seconds)
        return signals

    # ----------------------------------------------------------------------------------
    # Bornage mémoire
    # ----------------------------------------------------------------------------------

    def _enforce_limits(self, timestamp: float) -> None:
        """Borne l'état mémoire : un flux à forte cardinalité ne doit pas épuiser la RAM.

        Une attaque par balayage crée justement des dizaines de milliers d'entités : si le
        détecteur d'anomalie devenait un vecteur de déni de service, ce serait une ironie
        coûteuse. On évince donc les entités les plus anciennes, en commençant par celles
        dont l'horodatage est le plus éloigné.
        """
        if self.entity_ttl_seconds:
            cutoff = timestamp - self.entity_ttl_seconds
            while self._entities:
                key, stats = next(iter(self._entities.items()))
                if stats.last_seen >= cutoff:
                    break
                self._entities.pop(key, None)
                self.evicted_entities += 1

        while len(self._entities) > self.max_entities:
            self._entities.popitem(last=False)
            self.evicted_entities += 1

    # ----------------------------------------------------------------------------------
    # Observabilité
    # ----------------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "observed_events": self.observed_events,
            "signals_emitted": self.signals_emitted,
            "tracked_entities": len(self._entities),
            "tracked_tenants": len(self._tenants),
            "evicted_entities": self.evicted_entities,
            "bucket_seconds": self.bucket_seconds,
            "warmup_samples": self.warmup_samples,
            "zscore_threshold": self.zscore_threshold,
            "min_observed": self.min_observed,
            "entity_fields": list(self.entity_fields),
        }

    def reset(self) -> None:
        """Réinitialise l'état (rechargement de configuration, tests)."""
        self._entities.clear()
        self._tenants.clear()
        self.evicted_entities = 0


# --------------------------------------------------------------------------------------
# Aides
# --------------------------------------------------------------------------------------


def _bucket_start(timestamp: float, bucket_seconds: int) -> float:
    return math.floor(timestamp / bucket_seconds) * bucket_seconds


def _entity_value(event: Event, field_name: str) -> str | None:
    value = deep_get(event.model_dump(mode="python"), field_name)
    if value is None or value == "":
        return None
    return str(value)[:128]


def _severity_for(zscore: float) -> Severity:
    """Gravité graduée : un écart de 4 σ et un écart de 20 σ ne méritent pas le même traitement."""
    if zscore >= 20:
        return "critical"
    if zscore >= 12:
        return "high"
    if zscore >= 7:
        return "medium"
    return "low"


def build_detector(settings: Any) -> AnomalyDetector | None:
    """Construit le détecteur à partir de la configuration, ou ``None`` s'il est désactivé."""
    if not getattr(settings, "anomaly_enabled", False):
        return None
    return AnomalyDetector(
        bucket_seconds=getattr(settings, "anomaly_bucket_seconds", 60),
        warmup_samples=getattr(settings, "anomaly_warmup_samples", 30),
        zscore_threshold=getattr(settings, "anomaly_zscore_threshold", 4.0),
        min_observed=getattr(settings, "anomaly_min_observed", 20),
        entity_fields=list(getattr(settings, "anomaly_entity_fields", ["labels.src_ip"])),
        max_entities=getattr(settings, "anomaly_max_entities", 20_000),
        entity_ttl_seconds=getattr(settings, "anomaly_entity_ttl_seconds", 86_400),
        detect_new_sources=getattr(settings, "anomaly_detect_new_sources", True),
    )


__all__ = [
    "CHECK_CARDINALITY",
    "CHECK_NEW_SOURCE",
    "CHECK_RATE",
    "VARIANCE_FLOOR",
    "AnomalyDetector",
    "AnomalySignal",
    "EntityStats",
    "build_detector",
]
