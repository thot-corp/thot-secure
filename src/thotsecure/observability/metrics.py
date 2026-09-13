"""Métriques Prometheus — exposition **sans dépendance externe**.

Un registre minimal (compteurs, jauges, histogrammes) et un rendu au format texte
d'exposition Prometheus. Écrire cinquante lignes plutôt que d'ajouter ``prometheus_client``
garde l'image de production légère et le paquet installable en environnement cloisonné.

Les métriques sont **pilotées par les valeurs réelles du service** au moment du scrape : les
jauges (nombre de findings ouverts, actions en attente, validité de l'audit) sont donc
toujours fraîches, ce qui évite les dérives classiques d'un état mis en cache.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

#: Buckets d'histogramme par défaut (secondes), adaptés à un pipeline de détection.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
)

MetricLabels = tuple[tuple[str, str], ...]


def _label_key(labels: dict[str, str] | None) -> MetricLabels:
    return tuple(sorted((str(key), str(value)) for key, value in (labels or {}).items()))


def _format_labels(labels: MetricLabels, extra: dict[str, str] | None = None) -> str:
    items = list(labels)
    if extra:
        items.extend((str(key), str(value)) for key, value in sorted(extra.items()))
    if not items:
        return ""
    rendered = ",".join(f'{key}="{_escape(value)}"' for key, value in items)
    return f"{{{rendered}}}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class MetricsRegistry:
    """Registre de métriques thread-safe."""

    def __init__(self, *, namespace: str = "thotsecure") -> None:
        self.namespace = namespace
        self._lock = threading.RLock()
        self._counters: dict[tuple[str, MetricLabels], float] = defaultdict(float)
        self._gauges: dict[tuple[str, MetricLabels], float] = {}
        self._histograms: dict[tuple[str, MetricLabels], dict[str, Any]] = {}
        self._help: dict[str, str] = {}
        self._types: dict[str, str] = {}
        self._collectors: list[Callable[[MetricsRegistry], None]] = []

    # ----------------------------------------------------------------------------------
    # Déclaration
    # ----------------------------------------------------------------------------------

    def describe(self, name: str, help_text: str, metric_type: str) -> None:
        self._help[name] = help_text
        self._types[name] = metric_type

    def register_collector(self, collector: Callable[[MetricsRegistry], None]) -> None:
        """Enregistre une fonction appelée à chaque scrape pour rafraîchir les jauges."""
        self._collectors.append(collector)

    # ----------------------------------------------------------------------------------
    # Écriture
    # ----------------------------------------------------------------------------------

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = (name, _label_key(labels))
        with self._lock:
            self._counters[key] += value
            self._types.setdefault(name, "counter")

    def set(self, name: str, value: float, **labels: str) -> None:
        key = (name, _label_key(labels))
        with self._lock:
            self._gauges[key] = float(value)
            self._types.setdefault(name, "gauge")

    def observe(
        self, name: str, value: float, *, buckets: Iterable[float] | None = None, **labels: str
    ) -> None:
        key = (name, _label_key(labels))
        bounds = tuple(buckets or DEFAULT_BUCKETS)
        with self._lock:
            entry = self._histograms.get(key)
            if entry is None:
                entry = {"bounds": bounds, "counts": [0] * len(bounds), "sum": 0.0, "count": 0}
                self._histograms[key] = entry
                self._types.setdefault(name, "histogram")
            entry["sum"] += float(value)
            entry["count"] += 1
            for index, bound in enumerate(entry["bounds"]):
                if value <= bound:
                    entry["counts"][index] += 1

    def track(self, name: str, **labels: str) -> _Timer:
        return _Timer(self, name, labels)

    # ----------------------------------------------------------------------------------
    # Lecture / rendu
    # ----------------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": {
                    f"{name}{_label_key(labels)}": value
                    for (name, labels), value in self._counters.items()
                },
                "gauges": {
                    f"{name}{_label_key(labels)}": value
                    for (name, labels), value in self._gauges.items()
                },
                "histograms": {
                    f"{name}{_label_key(labels)}": {
                        "count": entry["count"],
                        "sum": round(entry["sum"], 6),
                    }
                    for (name, labels), entry in self._histograms.items()
                },
            }

    def counter_value(self, name: str, **labels: str) -> float:
        with self._lock:
            return self._counters.get((name, _label_key(labels)), 0.0)

    def gauge_value(self, name: str, **labels: str) -> float | None:
        with self._lock:
            return self._gauges.get((name, _label_key(labels)))

    def render(self) -> str:
        """Rend le format texte d'exposition Prometheus."""
        for collector in list(self._collectors):
            try:
                collector(self)
            except Exception:
                continue

        lines: list[str] = []
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {
                key: {
                    "bounds": list(entry["bounds"]),
                    "counts": list(entry["counts"]),
                    "sum": entry["sum"],
                    "count": entry["count"],
                }
                for key, entry in self._histograms.items()
            }

        emitted: set[str] = set()
        for name, labels in sorted(counters, key=lambda item: (item[0], item[1])):
            self._emit_header(lines, name, emitted)
            lines.append(f"{name}{_format_labels(labels)} {counters[(name, labels)]:g}")

        for name, labels in sorted(gauges, key=lambda item: (item[0], item[1])):
            self._emit_header(lines, name, emitted)
            lines.append(f"{name}{_format_labels(labels)} {gauges[(name, labels)]:g}")

        for name, labels in sorted(histograms, key=lambda item: (item[0], item[1])):
            self._emit_header(lines, name, emitted)
            entry = histograms[(name, labels)]
            cumulative = 0
            for bound, count in zip(entry["bounds"], entry["counts"], strict=False):
                cumulative = count  # les compteurs de buckets sont déjà cumulés
                lines.append(
                    f"{name}_bucket{_format_labels(labels, {'le': repr(bound)})} {cumulative}"
                )
            lines.append(f"{name}_bucket{_format_labels(labels, {'le': '+Inf'})} {entry['count']}")
            lines.append(f"{name}_sum{_format_labels(labels)} {entry['sum']:g}")
            lines.append(f"{name}_count{_format_labels(labels)} {entry['count']}")

        return "\n".join(lines) + "\n"

    def _emit_header(self, lines: list[str], name: str, emitted: set[str]) -> None:
        if name in emitted:
            return
        emitted.add(name)
        help_text = self._help.get(name, name.replace("_", " "))
        metric_type = self._types.get(name, "gauge")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")


class _Timer:
    """Chronomètre contextuel qui alimente un histogramme."""

    __slots__ = ("_labels", "_name", "_registry", "_started")

    def __init__(self, registry: MetricsRegistry, name: str, labels: dict[str, str]) -> None:
        self._registry = registry
        self._name = name
        self._labels = labels
        self._started = 0.0

    def __enter__(self) -> _Timer:
        self._started = time.perf_counter()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._registry.observe(self._name, time.perf_counter() - self._started, **self._labels)


#: Catalogue des métriques exposées (également utilisé par les alertes du déploiement).
METRICS_CATALOG: dict[str, str] = {
    "thotsecure_events_ingested_total": "Nombre total d'événements acceptés par tenant.",
    "thotsecure_events_rejected_total": "Nombre d'événements refusés (tenant inconnu, lot trop grand).",
    "thotsecure_findings_total": "Findings créés, par sévérité.",
    "thotsecure_findings_open": "Findings actuellement ouverts.",
    "thotsecure_rule_eval_seconds": "Durée d'évaluation d'un événement par le moteur de règles.",
    "thotsecure_pipeline_processed_total": "Événements traversant le pipeline complet.",
    "thotsecure_pipeline_errors_total": "Erreurs de traitement du pipeline.",
    "thotsecure_actions_total": "Actions par statut et par playbook.",
    "thotsecure_actions_auto_total": "Actions déclenchées sans approbation humaine.",
    "thotsecure_actions_pending_approval": "Actions en attente d'approbation.",
    "thotsecure_rollbacks_total": "Rollbacks exécutés.",
    "thotsecure_decisions_total": "Décisions par type (auto, require_approval, notify_only, ignore).",
    "thotsecure_audit_records_total": "Enregistrements du journal d'audit.",
    "thotsecure_audit_chain_valid": "1 si la chaîne d'audit est intègre, 0 sinon (alerte critique).",
    "thotsecure_dry_run": "1 si le mode simulation est actif (valeur attendue en production supervisée).",
    "thotsecure_api_requests_total": "Requêtes HTTP par route et par code de statut.",
    "thotsecure_api_request_seconds": "Latence des requêtes HTTP.",
    "thotsecure_ws_clients": "Clients WebSocket connectés.",
    "thotsecure_collector_runs_total": "Exécutions de collecteurs, par collecteur et statut.",
    "thotsecure_collector_errors_total": "Erreurs de collecte.",
    "thotsecure_bus_dropped_total": "Événements écartés par le bus (file pleine).",
    "thotsecure_bus_published_total": "Événements publiés sur le bus.",
    "thotsecure_http_probe_requests_total": "Requêtes émises par l'audit de surface.",
    "thotsecure_up": "1 si le service répond (toujours 1 sur une réponse réussie).",
    "thotsecure_start_time_seconds": "Horodatage Unix de démarrage du service.",
}


def register_catalog(registry: MetricsRegistry) -> None:
    for name, help_text in METRICS_CATALOG.items():
        metric_type = "counter" if name.endswith("_total") else "gauge"
        if name.endswith("_seconds") and not name.endswith("_start_time_seconds"):
            metric_type = "histogram"
        registry.describe(name, help_text, metric_type)


__all__ = [
    "DEFAULT_BUCKETS",
    "METRICS_CATALOG",
    "MetricsRegistry",
    "register_catalog",
]
