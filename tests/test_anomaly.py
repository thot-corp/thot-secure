"""Détection d'anomalie : exactitude statistique, absence de faux positifs, bornage mémoire.

Un détecteur d'anomalie a deux façons d'échouer, toutes deux coûteuses :

* **trop bavard** — il signale tout, l'astreinte apprend à ignorer ses alertes, et il devient
  un générateur de bruit qu'on finit par désactiver ;
* **trop discret** — ses seuils sont si hauts qu'il ne signale jamais rien, et il donne
  l'illusion d'une couverture qui n'existe pas.

Ces tests vérifient donc les deux directions : du trafic stationnaire **ne doit rien**
déclencher, et une rupture franche **doit** être détectée — avec les bons chiffres à l'appui
(observé, attendu, écart), parce qu'une anomalie non explicable n'est pas exploitable.
"""

from __future__ import annotations

import unittest

from thotsecure.core.models import Event, EventSource
from thotsecure.detection.anomaly import (
    CHECK_CARDINALITY,
    CHECK_NEW_SOURCE,
    CHECK_RATE,
    AnomalyDetector,
)

from .support import StackTestCase, build_stack

BUCKET = 60


def make_event(
    *,
    tenant_id: str = "acme",
    src_ip: str = "203.0.113.9",
    host: str = "shop.acme.fr",
    kind: str = "http.request",
) -> Event:
    return Event(
        tenant_id=tenant_id,
        kind=kind,  # type: ignore[arg-type]
        source=EventSource(type="log_tail", name="nginx", host=host),
        labels={"src_ip": src_ip, "host": host, "path": "/"},
        payload={"status": 200},
    )


class AnomalyDetectorTest(unittest.TestCase):
    """Le détecteur, testé hors pipeline (déterministe, sans horloge réelle)."""

    def _detector(self, **overrides: object) -> AnomalyDetector:
        options: dict[str, object] = {
            "bucket_seconds": BUCKET,
            "warmup_samples": 5,
            "zscore_threshold": 4.0,
            "min_observed": 20,
            "entity_fields": ["labels.src_ip"],
            "detect_new_sources": False,
        }
        options.update(overrides)
        return AnomalyDetector(**options)  # type: ignore[arg-type]

    # -- absence de faux positifs ------------------------------------------------------

    def test_stationary_traffic_never_triggers(self) -> None:
        """Un flux régulier ne doit JAMAIS produire de signal : c'est la propriété la plus
        importante du détecteur, celle qui décide s'il est utilisable en production."""
        detector = self._detector()
        signals = []
        # 40 buckets de 25 événements, parfaitement réguliers.
        for bucket in range(40):
            for index in range(25):
                signals.extend(
                    detector.observe(
                        make_event(), now=bucket * BUCKET + index * (BUCKET / 25)
                    )
                )
        self.assertEqual([], signals, "trafic stationnaire signalé à tort")

    def test_warmup_suppresses_early_signals(self) -> None:
        """Pendant la chauffe, même un pic ne doit rien produire : la moyenne n'existe pas."""
        detector = self._detector(warmup_samples=10)
        signals = []
        for index in range(5):
            signals.extend(detector.observe(make_event(), now=index * 0.1))
        # Pic immédiat dans le premier bucket.
        for index in range(80):
            signals.extend(detector.observe(make_event(), now=BUCKET + index * 0.01))
        rate_signals = [s for s in signals if s.check == CHECK_RATE]
        self.assertEqual([], rate_signals)

    def test_below_minimum_volume_is_ignored(self) -> None:
        """Un écart statistiquement fort mais opérationnellement insignifiant est ignoré."""
        detector = self._detector(min_observed=50, zscore_threshold=3.0)
        # Base : 1 événement par bucket.
        for bucket in range(12):
            detector.observe(make_event(), now=bucket * BUCKET)
        # Pic à 10 événements : très au-dessus de la moyenne, mais sous le minimum.
        signals = []
        for index in range(10):
            signals.extend(detector.observe(make_event(), now=BUCKET * 12 + index * 0.1))
        detector.observe(make_event(), now=BUCKET * 13)
        self.assertEqual([], [s for s in signals if s.check == CHECK_RATE])

    # -- détection réelle --------------------------------------------------------------

    def test_volume_burst_is_detected_with_readable_numbers(self) -> None:
        """Un pic franc doit être détecté, avec des chiffres exploitables par un analyste."""
        detector = self._detector(warmup_samples=5, min_observed=20)
        for bucket in range(10):
            for index in range(20):
                detector.observe(make_event(), now=bucket * BUCKET + index * 0.5)

        signals = []
        for index in range(300):
            signals.extend(detector.observe(make_event(), now=BUCKET * 10 + index * 0.1))
        # L'intervalle n'est jugé qu'une fois COMPLET : le verdict arrive donc avec l'événement
        # suivant, qui clôt le bucket. Ne pas collecter ce retour était le défaut du test — le
        # détecteur fonctionnait, la mesure était fausse.
        signals.extend(detector.observe(make_event(), now=BUCKET * 11 + 1))

        rate_signals = [s for s in signals if s.check == CHECK_RATE]
        self.assertTrue(rate_signals, "le pic de volume n'a pas été détecté")
        signal = rate_signals[0]
        self.assertGreater(signal.observed, signal.expected)
        self.assertGreater(signal.zscore, 4.0)
        self.assertEqual("203.0.113.9", signal.entity)
        # L'explication doit contenir les trois nombres, sinon l'analyste ne peut pas juger.
        self.assertIn("écarts-types", signal.detail)
        self.assertIn("contre", signal.detail)

    def test_severity_scales_with_deviation(self) -> None:
        detector = self._detector(warmup_samples=5, min_observed=20)
        for bucket in range(10):
            for index in range(20):
                detector.observe(make_event(), now=bucket * BUCKET + index * 0.5)
        signals = []
        for index in range(3000):
            signals.extend(detector.observe(make_event(), now=BUCKET * 10 + index * 0.01))
        signals.extend(detector.observe(make_event(), now=BUCKET * 11 + 1))
        rate_signals = [s for s in signals if s.check == CHECK_RATE]
        self.assertTrue(rate_signals)
        self.assertIn(rate_signals[0].severity_hint, {"high", "critical"})

    def test_new_source_is_signalled_after_warmup_only(self) -> None:
        """Le signal « source nouvelle » n'a de valeur qu'une fois le tenant connu : sinon il
        se déclenche sur les premiers contacts d'une installation neuve."""
        detector = self._detector(detect_new_sources=True, warmup_samples=5)
        # La chauffe s'achève à ``warmup_samples * 2`` événements, soit 10 ici.
        early = []
        for index in range(8):  # 8 événements : encore en chauffe
            early.extend(detector.observe(make_event(src_ip="198.51.100.7"), now=index * 0.1))
        for index in range(4):  # franchit la fin de chauffe, mais source déjà connue
            early.extend(detector.observe(make_event(src_ip="198.51.100.7"), now=1.0 + index * 0.1))
        self.assertEqual([], [s for s in early if s.check == CHECK_NEW_SOURCE])

        # Chauffe terminée : une adresse inédite est signalée, une seule fois.
        first = detector.observe(make_event(src_ip="203.0.113.200"), now=2.0)
        second = detector.observe(make_event(src_ip="203.0.113.200"), now=2.1)
        self.assertEqual(1, len([s for s in first if s.check == CHECK_NEW_SOURCE]))
        self.assertEqual([], [s for s in second if s.check == CHECK_NEW_SOURCE])

    def test_distributed_attack_is_detected_through_cardinality(self) -> None:
        """Aucune règle par adresse ne peut voir une attaque répartie : c'est le rôle de la
        cardinalité."""
        detector = self._detector(warmup_samples=5, min_observed=10)
        # Base : 3 sources distinctes par minute.
        for bucket in range(10):
            for offset in range(3):
                detector.observe(
                    make_event(src_ip=f"198.51.100.{offset}"), now=bucket * BUCKET + offset
                )
        signals = []
        # Attaque : 60 sources distinctes dans une minute.
        for offset in range(60):
            signals.extend(
                detector.observe(make_event(src_ip=f"203.0.113.{offset}"), now=BUCKET * 10 + offset * 0.5)
            )
        signals.extend(detector.observe(make_event(src_ip="203.0.113.250"), now=BUCKET * 11 + 1))
        cardinality = [s for s in signals if s.check == CHECK_CARDINALITY]
        self.assertTrue(cardinality, "l'attaque distribuée n'a pas été détectée")
        self.assertGreater(cardinality[0].observed, cardinality[0].expected)
        self.assertEqual("high", cardinality[0].severity_hint)

    # -- robustesse --------------------------------------------------------------------

    def test_event_without_tracked_field_is_ignored_without_error(self) -> None:
        detector = self._detector(entity_fields=["labels.src_ip", "labels.user"])
        event = Event(
            tenant_id="acme",
            kind="log.line",
            source=EventSource(type="log_tail"),
            labels={"message": "aucune adresse source disponible"},
        )
        self.assertEqual([], detector.observe(event, now=0.0))

    def test_memory_is_bounded(self) -> None:
        """Une attaque par balayage crée des dizaines de milliers d'entités : le détecteur ne
        doit pas devenir lui-même un vecteur de saturation mémoire."""
        detector = self._detector(max_entities=50, entity_ttl_seconds=0)
        for index in range(500):
            detector.observe(make_event(src_ip=f"203.0.113.{index % 256}.{index // 256}"), now=index * 0.1)
        stats = detector.stats()
        self.assertLessEqual(stats["tracked_entities"], 51)
        self.assertGreater(stats["evicted_entities"], 0)

    def test_detector_never_raises_on_odd_input(self) -> None:
        """Le détecteur ne doit jamais interrompre le pipeline : une exception ici serait un
        angle mort exploitable en émettant des événements malformés."""
        detector = self._detector()
        odd = Event(
            tenant_id="acme",
            kind="generic",
            source=EventSource(type="manual"),
            labels={"src_ip": "x" * 500},
            payload={"nested": {"deep": [1, 2, 3]}},
        )
        for index in range(50):
            self.assertIsInstance(detector.observe(odd, now=float(index)), list)


class AnomalyPipelineTest(StackTestCase):
    """Intégration : un signal d'anomalie suit le chemin habituel (règle → finding → décision)."""

    #: Les règles d'anomalie du dépôt (`rules/anomaly/`) ne sont pas dans les fixtures du banc
    #: de test : on en fournit une équivalente, volontairement minimale, pour vérifier la
    #: **chaîne complète** et pas seulement le détecteur.
    extra_rules = {
        "anomaly-test.yaml": """
id: AO-ANO-TEST
title: Anomalie de volume (règle de test)
description: Règle minimale utilisée pour vérifier l'intégration du détecteur au pipeline.
severity: high
confidence: 0.7
tags: [anomaly, volume-anomaly]
source_types: [baseline]
kinds: [anomaly]
match:
  all:
    - field: labels.check
      op: eq
      value: rate_anomaly
dedup:
  key: [labels.src_ip]
  ttl_seconds: 900
risk:
  base: 55
remediation: Vérifier la source, puis décider d'une limitation de débit proportionnée.
""",
    }

    def _stack_with_anomaly(self) -> None:
        """Installe un détecteur à horloge **pilotée par le test**.

        L'horloge est un attribut que le test fait avancer lui-même. C'est indispensable : un
        pic de volume se définit par « beaucoup d'événements dans le même intervalle », donc le
        temps ne doit PAS s'écouler proportionnellement au nombre d'événements. Une horloge qui
        avance à chaque événement rendrait tout pic invisible par construction.
        """
        from thotsecure.detection.anomaly import AnomalyDetector

        self._fake_now = 0.0

        def clock() -> float:
            return self._fake_now

        self.stack.pipeline.anomaly = AnomalyDetector(
            bucket_seconds=10,
            warmup_samples=3,
            zscore_threshold=3.0,
            min_observed=10,
            entity_fields=["labels.src_ip"],
            detect_new_sources=False,
            clock=clock,
        )

    def _ingest_at(self, timestamp: float, count: int) -> None:
        self._fake_now = timestamp
        for _ in range(count):
            self.stack.pipeline.ingest([self.stack.event(source_type="log_tail")])

    def test_anomaly_signal_produces_an_audited_finding(self) -> None:
        self._stack_with_anomaly()
        # Chauffe : 6 intervalles de 10 s, 10 événements chacun (trafic régulier).
        for bucket in range(6):
            self._ingest_at(bucket * 10.0, 10)
        # Pic : 300 événements dans le même intervalle de 10 s…
        self._ingest_at(60.0, 300)
        # …puis un événement qui clôt l'intervalle et déclenche le verdict.
        self._ingest_at(70.0, 1)

        findings, _ = self.stack.store.list_findings("acme")
        anomaly_findings = [
            finding for finding in findings if finding.rule_id.startswith("AO-ANO-")
        ]
        self.assertTrue(
            anomaly_findings,
            f"aucun finding d'anomalie produit (findings: {[f.rule_id for f in findings]})",
        )
        self.assertIn(anomaly_findings[0].severity, {"medium", "high", "critical"})

        anomaly_events, _ = self.stack.store.query_events("acme", kinds=["anomaly"])
        self.assertTrue(anomaly_events, "l'événement d'anomalie doit être persisté")

        actions = [record.action for record in self.stack.store.iter_audit()]
        self.assertIn("anomaly.detected", actions, "la détection doit être auditée")
        self.assertTrue(
            self.stack.audit.verify(tenant_id="acme").valid, "la chaîne d'audit doit rester valide"
        )

    def test_disabled_detector_produces_no_anomaly(self) -> None:
        """Sans détecteur, aucun événement d'anomalie : le comportement par défaut est inchangé."""
        for _ in range(50):
            self.stack.pipeline.ingest([self.stack.event(source_type="log_tail")])
        anomaly_events, _ = self.stack.store.query_events("acme", kinds=["anomaly"])
        self.assertEqual([], anomaly_events)

    def test_anomaly_events_do_not_recurse(self) -> None:
        """Un événement d'anomalie ne doit pas être réanalysé comme un événement ordinaire :
        sinon une anomalie en engendrerait d'autres sans fin."""
        self._stack_with_anomaly()
        calls = {"count": 0}
        original = self.stack.pipeline.anomaly.observe

        def counting_observe(event, now=None):  # type: ignore[no-untyped-def]
            calls["count"] += 1
            return original(event, now=now)

        self.stack.pipeline.anomaly.observe = counting_observe  # type: ignore[method-assign]
        anomaly_event = Event(
            tenant_id="acme",
            kind="anomaly",
            source=EventSource(type="baseline", name="anomaly_detector"),
            labels={"check": CHECK_RATE, "src_ip": "203.0.113.9"},
        )
        self.stack.pipeline.process_event(anomaly_event)
        self.assertEqual(0, calls["count"], "un événement d'anomalie a été réanalysé")


class AnomalyConfigTest(unittest.TestCase):
    """La détection est désactivée par défaut : c'est une décision de sûreté, elle est testée."""

    def test_disabled_by_default(self) -> None:
        stack = build_stack(self._tmp_dir())
        self.addCleanup(stack.close)
        self.assertIsNone(stack.pipeline.anomaly, "le détecteur ne doit pas être actif par défaut")

    def test_enabled_builds_a_detector_with_the_configured_thresholds(self) -> None:
        from thotsecure.core.config import Settings
        from thotsecure.detection.anomaly import build_detector

        settings = Settings(
            root_dir=self._tmp_dir(),
            secret_key="test-secret-key-for-anomaly-tests-0123456789",
            anomaly_enabled=True,
            anomaly_bucket_seconds=30,
            anomaly_zscore_threshold=5.5,
            anomaly_min_observed=42,
            anomaly_entity_fields=["labels.src_ip", "labels.host"],
        )
        detector = build_detector(settings)
        self.assertIsNotNone(detector)
        assert detector is not None
        self.assertEqual(30, detector.bucket_seconds)
        self.assertEqual(5.5, detector.zscore_threshold)
        self.assertEqual(42, detector.min_observed)
        self.assertEqual(["labels.src_ip", "labels.host"], detector.entity_fields)

    def _tmp_dir(self) -> str:
        import tempfile
        from pathlib import Path

        path = Path(tempfile.mkdtemp(prefix="thotsecure-anomaly-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
        return str(path)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
