"""Suite de **conformité** de la couche de persistance : le même corpus contre les deux backends.

Pourquoi ce fichier existe : la limite reconnue du produit était « un seul backend éprouvé ». Une
seconde implémentation (PostgreSQL/TimescaleDB) ne vaut que si elle se comporte **comme** la
première sur tout ce dont le reste du code dépend : isolation multi-tenant, idempotence,
pagination par curseur, chaîne d'audit, verrous, purge. Écrire des tests PostgreSQL séparés
laisserait diverger les deux comportements en silence ; ici, la classe
:class:`StoreConformanceTest` ne connaît que ``storage.base.StoreProtocol`` et rejoue le même
scénario sur la fabrique fournie par la sous-classe.

* :class:`SqliteStoreConformanceTest` — toujours exécutée (aucune dépendance, aucun réseau) ;
* :class:`PostgresStoreConformanceTest` — **ignorée automatiquement** si la variable
  d'environnement ``THOT_TEST_POSTGRES_DSN`` n'est pas définie (cas du poste de développement) ;
  en CI, le job ``postgres`` fournit un service TimescaleDB et l'exporte ;
* :class:`PostgresClaimConformanceTest` — vérifie en plus la réservation atomique des événements à
  rejouer (capacité propre à PostgreSQL), également ignorée sans DSN.

Commande de vérification locale (les cas PostgreSQL sont comptés comme « ignorés ») :

    python -m unittest tests.test_storage_conformance -v
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from thotsecure.audit.chain import AuditChain
from thotsecure.core.errors import ConflictError, NotFoundError, StorageError
from thotsecure.core.models import (
    Action,
    ActionTarget,
    ApiKeyRecord,
    Event,
    EventSource,
    Finding,
    Tenant,
)
from thotsecure.core.util import new_id, utcnow
from thotsecure.storage import store_interface_methods
from thotsecure.storage.postgres import PostgresStore
from thotsecure.storage.store import MAX_PAGE_SIZE, Store

#: Variable d'environnement qui active les cas PostgreSQL (voir ``.github/workflows/ci.yml``).
POSTGRES_DSN_ENV = "THOT_TEST_POSTGRES_DSN"

#: Tenant principal des tests, et second tenant servant à prouver l'isolation.
TENANT = "acme"
OTHER_TENANT = "globex"


def postgres_dsn() -> str | None:
    """DSN de test PostgreSQL, ou ``None`` si les cas PostgreSQL doivent être ignorés."""
    return os.environ.get(POSTGRES_DSN_ENV) or None


class StoreConformanceTest(unittest.TestCase):
    """Contrat commun : tout magasin conforme passe ces tests sans adaptation.

    Une sous-classe fournit deux choses et rien d'autre :

    * :meth:`store_factory` — construit le magasin sur un répertoire temporaire ;
    * :meth:`tamper_audit` — modifie un enregistrement d'audit **en contournant** l'API, afin de
      prouver que la vérification d'intégrité détecte la falsification (l'accès direct dépend du
      backend, c'est la seule méthode non portable).

    Cette classe de base ne s'exécute pas telle quelle : sa fabrique lève ``SkipTest``, ce qui la
    fait apparaître comme « ignorée » plutôt qu'en échec.
    """

    #: Délai maximal (secondes) accordé aux assertions de concurrence.
    CONCURRENCY_TIMEOUT = 60.0

    # ----------------------------------------------------------------------------------
    # Fabrique fournie par la sous-classe
    # ----------------------------------------------------------------------------------

    def store_factory(self, root: Path) -> Any:
        """Construit le magasin à tester. **À surcharger.**"""
        raise unittest.SkipTest(
            "classe de base abstraite : exécuter SqliteStoreConformanceTest ou "
            "PostgresStoreConformanceTest"
        )

    def tamper_audit(self, seq: int) -> None:
        """Falsifie l'enregistrement d'audit ``seq`` (acteur modifié). **À surcharger.**"""
        raise NotImplementedError

    # ----------------------------------------------------------------------------------
    # Cycle de vie des tests
    # ----------------------------------------------------------------------------------

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(
            prefix="thot-storage-conformance-", ignore_cleanup_errors=True
        )
        self.root = Path(self._tmp.name)
        self.store = self.store_factory(self.root)
        self.reset_store()
        self.tenant = self.store.upsert_tenant(
            Tenant(tenant_id=TENANT, name="ACME SAS", mode="supervised", dry_run=True)
        )
        self.store.upsert_tenant(Tenant(tenant_id=OTHER_TENANT, name="Globex"))

    def tearDown(self) -> None:
        store = getattr(self, "store", None)
        if store is not None:
            store.close()
        self._tmp.cleanup()

    def reset_store(self) -> None:
        """Ramène le magasin à un état vide. Par défaut : rien (base neuve)."""

    # ----------------------------------------------------------------------------------
    # Fabriques d'objets de test
    # ----------------------------------------------------------------------------------

    def make_event(
        self,
        *,
        event_id: str | None = None,
        tenant_id: str = TENANT,
        ts: Any = None,
        kind: str = "http.request",
        source_type: str = "log_tail",
        labels: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Event:
        return Event(
            event_id=event_id or new_id("ev_"),
            tenant_id=tenant_id,
            ts=ts or utcnow(),
            kind=kind,  # type: ignore[arg-type]
            source=EventSource(type=source_type, name="collecteur-test", host="shop.acme.fr"),
            severity_hint="medium",
            labels=labels if labels is not None else {"src_ip": "203.0.113.9", "path": "/login"},
            payload=payload if payload is not None else {"status": 403, "bytes": 512},
        )

    def make_finding(
        self,
        *,
        finding_id: str | None = None,
        tenant_id: str = TENANT,
        rule_id: str = "AO-WEB-001",
        dedup_key: str = "203.0.113.9",
        severity: str = "high",
        risk_score: float = 78.5,
        status: str = "open",
        tags: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            finding_id=finding_id or new_id("fi_"),
            tenant_id=tenant_id,
            rule_id=rule_id,
            rule_name="Tentative d'injection SQL",
            severity=severity,  # type: ignore[arg-type]
            risk_score=risk_score,
            confidence=0.85,
            status=status,  # type: ignore[arg-type]
            title="Tentative d'injection SQL depuis 203.0.113.9",
            description="Motif « union select » détecté dans un paramètre de requête.",
            remediation="Bloquer l'IP source au WAF pendant 1 h.",
            tags=tags if tags is not None else ["web", "owasp:a03"],
            mitre=["T1190"],
            evidence=evidence if evidence is not None else {"samples": [{"status": 403}]},
            dedup_key=dedup_key,
        )

    def make_action(
        self,
        *,
        action_id: str | None = None,
        tenant_id: str = TENANT,
        finding_id: str | None = None,
        playbook: str = "block-source-ip",
        status: str = "planned",
        target_value: str = "203.0.113.9",
        idempotency_key: str | None = None,
        dry_run: bool = True,
    ) -> Action:
        return Action(
            action_id=action_id or new_id("ac_"),
            tenant_id=tenant_id,
            finding_id=finding_id,
            policy_id="auto-block-high-web",
            playbook=playbook,
            status=status,  # type: ignore[arg-type]
            mode="manual",
            dry_run=dry_run,
            params={"target": target_value, "duration_seconds": 3600},
            target=ActionTarget(type="ip", value=target_value),
            requested_by="api-key:ci",
            idempotency_key=idempotency_key or new_id("idem_"),
        )

    # ----------------------------------------------------------------------------------
    # Interface
    # ----------------------------------------------------------------------------------

    def test_interface_is_implemented_in_full(self) -> None:
        """Chaque méthode du contrat est présente et appelable sur le magasin."""
        missing = [
            name
            for name in store_interface_methods()
            if not callable(getattr(self.store, name, None))
        ]
        self.assertEqual([], missing, f"méthodes du contrat absentes : {missing}")
        self.assertTrue(self.store.backend_name)

    def test_backend_features_are_declared_as_a_frozenset(self) -> None:
        """``supports_backend_features()`` retourne un ensemble (jamais ``None``)."""
        features = self.store.supports_backend_features()
        self.assertIsInstance(features, frozenset)
        self.assertTrue(all(isinstance(name, str) for name in features))

    def test_transaction_context_manager_is_usable(self) -> None:
        """Une transaction vide s'ouvre et se referme sans erreur."""
        with self.store.transaction():
            pass
        self.assertTrue(self.store.health())

    # ----------------------------------------------------------------------------------
    # Tenants et clés API
    # ----------------------------------------------------------------------------------

    def test_tenant_lifecycle(self) -> None:
        """Upsert, lecture, listage, mise à jour et tenant inconnu."""
        self.assertEqual("ACME SAS", self.tenant.name)

        fetched = self.store.get_tenant(TENANT)
        self.assertIsNotNone(fetched)
        self.assertEqual(TENANT, fetched.tenant_id)  # type: ignore[union-attr]
        self.assertEqual("supervised", fetched.mode)  # type: ignore[union-attr]
        self.assertTrue(fetched.dry_run)  # type: ignore[union-attr]

        self.assertIsNone(self.store.get_tenant("inexistant"))
        with self.assertRaises(NotFoundError):
            self.store.require_tenant("inexistant")

        self.assertEqual([TENANT, OTHER_TENANT], [t.tenant_id for t in self.store.list_tenants()])

        updated = self.store.update_tenant(
            TENANT,
            mode="auto",
            dry_run=False,
            autonomy_allowlist=["10.0.0.0/8"],
            protected_targets=["10.0.0.1"],
            max_actions_per_hour=5,
        )
        self.assertEqual("auto", updated.mode)
        self.assertFalse(updated.dry_run)
        self.assertEqual(["10.0.0.0/8"], updated.autonomy_allowlist)
        self.assertEqual(["10.0.0.1"], updated.protected_targets)
        self.assertEqual(5, updated.max_actions_per_hour)

        reloaded = self.store.get_tenant(TENANT)
        self.assertEqual(["10.0.0.0/8"], reloaded.autonomy_allowlist)  # type: ignore[union-attr]

    def test_tenant_update_of_unknown_tenant_is_not_found(self) -> None:
        with self.assertRaises(NotFoundError):
            self.store.update_tenant("inexistant", mode="auto")

    def test_tenant_update_ignores_unknown_and_none_fields(self) -> None:
        """Un champ non autorisé ou ``None`` est ignoré, sans erreur (la validation est en amont)."""
        updated = self.store.update_tenant(TENANT, mode=None, champ_inconnu="x")
        self.assertEqual("supervised", updated.mode)
        self.assertEqual("ACME SAS", updated.name)

    def test_api_key_lifecycle(self) -> None:
        """Insertion hachée, recherche par empreinte, révocation, horodatage d'usage."""
        record = ApiKeyRecord(
            key_id=new_id("key_"),
            tenant_id=TENANT,
            label="ci",
            role="responder",
            key_hash=f"scrypt$test${new_id()}",
            key_prefix="ao_test",
        )
        self.store.insert_api_key(record)
        self.assertEqual(record.key_id, self.store.get_api_key(record.key_id).key_id)  # type: ignore[union-attr]
        self.assertIsNotNone(self.store.find_api_key_by_hash(record.key_hash))
        self.assertEqual(1, len(self.store.list_api_keys(TENANT)))
        self.assertEqual([], self.store.list_api_keys(OTHER_TENANT))

        with self.assertRaises(ConflictError):
            self.store.insert_api_key(record)

        self.store.touch_api_key(record.key_id)
        touched = self.store.get_api_key(record.key_id)
        self.assertIsNotNone(touched.last_used_at)  # type: ignore[union-attr]

        self.assertTrue(self.store.revoke_api_key(record.key_id))
        self.assertFalse(self.store.revoke_api_key(record.key_id))
        self.assertIsNone(self.store.find_api_key_by_hash(record.key_hash))
        self.assertIsNotNone(self.store.get_api_key(record.key_id))

    def test_api_key_revocation_is_scoped_to_the_tenant(self) -> None:
        """Un tenant ne peut pas révoquer la clé d'un autre (défense en profondeur)."""
        record = ApiKeyRecord(
            key_id=new_id("key_"),
            tenant_id=TENANT,
            label="ci",
            role="viewer",
            key_hash=f"scrypt$test${new_id()}",
            key_prefix="ao_test",
        )
        self.store.insert_api_key(record)
        self.assertFalse(self.store.revoke_api_key(record.key_id, tenant_id=OTHER_TENANT))
        self.assertIsNotNone(self.store.find_api_key_by_hash(record.key_hash))

    # ----------------------------------------------------------------------------------
    # Événements
    # ----------------------------------------------------------------------------------

    def test_event_insert_is_idempotent(self) -> None:
        """Rejouer le même événement n'écrit rien et ne lève pas."""
        event = self.make_event()
        self.assertTrue(self.store.insert_event(event))
        self.assertFalse(self.store.insert_event(event))
        self.assertEqual(1, self.store.count_events(TENANT))
        stored = self.store.get_event(TENANT, event.event_id)
        self.assertIsNotNone(stored)
        self.assertEqual(event.labels, stored.labels)  # type: ignore[union-attr]
        self.assertEqual(event.payload, stored.payload)  # type: ignore[union-attr]
        self.assertEqual("log_tail", stored.source.type)  # type: ignore[union-attr]

    def test_event_is_not_visible_from_another_tenant(self) -> None:
        """Isolation : le même ``event_id`` dans un autre tenant n'est pas lisible."""
        event = self.make_event()
        self.store.insert_event(event)
        self.assertIsNone(self.store.get_event(OTHER_TENANT, event.event_id))
        self.assertEqual(0, self.store.count_events(OTHER_TENANT))

    def test_event_batch_insert_counts_only_new_rows(self) -> None:
        """Insertion par lots : seules les lignes réellement nouvelles sont comptées."""
        self.assertEqual(0, self.store.insert_events([]))
        events = [self.make_event() for _ in range(5)]
        self.assertEqual(5, self.store.insert_events(events))
        self.assertEqual(0, self.store.insert_events(events))

        mixed = [events[0], events[1], self.make_event(), self.make_event()]
        self.assertEqual(2, self.store.insert_events(mixed))
        self.assertEqual(7, self.store.count_events(TENANT))

    def test_event_batch_insert_is_atomic(self) -> None:
        """Un lot trop gros pour une seule instruction passe par plusieurs et reste complet."""
        events = [self.make_event() for _ in range(2500)]
        self.assertEqual(2500, self.store.insert_events(events))
        self.assertEqual(2500, self.store.count_events(TENANT))

    def test_event_queries_filter_and_group(self) -> None:
        """Filtres ``kinds`` / ``source_types`` / ``q`` et comptage par type."""
        self.store.insert_events(
            [
                self.make_event(kind="http.request", labels={"src_ip": "10.0.0.1"}),
                self.make_event(kind="http.request", labels={"src_ip": "10.0.0.2"}),
                self.make_event(kind="log.line", source_type="syslog", labels={"msg": "reboot"}),
                self.make_event(tenant_id=OTHER_TENANT, kind="http.request"),
            ]
        )
        page, _ = self.store.query_events(TENANT, kinds=["http.request"])
        self.assertEqual(2, len(page))
        page, _ = self.store.query_events(TENANT, source_types=["syslog"])
        self.assertEqual(1, len(page))
        page, _ = self.store.query_events(TENANT, q="10.0.0.2")
        self.assertEqual(1, len(page))
        self.assertEqual({"http.request": 2, "log.line": 1}, self.store.events_by_kind(TENANT))
        self.assertEqual(3, self.store.count_events(TENANT))
        self.assertEqual(1, self.store.count_events(OTHER_TENANT))

    def test_event_cursor_pagination_is_stable(self) -> None:
        """La pagination par curseur ne duplique ni n'omet aucun événement."""
        events = [self.make_event() for _ in range(7)]
        self.store.insert_events(events)
        seen: list[str] = []
        cursor = None
        pages = 0
        while True:
            page, cursor = self.store.query_events(TENANT, limit=2, cursor=cursor)
            seen.extend(event.event_id for event in page)
            pages += 1
            if cursor is None:
                break
            self.assertLessEqual(pages, 10, "la pagination ne converge pas")
        self.assertEqual(7, len(seen))
        self.assertEqual(7, len(set(seen)), "un événement est apparu sur deux pages")
        self.assertEqual(sorted(event.event_id for event in events), sorted(seen))

    def test_event_limit_is_clamped(self) -> None:
        """``limit`` est borné : une requête ne peut pas épuiser la mémoire du serveur."""
        self.store.insert_events([self.make_event() for _ in range(3)])
        page, cursor = self.store.query_events(TENANT, limit=10_000)
        self.assertLessEqual(len(page), MAX_PAGE_SIZE)
        self.assertIsNone(cursor)

    def test_invalid_cursor_is_a_storage_error(self) -> None:
        with self.assertRaises(StorageError):
            self.store.query_events(TENANT, cursor="pas-un-curseur-valide!!")

    def test_pending_events_and_marking(self) -> None:
        """Rejeu : lecture sans effet de bord, puis marquage idempotent."""
        events = [self.make_event() for _ in range(3)]
        self.store.insert_events(events)
        pending = self.store.pending_events(limit=10)
        self.assertEqual(3, len(pending))
        self.assertEqual(
            sorted(event.event_id for event in events), sorted(e.event_id for e in pending)
        )
        # La lecture n'a rien marqué : une seconde lecture retourne le même lot.
        self.assertEqual(3, len(self.store.pending_events(limit=10)))

        self.assertEqual(0, self.store.mark_events_processed([]))
        self.assertEqual(
            2, self.store.mark_events_processed([events[0].event_id, events[1].event_id])
        )
        self.assertEqual(0, self.store.mark_events_processed([events[0].event_id]))
        remaining = self.store.pending_events(limit=10)
        self.assertEqual([events[2].event_id], [event.event_id for event in remaining])

    # ----------------------------------------------------------------------------------
    # Findings
    # ----------------------------------------------------------------------------------

    def test_finding_lifecycle_and_dedup_search(self) -> None:
        """Insertion, recherche par déduplication, mise à jour, statuts exclus."""
        finding = self.make_finding()
        self.store.insert_finding(finding)

        found = self.store.find_open_finding(TENANT, "AO-WEB-001", "203.0.113.9")
        self.assertIsNotNone(found)
        self.assertEqual(finding.finding_id, found.finding_id)  # type: ignore[union-attr]
        self.assertIsNone(self.store.find_open_finding(TENANT, "AO-WEB-001", "autre-cle"))
        self.assertIsNone(self.store.find_open_finding(OTHER_TENANT, "AO-WEB-001", "203.0.113.9"))

        updated = self.store.update_finding(
            TENANT,
            finding.finding_id,
            status="acked",
            comment="vu avec l'équipe",
            count=7,
            last_seen=utcnow(),
        )
        self.assertEqual("acked", updated.status)
        self.assertEqual(7, updated.count)
        self.assertEqual("vu avec l'équipe", updated.comment)
        self.assertIsNotNone(
            self.store.find_open_finding(TENANT, "AO-WEB-001", "203.0.113.9"),
            "un finding acquitté reste déduplicable",
        )

        self.store.update_finding(
            TENANT, finding.finding_id, status="closed", resolution="true_positive"
        )
        self.assertIsNone(
            self.store.find_open_finding(TENANT, "AO-WEB-001", "203.0.113.9"),
            "un finding clos ne doit plus absorber de nouveaux événements",
        )

    def test_finding_update_of_unknown_finding_is_not_found(self) -> None:
        with self.assertRaises(NotFoundError):
            self.store.update_finding(TENANT, "fi_inexistant", status="acked")

    def test_finding_update_ignores_unknown_fields(self) -> None:
        finding = self.make_finding()
        self.store.insert_finding(finding)
        updated = self.store.update_finding(TENANT, finding.finding_id, severity=None, bidon=1)
        self.assertEqual("high", updated.severity)

    def test_finding_queries_and_counts(self) -> None:
        """Listes filtrées et compteurs (par sévérité, par statut, top règles)."""
        self.store.insert_finding(self.make_finding(risk_score=90.0, severity="critical"))
        self.store.insert_finding(
            self.make_finding(risk_score=70.0, rule_id="AO-WEB-050", severity="medium")
        )
        self.store.insert_finding(
            self.make_finding(risk_score=10.0, tenant_id=OTHER_TENANT, severity="low")
        )
        self.assertEqual(2, len(self.store.list_findings(TENANT)[0]))
        self.assertEqual(1, len(self.store.list_findings(TENANT, min_risk=80.0)[0]))
        self.assertEqual(1, len(self.store.list_findings(TENANT, severity=["critical"])[0]))
        self.assertEqual(1, len(self.store.list_findings(TENANT, rule_id="AO-WEB-050")[0]))
        # Les deux findings du tenant portent « injection » dans leur titre et leur description.
        self.assertEqual(2, len(self.store.list_findings(TENANT, q="injection")[0]))
        self.assertEqual(0, len(self.store.list_findings(TENANT, status=["closed"])[0]))

        counts = self.store.count_findings(TENANT)
        self.assertEqual({"critical": 1, "medium": 1}, counts["by_severity"])
        self.assertEqual({"open": 2}, counts["by_status"])
        self.assertEqual(2, len(counts["top_rules"]))
        self.assertIsInstance(counts["top_rules"][0]["max_risk"], float)

        windowed = self.store.count_findings(TENANT, since=utcnow())
        self.assertIn("by_status", windowed)

    def test_finding_cursor_pagination_on_both_sort_orders(self) -> None:
        """Les deux tris de la console (``risk_score`` et ``last_seen``) paginent correctement."""
        for index in range(5):
            finding = self.make_finding(risk_score=10.0 * (index + 1))
            finding.last_seen = utcnow()
            self.store.insert_finding(finding)

        for sort in ("risk_score", "last_seen"):
            seen: list[str] = []
            cursor = None
            guard = 0
            while True:
                page, cursor = self.store.list_findings(TENANT, sort=sort, limit=2, cursor=cursor)
                seen.extend(finding.finding_id for finding in page)
                guard += 1
                if cursor is None:
                    break
                self.assertLessEqual(guard, 10, f"pagination {sort} non convergente")
            self.assertEqual(5, len(seen), f"tri {sort} : éléments perdus")
            self.assertEqual(5, len(set(seen)), f"tri {sort} : doublons entre pages")

    # ----------------------------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------------------------

    def test_action_idempotency_is_enforced_by_the_store(self) -> None:
        """Rejouer une exécution ne crée pas de seconde action (clé d'idempotence unique)."""
        finding = self.make_finding()
        self.store.insert_finding(finding)
        action = self.make_action(
            finding_id=finding.finding_id, idempotency_key="acme:block:1.2.3.4:1"
        )
        self.store.insert_action(action)

        duplicate = self.make_action(
            finding_id=finding.finding_id, idempotency_key="acme:block:1.2.3.4:1"
        )
        with self.assertRaises(ConflictError) as raised:
            self.store.insert_action(duplicate)
        self.assertEqual(action.action_id, raised.exception.details.get("action_id"))
        existing = self.store.find_action_by_idempotency("acme:block:1.2.3.4:1")
        self.assertIsNotNone(existing)
        self.assertEqual(action.action_id, existing.action_id)  # type: ignore[union-attr]

    def test_action_lifecycle(self) -> None:
        """Cycle de vie : planification, approbation, exécution, lecture, mise à jour."""
        finding = self.make_finding()
        self.store.insert_finding(finding)
        action = self.make_action(finding_id=finding.finding_id, status="pending_approval")
        self.store.insert_action(action)

        loaded = self.store.get_action(TENANT, action.action_id)
        self.assertIsNotNone(loaded)
        self.assertEqual("pending_approval", loaded.status)  # type: ignore[union-attr]
        self.assertEqual("203.0.113.9", loaded.target.value)  # type: ignore[union-attr]
        self.assertEqual({"target": "203.0.113.9", "duration_seconds": 3600}, loaded.params)  # type: ignore[union-attr]
        self.assertIsNone(self.store.get_action(OTHER_TENANT, action.action_id))

        action.status = "succeeded"
        action.approved_by = "api-key:ci"
        action.approved_at = utcnow()
        action.executed_at = utcnow()
        action.result = {"simulated": True, "blocked": "203.0.113.9"}
        action.audit_seq = 42
        self.store.update_action(action)
        reloaded = self.store.get_action(TENANT, action.action_id)
        self.assertEqual("succeeded", reloaded.status)  # type: ignore[union-attr]
        self.assertEqual("api-key:ci", reloaded.approved_by)  # type: ignore[union-attr]
        self.assertEqual({"simulated": True, "blocked": "203.0.113.9"}, reloaded.result)  # type: ignore[union-attr]
        self.assertEqual(42, reloaded.audit_seq)  # type: ignore[union-attr]

        missing = self.make_action(action_id="ac_inexistant")
        with self.assertRaises(NotFoundError):
            self.store.update_action(missing)

    def test_action_filters_counts_and_cooldown_lookup(self) -> None:
        """Filtres, plafond horaire et recherche de cooldown par cible."""
        finding = self.make_finding()
        self.store.insert_finding(finding)
        succeeded = self.make_action(
            finding_id=finding.finding_id, status="succeeded", target_value="203.0.113.9"
        )
        rejected = self.make_action(
            finding_id=finding.finding_id,
            status="rejected",
            target_value="203.0.113.10",
            playbook="notify",
        )
        self.store.insert_action(succeeded)
        self.store.insert_action(rejected)

        self.assertEqual(2, len(self.store.list_actions(TENANT)[0]))
        self.assertEqual(1, len(self.store.list_actions(TENANT, status=["succeeded"])[0]))
        self.assertEqual(1, len(self.store.list_actions(TENANT, playbook="notify")[0]))
        self.assertEqual(2, len(self.store.list_actions(TENANT, finding_id=finding.finding_id)[0]))
        self.assertEqual([], self.store.list_actions(OTHER_TENANT)[0])

        self.assertEqual({"succeeded": 1, "rejected": 1}, self.store.actions_by_status(TENANT))
        self.assertEqual(1, self.store.count_actions_since(TENANT, "2000-01-01T00:00:00Z"))
        self.assertEqual(
            2,
            self.store.count_actions_since(TENANT, "2000-01-01T00:00:00Z", exclude_failed=False),
        )
        self.assertEqual(
            0, self.store.count_actions_since(TENANT, "2000-01-01T00:00:00Z", playbook="inconnu")
        )

        latest = self.store.last_action_for(TENANT, "block-source-ip", "203.0.113.9")
        self.assertIsNotNone(latest)
        self.assertEqual(succeeded.action_id, latest.action_id)  # type: ignore[union-attr]
        self.assertIsNone(self.store.last_action_for(TENANT, "block-source-ip", "198.51.100.7"))
        self.assertEqual(2, len(self.store.actions_for_finding(TENANT, finding.finding_id)))

    def test_action_cursor_pagination_is_stable(self) -> None:
        finding = self.make_finding()
        self.store.insert_finding(finding)
        for _ in range(5):
            self.store.insert_action(self.make_action(finding_id=finding.finding_id))
        seen: list[str] = []
        cursor = None
        guard = 0
        while True:
            page, cursor = self.store.list_actions(TENANT, limit=2, cursor=cursor)
            seen.extend(action.action_id for action in page)
            guard += 1
            if cursor is None:
                break
            self.assertLessEqual(guard, 10, "pagination des actions non convergente")
        self.assertEqual(5, len(seen))
        self.assertEqual(5, len(set(seen)))

    # ----------------------------------------------------------------------------------
    # Audit
    # ----------------------------------------------------------------------------------

    def test_audit_chain_is_valid_then_tampering_is_detected(self) -> None:
        """La chaîne est valide, et **toute** modification d'un maillon est détectée.

        C'est l'invariant le plus important du produit : sans lui, ``/api/v1/audit/verify``
        n'aurait aucune valeur en investigation.
        """
        chain = AuditChain(self.store)
        first = self.store.append_audit(
            tenant_id=TENANT, actor="api-key:ci", actor_role="responder", action="system.start"
        )
        second = self.store.append_audit(
            tenant_id=TENANT,
            actor="api-key:ci",
            actor_role="responder",
            action="action.execute",
            target={"type": "action", "id": "ac_1"},
            before={"status": "approved"},
            after={"status": "succeeded"},
            context={"dry_run": True},
        )
        third = self.store.append_audit(
            tenant_id=OTHER_TENANT, actor="system", action="tenant.create"
        )

        self.assertLess(first.seq, second.seq)
        self.assertLess(second.seq, third.seq)
        self.assertEqual(
            second.hash, third.prev_hash, "la chaîne est globale, tous tenants confondus"
        )
        self.assertNotEqual("", second.hash)

        verdict = chain.verify()
        self.assertTrue(verdict.valid, verdict.reason)
        self.assertEqual(3, verdict.records)
        self.assertEqual(3, self.store.count_audit(TENANT) + self.store.count_audit(OTHER_TENANT))

        self.tamper_audit(second.seq)
        broken = chain.verify()
        self.assertFalse(broken.valid, "une falsification doit être détectée")
        self.assertEqual(second.seq, broken.broken_at)

    def test_audit_chain_survives_concurrent_appends(self) -> None:
        """Des écritures concurrentes ne cassent jamais la chaîne (verrou transactionnel)."""
        threads_count = 4
        per_thread = 10
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            try:
                for step in range(per_thread):
                    self.store.append_audit(
                        tenant_id=TENANT,
                        actor=f"thread-{index}",
                        actor_role="system",
                        action="action.plan",
                        after={"step": step},
                    )
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(index,), daemon=True)
            for index in range(threads_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=self.CONCURRENCY_TIMEOUT)
            self.assertFalse(thread.is_alive(), "une écriture d'audit est bloquée")
        self.assertEqual([], [str(error) for error in errors])

        records = list(self.store.iter_audit())
        self.assertEqual(threads_count * per_thread, len(records))
        sequences = [record.seq for record in records]
        self.assertEqual(sorted(set(sequences)), sorted(sequences), "numéros de séquence dupliqués")
        verdict = AuditChain(self.store).verify()
        self.assertTrue(verdict.valid, verdict.reason)

    def test_audit_reads_filters_and_pagination(self) -> None:
        """Lecture filtrée, itération ordonnée et pagination par curseur."""
        for index in range(5):
            self.store.append_audit(
                tenant_id=TENANT if index % 2 == 0 else OTHER_TENANT,
                actor="api-key:ci" if index < 3 else "system",
                actor_role="responder",
                action="finding.ack" if index % 2 == 0 else "finding.close",
            )

        page, cursor = self.store.list_audit(TENANT, action="finding.ack", limit=10)
        self.assertEqual(3, len(page))
        self.assertIsNone(cursor)
        self.assertTrue(all(record.action == "finding.ack" for record in page))
        self.assertEqual(2, len(self.store.list_audit(TENANT, actor="api-key:ci", limit=10)[0]))
        self.assertEqual(3, self.store.count_audit(TENANT))

        seen: list[int] = []
        cursor = None
        guard = 0
        while True:
            page, cursor = self.store.list_audit(TENANT, limit=1, cursor=cursor)
            seen.extend(record.seq for record in page)
            guard += 1
            if cursor is None:
                break
            self.assertLessEqual(guard, 10, "pagination d'audit non convergente")
        self.assertEqual(3, len(seen))
        self.assertEqual(
            sorted(seen, reverse=True), seen, "l'audit se lit du plus récent au plus ancien"
        )

        tenant_records = list(self.store.iter_audit(tenant_id=TENANT))
        self.assertEqual(3, len(tenant_records))
        self.assertEqual(
            [record.seq for record in sorted(tenant_records, key=lambda r: r.seq)],
            [record.seq for record in tenant_records],
        )
        all_records = list(self.store.iter_audit())
        self.assertEqual(5, len(all_records))
        self.assertTrue(all(record.context == {} for record in all_records))

    # ----------------------------------------------------------------------------------
    # Collecteurs, suppressions, statistiques, rétention
    # ----------------------------------------------------------------------------------

    def test_collector_runs_are_aggregated(self) -> None:
        """Un run par collecteur est historisé et le dernier état est exposé."""
        self.store.record_collector_run(
            tenant_id=TENANT, collector="web_probe", status="ok", started_at=utcnow(), events=12
        )
        self.store.record_collector_run(
            tenant_id=TENANT,
            collector="web_probe",
            status="partial",
            started_at=utcnow(),
            finished_at=utcnow(),
            events=3,
            findings=1,
            errors=2,
            detail={"reason": "timeout sur 1 cible"},
        )
        stats = self.store.collector_stats(TENANT)
        self.assertEqual(1, len(stats))
        entry = stats["web_probe"]
        self.assertEqual(2, entry["runs"])
        self.assertEqual(15, entry["events"])
        self.assertEqual(1, entry["findings"])
        self.assertEqual(2, entry["errors"])
        self.assertIn(entry["last_status"], {"ok", "partial"})
        self.assertIsInstance(entry["detail"], dict)
        self.assertEqual({}, self.store.collector_stats(OTHER_TENANT))

    def test_suppressions_lifecycle(self) -> None:
        """Une exception couvre une règle, expire, et une exception vide couvre toutes les cibles."""
        from datetime import timedelta

        active = self.store.add_suppression(
            tenant_id=TENANT,
            rule_id="AO-WEB-001",
            dedup_key="203.0.113.9",
            reason="test de charge planifié",
            expires_at=utcnow() + timedelta(days=1),
            created_by="api-key:ci",
        )
        self.assertTrue(active)
        self.assertTrue(self.store.is_suppressed(TENANT, "AO-WEB-001", "203.0.113.9"))
        self.assertFalse(self.store.is_suppressed(TENANT, "AO-WEB-001", "198.51.100.1"))
        self.assertFalse(self.store.is_suppressed(TENANT, "AO-WEB-050", "203.0.113.9"))
        self.assertFalse(self.store.is_suppressed(OTHER_TENANT, "AO-WEB-001", "203.0.113.9"))

        self.store.add_suppression(
            tenant_id=TENANT,
            rule_id="AO-WEB-050",
            dedup_key="",
            reason="règle en cours de calibrage",
            expires_at=utcnow() + timedelta(hours=1),
        )
        self.assertTrue(
            self.store.is_suppressed(TENANT, "AO-WEB-050", "n-importe-quelle-cible"),
            "une exception sans clé couvre toutes les cibles de la règle",
        )

        self.store.add_suppression(
            tenant_id=TENANT,
            rule_id="AO-WEB-099",
            dedup_key="x",
            reason="déjà expirée",
            expires_at=utcnow() - timedelta(minutes=1),
        )
        self.assertFalse(self.store.is_suppressed(TENANT, "AO-WEB-099", "x"))
        listed = self.store.list_suppressions(TENANT)
        self.assertEqual(2, len(listed), "les exceptions expirées ne sont pas listées")
        self.assertTrue(all(isinstance(item["expires_at"], str) for item in listed))
        self.assertEqual([], self.store.list_suppressions(OTHER_TENANT))

    def test_stats_overview(self) -> None:
        """Le tableau de bord agrège les événements, findings et actions de la fenêtre."""
        finding = self.make_finding(risk_score=91.5, severity="critical")
        self.store.insert_finding(finding)
        self.store.insert_events([self.make_event(), self.make_event(kind="log.line")])
        planned = self.make_action(finding_id=finding.finding_id, status="succeeded")
        self.store.insert_action(planned)
        self.store.append_audit(tenant_id=TENANT, actor="api-key:ci", action="action.execute")

        overview = self.store.stats_overview(TENANT, window_hours=24)
        self.assertEqual(TENANT, overview.tenant_id)
        self.assertEqual(2, overview.events_total)
        self.assertEqual({"http.request": 1, "log.line": 1}, overview.events_by_kind)
        self.assertEqual(1, overview.findings_total)
        self.assertEqual(1, overview.findings_open)
        self.assertEqual({"critical": 1}, overview.findings_by_severity)
        self.assertEqual(1, overview.actions_total)
        self.assertIn("succeeded", overview.actions_by_status)
        self.assertEqual(1, overview.audit_records)
        self.assertEqual("supervised", overview.autonomy)
        self.assertTrue(overview.dry_run)
        # MTTD : ``created_at`` et ``first_seen`` sont posés par le modèle, l'écart est donc nul ou
        # positif selon l'arrondi à la milliseconde — jamais négatif, et ``None`` sans donnée.
        self.assertTrue(overview.mttd_seconds is None or overview.mttd_seconds >= 0)
        # MTTD/MTTR ne valent jamais 0 par défaut : aucun finding clos ⇒ MTTR inconnu.
        self.assertIsNone(overview.mttr_seconds)

    def test_purge_applies_retention_by_bounded_batches(self) -> None:
        """Rétention : les événements anciens partent, les récents restent, l'audit est préservé."""
        from datetime import timedelta

        old = self.make_event(ts=utcnow() - timedelta(days=40))
        recent = self.make_event(ts=utcnow())
        self.store.insert_events([old, recent])
        expired = self.store.add_suppression(
            tenant_id=TENANT,
            rule_id="AO-WEB-001",
            dedup_key="",
            reason="expirée",
            expires_at=utcnow() - timedelta(days=1),
        )
        self.assertTrue(expired)
        self.store.append_audit(tenant_id=TENANT, actor="system", action="system.start")

        result = self.store.purge(retention_days=30, audit_retention_days=365)
        self.assertEqual({"events", "suppressions", "audit"}, set(result))
        self.assertGreaterEqual(result["events"], 1, "l'événement ancien doit être purgé")
        self.assertGreaterEqual(result["suppressions"], 1)
        self.assertEqual(0, result["audit"], "le journal d'audit n'est jamais purgé par défaut")
        self.assertIsNone(self.store.get_event(TENANT, old.event_id))
        self.assertIsNotNone(self.store.get_event(TENANT, recent.event_id))
        self.assertEqual(0, len(self.store.list_suppressions(TENANT)))
        self.assertEqual(1, self.store.count_audit(TENANT))

    def test_health_and_close(self) -> None:
        """``health()`` interroge réellement la base ; un magasin fermé refuse de servir."""
        self.assertTrue(self.store.health())
        self.store.close()
        self.assertFalse(self.store.health())
        with self.assertRaises(StorageError):
            self.store.get_tenant(TENANT)


class SqliteStoreConformanceTest(StoreConformanceTest):
    """Conformité de l'implémentation SQLite (référence) — toujours exécutée."""

    def store_factory(self, root: Path) -> Store:
        store = Store(root / "conformance.db")
        store.init_schema()
        return store

    def tamper_audit(self, seq: int) -> None:
        """Modifie l'acteur d'un maillon en SQL direct (aucun trigger d'immuabilité dans le DDL)."""
        with self.store._write_lock:
            self.store.connection.execute(
                "UPDATE audit_log SET actor = 'attaquant' WHERE seq = ?", (seq,)
            )


@unittest.skipUnless(
    postgres_dsn(),
    f"PostgreSQL indisponible : définir {POSTGRES_DSN_ENV} (voir le job « postgres » de la CI)",
)
class PostgresStoreConformanceTest(StoreConformanceTest):
    """Conformité de l'implémentation PostgreSQL/TimescaleDB — ignorée sans serveur."""

    def store_factory(self, root: Path) -> PostgresStore:
        store = PostgresStore(postgres_dsn(), env="dev", max_size=8, sslmode="prefer")
        store.init_schema()
        return store

    def reset_store(self) -> None:
        """Les tests partagent la même base : on repart d'un schéma vide à chaque test."""
        self.store.reset_database()

    def tamper_audit(self, seq: int) -> None:
        self.store._execute("UPDATE audit_log SET actor = %s WHERE seq = %s", ("attaquant", seq))


@unittest.skipUnless(
    postgres_dsn(),
    f"PostgreSQL indisponible : définir {POSTGRES_DSN_ENV} (voir le job « postgres » de la CI)",
)
class PostgresClaimConformanceTest(unittest.TestCase):
    """Réservation atomique des événements à rejouer (capacité propre à PostgreSQL).

    ``pending_events`` peut retourner le même lot à deux processus ; ``claim_pending_events``
    réserve au contraire chaque événement à un seul worker, avec un bail qui redevient réclamable
    après expiration — c'est ce qui rend un rejeu multi-nœuds sûr.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="thot-storage-claim-")
        self.store = PostgresStore(postgres_dsn(), env="dev", max_size=4, sslmode="prefer")
        self.store.init_schema()
        self.store.reset_database()
        self.store.upsert_tenant(Tenant(tenant_id=TENANT, name="ACME SAS"))
        self.events = [
            Event(
                event_id=new_id("ev_"),
                tenant_id=TENANT,
                kind="generic",
                source=EventSource(type="log_tail"),
            )
            for _ in range(4)
        ]
        self.store.insert_events(self.events)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_claim_is_exclusive_then_reclaimable_after_lease(self) -> None:
        claimed = self.store.claim_pending_events(limit=2, lease_seconds=300, worker="worker-1")
        self.assertEqual(2, len(claimed))
        claimed_ids = {event.event_id for event in claimed}

        # Un second worker ne reçoit pas les mêmes événements : ils sont réservés.
        other = self.store.claim_pending_events(limit=10, lease_seconds=300, worker="worker-2")
        self.assertEqual(2, len(other))
        self.assertEqual(set(), claimed_ids & {event.event_id for event in other})

        # Tous les événements sont désormais réservés.
        self.assertEqual([], self.store.claim_pending_events(limit=10, worker="worker-3"))

        # Un bail nul rend immédiatement les événements réclamables (worker mort).
        reclaimed = self.store.claim_pending_events(limit=10, lease_seconds=0, worker="worker-4")
        self.assertEqual(4, len(reclaimed))

    def test_marking_a_claimed_event_clears_the_claim(self) -> None:
        claimed = self.store.claim_pending_events(limit=1, worker="worker-1")
        event = claimed[0]
        self.assertEqual(1, self.store.mark_events_processed([event.event_id]))
        rows = self.store._fetchall(
            "SELECT claimed_by, claimed_at, processed FROM events WHERE event_id = %s",
            (event.event_id,),
        )
        self.assertTrue(rows[0]["processed"])
        self.assertIsNone(rows[0]["claimed_by"])
        self.assertIsNone(rows[0]["claimed_at"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
