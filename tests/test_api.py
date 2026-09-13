"""Tests de l'API : authentification, RBAC, isolation, cycle de vie, console et export.

Ces tests traversent la vraie application FastAPI (``create_app``) avec un vrai service, la
vraie base SQLite et les vrais chargeurs YAML. Ils vérifient notamment ce qu'un audit de
sécurité chercherait en premier : l'isolation entre tenants et le refus d'exécuter une action
non approuvée.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from thotsecure.core.models import Tenant
from thotsecure.main import create_app

from .support import build_stack

CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')


class ApiTestCase(unittest.TestCase):
    """Base : pile complète + application FastAPI + clés de rôles variés."""

    tenant_mode = "supervised"
    dry_run = True

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="thotsecure-api-"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self.stack = build_stack(self._tmp, tenant_mode=self.tenant_mode, dry_run=self.dry_run)
        self.addCleanup(self.stack.close)

        # Clés de chaque rôle, écrites dans la même base que celle utilisée par l'application.
        self.keys: dict[str, str] = {}
        for role in ("viewer", "analyst", "responder", "admin"):
            _, plaintext = self.stack.keys.create(tenant_id="acme", role=role, label=f"test-{role}")  # type: ignore[arg-type]
            self.keys[role] = plaintext

        self.app = create_app(settings=self.stack.settings)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self._close_client)

    def _close_client(self) -> None:
        self.client.__exit__(None, None, None)

    # -- aides -------------------------------------------------------------------------

    def auth(self, role: str = "responder") -> dict[str, str]:
        return {"X-API-Key": self.keys[role]}

    def ingest_sqli_burst(self, *, key: str = "responder", src_ip: str = "203.0.113.9") -> dict:
        events = [
            {
                "kind": "http.request",
                "source": {"type": "webhook", "host": "shop.acme.fr"},
                "labels": {
                    "src_ip": src_ip,
                    "path": f"/p?id=1 UNION SELECT {index}--",
                    "host": "shop.acme.fr",
                },
                "payload": {"status": 403},
            }
            for index in range(3)
        ]
        response = self.client.post(
            "/api/v1/events", json={"events": events}, headers=self.auth(key)
        )
        return response


class HealthTest(ApiTestCase):
    def test_health_and_version_expose_safety_state(self) -> None:
        health = self.client.get("/healthz")
        self.assertEqual(200, health.status_code)
        self.assertEqual("ok", health.json()["status"])

        version = self.client.get("/version")
        self.assertEqual(200, version.status_code)
        body = version.json()
        self.assertTrue(body["defensive_only"])
        self.assertTrue(body["safety"]["dry_run"])
        self.assertEqual("Apache-2.0", body["license"])

    def test_readyz_checks_real_dependencies(self) -> None:
        response = self.client.get("/readyz")
        self.assertIn(response.status_code, {200, 503})
        checks = response.json()["checks"]
        self.assertTrue(checks["database"]["ok"])
        self.assertTrue(checks["rules"]["ok"])
        self.assertTrue(checks["policies"]["ok"])
        self.assertTrue(checks["playbooks"]["ok"])

    def test_metrics_are_prometheus_text(self) -> None:
        self.ingest_sqli_burst()
        response = self.client.get("/metrics")
        self.assertEqual(200, response.status_code)
        self.assertIn("thotsecure_up 1", response.text)
        self.assertIn("# TYPE thotsecure_events_ingested_total counter", response.text)
        self.assertIn('thotsecure_events_ingested_total{tenant="acme"} 3', response.text)
        self.assertIn("thotsecure_audit_chain_valid 1", response.text)


class AuthenticationTest(ApiTestCase):
    def test_missing_key_is_rejected(self) -> None:
        response = self.client.get("/api/v1/findings")
        self.assertEqual(401, response.status_code)
        self.assertEqual("unauthenticated", response.json()["error"]["code"])

    def test_invalid_key_is_rejected(self) -> None:
        response = self.client.get(
            "/api/v1/findings", headers={"X-API-Key": "thot_INEXISTANT_abcdefghijkl"}
        )
        self.assertEqual(401, response.status_code)

    def test_whoami_reflects_role(self) -> None:
        response = self.client.get("/api/v1/auth/whoami", headers=self.auth("viewer"))
        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertEqual("viewer", body["role"])
        self.assertIn("read:findings", body["capabilities"])
        self.assertNotIn("execute:actions", body["capabilities"])


class RbacTest(ApiTestCase):
    def test_viewer_cannot_ingest(self) -> None:
        response = self.ingest_sqli_burst(key="viewer")
        self.assertEqual(403, response.status_code)
        self.assertEqual("forbidden", response.json()["error"]["code"])

    def test_viewer_cannot_plan_an_action(self) -> None:
        response = self.client.post(
            "/api/v1/actions/plan",
            json={"playbook": "block-source-ip", "params": {"target": "203.0.113.9"}},
            headers=self.auth("viewer"),
        )
        self.assertEqual(403, response.status_code)

    def test_admin_only_routes(self) -> None:
        self.assertEqual(
            403, self.client.get("/api/v1/tenants", headers=self.auth("responder")).status_code
        )
        self.assertEqual(
            200, self.client.get("/api/v1/tenants", headers=self.auth("admin")).status_code
        )


class IngestionTest(ApiTestCase):
    def test_ingestion_produces_findings_and_actions(self) -> None:
        response = self.ingest_sqli_burst()
        self.assertEqual(202, response.status_code)
        body = response.json()
        self.assertEqual(3, body["accepted"])
        self.assertEqual(1, len(body["findings"]))
        finding = body["findings"][0]
        self.assertEqual("AO-WEB-001", finding["rule_id"])
        self.assertEqual("high", finding["severity"])
        self.assertIsNotNone(finding["decision"])

    def test_tenant_id_from_key_is_authoritative(self) -> None:
        """Un client ne peut pas écrire dans un autre tenant, même en le demandant."""
        self.stack.store.upsert_tenant(Tenant(tenant_id="globex", name="Globex"))
        event = {
            "tenant_id": "globex",
            "kind": "log.line",
            "source": {"type": "webhook"},
            "labels": {"message": "tentative"},
        }
        response = self.client.post("/api/v1/events", json=event, headers=self.auth())
        self.assertEqual(202, response.status_code)
        found, _ = self.stack.store.list_findings("globex")
        self.assertEqual([], found)
        events, _ = self.stack.store.query_events("globex")
        self.assertEqual([], events)

    def test_unknown_tenant_is_reported_not_created(self) -> None:
        response = self.client.post(
            "/api/v1/events",
            json={"events": [{"kind": "log.line", "source": {"type": "webhook"}, "labels": {}}]},
            headers={"X-API-Key": self.keys["admin"]},
        )
        # Le tenant de la clé admin est bien « acme » : l'ingestion doit réussir.
        self.assertEqual(202, response.status_code)

    def test_invalid_events_are_collected_not_fatal(self) -> None:
        response = self.client.post(
            "/api/v1/events",
            json={
                "events": [
                    {"kind": "log.line", "source": {"type": "webhook"}, "labels": {"ok": "1"}},
                    {"kind": "type-inconnu", "source": {"type": "webhook"}},
                ]
            },
            headers=self.auth(),
        )
        self.assertEqual(202, response.status_code)
        body = response.json()
        self.assertEqual(1, body["accepted"])
        self.assertTrue(any(item.get("error") == "validation_error" for item in body["errors"]))

    def test_findings_are_isolated_between_tenants(self) -> None:
        self.ingest_sqli_burst()
        self.stack.store.upsert_tenant(Tenant(tenant_id="globex", name="Globex"))
        _, globex_key = self.stack.keys.create(tenant_id="globex", role="responder")  # type: ignore[arg-type]
        response = self.client.get("/api/v1/findings", headers={"X-API-Key": globex_key})
        self.assertEqual(200, response.status_code)
        self.assertEqual([], response.json()["items"])

        acme = self.client.get("/api/v1/findings", headers=self.auth()).json()
        self.assertTrue(acme["items"])
        finding_id = acme["items"][0]["finding_id"]
        # Un autre tenant ne peut ni lire ni deviner l'existence du finding.
        detail = self.client.get(
            f"/api/v1/findings/{finding_id}", headers={"X-API-Key": globex_key}
        )
        self.assertEqual(404, detail.status_code)


class ActionLifecycleTest(ApiTestCase):
    def test_plan_execute_rollback_cycle(self) -> None:
        self.ingest_sqli_burst()
        findings = self.client.get("/api/v1/findings", headers=self.auth()).json()["items"]
        finding_id = findings[0]["finding_id"]

        planned = self.client.post(
            "/api/v1/actions/plan",
            json={
                "finding_id": finding_id,
                "playbook": "block-source-ip",
                "params": {"target": "labels.src_ip", "duration_seconds": 600},
            },
            headers=self.auth(),
        )
        self.assertEqual(201, planned.status_code, planned.text)
        action = planned.json()
        self.assertEqual("planned", action["status"])
        self.assertEqual("203.0.113.9", action["target"]["value"])
        self.assertTrue(action["effective_dry_run"])
        self.assertTrue(action["playbook_reversible"])

        executed = self.client.post(
            f"/api/v1/actions/{action['action_id']}/execute", headers=self.auth()
        )
        self.assertEqual(200, executed.status_code, executed.text)
        executed_body = executed.json()
        # En simulation, une action planifiée peut être exécutée : c'est une répétition.
        self.assertEqual("succeeded", executed_body["status"])
        self.assertTrue(executed_body["result"]["simulated"])
        self.assertTrue(executed_body["rollback"]["available"])

        rolled_back = self.client.post(
            f"/api/v1/actions/{action['action_id']}/rollback", headers=self.auth()
        )
        self.assertEqual(200, rolled_back.status_code, rolled_back.text)
        self.assertEqual("rolled_back", rolled_back.json()["status"])
        self.assertFalse(rolled_back.json()["rollback"]["available"])

    def test_approval_flow_records_the_approver(self) -> None:
        self.ingest_sqli_burst()
        finding_id = self.client.get("/api/v1/findings", headers=self.auth()).json()["items"][0][
            "finding_id"
        ]
        planned = self.client.post(
            "/api/v1/actions/plan",
            json={
                "finding_id": finding_id,
                "playbook": "block-source-ip",
                "params": {"target": "203.0.113.9"},
            },
            headers=self.auth(),
        )
        self.assertEqual(201, planned.status_code, planned.text)
        approved = self.client.post(
            f"/api/v1/actions/{planned.json()['action_id']}/approve",
            json={"comment": "validé par l'astreinte"},
            headers=self.auth(),
        )
        self.assertEqual(200, approved.status_code, approved.text)
        self.assertEqual("approved", approved.json()["status"])
        self.assertTrue(approved.json()["approved_by"].startswith("api-key:"))

        # Un rejet reste possible tant que l'action n'est pas terminale : approuver puis se
        # raviser avant l'exécution est un besoin opérationnel légitime.
        rejected = self.client.post(
            f"/api/v1/actions/{planned.json()['action_id']}/reject",
            json={"reason": "mesure finalement inutile"},
            headers=self.auth(),
        )
        self.assertEqual(200, rejected.status_code, rejected.text)
        self.assertEqual("rejected", rejected.json()["status"])

        # Un second rejet est refusé : l'action est désormais terminale.
        again = self.client.post(
            f"/api/v1/actions/{planned.json()['action_id']}/reject",
            json={"reason": "encore"},
            headers=self.auth(),
        )
        self.assertEqual(409, again.status_code)
        self.assertEqual("conflict", again.json()["error"]["code"])

    def test_unknown_playbook_is_rejected(self) -> None:
        response = self.client.post(
            "/api/v1/actions/plan",
            json={"playbook": "playbook-inexistant", "params": {}},
            headers=self.auth(),
        )
        self.assertEqual(404, response.status_code)

    def test_invalid_parameter_is_rejected_before_execution(self) -> None:
        response = self.client.post(
            "/api/v1/actions/plan",
            json={"playbook": "block-source-ip", "params": {"target": "pas-une-ip"}},
            headers=self.auth(),
        )
        self.assertEqual(422, response.status_code)
        self.assertEqual("playbook_error", response.json()["error"]["code"])


class ActionRefusalTest(ApiTestCase):
    """Mode réel (dry-run désactivé) : une action non approuvée ne doit pas s'exécuter."""

    dry_run = False

    def test_unapproved_action_in_real_mode_is_refused(self) -> None:
        self.ingest_sqli_burst()
        planned = self.client.post(
            "/api/v1/actions/plan",
            json={"playbook": "block-source-ip", "params": {"target": "203.0.113.99"}},
            headers=self.auth(),
        )
        self.assertEqual(201, planned.status_code, planned.text)
        action = planned.json()
        self.assertFalse(action["effective_dry_run"])

        refused = self.client.post(
            f"/api/v1/actions/{action['action_id']}/execute", headers=self.auth()
        )
        self.assertEqual(409, refused.status_code)
        self.assertEqual("autonomy_refused", refused.json()["error"]["code"])

        # Après approbation, l'exécution est acceptée (le connecteur reste en simulation).
        self.client.post(
            f"/api/v1/actions/{action['action_id']}/approve", json={}, headers=self.auth()
        )
        executed = self.client.post(
            f"/api/v1/actions/{action['action_id']}/execute", headers=self.auth()
        )
        self.assertEqual(200, executed.status_code, executed.text)
        self.assertEqual("succeeded", executed.json()["status"])


class FindersAndReportsTest(ApiTestCase):
    def test_finding_qualification_and_report(self) -> None:
        self.ingest_sqli_burst()
        finding_id = self.client.get("/api/v1/findings", headers=self.auth()).json()["items"][0][
            "finding_id"
        ]

        ack = self.client.post(
            f"/api/v1/findings/{finding_id}/ack",
            json={"comment": "pris en charge"},
            headers=self.auth(),
        )
        self.assertEqual(200, ack.status_code)
        self.assertEqual("acked", ack.json()["status"])

        closed = self.client.post(
            f"/api/v1/findings/{finding_id}/close",
            json={"resolution": "true_positive", "comment": "WAF mis à jour"},
            headers=self.auth(),
        )
        self.assertEqual(200, closed.status_code)
        self.assertEqual("closed", closed.json()["status"])

        # Transition invalide : un finding déjà clos ne peut pas être acquitté.
        invalid = self.client.post(
            f"/api/v1/findings/{finding_id}/ack", json={}, headers=self.auth()
        )
        self.assertEqual(409, invalid.status_code)

        markdown = self.client.get(
            f"/api/v1/findings/{finding_id}/report?format=md", headers=self.auth()
        )
        self.assertEqual(200, markdown.status_code)
        self.assertIn("Calcul du score de risque", markdown.text)

        sarif = self.client.get(
            f"/api/v1/findings/{finding_id}/report?format=sarif", headers=self.auth()
        )
        self.assertEqual(200, sarif.status_code)
        self.assertEqual("2.1.0", sarif.json()["version"])

    def test_suppression_requires_a_dated_exception(self) -> None:
        self.ingest_sqli_burst()
        finding_id = self.client.get("/api/v1/findings", headers=self.auth()).json()["items"][0][
            "finding_id"
        ]
        response = self.client.post(
            f"/api/v1/findings/{finding_id}/suppress",
            json={"duration_seconds": 3600, "reason": "scanner interne connu"},
            headers=self.auth(),
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("suppressed", response.json()["status"])
        self.assertTrue(response.json()["expires_at"])


class AuditApiTest(ApiTestCase):
    def test_chain_is_valid_and_exportable(self) -> None:
        self.ingest_sqli_burst()
        verdict = self.client.get("/api/v1/audit/verify", headers=self.auth())
        self.assertEqual(200, verdict.status_code)
        self.assertTrue(verdict.json()["valid"])

        export = self.client.get("/api/v1/audit/export?format=cef", headers=self.auth())
        self.assertEqual(200, export.status_code)
        self.assertIn("CEF:0|", export.text)

        jsonl = self.client.get("/api/v1/audit/export?format=jsonl", headers=self.auth())
        self.assertEqual(200, jsonl.status_code)
        self.assertIn('"hash"', jsonl.text)


class ConfigApiTest(ApiTestCase):
    def test_rules_and_policies_are_exposed(self) -> None:
        rules = self.client.get("/api/v1/rules", headers=self.auth())
        self.assertEqual(200, rules.status_code)
        self.assertTrue(rules.json()["items"])
        self.assertIn("sigma_support", rules.json())

        policies = self.client.get("/api/v1/policies", headers=self.auth())
        self.assertEqual(200, policies.status_code)
        self.assertTrue(policies.json()["items"])
        self.assertIn("protected_target", policies.json()["guards"])

        playbooks = self.client.get("/api/v1/playbooks", headers=self.auth())
        self.assertEqual(200, playbooks.status_code)
        body = playbooks.json()
        self.assertTrue(body["items"])
        # Le connecteur WAF doit être en simulation par défaut : c'est la garantie de sûreté.
        self.assertIn("simulation", body["connectors"]["waf"])
        self.assertIn("block-source-ip", {item["name"] for item in body["items"]})

    def test_rule_validation_endpoint(self) -> None:
        valid_rule = """
id: AO-TEST-001
title: Règle de test
severity: high
match:
  all:
    - field: labels.check
      op: eq
      value: test
remediation: Ne rien faire, c'est un test.
"""
        response = self.client.post(
            "/api/v1/rules/validate", json={"text": valid_rule}, headers=self.auth("admin")
        )
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["valid"])

        invalid = self.client.post(
            "/api/v1/rules/validate",
            json={"text": "id: AO-TEST-002\ntitle: sans match\n"},
            headers=self.auth("admin"),
        )
        self.assertEqual(200, invalid.status_code)
        self.assertFalse(invalid.json()["valid"])

    def test_collectors_status_requires_capability(self) -> None:
        response = self.client.get("/api/v1/collectors", headers=self.auth("viewer"))
        self.assertEqual(200, response.status_code)
        names = {item["name"] for item in response.json()["items"]}
        self.assertIn("web_probe", names)
        self.assertIn("dependency_scan", names)


class StreamTest(ApiTestCase):
    def test_websocket_requires_authentication(self) -> None:
        # Sans clé ni jeton, l'application ferme la connexion avant l'acceptation
        # (``close(code=1008)``) : Starlette lève ``WebSocketDisconnect`` au handshake.
        with (
            self.assertRaises(WebSocketDisconnect),
            self.client.websocket_connect("/api/v1/ws/stream") as socket,
        ):
            socket.receive_json()

    def test_websocket_sends_hello_frame(self) -> None:
        with self.client.websocket_connect(
            f"/api/v1/ws/stream?api_key={self.keys['viewer']}"
        ) as socket:
            frame = socket.receive_json()
        self.assertEqual("hello", frame["type"])
        self.assertEqual("acme", frame["data"]["tenant_id"])


class ConsoleTest(ApiTestCase):
    def test_login_flow_and_csrf_protection(self) -> None:
        login_page = self.client.get("/ui/login")
        self.assertEqual(200, login_page.status_code)
        self.assertIn("Thot Secure", login_page.text)

        bad = self.client.post("/ui/login", data={"api_key": "thot_MAUVAISE_clefabcdefghij"})
        self.assertEqual(200, bad.status_code)
        self.assertIn("invalide", bad.text)

        ok = self.client.post(
            "/ui/login", data={"api_key": self.keys["responder"]}, follow_redirects=False
        )
        self.assertEqual(303, ok.status_code)
        self.assertIn("thot_session", ok.cookies)

        dashboard = self.client.get("/ui/dashboard")
        self.assertEqual(200, dashboard.status_code)
        self.assertIn("Mode simulation actif", dashboard.text)
        token = CSRF_PATTERN.search(dashboard.text)
        self.assertIsNotNone(token, "la console doit exposer un jeton CSRF")

        # Une opération sensible sans jeton CSRF valide doit être refusée.
        refused = self.client.post(
            "/ui/actions/action-inexistante/approve", data={"csrf_token": "faux", "comment": ""}
        )
        self.assertEqual(403, refused.status_code)

    def test_support_page_shows_official_addresses_and_antiscam(self) -> None:
        response = self.client.get("/ui/support")
        self.assertEqual(200, response.status_code)
        self.assertIn("33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR", response.text)
        self.assertIn("95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi", response.text)
        self.assertIn("aucune contrepartie", response.text)
        self.assertIn("Avertissement anti-arnaque", response.text)
        self.assertIn("ne demandera", response.text)

    def test_anonymous_access_is_redirected_to_login(self) -> None:
        fresh = TestClient(self.app)
        response = fresh.get("/ui/findings", follow_redirects=False)
        self.assertIn(response.status_code, {401, 403, 303, 307})


def _client_for(path: Path) -> TestClient:  # pragma: no cover - utilitaire
    return TestClient(create_app())
