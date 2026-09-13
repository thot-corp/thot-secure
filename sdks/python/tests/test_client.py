"""Tests du client Thot Secure — exécutables **hors ligne**.

Aucun réseau n'est utilisé : la couche transport est simulée (``FakeTransport``) et injectée
dans ``ThotSecureClient``. Cela vérifie exactement ce que le SDK envoie (URL, méthode, en-têtes,
corps, paramètres) et comment il interprète les réponses.

Exécution ::

    python -m unittest discover -s sdks/python/tests -t sdks/python -v
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest
import warnings
from typing import Any
from unittest import mock

# Permet d'exécuter les tests depuis n'importe quel répertoire de travail.
_SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

from thotsecure_sdk import Event, ThotSecureClient
from thotsecure_sdk.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    ServerError,
    ThotSecureError,
    TransportError,
    ValidationError,
    redact_url,
)
from thotsecure_sdk.transport import (
    HttpRequest,
    HttpResponse,
    RetryingTransport,
    Transport,
    is_retry_safe,
    parse_retry_after,
)

BASE_URL = "https://aegis.example.test"
API_KEY = "ao_test_key_do_not_log"
TENANT = "acme"


def json_response(
    status: int = 200,
    payload: Any = None,
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    """Fabrique une ``HttpResponse`` JSON (ou vide si ``payload`` est ``None`` et statut 204)."""
    if payload is None and status == 204:
        content = b""
    else:
        content = json.dumps(payload if payload is not None else {}).encode("utf-8")
    all_headers = {"Content-Type": "application/json"}
    all_headers.update(headers or {})
    return HttpResponse(status_code=status, headers=all_headers, content=content)


class FakeTransport(Transport):
    """Transport simulé : enregistre les requêtes et rejoue une file de réponses."""

    def __init__(self, responses: list[Any] | None = None, default: Any = None) -> None:
        self.requests: list[HttpRequest] = []
        self.responses: list[Any] = list(responses or [])
        self.default = default
        self.closed = False

    def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if self.responses:
            item = self.responses.pop(0)
        elif self.default is not None:
            item = self.default
        else:
            raise AssertionError(f"requête inattendue : {request.method} {request.url}")
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            item = item(request)
        return item

    def close(self) -> None:
        self.closed = True

    # -- aides de test -------------------------------------------------------------

    @property
    def last(self) -> HttpRequest:
        if not self.requests:
            raise AssertionError("aucune requête enregistrée")
        return self.requests[-1]

    def body(self, index: int = -1) -> Any:
        content = self.requests[index].content
        if content is None:
            return None
        return json.loads(content.decode("utf-8"))


class ClientTestCase(unittest.TestCase):
    """Base commune : client + transport simulé + horloge de sommeil contrôlée."""

    def setUp(self) -> None:
        self.sleeps: list[float] = []

    def make_client(self, transport: Transport, **kwargs: Any) -> ThotSecureClient:
        params: dict[str, Any] = {
            "base_url": BASE_URL,
            "api_key": API_KEY,
            "tenant_id": TENANT,
            "transport": transport,
            "sleep": self.sleeps.append,
            "rand": lambda: 0.0,
        }
        params.update(kwargs)
        return ThotSecureClient(**params)


# ======================================================================================
# URL, méthode, en-têtes, sérialisation
# ======================================================================================


class TestRequestShape(ClientTestCase):
    def test_get_tenant_builds_url_and_headers(self) -> None:
        fake = FakeTransport([json_response(200, {"tenant_id": TENANT, "name": "ACME"})])
        client = self.make_client(fake)

        tenant = client.get_tenant()

        self.assertEqual(fake.last.method, "GET")
        self.assertEqual(fake.last.url, BASE_URL + "/api/v1/tenants/acme")
        self.assertEqual(fake.last.headers["X-API-Key"], API_KEY)
        self.assertEqual(fake.last.headers["Accept"], "application/json")
        self.assertTrue(fake.last.headers["User-Agent"].startswith("thotsecure-sdk-python/"))
        self.assertIsNone(fake.last.content)
        self.assertEqual(tenant.tenant_id, TENANT)
        self.assertEqual(tenant.name, "ACME")

    def test_explicit_tenant_argument_wins_over_default(self) -> None:
        fake = FakeTransport([json_response(200, {"tenant_id": "globex"})])
        client = self.make_client(fake)

        client.get_tenant("globex")

        self.assertEqual(fake.last.url, BASE_URL + "/api/v1/tenants/globex")

    def test_missing_tenant_raises_client_validation_error(self) -> None:
        fake = FakeTransport()
        client = self.make_client(fake, tenant_id=None)

        with self.assertRaises(ValidationError):
            client.get_tenant()
        self.assertEqual(fake.requests, [])

    def test_query_parameters_are_serialized_and_none_dropped(self) -> None:
        fake = FakeTransport([json_response(200, {"items": []})])
        client = self.make_client(fake)

        client.list_findings(status="open", severity="critical", min_risk=70, limit=25)

        url = fake.last.full_url()
        self.assertIn("/api/v1/findings?", url)
        self.assertIn("status=open", url)
        self.assertIn("severity=critical", url)
        self.assertIn("min_risk=70", url)
        self.assertIn("limit=25", url)
        self.assertNotIn("cursor=", url)
        self.assertNotIn("rule_id=", url)

    def test_boolean_query_parameter_lowercased(self) -> None:
        fake = FakeTransport([json_response(200, {"ok": True})])
        client = self.make_client(fake)

        client._request("GET", "/thing", params=client._qparams(flag=True, other=False))

        self.assertIn("flag=true", fake.last.full_url())
        self.assertIn("other=false", fake.last.full_url())

    def test_public_healthz_has_no_api_key_header(self) -> None:
        fake = FakeTransport([json_response(200, {"status": "ok", "version": "0.1.0", "uptime_s": 12})])
        client = self.make_client(fake)

        payload = client.healthz()

        self.assertEqual(fake.last.url, BASE_URL + "/healthz")
        self.assertNotIn("X-API-Key", fake.last.headers)
        self.assertEqual(payload["status"], "ok")

    def test_ingest_event_serializes_contract_fields(self) -> None:
        fake = FakeTransport(
            [json_response(202, {"accepted": 1, "rejected": 0, "event_ids": ["e1"], "findings": []})]
        )
        client = self.make_client(fake)
        event = Event.from_dict(
            {
                "event_id": "e1",
                "schema_version": "1",
                "tenant_id": TENANT,
                "ts": "2026-02-14T10:00:00.123Z",
                "kind": "http.request",
                "source": {"type": "web_probe", "name": "prod-edge", "host": "shop.acme.fr"},
                "severity_hint": "info",
                "labels": {"src_ip": "203.0.113.9", "path": "/login", "method": "POST"},
                "payload": {"status": 403},
                "raw_ref": None,
            }
        )

        result = client.ingest_event(event)

        self.assertEqual(fake.last.method, "POST")
        self.assertEqual(fake.last.headers["Content-Type"], "application/json")
        body = fake.body()
        self.assertEqual(body["kind"], "http.request")
        self.assertEqual(body["labels"]["src_ip"], "203.0.113.9")
        # Noms de champs strictement snake_case du contrat §3.
        self.assertIn("severity_hint", body)
        self.assertNotIn("riskScore", json.dumps(body))
        self.assertEqual(result.accepted, 1)
        self.assertEqual(result.event_ids, ["e1"])

    def test_ingest_batch_wraps_events_and_chunks_over_500(self) -> None:
        fake = FakeTransport(
            default=json_response(202, {"accepted": 1, "rejected": 0, "event_ids": [], "findings": []})
        )
        client = self.make_client(fake)
        events = [{"tenant_id": TENANT, "kind": "log.line", "labels": {"n": i}} for i in range(501)]

        result = client.ingest_events(events)

        self.assertEqual(len(fake.requests), 2)
        first = fake.body(0)
        self.assertEqual(len(first["events"]), 500)
        self.assertEqual(len(fake.body(1)["events"]), 1)
        self.assertEqual(result.accepted, 2)

    def test_ingest_events_rejects_invalid_chunk_size(self) -> None:
        client = self.make_client(FakeTransport())
        with self.assertRaises(ValidationError):
            client.ingest_events([], chunk_size=501)

    def test_ingest_event_fills_tenant_from_client(self) -> None:
        fake = FakeTransport(
            [json_response(202, {"accepted": 1, "rejected": 0, "event_ids": [], "findings": []})]
        )
        client = self.make_client(fake)

        client.ingest_event({"kind": "log.line", "labels": {"a": "b"}})

        self.assertEqual(fake.body()["tenant_id"], TENANT)

    def test_validate_rule_accepts_yaml_string(self) -> None:
        fake = FakeTransport([json_response(200, {"valid": True, "errors": []})])
        client = self.make_client(fake)

        result = client.validate_rule("id: AO-WEB-001\ntitle: test\n")

        self.assertEqual(fake.last.headers["Content-Type"], "application/yaml")
        self.assertEqual(fake.last.content, b"id: AO-WEB-001\ntitle: test\n")
        self.assertTrue(result.valid)

    def test_create_key_rejects_unknown_role(self) -> None:
        fake = FakeTransport()
        client = self.make_client(fake)
        with self.assertRaises(ValidationError):
            client.create_key(role="root")
        self.assertEqual(fake.requests, [])

    def test_export_audit_validates_format(self) -> None:
        client = self.make_client(FakeTransport([json_response(200, {}, {"Content-Type": "text/plain"})]))
        with self.assertRaises(ValidationError):
            client.export_audit(format="xml")

    def test_export_audit_returns_text(self) -> None:
        response = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            content=b'{"seq":1}\n',
        )
        fake = FakeTransport([response])
        client = self.make_client(fake)

        text = client.export_audit(format="jsonl")

        self.assertEqual(text, '{"seq":1}\n')
        self.assertIn("/api/v1/audit/export", fake.last.url)
        self.assertIn("format=jsonl", fake.last.full_url())

    def test_get_report_returns_text_and_validates_format(self) -> None:
        response = HttpResponse(status_code=200, headers={}, content=b"<sarif/>")
        fake = FakeTransport([response])
        client = self.make_client(fake)

        self.assertEqual(client.get_report("f1", format="sarif"), "<sarif/>")
        self.assertIn("format=sarif", fake.last.full_url())
        self.assertEqual(fake.last.url, BASE_URL + "/api/v1/findings/f1/report")
        with self.assertRaises(ValidationError):
            client.get_report("f1", format="pdf")

    def test_revoke_key_accepts_204(self) -> None:
        fake = FakeTransport([HttpResponse(status_code=204, headers={}, content=b"")])
        client = self.make_client(fake)

        self.assertIsNone(client.revoke_key("k1"))
        self.assertEqual(fake.last.method, "DELETE")
        self.assertEqual(fake.last.url, BASE_URL + "/api/v1/keys/k1")

    def test_update_tenant_requires_at_least_one_field(self) -> None:
        client = self.make_client(FakeTransport())
        with self.assertRaises(ValidationError):
            client.update_tenant()

    def test_update_tenant_sends_patch_body(self) -> None:
        fake = FakeTransport([json_response(200, {"tenant_id": TENANT, "mode": "supervised"})])
        client = self.make_client(fake)

        client.update_tenant(mode="supervised", dry_run=True)

        self.assertEqual(fake.last.method, "PATCH")
        self.assertEqual(fake.body(), {"mode": "supervised", "dry_run": True})

    def test_update_tenant_rejects_invalid_mode(self) -> None:
        client = self.make_client(FakeTransport())
        with self.assertRaises(ValidationError):
            client.update_tenant(mode="yolo")

    def test_ws_url_uses_query_parameters(self) -> None:
        client = self.make_client(FakeTransport())

        url = client.ws_url()

        self.assertTrue(url.startswith("wss://aegis.example.test/api/v1/ws/stream?"))
        self.assertIn("api_key=" + API_KEY, url)
        self.assertIn("tenant_id=acme", url)

    def test_whoami_and_stats_and_collectors(self) -> None:
        fake = FakeTransport(
            [
                json_response(
                    200, {"tenant_id": TENANT, "role": "responder", "capabilities": ["read:events"]}
                ),
                json_response(200, {"findings_by_severity": {"critical": 2}, "autonomy_mode": "supervised"}),
                json_response(200, {"items": [{"name": "nginx", "last_run_at": "2026-02-14T10:00:00Z"}]}),
                json_response(200, {"collector": "nginx", "items": 42}),
            ]
        )
        client = self.make_client(fake)

        who = client.whoami()
        stats = client.stats_overview()
        collectors = client.list_collectors()
        run = client.run_collector("nginx")

        self.assertEqual(who["role"], "responder")
        self.assertEqual(stats.findings_by_severity["critical"], 2)
        self.assertEqual(stats.autonomy_mode, "supervised")
        self.assertEqual(collectors[0].name, "nginx")
        self.assertEqual(run["items"], 42)
        self.assertEqual(fake.requests[3].url, BASE_URL + "/api/v1/collectors/nginx/run")

    def test_full_action_lifecycle_routes(self) -> None:
        fake = FakeTransport(
            [
                json_response(200, {"action_id": "a1", "status": "planned"}),
                json_response(200, {"items": [{"action_id": "a1"}]}),
                json_response(200, {"action_id": "a1", "status": "pending_approval"}),
                json_response(200, {"action_id": "a1", "status": "approved"}),
                json_response(200, {"action_id": "a1", "status": "succeeded"}),
                json_response(200, {"action_id": "a1", "status": "rolled_back"}),
                json_response(200, {"action_id": "a1", "status": "rejected"}),
            ]
        )
        client = self.make_client(fake)

        planned = client.plan_action("f1", "block-source-ip", params={"target": "203.0.113.9"})
        listed = client.list_actions(status="planned")
        current = client.get_action("a1")
        approved = client.approve_action("a1", comment="ok")
        executed = client.execute_action("a1", idempotency_key="acme:block:203.0.113.9")
        rolled = client.rollback_action("a1")
        rejected = client.reject_action("a1", reason="faux positif")

        paths = [request.url for request in fake.requests]
        self.assertEqual(
            paths,
            [
                BASE_URL + "/api/v1/actions/plan",
                BASE_URL + "/api/v1/actions",
                BASE_URL + "/api/v1/actions/a1",
                BASE_URL + "/api/v1/actions/a1/approve",
                BASE_URL + "/api/v1/actions/a1/execute",
                BASE_URL + "/api/v1/actions/a1/rollback",
                BASE_URL + "/api/v1/actions/a1/reject",
            ],
        )
        self.assertEqual(planned.status, "planned")
        self.assertEqual(listed[0].action_id, "a1")
        self.assertEqual(current.status, "pending_approval")
        self.assertEqual(approved.status, "approved")
        self.assertEqual(executed.status, "succeeded")
        self.assertEqual(rolled.status, "rolled_back")
        self.assertEqual(rejected.status, "rejected")

        # plan_action : corps strictement conforme au contrat §4.6
        self.assertEqual(
            fake.body(0),
            {
                "finding_id": "f1",
                "playbook": "block-source-ip",
                "params": {"target": "203.0.113.9"},
                "dry_run": True,
            },
        )
        # approve / reject : corps documentés
        self.assertEqual(fake.body(3), {"comment": "ok"})
        self.assertEqual(fake.body(6), {"reason": "faux positif"})
        # execute : clé d'idempotence transmise en corps ET en en-tête
        self.assertEqual(fake.body(4), {"idempotency_key": "acme:block:203.0.113.9"})
        self.assertEqual(fake.requests[4].headers["Idempotency-Key"], "acme:block:203.0.113.9")
        self.assertTrue(fake.requests[4].retry_safe)

    def test_findings_routes(self) -> None:
        fake = FakeTransport(
            [
                json_response(200, {"items": [{"finding_id": "f1", "risk_score": 78.5, "status": "open"}]}),
                json_response(200, {"finding_id": "f1", "actions": []}),
                json_response(200, {"status": "acked"}),
                json_response(200, {"status": "closed"}),
                json_response(200, {"status": "suppressed"}),
            ]
        )
        client = self.make_client(fake)

        page = client.list_findings(severity="high", sort="risk_score")
        finding = client.get_finding("f1")
        acked = client.ack_finding("f1", comment="en cours")
        closed = client.close_finding("f1", "true_positive")
        suppressed = client.suppress_finding("f1", duration_seconds=3600, reason="faux positif chronique")

        self.assertEqual(page[0].risk_score, 78.5)
        self.assertEqual(finding.extra["actions"], [])
        self.assertEqual(acked["status"], "acked")
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(suppressed["status"], "suppressed")
        self.assertEqual(fake.requests[2].url, BASE_URL + "/api/v1/findings/f1/ack")
        self.assertEqual(fake.body(3), {"resolution": "true_positive"})
        self.assertEqual(fake.body(4), {"duration_seconds": 3600, "reason": "faux positif chronique"})
        with self.assertRaises(ValidationError):
            client.close_finding("f1", "peut_etre")

    def test_rules_policies_playbooks_routes(self) -> None:
        fake = FakeTransport(
            [
                json_response(200, {"items": [{"rule_id": "AO-WEB-001", "severity": "high"}]}),
                json_response(200, {"rule_id": "AO-WEB-001", "yaml": "id: AO-WEB-001\n"}),
                json_response(200, {"valid": True, "errors": []}),
                json_response(200, {"loaded": 12, "errors": []}),
                json_response(200, {"items": [{"id": "auto-block-high-web", "priority": 100}]}),
                json_response(200, {"loaded": 3}),
                json_response(200, {"items": [{"name": "block-source-ip", "reversible": True}]}),
            ]
        )
        client = self.make_client(fake)

        rules = client.list_rules()
        rule = client.get_rule("AO-WEB-001")
        validation = client.validate_rule({"id": "AO-WEB-001"})
        reloaded = client.reload_rules()
        policies = client.list_policies()
        reloaded_policies = client.reload_policies()
        playbooks = client.list_playbooks()

        self.assertEqual(rules[0].rule_id, "AO-WEB-001")
        self.assertEqual(rule.yaml_source, "id: AO-WEB-001\n")
        self.assertTrue(validation.valid)
        self.assertEqual(reloaded["loaded"], 12)
        self.assertEqual(policies["items"][0]["priority"], 100)
        self.assertEqual(reloaded_policies["loaded"], 3)
        self.assertTrue(playbooks[0].reversible)
        self.assertEqual(fake.requests[0].url, BASE_URL + "/api/v1/rules")
        self.assertEqual(fake.requests[3].url, BASE_URL + "/api/v1/rules/reload")

    def test_audit_routes(self) -> None:
        fake = FakeTransport(
            [
                json_response(
                    200,
                    {
                        "items": [
                            {
                                "seq": 42,
                                "actor": "api-key:ci",
                                "actor_role": "responder",
                                "action": "action.approve",
                                "hash": "sha256:abc",
                                "prev_hash": "sha256:def",
                            }
                        ]
                    },
                ),
                json_response(200, {"valid": True, "records": 42, "broken_at": None}),
            ]
        )
        client = self.make_client(fake)

        records = client.list_audit(action="action.approve", actor="api-key:ci")
        verification = client.verify_audit()

        self.assertEqual(records[0].seq, 42)
        self.assertEqual(records[0].actor_role, "responder")
        self.assertTrue(verification.valid)
        self.assertEqual(verification.records, 42)
        self.assertIn("action=action.approve", fake.requests[0].full_url())

    def test_pagination_follows_cursor(self) -> None:
        fake = FakeTransport(
            [
                json_response(200, {"items": [{"finding_id": "f1"}], "next_cursor": "c2"}),
                json_response(200, {"items": [{"finding_id": "f2"}], "next_cursor": None}),
            ]
        )
        client = self.make_client(fake)

        ids = [finding.finding_id for finding in client.iter_findings(status="open")]

        self.assertEqual(ids, ["f1", "f2"])
        self.assertIn("cursor=c2", fake.requests[1].full_url())

    def test_pagination_protects_against_cursor_loop(self) -> None:
        fake = FakeTransport(
            default=json_response(200, {"items": [{"finding_id": "f"}], "next_cursor": "same"})
        )
        client = self.make_client(fake)

        ids = list(client.iter_findings())

        self.assertEqual(len(ids), 2)  # page initiale + une seule page répétée


# ======================================================================================
# Mapping d'erreurs (§4.6)
# ======================================================================================


class TestErrorMapping(ClientTestCase):
    def _raise_for(self, status: int, payload: Any, headers: dict[str, str] | None = None):
        fake = FakeTransport([json_response(status, payload, headers)])
        client = self.make_client(fake, max_retries=0)
        with self.assertRaises(ThotSecureError) as ctx:
            client.get_tenant()
        return ctx.exception

    def test_401_maps_to_authentication_error(self) -> None:
        error = self._raise_for(401, {"error": {"code": "unauthenticated", "message": "clé inconnue"}})
        self.assertIsInstance(error, AuthenticationError)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(error.code, "unauthenticated")

    def test_403_maps_to_permission_denied(self) -> None:
        error = self._raise_for(403, {"error": {"code": "forbidden", "message": "capability manquante"}})
        self.assertIsInstance(error, PermissionDeniedError)

    def test_404_maps_to_not_found(self) -> None:
        error = self._raise_for(404, {"error": {"code": "not_found", "message": "inconnu"}})
        self.assertIsInstance(error, NotFoundError)

    def test_409_maps_to_conflict(self) -> None:
        error = self._raise_for(409, {"error": {"code": "conflict", "message": "action non approuvée"}})
        self.assertIsInstance(error, ConflictError)

    def test_400_and_422_map_to_validation_error(self) -> None:
        self.assertIsInstance(
            self._raise_for(400, {"error": {"code": "validation_error", "message": "corps invalide"}}),
            ValidationError,
        )
        self.assertIsInstance(
            self._raise_for(422, {"error": {"code": "unprocessable", "message": "sémantique"}}),
            ValidationError,
        )

    def test_429_maps_to_rate_limited_with_retry_after(self) -> None:
        error = self._raise_for(
            429,
            {"error": {"code": "rate_limited", "message": "trop de requêtes"}},
            {"Retry-After": "7"},
        )
        self.assertIsInstance(error, RateLimitedError)
        self.assertEqual(error.retry_after, 7.0)

    def test_500_maps_to_server_error(self) -> None:
        error = self._raise_for(500, {"error": {"code": "internal_error", "message": "boum"}})
        self.assertIsInstance(error, ServerError)

    def test_error_code_wins_over_status(self) -> None:
        error = self._raise_for(503, {"error": {"code": "forbidden", "message": "cas tordu"}})
        self.assertIsInstance(error, PermissionDeniedError)

    def test_fastapi_style_detail_is_understood(self) -> None:
        error = self._raise_for(422, {"detail": [{"loc": ["body"], "msg": "field required"}]})
        self.assertIsInstance(error, ValidationError)
        self.assertEqual(error.message, "validation error")
        self.assertIn("errors", error.details)

    def test_non_json_error_body_does_not_crash(self) -> None:
        fake = FakeTransport([HttpResponse(status_code=502, headers={}, content=b"<html>bad gateway</html>")])
        client = self.make_client(fake, max_retries=0)
        with self.assertRaises(ServerError) as ctx:
            client.get_tenant()
        self.assertIn("bad gateway", str(ctx.exception))

    def test_error_never_contains_api_key(self) -> None:
        fake = FakeTransport([json_response(403, {"error": {"code": "forbidden", "message": "nope"}})])
        client = self.make_client(fake, max_retries=0)
        with self.assertRaises(PermissionDeniedError) as ctx:
            client.get_tenant()
        rendered = f"{ctx.exception} | {ctx.exception!r}"
        self.assertNotIn(API_KEY, rendered)
        self.assertNotIn(API_KEY, repr(client))

    def test_redact_url_masks_api_key(self) -> None:
        url = "https://h/api/v1/ws/stream?api_key=ao_secret&tenant_id=acme"
        redacted = redact_url(url)
        self.assertNotIn("ao_secret", redacted)
        self.assertIn("tenant_id=acme", redacted)
        self.assertIn("api_key=***", redacted)

    def test_details_are_exposed(self) -> None:
        error = self._raise_for(
            409,
            {"error": {"code": "conflict", "message": "déjà exécutée", "details": {"status": "executing"}}},
        )
        self.assertEqual(error.details, {"status": "executing"})


# ======================================================================================
# Politique de retry
# ======================================================================================


class TestRetryPolicy(ClientTestCase):
    def test_is_retry_safe_rules(self) -> None:
        self.assertTrue(is_retry_safe("GET"))
        self.assertTrue(is_retry_safe("DELETE"))
        self.assertTrue(is_retry_safe("PUT"))
        self.assertFalse(is_retry_safe("POST"))
        self.assertFalse(is_retry_safe("PATCH"))
        self.assertTrue(is_retry_safe("POST", "key-123"))

    def test_parse_retry_after(self) -> None:
        self.assertEqual(parse_retry_after("5"), 5.0)
        self.assertEqual(parse_retry_after("0"), 0.0)
        self.assertIsNone(parse_retry_after(None))
        self.assertIsNone(parse_retry_after("n'importe quoi"))
        self.assertGreater(parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") or 0, 0)

    def test_get_is_retried_on_503_then_succeeds(self) -> None:
        fake = FakeTransport(
            [
                json_response(503, {"error": {"code": "internal_error", "message": "indisponible"}}),
                json_response(200, {"tenant_id": TENANT, "name": "ACME"}),
            ]
        )
        client = self.make_client(fake, max_retries=3)

        tenant = client.get_tenant()

        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(tenant.tenant_id, TENANT)
        self.assertEqual(len(self.sleeps), 1)
        # backoff exponentiel : base 0.5 * 2**0 = 0.5, jitter fixé à 0.5 → 0.25
        self.assertAlmostEqual(self.sleeps[0], 0.25, places=6)

    def test_backoff_grows_exponentially(self) -> None:
        fake = FakeTransport(
            [
                json_response(502, {"error": {"code": "internal_error", "message": "x"}}),
                json_response(503, {"error": {"code": "internal_error", "message": "x"}}),
                json_response(200, {"tenant_id": TENANT}),
            ]
        )
        client = self.make_client(fake, max_retries=5, backoff_base=1.0)

        client.get_tenant()

        self.assertEqual(len(self.sleeps), 2)
        self.assertAlmostEqual(self.sleeps[0], 0.5, places=6)
        self.assertAlmostEqual(self.sleeps[1], 1.0, places=6)

    def test_rate_limited_honours_retry_after(self) -> None:
        fake = FakeTransport(
            [
                json_response(
                    429,
                    {"error": {"code": "rate_limited", "message": "doucement"}},
                    {"Retry-After": "2"},
                ),
                json_response(200, {"items": []}),
            ]
        )
        client = self.make_client(fake, max_retries=2)

        client.list_events()

        self.assertEqual(self.sleeps, [2.0])

    def test_post_without_idempotency_key_is_never_retried(self) -> None:
        fake = FakeTransport(
            [
                json_response(503, {"error": {"code": "internal_error", "message": "indisponible"}}),
                json_response(202, {"accepted": 1, "rejected": 0, "event_ids": [], "findings": []}),
            ]
        )
        client = self.make_client(fake, max_retries=3)

        with self.assertRaises(ServerError):
            client.ingest_event({"kind": "log.line"})

        self.assertEqual(len(fake.requests), 1)
        self.assertEqual(self.sleeps, [])
        self.assertFalse(fake.last.retry_safe)

    def test_post_with_idempotency_key_is_retried(self) -> None:
        fake = FakeTransport(
            [
                json_response(503, {"error": {"code": "internal_error", "message": "indisponible"}}),
                json_response(200, {"action_id": "a1", "status": "succeeded"}),
            ]
        )
        client = self.make_client(fake, max_retries=3)

        action = client.execute_action("a1", idempotency_key="idem-1")

        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(action.status, "succeeded")
        self.assertTrue(fake.requests[0].retry_safe)

    def test_network_error_is_retried_then_raises_transport_error(self) -> None:
        fake = FakeTransport(
            [
                TransportError("connexion refusée"),
                TransportError("connexion refusée"),
                TransportError("connexion refusée"),
            ]
        )
        client = self.make_client(fake, max_retries=2)

        with self.assertRaises(TransportError):
            client.get_tenant()

        self.assertEqual(len(fake.requests), 3)

    def test_network_error_then_success(self) -> None:
        fake = FakeTransport([TransportError("timeout"), json_response(200, {"tenant_id": TENANT})])
        client = self.make_client(fake, max_retries=1)

        self.assertEqual(client.get_tenant().tenant_id, TENANT)
        self.assertEqual(len(fake.requests), 2)

    def test_max_retries_zero_disables_retry(self) -> None:
        fake = FakeTransport([json_response(503, {"error": {"code": "internal_error", "message": "x"}})])
        client = self.make_client(fake, max_retries=0)

        with self.assertRaises(ServerError):
            client.get_tenant()

        self.assertEqual(len(fake.requests), 1)

    def test_four_xx_is_not_retried(self) -> None:
        fake = FakeTransport([json_response(400, {"error": {"code": "validation_error", "message": "x"}})])
        client = self.make_client(fake, max_retries=3)

        with self.assertRaises(ValidationError):
            client.get_tenant()

        self.assertEqual(len(fake.requests), 1)


# ======================================================================================
# Configuration, sécurité, cycle de vie
# ======================================================================================


class TestConfigurationAndLifecycle(ClientTestCase):
    def test_environment_defaults(self) -> None:
        env = {
            "THOT_URL": "http://127.0.0.1:9090",
            "THOT_API_KEY": "ao_from_env",
            "THOT_TENANT_ID": "env-tenant",
            "THOT_TIMEOUT": "12.5",
            "THOT_MAX_RETRIES": "1",
            "THOT_VERIFY_TLS": "false",
        }
        with mock.patch.dict(os.environ, env, clear=False), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = ThotSecureClient(transport=FakeTransport())
        self.assertEqual(client.base_url, "http://127.0.0.1:9090")
        self.assertEqual(client.api_key, "ao_from_env")
        self.assertEqual(client.tenant_id, "env-tenant")
        self.assertEqual(client.timeout, 12.5)
        self.assertEqual(client.max_retries, 1)
        self.assertFalse(client.verify_tls)

    def test_explicit_arguments_win_over_environment(self) -> None:
        env = {"THOT_URL": "http://ignored", "THOT_API_KEY": "ao_ignored"}
        with mock.patch.dict(os.environ, env, clear=False):
            client = ThotSecureClient(
                base_url="https://explicit.example", api_key="ao_explicit", transport=FakeTransport()
            )
        self.assertEqual(client.base_url, "https://explicit.example")
        self.assertEqual(client.api_key, "ao_explicit")

    def test_invalid_base_url_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ThotSecureClient(base_url="aegis.example", transport=FakeTransport())

    def test_verify_tls_false_emits_explicit_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            ThotSecureClient(base_url=BASE_URL, verify_tls=False, transport=FakeTransport())
        messages = " ".join(str(w.message) for w in caught)
        self.assertIn("TLS", messages)
        self.assertIn("DÉSACTIVÉE", messages)

    def test_context_manager_closes_transport(self) -> None:
        fake = FakeTransport([json_response(200, {"status": "ok"})])
        with self.make_client(fake) as client:
            client.healthz()
        self.assertTrue(fake.closed)

    def test_close_is_idempotent(self) -> None:
        fake = FakeTransport()
        client = self.make_client(fake)
        client.close()
        client.close()
        self.assertTrue(fake.closed)

    def test_readyz_returns_dict_on_503(self) -> None:
        fake = FakeTransport(
            [
                json_response(503, {"error": {"code": "internal_error", "message": "DB indisponible"}}),
                json_response(503, {"error": {"code": "internal_error", "message": "DB indisponible"}}),
            ]
        )
        client = self.make_client(fake, max_retries=0)

        payload = client.readyz()

        self.assertEqual(payload["status"], "unavailable")
        self.assertEqual(payload["http_status"], 503)
        with self.assertRaises(ServerError):
            client.readyz(raise_on_error=True)

    def test_version_and_metrics(self) -> None:
        fake = FakeTransport(
            [
                json_response(200, {"version": "0.1.0", "commit": "abc", "license": "Apache-2.0"}),
                HttpResponse(
                    status_code=200,
                    headers={"Content-Type": "text/plain"},
                    content=b"# HELP thotsecure_events_total\n",
                ),
            ]
        )
        client = self.make_client(fake)

        self.assertEqual(client.version()["version"], "0.1.0")
        self.assertIn("thotsecure_events_total", client.metrics())
        self.assertEqual(fake.requests[1].url, BASE_URL + "/metrics")

    def test_retrying_transport_counts_retries(self) -> None:
        inner = FakeTransport(
            [
                json_response(503, {"error": {"code": "internal_error", "message": "x"}}),
                json_response(200, {"ok": True}),
            ]
        )
        transport = RetryingTransport(inner, max_retries=1, sleep=self.sleeps.append, rand=lambda: 0.0)

        response = transport.send(HttpRequest(method="GET", url=BASE_URL + "/healthz"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(transport.retry_count, 1)
        self.assertEqual(len(inner.requests), 2)
        self.assertEqual(self.sleeps, [0.25])


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
