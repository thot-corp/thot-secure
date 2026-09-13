"""Tests des helpers d'intégration et des modèles — exécutables **hors ligne**.

Exécution ::

    python -m unittest discover -s sdks/python/tests -t sdks/python -v
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone

_SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

from thotsecure_sdk import Event, Finding, Page, Tenant  # noqa: E402
from thotsecure_sdk.helpers import (  # noqa: E402
    MAX_PAYLOAD_BYTES,
    chunked,
    env,
    from_syslog_line,
    iter_jsonl,
    normalize_event,
    parse_http_log_line,
    parse_timestamp,
    pseudonymize_ip,
    pseudonymize_ip_fields,
    redact_secrets,
    truncate_payload,
)

NGINX_LINE = (
    '203.0.113.9 - alice [14/Feb/2026:10:00:00 +0100] "POST /login?user=admin HTTP/1.1" '
    '403 512 "https://shop.acme.fr/" "curl/8.5.0"'
)

APACHE_COMMON_LINE = (
    '198.51.100.7 - - [14/Feb/2026:09:59:58 +0000] "GET /index.html HTTP/1.0" 200 2326'
)

NGINX_VHOST_LINE = (
    'shop.acme.fr:443 203.0.113.42 - - [14/Feb/2026:10:01:02 +0000] '
    '"GET /search?q=union+select HTTP/2.0" 500 1234 "-" "Mozilla/5.0"'
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

SALT = "sel-de-test-organisation"


class TestParseHttpLogLine(unittest.TestCase):
    def test_nginx_combined(self) -> None:
        record = parse_http_log_line(NGINX_LINE)
        assert record is not None
        self.assertEqual(record["src_ip"], "203.0.113.9")
        self.assertEqual(record["user"], "alice")
        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["path"], "/login")
        self.assertEqual(record["query"], "user=admin")
        self.assertEqual(record["protocol"], "HTTP/1.1")
        self.assertEqual(record["status"], 403)
        self.assertEqual(record["bytes"], 512)
        self.assertEqual(record["referer"], "https://shop.acme.fr/")
        self.assertEqual(record["user_agent"], "curl/8.5.0")
        self.assertIsNone(record["vhost"])

    def test_apache_common_without_referer(self) -> None:
        record = parse_http_log_line(APACHE_COMMON_LINE)
        assert record is not None
        self.assertEqual(record["status"], 200)
        self.assertIsNone(record["user_agent"])
        self.assertIsNone(record["query"])
        self.assertEqual(record["path"], "/index.html")

    def test_vhost_prefix(self) -> None:
        record = parse_http_log_line(NGINX_VHOST_LINE)
        assert record is not None
        self.assertEqual(record["vhost"], "shop.acme.fr:443")
        self.assertEqual(record["src_ip"], "203.0.113.42")
        self.assertEqual(record["status"], 500)

    def test_non_http_line_returns_none(self) -> None:
        self.assertIsNone(parse_http_log_line("ceci n'est pas un log HTTP"))


class TestNormalizeEvent(unittest.TestCase):
    def test_nginx_line_becomes_contract_event(self) -> None:
        event = normalize_event(
            NGINX_LINE, tenant_id="acme", source_name="prod-edge", source_type="log_tail"
        )

        payload = event.to_dict()
        self.assertEqual(payload["tenant_id"], "acme")
        self.assertEqual(payload["schema_version"], "1")
        self.assertEqual(payload["kind"], "http.request")
        self.assertEqual(payload["labels"]["src_ip"], "203.0.113.9")
        self.assertEqual(payload["labels"]["method"], "POST")
        self.assertEqual(payload["labels"]["path"], "/login")
        self.assertEqual(payload["payload"]["status"], 403)
        self.assertEqual(payload["payload"]["bytes"], 512)
        self.assertEqual(payload["source"]["name"], "prod-edge")
        self.assertEqual(payload["severity_hint"], "low")
        self.assertEqual(payload["ts"], "2026-02-14T09:00:00.000Z")  # +0100 → UTC
        self.assertIsNone(payload["raw_ref"])
        # event_id : UUID v4 bien formé
        self.assertRegex(payload["event_id"], r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        # labels plats à valeurs scalaires (contrat §3.1)
        for value in payload["labels"].values():
            self.assertIsInstance(value, (str, int, float, bool))

    def test_json_structured_line(self) -> None:
        line = json.dumps(
            {
                "@timestamp": "2026-02-14T10:00:00Z",
                "client_ip": "203.0.113.77",
                "http_method": "GET",
                "request_uri": "/admin",
                "status_code": 401,
                "server_name": "edge-1",
            }
        )
        event = normalize_event(line, tenant_id="acme", source_host=None)

        self.assertEqual(event.kind, "http.request")
        self.assertEqual(event.labels["src_ip"], "203.0.113.77")
        self.assertEqual(event.labels["path"], "/admin")
        self.assertEqual(event.labels["host"], "edge-1")
        self.assertEqual(event.payload["status"], 401)
        self.assertEqual(event.severity_hint, "low")

    def test_generic_line_falls_back_to_log_line(self) -> None:
        event = normalize_event("kernel: unexpected reboot", tenant_id="acme")

        self.assertEqual(event.kind, "log.line")
        self.assertEqual(event.payload["message"], "kernel: unexpected reboot")
        self.assertIsNone(event.severity_hint)

    def test_mapping_source(self) -> None:
        event = normalize_event(
            {"src_ip": "10.0.0.5", "method": "DELETE", "path": "/api/v1/keys/k1", "status": "403"},
            tenant_id="acme",
        )
        self.assertEqual(event.labels["method"], "DELETE")
        self.assertEqual(event.payload["status"], 403)
        self.assertEqual(event.kind, "http.request")

    def test_secrets_are_redacted_from_log_lines(self) -> None:
        line = (
            '203.0.113.9 - - [14/Feb/2026:10:00:00 +0000] '
            '"GET /api?token=%s HTTP/1.1" 403 12 "-" "curl/8.5.0"' % JWT
        )
        event = normalize_event(line, tenant_id="acme")
        serialized = json.dumps(event.to_dict())

        self.assertNotIn(JWT, serialized)
        self.assertIn("REDACTED", serialized)

    def test_ip_salt_pseudonymizes_source_ip(self) -> None:
        event = normalize_event(NGINX_LINE, tenant_id="acme", ip_salt=SALT)

        pseudonym = event.labels["src_ip"]
        self.assertTrue(pseudonym.startswith("ip-"))
        self.assertNotIn("203.0.113.9", json.dumps(event.to_dict()))
        # déterminisme : même sel + même IP → même pseudonyme
        again = normalize_event(NGINX_LINE, tenant_id="acme", ip_salt=SALT)
        self.assertEqual(again.labels["src_ip"], pseudonym)

    def test_invalid_kind_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_event(NGINX_LINE, tenant_id="acme", kind="port.scan")

    def test_missing_tenant_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_event(NGINX_LINE, tenant_id="")

    def test_payload_is_truncated_above_32_kib(self) -> None:
        huge = "A" * (64 * 1024)
        event = normalize_event(
            {"message": huge, "status": 500}, tenant_id="acme", extra_payload={"trace": huge}
        )
        serialized = json.dumps(event.payload)

        self.assertLessEqual(len(serialized.encode("utf-8")), MAX_PAYLOAD_BYTES)
        self.assertIsNotNone(event.raw_ref)

    def test_extra_labels_and_payload(self) -> None:
        event = normalize_event(
            NGINX_LINE,
            tenant_id="acme",
            extra_labels={"environment": "prod", "asset": "web-1"},
            extra_payload={"request_id": "r-1"},
        )
        self.assertEqual(event.labels["environment"], "prod")
        self.assertEqual(event.payload["request_id"], "r-1")


class TestSyslog(unittest.TestCase):
    def test_rfc3164(self) -> None:
        event = from_syslog_line(
            "<34>Feb 14 10:00:00 edge sshd[123]: Failed password for root from 203.0.113.9 port 22",
            tenant_id="acme",
        )

        self.assertEqual(event.kind, "syslog")
        self.assertEqual(event.severity_hint, "critical")  # severity code 2 = critical
        self.assertEqual(event.labels["syslog_facility"], "auth")
        self.assertEqual(event.labels["syslog_severity"], 2)
        self.assertEqual(event.labels["syslog_tag"], "sshd")
        self.assertEqual(event.labels["syslog_pid"], "123")
        self.assertEqual(event.labels["src_ip"], "203.0.113.9")
        self.assertIn("Failed password", event.payload["message"])

    def test_rfc5424(self) -> None:
        event = from_syslog_line(
            "<165>1 2026-02-14T10:00:00Z host app 1234 ID47 - message structuré",
            tenant_id="acme",
        )

        self.assertEqual(event.kind, "syslog")
        self.assertEqual(event.labels["syslog_facility"], "local4")
        self.assertEqual(event.severity_hint, "low")  # severity code 5 = notice
        self.assertEqual(event.payload["message"], "message structuré")
        self.assertEqual(event.ts, "2026-02-14T10:00:00.000Z")

    def test_plain_line_without_priority(self) -> None:
        event = from_syslog_line("juste un message", tenant_id="acme")
        self.assertEqual(event.payload["message"], "juste un message")
        self.assertIsNone(event.severity_hint)

    def test_empty_line_rejected(self) -> None:
        with self.assertRaises(ValueError):
            from_syslog_line("   ", tenant_id="acme")


class TestRedactSecrets(unittest.TestCase):
    def test_sensitive_headers_and_fields(self) -> None:
        data = {
            "headers": {
                "Authorization": "Bearer abcdef1234567890",
                "Cookie": "session=abcdef",
                "Set-Cookie": "sid=1; HttpOnly",
                "X-Api-Key": "ao_super_secret",
                "User-Agent": "curl/8.5.0",
                "Accept": "application/json",
            },
            "password": "hunter2",
            "api_key": "ao_autre_cle",
            "access_token": "tok_123",
            "authorization": "Basic dXNlcjpwYXNz",
            "user_agent": "curl/8.5.0",
            "path": "/login",
        }

        redacted = redact_secrets(data)

        self.assertEqual(redacted["headers"]["Authorization"], "Bearer [REDACTED]")
        self.assertEqual(redacted["headers"]["Cookie"], "[REDACTED]")
        self.assertEqual(redacted["headers"]["Set-Cookie"], "[REDACTED]")
        self.assertEqual(redacted["headers"]["X-Api-Key"], "[REDACTED]")
        self.assertEqual(redacted["headers"]["User-Agent"], "curl/8.5.0")
        self.assertEqual(redacted["headers"]["Accept"], "application/json")
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["access_token"], "[REDACTED]")
        self.assertEqual(redacted["authorization"], "Basic [REDACTED]")
        self.assertEqual(redacted["user_agent"], "curl/8.5.0")
        self.assertEqual(redacted["path"], "/login")

    def test_input_is_not_mutated(self) -> None:
        data = {"password": "hunter2"}
        redact_secrets(data)
        self.assertEqual(data["password"], "hunter2")

    def test_jwt_inside_arbitrary_value(self) -> None:
        redacted = redact_secrets({"raw": "Authorization: Bearer %s" % JWT})
        self.assertNotIn(JWT, redacted["raw"])
        self.assertIn("REDACTED", redacted["raw"])

    def test_query_string_secret(self) -> None:
        redacted = redact_secrets({"query": "user=bob&token=abc123&x=1"})
        self.assertNotIn("abc123", redacted["query"])
        self.assertIn("token=[REDACTED]", redacted["query"])
        self.assertIn("user=bob", redacted["query"])

    def test_nested_lists_and_tuples(self) -> None:
        data = {"events": [{"headers": {"Cookie": "a=b"}}, {"note": "ok"}], "pair": ("a", "b")}
        redacted = redact_secrets(data)
        self.assertEqual(redacted["events"][0]["headers"]["Cookie"], "[REDACTED]")
        self.assertEqual(redacted["events"][1]["note"], "ok")
        self.assertEqual(redacted["pair"], ["a", "b"])

    def test_case_and_separator_insensitivity(self) -> None:
        for key in ("AUTHORIZATION", "Authorization", "authorization", "X-API-KEY", "x_api_key", "set-cookie"):
            self.assertEqual(redact_secrets({key: "valeur"})[key], "[REDACTED]", key)


class TestPseudonymizeIp(unittest.TestCase):
    def test_deterministic_and_salted(self) -> None:
        first = pseudonymize_ip("203.0.113.9", SALT)
        second = pseudonymize_ip("203.0.113.9", SALT)
        other_salt = pseudonymize_ip("203.0.113.9", "autre-sel")
        other_ip = pseudonymize_ip("203.0.113.10", SALT)

        self.assertEqual(first, second)
        self.assertNotEqual(first, other_salt)
        self.assertNotEqual(first, other_ip)
        self.assertTrue(first.startswith("ip-"))
        self.assertEqual(len(first), len("ip-") + 32)
        self.assertNotIn("203.0.113.9", first)

    def test_ipv6_and_cidr(self) -> None:
        self.assertTrue(pseudonymize_ip("2001:db8::1", SALT).startswith("ip-"))
        self.assertTrue(pseudonymize_ip("10.0.0.0/8", SALT).startswith("ip-"))

    def test_keep_prefix(self) -> None:
        token = pseudonymize_ip("203.0.113.9", SALT, keep_prefix=True)
        self.assertIn("@203.0.113.0/24", token)

    def test_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            pseudonymize_ip("pas-une-ip", SALT)
        with self.assertRaises(ValueError):
            pseudonymize_ip("203.0.113.9", "")
        with self.assertRaises(ValueError):
            pseudonymize_ip("", SALT)

    def test_fields_helper(self) -> None:
        data = {
            "labels": {"src_ip": "203.0.113.9", "dst_ip": "10.0.0.1", "path": "/x"},
            "payload": {"headers": {"X-Forwarded-For": "203.0.113.9"}},
            "samples": [{"remote_addr": "198.51.100.4"}],
            "untouched": "not-an-ip-value",
        }

        result = pseudonymize_ip_fields(data, SALT)

        self.assertTrue(result["labels"]["src_ip"].startswith("ip-"))
        self.assertTrue(result["labels"]["dst_ip"].startswith("ip-"))
        self.assertEqual(result["labels"]["path"], "/x")
        self.assertNotIn("203.0.113.9", json.dumps(result))
        self.assertTrue(result["samples"][0]["remote_addr"].startswith("ip-"))

    def test_fields_helper_tolerates_non_ip_values(self) -> None:
        result = pseudonymize_ip_fields({"src_ip": "unknown"}, SALT)
        self.assertEqual(result["src_ip"], "unknown")


class TestUtilities(unittest.TestCase):
    def test_chunked_respects_batch_limit(self) -> None:
        batches = list(chunked(range(501)))
        self.assertEqual([len(b) for b in batches], [500, 1])
        self.assertEqual(list(chunked([], 10)), [])
        with self.assertRaises(ValueError):
            list(chunked([1, 2, 3], 0))

    def test_truncate_payload_noop_when_small(self) -> None:
        payload, truncated = truncate_payload({"status": 200})
        self.assertFalse(truncated)
        self.assertEqual(payload, {"status": 200})

    def test_truncate_payload_enforces_limit(self) -> None:
        payload, truncated = truncate_payload({"big": "x" * 100_000, "status": 500}, max_bytes=4096)
        self.assertTrue(truncated)
        self.assertLessEqual(len(json.dumps(payload).encode("utf-8")), 4096)
        self.assertEqual(payload.get("status"), 500)

    def test_parse_timestamp_variants(self) -> None:
        self.assertEqual(parse_timestamp("2026-02-14T10:00:00Z").year, 2026)  # type: ignore[union-attr]
        self.assertEqual(
            parse_timestamp("14/Feb/2026:10:00:00 +0000").isoformat(),  # type: ignore[union-attr]
            datetime(2026, 2, 14, 10, 0, tzinfo=timezone.utc).isoformat(),
        )
        self.assertEqual(parse_timestamp(1771063200).year, 2026)  # type: ignore[union-attr]
        self.assertEqual(parse_timestamp(1771063200000).year, 2026)  # type: ignore[union-attr]
        self.assertEqual(parse_timestamp("Feb 14 10:00:00").month, 2)  # type: ignore[union-attr]
        self.assertIsNone(parse_timestamp("n'importe quoi"))

    def test_iter_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.jsonl"
            path.write_text(
                '{"a": 1}\n\n{"b": 2}\n',
                encoding="utf-8",
            )
            self.assertEqual(list(iter_jsonl(path)), [{"a": 1}, {"b": 2}])

    def test_iter_jsonl_invalid_line_reports_position(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.jsonl"
            path.write_text('{"a": 1}\n{invalide\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                list(iter_jsonl(path))
            self.assertIn(":2", str(ctx.exception))

    def test_iter_jsonl_skip_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.jsonl"
            path.write_text('{"a": 1}\n{invalide\n{"b": 2}\n', encoding="utf-8")
            self.assertEqual(list(iter_jsonl(path, skip_invalid=True)), [{"a": 1}, {"b": 2}])

    def test_env_helper(self) -> None:
        self.assertEqual(env("THOT_TEST_ABSENTE", "defaut"), "defaut")
        with self.assertRaises(RuntimeError):
            env("THOT_TEST_ABSENTE", required=True)


class TestModels(unittest.TestCase):
    CONTRACT_EVENT = {
        "event_id": "e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11",
        "schema_version": "1",
        "tenant_id": "acme",
        "ts": "2026-02-14T10:00:00.123Z",
        "kind": "http.request",
        "source": {"type": "web_probe", "name": "prod-edge", "host": "shop.acme.fr"},
        "severity_hint": "info",
        "labels": {"src_ip": "203.0.113.9", "path": "/login", "method": "POST"},
        "payload": {"status": 403, "bytes": 512, "user_agent": "curl/8.5"},
        "raw_ref": None,
    }

    CONTRACT_FINDING = {
        "finding_id": "f1c2",
        "tenant_id": "acme",
        "rule_id": "AO-WEB-001",
        "rule_name": "SQL injection attempt in query string",
        "severity": "high",
        "risk_score": 78.5,
        "confidence": 0.85,
        "status": "open",
        "title": "Tentative d'injection SQL depuis 203.0.113.9",
        "description": "…",
        "remediation": "…",
        "tags": ["web", "owasp:a03", "mitre:T1190"],
        "mitre": ["T1190"],
        "evidence": {"samples": [{"ts": "…", "labels": {}}]},
        "first_seen": "2026-02-14T10:00:00Z",
        "last_seen": "2026-02-14T10:04:12Z",
        "count": 7,
        "event_ids": ["e6f0"],
        "created_at": "2026-02-14T10:00:01Z",
        "updated_at": "2026-02-14T10:04:13Z",
    }

    def test_event_round_trip(self) -> None:
        event = Event.from_dict(self.CONTRACT_EVENT)
        self.assertEqual(event.to_dict(), self.CONTRACT_EVENT)

    def test_finding_round_trip_and_snake_case(self) -> None:
        finding = Finding.from_dict(self.CONTRACT_FINDING)
        self.assertEqual(finding.to_dict(), self.CONTRACT_FINDING)
        self.assertEqual(finding.risk_score, 78.5)
        self.assertEqual(finding.status, "open")
        self.assertIn("risk_score", json.dumps(finding.to_dict()))

    def test_unknown_fields_are_preserved_in_extra(self) -> None:
        finding = Finding.from_dict({**self.CONTRACT_FINDING, "actions": [{"action_id": "a1"}]})

        self.assertEqual(finding.extra["actions"], [{"action_id": "a1"}])
        self.assertEqual(finding.to_dict()["actions"], [{"action_id": "a1"}])

    def test_to_dict_omit_none(self) -> None:
        tenant = Tenant(tenant_id="acme", name="ACME")
        self.assertIn("mode", tenant.to_dict())
        self.assertNotIn("mode", tenant.to_dict(omit_none=True))

    def test_from_dict_accepts_none(self) -> None:
        self.assertIsNone(Tenant.from_dict(None))

    def test_from_dict_rejects_non_mapping(self) -> None:
        with self.assertRaises(TypeError):
            Tenant.from_dict(["pas", "un", "mapping"])  # type: ignore[arg-type]

    def test_labels_must_stay_flat(self) -> None:
        event = Event.from_dict({**self.CONTRACT_EVENT, "labels": {"nested": {"a": 1}, "ok": "valeur"}})
        self.assertEqual(event.to_dict()["labels"], {"ok": "valeur"})

    def test_page_from_items_payload(self) -> None:
        page: Page = Page.from_payload(
            {"items": [{"finding_id": "f1"}, {"finding_id": "f2"}], "next_cursor": "abc"}, Finding
        )

        self.assertEqual(len(page), 2)
        self.assertEqual(page[0].finding_id, "f1")
        self.assertEqual(page.next_cursor, "abc")
        self.assertTrue(page)

    def test_page_from_bare_list(self) -> None:
        page: Page = Page.from_payload([{"tenant_id": "acme"}], Tenant)
        self.assertEqual(page.items[0].tenant_id, "acme")
        self.assertIsNone(page.next_cursor)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
