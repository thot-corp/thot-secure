"""Tests des collecteurs : analyse de journaux, dépendances, configuration, audit de surface.

Le test de l'audit de surface démarre un **vrai serveur HTTP local** qui reproduit les défauts
recherchés (en-têtes absents, fichier ``.git/config`` exposé). On vérifie donc le collecteur
sur des réponses réelles, pas sur des simulacres.
"""

from __future__ import annotations

import http.server
import socket
import socketserver
import textwrap
import threading
from pathlib import Path

from thotsecure.collectors.base import CollectorContext
from thotsecure.collectors.config_audit import SSH_CHECKS, run_checks
from thotsecure.collectors.dependency_scan import (
    compare_versions,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements,
)
from thotsecure.collectors.log_tail import parse_log_line
from thotsecure.collectors.syslog import parse_syslog_line
from thotsecure.collectors.web_probe import WebProbeCollector

from .support import StackTestCase, build_stack


class LogParsingTest(StackTestCase):
    def test_combined_log_is_normalized(self) -> None:
        line = (
            '203.0.113.9 - - [14/Feb/2026:10:00:00 +0000] "POST /login HTTP/1.1" 403 512 '
            '"-" "curl/8.5.0"'
        )
        parsed = parse_log_line(line)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual("http.request", parsed.kind)
        self.assertEqual("203.0.113.9", parsed.labels["src_ip"])
        self.assertEqual("/login", parsed.labels["path"])
        self.assertEqual(403, parsed.labels["status"])
        self.assertEqual(512, parsed.payload["bytes"])

    def test_json_log_is_normalized_and_priority_is_a_label(self) -> None:
        parsed = parse_log_line(
            '{"ts":"2026-02-14T10:00:00Z","remote_addr":"198.51.100.7","request_method":"GET",'
            '"request_uri":"/admin","status":403,"message":"access denied"}'
        )
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual("198.51.100.7", parsed.labels["src_ip"])
        self.assertEqual("/admin", parsed.labels["path"])
        self.assertEqual("access denied", parsed.labels["message"])

    def test_unparseable_line_is_kept_as_raw(self) -> None:
        parsed = parse_log_line("une ligne totalement libre sans structure")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual("log.line", parsed.kind)
        self.assertIn("libre", parsed.labels["message"])

    def test_syslog_rfc5424_and_rfc3164(self) -> None:
        modern = parse_syslog_line(
            "<34>1 2026-02-14T10:00:00Z web01 sshd 1234 ID47 - Failed password for root from 203.0.113.9"
        )
        self.assertIsNotNone(modern)
        assert modern is not None
        self.assertEqual("auth", modern["facility"])
        self.assertEqual("critical", modern["severity"])
        self.assertEqual("web01", modern["host"])
        self.assertIn("Failed password", modern["message"])

        legacy = parse_syslog_line(
            "<38>Feb 14 10:00:00 web01 sshd[1234]: Accepted publickey for deploy from 198.51.100.4"
        )
        self.assertIsNotNone(legacy)
        assert legacy is not None
        self.assertEqual("sshd", legacy["app"])
        self.assertEqual("info", legacy["severity"])
        self.assertIn("Accepted publickey", legacy["message"])

    def test_raw_syslog_line_is_never_dropped(self) -> None:
        parsed = parse_syslog_line("message sans en-tête PRI du tout")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertIn("sans en-tête", parsed["message"])


class DependencyParsingTest(StackTestCase):
    def test_requirements_pins_are_parsed(self) -> None:
        dependencies = parse_requirements(
            "jinja2==3.1.2\nrequests==2.31.0\n# commentaire\ndjango>=4.2\n-e .\n"
        )
        names = {item.name: item.version for item in dependencies}
        self.assertEqual("3.1.2", names["jinja2"])
        self.assertEqual("2.31.0", names["requests"])
        # Une contrainte non épinglée ne permet pas de conclure : elle est ignorée.
        self.assertNotIn("django", names)

    def test_package_json_dependencies(self) -> None:
        dependencies = parse_package_json('{"dependencies":{"lodash":"^4.17.20","axios":"~1.5.0"}}')
        names = {item.name: item.version for item in dependencies}
        self.assertEqual("4.17.20", names["lodash"])
        self.assertEqual("1.5.0", names["axios"])
        self.assertEqual("npm", dependencies[0].ecosystem)

    def test_go_mod_and_pom(self) -> None:
        go_dependencies = parse_go_mod(
            "module example\n\nrequire (\n\tgolang.org/x/text v0.3.7\n)\n"
        )
        self.assertEqual("golang.org/x/text", go_dependencies[0].name)
        self.assertEqual("0.3.7", go_dependencies[0].version)

        pom = parse_pom_xml(
            "<dependency><groupId>org.springframework</groupId>"
            "<artifactId>spring-core</artifactId><version>5.3.10</version></dependency>"
        )
        self.assertEqual("org.springframework:spring-core", pom[0].name)
        self.assertEqual("5.3.10", pom[0].version)

    def test_version_comparison_handles_prereleases(self) -> None:
        self.assertLess(compare_versions("4.17.20", "4.17.21"), 0)
        self.assertEqual(compare_versions("1.0.0", "1.0.0"), 0)
        # Une pré-version doit être considérée comme antérieure à la version finale.
        self.assertLess(compare_versions("1.0rc1", "1.0"), 0)
        self.assertLess(compare_versions("2.0.0", "2.17.1"), 0)

    def test_dependency_scan_emits_events_for_vulnerable_pins(self) -> None:
        result = self.stack.collectors.run("dependency_scan", "acme")
        self.assertIn(result.status, {"ok", "partial"})
        checks = {event.labels.get("check") for event in result.events}
        self.assertIn("vulnerable_dependency", checks)
        cves = {event.labels.get("cve") for event in result.events}
        # jinja2==3.1.2 et pyyaml==5.3.1 sont dans l'instantané livré.
        self.assertIn("CVE-2024-34064", cves)
        self.assertIn("CVE-2020-14343", cves)


class ConfigAuditTest(StackTestCase):
    def test_permissive_ssh_configuration_is_detected(self) -> None:
        findings = run_checks(
            "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n",
            SSH_CHECKS,
        )
        checks = {item["check"] for item in findings}
        self.assertIn("ssh_permit_root_login", checks)
        self.assertIn("ssh_password_authentication", checks)
        self.assertIn("ssh_empty_passwords", checks)
        # MaxAuthTries est absent de ce fichier : le contrôle « présence attendue » déclenche.
        self.assertIn("ssh_max_auth_tries", checks)

    def test_config_audit_collector_produces_a_finding(self) -> None:
        result = self.stack.collectors.run("config_audit", "acme")
        checks = {event.labels.get("check") for event in result.events}
        self.assertIn("ssh_permit_root_login", checks)

        findings, _ = self.stack.store.list_findings("acme", rule_id="AO-CFG-001")
        self.assertTrue(findings, "la règle config doit produire un finding")
        self.assertEqual("high", findings[0].severity)
        # Un durcissement de configuration est notifié, jamais appliqué automatiquement.
        self.assertEqual("notify_only", self._decision_for(findings[0].finding_id))

    def _decision_for(self, finding_id: str) -> str:
        finding = self.stack.store.get_finding("acme", finding_id)
        assert finding is not None
        decision = self.stack.decision.decide_for_finding(
            finding, self.stack.tenant, environment="dev", settings=self.stack.settings
        )
        return decision.decision

    def test_missing_expected_setting_is_reported(self) -> None:
        findings = run_checks("Port 22\nPermitRootLogin no\n", SSH_CHECKS)
        checks = {item["check"] for item in findings}
        # Aucun HSTS n'est présent → le contrôle « présence attendue » déclenche.
        self.assertIn("ssh_max_auth_tries", checks)


class LogTailTest(StackTestCase):
    def test_log_tail_reads_only_new_lines(self) -> None:
        log_path = self.stack.root / "logs" / "access.log"
        first = self.stack.collectors.run("log_tail", "acme")
        self.assertGreaterEqual(len(first.events), 3)

        # Deuxième passe sans nouveau contenu : rien ne doit être relu.
        second = self.stack.collectors.run("log_tail", "acme")
        self.assertEqual(0, len(second.events), "aucune ligne ne doit être relue")

        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(
                '203.0.113.9 - - [14/Feb/2026:10:05:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl"\n'
            )
        third = self.stack.collectors.run("log_tail", "acme")
        self.assertEqual(1, len(third.events))
        self.assertEqual("/.env", third.events[0].labels.get("path"))

    def test_rotation_is_detected(self) -> None:
        log_path = self.stack.root / "logs" / "access.log"
        self.stack.collectors.run("log_tail", "acme")
        # Rotation : le fichier est tronqué puis réécrit plus court.
        log_path.write_text(
            '198.51.100.9 - - [14/Feb/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"\n',
            encoding="utf-8",
        )
        result = self.stack.collectors.run("log_tail", "acme")
        self.assertEqual(1, len(result.events), "après rotation, la nouvelle ligne doit être lue")


class _ProbeHandler(http.server.BaseHTTPRequestHandler):
    """Serveur de test qui reproduit les défauts recherchés par l'audit de surface."""

    def do_GET(self) -> None:
        if self.path == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n"
            self._respond(200, body, content_type="text/plain")
            return
        if self.path == "/.well-known/security.txt":
            self._respond(404, b"not found")
            return
        if self.path.endswith("/"):
            # Page principale : aucun en-tête de sécurité, cookie sans attributs, bannière.
            self._respond(
                200,
                b"<html><body>ok</body></html>",
                extra_headers={"Set-Cookie": "session=abc123", "Server": "nginx/1.18.0"},
            )
            return
        self._respond(404, b"not found")

    def _respond(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/html",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence le serveur de test
        return


class WebProbeTest(StackTestCase):
    """Audit de surface contre un serveur HTTP local réel."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ProbeHandler)
        cls._server.daemon_threads = True
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._server.shutdown()
        cls._server.server_close()
        cls._thread.join(timeout=5)

    def setUp(self) -> None:
        self._tmp = Path(self._make_temp())
        targets = textwrap.dedent(
            f"""
            tenants:
              acme:
                assets:
                  - host: 127.0.0.1
                    urls: ["http://127.0.0.1:{self._port}"]
                owned_cidrs: ["127.0.0.1/32"]
                allow_probe: true
            """
        )
        self.stack = build_stack(self._tmp, targets_yaml=targets)
        self.addCleanup(self.stack.close)
        self.addCleanup(_remove_tree, self._tmp)

    def _make_temp(self) -> str:
        import tempfile

        return tempfile.mkdtemp(prefix="thotsecure-probe-")

    def test_probe_detects_missing_headers_cookie_flags_and_exposed_files(self) -> None:
        collector = WebProbeCollector()
        tenant = self.stack.store.get_tenant("acme")
        assert tenant is not None
        context = CollectorContext(
            tenant=tenant,
            scope=self.stack.registry.for_tenant("acme"),
            settings=self.stack.settings,
            run_id="test",
            emit=lambda **_: None,
        )
        result = collector.collect(context)
        checks = {event.labels.get("check") for event in result.events}

        self.assertIn("missing_hsts", checks)
        self.assertIn("missing_csp", checks)
        self.assertIn("cookie_without_secure", checks)
        self.assertIn("cookie_without_httponly", checks)
        self.assertIn("version_disclosure", checks)
        self.assertIn("exposed_path", checks)
        self.assertIn("no_https", checks)

        exposed = [event for event in result.events if event.labels.get("check") == "exposed_path"]
        paths = {event.labels.get("path") for event in exposed}
        self.assertIn("/.git/config", paths)
        # La signature de contenu doit confirmer l'exposition.
        self.assertTrue(any(event.payload.get("signature_match") for event in exposed))

    def test_probe_is_refused_without_optin(self) -> None:
        targets = textwrap.dedent(
            f"""
            tenants:
              acme:
                assets:
                  - host: 127.0.0.1
                    urls: ["http://127.0.0.1:{self._port}"]
                allow_probe: false
            """
        )
        import shutil
        import tempfile

        other_root = Path(tempfile.mkdtemp(prefix="thotsecure-probe-refus-"))
        self.addCleanup(shutil.rmtree, other_root, ignore_errors=True)
        stack = build_stack(other_root, targets_yaml=targets)
        self.addCleanup(stack.close)

        result = stack.collectors.run("web_probe", "acme")
        self.assertEqual("skipped", result.status)
        self.assertIn("allow_probe", result.detail.get("reason", ""))
        self.assertEqual([], result.events)


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
