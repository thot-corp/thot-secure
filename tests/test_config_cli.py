"""Tests de configuration et de CLI : défauts sûrs, persistance des secrets, codes de sortie.

Ces deux surfaces sont les premières que rencontre un exploitant. Deux propriétés y sont
critiques et testées ici :

* **les défauts sont sûrs** — le mode simulation est actif, l'autonomie est supervisée, et
  toute déviation produit un avertissement explicite ;
* **la clé de signature est partagée entre processus** — sans cela, une clé API créée en CLI
  n'est pas vérifiable par le serveur, ce qui rend le produit inutilisable en pratique.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from thotsecure import FUNDING_ADDRESSES
from thotsecure.cli import EXIT_NEGATIVE, EXIT_OK, main
from thotsecure.core.config import DEV_BOOTSTRAP_KEY, Settings
from thotsecure.core.errors import ConfigError

from .support import build_stack


class SettingsDefaultsTest(unittest.TestCase):
    """Les défauts doivent protéger l'utilisateur contre lui-même."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="thotsecure-config-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self._tmp, ignore_errors=True))

    def _settings(self, **overrides: object) -> Settings:
        base = {
            "root_dir": str(self._tmp),
            "secret_key": "test-secret-key-for-unit-tests-only-0123456789",
        }
        base.update(overrides)
        return Settings(**base)  # type: ignore[arg-type]

    def test_safe_defaults(self) -> None:
        settings = self._settings()
        self.assertTrue(settings.dry_run, "le mode simulation doit être actif par défaut")
        self.assertEqual("supervised", settings.autonomy)
        self.assertEqual("dev", settings.env)
        self.assertTrue(settings.require_target_declaration)
        self.assertEqual(85.0, settings.critical_score_threshold)
        self.assertEqual(20, settings.max_actions_per_hour)

    def test_env_override_disables_dry_run_but_warns(self) -> None:
        os.environ["THOT_DRY_RUN"] = "false"
        os.environ["THOT_AUTONOMY"] = "auto"
        self.addCleanup(os.environ.pop, "THOT_DRY_RUN", None)
        self.addCleanup(os.environ.pop, "THOT_AUTONOMY", None)

        settings = Settings(root_dir=str(self._tmp))
        self.assertFalse(settings.dry_run)
        self.assertEqual("auto", settings.autonomy)
        warnings = settings.safety_warnings()
        self.assertTrue(any("EFFET RÉEL" in warning for warning in warnings))
        self.assertTrue(any("sans approbation" in warning for warning in warnings))

    def test_production_refuses_the_public_bootstrap_key(self) -> None:
        with self.assertRaises(ConfigError):
            Settings(
                root_dir=str(self._tmp),
                env="prod",  # type: ignore[arg-type]
                bootstrap_api_key=DEV_BOOTSTRAP_KEY,
                secret_key="x" * 40,
            )

    def test_secret_key_is_persisted_and_shared_between_instances(self) -> None:
        """Sans persistance, chaque processus génère sa propre clé : les clés API créées en
        CLI deviendraient invérifiables par le serveur."""
        first = self._settings()  # sans secret_key fourni
        first.root_dir = str(self._tmp)
        first.secret_key = ""
        first._resolve_secret_key()  # noqa: SLF001 - vérification ciblée de la résolution

        self.assertEqual("file", first.secret_key_source)
        self.assertTrue(first.secret_key_file.exists())
        self.assertGreaterEqual(len(first.secret_key), 32)

        second = self._settings()
        second.root_dir = str(self._tmp)
        second.secret_key = ""
        second._resolve_secret_key()  # noqa: SLF001
        self.assertEqual(first.secret_key, second.secret_key, "la clé doit être partagée")

    def test_db_path_resolution(self) -> None:
        relative = self._settings()
        self.assertEqual(self._tmp.resolve() / "data" / "thotsecure.db", relative.db_path)

        absolute = self._settings(db_url="sqlite:////tmp/absolu/thot.db")
        self.assertEqual(Path("/tmp/absolu/thot.db").resolve(), absolute.db_path)

    def test_public_summary_never_leaks_secrets(self) -> None:
        settings = self._settings(bootstrap_api_key="cle-secrete-de-test-abcdefghijkl")
        summary = settings.public_summary()
        rendered = str(summary)
        self.assertNotIn(settings.secret_key, rendered)
        self.assertNotIn("cle-secrete-de-test", rendered)
        self.assertIn("dry_run", summary)
        self.assertIn("unsafe_defaults", summary)


class CliTest(unittest.TestCase):
    """La CLI doit être scriptable : codes de sortie stables et sortie JSON exploitable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = Path(tempfile.mkdtemp(prefix="thotsecure-cli-"))
        cls.stack = build_stack(cls._tmp)
        cls.stack.close()

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil

        shutil.rmtree(cls._tmp, ignore_errors=True)

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        """Exécute la CLI en interceptant les sorties (aucun sous-processus)."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--root", str(self._tmp), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_rules_validate_succeeds(self) -> None:
        code, out, _ = self.run_cli("rules", "validate")
        self.assertEqual(EXIT_OK, code)
        self.assertIn("valide", out)

    def test_rules_validate_returns_3_on_invalid_rule(self) -> None:
        broken = self._tmp / "rules" / "casse.yaml"
        broken.write_text("id: AO-BROKEN\ntitle: sans match\nseverity: low\n", encoding="utf-8")
        self.addCleanup(broken.unlink)
        code, _, _ = self.run_cli("rules", "validate")
        self.assertEqual(EXIT_NEGATIVE, code, "une règle invalide doit produire le code 3")

    def test_policies_validate_succeeds(self) -> None:
        code, out, _ = self.run_cli("policies", "validate")
        self.assertEqual(EXIT_OK, code)
        self.assertIn("politique", out)

    def test_funding_shows_official_addresses(self) -> None:
        code, out, _ = self.run_cli("funding")
        self.assertEqual(EXIT_OK, code)
        self.assertIn(FUNDING_ADDRESSES["BTC"], out)
        self.assertIn(FUNDING_ADDRESSES["SOL"], out)
        self.assertIn("aucune contrepartie", out)
        self.assertIn("Bitcoin mainnet", out)

    def test_funding_json_is_machine_readable(self) -> None:
        import json

        code, out, _ = self.run_cli("--json", "funding")
        self.assertEqual(EXIT_OK, code)
        payload = json.loads(out)
        self.assertEqual(FUNDING_ADDRESSES["BTC"], payload["addresses"]["BTC"])
        self.assertIn("antiscam", payload)

    def test_tenant_key_and_findings_workflow(self) -> None:
        import json

        code, out, _ = self.run_cli(
            "--json", "tenant", "create", "--id", "clitest", "--name", "CLI Test", "--mode", "supervised"
        )
        self.assertEqual(EXIT_OK, code)
        self.assertEqual("clitest", json.loads(out)["tenant_id"])

        code, out, _ = self.run_cli(
            "--json", "key", "create", "--tenant", "clitest", "--role", "responder"
        )
        self.assertEqual(EXIT_OK, code)
        payload = json.loads(out)
        self.assertTrue(payload["api_key"].startswith("thot_"))
        self.assertEqual("responder", payload["role"])

        code, out, _ = self.run_cli("--json", "findings", "list", "--tenant", "clitest")
        self.assertEqual(EXIT_OK, code)
        self.assertEqual(0, json.loads(out)["count"])

        code, out, _ = self.run_cli("--json", "audit", "verify", "--tenant", "clitest")
        self.assertEqual(EXIT_OK, code)
        self.assertTrue(json.loads(out)["valid"])

    def test_demo_populates_the_pipeline(self) -> None:
        import json

        code, out, _ = self.run_cli("--json", "demo", "--tenant", "demo")
        self.assertEqual(EXIT_OK, code)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["accepted"], 1)
        self.assertTrue(payload["findings"], "la démonstration doit produire un finding")
        finding = payload["findings"][0]
        self.assertIn(finding["severity"], {"high", "critical"})
        self.assertGreater(finding["risk_score"], 40)

    def test_doctor_reports_safety_state(self) -> None:
        import json

        code, out, _ = self.run_cli("--json", "doctor")
        self.assertIn(code, {EXIT_OK, EXIT_NEGATIVE})
        payload = json.loads(out)
        checks = {check["check"]: check for check in payload["checks"]}
        self.assertTrue(checks["base de données"]["ok"])
        self.assertIn("mode simulation", checks)
        self.assertTrue(checks["mode simulation"]["ok"], "le dry-run doit être actif en test")

    def test_unknown_action_is_rejected(self) -> None:
        code, _, err = self.run_cli(
            "--json", "actions", "plan", "--tenant", "demo", "--playbook", "playbook-inexistant"
        )
        self.assertEqual(1, code)
        self.assertIn("not_found", err.lower())

    def test_audit_export_produces_cef(self) -> None:
        # Le test crée lui-même son tenant : il ne dépend pas de l'ordre d'exécution des
        # autres tests, qui partagent ce répertoire temporaire.
        self.run_cli("--json", "tenant", "create", "--id", "auditexport", "--name", "Export")
        code, out, _ = self.run_cli("audit", "export", "--tenant", "auditexport", "--format", "cef")
        self.assertEqual(EXIT_OK, code)
        self.assertIn("CEF:0|", out)
        self.assertIn("auditexport", out)


class SecretRedactionTest(unittest.TestCase):
    """La redaction est une frontière de sécurité : un secret qui fuit dans un journal est un
    incident. Ces cas viennent de formats réellement observés dans des journaux applicatifs."""

    def test_secrets_are_masked(self) -> None:
        from thotsecure.core.util import redact_secrets

        cases = {
            "X-API-Key: thot_K3D0E950D60C_abcdefghijklmnopqrstuvwx": "thot_K3D0E950D60C",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh": "eyJhbGciOiJIUzI1NiJ9",
            "token=abcdef123456": "abcdef123456",
            "access_token=xyz789abc": "xyz789abc",
            "password=hunter2": "hunter2",
            "Cookie: session=abc123def456": "abc123def456",
            "https://api.exemple.fr/v1?api_key=SECRETVALUE": "SECRETVALUE",
        }
        for raw, secret in cases.items():
            masked = redact_secrets(raw)
            self.assertNotIn(secret, masked, f"secret non masqué dans : {raw}")
            self.assertIn("redacted", masked.lower())

    def test_normal_text_is_preserved(self) -> None:
        from thotsecure.core.util import redact_secrets

        for text in (
            "path=/api/v1/events status=403 src=203.0.113.9",
            "mot de passe oublié (aucun secret ici)",
            "GET /produit?id=1 UNION SELECT 1-- HTTP/1.1",
        ):
            self.assertEqual(text, redact_secrets(text), "la redaction ne doit pas mutiler le texte")

    def test_payload_is_truncated(self) -> None:
        from thotsecure.core.util import redact_secrets

        masked = redact_secrets("A" * 10_000)
        self.assertLess(len(masked), 10_000)
        self.assertIn("tronqué", masked)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
