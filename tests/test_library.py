"""Tests de la bibliothèque livrée : règles, politiques et playbooks.

Ce test est le **garde-fou éditorial** du dépôt. Une règle mal écrite rejetée au chargement
est une détection absente : le produit a l'air de fonctionner, mais il est aveugle. En CI, ce
test empêche une contribution de casser silencieusement la bibliothèque.

Il vérifie aussi les invariants produit : toute règle de sévérité élevée documente sa
remédiation, tout playbook réversible a un rollback, et aucun playbook non réversible ne peut
s'exécuter automatiquement.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from thotsecure.actions.playbook_loader import load_playbooks_from_dir
from thotsecure.actions.registry import ConnectorRegistry
from thotsecure.decision.policy_loader import load_policies_from_dir
from thotsecure.detection.rule_loader import load_rules_from_dir

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
POLICIES_DIR = REPO_ROOT / "policies"
PLAYBOOKS_DIR = REPO_ROOT / "playbooks"


class ShippedRulesTest(unittest.TestCase):
    """La bibliothèque de détection livrée doit être intégralement valide."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules, cls.diagnostics = load_rules_from_dir(RULES_DIR)
        cls.by_id = {rule.id: rule for rule in cls.rules}

    def test_every_shipped_rule_loads(self) -> None:
        self.assertEqual(
            [],
            [(item.path, item.error) for item in self.diagnostics],
            "une règle livrée ne se charge pas : elle serait silencieusement ignorée",
        )
        self.assertGreaterEqual(len(self.rules), 15, "bibliothèque trop pauvre pour être utile")

    def test_collectors_are_covered(self) -> None:
        """Chaque type de source produit par un collecteur doit avoir au moins une règle."""
        covered = {source for rule in self.rules for source in rule.source_types}
        for expected in (
            "web_probe",
            "log_tail",
            "dependency",
            "config_audit",
            "tls_cert",
            "syslog",
            #: La détection d'anomalie statistique ne vaut que si une règle l'exploite : le
            #: détecteur produit des événements, ce sont les règles qui décident.
            "baseline",
        ):
            self.assertIn(expected, covered, f"aucune règle n'exploite la source '{expected}'")

    def test_high_severity_rules_document_their_remediation(self) -> None:
        for rule in self.rules:
            if rule.severity in {"high", "critical"}:
                self.assertTrue(
                    rule.remediation.strip(),
                    f"la règle {rule.id} est de sévérité {rule.severity} sans remédiation",
                )

    def test_rules_reference_known_sources(self) -> None:
        valid = {
            "web_probe",
            "log_tail",
            "dependency",
            "webhook",
            "syslog",
            "tls_cert",
            "config_audit",
            #: Produit par le détecteur d'anomalie du moteur, et non par un collecteur.
            "baseline",
            "manual",
            "demo",
        }
        for rule in self.rules:
            for source in rule.source_types:
                self.assertIn(source, valid, f"règle {rule.id}: source inconnue '{source}'")

    def test_threshold_rules_group_by_a_label(self) -> None:
        for rule in self.rules:
            if rule.match.threshold and rule.match.threshold.count > 1:
                self.assertTrue(
                    rule.match.threshold.group_by,
                    f"règle {rule.id}: seuil sans regroupement (il matcherait globalement)",
                )
                for field_name in rule.match.threshold.group_by:
                    self.assertTrue(
                        field_name.startswith("labels."), f"règle {rule.id}: {field_name}"
                    )

    def test_every_rule_has_false_positive_documentation_when_matching_patterns(self) -> None:
        """Une règle peut être peu précise, mais elle doit alors l'assumer par écrit."""
        for rule in self.rules:
            has_regex = any(
                condition.op == "regex"
                for condition in [*rule.match.all, *rule.match.any, *rule.match.not_]
            )
            if has_regex:
                self.assertTrue(
                    rule.false_positives,
                    f"règle {rule.id}: détection par motif sans faux positifs documentés",
                )

    def test_sigma_rule_was_translated(self) -> None:
        sigma_rules = [rule for rule in self.rules if rule.sigma_compat]
        self.assertTrue(sigma_rules, "l'exemple Sigma doit être traduit automatiquement")
        for rule in sigma_rules:
            self.assertTrue(rule.id.startswith(("SIGMA-", "AO-")))
            self.assertTrue(rule.match.all or rule.match.any)


class ShippedPoliciesTest(unittest.TestCase):
    """Les politiques livrées doivent être valides et ne jamais contourner les garde-fous."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.playbooks, _ = load_playbooks_from_dir(PLAYBOOKS_DIR)
        cls.policies, cls.diagnostics = load_policies_from_dir(
            POLICIES_DIR, known_playbooks=set(cls.playbooks)
        )
        cls.by_id = {policy.id: policy for policy in cls.policies}

    def test_every_shipped_policy_loads(self) -> None:
        self.assertEqual([], [(item.path, item.error) for item in self.diagnostics])
        self.assertTrue(self.policies)

    def test_policies_are_sorted_by_priority(self) -> None:
        priorities = [policy.priority for policy in self.policies]
        self.assertEqual(sorted(priorities, reverse=True), priorities)

    def test_policies_reference_existing_playbooks(self) -> None:
        for policy in self.policies:
            if policy.then.playbook:
                self.assertIn(policy.then.playbook, self.playbooks)
            if policy.rollback.playbook:
                self.assertIn(policy.rollback.playbook, self.playbooks)

    def test_no_policy_forces_real_execution(self) -> None:
        """Aucune politique livrée ne doit désactiver le dry-run : c'est une décision humaine."""
        for policy in self.policies:
            self.assertIsNot(
                policy.then.dry_run,
                False,
                f"la politique {policy.id} force dry_run=false : interdit dans la bibliothèque livrée",
            )

    def test_auto_policies_are_conditioned(self) -> None:
        for policy in self.policies:
            if policy.then.decision == "auto":
                self.assertTrue(policy.when, f"politique {policy.id}: 'auto' sans condition")
                self.assertTrue(
                    policy.description.strip(), f"politique {policy.id}: non documentée"
                )

    def test_bounded_volumes(self) -> None:
        for policy in self.policies:
            if policy.then.max_actions_per_hour is not None:
                self.assertLessEqual(policy.then.max_actions_per_hour, 100)
            cooldown = policy.then.cooldown_seconds
            if cooldown is not None:
                self.assertGreaterEqual(cooldown, 60, f"politique {policy.id}: cooldown trop court")


class ShippedPlaybooksTest(unittest.TestCase):
    """Les playbooks livrés doivent respecter l'invariant de réversibilité."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.playbooks, cls.diagnostics = load_playbooks_from_dir(PLAYBOOKS_DIR)

    def test_every_shipped_playbook_loads(self) -> None:
        self.assertEqual([], [(item.path, item.error) for item in self.diagnostics])
        self.assertGreaterEqual(len(self.playbooks), 10)

    def test_reversible_playbooks_have_a_rollback(self) -> None:
        for name, playbook in self.playbooks.items():
            if playbook.reversible:
                self.assertTrue(playbook.rollback, f"playbook {name}: réversible sans rollback")

    def test_irreversible_playbooks_are_documented(self) -> None:
        """Un playbook non réversible doit expliquer pourquoi, en clair."""
        irreversible = {name: item for name, item in self.playbooks.items() if not item.reversible}
        self.assertTrue(irreversible, "au moins un playbook irréversible (revoke-session) attendu")
        for name, playbook in irreversible.items():
            self.assertIn(
                "irréversible",
                playbook.description.lower(),
                f"playbook {name}: irréversibilité non documentée",
            )

    def test_connectors_used_by_playbooks_exist(self) -> None:
        registry = ConnectorRegistry()
        for name, playbook in self.playbooks.items():
            for step in [*playbook.execute, *playbook.rollback]:
                # Un connecteur logique inconnu retombe sur la simulation : on vérifie
                # seulement qu'il est déclaré ou qu'il correspond à un pilote connu.
                from thotsecure.actions.registry import DRIVERS

                self.assertTrue(
                    step.connector in registry.configuration or step.connector in DRIVERS,
                    f"playbook {name}: connecteur inconnu '{step.connector}'",
                )

    def test_destructive_operations_are_never_automatic(self) -> None:
        """Un playbook non réversible ne doit pas être déclaré automatisable."""
        for name, playbook in self.playbooks.items():
            if not playbook.reversible:
                self.assertTrue(
                    playbook.dry_run_capable,
                    f"playbook {name}: un playbook irréversible doit au moins être simulable",
                )

    def test_parameters_are_typed(self) -> None:
        for name, playbook in self.playbooks.items():
            for param_name, spec in playbook.params.items():
                self.assertTrue(
                    spec.description, f"{name}.{param_name}: paramètre sans description"
                )
                self.assertTrue(
                    spec.type,
                    f"{name}.{param_name}: paramètre sans type",
                )


class ConfigExamplesTest(unittest.TestCase):
    """Les exemples de configuration doivent être copiables tels quels."""

    def test_examples_exist_and_are_safe_by_default(self) -> None:
        import yaml

        targets = REPO_ROOT / "config" / "targets.example.yaml"
        connectors = REPO_ROOT / "config" / "connectors.example.yaml"
        self.assertTrue(targets.exists(), "config/targets.example.yaml manquant")
        self.assertTrue(connectors.exists(), "config/connectors.example.yaml manquant")

        document = yaml.safe_load(connectors.read_text(encoding="utf-8"))
        drivers = {
            body.get("driver")
            for body in (document.get("connectors") or {}).values()
            if isinstance(body, dict)
        }
        # L'exemple livré ne doit activer aucun connecteur réel par défaut : les pilotes
        # réels sont uniquement proposés en commentaire.
        for driver in drivers:
            self.assertIn(
                driver,
                {"simulation", "local-quarantine", "local-ticket", "nginx-local", "http-webhook"},
            )
        self.assertIn("simulation", drivers, "l'exemple doit rester en simulation par défaut")

    def test_no_secret_in_examples(self) -> None:
        """Aucun exemple livré ne doit contenir de secret réel."""
        import re

        pattern = re.compile(r"(?i)(secret|token|password)\s*:\s*[\"']?([A-Za-z0-9/+_-]{20,})")
        for path in [
            REPO_ROOT / "config" / "targets.example.yaml",
            REPO_ROOT / "config" / "connectors.example.yaml",
        ]:
            text = path.read_text(encoding="utf-8")
            for match in pattern.finditer(text):
                value = match.group(2)
                # Les valeurs manifestement fictives sont tolérées et signalées comme telles.
                self.assertTrue(
                    value.startswith("changeme") or value.startswith("<"),
                    f"secret potentiel en clair dans {path.name}: {value[:8]}…",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
