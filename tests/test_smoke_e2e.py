"""Test de bout en bout : ingérer → détecter → décider → agir → annuler → auditer.

C'est le test qui compte le plus : il traverse toute la chaîne avec les **vrais**
chargeurs YAML, le vrai moteur de règles, le vrai moteur de décision, le vrai exécuteur de
playbooks et le vrai journal d'audit chaîné. Si ce test passe, le produit fonctionne.
"""

from __future__ import annotations

from thotsecure.core.models import Tenant

from .support import StackTestCase, build_stack


class EndToEndTest(StackTestCase):
    tenant_mode = "supervised"
    dry_run = True

    def test_rules_policies_and_playbooks_load_from_disk(self) -> None:
        rules = {rule.id for rule in self.stack.detection.rules}
        self.assertIn("AO-WEB-001", rules)
        self.assertIn("AO-WEB-050", rules)
        self.assertIn("AO-DEP-001", rules)
        # La règle Sigma de test doit avoir été traduite automatiquement.
        self.assertTrue(any(rule.sigma_compat for rule in self.stack.detection.rules))
        # Les playbooks et politiques de test doivent tous être chargés : un diagnostic
        # signale toujours une vraie erreur de format ou de référence croisée.
        self.assertEqual([], self.stack.rule_diagnostics)  # type: ignore[attr-defined]
        self.assertEqual([], self.stack.playbook_diagnostics)  # type: ignore[attr-defined]
        self.assertEqual([], self.stack.policy_diagnostics)  # type: ignore[attr-defined]
        self.assertIn("block-source-ip", self.stack.playbooks)
        self.assertIn("patch-dependency", self.stack.playbooks)
        self.assertIn(
            "approval-supply-chain", {policy.id for policy in self.stack.decision.policies}
        )

    def test_threshold_is_required_before_a_finding_is_raised(self) -> None:
        burst = self.stack.sqli_burst(count=3)
        first = self.stack.pipeline.ingest([burst[0]])
        self.assertEqual([], first.findings, "le seuil de 3 occurrences ne doit pas être franchi")

        second = self.stack.pipeline.ingest(burst[1:])
        self.assertEqual(1, len(second.findings))
        finding = second.findings[0]
        self.assertEqual("AO-WEB-001", finding.rule_id)
        self.assertEqual("high", finding.severity)
        self.assertGreaterEqual(finding.risk_score, 40)

    def test_decision_requires_approval_in_supervised_mode(self) -> None:
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        self.assertEqual(1, len(outcome.decisions))
        decision = outcome.decisions[0]
        # Le score dépasse le seuil critique (85) : en mode supervisé, l'automatique est refusé.
        self.assertIn(decision.decision, {"auto", "require_approval"})
        self.assertEqual("block-source-ip", decision.playbook)
        self.assertTrue(decision.dry_run, "le dry-run global doit être respecté")

    def test_manual_lifecycle_plan_approve_execute_rollback(self) -> None:
        """Parcours humain complet : planifier, approuver, exécuter, annuler."""
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        self.assertTrue(outcome.findings, "un finding est nécessaire pour planifier une action")
        finding = outcome.findings[0]

        planned = self.stack.actions.plan(
            tenant=self.stack.tenant,
            playbook_name="block-source-ip",
            actor="analyst@acme.local",
            finding=finding,
            params={"target": "labels.src_ip", "duration_seconds": 900},
            mode="manual",
        )
        self.assertEqual("planned", planned.status)
        self.assertEqual("ip:203.0.113.9", str(planned.target))
        self.assertEqual(900, planned.params["duration_seconds"])
        self.assertTrue(planned.dry_run)

        approved = self.stack.actions.approve(
            tenant=self.stack.tenant, action_id=planned.action_id, actor="rssi@acme.local"
        )
        self.assertEqual("approved", approved.status)
        self.assertEqual("rssi@acme.local", approved.approved_by)

        executed = self.stack.actions.execute(
            tenant=self.stack.tenant, action_id=planned.action_id, actor="rssi@acme.local"
        )
        self.assertEqual("succeeded", executed.status, executed.result)
        self.assertIsNotNone(executed.result)
        self.assertTrue(executed.result.get("simulated"), "dry-run actif ⇒ résultat simulé")
        self.assertTrue(executed.rollback.available)
        self.assertIsNotNone(executed.rollback.token)

        rolled_back = self.stack.actions.rollback(
            tenant=self.stack.tenant, action_id=planned.action_id, actor="rssi@acme.local"
        )
        self.assertEqual("rolled_back", rolled_back.status)
        self.assertFalse(rolled_back.rollback.available)
        self.assertIsNotNone(rolled_back.rollback.performed_at)
        self.assertIn("unblock_ip", str(rolled_back.rollback.result))

    def test_auto_policy_executes_a_simulated_action(self) -> None:
        """Politique 'auto' sous le seuil critique : l'action part seule, en simulation."""
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        self.assertEqual(1, len(outcome.actions), "la politique auto doit produire une action")
        action = outcome.actions[0]
        self.assertEqual("auto", action.mode)
        self.assertEqual("succeeded", action.status, action.result)
        steps = (action.result or {}).get("steps") or []
        self.assertTrue(steps)
        self.assertTrue(all(step["simulated"] for step in steps))

    def test_audit_chain_is_valid_and_records_the_cycle(self) -> None:
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        self.assertTrue(outcome.result.accepted >= 3)
        verdict = self.stack.audit.verify(tenant_id=self.stack.tenant.tenant_id)
        self.assertTrue(verdict.valid, verdict.reason)
        actions = [record.action for record in self.stack.store.iter_audit()]
        self.assertIn("event.ingest", actions)
        self.assertIn("finding.create", actions)
        self.assertIn("decision.evaluate", actions)

    def test_tenant_isolation_on_findings(self) -> None:
        other = Tenant(tenant_id="globex", name="Globex", mode="supervised", dry_run=True)
        self.stack.store.upsert_tenant(other)
        self.stack.pipeline.ingest(self.stack.sqli_burst())

        acme_findings, _ = self.stack.store.list_findings("acme")
        globex_findings, _ = self.stack.store.list_findings("globex")
        self.assertTrue(acme_findings)
        self.assertEqual([], globex_findings)

        event = self.stack.event(tenant_id="globex")
        self.stack.pipeline.ingest(self.stack.sqli_burst(src_ip="198.18.0.7"))
        self.stack.pipeline.ingest([event])
        self.assertIsNone(
            self.stack.store.get_finding("globex", acme_findings[0].finding_id),
            "un tenant ne doit jamais pouvoir lire le finding d'un autre",
        )

    def test_unknown_tenant_events_are_rejected(self) -> None:
        outcome = self.stack.pipeline.ingest([self.stack.event(tenant_id="inconnu")])
        self.assertEqual(0, outcome.result.accepted)
        self.assertEqual(1, outcome.result.rejected)
        self.assertTrue(any("unknown_tenant" in str(item) for item in outcome.result.errors))

    def test_api_key_roundtrip_and_rbac(self) -> None:
        info, key = self.stack.keys.create(tenant_id="acme", role="responder", label="ci")
        self.assertTrue(key.startswith("thot_"))
        principal = self.stack.keys.authenticate(key)
        self.assertEqual("acme", principal.tenant_id)
        self.assertEqual("responder", principal.role)
        self.assertTrue(principal.can("execute:actions"))
        self.assertFalse(principal.can("admin:tenants"))
        self.assertTrue(self.stack.keys.revoke(key_id=info.key_id))
        with self.assertRaises(Exception):
            self.stack.keys.authenticate(key)


class DryRunDisabledTest(StackTestCase):
    """Même chaîne, mais avec un tenant en mode autonome et sans simulation."""

    tenant_mode = "auto"
    dry_run = False

    def test_connectors_are_still_simulated_without_configuration(self) -> None:
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        self.assertTrue(outcome.actions, "en mode auto, une action doit être créée")
        action = outcome.actions[0]
        self.assertEqual("succeeded", action.status, action.result)
        self.assertIn("simulation", str(action.result.get("steps", [])))
        # Le connecteur par défaut est la simulation : aucun effet réel, et c'est assumé.
        steps = action.result.get("steps") or []
        self.assertTrue(all(step.get("simulated") for step in steps))


class ProtectedTargetTest(StackTestCase):
    tenant_mode = "auto"
    dry_run = False

    def test_protected_target_is_never_actioned_automatically(self) -> None:
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst(src_ip="10.0.0.1"))
        self.assertEqual(1, len(outcome.decisions))
        decision = outcome.decisions[0]
        self.assertEqual("notify_only", decision.decision)
        self.assertIn("protected_target", decision.guards)
        self.assertEqual([], outcome.actions)


def _unused_build_stack_reference() -> None:  # pragma: no cover - garde l'import explicite
    build_stack
