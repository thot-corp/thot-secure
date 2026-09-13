"""Les playbooks **livrés** s'exécutent et s'annulent réellement, placeholders compris.

Pourquoi ce fichier existe, alors que `test_smoke_e2e.py` traverse déjà toute la chaîne : le
reste de la suite utilise des playbooks *de test*, écrits dans le même dépôt mais plus simples.
Les playbooks réellement expédiés utilisent des placeholders que le contexte du moteur doit
fournir (`${finding.remediation}`) et des jetons injectés au moment du rollback
(`${params.rollback_token}`). Deux défauts réels ont échappé à toute la suite parce qu'ils ne
se voient que sur les fichiers livrés :

* un placeholder absent du contexte fait **échouer le playbook entier**, y compris une étape
  marquée `optional: true` — donc le ticket n'est jamais ouvert, en silence ;
* une priorité de fusion inversée dans la construction du contexte fait que
  `${params.rollback_token}` n'est jamais résolu, donc l'annulation échoue.

Ces deux défauts sont testés ici par un **effet observable sur le disque**, pas par
l'inspection d'un statut : le ticket est créé, puis il porte la trace de sa clôture.
"""

from __future__ import annotations

from pathlib import Path

from thotsecure.actions.playbook_loader import load_playbooks_from_dir

from .support import StackTestCase

REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_PLAYBOOKS_DIR = REPO_ROOT / "playbooks"


def load_shipped_playbooks() -> dict:
    """Charge la bibliothèque réellement livrée, et refuse tout élément rejeté au passage."""
    playbooks, diagnostics = load_playbooks_from_dir(SHIPPED_PLAYBOOKS_DIR)
    problems = [(item.path, item.error) for item in diagnostics]
    if problems:  # pragma: no cover - dépend du dépôt, pas du test
        raise AssertionError(f"playbooks livrés rejetés au chargement : {problems}")
    return playbooks


class ShippedPlaybookEndToEndTest(StackTestCase):
    """Exécution et annulation réelles des playbooks livrés.

    ``dry_run = False`` est **nécessaire** ici, et c'est un choix explicite : en simulation,
    les connecteurs locaux n'écrivent rien, et l'effet observable disparaît — or c'est
    précisément l'effet observable qui prouve que le placeholder a été résolu. Tout se passe
    dans un répertoire temporaire, avec des connecteurs locaux : aucune requête réseau, aucune
    écriture hors du bac à sable du test.
    """

    dry_run = False

    def setUp(self) -> None:
        super().setUp()
        # Les playbooks livrés remplacent ceux du socle de test, à noms identiques.
        self.shipped = load_shipped_playbooks()
        self.stack.actions.playbooks.update(self.shipped)

    def _tickets_dir(self) -> Path:
        return self.stack.root / "data" / "tickets"

    def _plan_approve_execute(self, finding, playbook_name: str, params: dict) -> object:
        action = self.stack.actions.plan(
            tenant=self.stack.tenant,
            playbook_name=playbook_name,
            actor="analyst@acme.local",
            finding=finding,
            params=params,
            mode="manual",
        )
        self.stack.actions.approve(
            tenant=self.stack.tenant, action_id=action.action_id, actor="rssi@acme.local"
        )
        return self.stack.actions.execute(
            tenant=self.stack.tenant, action_id=action.action_id, actor="rssi@acme.local"
        )

    def _block_and_collect_ticket(self):
        """Exécute le blocage livré et retourne ``(action, fichier de ticket)``."""
        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        finding = outcome.findings[0]
        self.assertTrue(
            finding.remediation.strip(),
            "la règle AO-WEB-001 livrée doit fournir une remédiation (sinon le test ne prouve rien)",
        )

        executed = self._plan_approve_execute(
            finding, "block-source-ip", {"target": "labels.src_ip", "duration_seconds": 900}
        )
        self.assertEqual("succeeded", executed.status, executed.result)

        tickets = sorted(self._tickets_dir().glob("*.md"))
        self.assertEqual(
            1,
            len(tickets),
            "l'étape de ticketing, même optionnelle, ne doit pas être sautée par un placeholder "
            "non résolu",
        )
        body = tickets[0].read_text(encoding="utf-8")
        self.assertIn(finding.remediation, body, "la remédiation doit figurer dans le ticket")
        # La cible et le titre du finding sont, eux aussi, des placeholders résolus.
        self.assertIn("Blocage de 203.0.113.9", body)
        self.assertIn(finding.finding_id, body, "le ticket doit rester rattaché à son finding")
        return executed, tickets[0]

    def test_the_shipped_block_playbook_opens_a_ticket_containing_the_remediation(self) -> None:
        """`${finding.remediation}` doit être résolu : sinon le ticket n'existe pas."""
        self._block_and_collect_ticket()

    def test_the_shipped_rollback_closes_the_ticket_through_the_injected_token(self) -> None:
        """`${params.rollback_token}` doit être résolu : sinon la clôture échoue."""
        executed, ticket = self._block_and_collect_ticket()

        rolled_back = self.stack.actions.rollback(
            tenant=self.stack.tenant, action_id=executed.action_id, actor="rssi@acme.local"
        )
        self.assertEqual(
            "rolled_back",
            rolled_back.status,
            "l'annulation doit aboutir : un échec ici signifie que le jeton de rollback n'a pas "
            f"été transmis au connecteur ({rolled_back.rollback.result})",
        )
        self.assertIn(
            "## Clôture",
            ticket.read_text(encoding="utf-8"),
            "le ticket doit porter la trace de sa clôture, par identifiant et non par recherche",
        )

    def test_a_failed_rollback_keeps_the_token_and_is_audited(self) -> None:
        """Un playbook de rollback cassé ne doit pas faire perdre le moyen d'annuler."""
        executed, _ = self._block_and_collect_ticket()

        original = self.stack.actions.playbooks["block-source-ip"]
        # On casse **volontairement** le rollback : placeholder inexistant. `model_copy` ne
        # valide pas, ce qui est exactement ce qu'il faut pour simuler un playbook défectueux.
        broken_step = original.rollback[0].model_copy(
            update={"with_": {"ip": "${params.inexistant}"}}
        )
        broken = original.model_copy(update={"rollback": [broken_step, *original.rollback[1:]]})
        self.stack.actions.playbooks["block-source-ip"] = broken
        self.addCleanup(self.stack.actions.playbooks.__setitem__, "block-source-ip", original)

        failed = self.stack.actions.rollback(
            tenant=self.stack.tenant, action_id=executed.action_id, actor="rssi@acme.local"
        )
        self.assertEqual("failed", failed.status)
        self.assertTrue(
            failed.rollback.available,
            "le jeton de rollback doit rester utilisable après un échec : sinon l'opérateur "
            "perd le seul moyen de lever son propre blocage",
        )
        self.assertIn("inexistant", str(failed.rollback.result))

        # Le playbook réparé doit pouvoir annuler ensuite, avec le **même** jeton.
        self.stack.actions.playbooks["block-source-ip"] = original
        recovered = self.stack.actions.rollback(
            tenant=self.stack.tenant, action_id=executed.action_id, actor="rssi@acme.local"
        )
        self.assertEqual("rolled_back", recovered.status, recovered.rollback.result)

    def test_every_shipped_playbook_resolves_its_placeholders(self) -> None:
        """Générique : aucun playbook livré ne référence un champ absent du contexte.

        L'exécution se fait en simulation : ce qui est vérifié ici est la **résolution** des
        placeholders, pas l'effet des connecteurs (qui peuvent légitimement refuser une cible
        hors périmètre déclaré).
        """
        from thotsecure.core.errors import PlaybookError

        outcome = self.stack.pipeline.ingest(self.stack.sqli_burst())
        finding = outcome.findings[0]
        action = self.stack.actions.plan(
            tenant=self.stack.tenant,
            playbook_name="block-source-ip",
            actor="analyst@acme.local",
            finding=finding,
            params={"target": "labels.src_ip", "duration_seconds": 900},
            mode="manual",
        )
        context = self.stack.actions._execution_context(self.stack.tenant, action)

        samples = {
            "ip": "203.0.113.9",
            "host": "shop.acme.fr",
            "url": "https://shop.acme.fr/",
            "path": "/tmp/exemple",
            "package": "jinja2",
            "secret": "exemple/secret",
            "duration": 900,
            "string": "exemple",
        }
        checked = 0
        for name, playbook in self.shipped.items():
            params: dict = {}
            for param_name, spec in playbook.params.items():
                default = spec.default
                params[param_name] = (
                    default if default not in (None, "") else samples.get(spec.type, "exemple")
                )
            for step in [*playbook.execute, *playbook.rollback]:
                # Le rollback reçoit, comme dans le moteur, le jeton issu de la dernière étape.
                step_params = dict(params)
                step_params.setdefault("rollback_token", "jeton-exemple")
                try:
                    from thotsecure.actions.executor import render_params

                    render_params(step, {**context, "params": step_params})
                except PlaybookError as exc:  # pragma: no cover - échec attendu si régression
                    self.fail(f"playbook livré {name}: placeholder non résolu ({step.call}) — {exc}")
                checked += 1
        self.assertGreaterEqual(checked, 20, "trop peu d'étapes vérifiées pour être utile")


if __name__ == "__main__":  # pragma: no cover
    import unittest

    unittest.main()
