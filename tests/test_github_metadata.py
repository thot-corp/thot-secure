"""Cohérence des métadonnées GitHub : toute étiquette référencée doit exister.

Une étiquette absente n'est **pas** une erreur pour GitHub : elle est silencieusement ignorée.
Résultat observé sur ce dépôt : les pull requests de Dependabot arrivaient sans aucune
étiquette, l'étiquetage automatique échouait, et les modèles d'issue proposaient des étiquettes
qui n'existaient pas. Rien de tout cela n'apparaît dans un journal — d'où ce test.

Il vérifie que l'unique source de vérité (`.github/labels.yml`) déclare bien toutes les
étiquettes demandées par la configuration du dépôt. Il ne contacte pas GitHub : il compare des
fichiers.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB = REPO_ROOT / ".github"


def declared_labels() -> set[str]:
    """Étiquettes déclarées dans la source de vérité."""
    document = yaml.safe_load((GITHUB / "labels.yml").read_text(encoding="utf-8"))
    return {str(entry["name"]) for entry in document if isinstance(entry, dict)}


def dependabot_labels() -> set[str]:
    document = yaml.safe_load((GITHUB / "dependabot.yml").read_text(encoding="utf-8"))
    labels: set[str] = set()
    for update in document.get("updates") or []:
        for label in update.get("labels") or []:
            labels.add(str(label))
    return labels


def labeler_labels() -> set[str]:
    """Clés de premier niveau de labeler.yml : ce sont les étiquettes posées par chemin."""
    document = yaml.safe_load((GITHUB / "labeler.yml").read_text(encoding="utf-8"))
    return {str(key) for key in (document or {})}


def template_labels() -> set[str]:
    """Étiquettes demandées par les modèles d'issue (`labels:` au format YAML)."""
    labels: set[str] = set()
    for path in sorted((GITHUB / "ISSUE_TEMPLATE").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            continue
        for label in document.get("labels") or []:
            labels.add(str(label))
    config = GITHUB / "ISSUE_TEMPLATE" / "config.yml"
    if config.exists():
        document = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
        for entry in document.get("labels") or []:
            if isinstance(entry, dict):
                labels.add(str(entry.get("name")))
    return {label for label in labels if label}


class GithubLabelsTest(unittest.TestCase):
    def test_labels_file_is_not_empty(self) -> None:
        self.assertGreaterEqual(len(declared_labels()), 20, "taxonomie d'étiquettes suspicieusement pauvre")

    def test_dependabot_labels_are_declared(self) -> None:
        missing = sorted(dependabot_labels() - declared_labels())
        self.assertEqual(
            [],
            missing,
            "Dependabot applique ces étiquettes : elles doivent exister, sinon elles sont "
            "silencieusement ignorées et ses pull requests arrivent sans étiquette",
        )

    def test_labeler_labels_are_declared(self) -> None:
        missing = sorted(labeler_labels() - declared_labels())
        self.assertEqual([], missing, "étiquette(s) posée(s) par chemin mais non déclarée(s)")

    def test_issue_template_labels_are_declared(self) -> None:
        missing = sorted(template_labels() - declared_labels())
        self.assertEqual([], missing, "étiquette(s) proposée(s) par un modèle d'issue inconnue(s)")

    def test_labeler_config_uses_the_v5_shape(self) -> None:
        """Le format v4 (liste plate de globs) est rejeté par l'action v5."""
        document = yaml.safe_load((GITHUB / "labeler.yml").read_text(encoding="utf-8"))
        for label, rules in (document or {}).items():
            with self.subTest(label=label):
                self.assertIsInstance(rules, list, f"règle '{label}' : liste de règles attendue")
                for rule in rules:
                    self.assertIn(
                        "changed-files",
                        rule,
                        f"règle '{label}' : la clé 'changed-files' est obligatoire en v5",
                    )

    def test_the_labeler_workflow_does_not_pass_an_empty_sync_labels(self) -> None:
        """Régression nommée : `sync-labels: ''` fait échouer actions/labeler@v5.

        Le contrôle porte sur le YAML **analysé**, pas sur le texte : le fichier explique
        justement cette cause d'échec dans un commentaire, et une recherche textuelle se
        déclencherait sur sa propre documentation.
        """
        workflow = yaml.safe_load(
            (GITHUB / "workflows" / "labeler.yml").read_text(encoding="utf-8")
        )
        steps = workflow["jobs"]["label"]["steps"]
        labeler_steps = [step for step in steps if "labeler" in str(step.get("uses", ""))]
        self.assertTrue(labeler_steps, "plus aucune étape actions/labeler : le test ne prouve rien")
        for step in labeler_steps:
            with self.subTest(step=step.get("name")):
                self.assertNotIn(
                    "sync-labels",
                    step.get("with") or {},
                    "une chaîne vide n'est pas un scalaire YAML valide : l'action lève « Input "
                    "does not meet YAML 1.2 Core Schema specification ». Laisser la valeur par "
                    "défaut (false).",
                )

    def test_pyproject_extra_groups_are_documented(self) -> None:
        """Tout extra déclaré doit être cité dans la documentation d'installation."""
        document = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        extras = set((document.get("project") or {}).get("optional-dependencies") or {})
        installation = (REPO_ROOT / "docs" / "installation.md").read_text(encoding="utf-8")
        for extra in sorted(extras):
            with self.subTest(extra=extra):
                self.assertIn(
                    f".[{extra}]",
                    installation,
                    f"l'extra '{extra}' existe mais n'est documenté nulle part : "
                    "personne ne saura qu'il est disponible",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
