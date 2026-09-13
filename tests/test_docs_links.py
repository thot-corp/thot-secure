"""Cohérence de la documentation : liens internes et ancres.

`mkdocs build --strict` transforme tout avertissement en erreur : un lien vers un fichier
inexistant, ou vers une ancre absente, **fait échouer le déploiement de la documentation**.
C'est arrivé sur le premier tag : 18 liens de `docs/cli.md` étaient préfixés d'un `../` de trop,
et 5 renvoyaient vers un fichier situé hors de `docs/` (impossible à résoudre pour MkDocs).

Ces tests rejouent le contrôle localement, sans installer MkDocs ni accéder au réseau, pour
qu'une contribution ne puisse pas casser le site de documentation sans être arrêtée.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER = REPO_ROOT / "scripts" / "check-docs-links.py"


class DocumentationLinksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        completed = subprocess.run(
            [sys.executable, str(CHECKER), "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        cls.exit_code = completed.returncode
        cls.stdout = completed.stdout
        try:
            cls.report = json.loads(completed.stdout)
        except ValueError:
            cls.report = {"broken": [], "files": 0}

    def test_checker_exists(self) -> None:
        self.assertTrue(CHECKER.is_file(), "scripts/check-docs-links.py doit exister")

    def test_no_broken_internal_link(self) -> None:
        broken = self.report.get("broken", [])
        details = "\n".join(
            f"  {item['file']} -> {item['target']} : {item['reason']}" for item in broken
        )
        self.assertEqual(
            [],
            broken,
            "des liens internes de la documentation sont cassés — "
            f"`mkdocs build --strict` échouerait :\n{details}",
        )

    def test_documentation_is_substantial(self) -> None:
        """Le contrôle ne doit pas passer « parce qu'il n'y a rien à vérifier »."""
        self.assertGreaterEqual(self.report.get("files", 0), 25, "documentation trop pauvre")
        self.assertGreaterEqual(
            self.report.get("internal", 0), 200, "trop peu de liens internes pour être crédible"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
