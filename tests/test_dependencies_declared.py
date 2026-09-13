"""Aucune dépendance fantôme : tout paquet importé par le produit doit être déclaré.

Un paquet installé sur la machine de développement mais absent de `pyproject.toml` produit
la pire des pannes : tout va bien chez l'auteur, et le produit ne démarre pas chez
l'utilisateur. C'est exactement ce qui est arrivé à `python-multipart` — la console
embarquée l'utilise à travers `Form(...)`, FastAPI lève une `RuntimeError` à l'import, et
`tests/test_api.py` ne pouvait pas être importé sur une installation propre : la suite
s'arrêtait à 76 tests sur 378, en CI uniquement.

Ce test lit les imports **réels** du paquet (analyse syntaxique, aucune exécution) et les
compare à ce que le projet déclare. Il ne cherche pas à être exhaustif sur les cas tordus :
il attrape le cas qui compte, celui du paquet oublié.
"""

from __future__ import annotations

import ast
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO_ROOT / "src" / "thotsecure"

#: Modules importés par le code mais fournis par le projet lui-même ou par la bibliothèque
#: standard, donc jamais déclarés comme dépendances.
FIRST_PARTY = {"thotsecure"}

#: Dépendances optionnelles : importées **paresseusement** par `importlib.import_module`
#: (donc invisibles pour une analyse d'imports) et volontairement absentes des dépendances
#: obligatoires. Elles sont listées ici pour que l'intention soit explicite.
OPTIONAL_AT_RUNTIME = {"psycopg", "psycopg2", "psycopg_pool", "psycopg2.extras"}


def declared_distributions() -> set[str]:
    """Noms de distribution déclarés en dépendances obligatoires ou optionnelles."""
    document = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project") or {}
    declared: set[str] = set()
    for requirement in project.get("dependencies") or []:
        declared.add(_distribution_name(requirement))
    for group in (project.get("optional-dependencies") or {}).values():
        for requirement in group:
            declared.add(_distribution_name(requirement))
    return {name for name in declared if name}


def _distribution_name(requirement: str) -> str:
    """`pydantic-settings>=2.2` → `pydantic_settings` (forme normalisée des imports)."""
    name = requirement.split(";")[0].split("[")[0]
    for separator in (">=", "<=", "==", "!=", "~=", ">", "<", " "):
        name = name.split(separator)[0]
    return name.strip().lower().replace("-", "_")


def imported_top_level_modules() -> dict[str, set[str]]:
    """Modules de premier niveau importés par le paquet, avec les fichiers concernés."""
    found: dict[str, set[str]] = {}
    for path in sorted(SOURCE_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    found.setdefault(root, set()).add(path.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # import relatif : interne au paquet
                    continue
                if node.module:
                    root = node.module.split(".")[0]
                    found.setdefault(root, set()).add(path.name)
    return found


class DeclaredDependenciesTest(unittest.TestCase):
    def test_every_imported_package_is_declared(self) -> None:
        declared = declared_distributions()
        stdlib = set(sys.stdlib_module_names)
        missing: list[str] = []
        for module, files in sorted(imported_top_level_modules().items()):
            normalized = module.lower().replace("-", "_")
            if normalized in FIRST_PARTY or normalized in stdlib:
                continue
            if normalized in OPTIONAL_AT_RUNTIME:
                continue
            # Correspondance tolérante : `pydantic_settings` déclaré, `pydantic_settings`
            # importé ; `yaml` importé pour la distribution `PyYAML`.
            if normalized in declared or _alias_of(normalized) in declared:
                continue
            missing.append(f"{module} (importé par {', '.join(sorted(files))})")
        self.assertEqual(
            [],
            missing,
            "dépendance(s) utilisée(s) mais non déclarée(s) dans pyproject.toml : "
            "le produit fonctionnerait chez vous et échouerait à l'installation",
        )

    def test_known_import_aliases_are_covered(self) -> None:
        """Les noms d'import qui diffèrent du nom de distribution sont déclarés par alias."""
        declared = declared_distributions()
        # `import yaml` correspond à la distribution `PyYAML` ; `import multipart` à
        # `python-multipart`. Ces deux-là sont utilisés par le produit : on vérifie que
        # l'alias est bien reconnu, sinon le test ci-dessus serait un faux négatif.
        self.assertIn("pyyaml", declared)
        self.assertIn("python_multipart", declared)
        self.assertEqual("pyyaml", _alias_of("yaml"))
        self.assertEqual("python_multipart", _alias_of("multipart"))

    def test_the_console_form_dependency_is_present(self) -> None:
        """Régression nommée : sans `python-multipart`, `import thotsecure.main` échoue."""
        self.assertIn("python_multipart", declared_distributions())
        routes = SOURCE_DIR / "ui" / "routes.py"
        self.assertIn(
            "Form(",
            routes.read_text(encoding="utf-8"),
            "si la console n'utilise plus de formulaire, la dépendance peut être retirée",
        )


def _alias_of(module: str) -> str:
    """Nom de distribution associé à un nom d'import connu, quand les deux diffèrent."""
    return {
        "yaml": "pyyaml",
        "multipart": "python_multipart",
        "jwt": "pyjwt",
        "dateutil": "python_dateutil",
        "PIL": "pillow",
    }.get(module, module)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
