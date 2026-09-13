"""Réécrit les liens MkDocs sortant de `docs/` en URL absolues GitHub.

`mkdocs build --strict` échoue sur tout lien relatif qui sort de `docs_dir` : les fichiers
racine du dépôt (CHANGELOG, CONTRIBUTING, SECURITY, LICENSE…) ne font pas partie des
« documentation files », et MkDocs ne peut donc pas les résoudre. Le site publié pointe vers
leur source canonique sur la forge.

Usage :
    python scripts/fix-docs-external-links.py            # affiche ce qui serait changé
    python scripts/fix-docs-external-links.py --write    # applique
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
BLOB_BASE = "https://github.com/thot-corp/thot-secure/blob/main"

#: Fichiers de la racine du dépôt, tels qu'ils sont cités depuis `docs/`.
ROOT_FILES = (
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "README.md",
    "NOTICE",
    "LICENSE",
)

_LINK = re.compile(r"\]\((\.\./)+(" + "|".join(re.escape(name) for name in ROOT_FILES) + r")\)")


def rewrite(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"]({BLOB_BASE}/{match.group(2)})"

    return _LINK.sub(replace, text), count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="écrit les fichiers modifiés")
    args = parser.parse_args()

    changed = 0
    total = 0
    for path in sorted(DOCS_DIR.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        updated, count = rewrite(text)
        if not count:
            continue
        changed += 1
        total += count
        print(f"{path.relative_to(REPO_ROOT)} : {count} lien(s)")
        if args.write:
            path.write_text(updated, encoding="utf-8")

    verb = "réécrit(s)" if args.write else "à réécrire"
    print(f"\n{total} lien(s) {verb} dans {changed} fichier(s)")
    if not args.write and total:
        print("Relancez avec --write pour appliquer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
