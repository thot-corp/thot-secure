#!/usr/bin/env python3
"""Réaligne toutes les URL du dépôt sur un nouveau couple ``owner/name``.

À quoi ça sert :

* **Publier sous un autre compte ou une autre organisation** que celle supposée par les
  fichiers livrés (README, `pyproject.toml`, `mkdocs.yml`, `CITATION.cff`, labels OCI de
  l'image, workflows, templates d'issues, SDK, scripts d'installation, kit éditorial) ;
* **Créer un fork** : un fork doit de toute façon pointer vers ses propres URL, sinon les
  badges, les liens de release et l'image GHCR renvoient chez l'amont.

Utilisation :

    python scripts/set-repository-urls.py --owner mon-compte --name thot-secure --check
    python scripts/set-repository-urls.py --owner mon-compte --name thot-secure

`--check` n'écrit rien : il affiche exactement ce qui serait modifié. C'est le mode à utiliser
en premier — un `--owner` mal orthographié laisserait un dépôt incohérent.

Le script ne touche ni `LICENSE`, ni les adresses de dons, ni les identifiants de paquets
(`thotsecure`, `thotsecure.cli`, `THOT_*`) : seules les **URL et les références d'hébergement**
changent.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

#: Identifiants actuels des fichiers livrés.
CURRENT_OWNER = "thotsecure"
CURRENT_REPO = "thot-secure"

#: Motifs de remplacement, dans l'ordre : le plus spécifique d'abord.
PATTERN_TEMPLATES: tuple[tuple[str, str], ...] = (
    # URL GitHub complètes (clone, compare, blob, issues, advisories, labels…)
    (f"github.com/{CURRENT_OWNER}/{CURRENT_REPO}", "github.com/{owner}/{repo}"),
    # Org seule : labels OCI, références de packages, badges
    (f"github.com/{CURRENT_OWNER}", "github.com/{owner}"),
    # Image de conteneur (GHCR)
    (f"ghcr.io/{CURRENT_OWNER}", "ghcr.io/{owner}"),
    # Identifiant propriétaire sans domaine (ex. `repo_name: thotsecure/thot-secure` de MkDocs)
    (f"{CURRENT_OWNER}/{CURRENT_REPO}", "{owner}/{repo}"),
    # Sponsors GitHub (le compte qui reçoit les dons peut différer de l'organisation)
    (f"github: [{CURRENT_OWNER}]", "github: [{sponsor}]"),
    (f"github: [ {CURRENT_OWNER} ]", "github: [ {sponsor} ]"),
    # GitHub Actions : variables d'environnement de publication d'image
    (f"GITHUB_REPOSITORY_OWNER: {CURRENT_OWNER}", "GITHUB_REPOSITORY_OWNER: {owner}"),
)

SCANNED_SUFFIXES = (
    ".md",
    ".markdown",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".py",
    ".sh",
    ".ps1",
    ".psm1",
    ".ts",
    ".tsx",
    ".js",
    ".go",
    ".mod",
    ".tf",
    ".tfvars",
    ".cff",
    ".html",
    ".css",
    ".service",
    ".example",
)
SCANNED_NAMES = ("Dockerfile", "Makefile", "NOTICE", "CITATION.cff", "CODEOWNERS")

#: Fichiers jamais modifiés par ce script.
PROTECTED = ("LICENSE", "NOTICE")
PROTECTED_DIRS = (
    ".git",
    "node_modules",
    "__pycache__",
    "data",
    ".venv",
    "venv",
    "dist",
    "build",
    "site",
)


def tracked_files(root: Path) -> list[Path]:
    """Fichiers suivis par Git (on ne touche jamais à un fichier non versionné)."""
    try:
        completed = subprocess.run(  # noqa: S603 - git local, arguments fixes
            ["git", "-C", str(root), "ls-files"],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        print(
            "! git ls-files a échoué : le script doit être lancé dans un dépôt Git", file=sys.stderr
        )
        return []
    return [root / line for line in completed.stdout.splitlines() if line.strip()]


def is_relevant(path: Path) -> bool:
    # Le script ne se réécrit jamais lui-même : ses constantes décrivent l'état ACTUEL du
    # dépôt, et une auto-modification le rendrait inutilisable au second passage.
    if path.name == Path(__file__).name:
        return False
    if any(part in PROTECTED_DIRS for part in path.parts):
        return False
    if path.name in PROTECTED:
        return False
    return path.suffix.lower() in SCANNED_SUFFIXES or path.name in SCANNED_NAMES


def build_patterns(owner: str, repo: str, sponsor: str) -> list[tuple[str, str]]:
    patterns: list[tuple[str, str]] = []
    for before, after_template in PATTERN_TEMPLATES:
        after = after_template.format(owner=owner, repo=repo, sponsor=sponsor)
        if before != after:
            patterns.append((before, after))
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Réaligne les URL du dépôt sur un couple owner/nom (publication ou fork)."
    )
    parser.add_argument("--owner", required=True, help="compte ou organisation GitHub cible")
    parser.add_argument("--name", required=True, help="nom du dépôt cible")
    parser.add_argument(
        "--sponsor",
        default=None,
        help="compte GitHub Sponsors (par défaut : le même que --owner)",
    )
    parser.add_argument("--root", default=".", help="racine du dépôt (défaut : répertoire courant)")
    parser.add_argument(
        "--check", action="store_true", help="n'écrit rien, affiche les changements"
    )
    args = parser.parse_args(argv)

    owner = args.owner.strip().lstrip("@").lower()
    repo = args.name.strip()
    sponsor = (args.sponsor or owner).strip().lstrip("@")

    if owner == CURRENT_OWNER and repo == CURRENT_REPO:
        print("v rien à faire : le dépôt pointe déjà vers cette cible")
        return 0
    if "/" in owner or " " in owner or not owner:
        print("x --owner invalide (attendu : un nom de compte ou d'organisation)", file=sys.stderr)
        return 2
    if "/" in repo or " " in repo or not repo:
        print("x --name invalide (attendu : un nom de dépôt)", file=sys.stderr)
        return 2

    root = Path(args.root).resolve()
    patterns = build_patterns(owner, repo, sponsor)

    print(f"Cible : {owner}/{repo} (sponsors : {sponsor})")
    print(f"Mode  : {'vérification (aucune écriture)' if args.check else 'écriture'}")
    print()

    changed_files = 0
    total_replacements = 0
    details: list[tuple[Path, int]] = []

    for path in tracked_files(root):
        if not is_relevant(path) or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        original = text
        replacements = 0
        for before, after in patterns:
            count = text.count(before)
            if count:
                text = text.replace(before, after)
                replacements += count

        if text == original:
            continue

        changed_files += 1
        total_replacements += replacements
        details.append((path.relative_to(root), replacements))
        if not args.check:
            path.write_text(text, encoding="utf-8", newline="")

    for path, count in sorted(details):
        print(f"  {path!s:<58} {count:>3} remplacement(s)")

    print()
    print(f"Bilan : {changed_files} fichier(s), {total_replacements} remplacement(s)")
    if args.check:
        print("Relancez sans --check pour appliquer.")
    else:
        print("Vérifiez ensuite :  git diff --stat")
        print('Puis committez :     git commit -am "chore: aligner les URL sur le dépôt publié"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
