#!/usr/bin/env python3
"""Vérifie les liens internes de la documentation (et les ancres déclarées).

Pourquoi ce script existe : ``mkdocs build --strict`` transforme **tout avertissement en
erreur**. Un lien vers un fichier qui n'existe pas, ou vers une ancre absente, fait donc
échouer le déploiement de la documentation — et une documentation qui ne se déploie plus est
une documentation que personne ne lit.

Le script ne nécessite ni réseau ni MkDocs : il analyse les fichiers Markdown de ``docs/`` et
résout les liens relatifs sur le disque.

Utilisation :

    python scripts/check-docs-links.py            # rapport lisible
    python scripts/check-docs-links.py --json     # sortie machine (CI)
    python scripts/check-docs-links.py --strict   # code de sortie 3 si un problème est trouvé

Les liens externes (http/https/mailto) sont **ignorés** : les vérifier exigerait du réseau, et
une CI de documentation ne doit pas dépendre de la disponibilité d'un site tiers. Ils sont
seulement comptés.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

#: Liens Markdown : [texte](cible "titre optionnel")
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
#: Titres Markdown, pour construire l'ensemble des ancres valides.
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*?)\s*$", re.MULTILINE)
#: Blocs de code : on n'y cherche pas de liens (les exemples contiennent des URL factices).
CODE_FENCE = re.compile(r"^(```|~~~)", re.MULTILINE)

SCHEMES = ("http://", "https://", "mailto:", "tel:", "ftp://")


def strip_code_blocks(text: str) -> str:
    """Retire les blocs de code : un exemple ne doit pas produire de faux positif."""
    lines = text.splitlines()
    output: list[str] = []
    inside = False
    fence = ""
    for line in lines:
        marker = CODE_FENCE.match(line)
        if marker:
            if not inside:
                inside, fence = True, marker.group(1)
            elif line.startswith(fence):
                inside = False
            output.append("")
            continue
        # Le code inline `...` est neutralisé : il contient souvent des chemins d'exemple.
        output.append("" if inside else re.sub(r"`[^`]*`", "", line))
    return "\n".join(output)


def slugify(heading: str) -> str:
    """Convertit un titre en ancre, **exactement comme MkDocs**.

    MkDocs (extension ``toc`` de Python-Markdown) supprime les diacritiques avant de
    fabriquer l'ancre : « Format des règles de détection » devient
    ``format-des-regles-de-detection``, sans accents. Un vérificateur qui conserverait les
    accents signalerait tous ces liens comme cassés — un faux positif qui masquerait les
    vrais problèmes.
    """
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"[\s]+", "-", text).strip("-")


def suggest_anchor(anchor: str, known: set[str], *, limit: int = 2) -> list[str]:
    """Propose les ancres existantes les plus proches (préfixe commun le plus long).

    Sans suggestion, corriger un lien mort demande d'ouvrir le fichier cible et de relire les
    titres : c'est exactement le genre de friction qui fait qu'on laisse un lien cassé.
    """
    anchor = anchor.lower()
    scored: list[tuple[int, str]] = []
    for candidate in known:
        common = 0
        for left, right in zip(anchor, candidate, strict=False):
            if left != right:
                break
            common += 1
        if common >= 8 or candidate in anchor or anchor in candidate:
            scored.append((common, candidate))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [candidate for _, candidate in scored[:limit]]


def collect_anchors(path: Path, text: str) -> set[str]:
    """Ancres disponibles dans un fichier.

    Attention : les titres sont extraits du texte **brut**, pas du texte nettoyé. Un titre
    comme ``## 3. `audit verify` échoue`` produit l'ancre ``3-audit-verify-echoue`` : le code
    inline fait partie du titre. Le nettoyer ferait disparaître « audit verify » et ferait
    signaler comme cassés des liens parfaitement valides — un faux positif qui masquerait les
    vrais problèmes.
    """
    anchors: set[str] = set()
    for _, heading in HEADING_PATTERN.findall(text):
        anchors.add(slugify(heading))
    # Ancre explicite : <a name="..."> ou id="..."
    anchors.update(re.findall(r'<a\s+(?:name|id)="([^"]+)"', text))
    anchors.update(re.findall(r'\sid="([^"]+)"', text))
    return anchors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vérifie les liens internes de docs/.")
    parser.add_argument("--docs", default="docs", help="répertoire de documentation")
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    parser.add_argument("--strict", action="store_true", help="code 3 si un problème est détecté")
    args = parser.parse_args(argv)

    docs = Path(args.docs).resolve()
    if not docs.is_dir():
        print(f"x répertoire de documentation introuvable : {docs}", file=sys.stderr)
        return 1

    files = sorted(docs.rglob("*.md"))
    anchors_by_file: dict[Path, set[str]] = {}
    for path in files:
        anchors_by_file[path] = collect_anchors(
            path, path.read_text(encoding="utf-8", errors="replace")
        )

    broken: list[dict[str, object]] = []
    external = 0
    internal = 0

    for path in files:
        text = strip_code_blocks(path.read_text(encoding="utf-8", errors="replace"))
        for target in LINK_PATTERN.findall(text):
            if target.startswith(SCHEMES):
                external += 1
                continue
            if target.startswith("#"):
                internal += 1
                anchor = target[1:].lower()
                if anchor and anchor not in anchors_by_file[path]:
                    broken.append(
                        {
                            "file": str(path.relative_to(docs)),
                            "target": target,
                            "reason": "ancre absente dans le même fichier",
                            "suggestions": suggest_anchor(anchor, anchors_by_file[path]),
                        }
                    )
                continue

            internal += 1
            file_part, _, anchor = target.partition("#")
            resolved = (path.parent / file_part).resolve()
            if not resolved.exists():
                broken.append(
                    {
                        "file": str(path.relative_to(docs)),
                        "target": target,
                        "reason": "fichier introuvable",
                    }
                )
                continue
            # Un lien qui sort de `docs/` est introuvable **pour MkDocs**, même si le fichier
            # existe sur le disque : `mkdocs build --strict` échoue dessus. C'est le piège le
            # plus courant d'un dépôt où la documentation vit dans un sous-répertoire, et il
            # ne se voit pas en local — d'où ce contrôle explicite.
            if not resolved.is_relative_to(docs):
                broken.append(
                    {
                        "file": str(path.relative_to(docs)),
                        "target": target,
                        "reason": (
                            "cible hors de docs/ : MkDocs ne peut pas la résoudre — utilisez "
                            "l'URL absolue du fichier sur la forge"
                        ),
                    }
                )
                continue
            if anchor and resolved.suffix == ".md":
                known = anchors_by_file.get(resolved)
                if known is None:
                    known = collect_anchors(
                        resolved, resolved.read_text(encoding="utf-8", errors="replace")
                    )
                    anchors_by_file[resolved] = known
                if anchor.lower() not in known:
                    broken.append(
                        {
                            "file": str(path.relative_to(docs)),
                            "target": target,
                            "reason": "ancre absente dans le fichier cible",
                            "suggestions": suggest_anchor(anchor, known),
                        }
                    )

    if args.json:
        print(
            json.dumps(
                {"files": len(files), "internal": internal, "external": external, "broken": broken},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for item in broken:
            print(f"x {item['file']} -> {item['target']} : {item['reason']}")
            hints = item.get("suggestions") or []
            for hint in hints:
                print(f"    suggestion : #{hint}")
        print()
        print(
            f"{len(files)} fichier(s) analysé(s) — {internal} lien(s) interne(s), "
            f"{external} lien(s) externe(s) ignoré(s)"
        )
        if broken:
            print(
                f"x {len(broken)} lien(s) cassé(s) : `mkdocs build --strict` échouerait sur ces "
                "avertissements"
            )
        else:
            print("v aucun lien interne cassé")

    if broken and args.strict:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
