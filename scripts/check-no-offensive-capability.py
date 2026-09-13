#!/usr/bin/env python3
"""Garde-fou : Thot Secure ne contient aucune capacité offensive.

Ce script est exécuté en pre-commit, en CI et par la suite de tests. Il échoue (code 3) si
l'une des constructions suivantes apparaît dans le code livré :

* **accès shell inversé** : ``/dev/tcp/``, ``pty.spawn``, ``socket`` + ``dup2`` ;
* **outils offensifs invoqués** : ``sqlmap``, ``hydra``, ``nmap -sS``, ``masscan``,
  ``msfconsole``, ``metasploit``, ``meterpreter``… ;
* **charges utiles d'exploitation** : ``shellcode``, ``reverse_shell``, ``bind_shell`` ;
* **déni de service** : boucles de requêtes concurrentes non bornées (``ThreadPoolExecutor``
  sans limite dans un script réseau), ``while True: requests.get``.

Pourquoi un script dédié plutôt qu'une simple relecture : cet invariant est **structurel**.
Il doit être vérifiable par une machine, à chaque commit, y compris pour une contribution
extérieure. Un projet qui se dit défensif sans le vérifier finit par ne plus l'être.

Les noms d'outils apparaissent légitimement dans ``rules/`` et ``policies/`` : ce sont des
**motifs de détection** (repérer le user-agent d'un scanner dans un journal). Ces répertoires
sont donc exclus du contrôle — mais les *appels* à ces outils, dans le code, ne le sont pas.
"""

from __future__ import annotations

import contextlib
import re
import sys
from pathlib import Path


def _configure_output_encoding() -> None:
    """Force UTF-8 sur les flux standard (sans effet hors Windows, jamais bloquant).

    Sans cela, un terminal Windows en page de code cp1252 produit des octets non UTF-8 : le
    message reste lisible à l'écran, mais tout appelant qui décode en UTF-8 (CI, pre-commit,
    suite de tests) reçoit du texte corrompu. Un contrôle de sécurité doit être lisible par
    une machine autant que par un humain.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


_configure_output_encoding()

#: Répertoires analysés : le code livré, celui qui s'exécute.
SCANNED_DIRECTORIES = ("src", "examples", "sdks", "scripts", "deploy", "tests", "web/src")

#: Répertoires exclus : les noms d'outils offensifs y sont des motifs de DÉTECTION.
EXCLUDED_DIRECTORIES = ("rules", "policies", "playbooks", "node_modules", "__pycache__", "data")

#: Motifs interdits, avec l'explication associée. Volontairement précis : un faux positif
#: bloquerait une contribution légitime et décrédibiliserait le contrôle.
FORBIDDEN_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"/dev/tcp/", "accès shell inversé via les pseudo-fichiers de Bash", "error"),
    (
        r"pty\.spawn|os\.openpty|import\s+pty\b",
        "allocation de terminal pour une session interactive",
        "error",
    ),
    (
        r"dup2\s*\(\s*\w+\.fileno",
        "redirection de descripteurs vers un socket (shell inversé)",
        "error",
    ),
    (
        r"shellcode|reverse[_ ]shell|bind[_ ]shell|meterpreter|beacon\.dll",
        "charge utile d'exploitation",
        "error",
    ),
    (
        r"\bmsfconsole\b|\bmetasploit\b|cobalt\s*strike|sliver\s*>",
        "cadriciel d'exploitation",
        "error",
    ),
    # Les invocations peuvent être écrites en ligne de commande (`sqlmap -u …`) ou en liste
    # d'arguments (`["sqlmap", "-u", …]`) : on couvre les deux formes.
    (r"\bsqlmap\b[^\n]{0,24}(-u\b|--url)", "invocation de l'outil d'injection SQL", "error"),
    (r"\bhydra\b[^\n]{0,24}-[lLPp]", "invocation de l'outil de force brute", "error"),
    (r"\bnmap\b[^\n]{0,24}-s[SsUu]", "invocation de scan de ports", "error"),
    (r"\bmasscan\b|\bzgrab\b|\bunicornscan\b", "invocation d'outil de balayage massif", "error"),
    (
        r"\bnikto\b[^\n]{0,24}-host|\bwfuzz\b[^\n]{0,16}-c\b|\bgobuster\b[^\n]{0,16}dir",
        "invocation de scanner de vulnérabilités",
        "error",
    ),
    (r"exploit\s*\(\s*(target|victim|host)", "appel d'exploitation d'une cible", "error"),
    (
        r"while\s+True\s*:\s*\n\s*[^\n]*requests\.(get|post)\s*\(",
        "boucle de requêtes non bornée (déni de service)",
        "error",
    ),
    (
        r"ThreadPoolExecutor\s*\(\s*max_workers\s*=\s*None",
        "parallélisme non borné sur une opération réseau",
        "warning",
    ),
)

#: Marqueur explicite permettant de justifier une exception dans le code lui-même.
ALLOWLIST_MARKER = "thotsecure: defensive-detection-pattern"

#: Extensions analysées.
SCANNED_SUFFIXES = (
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".sh",
    ".bash",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".tf",
    ".rego",
    ".conf",
)


def scan_file(path: Path) -> list[tuple[int, str, str, str]]:
    """Analyse un fichier et retourne les correspondances interdites."""
    findings: list[tuple[int, str, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Un fichier peut déclarer sa légitimité (règle de détection embarquée dans du code,
    # documentation d'un test…) : le marqueur doit être explicite et visible dans le fichier.
    if ALLOWLIST_MARKER in text:
        return findings

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        # Les commentaires qui décrivent une interdiction ne sont pas une infraction.
        if stripped.startswith(("#", "//", "*", "/*")) and not re.search(
            r"(curl|wget|nc)\s", stripped
        ):
            continue
        for pattern, reason, severity in FORBIDDEN_PATTERNS:
            if re.search(pattern, line):
                findings.append((line_number, severity, reason, stripped[:160]))
    return findings


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory in SCANNED_DIRECTORIES:
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
                continue
            if any(part in EXCLUDED_DIRECTORIES for part in path.parts):
                continue
            files.append(path)
    return sorted(files)


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    if not root.is_dir():
        print(f"x répertoire introuvable : {root}", file=sys.stderr)
        return 1

    errors = 0
    warnings = 0
    scanned = 0
    for path in iter_files(root):
        scanned += 1
        findings = scan_file(path)
        for line_number, severity, reason, excerpt in findings:
            relative = path.relative_to(root)
            if severity == "error":
                errors += 1
                print(f"x {relative}:{line_number} — {reason}")
            else:
                warnings += 1
                print(f"! {relative}:{line_number} — {reason} (avertissement)")
            print(f"    {excerpt}")

    print()
    print(f"Thot Secure est strictement défensif — {scanned} fichier(s) analysé(s)")
    if errors:
        print(f"x {errors} construction(s) offensive(s) détectée(s) : la contribution est refusée")
        print("  Si ce code est un MOTIF DE DÉTECTION légitime, ajoutez le marqueur")
        print(f"  « {ALLOWLIST_MARKER} » dans le fichier et expliquez-le en commentaire.")
        return 3
    if warnings:
        print(f"! {warnings} avertissement(s) à justifier en revue")
    print("v aucune capacité offensive détectée")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
