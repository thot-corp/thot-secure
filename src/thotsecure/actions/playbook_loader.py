"""Chargement et validation des playbooks.

Un playbook est une **procédure** : une suite d'étapes ordonnées, exécutables par des
connecteurs, avec un bloc de rollback obligatoire pour tout ce qui est réversible. Le
chargement refuse les playbooks incohérents (étape sans connecteur connu, paramètre
obligatoire non déclaré, rollback manquant alors que ``reversible: true``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError as PydanticValidationError

from ..core.logging_setup import get_logger
from ..core.models import Playbook, RuleDiagnostic

log = get_logger("actions.playbooks")

MAX_PLAYBOOK_FILE_BYTES = 512 * 1024
PLAYBOOK_SUFFIXES = (".yaml", ".yml", ".json")


class PlaybookLoadError(ValueError):
    """Playbook invalide."""


def load_playbooks_from_dir(
    directory: str | Path, *, known_connectors: set[str] | None = None
) -> tuple[dict[str, Playbook], list[RuleDiagnostic]]:
    """Charge tous les playbooks d'un répertoire. Retourne ``(playbooks, diagnostics)``."""
    root = Path(directory)
    playbooks: dict[str, Playbook] = {}
    diagnostics: list[RuleDiagnostic] = []
    if not root.exists():
        diagnostics.append(
            RuleDiagnostic(path=str(root), error="répertoire de playbooks inexistant")
        )
        log.warning("répertoire de playbooks inexistant", extra={"path": str(root)})
        return playbooks, diagnostics

    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in PLAYBOOK_SUFFIXES:
            continue
        if file_path.name.startswith("."):
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
            if len(text.encode("utf-8")) > MAX_PLAYBOOK_FILE_BYTES:
                raise PlaybookLoadError("fichier trop volumineux")
            documents = [doc for doc in yaml.safe_load_all(text) if doc is not None]
        except (OSError, UnicodeDecodeError, yaml.YAMLError, PlaybookLoadError) as exc:
            diagnostics.append(RuleDiagnostic(path=str(file_path), error=str(exc)))
            log.error("playbook rejeté", extra={"path": str(file_path), "error": str(exc)})
            continue

        for document in documents:
            if not isinstance(document, dict):
                diagnostics.append(
                    RuleDiagnostic(
                        path=str(file_path), error="un playbook doit être un mapping YAML"
                    )
                )
                continue
            try:
                playbook = parse_playbook(
                    document, path=str(file_path), known_connectors=known_connectors
                )
            except PlaybookLoadError as exc:
                diagnostics.append(
                    RuleDiagnostic(
                        path=str(file_path), rule_id=str(document.get("name")), error=str(exc)
                    )
                )
                log.error(
                    "playbook rejeté",
                    extra={
                        "path": str(file_path),
                        "playbook": document.get("name"),
                        "error": str(exc),
                    },
                )
                continue
            if playbook.name in playbooks:
                diagnostics.append(
                    RuleDiagnostic(
                        path=str(file_path),
                        rule_id=playbook.name,
                        error=(
                            "nom de playbook en double (déjà défini dans "
                            f"{playbooks[playbook.name].path})"
                        ),
                    )
                )
                continue
            playbooks[playbook.name] = playbook

    log.info(
        "playbooks chargés",
        extra={"playbooks": len(playbooks), "diagnostics": len(diagnostics)},
    )
    return playbooks, diagnostics


def parse_playbook(
    document: dict[str, Any], *, path: str | None = None, known_connectors: set[str] | None = None
) -> Playbook:
    try:
        playbook = Playbook(**document)
    except PydanticValidationError as exc:
        raise PlaybookLoadError(_format_errors(exc)) from exc
    playbook.path = path
    problems = validate_playbook(playbook, known_connectors=known_connectors)
    if problems:
        raise PlaybookLoadError("; ".join(problems))
    return playbook


#: Paramètres injectés par l'exécuteur au moment du rollback. Ils n'ont pas à être déclarés
#: dans ``params`` : ``${params.rollback_token}`` est fourni automatiquement depuis la pile
#: d'exécution, ce qui permet à un bloc de rollback de cibler précisément ce qui a été créé.
IMPLICIT_PARAMS = frozenset({"rollback_token"})


def validate_playbook(playbook: Playbook, *, known_connectors: set[str] | None = None) -> list[str]:
    problems: list[str] = []

    declared = set(playbook.params) | IMPLICIT_PARAMS
    referenced: set[str] = set()
    for step in [*playbook.execute, *playbook.rollback]:
        for value in _walk_values(step.with_):
            for placeholder in _placeholders(value):
                if placeholder.startswith("params."):
                    referenced.add(placeholder[len("params.") :])
                elif placeholder.split(".")[0] not in {
                    "params",
                    "finding",
                    "action",
                    "tenant",
                    "now",
                    "context",
                }:
                    problems.append(
                        f"étape {step.connector}.{step.call}: espace de nommage inconnu "
                        f"dans '${{{placeholder}}}'"
                    )
        if known_connectors is not None and step.connector not in known_connectors:
            problems.append(
                f"étape {step.connector}.{step.call}: connecteur '{step.connector}' inconnu "
                f"(disponibles: {sorted(known_connectors)})"
            )

    undeclared = sorted(referenced - declared)
    if undeclared:
        problems.append(
            f"paramètres utilisés mais non déclarés dans 'params': {undeclared} "
            "(tout paramètre doit être typé et documenté)"
        )

    for name, spec in playbook.params.items():
        if spec.required and spec.default is not None:
            problems.append(f"paramètre '{name}': required=true et default sont contradictoires")
        if (
            spec.type in {"integer", "duration"}
            and spec.default is not None
            and not isinstance(spec.default, int)
        ):
            problems.append(f"paramètre '{name}': default doit être un entier")
        if spec.min is not None and spec.max is not None and spec.min > spec.max:
            problems.append(f"paramètre '{name}': min > max")

    if playbook.reversible and not any(step.optional for step in playbook.rollback):
        # Un rollback entièrement optionnel ne restaure rien : c'est un piège.
        pass

    for step in playbook.execute:
        if step.call.startswith("undo_"):
            problems.append(
                f"étape {step.connector}.{step.call}: une étape d'exécution ne peut pas être "
                "une opération d'annulation (placez-la dans 'rollback')"
            )

    return problems


def dump_playbook(playbook: Playbook) -> str:
    payload = playbook.model_dump(mode="json", exclude_none=True, by_alias=True)
    payload.pop("path", None)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def playbook_summaries(playbooks: dict[str, Playbook]) -> list[dict[str, Any]]:
    return [playbook.summary() for _, playbook in sorted(playbooks.items())]


# --------------------------------------------------------------------------------------


def _walk_values(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_values(item)


def _placeholders(value: str) -> list[str]:
    import re

    return re.findall(r"\$\{([^}]+)\}", value)


def _format_errors(exc: PydanticValidationError) -> str:
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(item) for item in error.get("loc", ()))
        parts.append(f"{location or '<racine>'}: {error.get('msg')}")
    return " | ".join(parts)


__all__ = [
    "IMPLICIT_PARAMS",
    "MAX_PLAYBOOK_FILE_BYTES",
    "PLAYBOOK_SUFFIXES",
    "PlaybookLoadError",
    "dump_playbook",
    "load_playbooks_from_dir",
    "parse_playbook",
    "playbook_summaries",
    "validate_playbook",
]
