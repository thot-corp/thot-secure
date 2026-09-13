"""Chargement et validation des politiques de décision (*policy-as-code*).

La décision est le point le plus sensible d'un SOAR : c'est ici qu'on autorise une machine à
agir sur l'infrastructure. Trois principes s'appliquent donc :

1. **Strict par défaut** : une politique dont un champ est inconnu est rejetée (une faute de
   frappe dans ``then.playbook`` doit être une erreur bruyante, pas une décision silencieuse
   qui ne fait rien — ou pire, qui fait autre chose).
2. **Une politique ne peut pas lever un garde-fou** : ``max_actions_per_hour``,
   l'allowlist de cibles protégées et le dry-run global sont appliqués par le moteur,
   après la politique. Le format ne permet pas de les contourner.
3. **Traçable** : chaque politique porte une priorité explicite et un identifiant stable,
   cités dans le finding, l'action et le journal d'audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError as PydanticValidationError

from ..core.logging_setup import get_logger
from ..core.models import Policy, RuleDiagnostic

log = get_logger("decision.loader")

MAX_POLICY_FILE_BYTES = 512 * 1024
POLICY_SUFFIXES = (".yaml", ".yml", ".json")

#: Clés autorisées dans ``when``. Toute autre clé est une erreur de chargement : c'est ce
#: qui empêche une politique « qui a l'air de filtrer » de matcher en réalité tout le reste.
ALLOWED_WHEN_KEYS = frozenset(
    {
        "finding.severity",
        "finding.risk_score",
        "finding.confidence",
        "finding.rule_id",
        "finding.tags",
        "finding.tags_any",
        "finding.status",
        "finding.count",
        "finding.title",
        "finding.mitre",
        "tenant.id",
        "tenant.mode",
        "environment",
        "time.hour_utc",
        "time.weekday",
        "action.playbook",
    }
)

#: Opérateurs autorisés dans une condition comparateur (``{gte: 70}``).
ALLOWED_WHEN_OPERATORS = frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "matches"})

#: Décisions valides, du plus permissif au plus conservateur (documentation).
DECISION_ORDER = ("auto", "require_approval", "notify_only", "ignore")


class PolicyLoadError(ValueError):
    """Politique invalide."""


def load_policies_from_dir(
    directory: str | Path, *, known_playbooks: set[str] | None = None
) -> tuple[list[Policy], list[RuleDiagnostic]]:
    """Charge toutes les politiques d'un répertoire, triées par priorité décroissante."""
    root = Path(directory)
    policies: list[Policy] = []
    diagnostics: list[RuleDiagnostic] = []
    if not root.exists():
        diagnostics.append(RuleDiagnostic(path=str(root), error="répertoire de politiques inexistant"))
        log.warning("répertoire de politiques inexistant", extra={"path": str(root)})
        return policies, diagnostics

    seen: dict[str, str] = {}
    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in POLICY_SUFFIXES:
            continue
        if file_path.name.startswith(".") or "rego" in file_path.parts:
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
            if len(text.encode("utf-8")) > MAX_POLICY_FILE_BYTES:
                raise PolicyLoadError("fichier de politique trop volumineux")
            documents = [doc for doc in yaml.safe_load_all(text) if doc is not None]
        except (OSError, UnicodeDecodeError, yaml.YAMLError, PolicyLoadError) as exc:
            diagnostics.append(RuleDiagnostic(path=str(file_path), error=str(exc)))
            log.error("politique rejetée", extra={"path": str(file_path), "error": str(exc)})
            continue

        for document in documents:
            if not isinstance(document, dict):
                diagnostics.append(RuleDiagnostic(path=str(file_path), error="la politique doit être un mapping"))
                continue
            try:
                policy = parse_policy(document, path=str(file_path), known_playbooks=known_playbooks)
            except PolicyLoadError as exc:
                diagnostics.append(
                    RuleDiagnostic(path=str(file_path), rule_id=str(document.get("id")), error=str(exc))
                )
                log.error(
                    "politique rejetée",
                    extra={"path": str(file_path), "policy_id": document.get("id"), "error": str(exc)},
                )
                continue
            if policy.id in seen:
                diagnostics.append(
                    RuleDiagnostic(
                        path=str(file_path),
                        rule_id=policy.id,
                        error=f"identifiant de politique en double (déjà défini dans {seen[policy.id]})",
                    )
                )
                continue
            seen[policy.id] = str(file_path)
            policies.append(policy)

    policies.sort(key=lambda item: (-item.priority, item.id))
    log.info(
        "politiques chargées",
        extra={
            "policies": len(policies),
            "enabled": sum(1 for policy in policies if policy.enabled),
            "diagnostics": len(diagnostics),
        },
    )
    return policies, diagnostics


def parse_policy(
    document: dict[str, Any], *, path: str | None = None, known_playbooks: set[str] | None = None
) -> Policy:
    try:
        policy = Policy(**document)
    except PydanticValidationError as exc:
        raise PolicyLoadError(_format_errors(exc)) from exc
    policy.path = path
    problems = validate_policy(policy, known_playbooks=known_playbooks)
    if problems:
        raise PolicyLoadError("; ".join(problems))
    return policy


def validate_policy(policy: Policy, *, known_playbooks: set[str] | None = None) -> list[str]:
    problems: list[str] = []

    unknown = sorted(set(policy.when) - ALLOWED_WHEN_KEYS)
    if unknown:
        problems.append(
            f"clés inconnues dans 'when': {unknown} "
            f"(autorisées: {sorted(ALLOWED_WHEN_KEYS)})"
        )

    for key, value in policy.when.items():
        if isinstance(value, dict):
            bad_ops = sorted(set(value) - ALLOWED_WHEN_OPERATORS)
            if bad_ops:
                problems.append(f"opérateurs inconnus pour '{key}': {bad_ops}")
            if key == "finding.severity":
                for operator in ("gt", "gte", "lt", "lte"):
                    if operator in value and str(value[operator]).lower() not in {
                        "info",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    }:
                        problems.append(
                            f"'finding.severity' avec '{operator}' attend un niveau "
                            "(info|low|medium|high|critical)"
                        )
        elif isinstance(value, (list, tuple, str, int, float, bool)):
            continue
        else:
            problems.append(f"valeur invalide pour '{key}': {type(value).__name__}")

    if policy.then.playbook and known_playbooks is not None:
        if policy.then.playbook not in known_playbooks:
            problems.append(
                f"then.playbook='{policy.then.playbook}' n'existe pas "
                f"(disponibles: {sorted(known_playbooks)})"
            )
    if policy.rollback.playbook and known_playbooks is not None:
        if policy.rollback.playbook not in known_playbooks:
            problems.append(f"rollback.playbook='{policy.rollback.playbook}' n'existe pas")

    if policy.then.decision == "auto" and not policy.when:
        problems.append(
            "une politique 'auto' sans aucune condition 'when' exécuterait des actions sur "
            "tous les findings : c'est interdit (ajoutez au moins une condition)"
        )

    if policy.then.dry_run is False and policy.then.decision == "auto":
        # Autorisé, mais cela désactive une protection : on exige une description explicite.
        if not policy.description.strip():
            problems.append(
                "une politique 'auto' avec dry_run=false doit être documentée ('description')"
            )

    if policy.then.max_actions_per_hour is not None and policy.then.max_actions_per_hour > 100:
        problems.append("then.max_actions_per_hour > 100 : refusé (risque de tempête d'actions)")

    for field_name, seconds in (
        ("then.cooldown_seconds", policy.then.cooldown_seconds),
        ("rollback.auto_after_seconds", policy.rollback.auto_after_seconds),
    ):
        if seconds is not None and seconds < 0:
            problems.append(f"{field_name} ne peut pas être négatif")

    return problems


def _format_errors(exc: PydanticValidationError) -> str:
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(item) for item in error.get("loc", ()))
        parts.append(f"{location or '<racine>'}: {error.get('msg')}")
    return " | ".join(parts)


def dump_policy(policy: Policy) -> str:
    payload = policy.model_dump(mode="json", exclude_none=True)
    payload.pop("path", None)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def policy_summaries(policies: list[Policy]) -> list[dict[str, Any]]:
    return [policy.summary() for policy in policies]


__all__ = [
    "ALLOWED_WHEN_KEYS",
    "ALLOWED_WHEN_OPERATORS",
    "DECISION_ORDER",
    "PolicyLoadError",
    "dump_policy",
    "load_policies_from_dir",
    "parse_policy",
    "policy_summaries",
    "validate_policy",
]
