"""Exécuteur de playbooks : rendu des paramètres, exécution ordonnée, pile de rollback.

L'exécuteur est délibérément **synchrone et séquentiel**. Un playbook est une procédure :
paralléliser ses étapes rendrait le rollback ambigu (« qu'est-ce qui a été appliqué avant
l'échec ? »). La séquentialité est ici une propriété de sûreté, pas une limitation.

En cas d'échec d'une étape non optionnelle, l'exécuteur **s'arrête** et retourne la pile des
étapes déjà appliquées : le moteur d'actions peut alors déclencher un rollback automatique
partiel, ce qui évite de laisser l'infrastructure dans un état intermédiaire inconnu.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import PlaybookError
from ..core.logging_setup import get_logger
from ..core.models import Playbook, PlaybookStep
from ..core.util import iso_z, utcnow
from .connectors.base import ConnectorResult
from .registry import ConnectorRegistry

log = get_logger("actions.executor")

#: Correspondance opération → opération d'annulation, utilisée quand un playbook ne définit
#: pas de bloc ``rollback`` explicite.
UNDO_MAP: dict[str, str] = {
    "block_ip": "unblock_ip",
    "rate_limit": "remove_rate_limit",
    "quarantine_file": "restore_file",
    "isolate_host": "unisolate_host",
    "open_ticket": "close_ticket",
}

#: Opérations intrinsèquement irréversibles : une session révoquée ne se « dé-révoque » pas.
IRREVERSIBLE_OPERATIONS = frozenset({"revoke_session", "rotate_secret", "notify"})

_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")


@dataclass(slots=True)
class StepOutcome:
    index: int
    connector: str
    call: str
    ok: bool
    detail: str = ""
    error: str | None = None
    simulated: bool = False
    rollback_token: str | None = None
    duration_ms: float = 0.0
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "connector": self.connector,
            "call": self.call,
            "ok": self.ok,
            "detail": self.detail,
            "error": self.error,
            "simulated": self.simulated,
            "rollback_token": self.rollback_token,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass(slots=True)
class ExecutionOutcome:
    ok: bool
    steps: list[StepOutcome] = field(default_factory=list)
    rollback_token: str | None = None
    error: str | None = None
    simulated: bool = False
    rollback_available: bool = True

    @property
    def applied_steps(self) -> list[StepOutcome]:
        return [step for step in self.steps if step.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "simulated": self.simulated,
            "error": self.error,
            "rollback_available": self.rollback_available,
            "steps": [step.to_dict() for step in self.steps],
        }


class PlaybookExecutor:
    """Exécute un playbook via les connecteurs configurés."""

    def __init__(self, connectors: ConnectorRegistry, *, dry_run: bool = True) -> None:
        self.connectors = connectors
        self.dry_run = dry_run

    # ----------------------------------------------------------------------------------
    # Exécution
    # ----------------------------------------------------------------------------------

    def execute(
        self,
        playbook: Playbook,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
        *,
        dry_run: bool | None = None,
    ) -> ExecutionOutcome:
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        render_context = _build_context(params, context)
        outcome = ExecutionOutcome(ok=True, simulated=effective_dry_run)
        applied: list[dict[str, Any]] = []

        for index, step in enumerate(playbook.execute):
            step_params = render_params(step, render_context)
            connector = self.connectors.get(step.connector)
            connector.dry_run = effective_dry_run
            result = connector.call(step.call, step_params)
            step_outcome = _to_step_outcome(index, step, result, step_params)
            outcome.steps.append(step_outcome)

            if result.ok:
                applied.append(
                    {
                        "index": index,
                        "connector": step.connector,
                        "call": step.call,
                        "params": step_params,
                        "rollback_token": result.rollback_token,
                    }
                )
                if result.simulated:
                    outcome.simulated = True
                continue

            if step.optional:
                log.warning(
                    "étape optionnelle en échec, poursuite du playbook",
                    extra={"playbook": playbook.name, "step": step.call, "error": result.error},
                )
                continue

            # Échec bloquant : on s'arrête ici et on rend la pile pour rollback partiel.
            outcome.ok = False
            outcome.error = f"étape {index} ({step.connector}.{step.call}) en échec: {result.error}"
            outcome.rollback_token = _pack_token(playbook.name, applied)
            outcome.rollback_available = bool(applied)
            log.error(
                "playbook interrompu",
                extra={"playbook": playbook.name, "step": step.call, "error": result.error},
            )
            return outcome

        outcome.rollback_token = _pack_token(playbook.name, applied)
        outcome.rollback_available = bool(applied) and _has_rollback_path(playbook, applied)
        return outcome

    # ----------------------------------------------------------------------------------
    # Annulation
    # ----------------------------------------------------------------------------------

    def rollback(
        self,
        playbook: Playbook | None,
        token: str,
        context: dict[str, Any] | None = None,
        *,
        dry_run: bool | None = None,
    ) -> ExecutionOutcome:
        """Annule une exécution à partir de sa pile.

        Deux stratégies, dans cet ordre :

        1. le bloc ``rollback`` du playbook est exécuté, avec les jetons de rollback injectés
           dans les paramètres (``${params.rollback_token}``) ;
        2. à défaut, la pile est déroulée en ordre inverse via ``UNDO_MAP``.
        """
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        stack = _unpack_token(token)
        if stack is None:
            return ExecutionOutcome(ok=False, error="jeton de rollback illisible", rollback_available=False)

        steps_applied: list[dict[str, Any]] = stack.get("steps", [])
        if not steps_applied:
            return ExecutionOutcome(
                ok=True,
                error=None,
                rollback_available=False,
                simulated=effective_dry_run,
            )

        outcome = ExecutionOutcome(ok=True, simulated=effective_dry_run)

        if playbook is not None and playbook.rollback:
            base_params = dict((context or {}).get("params") or {})
            base_params["rollback_token"] = _last_token(steps_applied)
            render_context = _build_context(base_params, context)
            for index, step in enumerate(playbook.rollback):
                step_params = render_params(step, render_context)
                connector = self.connectors.get(step.connector)
                connector.dry_run = effective_dry_run
                result = connector.call(step.call, step_params)
                step_outcome = _to_step_outcome(index, step, result, step_params)
                outcome.steps.append(step_outcome)
                if result.simulated:
                    outcome.simulated = True
                if not result.ok and not step.optional:
                    outcome.ok = False
                    outcome.error = (
                        f"rollback interrompu à l'étape {index} "
                        f"({step.connector}.{step.call}): {result.error}"
                    )
                    return outcome
            outcome.rollback_available = False
            return outcome

        # Repli : dérouler la pile en ordre inverse.
        irreversible: list[str] = []
        for index, entry in enumerate(reversed(steps_applied)):
            operation = str(entry.get("call", ""))
            undo = UNDO_MAP.get(operation)
            if undo is None:
                if operation in IRREVERSIBLE_OPERATIONS:
                    irreversible.append(operation)
                continue
            connector = self.connectors.get(str(entry.get("connector", "simulation")))
            connector.dry_run = effective_dry_run
            undo_params = dict(entry.get("params") or {})
            if entry.get("rollback_token"):
                undo_params["rollback_token"] = entry["rollback_token"]
            result = connector.call(undo, undo_params)
            synthetic = PlaybookStep(connector=str(entry.get("connector", "")), call=undo, with_=undo_params)
            outcome.steps.append(_to_step_outcome(index, synthetic, result, undo_params))
            if result.simulated:
                outcome.simulated = True
            if not result.ok:
                outcome.ok = False
                outcome.error = f"annulation partielle : {undo} a échoué ({result.error})"

        if irreversible:
            outcome.ok = outcome.ok and True
            note = (
                "opérations non réversibles rencontrées, aucune annulation possible : "
                + ", ".join(sorted(set(irreversible)))
            )
            outcome.error = f"{outcome.error} | {note}" if outcome.error else note
        outcome.rollback_available = False
        return outcome

    # ----------------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {"dry_run": self.dry_run, **self.connectors.stats()}


# --------------------------------------------------------------------------------------
# Rendu des paramètres
# --------------------------------------------------------------------------------------


def _build_context(params: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any]:
    """Construit le contexte de résolution des ``${...}``.

    ``params`` est appliqué **en dernier**, volontairement : c'est le jeu de paramètres de
    *ce* passage de rendu. Dans l'ordre inverse, le ``params`` porté par le contexte
    écraserait le ``rollback_token`` que :meth:`PlaybookExecutor.rollback` vient d'injecter,
    et ``${params.rollback_token}`` ne serait jamais résolu — l'annulation échouerait alors
    précisément sur les playbooks qui savent annuler par identifiant.
    """
    base = dict(context or {})
    return {
        **base,
        "params": params,
        "now": iso_z(utcnow()),
    }


def render_params(step: PlaybookStep, context: dict[str, Any]) -> dict[str, Any]:
    """Résout les ``${...}`` d'une étape.

    Un placeholder non résolu **lève** : envoyer la chaîne littérale ``${params.target}`` à
    une API de WAF produirait une action absurde, voire dangereuse. Mieux vaut un échec net
    et audité qu'une action silencieusement fausse.
    """
    return {key: _render_value(value, context) for key, value in step.with_.items()}


def _render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _render_string(value, context)
    if isinstance(value, dict):
        return {key: _render_value(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    return value


def _render_string(template: str, context: dict[str, Any]) -> Any:
    matches = list(_PLACEHOLDER.finditer(template))
    if not matches:
        return template

    # Un template réduit à un seul placeholder conserve le type d'origine (int, bool…),
    # ce qui évite de sérialiser un entier en chaîne vers un connecteur.
    if len(matches) == 1 and matches[0].group(0) == template:
        return _resolve(matches[0].group(1), context)

    def substitute(match: re.Match[str]) -> str:
        value = _resolve(match.group(1), context)
        return "" if value is None else str(value)

    return _PLACEHOLDER.sub(substitute, template)


def _resolve(path: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            raise PlaybookError(
                f"paramètre non résolu: ${{{path}}}",
                details={"placeholder": path, "available": sorted(context)},
            )
    return current


def _pack_token(playbook_name: str, steps: list[dict[str, Any]]) -> str:
    return json.dumps({"playbook": playbook_name, "steps": steps}, ensure_ascii=False, default=str)


def _unpack_token(token: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(token)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _last_token(steps: list[dict[str, Any]]) -> str:
    for entry in reversed(steps):
        if entry.get("rollback_token"):
            return str(entry["rollback_token"])
    return ""


def _has_rollback_path(playbook: Playbook, applied: list[dict[str, Any]]) -> bool:
    if playbook.rollback:
        return True
    return any(str(entry.get("call")) in UNDO_MAP for entry in applied)


def _to_step_outcome(
    index: int, step: PlaybookStep, result: ConnectorResult, params: dict[str, Any]
) -> StepOutcome:
    return StepOutcome(
        index=index,
        connector=step.connector,
        call=step.call,
        ok=result.ok,
        detail=result.detail or "",
        error=result.error,
        simulated=result.simulated,
        rollback_token=result.rollback_token,
        duration_ms=result.duration_ms,
        params={key: value for key, value in params.items() if key != "rollback_token"},
    )


__all__ = [
    "IRREVERSIBLE_OPERATIONS",
    "UNDO_MAP",
    "ExecutionOutcome",
    "PlaybookExecutor",
    "StepOutcome",
    "render_params",
]
