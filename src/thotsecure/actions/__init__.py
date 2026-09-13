"""Moteur d'action (SOAR) : playbooks, connecteurs, exécution, rollback."""

from __future__ import annotations

from .engine import ActionEngine, validate_params
from .executor import ExecutionOutcome, PlaybookExecutor, StepOutcome, render_params
from .playbook_loader import (
    PlaybookLoadError,
    dump_playbook,
    load_playbooks_from_dir,
    parse_playbook,
    playbook_summaries,
    validate_playbook,
)
from .registry import DEFAULT_CONNECTORS, DRIVERS, ConnectorRegistry

__all__ = [
    "DEFAULT_CONNECTORS",
    "DRIVERS",
    "ActionEngine",
    "ConnectorRegistry",
    "ExecutionOutcome",
    "PlaybookExecutor",
    "PlaybookLoadError",
    "StepOutcome",
    "dump_playbook",
    "load_playbooks_from_dir",
    "parse_playbook",
    "playbook_summaries",
    "render_params",
    "validate_params",
    "validate_playbook",
]
