"""Moteur de décision : *policy-as-code* YAML, garde-fous, adaptateur OPA optionnel."""

from __future__ import annotations

from .engine import (
    DecisionContext,
    DecisionEngine,
    PolicyEvaluation,
    evaluate_when,
    extract_targets,
    resolve_param_target,
)
from .opa import DEFAULT_QUERY, OpaEvaluator, decision_from_rego
from .policy_loader import (
    ALLOWED_WHEN_KEYS,
    ALLOWED_WHEN_OPERATORS,
    PolicyLoadError,
    dump_policy,
    load_policies_from_dir,
    parse_policy,
    policy_summaries,
    validate_policy,
)

__all__ = [
    "ALLOWED_WHEN_KEYS",
    "ALLOWED_WHEN_OPERATORS",
    "DEFAULT_QUERY",
    "DecisionContext",
    "DecisionEngine",
    "OpaEvaluator",
    "PolicyEvaluation",
    "PolicyLoadError",
    "decision_from_rego",
    "dump_policy",
    "evaluate_when",
    "extract_targets",
    "load_policies_from_dir",
    "parse_policy",
    "policy_summaries",
    "resolve_param_target",
    "validate_policy",
]
