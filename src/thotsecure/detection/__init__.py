"""Moteur de détection : règles YAML, opérateurs, seuils, compatibilité Sigma-lite."""

from __future__ import annotations

from .engine import CompiledRule, DetectionEngine, MatchResult
from .matchers import (
    RegexTooComplexError,
    compile_regex,
    condition_is_coherent,
    evaluate_condition,
    looks_like_redos,
)
from .rule_loader import (
    RULE_SUFFIXES,
    RuleLoadError,
    dump_rule,
    load_rule_text,
    load_rules_from_dir,
    parse_rule_text,
    sigma_supported_subset,
    validate_rule,
)

__all__ = [
    "RULE_SUFFIXES",
    "CompiledRule",
    "DetectionEngine",
    "MatchResult",
    "RegexTooComplexError",
    "RuleLoadError",
    "compile_regex",
    "condition_is_coherent",
    "dump_rule",
    "evaluate_condition",
    "load_rule_text",
    "load_rules_from_dir",
    "looks_like_redos",
    "parse_rule_text",
    "sigma_supported_subset",
    "validate_rule",
]
