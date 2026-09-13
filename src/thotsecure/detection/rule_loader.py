"""Chargement et validation de la bibliothèque de règles.

Principes :

* **Une règle fautive ne casse jamais le chargement.** Elle est rejetée avec un diagnostic
  précis (fichier, raison) et les autres règles restent actives. Un opérateur doit pouvoir
  pousser une règle imparfaite sans aveugler tout son SOC.
* **``yaml.safe_load`` uniquement.** Une règle est du contenu potentiellement fourni par un
  tiers : jamais de constructeur arbitraire, jamais d'exécution de code.
* **Taille bornée.** Un fichier de règle de plus de 1 Mio est refusé (protection contre
  l'épuisement mémoire par un dépôt compromis).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError as PydanticValidationError

from ..core.logging_setup import get_logger
from ..core.models import (
    Condition,
    MatchSpec,
    Rule,
    RuleDedup,
    RuleDiagnostic,
    RuleRisk,
)
from .matchers import condition_is_coherent

log = get_logger("detection.loader")

#: Taille maximale d'un fichier de règle (protection anti-épuisement mémoire).
MAX_RULE_FILE_BYTES = 1024 * 1024

RULE_SUFFIXES = (".yaml", ".yml", ".json")

#: Correspondance des niveaux Sigma vers nos sévérités.
SIGMA_LEVEL_MAP = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

#: Préfixe appliqué aux champs Sigma : Sigma décrit des champs d'événements Windows/EDR,
#: nos règles interrogent ``payload.<champ>`` par défaut.
SIGMA_FIELD_PREFIX = "payload."


class RuleLoadError(ValueError):
    """Erreur de chargement d'une règle (contient un diagnostic exploitable)."""


# --------------------------------------------------------------------------------------
# Chargement
# --------------------------------------------------------------------------------------


def parse_rule_text(text: str, *, path: str | None = None) -> list[Rule]:
    """Analyse un document YAML/JSON pouvant contenir une ou plusieurs règles.

    Un fichier peut contenir plusieurs documents (``---``) ; chaque document produit une
    règle. Retourne la liste des règles valides, en levant ``RuleLoadError`` sur la
    première erreur rencontrée.
    """
    if len(text.encode("utf-8")) > MAX_RULE_FILE_BYTES:
        raise RuleLoadError(f"fichier de règle trop volumineux (> {MAX_RULE_FILE_BYTES} octets)")
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"YAML invalide: {exc}") from exc

    rules: list[Rule] = []
    for document in documents:
        if document is None:
            continue
        if not isinstance(document, dict):
            raise RuleLoadError("un document de règle doit être un mapping YAML")
        if "detection" in document and "match" not in document:
            rules.extend(_translate_sigma(document, path=path))
            continue
        rules.append(_build_rule(document, path=path))
    return rules


def _build_rule(document: dict[str, Any], *, path: str | None) -> Rule:
    payload = dict(document)
    payload.pop("$schema", None)
    try:
        rule = Rule(**payload)
    except PydanticValidationError as exc:
        raise RuleLoadError(_format_pydantic_error(exc)) from exc
    rule.path = path
    problems = validate_rule(rule)
    if problems:
        raise RuleLoadError("; ".join(problems))
    return rule


def _format_pydantic_error(exc: PydanticValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors()[:5]:
        location = ".".join(str(item) for item in error.get("loc", ()))
        parts.append(f"{location or '<racine>'}: {error.get('msg')}")
    return " | ".join(parts)


def validate_rule(rule: Rule) -> list[str]:
    """Contrôles sémantiques au-delà du schéma. Retourne la liste des problèmes."""
    problems: list[str] = []
    conditions: list[tuple[str, Condition]] = [
        *(("all", item) for item in rule.match.all),
        *(("any", item) for item in rule.match.any),
        *(("not", item) for item in rule.match.not_),
    ]
    for section, condition in conditions:
        ok, reason = condition_is_coherent(condition)
        if not ok:
            problems.append(f"match.{section}: {reason}")

    if rule.match.threshold:
        if rule.match.threshold.count > 1 and not rule.match.threshold.group_by:
            problems.append(
                "match.threshold: 'group_by' est obligatoire dès que count > 1 "
                "(sinon le seuil s'applique globalement, y compris entre tenants)"
            )
        for field in rule.match.threshold.group_by:
            if not field.startswith("labels."):
                problems.append(
                    f"match.threshold.group_by: '{field}' doit référencer un label "
                    "(ex. 'labels.src_ip') pour un regroupement fiable"
                )

    if rule.dedup.ttl_seconds > 0 and not rule.dedup.key and not rule.match.threshold:
        # Sans clé de dédup, tous les événements de la règle s'agrègent dans un seul
        # finding : c'est un choix légitime, mais il doit être explicite.
        pass

    for tag in rule.tags:
        if tag.startswith("mitre:") and len(tag) < 9:
            problems.append(f"tag MITRE suspect: {tag!r} (format attendu mitre:T1190)")
    return problems


def load_rules_from_dir(directory: str | Path) -> tuple[list[Rule], list[RuleDiagnostic]]:
    """Charge récursivement un répertoire de règles.

    Retourne ``(règles_valides, diagnostics)`` — l'appelant décide quoi faire des
    diagnostics (les journaliser, les exposer via ``rules/reload``, alerter).
    """
    root = Path(directory)
    rules: list[Rule] = []
    diagnostics: list[RuleDiagnostic] = []
    if not root.exists():
        diagnostics.append(RuleDiagnostic(path=str(root), error="répertoire de règles inexistant"))
        log.warning("répertoire de règles inexistant", extra={"path": str(root)})
        return rules, diagnostics

    seen: dict[str, str] = {}
    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in RULE_SUFFIXES:
            continue
        if file_path.name.startswith("."):
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
            loaded = parse_rule_text(text, path=str(file_path))
        except (RuleLoadError, OSError, UnicodeDecodeError) as exc:
            diagnostics.append(RuleDiagnostic(path=str(file_path), error=str(exc)))
            log.error("règle rejetée", extra={"path": str(file_path), "error": str(exc)})
            continue
        for rule in loaded:
            if rule.id in seen:
                diagnostics.append(
                    RuleDiagnostic(
                        path=str(file_path),
                        rule_id=rule.id,
                        error=f"identifiant de règle en double (déjà défini dans {seen[rule.id]})",
                    )
                )
                continue
            seen[rule.id] = str(file_path)
            rules.append(rule)

    enabled = sum(1 for rule in rules if rule.enabled)
    log.info(
        "bibliothèque de règles chargée",
        extra={"rules": len(rules), "enabled": enabled, "diagnostics": len(diagnostics)},
    )
    return rules, diagnostics


def load_rule_text(text: str, *, path: str | None = None) -> Rule:
    """Charge une règle unique depuis une chaîne (utilisé par ``POST /rules/validate``)."""
    rules = parse_rule_text(text, path=path)
    if not rules:
        raise RuleLoadError("aucune règle trouvée dans le document")
    if len(rules) > 1:
        raise RuleLoadError(f"{len(rules)} règles trouvées : envoyez un seul document")
    return rules[0]


def dump_rule(rule: Rule) -> str:
    """Sérialise une règle en YAML (utilisé par ``GET /rules/{id}``)."""
    payload = rule.model_dump(mode="json", exclude_none=True)
    payload.pop("path", None)
    payload.pop("sigma_compat", None)
    if "match" in payload and isinstance(payload["match"], dict):
        match = payload["match"]
        if not match.get("not"):
            match.pop("not", None)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


# --------------------------------------------------------------------------------------
# Compatibilité Sigma-lite
# --------------------------------------------------------------------------------------


def _translate_sigma(document: dict[str, Any], *, path: str | None) -> list[Rule]:
    """Traduit un sous-ensemble de Sigma (contrat §5, docs/detection/sigma.md).

    Le traducteur refuse explicitement les conditions qu'il ne peut pas représenter
    fidèlement : une mauvaise traduction silencieuse produit de faux négatifs, ce qui est
    bien pire qu'un refus.
    """
    title = str(document.get("title") or "").strip()
    if not title:
        raise RuleLoadError("règle Sigma sans 'title'")
    rule_id = str(document.get("id") or "").strip().upper()
    if not rule_id:
        slug = "".join(ch if ch.isalnum() else "-" for ch in title.upper())[:40]
        rule_id = f"SIGMA-{slug}".strip("-")
    if not rule_id.startswith(("AO-", "SIGMA-")):
        rule_id = f"SIGMA-{rule_id}"

    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise RuleLoadError("bloc 'detection' absent ou invalide")
    condition_expr = str(detection.get("condition") or "").strip()
    if not condition_expr:
        raise RuleLoadError("bloc 'detection' sans 'condition'")

    selections: dict[str, MatchSpec] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        selections[name] = _sigma_selection_to_spec(body, name=name)

    match = _combine_sigma_condition(condition_expr, selections)

    level = SIGMA_LEVEL_MAP.get(str(document.get("level", "medium")).lower(), "medium")
    severity = level if document.get("level") else "medium"
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "medium"

    tags = [str(tag) for tag in document.get("tags") or []]
    mitre = [tag.split(".", 1)[1].upper() for tag in tags if tag.lower().startswith("attack.t")]
    remediation = str((document.get("falsepositives") and "") or "")
    remediation = (
        remediation
        or "Analyser l'événement, confirmer ou infirmer, puis appliquer le playbook adapté."
    )

    rule = Rule(
        id=rule_id,
        title=title,
        description=str(document.get("description") or ""),
        status="test",
        severity=severity,  # type: ignore[arg-type]
        confidence=0.6,
        enabled=True,
        tags=tags,
        source_types=[],
        kinds=[],
        match=match,
        dedup=RuleDedup(key=["labels.src_ip"], ttl_seconds=900),
        risk=RuleRisk(base=60.0 if severity in {"high", "critical"} else 45.0),
        false_positives=[str(item) for item in document.get("falsepositives") or []],
        remediation=remediation,
        references=[str(item) for item in document.get("references") or []],
        path=path,
        sigma_compat=True,
    )
    for tag in mitre:
        if f"mitre:{tag}" not in rule.tags:
            rule.tags.append(f"mitre:{tag}")
    problems = validate_rule(rule)
    if problems:
        raise RuleLoadError("; ".join(problems))
    log.warning(
        "règle Sigma traduite : vérifiez la sémantique avant de l'activer en production",
        extra={"rule_id": rule.id, "path": path},
    )
    return [rule]


def _sigma_selection_to_spec(body: Any, *, name: str) -> MatchSpec:
    if not isinstance(body, dict):
        raise RuleLoadError(f"selection Sigma '{name}' doit être un mapping")
    conditions: list[Condition] = []
    for field_spec, value in body.items():
        conditions.extend(_sigma_field_conditions(str(field_spec), value, selection=name))
    if not conditions:
        raise RuleLoadError(f"selection Sigma '{name}' ne contient aucune condition")
    return MatchSpec(all=conditions)


def _sigma_field_conditions(field_spec: str, value: Any, *, selection: str) -> list[Condition]:
    parts = field_spec.split("|")
    field = parts[0].strip()
    modifiers = [part.strip().lower() for part in parts[1:]]
    path = field if "." in field else f"{SIGMA_FIELD_PREFIX}{field}"

    unsupported = {
        "base64",
        "base64offset",
        "utf16",
        "utf16le",
        "utf16be",
        "wide",
        "windash",
        "expand",
        "fieldref",
    }
    if unsupported.intersection(modifiers):
        raise RuleLoadError(
            f"selection '{selection}': modificateur Sigma non supporté "
            f"({sorted(unsupported.intersection(modifiers))}) — réécrivez la règle au format natif"
        )

    op = "eq"
    case_sensitive = True
    match_all = False
    for modifier in modifiers:
        if modifier == "contains":
            op = "icontains"
            case_sensitive = False
        elif modifier == "startswith":
            op = "startswith"
            case_sensitive = False
        elif modifier == "endswith":
            op = "endswith"
            case_sensitive = False
        elif modifier == "re":
            op = "regex"
        elif modifier == "cidr":
            op = "cidr"
        elif modifier in {"gt", "gte", "lt", "lte"}:
            op = modifier
        elif modifier == "all" or modifier in {"contains|all", "all|contains"}:
            match_all = True
        else:
            raise RuleLoadError(f"selection '{selection}': modificateur Sigma inconnu '{modifier}'")

    values = value if isinstance(value, list) else [value]
    # Sigma est insensible à la casse par défaut (hors modificateur |re).
    if op == "eq":
        case_sensitive = False

    conditions: list[Condition] = []
    if match_all:
        if op in {"eq", "in"}:
            conditions.extend(
                Condition(field=path, op="icontains", value=str(item), case_sensitive=False)
                for item in values
            )
        else:
            raise RuleLoadError(
                f"selection '{selection}': modificateur 'all' avec opérateur '{op}' non supporté"
            )
        return conditions

    if len(values) == 1:
        item = values[0]
        if (
            isinstance(item, str)
            and ("*" in item or "?" in item)
            and op in {"eq", "in", "contains", "icontains"}
        ):
            conditions.append(
                Condition(
                    field=path,
                    op="regex",
                    value=_sigma_wildcard_to_regex(item),
                    case_sensitive=case_sensitive,
                )
            )
        else:
            conditions.append(
                Condition(field=path, op=op, value=item, case_sensitive=case_sensitive)
            )
        return conditions

    if op in {"eq", "in"}:
        conditions.append(Condition(field=path, op="in", value=values, case_sensitive=False))
        return conditions

    # Plusieurs valeurs avec un opérateur non ensembliste : on exprime un OU via plusieurs
    # conditions, ce que le traducteur accepte uniquement au premier niveau (voir
    # _combine_sigma_condition).
    raise RuleLoadError(
        f"selection '{selection}': plusieurs valeurs avec l'opérateur '{op}' ne sont pas "
        "représentables fidèlement — utilisez un opérateur ensembliste ou le format natif"
    )


def _sigma_wildcard_to_regex(pattern: str) -> str:
    """Convertit les jokers Sigma (``*``, ``?``) en expression régulière ancrée."""
    import re as _re

    escaped = _re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
    return f"(?s)^{escaped}$"


def _combine_sigma_condition(expression: str, selections: dict[str, MatchSpec]) -> MatchSpec:
    """Traduit l'expression de condition Sigma en ``MatchSpec`` (all/any/not).

    Formes supportées : une selection, ``A and B``, ``A and not B``, ``A or B`` (tant que
    chaque branche reste une conjonction), ``1 of selection*``, ``all of selection*``,
    ``them``. Toute autre forme est refusée avec un message explicite.
    """
    tokens = _tokenize_condition(expression)
    parser = _ConditionParser(tokens, selections)
    spec = parser.parse()
    return spec


def _tokenize_condition(expression: str) -> list[str]:
    normalized = expression.replace("(", " ( ").replace(")", " ) ").replace("|", " | ")
    return [token for token in normalized.split() if token]


class _ConditionParser:
    """Analyseur descendant récursif minimal pour les expressions Sigma."""

    def __init__(self, tokens: list[str], selections: dict[str, MatchSpec]) -> None:
        self.tokens = tokens
        self.position = 0
        self.selections = selections

    def parse(self) -> MatchSpec:
        spec = self._parse_or()
        if self.position != len(self.tokens):
            raise RuleLoadError(
                f"condition Sigma : jeton inattendu {self.tokens[self.position]!r} "
                "(formes supportées : 'A and B', 'A and not B', 'A or B', '1 of X*', 'all of X*')"
            )
        return spec

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise RuleLoadError("condition Sigma incomplète (fin d'expression inattendue)")
        self.position += 1
        return token

    def _parse_or(self) -> MatchSpec:
        left = self._parse_and()
        while self._peek() and self._peek().lower() == "or":
            self._next()
            right = self._parse_and()
            left = self._merge_or(left, right)
        return left

    def _parse_and(self) -> MatchSpec:
        left = self._parse_unary()
        while self._peek() and self._peek().lower() == "and":
            self._next()
            right = self._parse_unary()
            left = self._merge_and(left, right)
        return left

    def _parse_unary(self) -> MatchSpec:
        token = self._peek()
        if token is None:
            raise RuleLoadError("condition Sigma incomplète")
        if token.lower() == "not":
            self._next()
            inner = self._parse_unary()
            return MatchSpec(not_=[*inner.all, *inner.any, *inner.not_])
        if token == "(":
            self._next()
            inner = self._parse_or()
            if self._peek() != ")":
                raise RuleLoadError("parenthèse fermante manquante dans la condition Sigma")
            self._next()
            return inner
        return self._parse_quantified_or_selection()

    def _parse_quantified_or_selection(self) -> MatchSpec:
        token = self._peek()
        if token is None:
            raise RuleLoadError("condition Sigma incomplète")
        lowered = token.lower()
        if lowered in {"1", "all"} and self.position + 1 < len(self.tokens):
            following = self.tokens[self.position + 1].lower()
            if following == "of":
                self._next()
                self._next()
                pattern = self._next()
                matched = self._match_pattern(pattern)
                if not matched:
                    raise RuleLoadError(
                        f"condition Sigma : aucune selection ne correspond à {pattern!r}"
                    )
                return self._combine_many(matched, mode="or" if lowered == "1" else "and")
        self._next()
        if token.lower() == "them":
            matched = list(self.selections.values())
            if not matched:
                raise RuleLoadError("condition Sigma 'them' sans aucune selection définie")
            return self._combine_many(matched, mode="or")
        if token not in self.selections:
            pattern_matched = self._match_pattern(token)
            if pattern_matched:
                return self._combine_many(pattern_matched, mode="or")
            raise RuleLoadError(
                f"condition Sigma : selection inconnue {token!r} "
                f"(définies : {sorted(self.selections)})"
            )
        return self.selections[token]

    def _match_pattern(self, pattern: str) -> list[MatchSpec]:
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [spec for name, spec in self.selections.items() if name.startswith(prefix)]
        if pattern in self.selections:
            return [self.selections[pattern]]
        return []

    def _combine_many(self, specs: list[MatchSpec], *, mode: str) -> MatchSpec:
        result = MatchSpec()
        for spec in specs:
            result = (
                self._merge_and(result, spec) if mode == "and" else self._merge_or(result, spec)
            )
        return result

    @staticmethod
    def _merge_and(left: MatchSpec, right: MatchSpec) -> MatchSpec:
        """``et`` : représentable tant qu'une seule des deux branches porte un ``ou``.

        La sémantique de ``MatchSpec`` est « toutes les conditions de ``all`` ET au moins une
        de ``any`` ET aucune de ``not`` ». On peut donc y fusionner ``(a ou b) ET c ET non d``,
        mais **pas** ``(a ou b) ET (c ou d)`` : cette dernière forme exige une conjonction de
        disjonctions, hors du format all/any/not. Dans ce cas, on refuse la traduction plutôt
        que de produire une règle approximative — un faux négatif silencieux est bien plus
        dangereux qu'un refus de chargement, qui est visible et corrigible.
        """
        if left.any and right.any:
            raise RuleLoadError(
                "condition Sigma : conjonction de deux branches 'ou' non représentable dans le "
                "format all/any/not — réécrivez la règle au format natif Thot Secure"
            )
        return MatchSpec(
            all=[*left.all, *right.all],
            any=[*left.any, *right.any],
            not_=[*left.not_, *right.not_],
            threshold=left.threshold or right.threshold,
        )

    @staticmethod
    def _merge_or(left: MatchSpec, right: MatchSpec) -> MatchSpec:
        """``ou`` n'est exprimable que si chaque branche est une condition unique sans 'all'."""
        for spec, side in ((left, "gauche"), (right, "droite")):
            if len(spec.all) > 1 or spec.any or spec.not_:
                raise RuleLoadError(
                    f"condition Sigma 'ou' : la branche {side} contient plusieurs conditions, "
                    "ce qui n'est pas représentable dans le format all/any/not — "
                    "réécrivez la règle au format natif Thot Secure"
                )
        conditions = [*left.all, *right.all]
        return MatchSpec(any=conditions)


def sigma_supported_subset() -> dict[str, Any]:
    """Description machine de ce que le traducteur accepte (exposé dans la documentation)."""
    return {
        "supported_keys": [
            "title",
            "id",
            "description",
            "status",
            "references",
            "tags",
            "logsource",
            "detection",
            "level",
            "falsepositives",
        ],
        "supported_modifiers": [
            "contains",
            "startswith",
            "endswith",
            "re",
            "cidr",
            "gt",
            "gte",
            "lt",
            "lte",
            "all",
        ],
        "supported_conditions": [
            "selection",
            "A and B",
            "A and not B",
            "A or B (branches simples)",
            "1 of selection*",
            "all of selection*",
            "them",
        ],
        "unsupported_modifiers": ["base64", "base64offset", "utf16", "wide", "windash", "fieldref"],
        "field_prefix": SIGMA_FIELD_PREFIX,
        "json_reference": json.dumps({"logsource": "non interprété par le traducteur"}),
    }


__all__ = [
    "MAX_RULE_FILE_BYTES",
    "RULE_SUFFIXES",
    "SIGMA_FIELD_PREFIX",
    "RuleLoadError",
    "dump_rule",
    "load_rule_text",
    "load_rules_from_dir",
    "parse_rule_text",
    "sigma_supported_subset",
    "validate_rule",
]
