"""Opérateurs de comparaison des règles de détection.

Deux exigences guident ce module :

1. **Ne jamais lever d'exception sur un événement.** Un collecteur qui envoie un champ
   manquant, un type inattendu ou une valeur vide ne doit pas pouvoir interrompre le
   pipeline de détection — sinon un attaquant obtient un déni de détection en émettant des
   événements malformés.
2. **Borner le coût d'une regex.** Une règle écrite par un contributeur peut contenir un
   motif à retour arrière catastrophique (ReDoS). Python n'offre pas de délai d'expiration
   sur ``re`` : on limite donc la longueur du texte analysé et on refuse les motifs
   manifestement dangereux au chargement (voir ``looks_like_redos``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from ..core.models import Condition, Operator
from ..core.util import deep_get, ip_in_cidrs, is_valid_cidr, is_valid_ip, safe_float

#: Longueur maximale de texte soumise à une expression régulière. Les charges utiles
#: utiles (chemins, user-agents) tiennent largement dedans ; au-delà, on tronque plutôt
#: que de risquer un retour arrière catastrophique.
MAX_REGEX_INPUT = 8192

#: Longueur maximale d'un motif de règle.
MAX_REGEX_PATTERN = 2048

_NESTED_QUANTIFIER = re.compile(r"(\([^)]*[+*][^)]*\)|\[[^\]]*\][+*]|\.\*)[+*{]")


class RegexTooComplexError(ValueError):
    """Motif refusé au chargement : risque de retour arrière catastrophique."""


def looks_like_redos(pattern: str) -> bool:
    """Heuristique de détection des motifs à retour arrière catastrophique.

    Ce n'est pas une preuve : c'est un filtre bon marché qui attrape les cas classiques
    (``(a+)+``, ``(.*)*``, ``[a-z]*+``) au moment du chargement de la règle, plutôt qu'au
    moment où la production subit l'attaque.
    """
    if len(pattern) > MAX_REGEX_PATTERN:
        return True
    if _NESTED_QUANTIFIER.search(pattern):
        return True
    return bool(re.search(r"\((?:[^()|]*[+*])[^()|]*\)\s*[+*{]", pattern))


@lru_cache(maxsize=2048)
def compile_regex(pattern: str, *, case_sensitive: bool = True) -> re.Pattern[str]:
    """Compile (et mémorise) une expression régulière, sans jamais lever.

    Retourne un motif qui ne matche rien en cas de motif invalide : une règle fautive ne
    doit pas faire tomber le moteur.
    """
    if len(pattern) > MAX_REGEX_PATTERN:
        raise RegexTooComplexError(f"motif trop long ({len(pattern)} > {MAX_REGEX_PATTERN})")
    if looks_like_redos(pattern):
        raise RegexTooComplexError(
            f"motif à risque de retour arrière catastrophique refusé: {pattern!r}"
        )
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise RegexTooComplexError(f"expression régulière invalide: {exc}") from exc


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _as_number(value: Any) -> float | None:
    """Convertit en nombre. ``None`` si la conversion n'a pas de sens."""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            # Accepte « 200 ms », « 1.5s », « 42 items » : très fréquent dans les logs.
            match = re.match(r"^([-+]?\d+(?:\.\d+)?)", text)
            if match:
                return float(match.group(1))
    return None


def _compare(actual: Any, expected: Any) -> int | None:
    """Compare deux valeurs. ``None`` si incomparables (jamais d'exception)."""
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return (actual > expected) - (actual < expected)
    left, right = _as_number(actual), _as_number(expected)
    if left is not None and right is not None:
        return (left > right) - (left < right)
    if actual is None or expected is None:
        return None
    left_text, right_text = _as_text(actual), _as_text(expected)
    return (left_text > right_text) - (left_text < right_text)


def _length_of(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (str, list, tuple, dict, set)):
        return len(value)
    return None


def evaluate_condition(condition: Condition, context: dict[str, Any]) -> bool:
    """Évalue une condition sur un contexte d'événement (dict issu de ``Event``).

    ``negate`` inverse le résultat, ce qui permet d'écrire ``ne`` sans opérateur dédié.
    """
    result = _evaluate(condition, context)
    return not result if condition.negate else result


def _evaluate(condition: Condition, context: dict[str, Any]) -> bool:
    actual = deep_get(context, condition.field)
    op: Operator = condition.op
    expected = condition.value

    # `exists` est le seul opérateur qui a du sens sur un champ absent.
    if op == "exists":
        want_present = True if expected is None else bool(expected)
        return (actual is not None) is want_present

    try:
        if op == "eq":
            if (
                isinstance(actual, str)
                and isinstance(expected, str)
                and not condition.case_sensitive
            ):
                return actual.lower() == expected.lower()
            if isinstance(actual, bool) or isinstance(expected, bool):
                return _as_text(actual).lower() == _as_text(expected).lower()
            comparison = _compare(actual, expected)
            return comparison == 0 if comparison is not None else actual == expected

        if op == "ne":
            if (
                isinstance(actual, str)
                and isinstance(expected, str)
                and not condition.case_sensitive
            ):
                return actual.lower() != expected.lower()
            comparison = _compare(actual, expected)
            return comparison != 0 if comparison is not None else actual != expected

        if op in {"gt", "gte", "lt", "lte"}:
            comparison = _compare(actual, expected)
            if comparison is None:
                return False
            return {
                "gt": comparison > 0,
                "gte": comparison >= 0,
                "lt": comparison < 0,
                "lte": comparison <= 0,
            }[op]

        if op in {"in", "not_in"}:
            if not isinstance(expected, (list, tuple, set)):
                expected = [expected]
            needle = _as_text(actual)
            haystack = {_as_text(item) for item in expected}
            if not condition.case_sensitive:
                needle = needle.lower()
                haystack = {item.lower() for item in haystack}
            found = needle in haystack
            return found if op == "in" else not found

        if op in {"contains", "icontains"}:
            text, needle = _as_text(actual), _as_text(expected)
            if op == "icontains" or not condition.case_sensitive:
                return needle.lower() in text.lower()
            return needle in text

        if op == "startswith":
            text, needle = _as_text(actual), _as_text(expected)
            if not condition.case_sensitive:
                return text.lower().startswith(needle.lower())
            return text.startswith(needle)

        if op == "endswith":
            text, needle = _as_text(actual), _as_text(expected)
            if not condition.case_sensitive:
                return text.lower().endswith(needle.lower())
            return text.endswith(needle)

        if op == "regex":
            if actual is None:
                return False
            text = _as_text(actual)
            if len(text) > MAX_REGEX_INPUT:
                text = text[:MAX_REGEX_INPUT]
            patterns = expected if isinstance(expected, (list, tuple)) else [expected]
            for pattern in patterns:
                try:
                    compiled = compile_regex(str(pattern), case_sensitive=condition.case_sensitive)
                except RegexTooComplexError:
                    # Une règle refusée au chargement ne devrait pas arriver ici ; si c'est
                    # le cas, on considère la condition comme non satisfaite plutôt que de
                    # faire échouer tout le pipeline.
                    return False
                if compiled.search(text):
                    return True
            return False

        if op == "cidr":
            if actual is None:
                return False
            candidates = expected if isinstance(expected, (list, tuple)) else [expected]
            cidrs = [str(item) for item in candidates if is_valid_cidr(str(item))]
            if not cidrs:
                return False
            return ip_in_cidrs(_as_text(actual), cidrs)

        if op == "len_gt":
            length = _length_of(actual)
            return length is not None and length > safe_float(expected)

        if op == "len_lt":
            length = _length_of(actual)
            return length is not None and length < safe_float(expected)

    except Exception:
        return False

    return False


def condition_is_coherent(condition: Condition) -> tuple[bool, str | None]:
    """Contrôle statique d'une condition au chargement d'une règle.

    Attrape les erreurs les plus fréquentes avant la production : regex invalide, opérande
    manquant, CIDR mal formé, comparaison numérique sur une valeur non numérique.
    """
    op = condition.op
    value = condition.value

    if op == "exists":
        return True, None
    if op in {"regex"}:
        patterns = value if isinstance(value, (list, tuple)) else [value]
        for pattern in patterns:
            if not isinstance(pattern, str):
                return False, f"op=regex exige une chaîne (reçu {type(pattern).__name__})"
            try:
                compile_regex(pattern, case_sensitive=condition.case_sensitive)
            except RegexTooComplexError as exc:
                return False, str(exc)
        return True, None
    if op == "cidr":
        candidates = value if isinstance(value, (list, tuple)) else [value]
        for item in candidates:
            if not is_valid_cidr(str(item)):
                return False, f"op=cidr exige une IP/plage valide (reçu {item!r})"
        return True, None
    if op in {"gt", "gte", "lt", "lte", "len_gt", "len_lt"}:
        if _as_number(value) is None:
            return False, f"op={op} exige une valeur numérique (reçu {value!r})"
        return True, None
    if op in {"in", "not_in"} and not isinstance(value, (list, tuple, set, str, int, float, bool)):
        return False, f"op={op} exige une liste ou un scalaire (reçu {type(value).__name__})"
    if op in {"contains", "icontains", "startswith", "endswith"} and not isinstance(
        value, (str, int, float)
    ):
        return False, f"op={op} exige une valeur textuelle (reçu {type(value).__name__})"
    return True, None


def is_ip_like(value: Any) -> bool:
    return is_valid_ip(_as_text(value))


__all__ = [
    "MAX_REGEX_INPUT",
    "MAX_REGEX_PATTERN",
    "RegexTooComplexError",
    "compile_regex",
    "condition_is_coherent",
    "evaluate_condition",
    "is_ip_like",
    "looks_like_redos",
]
