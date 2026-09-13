"""Scoring de risque — explicable, monotone et borné.

Un score de risque qui n'est pas explicable est un score que personne ne peut contester, et
donc un score auquel personne ne fait confiance. ``compute_risk`` retourne systématiquement
la décomposition du calcul : elle est stockée dans le finding et affichée dans les rapports.

Propriétés garanties (testées) :

* **borné** : toujours dans ``[0, 100]`` ;
* **monotone en sévérité** : à paramètres égaux, ``critical`` > ``high`` > … > ``info`` ;
* **monotone en confiance** : une règle plus confiante ne peut pas produire un score plus bas ;
* **monotone en criticité d'actif** : un actif plus critique augmente le score ;
* **croissant avec la répétition**, mais avec un rendement décroissant (une attaque qui
  frappe 10 000 fois n'est pas 10 000 fois plus grave qu'une attaque unique), et plafonné.
"""

from __future__ import annotations

import math

from ..core.models import RiskBreakdown, Rule, Tenant
from ..core.util import clamp

#: Base de score par sévérité (sur 100), avant modulation.
SEVERITY_BASE: dict[str, float] = {
    "info": 8.0,
    "low": 20.0,
    "medium": 40.0,
    "high": 62.0,
    "critical": 82.0,
}

#: Poids maximal apporté par ``rule.risk.base`` (0-100) au-dessus de la base de sévérité.
RULE_BASE_WEIGHT = 18.0

#: Amplitude maximale du facteur de répétition.
MAX_REPETITION_BONUS = 0.5


def severity_base(severity: str) -> float:
    return SEVERITY_BASE.get(severity, 40.0)


def compute_risk(
    rule: Rule,
    tenant: Tenant | None = None,
    *,
    count: int = 1,
    asset_criticality: float | None = None,
) -> RiskBreakdown:
    """Calcule le score de risque d'un finding et sa décomposition."""
    base = severity_base(rule.severity)
    if rule.risk.base is not None:
        # ``base`` est un bonus additif (0-100 → 0-18 points) : cela permet aux auteurs de
        # règle d'ajuster finement sans écraser la hiérarchie de sévérité.
        base += (rule.risk.base / 100.0) * RULE_BASE_WEIGHT

    confidence_factor = 0.5 + 0.5 * clamp(rule.confidence, 0.0, 1.0)

    criticality = asset_criticality if asset_criticality is not None else (
        tenant.asset_criticality if tenant else 1.0
    )
    asset_factor = clamp(criticality * rule.risk.asset_criticality, 0.1, 3.0)

    effective_count = max(1, int(count))
    repetition_factor = 1.0 + min(
        MAX_REPETITION_BONUS, math.log10(effective_count) * 0.25
    )

    raw = base * confidence_factor * asset_factor * repetition_factor
    final = round(clamp(raw, 0.0, 100.0), 2)

    steps = [
        f"base sévérité '{rule.severity}' = {severity_base(rule.severity):.1f}",
        (
            f"bonus règle = {(rule.risk.base / 100.0) * RULE_BASE_WEIGHT:.1f}"
            if rule.risk.base is not None
            else "bonus règle = 0.0 (non spécifié)"
        ),
        f"facteur de confiance (confidence={rule.confidence:.2f}) = {confidence_factor:.3f}",
        f"facteur d'actif (criticité={criticality:.2f}, règle={rule.risk.asset_criticality:.2f}) = {asset_factor:.3f}",
        f"facteur de répétition (count={effective_count}) = {repetition_factor:.3f}",
        f"score = {base:.1f} × {confidence_factor:.3f} × {asset_factor:.3f} × {repetition_factor:.3f} = {final:.2f}",
    ]

    return RiskBreakdown(
        base=round(base, 2),
        severity_factor=1.0,
        confidence_factor=round(confidence_factor, 3),
        asset_factor=round(asset_factor, 3),
        repetition_factor=round(repetition_factor, 3),
        final=final,
        formula="final = clamp(base × confiance × actif × répétition, 0, 100)",
        steps=steps,
    )


def risk_band(score: float) -> str:
    """Bande de risque lisible (utilisée par la console et les rapports)."""
    if score >= 85:
        return "critique"
    if score >= 70:
        return "élevé"
    if score >= 45:
        return "moyen"
    if score >= 20:
        return "faible"
    return "informational"


__all__ = [
    "MAX_REPETITION_BONUS",
    "RULE_BASE_WEIGHT",
    "SEVERITY_BASE",
    "compute_risk",
    "risk_band",
    "severity_base",
]
