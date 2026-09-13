"""Modèles d'entrée/sortie de l'API (contrat §4).

L'API réutilise les modèles de domaine comme modèles de sortie : le contrat d'interface et le
contrat interne ne peuvent donc pas diverger silencieusement. Seules les **entrées** ont des
modèles dédiés, avec des validations spécifiques à l'exposition HTTP.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..core.models import Event, Severity


class TenantCreateRequest(BaseModel):
    """Création d'un tenant."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(description="Identifiant technique (alphanumériques, '-', '_')")
    name: str = ""
    mode: Literal["manual", "supervised", "auto"] = "supervised"
    dry_run: bool = True
    autonomy_allowlist: list[str] = Field(default_factory=list)
    protected_targets: list[str] = Field(default_factory=list)
    max_actions_per_hour: int = Field(default=20, ge=1, le=1000)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    asset_criticality: float = Field(default=1.0, ge=0.1, le=3.0)


class TenantUpdateRequest(BaseModel):
    """Mise à jour d'un tenant (mode d'autonomie, dry-run, périmètre)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    mode: Literal["manual", "supervised", "auto"] | None = None
    dry_run: bool | None = None
    autonomy_allowlist: list[str] | None = None
    protected_targets: list[str] | None = None
    max_actions_per_hour: int | None = Field(default=None, ge=1, le=1000)
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    asset_criticality: float | None = Field(default=None, ge=0.1, le=3.0)


class KeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["viewer", "analyst", "responder", "admin"] = "viewer"
    label: str = Field(default="", max_length=80)


class EventBatchRequest(BaseModel):
    """Ingestion par lot (≤ 500 événements, cf. ``THOT_MAX_INGEST_BATCH``)."""

    model_config = ConfigDict(extra="forbid")

    events: list[Event] = Field(min_length=1)


class FindingCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str = Field(default="", max_length=2000)


class FindingCloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution: Literal["true_positive", "false_positive", "mitigated", "duplicate", "benign"] = (
        "true_positive"
    )
    comment: str = Field(default="", max_length=2000)


class FindingSuppressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duration_seconds: int = Field(default=86400, ge=60, le=31_536_000)
    reason: str = Field(default="", max_length=500)
    dedup_key: str = Field(default="", max_length=128, description="Cible précise (vide = toute la règle)")


class RuleValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Contenu YAML (ou JSON) de la règle.
    text: str = Field(min_length=1, max_length=200_000)


class ActionPlanRequest(BaseModel):
    """Planification d'une action (aucun effet de bord)."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str | None = None
    playbook: str
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool | None = Field(
        default=None,
        description="Forcer la simulation. La valeur globale THOT_DRY_RUN reste prioritaire.",
    )
    reason: str = Field(default="", max_length=500)


class ActionDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str = Field(default="", max_length=1000)


class ActionRejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=1000)


class SeverityFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: list[Severity] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return sorted(set(value))


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Forme unique des erreurs renvoyées par l'API."""

    error: ErrorDetail


__all__ = [
    "ActionDecisionRequest",
    "ActionPlanRequest",
    "ActionRejectRequest",
    "ErrorResponse",
    "EventBatchRequest",
    "FindingCloseRequest",
    "FindingCommentRequest",
    "FindingSuppressRequest",
    "KeyCreateRequest",
    "RuleValidateRequest",
    "TenantCreateRequest",
    "TenantUpdateRequest",
]
