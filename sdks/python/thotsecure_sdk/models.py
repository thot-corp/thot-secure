"""Modèles typés du contrat Thot Secure (docs/architecture/api-contract.md, §3).

Chaque modèle est une ``dataclass`` qui :

* expose **exactement** les noms de champs JSON du contrat (snake_case, ex. ``risk_score``) ;
* tolère les champs inconnus : ils sont conservés dans ``extra`` et réémis par :meth:`to_dict`,
  ce qui garantit la compatibilité ascendante quand le serveur enrichit une réponse ;
* sait se construire depuis un dictionnaire (:meth:`from_dict`) et se sérialiser
  (:meth:`to_dict`), y compris récursivement pour les modèles imbriqués.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import date, datetime
from typing import Any, ClassVar, Generic, TypeVar

__all__ = [
    "Action",
    "ApiKey",
    "AuditRecord",
    "AuditVerification",
    "CollectorStatus",
    "Decision",
    "Event",
    "Finding",
    "IngestOutcome",
    "IngestResult",
    "Model",
    "Page",
    "Playbook",
    "Rule",
    "RuleValidation",
    "StatsOverview",
    "Tenant",
]

T = TypeVar("T")


def _dump(value: Any) -> Any:
    """Sérialise récursivement une valeur (modèle, liste, mapping, date)."""
    if isinstance(value, Model):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {k: _dump(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_dump(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


@dataclass
class Model:
    """Base commune : tolérance aux champs inconnus et aller-retour dictionnaire."""

    #: Champs non reconnus, conservés tels quels pour ne rien perdre de la réponse serveur.
    extra: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    #: Champs imbriqués (nom du champ -> modèle) et listes de modèles.
    _NESTED: ClassVar[dict[str, type]] = {}
    _NESTED_LISTS: ClassVar[dict[str, type]] = {}

    # ------------------------------------------------------------------ utilitaires

    @classmethod
    def _field_names(cls) -> tuple:
        cached = cls.__dict__.get("_field_names_cache")
        if cached is None:
            cached = tuple(f.name for f in fields(cls) if f.name != "extra")
            cls._field_names_cache = cached
        return cached

    @classmethod
    def _convert(cls, name: str, value: Any) -> Any:
        nested = cls._NESTED.get(name)
        if nested is not None and isinstance(value, Mapping):
            return nested.from_dict(value)
        list_model = cls._NESTED_LISTS.get(name)
        if list_model is not None and isinstance(value, list):
            return [list_model.from_dict(item) if isinstance(item, Mapping) else item for item in value]
        return value

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> Any:
        """Construit le modèle depuis un dictionnaire (tolérant : champs inconnus → ``extra``)."""
        if data is None:
            return None
        if not isinstance(data, Mapping):
            raise TypeError(f"{cls.__name__}.from_dict attend un mapping, reçu {type(data)!r}")
        names = cls._field_names()
        kwargs: dict[str, Any] = {}
        for name in names:
            if name in data:
                kwargs[name] = cls._convert(name, data[name])
        kwargs["extra"] = {k: v for k, v in data.items() if k not in names}
        return cls(**kwargs)

    def to_dict(self, *, omit_none: bool = False) -> dict[str, Any]:
        """Sérialise le modèle.

        ``omit_none=True`` retire les champs ``None`` (utile pour construire un corps de requête) ;
        par défaut tous les champs du contrat sont présents, ce qui rend l'aller-retour fidèle.
        """
        out: dict[str, Any] = {}
        for name in self._field_names():
            value = getattr(self, name)
            if value is None and omit_none:
                continue
            out[name] = _dump(value)
        for key, value in self.extra.items():
            out.setdefault(key, _dump(value))
        return out

    def to_json(self, *, omit_none: bool = False) -> str:
        import json

        return json.dumps(self.to_dict(omit_none=omit_none), ensure_ascii=False, sort_keys=True)


@dataclass
class Page(Generic[T]):
    """Page de résultats (`limit` + `cursor`) renvoyée par les routes de liste."""

    items: list[T] = field(default_factory=list)
    next_cursor: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, index):
        return self.items[index]

    def __bool__(self) -> bool:
        return bool(self.items)

    @classmethod
    def from_payload(
        cls,
        payload: Any,
        model: type | None = None,
        *,
        items_key: str = "items",
    ) -> Page[Any]:
        """Normalise les formes de réponse possibles (``{"items":[...]}`` ou liste nue)."""
        if isinstance(payload, list):
            raw_items = payload
            container: dict[str, Any] = {}
        elif isinstance(payload, Mapping):
            container = dict(payload)
            raw_items = container.get(items_key)
            if raw_items is None:
                raw_items = container.get("data")
            if raw_items is None:
                raw_items = []
        else:
            container = {}
            raw_items = []
        if not isinstance(raw_items, list):
            raw_items = [raw_items]
        items: list[Any] = []
        for item in raw_items:
            if model is not None and isinstance(item, Mapping):
                items.append(model.from_dict(item))
            else:
                items.append(item)
        cursor = container.get("next_cursor") or container.get("cursor")
        return cls(items=items, next_cursor=cursor if isinstance(cursor, str) else None, raw=container)


# --------------------------------------------------------------------------------------
# §3.1 Event
# --------------------------------------------------------------------------------------


@dataclass
class Event(Model):
    """Événement normalisé, immuable (contrat §3.1)."""

    event_id: str | None = None
    schema_version: str | None = None
    tenant_id: str | None = None
    ts: str | None = None
    kind: str | None = None
    source: dict[str, Any] = field(default_factory=dict)
    severity_hint: str | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    raw_ref: str | None = None

    #: Valeurs admises par le contrat pour ``kind``.
    KINDS: ClassVar[tuple] = (
        "http.request",
        "http.response",
        "log.line",
        "tls.cert",
        "dependency",
        "config.audit",
        "syslog",
        "generic",
    )
    SEVERITY_HINTS: ClassVar[tuple] = ("info", "low", "medium", "high", "critical")

    def to_dict(self, *, omit_none: bool = False) -> dict[str, Any]:
        out = super().to_dict(omit_none=omit_none)
        # Le contrat exige un `labels` plat à valeurs scalaires : on filtre par sécurité.
        labels = out.get("labels")
        if isinstance(labels, Mapping):
            out["labels"] = {
                k: v for k, v in labels.items() if isinstance(v, (str, int, float, bool)) or v is None
            }
        return out


# --------------------------------------------------------------------------------------
# §3.2 Finding
# --------------------------------------------------------------------------------------


@dataclass
class Finding(Model):
    """Agrégat d'événements porteur d'un ``risk_score`` (contrat §3.2)."""

    finding_id: str | None = None
    tenant_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    confidence: float | None = None
    status: str | None = None
    title: str | None = None
    description: str | None = None
    remediation: str | None = None
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: str | None = None
    last_seen: str | None = None
    count: int | None = None
    event_ids: list[str] = field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None

    STATUSES: ClassVar[tuple] = ("open", "acked", "closed", "suppressed")
    SEVERITIES: ClassVar[tuple] = ("info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------------------
# §3.3 Decision
# --------------------------------------------------------------------------------------


@dataclass
class Decision(Model):
    """Décision rendue par le moteur policy-as-code (contrat §3.3)."""

    decision: str | None = None
    policy_id: str | None = None
    playbook: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    risk_score: float | None = None
    expires_at: str | None = None
    cooldown_seconds: int | None = None
    dry_run: bool | None = None

    DECISIONS: ClassVar[tuple] = ("auto", "require_approval", "notify_only", "ignore")


# --------------------------------------------------------------------------------------
# §3.4 Action
# --------------------------------------------------------------------------------------


@dataclass
class Action(Model):
    """Instance d'exécution d'un playbook, avec cycle de vie et rollback (contrat §3.4)."""

    action_id: str | None = None
    tenant_id: str | None = None
    finding_id: str | None = None
    policy_id: str | None = None
    playbook: str | None = None
    status: str | None = None
    mode: str | None = None
    dry_run: bool | None = None
    params: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    requested_by: str | None = None
    requested_at: str | None = None
    approved_by: str | None = None
    approved_at: str | None = None
    executed_at: str | None = None
    expires_at: str | None = None
    result: dict[str, Any] | None = None
    rollback: dict[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    audit_seq: int | None = None

    STATUSES: ClassVar[tuple] = (
        "planned",
        "pending_approval",
        "approved",
        "rejected",
        "executing",
        "succeeded",
        "failed",
        "expired",
        "rolled_back",
    )

    @property
    def is_terminal(self) -> bool:
        """``True`` si l'action ne peut plus évoluer (hors rollback)."""
        return self.status in ("rejected", "succeeded", "failed", "expired", "rolled_back")

    @property
    def rollback_available(self) -> bool:
        """``True`` si le playbook expose encore un rollback utilisable."""
        return bool(self.rollback.get("available")) and self.status == "succeeded"


# --------------------------------------------------------------------------------------
# §3.5 AuditRecord
# --------------------------------------------------------------------------------------


@dataclass
class AuditRecord(Model):
    """Entrée du journal append-only chaîné par hash (contrat §3.5)."""

    seq: int | None = None
    ts: str | None = None
    tenant_id: str | None = None
    actor: str | None = None
    actor_role: str | None = None
    action: str | None = None
    target: dict[str, Any] = field(default_factory=dict)
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    prev_hash: str | None = None
    hash: str | None = None


# --------------------------------------------------------------------------------------
# §4.2 Tenant / clés
# --------------------------------------------------------------------------------------


@dataclass
class Tenant(Model):
    """Frontière d'isolation multi-tenant (contrat §4.2)."""

    tenant_id: str | None = None
    name: str | None = None
    mode: str | None = None
    dry_run: bool | None = None
    autonomy_allowlist: list[str] = field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None

    MODES: ClassVar[tuple] = ("manual", "supervised", "auto")


@dataclass
class ApiKey(Model):
    """Métadonnées d'une clé API (la valeur n'est jamais relue après création)."""

    key_id: str | None = None
    api_key: str | None = None
    label: str | None = None
    role: str | None = None
    created_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None


# --------------------------------------------------------------------------------------
# §4.5 Règles / playbooks
# --------------------------------------------------------------------------------------


@dataclass
class Rule(Model):
    """Résumé ou règle complète (le YAML source est conservé dans ``extra['yaml']``)."""

    rule_id: str | None = None
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    confidence: float | None = None
    enabled: bool | None = None
    tags: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    path: str | None = None
    match: dict[str, Any] = field(default_factory=dict)
    dedup: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def yaml_source(self) -> str | None:
        """YAML source renvoyé par ``GET /rules/{rule_id}``, si présent."""
        value = self.extra.get("yaml") or self.extra.get("yaml_source")
        return value if isinstance(value, str) else None


@dataclass
class RuleValidation(Model):
    """Résultat de ``POST /rules/validate``."""

    valid: bool | None = None
    errors: list[Any] = field(default_factory=list)


@dataclass
class Playbook(Model):
    """Procédure d'action nommée, toujours accompagnée d'un rollback (contrat §7)."""

    name: str | None = None
    description: str | None = None
    params_schema: dict[str, Any] = field(default_factory=dict)
    reversible: bool | None = None
    dry_run_capable: bool | None = None
    connectors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# §4.8 Stats / collecteurs
# --------------------------------------------------------------------------------------


@dataclass
class StatsOverview(Model):
    """Compteurs agrégés 24 h / 7 j exposés par ``GET /stats/overview``."""

    window_24h: dict[str, Any] = field(default_factory=dict)
    window_7d: dict[str, Any] = field(default_factory=dict)
    events: dict[str, Any] = field(default_factory=dict)
    findings_by_severity: dict[str, Any] = field(default_factory=dict)
    mtta_seconds: float | None = None
    mttr_seconds: float | None = None
    top_rules: list[Any] = field(default_factory=list)
    actions_succeeded: int | None = None
    actions_rolled_back: int | None = None
    autonomy_mode: str | None = None


@dataclass
class CollectorStatus(Model):
    """État d'un collecteur (dernier run, items, erreurs)."""

    name: str | None = None
    type: str | None = None
    enabled: bool | None = None
    status: str | None = None
    last_run_at: str | None = None
    last_success_at: str | None = None
    items: int | None = None
    errors: int | None = None
    error: str | None = None


# --------------------------------------------------------------------------------------
# Réponses composées
# --------------------------------------------------------------------------------------


@dataclass
class IngestOutcome(Model):
    """Finding issu d'une ingestion (élément de ``findings[]`` du contrat §4.3)."""

    finding_id: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    decision: str | None = None


@dataclass
class IngestResult(Model):
    """Réponse ``202`` de ``POST /api/v1/events`` (contrat §4.3)."""

    accepted: int = 0
    rejected: int = 0
    event_ids: list[str] = field(default_factory=list)
    findings: list[IngestOutcome] = field(default_factory=list)

    _NESTED_LISTS: ClassVar[dict[str, type]] = {"findings": IngestOutcome}

    def merge(self, other: IngestResult) -> IngestResult:
        """Fusionne deux réponses d'ingestion (utilisé quand un lot est découpé)."""
        return IngestResult(
            accepted=self.accepted + other.accepted,
            rejected=self.rejected + other.rejected,
            event_ids=list(self.event_ids) + list(other.event_ids),
            findings=list(self.findings) + list(other.findings),
            extra=dict(self.extra),
        )


@dataclass
class AuditVerification(Model):
    """Réponse de ``GET /api/v1/audit/verify`` (contrat §4.7)."""

    valid: bool | None = None
    records: int | None = None
    broken_at: Any | None = None
