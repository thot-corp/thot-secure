"""Modèles typés du contrat Thot Secure (docs/architecture/api-contract.md, §3).

Chaque modèle est une ``dataclass`` qui :

* expose **exactement** les noms de champs JSON du contrat (snake_case, ex. ``risk_score``) ;
* tolère les champs inconnus : ils sont conservés dans ``extra`` et réémis par :meth:`to_dict`,
  ce qui garantit la compatibilité ascendante quand le serveur enrichit une réponse ;
* sait se construire depuis un dictionnaire (:meth:`from_dict`) et se sérialiser
  (:meth:`to_dict`), y compris récursivement pour les modèles imbriqués.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import date, datetime
from typing import Any, ClassVar, Dict, Generic, List, Mapping, Optional, TypeVar

__all__ = [
    "Model",
    "Page",
    "Event",
    "Finding",
    "Decision",
    "Action",
    "AuditRecord",
    "Tenant",
    "Rule",
    "Playbook",
    "StatsOverview",
    "CollectorStatus",
    "ApiKey",
    "IngestResult",
    "IngestOutcome",
    "RuleValidation",
    "AuditVerification",
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
    extra: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    #: Champs imbriqués (nom du champ -> modèle) et listes de modèles.
    _NESTED: ClassVar[Dict[str, type]] = {}
    _NESTED_LISTS: ClassVar[Dict[str, type]] = {}

    # ------------------------------------------------------------------ utilitaires

    @classmethod
    def _field_names(cls) -> tuple:
        cached = cls.__dict__.get("_field_names_cache")
        if cached is None:
            cached = tuple(f.name for f in fields(cls) if f.name != "extra")
            setattr(cls, "_field_names_cache", cached)
        return cached

    @classmethod
    def _convert(cls, name: str, value: Any) -> Any:
        nested = cls._NESTED.get(name)
        if nested is not None and isinstance(value, Mapping):
            return nested.from_dict(value)
        list_model = cls._NESTED_LISTS.get(name)
        if list_model is not None and isinstance(value, list):
            return [
                list_model.from_dict(item) if isinstance(item, Mapping) else item
                for item in value
            ]
        return value

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> Any:
        """Construit le modèle depuis un dictionnaire (tolérant : champs inconnus → ``extra``)."""
        if data is None:
            return None
        if not isinstance(data, Mapping):
            raise TypeError("%s.from_dict attend un mapping, reçu %r" % (cls.__name__, type(data)))
        names = cls._field_names()
        kwargs: Dict[str, Any] = {}
        for name in names:
            if name in data:
                kwargs[name] = cls._convert(name, data[name])
        kwargs["extra"] = {k: v for k, v in data.items() if k not in names}
        return cls(**kwargs)

    def to_dict(self, *, omit_none: bool = False) -> Dict[str, Any]:
        """Sérialise le modèle.

        ``omit_none=True`` retire les champs ``None`` (utile pour construire un corps de requête) ;
        par défaut tous les champs du contrat sont présents, ce qui rend l'aller-retour fidèle.
        """
        out: Dict[str, Any] = {}
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

    items: List[T] = field(default_factory=list)
    next_cursor: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

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
        model: Optional[type] = None,
        *,
        items_key: str = "items",
    ) -> "Page[Any]":
        """Normalise les formes de réponse possibles (``{"items":[...]}`` ou liste nue)."""
        if isinstance(payload, list):
            raw_items = payload
            container: Dict[str, Any] = {}
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
        items: List[Any] = []
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

    event_id: Optional[str] = None
    schema_version: Optional[str] = None
    tenant_id: Optional[str] = None
    ts: Optional[str] = None
    kind: Optional[str] = None
    source: Dict[str, Any] = field(default_factory=dict)
    severity_hint: Optional[str] = None
    labels: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    raw_ref: Optional[str] = None

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

    def to_dict(self, *, omit_none: bool = False) -> Dict[str, Any]:
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

    finding_id: Optional[str] = None
    tenant_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    status: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    count: Optional[int] = None
    event_ids: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    STATUSES: ClassVar[tuple] = ("open", "acked", "closed", "suppressed")
    SEVERITIES: ClassVar[tuple] = ("info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------------------
# §3.3 Decision
# --------------------------------------------------------------------------------------


@dataclass
class Decision(Model):
    """Décision rendue par le moteur policy-as-code (contrat §3.3)."""

    decision: Optional[str] = None
    policy_id: Optional[str] = None
    playbook: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    risk_score: Optional[float] = None
    expires_at: Optional[str] = None
    cooldown_seconds: Optional[int] = None
    dry_run: Optional[bool] = None

    DECISIONS: ClassVar[tuple] = ("auto", "require_approval", "notify_only", "ignore")


# --------------------------------------------------------------------------------------
# §3.4 Action
# --------------------------------------------------------------------------------------


@dataclass
class Action(Model):
    """Instance d'exécution d'un playbook, avec cycle de vie et rollback (contrat §3.4)."""

    action_id: Optional[str] = None
    tenant_id: Optional[str] = None
    finding_id: Optional[str] = None
    policy_id: Optional[str] = None
    playbook: Optional[str] = None
    status: Optional[str] = None
    mode: Optional[str] = None
    dry_run: Optional[bool] = None
    params: Dict[str, Any] = field(default_factory=dict)
    target: Dict[str, Any] = field(default_factory=dict)
    requested_by: Optional[str] = None
    requested_at: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    expires_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    rollback: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    audit_seq: Optional[int] = None

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

    seq: Optional[int] = None
    ts: Optional[str] = None
    tenant_id: Optional[str] = None
    actor: Optional[str] = None
    actor_role: Optional[str] = None
    action: Optional[str] = None
    target: Dict[str, Any] = field(default_factory=dict)
    before: Dict[str, Any] = field(default_factory=dict)
    after: Dict[str, Any] = field(default_factory=dict)
    prev_hash: Optional[str] = None
    hash: Optional[str] = None


# --------------------------------------------------------------------------------------
# §4.2 Tenant / clés
# --------------------------------------------------------------------------------------


@dataclass
class Tenant(Model):
    """Frontière d'isolation multi-tenant (contrat §4.2)."""

    tenant_id: Optional[str] = None
    name: Optional[str] = None
    mode: Optional[str] = None
    dry_run: Optional[bool] = None
    autonomy_allowlist: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    MODES: ClassVar[tuple] = ("manual", "supervised", "auto")


@dataclass
class ApiKey(Model):
    """Métadonnées d'une clé API (la valeur n'est jamais relue après création)."""

    key_id: Optional[str] = None
    api_key: Optional[str] = None
    label: Optional[str] = None
    role: Optional[str] = None
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


# --------------------------------------------------------------------------------------
# §4.5 Règles / playbooks
# --------------------------------------------------------------------------------------


@dataclass
class Rule(Model):
    """Résumé ou règle complète (le YAML source est conservé dans ``extra['yaml']``)."""

    rule_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    enabled: Optional[bool] = None
    tags: List[str] = field(default_factory=list)
    source_types: List[str] = field(default_factory=list)
    kinds: List[str] = field(default_factory=list)
    path: Optional[str] = None
    match: Dict[str, Any] = field(default_factory=dict)
    dedup: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    @property
    def yaml_source(self) -> Optional[str]:
        """YAML source renvoyé par ``GET /rules/{rule_id}``, si présent."""
        value = self.extra.get("yaml") or self.extra.get("yaml_source")
        return value if isinstance(value, str) else None


@dataclass
class RuleValidation(Model):
    """Résultat de ``POST /rules/validate``."""

    valid: Optional[bool] = None
    errors: List[Any] = field(default_factory=list)


@dataclass
class Playbook(Model):
    """Procédure d'action nommée, toujours accompagnée d'un rollback (contrat §7)."""

    name: Optional[str] = None
    description: Optional[str] = None
    params_schema: Dict[str, Any] = field(default_factory=dict)
    reversible: Optional[bool] = None
    dry_run_capable: Optional[bool] = None
    connectors: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# §4.8 Stats / collecteurs
# --------------------------------------------------------------------------------------


@dataclass
class StatsOverview(Model):
    """Compteurs agrégés 24 h / 7 j exposés par ``GET /stats/overview``."""

    window_24h: Dict[str, Any] = field(default_factory=dict)
    window_7d: Dict[str, Any] = field(default_factory=dict)
    events: Dict[str, Any] = field(default_factory=dict)
    findings_by_severity: Dict[str, Any] = field(default_factory=dict)
    mtta_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    top_rules: List[Any] = field(default_factory=list)
    actions_succeeded: Optional[int] = None
    actions_rolled_back: Optional[int] = None
    autonomy_mode: Optional[str] = None


@dataclass
class CollectorStatus(Model):
    """État d'un collecteur (dernier run, items, erreurs)."""

    name: Optional[str] = None
    type: Optional[str] = None
    enabled: Optional[bool] = None
    status: Optional[str] = None
    last_run_at: Optional[str] = None
    last_success_at: Optional[str] = None
    items: Optional[int] = None
    errors: Optional[int] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------------------
# Réponses composées
# --------------------------------------------------------------------------------------


@dataclass
class IngestOutcome(Model):
    """Finding issu d'une ingestion (élément de ``findings[]`` du contrat §4.3)."""

    finding_id: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    decision: Optional[str] = None


@dataclass
class IngestResult(Model):
    """Réponse ``202`` de ``POST /api/v1/events`` (contrat §4.3)."""

    accepted: int = 0
    rejected: int = 0
    event_ids: List[str] = field(default_factory=list)
    findings: List[IngestOutcome] = field(default_factory=list)

    _NESTED_LISTS: ClassVar[Dict[str, type]] = {"findings": IngestOutcome}

    def merge(self, other: "IngestResult") -> "IngestResult":
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

    valid: Optional[bool] = None
    records: Optional[int] = None
    broken_at: Optional[Any] = None
