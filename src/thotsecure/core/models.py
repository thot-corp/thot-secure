"""Modèles de domaine d'Thot Secure (contrat d'interface §3).

Tous les modèles sont des ``pydantic.BaseModel`` v2 : validation d'entrée, sérialisation
JSON conforme au contrat, et génération de schéma OpenAPI pour l'API.

Rappel de conception : un ``Event`` est **immuable**, un ``Finding`` est un **agrégat**, une
``Action`` a un **cycle de vie explicite** et un ``AuditRecord`` est **chaîné par hash**.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
    model_validator,
)

from .util import iso_z, new_id, utcnow

# --------------------------------------------------------------------------------------
# Types de base
# --------------------------------------------------------------------------------------

Severity = Literal["info", "low", "medium", "high", "critical"]
DecisionKind = Literal["auto", "require_approval", "notify_only", "ignore"]
ActionStatus = Literal[
    "planned",
    "pending_approval",
    "approved",
    "rejected",
    "executing",
    "succeeded",
    "failed",
    "expired",
    "rolled_back",
]
FindingStatus = Literal["open", "acked", "closed", "suppressed"]
EventKind = Literal[
    "http.request",
    "http.response",
    "log.line",
    "tls.cert",
    "dependency",
    "config.audit",
    "syslog",
    "generic",
]
SourceType = Literal[
    "web_probe",
    "log_tail",
    "dependency",
    "webhook",
    "syslog",
    "tls_cert",
    "config_audit",
    "manual",
    "demo",
]
Role = Literal["viewer", "analyst", "responder", "admin"]
Scalar = str | int | float | bool | None

#: Horodatage sérialisé en ISO-8601 UTC avec suffixe ``Z`` (format du contrat).
UtcDateTime = Annotated[datetime, PlainSerializer(iso_z, return_type=str, when_used="json")]

SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(str(severity or "info").lower(), 0)


def severity_at_least(value: str | None, minimum: str) -> bool:
    return severity_rank(value) >= severity_rank(minimum)


def max_severity(*values: str | None) -> str:
    best = "info"
    for value in values:
        if severity_rank(value) > severity_rank(best):
            best = str(value).lower()
    return best


class StrictModel(BaseModel):
    """Modèle de configuration : un champ inconnu est une erreur (les fautes de frappe
    dans une règle ou une politique doivent être signalées, pas ignorées)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)


# --------------------------------------------------------------------------------------
# Événements
# --------------------------------------------------------------------------------------


class EventSource(StrictModel):
    """Origine d'un événement (quel collecteur, sur quel hôte)."""

    type: SourceType
    name: str | None = None
    host: str | None = None


class Event(BaseModel):
    """Fait brut normalisé, émis par un collecteur. Immuable après ingestion."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True, str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: new_id("ev_"))
    schema_version: Literal["1"] = "1"
    tenant_id: str
    ts: UtcDateTime = Field(default_factory=utcnow)
    kind: EventKind = "generic"
    source: EventSource
    severity_hint: Severity | None = None
    labels: dict[str, Scalar] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None

    @field_validator("labels")
    @classmethod
    def _validate_labels(cls, value: dict[str, Any]) -> dict[str, Scalar]:
        """``labels`` doit rester **plat** et scalaire : c'est l'espace de nommage des règles
        (``labels.src_ip``). Un objet imbriqué est une erreur de collecteur, pas un cas limite."""
        flat: dict[str, Scalar] = {}
        for key, item in value.items():
            key = str(key)
            if isinstance(item, (dict, list, tuple, set)):
                raise ValueError(
                    f"labels.{key} doit être scalaire (str/int/float/bool/null) ; "
                    "utilisez 'payload' pour les structures imbriquées"
                )
            if isinstance(item, str):
                item = item[:1024]
            flat[key] = item
        return flat

    @field_validator("tenant_id")
    @classmethod
    def _validate_tenant(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned or len(cleaned) > 64:
            raise ValueError("tenant_id invalide (1-64 caractères)")
        return cleaned

    @property
    def src_ip(self) -> str | None:
        value = self.labels.get("src_ip")
        return str(value) if value else None

    def dedup_key(self, fields: list[str]) -> str:
        """Clé de regroupement d'un finding, construite sur les champs demandés par la règle."""
        from .util import stable_hash

        values = {field: self.labels.get(field) or self.payload.get(field) for field in fields}
        values["tenant_id"] = self.tenant_id
        return stable_hash(values)[:24]


class IngestResult(BaseModel):
    """Résultat d'une ingestion (réponse ``202`` de ``POST /api/v1/events``)."""

    accepted: int = 0
    rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------


class Finding(BaseModel):
    """Agrégat d'événements déclenché par une règle, porteur d'un score de risque."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(default_factory=lambda: new_id("fi_"))
    tenant_id: str
    rule_id: str
    rule_name: str = ""
    severity: Severity = "medium"
    risk_score: float = 0.0
    confidence: float = 0.5
    status: FindingStatus = "open"
    title: str = ""
    description: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    first_seen: UtcDateTime = Field(default_factory=utcnow)
    last_seen: UtcDateTime = Field(default_factory=utcnow)
    count: int = 1
    event_ids: list[str] = Field(default_factory=list)
    created_at: UtcDateTime = Field(default_factory=utcnow)
    updated_at: UtcDateTime = Field(default_factory=utcnow)
    #: Clé interne de regroupement (règle + entités de dédup) — absente du contrat public.
    dedup_key: str = ""
    resolution: str | None = None
    comment: str | None = None

    @field_validator("risk_score")
    @classmethod
    def _clamp_score(cls, value: float) -> float:
        return max(0.0, min(100.0, round(float(value), 2)))

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @property
    def is_open(self) -> bool:
        return self.status == "open"


class RiskBreakdown(BaseModel):
    """Décomposition **explicable** du score : un analyste doit pouvoir contester un score."""

    base: float = 0.0
    severity_factor: float = 1.0
    confidence_factor: float = 1.0
    asset_factor: float = 1.0
    repetition_factor: float = 1.0
    final: float = 0.0
    formula: str = ""
    steps: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Décision
# --------------------------------------------------------------------------------------


class Decision(BaseModel):
    """Sortie du moteur de décision (*policy-as-code*)."""

    decision: DecisionKind = "notify_only"
    policy_id: str | None = None
    playbook: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    risk_score: float = 0.0
    expires_at: UtcDateTime | None = None
    cooldown_seconds: int | None = None
    dry_run: bool = True
    evaluated_policies: list[str] = Field(default_factory=list)
    guards: list[str] = Field(default_factory=list)

    @property
    def triggers_action(self) -> bool:
        return self.decision in {"auto", "require_approval"} and bool(self.playbook)


# --------------------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------------------


class ActionTarget(StrictModel):
    type: Literal["ip", "cidr", "host", "url", "user", "session", "file", "package", "secret", "other"] = "other"
    value: str = ""

    def __str__(self) -> str:
        return f"{self.type}:{self.value}"


class ActionRollback(BaseModel):
    model_config = ConfigDict(extra="ignore")

    available: bool = True
    token: str | None = None
    performed_at: UtcDateTime | None = None
    result: dict[str, Any] | None = None
    expires_at: UtcDateTime | None = None
    auto_after_seconds: int | None = None


class Action(BaseModel):
    """Instance d'exécution d'un playbook, avec cycle de vie, réversibilité et audit."""

    model_config = ConfigDict(extra="ignore")

    action_id: str = Field(default_factory=lambda: new_id("ac_"))
    tenant_id: str
    finding_id: str | None = None
    policy_id: str | None = None
    playbook: str
    status: ActionStatus = "planned"
    mode: Literal["auto", "manual"] = "manual"
    dry_run: bool = True
    params: dict[str, Any] = Field(default_factory=dict)
    target: ActionTarget = Field(default_factory=ActionTarget)
    requested_by: str = "system"
    requested_at: UtcDateTime = Field(default_factory=utcnow)
    approved_by: str | None = None
    approved_at: UtcDateTime | None = None
    rejected_by: str | None = None
    rejected_at: UtcDateTime | None = None
    executed_at: UtcDateTime | None = None
    expires_at: UtcDateTime | None = None
    result: dict[str, Any] | None = None
    rollback: ActionRollback = Field(default_factory=ActionRollback)
    idempotency_key: str = ""
    audit_seq: int | None = None
    reason: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.status in {"succeeded", "failed", "rejected", "expired", "rolled_back"}

    @property
    def can_execute(self) -> bool:
        return self.status in {"planned", "approved"}

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "playbook": self.playbook,
            "status": self.status,
            "dry_run": self.dry_run,
            "mode": self.mode,
            "target": str(self.target),
        }


# --------------------------------------------------------------------------------------
# Tenants et clés
# --------------------------------------------------------------------------------------


class Tenant(StrictModel):
    """Frontière d'isolation. Le mode d'autonomie est décidé **par tenant**."""

    tenant_id: str
    name: str = ""
    mode: Literal["manual", "supervised", "auto"] = "supervised"
    dry_run: bool = True
    #: Plages (CIDR) sur lesquelles l'automatisation est autorisée. Vide = tout ce qui est
    #: déclaré dans ``config/targets.yaml`` pour ce tenant.
    autonomy_allowlist: list[str] = Field(default_factory=list)
    #: Plages **jamais** touchées automatiquement (infra critique, passerelle du tenant…).
    protected_targets: list[str] = Field(default_factory=list)
    max_actions_per_hour: int = 20
    cooldown_seconds: int = 300
    asset_criticality: float = 1.0
    created_at: UtcDateTime = Field(default_factory=utcnow)
    updated_at: UtcDateTime = Field(default_factory=utcnow)

    @field_validator("tenant_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned or len(cleaned) > 64:
            raise ValueError("tenant_id invalide (1-64 caractères)")
        if not all(ch.isalnum() or ch in "-_" for ch in cleaned):
            raise ValueError("tenant_id : alphanumériques, '-' et '_' uniquement")
        return cleaned

    @field_validator("asset_criticality")
    @classmethod
    def _clamp_criticality(cls, value: float) -> float:
        return max(0.1, min(3.0, float(value)))

    def allows_automation_for(self, ip: str | None) -> bool:
        """Vrai si l'automatisation est permise pour cette IP (allowlist vide = tolérant)."""
        from .util import ip_in_cidrs

        if not self.autonomy_allowlist:
            return True
        if not ip:
            return False
        return ip_in_cidrs(ip, self.autonomy_allowlist)

    def is_protected(self, ip: str | None) -> bool:
        """Vrai si la cible est explicitement protégée : aucune action automatique."""
        from .util import ip_in_cidrs

        if not ip or not self.protected_targets:
            return False
        return ip_in_cidrs(ip, self.protected_targets)


class ApiKeyInfo(BaseModel):
    """Métadonnées d'une clé API (jamais le secret)."""

    model_config = ConfigDict(extra="ignore")

    key_id: str
    tenant_id: str
    label: str = ""
    role: Role = "viewer"
    key_prefix: str = ""
    created_at: UtcDateTime = Field(default_factory=utcnow)
    last_used_at: UtcDateTime | None = None
    revoked_at: UtcDateTime | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class ApiKeyRecord(ApiKeyInfo):
    """Enregistrement interne : contient l'empreinte scrypt, jamais la clé en clair."""

    key_hash: str = ""


class Principal(BaseModel):
    """Identité authentifiée d'un appelant (API, CLI ou console)."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str
    role: Role = "viewer"
    key_id: str | None = None
    label: str = ""
    capabilities: frozenset[str] = Field(default_factory=frozenset)
    authenticated: bool = True

    @property
    def actor(self) -> str:
        if self.key_id:
            return f"api-key:{self.key_id}"
        return f"console:{self.tenant_id}"

    def can(self, capability: str) -> bool:
        return capability in self.capabilities


# --------------------------------------------------------------------------------------
# Règles de détection
# --------------------------------------------------------------------------------------

Operator = Literal[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "icontains",
    "startswith",
    "endswith",
    "regex",
    "exists",
    "cidr",
    "len_gt",
    "len_lt",
]


class Condition(StrictModel):
    """Test élémentaire sur un événement : ``labels.path`` ``regex`` ``(?i)union select``."""

    field: str
    op: Operator = "eq"
    value: Any = None
    case_sensitive: bool = True
    negate: bool = False

    @field_validator("field")
    @classmethod
    def _validate_field(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("'field' ne peut pas être vide")
        if cleaned.startswith("$") or ".." in cleaned:
            raise ValueError(f"chemin de champ invalide: {cleaned!r}")
        return cleaned


class Threshold(StrictModel):
    """Agrégation : ``count`` occurrences en ``window_seconds``, groupées par entités."""

    count: int = 1
    window_seconds: int = 60
    group_by: list[str] = Field(default_factory=list)

    @field_validator("count")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("threshold.count doit être ≥ 1")
        return value

    @field_validator("window_seconds")
    @classmethod
    def _window(cls, value: int) -> int:
        if value < 1 or value > 86400:
            raise ValueError("threshold.window_seconds doit être dans [1, 86400]")
        return value


class MatchSpec(StrictModel):
    """Combinaison logique de conditions. Sans ``all``/``any``, la règle ne matche rien
    (une règle qui matche tout est un incident de production, pas une détection)."""

    all: list[Condition] = Field(default_factory=list)
    any: list[Condition] = Field(default_factory=list)
    not_: list[Condition] = Field(default_factory=list, alias="not")
    threshold: Threshold | None = None

    def is_empty(self) -> bool:
        return not (self.all or self.any or self.not_)


class RuleDedup(StrictModel):
    key: list[str] = Field(default_factory=list)
    ttl_seconds: int = 900

    @field_validator("ttl_seconds")
    @classmethod
    def _ttl(cls, value: int) -> int:
        if value < 1 or value > 30 * 86400:
            raise ValueError("dedup.ttl_seconds doit être dans [1, 2592000]")
        return value


class RuleRisk(StrictModel):
    """Paramètres de scoring. ``base=None`` ⇒ la base est dérivée de la sévérité, ce qui
    évite de devoir recopier la même valeur dans des centaines de règles."""

    base: float | None = None
    asset_criticality: float = 1.0

    @field_validator("base")
    @classmethod
    def _clamp_base(cls, value: float | None) -> float | None:
        if value is None:
            return None
        return max(0.0, min(100.0, float(value)))


class Rule(StrictModel):
    """Règle de détection (contrat §5). Une règle invalide est rejetée avec un diagnostic :
    elle ne doit **jamais** interrompre le chargement de la bibliothèque."""

    id: str
    title: str
    description: str = ""
    status: Literal["draft", "test", "stable", "deprecated"] = "draft"
    severity: Severity = "medium"
    confidence: float = 0.5
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    source_types: list[SourceType] = Field(default_factory=list)
    kinds: list[EventKind] = Field(default_factory=list)
    match: MatchSpec
    dedup: RuleDedup = Field(default_factory=RuleDedup)
    risk: RuleRisk = Field(default_factory=RuleRisk)
    false_positives: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    #: Renseigné au chargement (jamais dans le YAML source).
    path: str | None = None
    sigma_compat: bool = False

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned:
            raise ValueError("'id' est obligatoire")
        if len(cleaned) > 80:
            raise ValueError("'id' trop long (max 80)")
        return cleaned

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @model_validator(mode="after")
    def _validate_semantics(self) -> Rule:
        if self.match.is_empty():
            raise ValueError("'match' doit définir au moins une condition dans all/any/not")
        if not self.title.strip():
            raise ValueError("'title' est obligatoire")
        # Une règle active à haut impact doit documenter sa remédiation : c'est la différence
        # entre une alerte et une capacité de réponse.
        if self.severity in {"high", "critical"} and not self.remediation.strip():
            raise ValueError(
                f"la règle {self.id} est de sévérité {self.severity} : "
                "'remediation' est obligatoire (que doit faire l'analyste ?)"
            )
        return self

    def summary(self) -> dict[str, Any]:
        return {
            "rule_id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "status": self.status,
            "tags": list(self.tags),
            "source_types": list(self.source_types),
            "kinds": list(self.kinds),
            "path": self.path,
            "sigma_compat": self.sigma_compat,
        }


class RuleDiagnostic(BaseModel):
    """Diagnostic de chargement d'une règle (journalisé, exposé par ``rules/reload``)."""

    path: str
    error: str
    rule_id: str | None = None


# --------------------------------------------------------------------------------------
# Politiques de décision
# --------------------------------------------------------------------------------------


class PolicyThen(StrictModel):
    decision: DecisionKind = "notify_only"
    playbook: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool | None = None
    cooldown_seconds: int | None = None
    max_actions_per_hour: int | None = None

    @model_validator(mode="after")
    def _validate_playbook(self) -> PolicyThen:
        if self.decision in {"auto", "require_approval"} and not self.playbook:
            raise ValueError(
                f"then.decision={self.decision} exige 'then.playbook' "
                "(sinon la décision ne mène à rien)"
            )
        return self


class PolicyRollback(StrictModel):
    playbook: str | None = None
    auto_after_seconds: int | None = None


class Policy(StrictModel):
    """Politique de décision (contrat §6)."""

    version: int = 1
    id: str
    priority: int = 0
    description: str = ""
    enabled: bool = True
    when: dict[str, Any] = Field(default_factory=dict)
    then: PolicyThen
    rollback: PolicyRollback = Field(default_factory=PolicyRollback)
    path: str | None = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 80:
            raise ValueError("'id' de politique invalide (1-80 caractères)")
        return cleaned

    def summary(self) -> dict[str, Any]:
        return {
            "policy_id": self.id,
            "priority": self.priority,
            "enabled": self.enabled,
            "description": self.description,
            "decision": self.then.decision,
            "playbook": self.then.playbook,
            "when": self.when,
            "path": self.path,
        }


# --------------------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------------------


class PlaybookParam(StrictModel):
    """Spécification d'un paramètre de playbook : type, obligation, bornes, énumération."""

    type: Literal[
        "string",
        "integer",
        "boolean",
        "duration",
        "ip",
        "cidr",
        "host",
        "path",
        "package",
        "secret",
        "url",
    ] = "string"
    required: bool = False
    default: Any = None
    description: str = ""
    min: float | None = None
    max: float | None = None
    choices: list[str] | None = None


class PlaybookStep(StrictModel):
    """Étape d'exécution : ``connector`` logique (``waf``, ``notify``…) + opération à appeler."""

    connector: str
    call: str
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    #: Si vrai, l'échec de l'étape n'interrompt pas le playbook (ex. notification).
    optional: bool = False


class PlaybookAudit(StrictModel):
    severity: Severity = "medium"
    notify: list[str] = Field(default_factory=list)


class Playbook(StrictModel):
    """Procédure d'action nommée, **toujours** accompagnée d'un rollback (contrat §7)."""

    name: str
    description: str = ""
    reversible: bool = True
    dry_run_capable: bool = True
    connectors: list[str] = Field(default_factory=list)
    params: dict[str, PlaybookParam] = Field(default_factory=dict)
    execute: list[PlaybookStep] = Field(default_factory=list)
    rollback: list[PlaybookStep] = Field(default_factory=list)
    audit: PlaybookAudit = Field(default_factory=PlaybookAudit)
    path: str | None = None

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 80:
            raise ValueError("'name' de playbook invalide")
        return cleaned

    @model_validator(mode="after")
    def _validate_reversibility(self) -> Playbook:
        if not self.execute:
            raise ValueError(f"le playbook {self.name} n'a aucune étape d'exécution")
        # Invariant produit : toute action doit pouvoir être annulée. Un playbook marqué
        # réversible sans étapes de rollback est un mensonge dangereux.
        if self.reversible and not self.rollback:
            raise ValueError(
                f"le playbook {self.name} est marqué reversible=true mais ne définit aucun "
                "rollback : soit ajoutez un rollback, soit passez reversible=false "
                "(et attendez-vous à une approbation humaine systématique)"
            )
        return self

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "reversible": self.reversible,
            "dry_run_capable": self.dry_run_capable,
            "connectors": list(self.connectors),
            "params_schema": {k: v.model_dump() for k, v in self.params.items()},
            "steps": len(self.execute),
            "rollback_steps": len(self.rollback),
            "path": self.path,
        }


# --------------------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------------------


class AuditRecord(BaseModel):
    """Enregistrement append-only, chaîné par hash (contrat §3.5)."""

    model_config = ConfigDict(extra="ignore")

    seq: int
    ts: UtcDateTime = Field(default_factory=utcnow)
    tenant_id: str
    actor: str
    actor_role: str = "system"
    action: str
    target: dict[str, Any] = Field(default_factory=dict)
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class AuditVerifyResult(BaseModel):
    valid: bool
    records: int = 0
    broken_at: int | None = None
    reason: str | None = None
    checked_at: UtcDateTime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------------------
# Collecteurs, statistiques
# --------------------------------------------------------------------------------------


class CollectorStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    source_type: str = "generic"
    description: str = ""
    enabled: bool = True
    interval_seconds: int = 300
    last_run: UtcDateTime | None = None
    last_status: Literal["never", "ok", "partial", "error"] = "never"
    last_error: str | None = None
    events_emitted: int = 0
    findings_emitted: int = 0
    runs: int = 0
    targets: list[str] = Field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class SeverityCounts(BaseModel):
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

    def add(self, severity: str, count: int = 1) -> None:
        if severity in SEVERITIES:
            setattr(self, severity, getattr(self, severity) + count)


class StatsOverview(BaseModel):
    """Indicateurs exposés par ``GET /api/v1/stats/overview`` et par la console."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str
    window_hours: int = 24
    generated_at: UtcDateTime = Field(default_factory=utcnow)
    events_total: int = 0
    events_by_kind: dict[str, int] = Field(default_factory=dict)
    findings_total: int = 0
    findings_open: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_status: dict[str, int] = Field(default_factory=dict)
    top_rules: list[dict[str, Any]] = Field(default_factory=list)
    actions_total: int = 0
    actions_by_status: dict[str, int] = Field(default_factory=dict)
    actions_auto: int = 0
    actions_manual: int = 0
    actions_rolled_back: int = 0
    actions_failed: int = 0
    mttd_seconds: float | None = None
    mttr_seconds: float | None = None
    autonomy: str = "supervised"
    dry_run: bool = True
    audit_records: int = 0
    audit_valid: bool = True
    collectors: list[CollectorStatus] = Field(default_factory=list)


__all__ = [
    "Action",
    "ActionRollback",
    "ActionStatus",
    "ActionTarget",
    "ApiKeyInfo",
    "ApiKeyRecord",
    "AuditRecord",
    "AuditVerifyResult",
    "CollectorStatus",
    "Condition",
    "Decision",
    "DecisionKind",
    "Event",
    "EventKind",
    "EventSource",
    "Finding",
    "FindingStatus",
    "IngestResult",
    "MatchSpec",
    "Operator",
    "Playbook",
    "PlaybookAudit",
    "PlaybookParam",
    "PlaybookStep",
    "Policy",
    "PolicyRollback",
    "PolicyThen",
    "Principal",
    "RiskBreakdown",
    "Role",
    "Rule",
    "RuleDedup",
    "RuleDiagnostic",
    "RuleRisk",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Scalar",
    "Severity",
    "SeverityCounts",
    "SourceType",
    "StatsOverview",
    "StrictModel",
    "Tenant",
    "Threshold",
    "UtcDateTime",
    "max_severity",
    "severity_at_least",
    "severity_rank",
]
