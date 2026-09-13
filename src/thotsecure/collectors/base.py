"""Contrat des collecteurs.

Un collecteur **observe** et produit des événements normalisés. Il n'écrit jamais en base, ne
décide rien et n'agit pas : c'est ce qui permet de tester un collecteur en isolation, de le
rejouer sur un jeu de données, et de garantir qu'aucune collecte ne peut déclencher
directement une contre-mesure sans passer par le moteur de décision.

Toutes les collectes respectent le **périmètre déclaré** (``config/targets.yaml``) : un
collecteur ne découvre pas de cibles tout seul et ne touche à rien qui ne soit explicitement
possédé par le tenant.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..core.config import Settings
from ..core.logging_setup import get_logger
from ..core.models import Event, EventKind, EventSource, Severity, SourceType, Tenant
from ..core.util import iso_z, new_id, redact_secrets, truncate, utcnow
from ..scope import TenantScope

log = get_logger("collectors")

CollectorStatusLiteral = Literal["ok", "partial", "error", "skipped"]


@dataclass(slots=True)
class CollectorContext:
    """Contexte d'exécution transmis à un collecteur."""

    tenant: Tenant
    scope: TenantScope
    settings: Settings
    run_id: str
    #: Émet un événement normalisé (rattaché automatiquement au tenant et au collecteur).
    emit: Callable[..., Event]

    def make_event(
        self,
        *,
        kind: EventKind,
        labels: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        severity_hint: Severity | None = None,
        source_name: str | None = None,
        source_host: str | None = None,
        source_type: SourceType | None = None,
        ts: Any = None,
    ) -> Event:
        """Construit un événement. Les secrets sont masqués et les tailles bornées."""
        return Event(
            event_id=new_id("ev_"),
            tenant_id=self.tenant.tenant_id,
            ts=ts or utcnow(),
            kind=kind,
            source=EventSource(
                type=source_type or "manual",  # type: ignore[arg-type]
                name=source_name,
                host=source_host,
            ),
            severity_hint=severity_hint,
            labels={str(key): _scalar(value) for key, value in (labels or {}).items()},
            payload=_sanitize(payload or {}),
        )

    @property
    def state_dir(self) -> Path:
        """Répertoire d'état du collecteur (positions de lecture de fichiers, etc.)."""
        directory = self.settings.data_path / "collectors"
        directory.mkdir(parents=True, exist_ok=True)
        return directory


@dataclass(slots=True)
class CollectorResult:
    """Résultat d'une exécution de collecteur."""

    collector: str
    status: CollectorStatusLiteral = "ok"
    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    started_at: Any = field(default_factory=utcnow)
    finished_at: Any = None

    @property
    def event_count(self) -> int:
        return len(self.events)

    def add_error(self, message: str) -> None:
        self.errors.append(truncate(redact_secrets(str(message)), 500))
        if self.status == "ok":
            self.status = "partial"

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "status": self.status,
            "events": self.event_count,
            "errors": self.errors[:20],
            "error_count": len(self.errors),
            "detail": self.detail,
            "started_at": iso_z(self.started_at) if self.started_at else None,
            "finished_at": iso_z(self.finished_at) if self.finished_at else None,
        }


class Collector(ABC):
    """Base des collecteurs."""

    #: Nom technique, utilisé par la CLI, l'API et la configuration.
    name: str = "abstract"
    #: Type d'origine inscrit dans les événements (sert de filtre d'entrée aux règles).
    source_type: SourceType = "manual"
    description: str = ""
    #: Intervalle par défaut dans le planificateur.
    default_interval_seconds: int = 300
    #: Vrai si le collecteur exige un opt-in explicite du tenant (``allow_probe: true``).
    requires_probe_optin: bool = False

    @abstractmethod
    def collect(self, context: CollectorContext) -> CollectorResult:
        """Exécute une passe de collecte. **Ne doit jamais lever** : utiliser ``add_error``."""

    # ----------------------------------------------------------------------------------

    def enabled(self, settings: Settings, scope: TenantScope) -> tuple[bool, str]:
        """Indique si le collecteur peut s'exécuter, avec la raison du refus."""
        if self.requires_probe_optin and not scope.allow_probe:
            return False, (
                f"le tenant '{scope.tenant_id}' n'a pas activé 'allow_probe' dans "
                "config/targets.yaml (opt-in explicite requis)"
            )
        return True, "autorisé"

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_type": self.source_type,
            "description": self.description,
            "interval_seconds": self.default_interval_seconds,
            "requires_probe_optin": self.requires_probe_optin,
        }

    # ----------------------------------------------------------------------------------

    def _skip(self, reason: str) -> CollectorResult:
        log.info(
            "collecte ignorée",
            extra={"collector": self.name, "reason": reason},
        )
        return CollectorResult(collector=self.name, status="skipped", detail={"reason": reason})


# --------------------------------------------------------------------------------------
# Assainissement des données collectées
# --------------------------------------------------------------------------------------

#: Clés dont la valeur est systématiquement masquée : un journal d'événements ne doit jamais
#: devenir un dépôt de secrets (RGPD + hygiène de sécurité).
_SENSITIVE_KEYS = (
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "private_key",
    "session",
    "csrf",
)


def _scalar(value: Any) -> Any:
    """Contraint une valeur à un scalaire (les ``labels`` doivent rester plats)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str):
            return truncate(redact_secrets(value), 512)
        return value
    return truncate(redact_secrets(str(value)), 512)


def _sanitize(payload: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Masque les secrets et borne la profondeur/la taille d'une charge utile."""
    from ..core.util import canonical_json

    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        key_text = str(key)
        if any(marker in key_text.lower() for marker in _SENSITIVE_KEYS):
            cleaned[key_text] = "<redacted>"
            continue
        if isinstance(value, dict) and depth < 3:
            cleaned[key_text] = _sanitize(value, depth=depth + 1)
        elif isinstance(value, (list, tuple)) and depth < 3:
            cleaned[key_text] = [
                _sanitize(item, depth=depth + 1) if isinstance(item, dict) else _scalar(item)
                for item in value[:50]
            ]
        elif isinstance(value, str):
            cleaned[key_text] = truncate(redact_secrets(value), 2048)
        else:
            cleaned[key_text] = value
    if len(canonical_json(cleaned)) > 32 * 1024:
        # Une charge utile de plus de 32 Kio n'apporte rien à la détection : on la tronque
        # plutôt que de saturer la base et la bande passante du bus.
        return {"_truncated": True, "keys": sorted(cleaned)[:50]}
    return cleaned


__all__ = [
    "Collector",
    "CollectorContext",
    "CollectorResult",
    "CollectorStatusLiteral",
]
