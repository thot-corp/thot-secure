"""Erreurs typées d'Thot Secure et mapping vers les statuts HTTP de l'API."""

from __future__ import annotations

from typing import Any


class ThotSecureError(Exception):
    """Erreur de base. ``code`` est stable et fait partie du contrat d'API."""

    code: str = "internal_error"
    http_status: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.details:
            return f"[{self.code}] {self.message} ({self.details})"
        return f"[{self.code}] {self.message}"


class ConfigError(ThotSecureError):
    """Configuration invalide ou incohérente."""

    code = "config_error"
    http_status = 500


class ValidationError(ThotSecureError):
    """Charge utile invalide (schéma, borne, type)."""

    code = "validation_error"
    http_status = 422


class AuthenticationError(ThotSecureError):
    """Clé API absente, inconnue, révoquée ou expirée."""

    code = "unauthenticated"
    http_status = 401


class PermissionDeniedError(ThotSecureError):
    """Le rôle de l'appelant ne porte pas la capacité requise."""

    code = "forbidden"
    http_status = 403


class NotFoundError(ThotSecureError):
    """Ressource inexistante **ou inaccessible au tenant de l'appelant**."""

    code = "not_found"
    http_status = 404


class ConflictError(ThotSecureError):
    """Transition d'état invalide (doublon, action déjà exécutée, etc.)."""

    code = "conflict"
    http_status = 409


class RateLimitedError(ThotSecureError):
    """Trop de requêtes (garde-fou anti-abus)."""

    code = "rate_limited"
    http_status = 429

    def __init__(
        self, message: str, *, retry_after: int = 60, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details=details)
        self.retry_after = retry_after


class TargetNotAllowedError(ThotSecureError):
    """La cible visée n'appartient pas au périmètre déclaré du tenant.

    Garde-fou anti-abus : Thot Secure n'agit **jamais** sur une infrastructure qui n'est pas
    explicitement déclarée comme possédée par le tenant.
    """

    code = "target_not_allowed"
    http_status = 403


class ProtectedTargetError(ThotSecureError):
    """La cible est dans l'allowlist protégée : l'automatisation est interdite."""

    code = "protected_target"
    http_status = 403


class RuleError(ThotSecureError):
    """Règle de détection invalide."""

    code = "rule_error"
    http_status = 422


class PolicyError(ThotSecureError):
    """Politique de décision invalide."""

    code = "policy_error"
    http_status = 422


class PlaybookError(ThotSecureError):
    """Playbook invalide, paramètres manquants ou étape en échec."""

    code = "playbook_error"
    http_status = 422


class ConnectorError(ThotSecureError):
    """Connecteur non configuré ou en échec."""

    code = "connector_error"
    http_status = 502


class StorageError(ThotSecureError):
    """Erreur de persistance."""

    code = "storage_error"
    http_status = 500


class AuditIntegrityError(ThotSecureError):
    """La chaîne d'audit est rompue : incident de sécurité majeur."""

    code = "audit_integrity_error"
    http_status = 500

    def __init__(self, message: str, *, broken_at: int | None = None) -> None:
        super().__init__(message, details={"broken_at": broken_at})
        self.broken_at = broken_at


class DryRunRefused(ThotSecureError):  # noqa: N818 - nom public exporté (contrat d'API)
    """Action refusée car le mode simulation est actif (comportement attendu et sûr)."""

    code = "dry_run_refused"
    http_status = 409


class AutonomyRefused(ThotSecureError):  # noqa: N818 - nom public exporté (contrat d'API)
    """Le mode d'autonomie du tenant exige une approbation humaine."""

    code = "autonomy_refused"
    http_status = 409


__all__ = [
    "AuditIntegrityError",
    "AuthenticationError",
    "AutonomyRefused",
    "ConfigError",
    "ConflictError",
    "ConnectorError",
    "DryRunRefused",
    "NotFoundError",
    "PermissionDeniedError",
    "PlaybookError",
    "PolicyError",
    "ProtectedTargetError",
    "RateLimitedError",
    "RuleError",
    "StorageError",
    "TargetNotAllowedError",
    "ThotSecureError",
    "ValidationError",
]
