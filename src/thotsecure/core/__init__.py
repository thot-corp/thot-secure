"""Cœur d'Thot Secure : configuration, modèles, erreurs, utilitaires.

Ce sous-paquet ne dépend que de la **stdlib**, de ``pydantic`` et de ``PyYAML``.
FastAPI, Jinja2 et uvicorn sont réservés à la couche API : le moteur de détection, le
scoring, la décision et les actions restent utilisables en bibliothèque, en CLI, dans un
job planifié ou dans un test unitaire, sans serveur HTTP.
"""

from __future__ import annotations

from .config import (
    DEFAULT_TENANT_SETTINGS,
    Autonomy,
    BusBackend,
    Settings,
    get_settings,
    set_settings,
)
from .errors import (
    AuditIntegrityError,
    AuthenticationError,
    AutonomyRefused,
    ConfigError,
    ConflictError,
    ConnectorError,
    DryRunRefused,
    NotFoundError,
    PermissionDeniedError,
    PlaybookError,
    PolicyError,
    ProtectedTargetError,
    RateLimitedError,
    RuleError,
    StorageError,
    TargetNotAllowedError,
    ThotSecureError,
    ValidationError,
)
from .logging_setup import bind_context, configure_logging, get_logger

__all__ = [
    "DEFAULT_TENANT_SETTINGS",
    "AuditIntegrityError",
    "AuthenticationError",
    "Autonomy",
    "AutonomyRefused",
    "BusBackend",
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
    "Settings",
    "StorageError",
    "TargetNotAllowedError",
    "ThotSecureError",
    "ValidationError",
    "bind_context",
    "configure_logging",
    "get_logger",
    "get_settings",
    "set_settings",
]
