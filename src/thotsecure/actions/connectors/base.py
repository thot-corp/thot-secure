"""Contrat des connecteurs d'action.

Un connecteur est le **seul** endroit du code qui produit un effet de bord sur le monde
extérieur (WAF, EDR, IAM, ticket…). Cette contrainte est volontaire : elle rend l'audit
d'un SOAR tractable, et elle permet de garantir par construction que :

* toute opération passe par ``call()``, qui gère le mode simulation, les erreurs et le
  journal d'exécution de façon uniforme ;
* une opération non supportée est refusée explicitement plutôt que silencieusement ignorée ;
* aucun connecteur ne peut lever d'exception vers le moteur : il retourne un résultat
  d'échec, qui sera audité comme tel.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ...core.logging_setup import get_logger

log = get_logger("actions.connector")

#: Opérations normalisées qu'un connecteur peut implémenter. Ajouter une opération ici est
#: un changement de contrat : les playbooks livrés s'y réfèrent par leur nom.
OPERATIONS = (
    "block_ip",
    "unblock_ip",
    "rate_limit",
    "remove_rate_limit",
    "quarantine_file",
    "restore_file",
    "isolate_host",
    "unisolate_host",
    "revoke_session",
    "rotate_secret",
    "patch_dependency",
    "harden_endpoint",
    "open_ticket",
    "close_ticket",
    "notify",
)


@dataclass(slots=True)
class ConnectorResult:
    """Résultat d'une opération de connecteur."""

    ok: bool
    operation: str = ""
    connector: str = ""
    detail: str = ""
    simulated: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0
    #: Jeton opaque permettant l'annulation (identifiant d'entrée, d'IP bloquée…).
    rollback_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "connector": self.connector,
            "operation": self.operation,
            "detail": self.detail,
            "simulated": self.simulated,
            "data": self.data,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "rollback_token": self.rollback_token,
        }


class ConnectorNotConfiguredError(RuntimeError):
    """Le connecteur est déclaré mais ses paramètres sont incomplets."""


class OperationNotSupportedError(RuntimeError):
    """L'opération n'est pas supportée par ce connecteur."""


class Connector(ABC):
    """Base des connecteurs.

    Une sous-classe implémente ``op_<operation>`` pour chaque opération supportée et
    déclare ``capabilities``. Le mode simulation est traité par la classe de base : une
    sous-classe n'a donc jamais à « faire semblant ».
    """

    #: Nom technique du pilote (``simulation``, ``nginx-local``, ``http-webhook``…).
    driver: str = "abstract"

    def __init__(self, settings: dict[str, Any] | None = None, *, dry_run: bool = True) -> None:
        self.settings = settings or {}
        self.dry_run = dry_run
        self.calls = 0
        self.failures = 0

    # ----------------------------------------------------------------------------------

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[str]:
        """Opérations supportées par ce connecteur."""

    @property
    def description(self) -> str:
        return f"{self.driver} ({len(self.capabilities)} opérations)"

    def supports(self, operation: str) -> bool:
        return operation in self.capabilities

    # ----------------------------------------------------------------------------------

    def call(self, operation: str, params: dict[str, Any] | None = None) -> ConnectorResult:
        """Point d'entrée unique. Ne lève jamais : retourne un résultat d'échec."""
        params = dict(params or {})
        started = time.perf_counter()
        self.calls += 1

        if not self.supports(operation):
            self.failures += 1
            return ConnectorResult(
                ok=False,
                operation=operation,
                connector=self.driver,
                error=f"opération '{operation}' non supportée par le connecteur '{self.driver}'",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        if self.dry_run:
            # Mode simulation : AUCUN effet de bord, mais un résultat honnête et exploitable.
            return ConnectorResult(
                ok=True,
                operation=operation,
                connector=self.driver,
                detail=f"[simulation] {operation} n'a pas été appliqué (dry-run actif)",
                simulated=True,
                data={"params_echo": redact_params(params)},
                duration_ms=(time.perf_counter() - started) * 1000,
                rollback_token=None,
            )

        try:
            handler = getattr(self, f"op_{operation}", None)
            if handler is None:
                raise OperationNotSupportedError(operation)
            result = handler(params)
        except ConnectorNotConfiguredError as exc:
            self.failures += 1
            return ConnectorResult(
                ok=False,
                operation=operation,
                connector=self.driver,
                error=f"connecteur non configuré: {exc}",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - un connecteur ne casse jamais le moteur
            self.failures += 1
            log.error(
                "échec d'une opération de connecteur",
                extra={"connector": self.driver, "operation": operation, "error": str(exc)},
            )
            return ConnectorResult(
                ok=False,
                operation=operation,
                connector=self.driver,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        result.operation = operation
        result.connector = self.driver
        result.duration_ms = (time.perf_counter() - started) * 1000
        if not result.ok:
            self.failures += 1
        return result

    # ----------------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "driver": self.driver,
            "dry_run": self.dry_run,
            "calls": self.calls,
            "failures": self.failures,
            "capabilities": sorted(self.capabilities),
        }


#: Clés dont la valeur ne doit jamais apparaître dans un journal ou un rapport.
_SENSITIVE_KEYS = ("token", "secret", "password", "api_key", "apikey", "authorization", "key")


def redact_params(payload: dict[str, Any]) -> dict[str, Any]:
    """Masque les valeurs sensibles d'un dictionnaire de paramètres (récursif)."""
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if any(marker in key.lower() for marker in _SENSITIVE_KEYS):
            redacted[key] = "<redacted>"
        elif isinstance(value, dict):
            redacted[key] = redact_params(value)
        else:
            redacted[key] = value
    return redacted


__all__ = [
    "OPERATIONS",
    "Connector",
    "ConnectorNotConfiguredError",
    "ConnectorResult",
    "OperationNotSupportedError",
    "redact_params",
]
