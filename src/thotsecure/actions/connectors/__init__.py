"""Connecteurs d'action : simulation, Nginx local, quarantaine, ticketing, webhook."""

from __future__ import annotations

from .base import (
    OPERATIONS,
    Connector,
    ConnectorNotConfiguredError,
    ConnectorResult,
    OperationNotSupportedError,
)
from .http_webhook import HttpWebhookConnector
from .local import LocalQuarantineConnector, LocalTicketConnector, NginxLocalConnector
from .simulation import SimulationConnector

__all__ = [
    "OPERATIONS",
    "Connector",
    "ConnectorNotConfiguredError",
    "ConnectorResult",
    "HttpWebhookConnector",
    "LocalQuarantineConnector",
    "LocalTicketConnector",
    "NginxLocalConnector",
    "OperationNotSupportedError",
    "SimulationConnector",
]
