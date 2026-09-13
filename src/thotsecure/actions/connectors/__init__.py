"""Connecteurs d'action : simulation, Nginx local, quarantaine, ticketing, webhook, natifs.

Le mode simulation reste le pilote **par défaut** de tout le produit : brancher un
connecteur natif est une décision explicite, prise dans ``config/connectors.yaml``.
"""

from __future__ import annotations

from .aws_waf import AwsWafConnector
from .base import (
    OPERATIONS,
    Connector,
    ConnectorNotConfiguredError,
    ConnectorResult,
    OperationNotSupportedError,
)
from .cloudflare import CloudflareConnector
from .http_client import HttpClient, HttpResult
from .http_webhook import HttpWebhookConnector
from .local import LocalQuarantineConnector, LocalTicketConnector, NginxLocalConnector
from .notifications import GithubIssueConnector, SlackConnector
from .simulation import SimulationConnector

__all__ = [
    "OPERATIONS",
    "AwsWafConnector",
    "CloudflareConnector",
    "Connector",
    "ConnectorNotConfiguredError",
    "ConnectorResult",
    "GithubIssueConnector",
    "HttpClient",
    "HttpResult",
    "HttpWebhookConnector",
    "LocalQuarantineConnector",
    "LocalTicketConnector",
    "NginxLocalConnector",
    "OperationNotSupportedError",
    "SimulationConnector",
    "SlackConnector",
]
