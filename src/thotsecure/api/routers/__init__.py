"""Routeurs de l'API v1."""

from __future__ import annotations

from . import actions, events, findings, health, security, stream, tenants

#: Ordre d'enregistrement : les routeurs sans préfixe dynamique d'abord.
ALL_ROUTERS = (
    health.router,
    stream.router,
    tenants.router,
    events.router,
    findings.router,
    actions.router,
    security.router,
)

__all__ = [
    "ALL_ROUTERS",
    "actions",
    "events",
    "findings",
    "health",
    "security",
    "stream",
    "tenants",
]
