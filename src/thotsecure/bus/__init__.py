"""Fabrique de bus et exports publics."""

from __future__ import annotations

from ..core.config import Settings
from ..core.logging_setup import get_logger
from ..storage import StoreProtocol
from .base import DEFAULT_QUEUE_SIZE, EventBus
from .memory import MemoryBus
from .nats import NatsBus
from .sqlite_bus import SqliteBus

log = get_logger("bus.factory")


def create_bus(settings: Settings, store: StoreProtocol | None = None) -> EventBus:
    """Instancie le bus configuré.

    Le repli est explicite : si un bus durable est demandé sans les moyens de l'obtenir, on
    le signale fortement plutôt que d'échouer au démarrage (un service de sécurité qui ne
    démarre pas ne protège rien).
    """
    queue_size = settings.bus_queue_size
    if settings.bus == "nats":
        if store is None:
            log.warning("bus NATS sans stockage : pas de rejeu possible au redémarrage")
        return NatsBus(
            settings.nats_url,
            subject=f"{settings.bus_subject_prefix}",
            store=store,
            queue_size=queue_size,
        )
    if settings.bus == "sqlite":
        if store is None:
            log.error("bus SQLite demandé sans stockage : bascule sur le bus mémoire")
            return MemoryBus(queue_size=queue_size)
        return SqliteBus(store, queue_size=queue_size)
    return MemoryBus(queue_size=queue_size)


__all__ = [
    "DEFAULT_QUEUE_SIZE",
    "EventBus",
    "MemoryBus",
    "NatsBus",
    "SqliteBus",
    "create_bus",
]
