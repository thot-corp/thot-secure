"""Contrat du bus d'événements.

Le pipeline d'Thot Secure est découplé de la source des événements : un collecteur publie, le
moteur consomme. Trois implémentations interchangeables (``memory``, ``sqlite``, ``nats``)
partagent cette interface, ce qui permet de démarrer en un seul processus puis de passer à
une architecture distribuée sans toucher au moteur.

Propriété importante : **un bus ne perd jamais silencieusement un événement**. Soit il le
livre, soit il incrémente un compteur de perte exposé par ``stats()`` (visible dans
``/metrics``). Une perte invisible est un angle mort de détection.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from ..core.logging_setup import get_logger
from ..core.models import Event

log = get_logger("bus")

#: Taille par défaut de la file d'un abonné. Au-delà, on écarte le plus ancien : mieux vaut
#: perdre un événement ancien que bloquer l'ingestion temps réel.
DEFAULT_QUEUE_SIZE = 5000


class EventBus(ABC):
    """Interface commune des bus."""

    name: str = "abstract"

    def __init__(self, *, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self.queue_size = queue_size
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._started = False
        self.published = 0
        self.dropped = 0
        self.delivered = 0
        self.received = 0
        self.errors = 0

    # -- cycle de vie -------------------------------------------------------------------

    async def start(self) -> None:
        self._started = True
        log.info("bus démarré", extra={"bus": self.name, "queue_size": self.queue_size})

    async def stop(self) -> None:
        self._started = False
        for queue in list(self._subscribers):
            self._subscribers.discard(queue)
        log.info("bus arrêté", extra={"bus": self.name, "delivered": self.delivered})

    @property
    def started(self) -> bool:
        return self._started

    # -- publication / abonnement -------------------------------------------------------

    @abstractmethod
    async def publish(self, event: Event) -> None:
        """Publie un événement normalisé."""

    def subscribe(self, *, maxsize: int | None = None) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize or self.queue_size)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(queue)

    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # -- diffusion locale --------------------------------------------------------------

    def _dispatch(self, event: Event) -> None:
        """Diffuse vers les abonnés locaux. File pleine ⇒ on écarte le plus ancien."""
        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                    self.dropped += 1
                except asyncio.QueueEmpty:  # pragma: no cover - course bénigne
                    pass
            try:
                queue.put_nowait(event)
                self.delivered += 1
            except asyncio.QueueFull:  # pragma: no cover
                self.dropped += 1

    async def drain(self, timeout: float = 1.0) -> None:
        """Laisse le temps aux consommateurs de vider les files (arrêt propre, tests)."""
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if all(queue.empty() for queue in self._subscribers):
                return
            await asyncio.sleep(0.01)

    # -- observabilité ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "bus": self.name,
            "started": self._started,
            "subscribers": len(self._subscribers),
            "published": self.published,
            "delivered": self.delivered,
            "received": self.received,
            "dropped": self.dropped,
            "errors": self.errors,
        }


__all__ = ["DEFAULT_QUEUE_SIZE", "EventBus"]
