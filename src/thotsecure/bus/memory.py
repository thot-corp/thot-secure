"""Bus en mémoire : diffusion locale, latence minimale, durabilité nulle.

Suffisant pour un déploiement mono-processus (poste de dev, MSP avec un seul nœud) et pour
les tests. Les événements non traités au moment d'un arrêt sont perdus — d'où l'avertissement
au démarrage quand ``THOT_BUS=memory`` en environnement non-dev.
"""

from __future__ import annotations

from ..core.models import Event
from .base import DEFAULT_QUEUE_SIZE, EventBus


class MemoryBus(EventBus):
    """Diffusion synchrone vers les abonnés locaux."""

    name = "memory"

    def __init__(self, *, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        super().__init__(queue_size=queue_size)

    async def publish(self, event: Event) -> None:
        self.published += 1
        self.received += 1
        self._dispatch(event)


__all__ = ["MemoryBus"]
