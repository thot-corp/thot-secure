"""Bus SQLite : diffusion locale **plus** reprise sur redémarrage.

Chaque événement est déjà persisté dans la table ``events`` (colonne ``processed``). Ce bus
rejoue au démarrage les événements jamais traités, et interroge périodiquement la base pour
récupérer ceux déposés par un autre processus partageant le même fichier SQLite.

C'est le mode recommandé pour un déploiement mono-nœud sérieux : durabilité sans service
externe, et aucune perte silencieuse après un redémarrage ou un crash du moteur.
"""

from __future__ import annotations

import asyncio
import contextlib

from ..core.logging_setup import get_logger
from ..core.models import Event
from ..storage import StoreProtocol
from .base import DEFAULT_QUEUE_SIZE, EventBus

log = get_logger("bus.sqlite")


class SqliteBus(EventBus):
    """Durabilité par la base, diffusion par la mémoire."""

    name = "sqlite"

    def __init__(
        self,
        store: StoreProtocol,
        *,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        poll_interval: float = 2.0,
    ) -> None:
        super().__init__(queue_size=queue_size)
        self.store = store
        self.poll_interval = poll_interval
        self._replayed = 0
        self._seen: set[str] = set()
        self._poll_task: asyncio.Task[None] | None = None
        self._run_polling = True

    async def start(self) -> None:
        await super().start()
        self._replayed = await self.replay_pending()
        if self._run_polling:
            self._poll_task = asyncio.create_task(self._poll_loop(), name="thotsecure-bus-poll")

    async def stop(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
            self._poll_task = None
        await super().stop()

    async def publish(self, event: Event) -> None:
        """Diffuse immédiatement. La persistance est la responsabilité de l'appelant
        (``Pipeline.ingest`` écrit d'abord, publie ensuite) : ainsi un échec d'écriture
        n'entraîne jamais un traitement sans trace."""
        self.published += 1
        self.received += 1
        self._seen.add(event.event_id)
        self._dispatch(event)

    async def replay_pending(self, *, limit: int = 1000) -> int:
        """Rejoue les événements jamais traités (démarrage ou reprise après incident)."""
        try:
            pending = self.store.pending_events(limit=limit)
        except Exception as exc:
            self.errors += 1
            log.error("reprise impossible", extra={"error": str(exc)})
            return 0
        for event in pending:
            if event.event_id in self._seen:
                continue
            self._seen.add(event.event_id)
            self.received += 1
            self._dispatch(event)
        if pending:
            log.warning(
                "événements non traités rejoués au démarrage",
                extra={"count": len(pending), "bus": self.name},
            )
        return len(pending)

    async def _poll_loop(self) -> None:
        """Détecte les événements déposés par un autre processus (ingestion multi-nœuds)."""
        while True:
            try:
                await asyncio.sleep(self.poll_interval)
                pending = self.store.pending_events(limit=500)
                fresh = [event for event in pending if event.event_id not in self._seen]
                for event in fresh:
                    self._seen.add(event.event_id)
                    self.received += 1
                    self._dispatch(event)
                if fresh:
                    log.debug(
                        "nouveaux événements récupérés par sondage", extra={"count": len(fresh)}
                    )
                # Bornage mémoire : au-delà de 50 000 identifiants mémorisés, on repart de
                # l'état courant de la base (les événements déjà traités ne sont plus listés).
                if len(self._seen) > 50_000:
                    self._seen = {event.event_id for event in self.store.pending_events(limit=1000)}
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.errors += 1
                log.error("erreur de sondage du bus", extra={"error": str(exc)})
                await asyncio.sleep(min(self.poll_interval * 5, 30))

    def stats(self) -> dict:
        return {**super().stats(), "replayed": self._replayed, "poll_interval": self.poll_interval}


__all__ = ["SqliteBus"]
