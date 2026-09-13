"""Diffusion temps réel vers la console (WebSocket).

Le gestionnaire de connexions est volontairement simple et **borné** :

* un nombre maximal de clients (un flux temps réel ne doit pas devenir un vecteur de déni de
  service : chaque client coûte de la mémoire et de la bande passante) ;
* une file par client avec **écartement du plus ancien** : un client lent ne bloque jamais le
  pipeline ;
* un battement de cœur périodique, pour que les proxys ne coupent pas une connexion inactive.

Les événements diffusés sont filtrés par tenant : un client ne reçoit jamais les données d'un
autre tenant, même si le serveur en traite plusieurs simultanément.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..core.logging_setup import get_logger
from ..core.util import iso_z, utcnow

log = get_logger("api.ws")

#: Nombre maximal de clients simultanés.
MAX_CLIENTS = 200

#: Taille de la file d'un client (au-delà, l'événement le plus ancien est écarté).
CLIENT_QUEUE_SIZE = 200

#: Intervalle du battement de cœur.
HEARTBEAT_SECONDS = 25.0


@dataclass
class Client:
    """Client WebSocket abonné."""

    client_id: str
    tenant_id: str
    queue: asyncio.Queue[dict[str, Any]]
    connected_at: Any = field(default_factory=utcnow)
    dropped: int = 0

    def push(self, frame: dict[str, Any]) -> None:
        if self.queue.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                self.queue.get_nowait()
                self.dropped += 1
        with contextlib.suppress(asyncio.QueueFull):
            self.queue.put_nowait(frame)


class ConnectionManager:
    """Registre des clients WebSocket, avec diffusion par tenant."""

    def __init__(self, *, max_clients: int = MAX_CLIENTS) -> None:
        self.max_clients = max_clients
        self._clients: dict[str, Client] = {}
        self._lock = asyncio.Lock()
        self.broadcast_total = 0
        self.dropped_total = 0

    # ----------------------------------------------------------------------------------

    async def connect(self, client_id: str, tenant_id: str) -> Client | None:
        """Enregistre un client. Retourne ``None`` si la limite est atteinte."""
        async with self._lock:
            if len(self._clients) >= self.max_clients:
                log.warning(
                    "connexion WebSocket refusée : limite atteinte",
                    extra={"clients": len(self._clients), "max": self.max_clients},
                )
                return None
            client = Client(
                client_id=client_id,
                tenant_id=tenant_id,
                queue=asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE),
            )
            self._clients[client_id] = client
        log.info(
            "client WebSocket connecté",
            extra={"client_id": client_id, "tenant_id": tenant_id, "clients": len(self._clients)},
        )
        return client

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            client = self._clients.pop(client_id, None)
        if client is not None:
            log.info(
                "client WebSocket déconnecté",
                extra={"client_id": client_id, "dropped": client.dropped},
            )

    def client_count(self) -> int:
        return len(self._clients)

    # ----------------------------------------------------------------------------------

    def broadcast(self, frame: dict[str, Any], *, tenant_id: str | None = None) -> int:
        """Diffuse une trame. Retourne le nombre de clients servis."""
        delivered = 0
        for client in list(self._clients.values()):
            if tenant_id is not None and client.tenant_id not in {tenant_id, "*"}:
                continue
            client.push(frame)
            delivered += 1
        self.broadcast_total += 1
        self.dropped_total = sum(client.dropped for client in self._clients.values())
        return delivered

    def publish_event(self, event: Any) -> None:
        """Diffuse un événement du pipeline."""
        self.broadcast(
            {
                "type": "event",
                "ts": iso_z(utcnow()),
                "data": {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "src_ip": event.labels.get("src_ip"),
                    "path": event.labels.get("path"),
                    "check": event.labels.get("check"),
                    "source": event.source.type,
                },
            },
            tenant_id=event.tenant_id,
        )

    def publish_finding(self, finding: Any, *, event: str = "created") -> None:
        self.broadcast(
            {
                "type": "finding",
                "event": event,
                "ts": iso_z(utcnow()),
                "data": {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "status": finding.status,
                    "title": finding.title,
                },
            },
            tenant_id=finding.tenant_id,
        )

    def publish_action(self, action: Any, event: str) -> None:
        self.broadcast(
            {
                "type": "action",
                "event": event,
                "ts": iso_z(utcnow()),
                "data": {
                    "action_id": action.action_id,
                    "playbook": action.playbook,
                    "status": action.status,
                    "dry_run": action.dry_run,
                    "mode": action.mode,
                    "target": str(action.target),
                    "finding_id": action.finding_id,
                },
            },
            tenant_id=action.tenant_id,
        )

    def publish_audit(self, record: Any) -> None:
        self.broadcast(
            {
                "type": "audit",
                "ts": iso_z(utcnow()),
                "data": {
                    "seq": record.seq,
                    "action": record.action,
                    "actor": record.actor,
                    "target": record.target,
                },
            },
            tenant_id=record.tenant_id,
        )

    def heartbeat(self) -> None:
        self.broadcast(
            {"type": "heartbeat", "ts": iso_z(utcnow()), "data": {"clients": self.client_count()}}
        )

    def stats(self) -> dict[str, Any]:
        return {
            "clients": self.client_count(),
            "max_clients": self.max_clients,
            "broadcasts": self.broadcast_total,
            "dropped": self.dropped_total,
        }


async def stream_frames(client: Client, *, heartbeat_seconds: float = HEARTBEAT_SECONDS):
    """Générateur de trames pour un client (file + battement de cœur)."""
    while True:
        try:
            frame = await asyncio.wait_for(client.queue.get(), timeout=heartbeat_seconds)
        except TimeoutError:
            yield json.dumps({"type": "heartbeat", "ts": iso_z(utcnow()), "data": {"quiet": True}})
            continue
        yield json.dumps(frame, ensure_ascii=False, default=str)


__all__ = [
    "CLIENT_QUEUE_SIZE",
    "HEARTBEAT_SECONDS",
    "MAX_CLIENTS",
    "Client",
    "ConnectionManager",
    "stream_frames",
]
