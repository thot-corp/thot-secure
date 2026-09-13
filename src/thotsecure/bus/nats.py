"""Bus NATS — client implémenté **en stdlib** (aucune dépendance ``nats-py``).

Le protocole NATS côté client est un protocole texte simple (``INFO``, ``CONNECT``,
``PUB``, ``SUB``, ``MSG``, ``PING``/``PONG``). L'implémenter ici évite une dépendance
supplémentaire dans l'image de production et garde le cœur d'Thot Secure installable hors
ligne, ce qui compte pour les déploiements en environnement cloisonné.

Comportement en cas d'échec : le bus ne fait **jamais** échouer l'ingestion. Si la connexion
NATS est indisponible, il bascule sur une diffusion locale et le signale (``degraded: true``)
afin que l'exploitant le voie dans ``/metrics`` et dans ``/readyz``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
from typing import Any
from urllib.parse import urlparse

from ..core.errors import ConfigError
from ..core.logging_setup import get_logger
from ..core.models import Event
from ..storage.store import Store
from .base import DEFAULT_QUEUE_SIZE, EventBus
from .memory import MemoryBus

log = get_logger("bus.nats")

_CRLF = b"\r\n"
_DEFAULT_SUBJECT = "thotsecure.events"


class NatsBus(EventBus):
    """Publication/abonnement NATS avec repli local automatique."""

    name = "nats"

    def __init__(
        self,
        url: str,
        *,
        subject: str = _DEFAULT_SUBJECT,
        store: Store | None = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        connect_timeout: float = 5.0,
        max_reconnect_attempts: int = 10,
    ) -> None:
        super().__init__(queue_size=queue_size)
        self.url = url
        self.subject = subject
        self.store = store
        self.connect_timeout = connect_timeout
        self.max_reconnect_attempts = max_reconnect_attempts

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._read_task: asyncio.Task[None] | None = None
        self._fallback = MemoryBus(queue_size=queue_size)
        self.degraded = False
        self.reconnect_attempts = 0

    # ----------------------------------------------------------------------------------
    # Cycle de vie
    # ----------------------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        try:
            await self._connect()
            self.degraded = False
            if self.store is not None:
                # Rejeu des événements non traités : NATS ne garantit pas la persistance
                # sans JetStream, la base reste la source de vérité.
                for event in self.store.pending_events(limit=1000):
                    self._dispatch(event)
        except Exception as exc:  # noqa: BLE001 - jamais bloquant
            self.degraded = True
            self.errors += 1
            log.error(
                "connexion NATS impossible : bascule en diffusion locale dégradée",
                extra={"url": self.url, "error": str(exc)},
            )

    async def stop(self) -> None:
        if self._read_task is not None:
            self._read_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._read_task
            self._read_task = None
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.write(b"UNSUB 1\r\n")
                await self._writer.drain()
                self._writer.close()
                with contextlib.suppress(Exception):
                    await self._writer.wait_closed()
            self._writer = None
        await super().stop()

    # ----------------------------------------------------------------------------------
    # Connexion
    # ----------------------------------------------------------------------------------

    async def _connect(self) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme not in {"nats", "tls"}:
            raise ConfigError(f"schéma NATS non supporté: {parsed.scheme}")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 4222
        use_tls = parsed.scheme == "tls"

        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=None),  # TLS géré par le proxy en MVP
            timeout=self.connect_timeout,
        )
        info_line = await asyncio.wait_for(self._reader.readline(), timeout=self.connect_timeout)
        info = _parse_info(info_line)
        if use_tls and not info.get("tls_required"):  # pragma: no cover - dépend du serveur
            log.warning("tls:// demandé mais le serveur n'exige pas TLS", extra={"url": self.url})

        connect_payload: dict[str, Any] = {
            "verbose": False,
            "pedantic": False,
            "lang": "python-thotsecure",
            "version": "0.1.0",
            "protocol": 1,
            "name": "thotsecure",
            "echo": False,
        }
        if parsed.username:
            connect_payload["user"] = parsed.username
            connect_payload["pass"] = parsed.password or ""
        if info.get("auth_required") and not parsed.username:
            raise ConfigError("le serveur NATS exige une authentification (THOT_NATS_URL)")
        self._send(f"CONNECT {json.dumps(connect_payload, separators=(',', ':'))}")
        self._send(f"SUB {self.subject} 1")
        self._send("PING")
        self._read_task = asyncio.create_task(self._read_loop(), name="thotsecure-nats-reader")
        log.info(
            "connecté à NATS",
            extra={"url": self.url, "subject": self.subject, "server": info.get("server_id", "?")},
        )

    def _send(self, command: str) -> None:
        if self._writer is None:
            raise RuntimeError("bus NATS non connecté")
        self._writer.write(command.encode("utf-8") + _CRLF)

    # ----------------------------------------------------------------------------------
    # Publication
    # ----------------------------------------------------------------------------------

    async def publish(self, event: Event) -> None:
        self.published += 1
        payload = event.model_dump_json().encode("utf-8")
        if self._writer is None or self.degraded:
            # Repli : l'événement est diffusé localement pour que le pipeline continue.
            if not self.degraded:
                self.degraded = True
                log.warning("NATS indisponible : diffusion locale")
            await self._fallback.publish(event)
            return
        try:
            self._send(f"PUB {self.subject} {len(payload)}")
            self._writer.write(payload + _CRLF)
            await self._writer.drain()
        except (ConnectionError, OSError, RuntimeError) as exc:
            self.errors += 1
            self.degraded = True
            log.error("échec de publication NATS, repli local", extra={"error": str(exc)})
            await self._fallback.publish(event)

    # ----------------------------------------------------------------------------------
    # Réception
    # ----------------------------------------------------------------------------------

    async def _read_loop(self) -> None:
        assert self._reader is not None
        reader = self._reader
        while True:
            try:
                line = await reader.readline()
                if not line:
                    raise ConnectionError("connexion NATS fermée par le serveur")
                command = line.strip()
                if command == b"PING":
                    self._send("PONG")
                    await self._drain()
                elif command.startswith(b"MSG "):
                    parts = command.split()
                    size = int(parts[-1])
                    body = await reader.readexactly(size + 2)
                    self._handle_message(body[:-2])
                elif command == b"+OK":
                    continue
                elif command.startswith(b"-ERR"):
                    self.errors += 1
                    log.error("erreur NATS", extra={"error": command.decode('utf-8', 'replace')})
                elif command.startswith(b"INFO"):
                    continue
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnexion gérée ci-dessous
                self.errors += 1
                log.error("flux NATS interrompu", extra={"error": str(exc)})
                await self._reconnect()

    async def _drain(self) -> None:
        if self._writer is not None:
            with contextlib.suppress(Exception):
                await self._writer.drain()

    def _handle_message(self, payload: bytes) -> None:
        event = parse_event(payload)
        if event is None:
            self.errors += 1
            return
        self.received += 1
        self._dispatch(event)

    async def _reconnect(self) -> None:
        """Reconnexion avec backoff exponentiel borné (jamais de boucle serrée)."""
        while self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            delay = min(2**self.reconnect_attempts * 0.2, 15.0) * (0.5 + random.random())  # noqa: S311
            log.warning(
                "tentative de reconnexion NATS",
                extra={"attempt": self.reconnect_attempts, "delay_s": round(delay, 2)},
            )
            await asyncio.sleep(delay)
            try:
                await self._connect()
                self.degraded = False
                self.reconnect_attempts = 0
                log.info("reconnexion NATS réussie")
                return
            except Exception as exc:  # noqa: BLE001
                log.error("reconnexion échouée", extra={"error": str(exc)})
        self.degraded = True
        log.error("NATS abandonné après plusieurs tentatives : mode dégradé permanent")

    def stats(self) -> dict[str, Any]:
        return {**super().stats(), "degraded": self.degraded, "subject": self.subject}


def _parse_info(line: bytes) -> dict[str, Any]:
    """Extrait l'objet JSON de la ligne ``INFO {...}``."""
    text = line.decode("utf-8", "replace").strip()
    if not text.startswith("INFO"):
        return {}
    try:
        return json.loads(text[4:].strip() or "{}")
    except ValueError:
        return {}


def parse_event(payload: bytes | str) -> Event | None:
    """Désérialise un événement reçu du bus. Retourne ``None`` si la charge est invalide."""
    try:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        return Event.model_validate_json(payload)
    except Exception:  # noqa: BLE001 - un message corrompu ne doit pas tuer le consommateur
        log.warning("message de bus ignoré (charge invalide)", extra={"size": len(payload)})
        return None


__all__ = ["NatsBus", "parse_event"]
