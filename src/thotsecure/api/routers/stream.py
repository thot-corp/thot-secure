"""Flux temps réel (WebSocket) : événements, findings, actions et audit.

Un client ne reçoit que les données de son tenant. L'authentification se fait par
``?api_key=`` (un navigateur ne peut pas positionner d'en-tête sur une connexion WebSocket) ou
par jeton de session de la console.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ...core.errors import AuthenticationError
from ...core.logging_setup import get_logger
from ...core.util import iso_z, utcnow
from ..ws import ConnectionManager, stream_frames

log = get_logger("api.stream")

router = APIRouter(prefix="/api/v1/ws", tags=["flux temps réel"])


@router.websocket("/stream")
async def stream(
    websocket: WebSocket,
    api_key: str | None = Query(default=None),
    token: str | None = Query(default=None),
    tenant_id: str | None = Query(default=None),
    types: str | None = Query(default=None, description="Types à recevoir, séparés par des virgules"),
) -> None:
    """Flux d'événements en temps réel."""
    service = getattr(websocket.app.state, "service", None)
    if service is None:  # pragma: no cover
        await websocket.close(code=1011, reason="service indisponible")
        return

    principal = None
    if api_key:
        try:
            principal = service.keys.authenticate(api_key)
        except AuthenticationError as exc:
            await websocket.close(code=1008, reason=exc.message[:120])
            return
    elif token:
        principal = service.keys.verify_session(token)
        if principal is None:
            await websocket.close(code=1008, reason="jeton de session invalide ou expiré")
            return
    if principal is None:
        await websocket.close(code=1008, reason="authentification requise (api_key ou token)")
        return

    # Portée : un client non-admin ne peut pas écouter un autre tenant.
    target_tenant = principal.tenant_id
    if tenant_id and tenant_id != principal.tenant_id:
        if "admin:tenants" not in principal.capabilities:
            await websocket.close(code=1008, reason="accès à un autre tenant refusé")
            return
        target_tenant = tenant_id
    if "read:events" not in principal.capabilities:
        await websocket.close(code=1008, reason="capacité read:events requise")
        return

    manager: ConnectionManager = websocket.app.state.streams
    client_id = uuid.uuid4().hex[:12]
    client = await manager.connect(client_id, target_tenant)
    if client is None:
        await websocket.close(code=1013, reason="trop de clients connectés")
        return

    allowed_types = {item.strip() for item in (types or "").split(",") if item.strip()}
    await websocket.accept()
    await websocket.send_json(
        {
            "type": "hello",
            "ts": iso_z(utcnow()),
            "data": {
                "client_id": client_id,
                "tenant_id": target_tenant,
                "role": principal.role,
                "types": sorted(allowed_types) or ["event", "finding", "action", "audit", "heartbeat"],
            },
        }
    )

    async def forward() -> None:
        async for frame in stream_frames(client):
            await websocket.send_text(frame)

    async def receive() -> None:
        """Lit les messages du client (ping applicatif). On ne traite aucune commande :
        un flux temps réel n'est pas un canal de commande."""
        while True:
            message = await websocket.receive_text()
            if message.strip().lower() in {"ping", '"ping"'}:
                await websocket.send_json({"type": "pong", "ts": iso_z(utcnow()), "data": {}})

    tasks = [asyncio.create_task(forward()), asyncio.create_task(receive())]
    try:
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001 - une déconnexion brutale est normale
        log.debug("flux WebSocket interrompu", extra={"client_id": client_id, "error": str(exc)})
    finally:
        for task in tasks:
            task.cancel()
        await manager.disconnect(client_id)
        try:
            await websocket.close()
        except RuntimeError:  # pragma: no cover - connexion déjà fermée
            pass


@router.get("/clients", summary="État des connexions temps réel")
async def ws_clients(websocket: WebSocket) -> None:  # pragma: no cover - documentation
    await websocket.close(code=1008, reason="utilisez /api/v1/auth/whoami et /metrics")


__all__ = ["router"]


def connection_stats(app: Any) -> dict[str, Any]:
    manager: ConnectionManager | None = getattr(app.state, "streams", None)
    return manager.stats() if manager else {"clients": 0}


__all__ = ["connection_stats", "router"]
