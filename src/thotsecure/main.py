"""Application FastAPI : assemblage, intergiciels, cycle de vie.

``uvicorn thotsecure.main:app`` démarre le service complet. L'application peut aussi être
construite avec une configuration injectée (``create_app(settings)``), ce qui est utilisé par
les tests et par un déploiement embarqué.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __license__, __version__
from .api.errors import register_exception_handlers
from .api.routers import ALL_ROUTERS
from .api.ws import ConnectionManager
from .core.config import Settings, get_settings
from .core.logging_setup import configure_logging, get_logger, new_request_id
from .core.util import utcnow
from .service import Service, build_service
from .ui.routes import STATIC_DIR, build_ui_router

log = get_logger("main")

#: Taille maximale du corps d'une requête (protection anti-épuisement mémoire).
MAX_BODY_BYTES = 8 * 1024 * 1024


def create_app(settings: Settings | None = None, *, service: Service | None = None) -> FastAPI:
    """Construit l'application FastAPI et son service."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    application = FastAPI(
        title="Thot Secure",
        description=(
            "SOAR/CSPM **défensif** : collecte, détection, scoring de risque, décision "
            "*policy-as-code* et contre-mesures **réversibles et auditées**.\n\n"
            "⚠️ Aucune capacité offensive : pas de scan agressif, pas d'exploitation, "
            "pas de déni de service, pas de riposte.\n\n"
            "Par défaut, le mode simulation est **actif** (`THOT_DRY_RUN=true`) et les "
            "connecteurs non configurés n'ont aucun effet réel."
        ),
        version=__version__,
        license_info={"name": __license__, "url": "https://www.apache.org/licenses/LICENSE-2.0"},
        contact={"name": "Thot Secure", "url": "https://thotsecure.dev"},
        openapi_tags=[
            {"name": "santé", "description": "Sondes, version, métriques Prometheus."},
            {"name": "tenants", "description": "Tenants, clés API, périmètre déclaré."},
            {"name": "événements", "description": "Ingestion et consultation des événements."},
            {
                "name": "findings",
                "description": "Qualification et rapports (md, html, sarif, cef).",
            },
            {
                "name": "actions",
                "description": "Playbooks : planification, approbation, exécution, rollback.",
            },
            {
                "name": "détection et configuration",
                "description": "Règles, politiques, audit, collecteurs.",
            },
            {"name": "flux temps réel", "description": "WebSocket temps réel."},
        ],
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    application.state.service = service
    application.state.streams = ConnectionManager()
    application.state.settings = settings
    application.state.started_at = utcnow()

    _register_middleware(application, settings)
    register_exception_handlers(application)
    for router in ALL_ROUTERS:
        application.include_router(router)
    application.include_router(build_ui_router())

    if STATIC_DIR.is_dir():
        application.mount("/ui/static", StaticFiles(directory=str(STATIC_DIR)), name="ui-static")

    _register_lifespan(application, settings, service)
    return application


# --------------------------------------------------------------------------------------


def _register_middleware(application: FastAPI, settings: Settings) -> None:
    if settings.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["X-API-Key", "Content-Type", "Authorization"],
        )

    @application.middleware("http")
    async def observability(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Identifiant de requête, mesure de latence, comptage par statut, taille bornée."""
        request_id = request.headers.get("x-request-id") or new_request_id()
        request.state.request_id = request_id

        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "payload_too_large",
                        "message": f"corps de requête supérieur à {MAX_BODY_BYTES} octets",
                        "details": {"max_bytes": MAX_BODY_BYTES},
                    }
                },
            )

        started = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - started

        service: Service | None = getattr(request.app.state, "service", None)
        if service is not None:
            route = request.scope.get("route")
            route_name = getattr(route, "path", request.url.path)
            service.metrics.inc(
                "thotsecure_api_requests_total",
                method=request.method,
                route=route_name,
                status=str(response.status_code),
            )
            service.metrics.observe(
                "thotsecure_api_request_seconds",
                duration,
                method=request.method,
                route=route_name,
            )

        response.headers["X-Request-Id"] = request_id
        # En-têtes de sûreté : l'API ne doit pas être encadrable ni indexable.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


def _register_lifespan(application: FastAPI, settings: Settings, injected: Service | None) -> None:
    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        service = injected or build_service(settings)
        app.state.service = service

        # Diffusion temps réel : les actions signalent leurs changements d'état.
        service.actions.on_change = lambda action, event: app.state.streams.publish_action(
            action, event
        )

        await service.start()
        forward_task = asyncio.create_task(
            _forward_bus_to_streams(service, app.state.streams), name="thotsecure-ws-forward"
        )

        for warning in settings.safety_warnings():
            log.warning(warning)
        log.info(
            "Thot Secure prêt",
            extra={
                "env": settings.env,
                "dry_run": settings.dry_run,
                "autonomy": settings.autonomy,
                "console": "/",
                "drapeaux": "/docs",
            },
        )
        try:
            yield
        finally:
            forward_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await forward_task
            await service.stop()
            service.close()

    application.router.lifespan_context = lifespan


async def _forward_bus_to_streams(service: Service, streams: ConnectionManager) -> None:
    """Relaye les événements du bus vers les clients WebSocket.

    Le pipeline consomme le bus de son côté ; les abonnés sont indépendants (diffusion en
    éventail), donc l'ajout de la console ne perturbe pas le traitement.
    """
    queue = service.bus.subscribe(maxsize=1000)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
            except TimeoutError:
                continue
            if streams.client_count():
                streams.publish_event(event)
                service.metrics.set("thotsecure_ws_clients", streams.client_count())
    except asyncio.CancelledError:
        raise
    finally:
        service.bus.unsubscribe(queue)


app = create_app()


__all__ = ["MAX_BODY_BYTES", "app", "create_app"]
