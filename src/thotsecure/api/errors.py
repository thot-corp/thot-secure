"""Gestionnaires d'erreurs de l'API : réponses normalisées, fuites maîtrisées.

Format unique et stable (contrat §4.6) :

```json
{"error": {"code": "forbidden", "message": "…", "details": {}}}
```

Deux principes de sûreté :

* en environnement ``prod``, une erreur interne ne divulgue **jamais** de trace ni de détail
  d'implémentation (une trace Python peut contenir des chemins, des requêtes SQL, des secrets) ;
* toute erreur 5xx est journalisée avec un identifiant de requête, pour que l'exploitant
  puisse la retrouver sans qu'elle soit exposée au client.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..core.errors import ThotSecureError, RateLimitedError
from ..core.logging_setup import get_logger

log = get_logger("api.errors")


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "details": details or {}}},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Installe les gestionnaires d'erreurs sur l'application."""

    @app.exception_handler(ThotSecureError)
    async def handle_domain_error(request: Request, exc: ThotSecureError) -> JSONResponse:
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(exc.retry_after)
        if exc.http_status >= 500:
            log.error(
                "erreur applicative",
                extra={
                    "code": exc.code,
                    "path": request.url.path,
                    "request_id": getattr(request.state, "request_id", None),
                    "details": exc.details,
                },
            )
        else:
            log.info(
                "requête refusée",
                extra={
                    "code": exc.code,
                    "status": exc.http_status,
                    "path": request.url.path,
                    "request_id": getattr(request.state, "request_id", None),
                },
            )
        return error_response(exc.http_status, exc.code, exc.message, details=exc.details, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = {
            "fields": [
                {
                    "location": ".".join(str(part) for part in error.get("loc", ())),
                    "message": error.get("msg", ""),
                    "type": error.get("type", ""),
                }
                for error in exc.errors()[:20]
            ]
        }
        return error_response(422, "validation_error", "charge utile invalide", details=details)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        log.error(
            "erreur non gérée",
            extra={
                "path": request.url.path,
                "request_id": request_id,
                "error": str(exc),
                "type": type(exc).__name__,
            },
            exc_info=True,
        )
        service = getattr(request.app.state, "service", None)
        is_prod = bool(service and service.settings.env == "prod")
        return error_response(
            500,
            "internal_error",
            (
                "erreur interne : consultez les journaux du service avec l'identifiant de requête"
                if is_prod
                else f"{type(exc).__name__}: {exc}"
            ),
            details={"request_id": request_id} if request_id else {},
        )


__all__ = ["error_response", "register_exception_handlers"]
