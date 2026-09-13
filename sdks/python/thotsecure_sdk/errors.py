"""Hiérarchie d'exceptions du SDK Thot Secure.

Le contrat d'interface (docs/architecture/api-contract.md, §4.6) normalise les erreurs
ainsi ::

    {"error": {"code": "forbidden", "message": "...", "details": {...}}}

avec les codes ``validation_error`` (400), ``unauthenticated`` (401), ``forbidden`` (403),
``not_found`` (404), ``conflict`` (409), ``unprocessable`` (422), ``rate_limited`` (429) et
``internal_error`` (500).

Règle de sécurité : aucune exception ne doit jamais contenir la clé API. Les URL sont
systématiquement passées par :func:`redact_url` avant d'être attachées à une erreur, car le
WebSocket transporte la clé en paramètre de requête.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    "AuthenticationError",
    "ConflictError",
    "NotFoundError",
    "PermissionDeniedError",
    "RateLimitedError",
    "ServerError",
    "ThotSecureError",
    "TransportError",
    "ValidationError",
    "WebSocketError",
    "error_from_response",
    "error_from_status",
    "redact_url",
]


#: Paramètres de requête qui ne doivent jamais apparaître dans un message d'erreur.
_SENSITIVE_QUERY_PARAMS = ("api_key", "apikey", "token", "access_token", "key", "password")


def redact_url(url: str | None) -> str | None:
    """Retourne *url* avec les paramètres sensibles masqués.

    ``https://h/api/v1/ws/stream?api_key=ao_secret&tenant_id=acme`` devient
    ``https://h/api/v1/ws/stream?api_key=***&tenant_id=acme``.
    """
    if not url:
        return url
    result = url
    for param in _SENSITIVE_QUERY_PARAMS:
        result = re.sub(
            rf"([?&]{re.escape(param)}=)[^&#\s]*",
            r"\1***",
            result,
            flags=re.IGNORECASE,
        )
    return result


class ThotSecureError(Exception):
    """Erreur de base du SDK Thot Secure.

    Attributs
    ---------
    message : message lisible (issu du serveur si disponible).
    code : code d'erreur du contrat (``forbidden``, ``rate_limited``, ...).
    status_code : code HTTP associé, ``None`` pour une erreur purement locale.
    details : dictionnaire ``details`` du contrat (jamais de secret).
    method / url : contexte de l'appel fautif (URL nettoyée par :func:`redact_url`).
    request_id : identifiant de corrélation éventuel renvoyé par le serveur.
    retryable : indique si un nouvel essai a du sens (utilisé par la couche transport).
    """

    code: str = "internal_error"
    status_code: int | None = None
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: Mapping[str, Any] | None = None,
        method: str | None = None,
        url: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.details: dict[str, Any] = dict(details) if details else {}
        self.method = method
        self.url = redact_url(url)
        self.request_id = request_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        parts = [self.message]
        meta = []
        if self.status_code is not None:
            meta.append(f"status={self.status_code}")
        if self.code:
            meta.append(f"code={self.code}")
        if self.method:
            meta.append("{} {}".format(self.method, self.url or ""))
        if self.request_id:
            meta.append(f"request_id={self.request_id}")
        if meta:
            parts.append("(" + ", ".join(meta) + ")")
        return " ".join(parts)


class TransportError(ThotSecureError):
    """Erreur réseau ou de transport (DNS, TLS, connexion coupée, timeout)."""

    code = "transport_error"
    retryable = True


class WebSocketError(TransportError):
    """Erreur de la couche WebSocket (handshake, trame invalide, connexion fermée)."""

    code = "websocket_error"


class AuthenticationError(ThotSecureError):
    """401 — clé API absente, inconnue ou révoquée."""

    code = "unauthenticated"
    status_code = 401


class PermissionDeniedError(ThotSecureError):
    """403 — la clé est valide mais ne porte pas la capacité requise."""

    code = "forbidden"
    status_code = 403


class NotFoundError(ThotSecureError):
    """404 — ressource inexistante ou appartenant à un autre tenant."""

    code = "not_found"
    status_code = 404


class ConflictError(ThotSecureError):
    """409 — conflit d'état (ex. exécuter une action non approuvée)."""

    code = "conflict"
    status_code = 409


class ValidationError(ThotSecureError):
    """400/422 — corps de requête invalide (côté serveur ou côté client)."""

    code = "validation_error"
    status_code = 400


class RateLimitedError(ThotSecureError):
    """429 — quota dépassé. ``retry_after`` indique le délai conseillé en secondes."""

    code = "rate_limited"
    status_code = 429
    retryable = True

    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs: Any) -> None:
        # On extrait les métadonnées AVANT super() pour ne pas les écraser ensuite.
        details = kwargs.get("details") or {}
        if retry_after is None:
            retry_after = _coerce_float(details.get("retry_after"))
        super().__init__(message, **kwargs)
        self.retry_after: float | None = retry_after


class ServerError(ThotSecureError):
    """5xx — erreur interne du serveur Thot Secure."""

    code = "internal_error"
    status_code = 500
    retryable = True


# --------------------------------------------------------------------------------------
# Mapping contrat -> exceptions
# --------------------------------------------------------------------------------------

_STATUS_TO_ERROR: dict[int, type] = {
    400: ValidationError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError,
    429: RateLimitedError,
}

_CODE_TO_ERROR: dict[str, type] = {
    "validation_error": ValidationError,
    "invalid_request": ValidationError,
    "unauthenticated": AuthenticationError,
    "unauthorized": AuthenticationError,
    "forbidden": PermissionDeniedError,
    "not_found": NotFoundError,
    "conflict": ConflictError,
    "unprocessable": ValidationError,
    "rate_limited": RateLimitedError,
    "internal_error": ServerError,
}


def error_from_status(status_code: int) -> type:
    """Retourne la classe d'exception correspondant à un code HTTP."""
    if status_code in _STATUS_TO_ERROR:
        return _STATUS_TO_ERROR[status_code]
    if status_code >= 500:
        return ServerError
    return ThotSecureError


def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def error_from_response(
    status_code: int,
    payload: Any = None,
    *,
    method: str | None = None,
    url: str | None = None,
    headers: Mapping[str, str] | None = None,
    raw_text: str | None = None,
) -> ThotSecureError:
    """Construit l'exception adéquate depuis une réponse HTTP en erreur.

    La priorité est donnée au ``error.code`` du contrat, puis au code HTTP, puis au texte brut.
    """
    code: str | None = None
    message: str | None = None
    details: dict[str, Any] = {}

    if isinstance(payload, Mapping):
        error = payload.get("error")
        if isinstance(error, Mapping):
            code = error.get("code") if isinstance(error.get("code"), str) else None
            message = error.get("message") if isinstance(error.get("message"), str) else None
            raw_details = error.get("details")
            if isinstance(raw_details, Mapping):
                details = dict(raw_details)
        elif isinstance(payload.get("detail"), str):
            # FastAPI renvoie parfois {"detail": "..."} : on l'accepte sans le masquer.
            message = payload["detail"]
        elif isinstance(payload.get("detail"), list):
            message = "validation error"
            details = {"errors": payload["detail"]}

    if message is None:
        message = raw_text.strip()[:500] if raw_text and raw_text.strip() else f"HTTP {status_code}"

    cls = _CODE_TO_ERROR.get(code or "", None) or error_from_status(status_code)

    request_id = None
    if headers:
        request_id = _header(headers, "x-request-id") or _header(headers, "x-correlation-id")

    kwargs: dict[str, Any] = {
        "code": code or getattr(cls, "code", None),
        "status_code": status_code,
        "details": details,
        "method": method,
        "url": url,
        "request_id": request_id,
    }

    if cls is RateLimitedError:
        retry_after = None
        if headers:
            retry_after = _coerce_float(_header(headers, "retry-after"))
        kwargs["retry_after"] = retry_after

    return cls(message, **kwargs)  # type: ignore[arg-type]


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Lecture d'en-tête insensible à la casse."""
    if name in headers:
        return headers[name]
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None
