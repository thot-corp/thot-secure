"""Couche HTTP du SDK Thot Secure.

Principes
---------
* **Zéro dépendance obligatoire** : ``httpx`` est utilisé s'il est importable, sinon le SDK
  retombe automatiquement sur ``urllib.request`` (stdlib).
* **Retries sûrs** : seuls les statuts ``429/502/503/504`` et les erreurs réseau sont réessayés,
  avec backoff exponentiel + jitter, et en respectant l'en-tête ``Retry-After``.
* **Idempotence** : une méthode non idempotente (``POST``/``PATCH``) n'est **jamais** réessayée
  sans ``idempotency_key`` explicite — voir :func:`is_retry_safe`.
* **TLS vérifié par défaut** : ``verify_tls=False`` produit un avertissement explicite.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import logging
import random
import ssl
import time
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from .errors import TransportError

logger = logging.getLogger("thotsecure_sdk.transport")

__all__ = [
    "IDEMPOTENT_METHODS",
    "RETRY_STATUS_CODES",
    "HttpRequest",
    "HttpResponse",
    "HttpxTransport",
    "RetryingTransport",
    "Transport",
    "UrllibTransport",
    "create_transport",
    "httpx_available",
    "is_retry_safe",
    "parse_retry_after",
]

#: Méthodes HTTP idempotentes par définition (RFC 9110) : réessayables sans risque.
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})

#: Statuts déclenchant un nouvel essai (contrat §4.6 + transitoires usuels).
RETRY_STATUS_CODES = frozenset({429, 502, 503, 504})

DEFAULT_USER_AGENT = "thotsecure-sdk-python/0.1.0"


def is_retry_safe(method: str, idempotency_key: str | None = None) -> bool:
    """Indique si l'appel peut être réessayé sans risque d'effet de bord dupliqué.

    ``POST``/``PATCH`` ne sont réessayés que si l'appelant fournit une ``idempotency_key``
    explicite (le serveur déduplique alors l'opération, cf. contrat §4.6).
    """
    if method.upper() in IDEMPOTENT_METHODS:
        return True
    return bool(idempotency_key)


def parse_retry_after(value: str | None) -> float | None:
    """Convertit un en-tête ``Retry-After`` (secondes ou date HTTP) en secondes flottantes."""
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        now = time.time()
        return max(0.0, when.timestamp() - now)
    return max(0.0, seconds)


def httpx_available() -> bool:
    """Indique si ``httpx`` est importable dans l'environnement courant."""
    try:
        return importlib.util.find_spec("httpx") is not None
    except (ImportError, ValueError):  # pragma: no cover - environnement exotique
        return False


@dataclass
class HttpRequest:
    """Requête HTTP décrite indépendamment de la bibliothèque utilisée."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: Mapping[str, Any] | None = None
    content: bytes | None = None
    timeout: float = 30.0
    #: ``False`` interdit tout nouvel essai (méthode non idempotente sans clé d'idempotence).
    retry_safe: bool = True

    def full_url(self) -> str:
        """URL finale, paramètres de requête sérialisés et encodés."""
        if not self.params:
            return self.url
        cleaned = {k: v for k, v in self.params.items() if v is not None}
        if not cleaned:
            return self.url
        query = urlparse.urlencode(cleaned, doseq=True)
        separator = "&" if "?" in self.url else "?"
        return f"{self.url}{separator}{query}"


@dataclass
class HttpResponse:
    """Réponse HTTP brute retournée par la couche transport."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        """Lecture d'en-tête insensible à la casse."""
        if name in self.headers:
            return self.headers[name]
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None

    def json(self) -> Any:
        """Décode le corps JSON ; ``None`` si le corps est vide."""
        if not self.content:
            return None
        return json.loads(self.content.decode("utf-8"))


class Transport:
    """Interface minimale d'un transport (injectable, ce qui rend le SDK testable hors ligne)."""

    def send(self, request: HttpRequest) -> HttpResponse:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        """Libère les ressources éventuelles. Idempotent."""


def _build_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    if verify_tls:
        return ssl.create_default_context()
    warnings.warn(
        "verify_tls=False : la vérification du certificat TLS est DÉSACTIVÉE. "
        "Cette option ne doit être utilisée que contre une instance locale de développement.",
        RuntimeWarning,
        stacklevel=3,
    )
    logger.warning("TLS: vérification du certificat désactivée (verify_tls=False)")
    return ssl._create_unverified_context()


class UrllibTransport(Transport):
    """Transport de repli, 100 % stdlib (``urllib.request``)."""

    def __init__(self, verify_tls: bool = True) -> None:
        self.verify_tls = verify_tls
        self._ssl_context: ssl.SSLContext | None = None

    def _context(self) -> ssl.SSLContext | None:
        if self._ssl_context is None:
            self._ssl_context = _build_ssl_context(self.verify_tls)
        return self._ssl_context

    def send(self, request: HttpRequest) -> HttpResponse:
        url = request.full_url()
        http_request = urlrequest.Request(
            url,
            data=request.content,
            method=request.method.upper(),
        )
        for name, value in request.headers.items():
            http_request.add_header(name, value)

        context = self._context() if url.lower().startswith("https://") else None
        try:
            with urlrequest.urlopen(http_request, timeout=request.timeout, context=context) as response:
                return HttpResponse(
                    status_code=int(response.status),
                    headers={k: v for k, v in response.headers.items()},
                    content=response.read(),
                )
        except urlerror.HTTPError as exc:
            # Un statut >= 400 est une réponse légitime : ce n'est pas une erreur de transport.
            body = b""
            # Le corps peut avoir déjà été lu (ou la connexion fermée) : toute erreur de lecture
            # laisse le corps vide, elle ne doit jamais masquer la réponse HTTP.
            with contextlib.suppress(Exception):  # pragma: no cover - corps déjà consommé
                body = exc.read() or b""
            headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
            return HttpResponse(status_code=int(exc.code), headers=headers, content=body)
        except (urlerror.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            raise TransportError(
                f"échec du transport vers {url} : {exc}",
                method=request.method,
                url=url,
            ) from exc

    def close(self) -> None:
        self._ssl_context = None


class HttpxTransport(Transport):
    """Transport ``httpx`` (utilisé automatiquement si la bibliothèque est présente)."""

    def __init__(self, verify_tls: bool = True, timeout: float = 30.0) -> None:
        import httpx  # import local : le SDK doit rester importable sans httpx

        self._httpx = httpx
        if not verify_tls:
            _build_ssl_context(False)  # émet l'avertissement explicite
        self._client = httpx.Client(
            verify=verify_tls,
            follow_redirects=False,
            timeout=timeout,
        )
        self.verify_tls = verify_tls

    def send(self, request: HttpRequest) -> HttpResponse:
        try:
            response = self._client.request(
                request.method.upper(),
                request.full_url(),
                headers=request.headers,
                content=request.content,
                timeout=request.timeout,
            )
        except self._httpx.HTTPError as exc:
            raise TransportError(
                f"échec du transport vers {request.url} : {exc}",
                method=request.method,
                url=request.url,
            ) from exc
        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
        )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover - fermeture best effort
            logger.debug("fermeture httpx ignorée", exc_info=True)


def create_transport(verify_tls: bool = True, prefer_httpx: bool = True, timeout: float = 30.0) -> Transport:
    """Fabrique le transport par défaut : ``httpx`` si présent, sinon ``urllib``."""
    if prefer_httpx and httpx_available():
        try:
            return HttpxTransport(verify_tls=verify_tls, timeout=timeout)
        except Exception:  # pragma: no cover - httpx cassé : repli silencieux documenté
            logger.warning("httpx indisponible à l'instanciation, repli sur urllib", exc_info=True)
    return UrllibTransport(verify_tls=verify_tls)


class RetryingTransport(Transport):
    """Décorateur de transport ajoutant la politique de retry du SDK.

    * backoff exponentiel plafonné (``backoff_base * 2**tentative``) ;
    * jitter multiplicatif dans ``[0.5, 1.0]`` (évite la synchronisation des clients) ;
    * ``Retry-After`` respecté lorsqu'il est présent (plafonné par ``max_retry_after``) ;
    * aucun retry si ``request.retry_safe`` est ``False``.
    """

    def __init__(
        self,
        inner: Transport,
        *,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        max_retry_after: float = 60.0,
        retry_status_codes: frozenset = RETRY_STATUS_CODES,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[], float] = random.random,
    ) -> None:
        self._inner = inner
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = float(backoff_base)
        self.backoff_max = float(backoff_max)
        self.max_retry_after = float(max_retry_after)
        self.retry_status_codes = retry_status_codes
        self._sleep = sleep
        self._rand = rand
        #: Nombre de tentatives supplémentaires réellement effectuées (utile pour les tests/métriques).
        self.retry_count = 0

    # ------------------------------------------------------------------ interne

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(retry_after, self.max_retry_after)
        raw = min(self.backoff_max, self.backoff_base * (2**attempt))
        return raw * (0.5 + 0.5 * self._rand())

    def _wait(self, delay: float, reason: str, request: HttpRequest) -> None:
        logger.warning(
            "retry dans %.3fs (%s) %s %s",
            delay,
            reason,
            request.method,
            request.url,
        )
        if delay > 0:
            self._sleep(delay)

    # ------------------------------------------------------------------ API

    def send(self, request: HttpRequest) -> HttpResponse:
        attempt = 0
        while True:
            try:
                response = self._inner.send(request)
            except TransportError as exc:
                retryable = getattr(exc, "retryable", True)
                if not (request.retry_safe and retryable and attempt < self.max_retries):
                    raise
                delay = self._delay(attempt, None)
                attempt += 1
                self.retry_count += 1
                self._wait(delay, "erreur réseau", request)
                continue

            if (
                response.status_code in self.retry_status_codes
                and request.retry_safe
                and attempt < self.max_retries
            ):
                retry_after = parse_retry_after(response.header("retry-after"))
                delay = self._delay(attempt, retry_after)
                attempt += 1
                self.retry_count += 1
                self._wait(delay, f"HTTP {response.status_code}", request)
                continue

            return response

    def close(self) -> None:
        self._inner.close()
