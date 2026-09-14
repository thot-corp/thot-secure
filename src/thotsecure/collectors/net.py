"""Primitives réseau des collecteurs (stdlib uniquement).

Deux principes :

* **un seul aller-retour par contrôle** : un outil défensif ne mitraille pas un site en
  production ; les requêtes sont séquentielles et espacées ;
* **une erreur réseau n'est jamais une exception** : elle devient un résultat exploitable
  (une cible injoignable est une information utile pour l'exploitant, pas un crash).
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

#: User-agent identifiant clairement l'outil et son usage : un administrateur qui voit passer
#: ces requêtes doit pouvoir savoir en trois secondes d'où elles viennent.
USER_AGENT = "ThotSecure/0.1.0 (+https://thot-corp.github.io/thot-secure/; audit défensif de surface)"

DEFAULT_TIMEOUT = 8.0
MAX_BODY_BYTES = 64 * 1024


@dataclass(slots=True)
class HttpResponse:
    """Réponse HTTP normalisée."""

    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    elapsed_ms: float = 0.0
    final_url: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "final_url": self.final_url,
            "error": self.error,
            "body_snippet": self.body_snippet[:500],
        }


@dataclass(slots=True)
class CertInfo:
    """Informations sur un certificat TLS."""

    host: str
    port: int = 443
    subject: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    protocol: str = ""
    cipher: str = ""
    days_to_expiry: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.not_after is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_to_expiry": self.days_to_expiry,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "error": self.error,
        }


def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    method: str = "GET",
    max_bytes: int = MAX_BODY_BYTES,
    verify_tls: bool = True,
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    """Requête HTTP unique, sans redirection automatique non maîtrisée."""
    if not url.lower().startswith(("http://", "https://")):
        return HttpResponse(url=url, error="schéma d'URL non supporté (http/https attendu)")

    request = urllib.request.Request(  # noqa: S310 - schéma déjà validé
        url,
        method=method.upper(),
        headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})},
    )
    context = None
    if url.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
    try:
        # On n'utilise volontairement pas d'ouvreur avec redirections : suivre une
        # redirection vers un domaine tiers sortirait du périmètre déclaré.
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:  # noqa: S310
            body = response.read(max_bytes)
            charset = response.headers.get_content_charset() or "utf-8"
            result = HttpResponse(
                url=url,
                status=int(response.status),
                headers={key.lower(): value for key, value in response.headers.items()},
                body_snippet=body.decode(charset, "replace"),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                final_url=response.geturl(),
            )
    except urllib.error.HTTPError as exc:
        result = HttpResponse(
            url=url,
            status=int(exc.code),
            headers={key.lower(): value for key, value in (exc.headers or {}).items()},
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result = HttpResponse(
            url=url,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            error=_describe_network_error(exc),
        )
    return result


def _describe_network_error(exc: Exception) -> str:
    """Traduit une erreur réseau en message exploitable (et non en trace Python)."""
    if isinstance(exc, urllib.error.URLError) and isinstance(
        exc.reason, ssl.SSLCertVerificationError
    ):
        return f"certificat TLS refusé: {exc.reason.verify_message}"
    if isinstance(exc, TimeoutError):
        return "délai d'attente dépassé"
    if isinstance(exc, socket.gaierror):
        return f"résolution DNS impossible: {exc}"
    return str(exc)[:300]


def inspect_certificate(
    host: str, port: int = 443, *, timeout: float = DEFAULT_TIMEOUT
) -> CertInfo:
    """Récupère les propriétés d'un certificat TLS, **sans** faire échouer la collecte.

    Le certificat est récupéré même s'il n'est pas validable (expiré, auto-signé) : c'est
    précisément ce qu'on veut pouvoir détecter et signaler.
    """
    info = CertInfo(host=host, port=port)
    context = ssl.create_default_context()
    # On ne souhaite PAS que la vérification échoue : on veut l'analyser nous-mêmes.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw_socket,
            context.wrap_socket(raw_socket, server_hostname=host) as tls_socket,
        ):
            certificate = tls_socket.getpeercert() or {}
            info.protocol = tls_socket.version() or ""
            cipher = tls_socket.cipher()
            info.cipher = f"{cipher[0]} ({cipher[1]})" if cipher else ""
        info.subject = _format_name(certificate.get("subject"))
        info.issuer = _format_name(certificate.get("issuer"))
        info.not_before = _parse_ssl_date(certificate.get("notBefore"))
        info.not_after = _parse_ssl_date(certificate.get("notAfter"))
        if info.not_after is not None:
            info.days_to_expiry = (info.not_after - datetime.now(UTC)).days
    except ssl.SSLError as exc:
        info.error = f"erreur TLS: {exc}"
    except (socket.gaierror, TimeoutError, ConnectionError, OSError) as exc:
        info.error = _describe_network_error(exc)
    return info


def _format_name(entries: Any) -> str:
    if not entries:
        return ""
    parts: list[str] = []
    for group in entries:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_ssl_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def scheme_of(url: str) -> str:
    return (urlparse(url).scheme or "").lower()


def port_of(url: str, default: int = 443) -> int:
    return urlparse(url).port or default


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_BODY_BYTES",
    "USER_AGENT",
    "CertInfo",
    "HttpResponse",
    "fetch",
    "host_of",
    "inspect_certificate",
    "port_of",
    "scheme_of",
]
