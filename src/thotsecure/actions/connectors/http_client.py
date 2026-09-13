"""Client HTTP minimal partagé par les connecteurs natifs (stdlib uniquement).

Cloudflare, AWS WAF, Slack et GitHub parlent tous HTTP : plutôt que de réécrire quatre fois
la même gestion d'erreurs, elle est centralisée ici. Trois garanties en découlent, et aucun
connecteur ne peut les contourner par distraction :

* **aucune exception ne remonte jamais** : une panne réseau, un certificat invalide ou une
  réponse illisible deviennent un :class:`HttpResult` en échec, que le connecteur traduit en
  ``ConnectorResult`` (contrat de ``Connector.call``) ;
* **vérification TLS activée par défaut** : ``verify_tls: false`` n'est possible
  qu'explicitement, et il est journalisé en avertissement — un connecteur d'action qui
  accepte n'importe quel certificat est un vecteur d'attaque, pas un outil de sécurité ;
* **aucun secret dans les journaux** : seuls le pilote, la méthode, l'hôte et le code de
  retour sont journalisés. Jamais les en-têtes (qui portent ``Authorization``), jamais le
  corps, jamais la query string.

Le transport en clair (``http://``) est refusé par défaut : il n'est toléré que vers la
boucle locale (tests locaux, passerelle sur la même machine) ou si le connecteur l'autorise
explicitement via ``allow_insecure_http``.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ...core.logging_setup import get_logger

log = get_logger("actions.connector.http")

#: User-Agent identifiant le produit : un administrateur doit pouvoir reconnaître nos appels.
USER_AGENT = "ThotSecure/0.1.0 (+https://thotsecure.dev)"

DEFAULT_TIMEOUT = 10.0

#: Au-delà, la réponse n'est plus un diagnostic mais une fuite de mémoire.
MAX_RESPONSE_BYTES = 64 * 1024


def is_loopback_host(host: str | None) -> bool:
    """Vrai si l'hôte est la boucle locale (``localhost``, ``127.0.0.0/8``, ``::1``)."""
    if not host:
        return False
    name = host.strip().strip("[]").split("%", 1)[0].lower()
    if name in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def parse_json_object(text: str) -> dict[str, Any]:
    """Décode un corps JSON en objet, sans jamais lever (``{}`` si illisible)."""
    if not text or not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _transport_reason(exc: urllib.error.URLError) -> str:
    """Raison d'une erreur de transport, sans URL (une URL peut contenir un secret)."""
    reason = getattr(exc, "reason", None)
    if reason is None:
        return type(exc).__name__
    if isinstance(reason, (TimeoutError, OSError, ssl.SSLError)):
        return f"{type(reason).__name__}: {reason}"
    return str(reason)


@dataclass(slots=True)
class HttpResult:
    """Résultat d'un appel HTTP : jamais d'exception, toujours un diagnostic."""

    ok: bool
    status: int = 0
    text: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    #: Vrai lorsqu'aucune réponse HTTP n'a été obtenue (DNS, TLS, connexion refusée…).
    transport_error: bool = False
    #: En-têtes de réponse, en minuscules. Certains protocoles y placent le type d'erreur
    #: (``x-amzn-errortype`` d'AWS). Jamais journalisés : ils peuvent porter un challenge.
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status < 500

    @property
    def is_server_error(self) -> bool:
        return self.status >= 500


class HttpClient:
    """Client ``urllib`` borné : méthode, en-têtes, corps JSON, délai, TLS."""

    def __init__(
        self,
        *,
        driver: str,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        log_url_path: bool = True,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.driver = driver
        self.timeout = float(timeout) if timeout else DEFAULT_TIMEOUT
        self.verify_tls = bool(verify_tls)
        self.allow_insecure_http = bool(allow_insecure_http)
        #: Mettre à ``False`` quand le chemin de l'URL **est** un secret (webhook Slack).
        self.log_url_path = bool(log_url_path)
        self.user_agent = user_agent

        if not self.verify_tls:
            log.warning(
                "vérification TLS DÉSACTIVÉE pour un connecteur natif : la connexion peut "
                "être interceptée et la contre-mesure détournée. À réserver à un réseau de "
                "confiance, et à documenter dans votre analyse de risque.",
                extra={"driver": self.driver},
            )

    # ----------------------------------------------------------------------------------

    def _prepare(self, url: str) -> tuple[str, ssl.SSLContext | None]:
        """Valide l'URL et construit le contexte TLS. Lève ``ValueError`` si inacceptable."""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            raise ValueError(f"URL invalide (http/https attendu): schéma '{parts.scheme or '?'}'")
        if not parts.netloc:
            raise ValueError("URL invalide : hôte manquant")
        if parts.scheme == "http" and not (
            self.allow_insecure_http or is_loopback_host(parts.hostname)
        ):
            raise ValueError(
                "transport en clair refusé vers un hôte distant : utilisez https:// "
                "(un appel HTTP non chiffré expose le jeton à l'interception)"
            )
        if parts.scheme == "https":
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return url, context
        return url, None

    def _log_target(self, url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or "?"
        if parts.port:
            host = f"{host}:{parts.port}"
        if not self.log_url_path:
            # Le chemin porte le secret (webhook Slack) : on ne journalise que l'hôte.
            return f"{parts.scheme}://{host}/<chemin masqué>"
        path = parts.path or "/"
        return f"{parts.scheme}://{host}{path}"

    # ----------------------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        body: bytes | None = None,
    ) -> HttpResult:
        """Exécute la requête et retourne un résultat — **ne lève jamais**."""
        try:
            target, context = self._prepare(url)
            data = body
            if data is None and json_body is not None:
                data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
            final_headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
            final_headers.update(headers or {})
            # Comparaison insensible à la casse : un connecteur qui passe « content-type »
            # (nom canonique SigV4) ne doit pas se voir ajouter un second en-tête, ce qui
            # ferait diverger le corps signé et le corps transmis.
            has_content_type = any(key.lower() == "content-type" for key in final_headers)
            if data is not None and not has_content_type:
                final_headers["Content-Type"] = "application/json"
            request = urllib.request.Request(  # noqa: S310 - schéma validé ci-dessus
                target, data=data, headers=final_headers, method=method.upper()
            )
        except ValueError as exc:
            return HttpResult(ok=False, error=str(exc), transport_error=True)
        except (TypeError, UnicodeError) as exc:
            return HttpResult(
                ok=False,
                error=f"requête non constructible ({type(exc).__name__}: {exc})",
                transport_error=True,
            )

        log.debug(
            "appel HTTP sortant",
            extra={
                "driver": self.driver,
                "method": method.upper(),
                "target": self._log_target(target),
            },
        )

        try:
            with urllib.request.urlopen(  # noqa: S310 - schéma validé ci-dessus
                request, timeout=self.timeout, context=context
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES)
                status = int(getattr(response, "status", 0) or 0)
                response_headers = {
                    str(key).lower(): str(value) for key, value in response.headers.items()
                }
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                if exc.fp is not None:
                    raw = exc.read(MAX_RESPONSE_BYTES)
            except (OSError, ValueError):  # pragma: no cover - corps déjà consommé
                raw = b""
            text = raw.decode("utf-8", "replace")
            return HttpResult(
                ok=False,
                status=int(exc.code or 0),
                text=text,
                payload=parse_json_object(text),
                error=f"HTTP {exc.code}",
                headers={
                    str(key).lower(): str(value)
                    for key, value in (exc.headers.items() if exc.headers else [])
                },
            )
        except urllib.error.URLError as exc:
            return HttpResult(
                ok=False,
                error=f"service injoignable ({_transport_reason(exc)})",
                transport_error=True,
            )
        except (TimeoutError, OSError, ValueError) as exc:
            return HttpResult(
                ok=False,
                error=f"erreur réseau ({type(exc).__name__}: {exc})",
                transport_error=True,
            )

        text = raw.decode("utf-8", "replace")
        return HttpResult(
            ok=200 <= status < 300,
            status=status,
            text=text,
            payload=parse_json_object(text),
            headers=response_headers,
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResult:
        return self.request("GET", url, headers=headers)

    def post_json(
        self, url: str, payload: dict[str, Any], *, headers: dict[str, str] | None = None
    ) -> HttpResult:
        return self.request("POST", url, headers=headers, json_body=payload)


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_RESPONSE_BYTES",
    "USER_AGENT",
    "HttpClient",
    "HttpResult",
    "is_loopback_host",
    "parse_json_object",
]
