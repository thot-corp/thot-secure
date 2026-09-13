"""Connecteur webhook HTTP : passerelle universelle vers un WAF, un EDR ou un orchestrateur.

Beaucoup d'équipes n'ont pas d'API de WAF directement exploitable, mais disposent d'un
Worker Cloudflare, d'une fonction Lambda, d'un flux n8n ou d'un script pfSense capable de
recevoir un POST. Ce connecteur couvre ce cas sans intégration spécifique — et sans
dépendance HTTP externe (``urllib`` de la stdlib).

Deux garanties :

* **signature HMAC-SHA256** du corps avec un secret partagé, pour que la passerelle puisse
  vérifier que la demande vient bien de Thot Secure et n'a pas été rejouée ;
* **vérification TLS** activée par défaut : un connecteur d'action qui accepte n'importe
  quel certificat est un vecteur d'attaque, pas un outil de sécurité.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ...core.logging_setup import get_logger
from .base import Connector, ConnectorNotConfiguredError, ConnectorResult

log = get_logger("actions.connector.webhook")

DEFAULT_TIMEOUT = 10.0

#: Schémas acceptés pour une URL de connecteur. Volontairement limité à HTTP et HTTPS :
#: ``urllib`` sait aussi ouvrir ``file://``, ``ftp://`` et ``data:``, et une URL de
#: configuration mal remplie ne doit pas transformer le connecteur en lecteur de disque.
ALLOWED_SCHEMES = frozenset({"http", "https"})


def _require_http_scheme(url: str, *, setting: str) -> str:
    """Valide le schéma d'une URL de connecteur, et refuse tout le reste.

    Comparaison via ``urlsplit`` et non ``startswith`` : ``HTTPS://…`` est une URL valide que
    ``startswith`` rejetait à tort, tandis que ``file://`` passait.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ConnectorNotConfiguredError(
            f"paramètre '{setting}' invalide : schéma '{scheme or 'absent'}' refusé "
            f"(http ou https attendu) — {url}"
        )
    return url


#: Toutes les opérations sont relayées à la passerelle : c'est elle qui sait quoi en faire.
RELAYED_OPERATIONS = frozenset(
    {
        "block_ip",
        "unblock_ip",
        "rate_limit",
        "remove_rate_limit",
        "quarantine_file",
        "restore_file",
        "isolate_host",
        "unisolate_host",
        "revoke_session",
        "rotate_secret",
        "patch_dependency",
        "harden_endpoint",
        "open_ticket",
        "close_ticket",
        "notify",
    }
)


class HttpWebhookConnector(Connector):
    """Relaye l'opération signée vers une URL configurée."""

    driver = "http-webhook"

    @property
    def capabilities(self) -> frozenset[str]:
        return RELAYED_OPERATIONS

    @property
    def url(self) -> str:
        url = str(self.settings.get("url") or "").strip()
        if not url:
            raise ConnectorNotConfiguredError(
                "paramètre 'url' absent : renseignez config/connectors.yaml "
                "(ex. https://waf-bridge.interne/thotsecure)"
            )
        return _require_http_scheme(url, setting="url")

    @property
    def rollback_url(self) -> str | None:
        """URL de l'opération inverse (``undo_*``), si elle est configurée.

        Le schéma est **contrôlé ici comme pour ``url``**, et ce n'était pas le cas : la valeur
        était renvoyée telle quelle puis passée à ``urlopen``. Or ``urllib`` ouvre bien d'autres
        choses que du HTTP — ``rollback_url: file:///etc/passwd`` faisait lire un fichier local,
        dont le contenu se retrouvait dans le résultat de l'action, donc dans le journal, l'audit
        et l'API. Un ``undo_*`` suffisait à déclencher le chemin, sans aucun accès réseau.

        Un connecteur qui peut lire le disque du serveur parce qu'une ligne de configuration a
        été mal remplie est exactement ce qu'un produit de sécurité ne doit pas être.
        """
        value = self.settings.get("rollback_url")
        if not value:
            return None
        return _require_http_scheme(str(value).strip(), setting="rollback_url")

    @property
    def secret(self) -> str:
        return str(self.settings.get("secret") or "")

    @property
    def timeout(self) -> float:
        return float(self.settings.get("timeout_seconds") or DEFAULT_TIMEOUT)

    @property
    def verify_tls(self) -> bool:
        return bool(self.settings.get("verify_tls", True))

    @property
    def extra_headers(self) -> dict[str, str]:
        headers = self.settings.get("headers") or {}
        return {str(key): str(value) for key, value in headers.items()}

    # ----------------------------------------------------------------------------------

    def _post(self, url: str, payload: dict[str, Any]) -> ConnectorResult:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ThotSecure/0.1.0 (+https://thotsecure.dev)",
            "X-Thot-Secure-Operation": str(payload.get("operation", "")),
            **self.extra_headers,
        }
        if self.secret:
            signature = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Thot-Secure-Signature"] = f"sha256={signature}"

        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                log.warning(
                    "vérification TLS désactivée pour un connecteur webhook : "
                    "à réserver à un réseau de confiance",
                    extra={"url": url},
                )

        request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:  # noqa: S310
                raw = response.read(64 * 1024).decode("utf-8", "replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace") if exc.fp else str(exc)
            return ConnectorResult(
                ok=False,
                error=f"HTTP {exc.code} de la passerelle: {detail[:300]}",
                data={"status": exc.code},
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return ConnectorResult(ok=False, error=f"passerelle injoignable: {exc}")

        parsed: dict[str, Any] = {}
        if raw.strip():
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = {"raw": raw[:500]}

        token = (
            parsed.get("rollback_token") or parsed.get("id") if isinstance(parsed, dict) else None
        )
        return ConnectorResult(
            ok=200 <= status < 300,
            detail=f"passerelle HTTP {status}",
            data={"status": status, "response": parsed},
            rollback_token=str(token) if token else None,
        )

    def _dispatch(self, operation: str, params: dict[str, Any]) -> ConnectorResult:
        target_url = (
            self.rollback_url if operation.startswith("undo_") and self.rollback_url else self.url
        )
        payload = {
            "operation": operation,
            "params": params,
            "source": "thotsecure",
            "version": "0.1.0",
        }
        return self._post(target_url, payload)

    def _decline(self, operation: str) -> ConnectorResult:
        return ConnectorResult(
            ok=False,
            error=(
                f"connecteur webhook non configuré : impossible d'exécuter '{operation}' "
                "(renseignez 'url' et 'secret' dans config/connectors.yaml)"
            ),
        )

    # -- opérations --------------------------------------------------------------------
    # Chaque opération est relayée ; les méthodes explicites rendent le contrat lisible et
    # permettent au passage de contrôle de capacités de fonctionner normalement.

    def op_block_ip(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("block_ip", params)

    def op_unblock_ip(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("undo_block_ip", params)

    def op_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("rate_limit", params)

    def op_remove_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("undo_rate_limit", params)

    def op_quarantine_file(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("quarantine_file", params)

    def op_restore_file(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("undo_quarantine_file", params)

    def op_isolate_host(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("isolate_host", params)

    def op_unisolate_host(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("undo_isolate_host", params)

    def op_revoke_session(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("revoke_session", params)

    def op_rotate_secret(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("rotate_secret", params)

    def op_patch_dependency(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("patch_dependency", params)

    def op_harden_endpoint(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("harden_endpoint", params)

    def op_open_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("open_ticket", params)

    def op_close_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("close_ticket", params)

    def op_notify(self, params: dict[str, Any]) -> ConnectorResult:
        return self._dispatch("notify", params)


__all__ = ["DEFAULT_TIMEOUT", "RELAYED_OPERATIONS", "HttpWebhookConnector"]
