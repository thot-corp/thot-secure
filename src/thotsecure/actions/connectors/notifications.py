"""Connecteurs de notification et de ticketing natifs : Slack et GitHub Issues.

Ces deux connecteurs sont volontairement **légers** : ils ne remplacent pas la passerelle
``http-webhook`` (qui reste la bonne réponse pour un outil maison, n8n ou Teams), ils
couvrent les deux intégrations que la plupart des équipes branchent en premier, avec un
schéma de message déjà correct — au lieu d'un POST générique que chaque intégration doit
réimplémenter.

* ``slack`` : message structuré (gravité, finding, action, cible) dans un canal, avec
  **correction** possible pour qu'une alerte erronée ne reste pas sans démenti ;
* ``github-issues`` : ouverture et fermeture d'issue, utile pour ``patch-dependency``
  (tracer la mise à jour à faire) comme pour tout incident à suivre.

Sécurité : l'URL de webhook Slack **est** un secret (elle contient le jeton du canal) et le
jeton GitHub en est un. Ni l'un ni l'autre n'apparaît dans un journal, un résultat ou une
erreur — le client HTTP partagé ne journalise que l'hôte pour Slack, et aucun
``ConnectorResult`` ne contient la configuration.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ...core.logging_setup import get_logger
from ...core.util import now_iso
from .base import Connector, ConnectorNotConfiguredError, ConnectorResult
from .http_client import DEFAULT_TIMEOUT, HttpClient, HttpResult

log = get_logger("actions.connector.notifications")

#: Gravités connues, avec l'emoji qui rend le canal lisible d'un coup d'œil.
SEVERITY_EMOJI = {
    "info": "ℹ️",  # noqa: RUF001 - emoji voulu : il rend le canal lisible d'un coup d'œil
    "low": "🔵",
    "medium": "⚠️",
    "high": "🔴",
    "critical": "🚨",
}

#: Champs texte de Slack : au-delà, l'API tronque ou rejette.
SLACK_TEXT_LIMIT = 2900

_GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


def _truncate(value: Any, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _severity(value: Any) -> str:
    severity = str(value or "medium").strip().lower()
    return severity if severity in SEVERITY_EMOJI else "medium"


class SlackConnector(Connector):
    """Notification Slack via webhook entrant (``webhook_url``)."""

    driver = "slack"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"notify"})

    @property
    def description(self) -> str:
        return "slack (webhook entrant, message structuré + correction)"

    # -- configuration -----------------------------------------------------------------

    @property
    def webhook_url(self) -> str:
        url = str(self.settings.get("webhook_url") or self.settings.get("url") or "").strip()
        if not url:
            raise ConnectorNotConfiguredError(
                "paramètre 'webhook_url' absent : créez un webhook entrant Slack dédié à "
                "Thot Secure et placez-le dans config/connectors.yaml (fichier protégé : "
                "l'URL du webhook est un secret)"
            )
        if not url.startswith(("https://", "http://")):
            raise ConnectorNotConfiguredError("URL de webhook invalide (http/https attendu)")
        return url

    def _client(self) -> HttpClient:
        return HttpClient(
            driver=self.driver,
            timeout=float(self.settings.get("timeout_seconds") or DEFAULT_TIMEOUT),
            verify_tls=bool(self.settings.get("verify_tls", True)),
            allow_insecure_http=bool(self.settings.get("allow_insecure_http", False)),
            # Le chemin de l'URL est le jeton du webhook : il ne doit jamais être journalisé.
            log_url_path=False,
        )

    # -- message -----------------------------------------------------------------------

    @staticmethod
    def correlation_token(payload: dict[str, Any], severity: str) -> str:
        """Identifiant de corrélation local.

        Un webhook entrant Slack ne renvoie aucun identifiant de message : on ne peut donc pas
        offrir un identifiant serveur. On rend un jeton déterministe (empreinte du message et
        de l'horodatage) qui permet de **rattacher** un message de correction au message
        initial, sans prétendre pouvoir le supprimer — Slack ne le permet pas.
        """
        material = json.dumps(payload, ensure_ascii=False, sort_keys=True) + severity
        return f"slack:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"

    def build_message(self, params: dict[str, Any]) -> dict[str, Any]:
        """Construit le corps envoyé à Slack (texte de repli + blocs structurés)."""
        severity = _severity(params.get("severity"))
        message = _truncate(
            params.get("message") or params.get("title") or "Notification Thot Secure",
            SLACK_TEXT_LIMIT,
        )
        correction_of = str(params.get("correction_of") or params.get("rollback_token") or "")
        is_correction = bool(params.get("correction")) or bool(correction_of)
        prefix = SEVERITY_EMOJI[severity]
        headline = f"{prefix} [{'CORRECTION' if is_correction else severity.upper()}] {message}"

        fields = [("Gravité", severity)]
        for label, key in (
            ("Finding", "finding_id"),
            ("Action", "action_id"),
            ("Cible", "target"),
            ("Hôte", "host"),
            ("Paquet", "package"),
            ("Locataire", "tenant_id"),
        ):
            value = params.get(key)
            if value:
                fields.append((label, str(value)))
        if correction_of:
            fields.append(("Annule", correction_of))

        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"{prefix} *{message}*"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{label}* : {_truncate(value, 120)}"}
                    for label, value in fields
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Thot Secure — {now_iso()}"
                            + (" — message de correction" if is_correction else "")
                        ),
                    }
                ],
            },
        ]
        payload: dict[str, Any] = {"text": headline, "blocks": blocks}
        if params.get("channel"):
            # Un webhook entrant cible déjà son canal : on refuse l'écrasement silencieux.
            log.warning(
                "paramètre 'channel' ignoré : un webhook entrant Slack est lié à son canal",
                extra={"connector": self.driver},
            )
        return payload

    # -- opération ---------------------------------------------------------------------

    def op_notify(self, params: dict[str, Any]) -> ConnectorResult:
        payload = self.build_message(params)
        url = self.webhook_url
        result = self._client().request(
            "POST", url, headers={"Content-Type": "application/json"}, json_body=payload
        )
        if result.transport_error:
            return ConnectorResult(
                ok=False,
                error=f"webhook Slack injoignable: {result.error}",
                data={"severity": _severity(params.get("severity"))},
            )
        # Slack répond « ok » (texte brut) en cas de succès, un code d'erreur sinon.
        body = (result.text or "").strip()
        if not result.ok or body.lower() != "ok":
            hint = ""
            if result.status == 404:
                hint = " (webhook révoqué ou canal supprimé ?)"
            elif result.status == 403:
                hint = " (webhook désactivé côté Slack ?)"
            detail = body[:200].replace("\n", " ") if body else "aucun corps de réponse"
            return ConnectorResult(
                ok=False,
                error=f"Slack a refusé la notification: HTTP {result.status}{hint} — {detail}",
                data={"severity": _severity(params.get("severity")), "status": result.status},
            )

        token = self.correlation_token(payload, _severity(params.get("severity")))
        log.info(
            "notification Slack envoyée",
            extra={
                "severity": _severity(params.get("severity")),
                "finding_id": params.get("finding_id"),
                "correlation": token,
            },
        )
        return ConnectorResult(
            ok=True,
            detail=(
                f"notification Slack envoyée (gravité {_severity(params.get('severity'))}) — "
                "le rollback consiste à émettre un message de correction dans le même canal"
            ),
            data={
                "severity": _severity(params.get("severity")),
                "correlation": token,
                "message": _truncate(payload["text"], 200),
                "rollback_operation": "notify (message de correction, pas de suppression possible)",
            },
            rollback_token=token,
        )

    def describe_state(self) -> dict[str, Any]:
        return {
            "driver": self.driver,
            "webhook_configured": bool(
                self.settings.get("webhook_url") or self.settings.get("url")
            ),
            "verify_tls": bool(self.settings.get("verify_tls", True)),
            "operations": sorted(self.capabilities),
        }


class GithubIssueConnector(Connector):
    """Ticketing GitHub : ouverture et fermeture d'issue via l'API REST."""

    driver = "github-issues"

    DEFAULT_API_URL = "https://api.github.com"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"open_ticket", "close_ticket"})

    @property
    def description(self) -> str:
        return "github-issues (API REST /issues)"

    # -- configuration -----------------------------------------------------------------

    @property
    def token(self) -> str:
        value = str(self.settings.get("token") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError(
                "paramètre 'token' absent : créez un jeton à portée minimale "
                "(permission 'Issues: write' sur le seul dépôt concerné) et placez-le dans "
                "config/connectors.yaml (fichier protégé, hors dépôt Git)"
            )
        return value

    @property
    def repository(self) -> str:
        value = str(self.settings.get("repository") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError(
                "paramètre 'repository' absent (format attendu « proprietaire/depot »)"
            )
        if not _GITHUB_REPOSITORY_RE.match(value):
            raise ConnectorNotConfiguredError(
                f"paramètre 'repository' invalide: '{value}' (format « proprietaire/depot »)"
            )
        return value

    @property
    def api_url(self) -> str:
        return str(self.settings.get("api_url") or self.DEFAULT_API_URL).strip().rstrip("/")

    @property
    def labels(self) -> list[str]:
        configured = self.settings.get("labels")
        if configured is None:
            return ["thotsecure"]
        if isinstance(configured, str):
            return [item.strip() for item in configured.split(",") if item.strip()]
        return [str(item) for item in configured]

    def _client(self) -> HttpClient:
        return HttpClient(
            driver=self.driver,
            timeout=float(self.settings.get("timeout_seconds") or DEFAULT_TIMEOUT),
            verify_tls=bool(self.settings.get("verify_tls", True)),
            allow_insecure_http=bool(self.settings.get("allow_insecure_http", False)),
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpResult:
        return self._client().request(
            method,
            f"{self.api_url}{path}",
            headers=self._headers(),
            json_body=body,
        )

    @staticmethod
    def _diagnose(result: HttpResult, action: str) -> str | None:
        """Diagnostic GitHub — sans jamais inclure le jeton ni les en-têtes envoyés."""
        if result.transport_error:
            return f"API GitHub injoignable: {result.error}"
        if result.ok:
            return None
        message = str(result.payload.get("message") or "").strip()
        errors = result.payload.get("errors")
        errors_text = ""
        if isinstance(errors, list):
            errors_text = "; ".join(
                str(item.get("message") if isinstance(item, dict) else item)[:120]
                for item in errors[:3]
            )
        hint = ""
        if result.status == 404:
            hint = " (dépôt ou issue introuvable, ou jeton sans accès)"
        elif result.status == 401:
            hint = " (jeton expiré ou révoqué)"
        elif result.status == 422:
            hint = " (données refusées par GitHub : vérifiez les étiquettes et le titre)"
        # ``message`` et ``errors[]`` portent des informations différentes : on garde les deux.
        detail = (
            " — ".join(part for part in (message, errors_text) if part)
            or (result.text or "").strip().replace("\n", " ")[:200]
        )
        return f"GitHub a refusé {action}: HTTP {result.status}{hint}" + (
            f" — {detail}" if detail else ""
        )

    # -- opérations --------------------------------------------------------------------

    def op_open_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        title = _truncate(
            params.get("title") or params.get("message") or "Incident Thot Secure", 256
        )
        severity = _severity(params.get("severity"))
        body_lines = [
            f"**Gravité** : {severity}",
            "",
            str(params.get("description") or "Incident ouvert automatiquement par Thot Secure."),
            "",
        ]
        for label, key in (
            ("Finding", "finding_id"),
            ("Action", "action_id"),
            ("Locataire", "tenant_id"),
            ("Cible", "target"),
            ("Paquet", "package"),
            ("Version visée", "version"),
            ("CVE", "cve"),
            ("Manifeste", "manifest"),
        ):
            if params.get(key):
                body_lines.append(f"- **{label}** : {params[key]}")
        body_lines += [
            "",
            "## Remédiation recommandée",
            "",
            str(
                params.get("remediation")
                or "Analyser, confirmer, appliquer, documenter — aucune modification "
                "automatique n'a été appliquée par ce ticket."
            ),
            "",
            f"---\n_Ouvert par Thot Secure le {now_iso()}._",
        ]

        payload: dict[str, Any] = {
            "title": title,
            "body": "\n".join(body_lines),
            "labels": self.labels,
        }
        assignees = params.get("assignees") or self.settings.get("assignees")
        if assignees:
            payload["assignees"] = (
                [assignees] if isinstance(assignees, str) else [str(item) for item in assignees]
            )

        result = self._request("POST", f"/repos/{self.repository}/issues", payload)
        failure = self._diagnose(result, "l'ouverture du ticket")
        if failure:
            return ConnectorResult(ok=False, error=failure)
        number = result.payload.get("number")
        html_url = str(result.payload.get("html_url") or "")
        if number is None:
            return ConnectorResult(
                ok=False,
                error=(
                    "GitHub a répondu sans numéro d'issue : rollback non garantissable, "
                    "vérifiez le dépôt avant de considérer le ticket comme ouvert"
                ),
            )
        ticket = str(number)
        log.info(
            "ticket GitHub ouvert",
            extra={"repository": self.repository, "issue_number": ticket, "severity": severity},
        )
        return ConnectorResult(
            ok=True,
            detail=f"issue GitHub #{ticket} ouverte dans {self.repository}",
            data={
                "ticket_id": ticket,
                "repository": self.repository,
                "url": html_url,
                "labels": self.labels,
                "severity": severity,
                "rollback_operation": "close_ticket (PATCH state=closed)",
            },
            rollback_token=ticket,
        )

    def op_close_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        number = ""
        for key in ("rollback_token", "ticket_id", "issue_number"):
            if params.get(key):
                number = str(params[key]).strip()
                break
        if not number:
            return ConnectorResult(
                ok=False, error="numéro d'issue manquant ('rollback_token' ou 'ticket_id')"
            )
        if not number.isdigit():
            return ConnectorResult(
                ok=False, error=f"numéro d'issue invalide: '{number}' (entier attendu)"
            )

        comment = str(params.get("comment") or params.get("resolution") or "").strip()
        if comment:
            commented = self._request(
                "POST", f"/repos/{self.repository}/issues/{number}/comments", {"body": comment}
            )
            failure = self._diagnose(commented, "le commentaire de clôture")
            if failure:
                return ConnectorResult(ok=False, error=failure, data={"ticket_id": number})

        result = self._request(
            "PATCH",
            f"/repos/{self.repository}/issues/{number}",
            {"state": "closed", "state_reason": "completed"},
        )
        failure = self._diagnose(result, "la fermeture du ticket")
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"ticket_id": number})
        state = str(result.payload.get("state") or "closed")
        log.info(
            "ticket GitHub clôturé",
            extra={"repository": self.repository, "issue_number": number, "state": state},
        )
        return ConnectorResult(
            ok=True,
            detail=f"issue GitHub #{number} clôturée dans {self.repository} (état {state})",
            data={"ticket_id": number, "repository": self.repository, "state": state},
        )

    def describe_state(self) -> dict[str, Any]:
        return {
            "driver": self.driver,
            "api_url": self.api_url,
            "repository_configured": bool(self.settings.get("repository")),
            "token_configured": bool(self.settings.get("token")),
            "labels": self.labels,
            "verify_tls": bool(self.settings.get("verify_tls", True)),
            "operations": sorted(self.capabilities),
        }


__all__ = [
    "SEVERITY_EMOJI",
    "SLACK_TEXT_LIMIT",
    "GithubIssueConnector",
    "SlackConnector",
]
