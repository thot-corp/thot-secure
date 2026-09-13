"""Connecteur natif Cloudflare : blocage d'adresse et limitation de débit en périphérie.

C'est le connecteur qui **retire la dépendance à la passerelle ``http-webhook``** pour les
contre-mesures les plus fréquentes d'un SOAR : bloquer l'adresse d'une attaque, la débloquer,
et limiter son débit.

Deux API Cloudflare sont utilisées, parce qu'elles ne font pas la même chose :

* **IP Access Rules** (``/accounts/{account_id}/firewall/access_rules/rules``) pour le
  blocage : la règle est créée en une requête et renvoie un **identifiant de règle**, que
  l'on conserve comme ``rollback_token``. Le déblocage supprime alors la règle **par
  identifiant** — c'est la seule façon fiable d'annuler exactement ce que l'on a posé : une
  recherche par valeur peut manquer la règle (``1.2.3.4`` et ``1.2.3.4/32`` ne sont pas la
  même chaîne côté API) ou, pire, supprimer une règle posée par quelqu'un d'autre.
* **Rulesets API** (phase ``http_ratelimit``) pour la limitation de débit : IP Access Rules
  ne sait pas limiter un débit, elle sait bloquer ou challenger. Une limitation se déclare
  dans le ruleset de phase de la zone.

Deux limites sont assumées et documentées dans ``docs/actions/playbooks.md`` :

* une IP Access Rule **n'expire pas côté Cloudflare** : la durée demandée est inscrite dans
  les ``notes`` et c'est le rollback de Thot Secure (manuel ou ``auto_after_seconds``) qui
  lève le blocage. Un blocage sans rollback est un déni de service que l'on s'inflige ;
* la limitation de débit Cloudflare est une fonctionnalité **payante** selon l'offre : si
  votre plan ne l'inclut pas, l'API refuse la règle et le connecteur remonte le message
  d'erreur Cloudflare tel quel — aucune action n'est revendiquée à tort.

Ce connecteur n'implémente **pas** ``notify``, bien que l'opération existe au contrat. Cloudflare
n'expose pas d'API d'envoi de message ad hoc : son API d'alerting gère des *politiques* (qui
notifier, sur quel événement), pas un texte libre. Détourner cette API pour y écrire un message
produirait un connecteur qui « réussit » sans que personne ne reçoive rien — exactement le faux
succès qu'un outil de sécurité ne doit jamais produire. Une notification passe par ``slack`` ou
par ``http-webhook``, et le nom logique ``notify`` doit rester sur l'un de ces pilotes.

Sécurité : le jeton d'API est lu **exclusivement** dans la configuration du connecteur, il
n'est jamais journalisé, jamais renvoyé dans un résultat, et il est masqué par
``redact_params``. La vérification TLS est active par défaut ; ``verify_tls: false`` est
possible mais journalisé en avertissement à chaque instanciation.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from datetime import timedelta
from typing import Any

from ...core.logging_setup import get_logger
from ...core.util import iso_z, new_id, utcnow
from .base import Connector, ConnectorNotConfiguredError, ConnectorResult
from .http_client import DEFAULT_TIMEOUT, HttpClient, HttpResult

log = get_logger("actions.connector.cloudflare")

#: Notes Cloudflare : 500 caractères maximum, au-delà l'API tronque ou refuse.
MAX_NOTES_LENGTH = 500

#: Périodes acceptées par la Rulesets API pour une règle de limitation (secondes).
ALLOWED_PERIODS = (10, 60, 120, 300, 600, 3600)

#: Borne du nombre de requêtes par période : au-delà, la demande est presque sûrement une
#: erreur d'unité (« 10 r/s » saisi comme 10 000 000) et mérite un refus explicite.
MAX_REQUESTS_PER_PERIOD = 1_000_000

#: Durée de mitigation : bornes des règles de limitation Cloudflare.
MIN_MITIGATION_TIMEOUT = 10
MAX_MITIGATION_TIMEOUT = 86400

#: Modes d'IP Access Rule utilisables pour une contre-mesure défensive. ``whitelist`` en est
#: volontairement exclu : autoriser explicitement une adresse n'est pas une riposte.
ALLOWED_RULE_MODES = ("block", "managed_challenge", "js_challenge", "challenge")

#: Un identifiant de règle Cloudflare est un UUID hexadécimal de 32 caractères. Ce contrôle de
#: forme n'est pas cosmétique : le moteur de playbooks injecte dans ``${params.rollback_token}``
#: le jeton de la **dernière étape appliquée**, qui peut appartenir à un autre connecteur (un
#: ticket, une simulation…). Sans ce filtre, ``unblock_ip`` enverrait une requête absurde
#: (``DELETE …/rules/simulation%3Aopen_ticket``) au lieu d'annuler réellement le blocage par la
#: valeur connue. On préfère toujours l'annulation réelle au respect littéral d'un jeton.
RULE_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")

#: Jeton de limitation : ``<ruleset_id>/<rule_id>``, deux UUID hexadécimaux.
RULESET_RULE_RE = re.compile(r"^[0-9a-fA-F]{32}/[0-9a-fA-F]{32}$")

_RATE_RE = re.compile(
    r"^(?P<count>\d+)\s*(?:r|req|reqs|request|requests)?\s*/\s*(?P<span>\d+)?\s*"
    r"(?P<unit>s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$",
    re.IGNORECASE,
)

_UNIT_SECONDS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
}


class CloudflareConnector(Connector):
    """Blocage, déblocage et limitation de débit via l'API Cloudflare (v4)."""

    driver = "cloudflare"

    DEFAULT_API_BASE = "https://api.cloudflare.com/client/v4"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"block_ip", "unblock_ip", "rate_limit", "remove_rate_limit"})

    @property
    def description(self) -> str:
        return "cloudflare (IP Access Rules + rulesets http_ratelimit)"

    # -- configuration -----------------------------------------------------------------

    @property
    def api_token(self) -> str:
        """Jeton d'API : lu dans la configuration, jamais journalisé ni retourné."""
        token = str(self.settings.get("api_token") or self.settings.get("token") or "").strip()
        if not token:
            raise ConnectorNotConfiguredError(
                "paramètre 'api_token' absent : créez un jeton Cloudflare à portée minimale "
                "(Account Firewall Access Rules: Edit, Zone WAF: Edit) et placez-le dans "
                "config/connectors.yaml, fichier protégé (chmod 600) et hors du dépôt Git"
            )
        return token

    @property
    def api_base(self) -> str:
        base = str(self.settings.get("api_base") or self.DEFAULT_API_BASE).strip().rstrip("/")
        if not base.startswith(("https://", "http://")):
            raise ConnectorNotConfiguredError(f"paramètre 'api_base' invalide: {base}")
        return base

    @property
    def account_id(self) -> str:
        account = str(self.settings.get("account_id") or "").strip()
        if not account:
            raise ConnectorNotConfiguredError(
                "paramètre 'account_id' absent (requis pour les IP Access Rules)"
            )
        return account

    @property
    def zone_id(self) -> str:
        zone = str(self.settings.get("zone_id") or "").strip()
        if not zone:
            raise ConnectorNotConfiguredError(
                "paramètre 'zone_id' absent (requis pour la limitation de débit)"
            )
        return zone

    # -- transport ---------------------------------------------------------------------

    def _client(self) -> HttpClient:
        return HttpClient(
            driver=self.driver,
            timeout=float(self.settings.get("timeout_seconds") or DEFAULT_TIMEOUT),
            verify_tls=bool(self.settings.get("verify_tls", True)),
            allow_insecure_http=bool(self.settings.get("allow_insecure_http", False)),
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> HttpResult:
        url = f"{self.api_base}{path}"
        if query:
            filtered = {key: value for key, value in query.items() if value is not None}
            url = f"{url}?{urllib.parse.urlencode(filtered)}"
        return self._client().request(
            method, url, headers=self._headers(), json_body=json_body
        )

    # -- diagnostic --------------------------------------------------------------------

    @staticmethod
    def format_errors(errors: Any) -> str:
        """Rend ``errors[]`` lisible : ``code 10000: message`` (diagnostic exploitable)."""
        formatted: list[str] = []
        for item in errors or []:
            if not isinstance(item, dict):
                formatted.append(str(item)[:200])
                continue
            code = item.get("code")
            message = str(item.get("message") or "").strip()
            formatted.append(f"code {code}: {message}" if code is not None else message)
        return "; ".join(part for part in formatted if part)

    def _diagnose(self, result: HttpResult) -> str | None:
        """Retourne ``None`` si l'appel Cloudflare a réussi, sinon un message exploitable.

        Le message ne contient jamais le jeton : les erreurs Cloudflare ne le renvoient pas,
        et l'on ne rajoute jamais les en-têtes de la requête au diagnostic.
        """
        if result.transport_error:
            return f"Cloudflare injoignable: {result.error}"
        cloudflare_errors = self.format_errors(result.payload.get("errors"))
        if result.payload.get("success") is True and result.ok:
            return None
        if cloudflare_errors:
            status = f"HTTP {result.status} — " if result.status else ""
            return f"{status}Cloudflare a refusé la requête: {cloudflare_errors}"
        if not result.ok:
            detail = (result.text or "").strip().replace("\n", " ")[:200]
            return (
                f"Cloudflare: HTTP {result.status}"
                + (f" — {detail}" if detail else "")
            )
        return None

    # -- validation des cibles ---------------------------------------------------------

    @staticmethod
    def normalize_target(raw: Any) -> tuple[str | None, str | None]:
        """Valide une IP/CIDR et retourne ``(valeur, erreur)``.

        Envoyer une valeur non validée à un WAF revient à poser une règle absurde : on refuse
        donc net, avec un message qui dit quoi corriger.
        """
        text = str(raw or "").strip()
        if not text:
            return None, "paramètre 'target' (IP ou CIDR) manquant"
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None, f"cible invalide '{text}': adresse IP ou plage CIDR attendue"
        if "/" in text:
            return str(network), None
        return str(network.network_address), None

    @staticmethod
    def _expression(target: str) -> str:
        """Expression Cloudflare correspondant à une adresse ou à une plage."""
        if "/" in target:
            return f"(ip.src in {{{target}}})"
        return f"(ip.src eq {target})"

    # -- opérations --------------------------------------------------------------------

    def op_block_ip(self, params: dict[str, Any]) -> ConnectorResult:
        target, error = self.normalize_target(params.get("target") or params.get("ip"))
        if error:
            return ConnectorResult(ok=False, error=error)

        duration = int(params.get("duration_seconds") or params.get("ttl") or 3600)
        note = str(params.get("reason") or params.get("note") or "Thot Secure auto-mitigation")
        action_id = str(params.get("action_id") or new_id("cf_"))
        mode = str(params.get("mode") or "block").strip().lower()
        if mode not in ALLOWED_RULE_MODES:
            return ConnectorResult(
                ok=False,
                error=(
                    f"mode '{mode}' refusé: modes autorisés {', '.join(ALLOWED_RULE_MODES)} "
                    "(une contre-mesure bloque ou challenge, elle n'autorise pas)"
                ),
            )

        expires_at = iso_z(utcnow() + timedelta(seconds=duration))
        notes = (
            f"Thot Secure {action_id} | {note} | TTL {duration}s | lever avant {expires_at}"
        )[:MAX_NOTES_LENGTH]
        body = {
            "mode": mode,
            "notes": notes,
            "configuration": {"target": "ip", "value": target},
        }

        result = self._request(
            "POST", f"/accounts/{self.account_id}/firewall/access_rules/rules", json_body=body
        )
        failure = self._diagnose(result)
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"target": target})

        rule = result.payload.get("result") or {}
        rule_id = str(rule.get("id") or "")
        if not rule_id:
            return ConnectorResult(
                ok=False,
                error=(
                    "Cloudflare a répondu sans identifiant de règle : impossible de garantir "
                    "le rollback, la règle est traitée comme non posée (vérifiez la console)"
                ),
                data={"target": target},
            )

        log.info(
            "adresse bloquée au niveau Cloudflare",
            extra={"rule_id": rule_id, "target": target, "mode": mode, "ttl_seconds": duration},
        )
        return ConnectorResult(
            ok=True,
            detail=(
                f"règle Cloudflare {rule_id} posée en mode '{mode}' pour {target}. "
                f"Durée demandée {duration}s (expiration non gérée par Cloudflare : elle est "
                f"inscrite dans les notes et le rollback doit être déclenché avant {expires_at})"
            ),
            data={
                "rule_id": rule_id,
                "mode": mode,
                "target": target,
                "duration_seconds": duration,
                "expires_at": expires_at,
                "rollback_operation": "unblock_ip (DELETE par identifiant de règle)",
            },
            rollback_token=rule_id,
        )

    def _warn_foreign_token(self, operation: str) -> None:
        """Signale un jeton d'une autre forme que celle rendue par ce connecteur.

        Le jeton n'est jamais recopié dans le journal : il peut provenir d'un autre système et
        contenir n'importe quoi.
        """
        log.warning(
            "jeton de rollback ignoré : sa forme n'est pas celle d'un identifiant Cloudflare "
            "(le moteur injecte le jeton de la dernière étape appliquée, qui peut appartenir à "
            "un autre connecteur) — annulation tentée par la valeur connue",
            extra={"connector": self.driver, "operation": operation},
        )

    def op_unblock_ip(self, params: dict[str, Any]) -> ConnectorResult:
        token = str(params.get("rollback_token") or params.get("rule_id") or "").strip()
        target, target_error = self.normalize_target(params.get("target") or params.get("ip"))

        if token and RULE_ID_RE.match(token):
            # Le jeton suffit : on supprime par identifiant, sans rechercher par valeur.
            return self._delete_rule(token, None if target_error else target)
        if token:
            self._warn_foreign_token("unblock_ip")
        if target_error:
            return ConnectorResult(
                ok=False,
                error=(
                    f"{target_error} — précisez 'target' (IP débloquée) ou le 'rollback_token' "
                    "rendu par block_ip (identifiant de règle Cloudflare)"
                ),
            )
        return self._delete_by_value(target)

    def _delete_rule(self, rule_id: str, target: str | None) -> ConnectorResult:
        """Suppression **par identifiant** : la seule annulation non ambiguë."""
        path = urllib.parse.quote(rule_id)
        result = self._request(
            "DELETE",
            f"/accounts/{self.account_id}/firewall/access_rules/rules/{path}",
        )
        failure = self._diagnose(result)
        if failure:
            if result.status == 404:
                return ConnectorResult(
                    ok=False,
                    error=(
                        f"règle Cloudflare '{rule_id}' introuvable (déjà supprimée ? "
                        "vérifiez la console Cloudflare avant de conclure)"
                    ),
                    data={"rule_id": rule_id, "target": target},
                )
            return ConnectorResult(ok=False, error=failure, data={"rule_id": rule_id})
        log.info("règle Cloudflare supprimée", extra={"rule_id": rule_id, "target": target})
        return ConnectorResult(
            ok=True,
            detail=(
                f"règle Cloudflare {rule_id} supprimée"
                + (f" (adresse {target})" if target else "")
            ),
            data={"rule_id": rule_id, "target": target, "removed": 1, "match": "rule_id"},
        )

    def _delete_by_value(self, target: str) -> ConnectorResult:
        """Repli : recherche par valeur, puis suppression de chaque règle trouvée.

        Ce repli existe parce qu'un ``rollback_token`` peut être perdu (base restaurée,
        action expirée). Il est **moins fiable** et le dit : les adresses sont comparées
        textuellement (``1.2.3.4`` vs ``1.2.3.4/32``), et la recherche peut ramener une règle
        posée par un autre outil. Le résultat porte donc ``match: configuration.value``.
        """
        listing = self._request(
            "GET",
            f"/accounts/{self.account_id}/firewall/access_rules/rules",
            query={
                "configuration.target": "ip",
                "configuration.value": target,
                "per_page": 50,
            },
        )
        failure = self._diagnose(listing)
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"target": target})

        rules = listing.payload.get("result") or []
        accepted_values = {target, f"{target}/32"}
        candidates = [
            str(rule.get("id"))
            for rule in rules
            if isinstance(rule, dict)
            and str((rule.get("configuration") or {}).get("value") or "") in accepted_values
            and rule.get("id")
        ]
        if not candidates:
            return ConnectorResult(
                ok=False,
                error=(
                    f"aucune règle Cloudflare ne correspond à {target} (déjà débloquée ? "
                    "ou règle posée dans une autre portée de compte)"
                ),
                data={"target": target, "match": "configuration.value"},
            )

        removed: list[str] = []
        for rule_id in candidates:
            deletion = self._request(
                "DELETE",
                f"/accounts/{self.account_id}/firewall/access_rules/rules/"
                f"{urllib.parse.quote(rule_id)}",
            )
            if self._diagnose(deletion) is None:
                removed.append(rule_id)

        return ConnectorResult(
            ok=bool(removed),
            detail=f"{len(removed)} règle(s) Cloudflare supprimée(s) pour {target}",
            data={
                "target": target,
                "rule_ids": removed,
                "removed": len(removed),
                "match": "configuration.value",
                "avertissement": (
                    "suppression par valeur : vérifiez qu'aucune règle légitime n'a été retirée"
                ),
            },
            error=None if removed else "aucune règle n'a pu être supprimée",
        )

    # -- limitation de débit -----------------------------------------------------------

    def _rate_settings(self, params: dict[str, Any]) -> tuple[dict[str, int] | None, str | None]:
        """Traduit ``rate`` (« 10r/s », « 30r/m ») en paramètres de règle Cloudflare."""
        explicit_period = params.get("period")
        explicit_requests = params.get("requests_per_period")
        if explicit_period is not None or explicit_requests is not None:
            period = int(explicit_period or 60)
            requests = int(explicit_requests or 0)
        else:
            raw = str(params.get("rate") or "10r/s").strip()
            match = _RATE_RE.match(raw)
            if not match:
                return None, (
                    f"débit '{raw}' incompris : syntaxe attendue « 10r/s », « 30r/m », "
                    "« 600r/h » (ou les paramètres 'requests_per_period' et 'period')"
                )
            count = int(match.group("count"))
            span = int(match.group("span") or 1)
            unit = _UNIT_SECONDS[match.group("unit").lower()]
            window = span * unit
            # On conserve la fenêtre déclarée quand Cloudflare l'autorise (« 30r/m » → 60 s),
            # et on retombe sinon sur la période autorisée la plus proche (« 10r/s » → 10 s,
            # en conservant le débit moyen). Une conversion qui change la fenêtre sans le dire
            # rendrait la règle incompréhensible pour l'exploitant.
            period = min(
                ALLOWED_PERIODS, key=lambda candidate: (abs(candidate - window), candidate)
            )
            requests = max(1, int(round(count * period / window)))

        if period not in ALLOWED_PERIODS:
            return None, (
                f"période {period}s refusée par Cloudflare : valeurs admises "
                f"{', '.join(str(item) for item in ALLOWED_PERIODS)}"
            )
        if not 1 <= requests <= MAX_REQUESTS_PER_PERIOD:
            return None, (
                f"{requests} requêtes par période hors bornes (1..{MAX_REQUESTS_PER_PERIOD}) : "
                "vérifiez l'unité du débit"
            )
        return {"period": period, "requests_per_period": requests}, None

    def _mitigation_timeout(self, params: dict[str, Any]) -> tuple[int | None, str | None]:
        duration = int(params.get("duration_seconds") or params.get("ttl") or 1800)
        if not MIN_MITIGATION_TIMEOUT <= duration <= MAX_MITIGATION_TIMEOUT:
            return None, (
                f"durée de limitation {duration}s hors bornes Cloudflare "
                f"({MIN_MITIGATION_TIMEOUT}..{MAX_MITIGATION_TIMEOUT})"
            )
        return duration, None

    def op_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        target, error = self.normalize_target(params.get("target") or params.get("ip"))
        if error:
            return ConnectorResult(ok=False, error=error)
        rate, rate_error = self._rate_settings(params)
        if rate_error:
            return ConnectorResult(ok=False, error=rate_error)
        mitigation, mitigation_error = self._mitigation_timeout(params)
        if mitigation_error:
            return ConnectorResult(ok=False, error=mitigation_error)

        note = str(params.get("reason") or params.get("note") or "Thot Secure rate limit")
        action_id = str(params.get("action_id") or new_id("cf_"))
        expression = self._expression(target or "")
        entrypoint = f"/zones/{self.zone_id}/rulesets/phases/http_ratelimit/entrypoint"

        current = self._request("GET", entrypoint)
        if current.status == 404:
            ruleset_id, existing = "", []
        else:
            failure = self._diagnose(current)
            if failure:
                return ConnectorResult(ok=False, error=failure, data={"target": target})
            ruleset = current.payload.get("result") or {}
            ruleset_id = str(ruleset.get("id") or "")
            existing = [
                rule
                for rule in (ruleset.get("rules") or [])
                if isinstance(rule, dict)
                # Une même source ne doit pas accumuler deux limitations concurrentes.
                and str(rule.get("expression") or "") != expression
            ]

        new_rule = {
            "action": str(params.get("action") or "block").strip().lower(),
            "description": f"Thot Secure {action_id} — {note} — {target}"[:255],
            "enabled": True,
            "expression": expression,
            "ratelimit": {
                "characteristics": ["ip.src"],
                "period": rate["period"],
                "requests_per_period": rate["requests_per_period"],
                "mitigation_timeout": mitigation,
            },
        }
        allowed_actions = {"block", "managed_challenge", "js_challenge", "challenge", "log"}
        if new_rule["action"] not in allowed_actions:
            return ConnectorResult(
                ok=False,
                error=(
                    f"action '{new_rule['action']}' refusée : utilisez block, "
                    "managed_challenge, js_challenge ou challenge"
                ),
            )

        written = self._request("PUT", entrypoint, json_body={"rules": [*existing, new_rule]})
        failure = self._diagnose(written)
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"target": target})

        ruleset = written.payload.get("result") or {}
        ruleset_id = str(ruleset.get("id") or ruleset_id)
        rule_id = self._find_rule_id(ruleset.get("rules") or [], action_id)
        if not ruleset_id or not rule_id:
            return ConnectorResult(
                ok=False,
                error=(
                    "Cloudflare a accepté la mise à jour sans rendre d'identifiant de règle : "
                    "rollback non garantissable, vérifiez le ruleset "
                    "http_ratelimit dans la console"
                ),
                data={"target": target},
            )

        log.info(
            "limitation de débit Cloudflare posée",
            extra={
                "ruleset_id": ruleset_id,
                "rule_id": rule_id,
                "target": target,
                "requests_per_period": rate["requests_per_period"],
                "period": rate["period"],
            },
        )
        return ConnectorResult(
            ok=True,
            detail=(
                f"limitation Cloudflare {rate['requests_per_period']} requêtes/{rate['period']}s "
                f"appliquée à {target} (mitigation {mitigation}s)"
            ),
            data={
                "ruleset_id": ruleset_id,
                "rule_id": rule_id,
                "target": target,
                "expression": expression,
                "requests_per_period": rate["requests_per_period"],
                "period": rate["period"],
                "mitigation_timeout": mitigation,
                "rollback_operation": "remove_rate_limit (DELETE par identifiant de règle)",
            },
            rollback_token=f"{ruleset_id}/{rule_id}",
        )

    @staticmethod
    def _find_rule_id(rules: Any, action_id: str) -> str:
        for rule in rules or []:
            if isinstance(rule, dict) and action_id in str(rule.get("description") or ""):
                return str(rule.get("id") or "")
        return ""

    def op_remove_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        token = str(params.get("rollback_token") or "").strip()
        target, target_error = self.normalize_target(params.get("target") or params.get("ip"))
        entrypoint = f"/zones/{self.zone_id}/rulesets/phases/http_ratelimit/entrypoint"

        if token:
            if RULESET_RULE_RE.match(token):
                ruleset_part, rule_part = token.split("/")
                deletion = self._request(
                    "DELETE",
                    f"/zones/{self.zone_id}/rulesets/{ruleset_part}/rules/{rule_part}",
                )
                failure = self._diagnose(deletion)
                if failure is None:
                    return ConnectorResult(
                        ok=True,
                        detail=f"règle de limitation {rule_part} supprimée (par identifiant)",
                        data={
                            "ruleset_id": ruleset_part,
                            "rule_id": rule_part,
                            "removed": 1,
                            "match": "rule_id",
                        },
                    )
                if deletion.status != 404:
                    return ConnectorResult(ok=False, error=failure)
            else:
                self._warn_foreign_token("remove_rate_limit")

        if target_error:
            return ConnectorResult(
                ok=False,
                error=(
                    f"{target_error} — précisez 'target' (adresse limitée) ou 'rollback_token' "
                    "(« <ruleset_id>/<rule_id> » rendu par rate_limit)"
                ),
            )

        # Repli documenté : on retire du ruleset les règles dont l'expression vise la cible.
        current = self._request("GET", entrypoint)
        failure = self._diagnose(current)
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"target": target})
        ruleset = current.payload.get("result") or {}
        ruleset_id = str(ruleset.get("id") or "")
        rules = [rule for rule in (ruleset.get("rules") or []) if isinstance(rule, dict)]
        needle = target or ""
        kept = [rule for rule in rules if needle not in str(rule.get("expression") or "")]
        removed = len(rules) - len(kept)
        if removed == 0:
            return ConnectorResult(
                ok=False,
                error=f"aucune limitation Cloudflare ne vise {target} (déjà retirée ?)",
                data={"target": target, "match": "expression"},
            )

        written = self._request("PUT", entrypoint, json_body={"rules": kept})
        failure = self._diagnose(written)
        if failure:
            return ConnectorResult(ok=False, error=failure, data={"target": target})
        return ConnectorResult(
            ok=True,
            detail=f"{removed} limitation(s) retirée(s) pour {target}",
            data={
                "ruleset_id": ruleset_id,
                "target": target,
                "removed": removed,
                "match": "expression",
                "avertissement": (
                    "retrait par expression : vérifiez le ruleset si une autre règle visait "
                    "la même adresse"
                ),
            },
        )

    # -- état --------------------------------------------------------------------------

    def describe_state(self) -> dict[str, Any]:
        """État du connecteur — jamais de secret, seulement la présence des paramètres."""
        return {
            "driver": self.driver,
            "api_base": str(self.settings.get("api_base") or self.DEFAULT_API_BASE),
            "account_id_configured": bool(self.settings.get("account_id")),
            "zone_id_configured": bool(self.settings.get("zone_id")),
            "api_token_configured": bool(
                self.settings.get("api_token") or self.settings.get("token")
            ),
            "verify_tls": bool(self.settings.get("verify_tls", True)),
            "operations": sorted(self.capabilities),
        }


__all__ = ["ALLOWED_PERIODS", "ALLOWED_RULE_MODES", "CloudflareConnector"]
