"""Client Python officiel pour l'API REST Thot Secure v0.1.0.

Le client couvre **l'intégralité** de la surface décrite par le contrat
(``docs/architecture/api-contract.md`` §4) sans inventer de route :

* §4.1 santé / méta / observabilité : :meth:`ThotSecureClient.healthz`, ``readyz``, ``version``,
  ``metrics``, ``whoami`` ;
* §4.2 tenants et clés API ;
* §4.3 événements (unitaire et par lots ≤ 500) ;
* §4.4 findings (ack / close / suppress) ;
* §4.5 règles, politiques, playbooks ;
* §4.6 actions SOAR (plan / approve / reject / execute / rollback) ;
* §4.7 audit (liste, vérification de chaîne, export SIEM) ;
* §4.8 stats, rapports, collecteurs, flux temps réel.

Sécurité : la clé API n'est jamais journalisée, ``verify_tls`` est à ``True`` par défaut, et
désactiver la vérification TLS déclenche un avertissement explicite.
"""

from __future__ import annotations

import json
import logging
import os
import warnings
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, Self

from . import helpers as _helpers
from .errors import (
    ServerError,
    ThotSecureError,
    ValidationError,
    error_from_response,
)
from .models import (
    Action,
    ApiKey,
    AuditRecord,
    AuditVerification,
    CollectorStatus,
    Event,
    Finding,
    IngestResult,
    Page,
    Playbook,
    Rule,
    RuleValidation,
    StatsOverview,
    Tenant,
)
from .transport import (
    DEFAULT_USER_AGENT,
    HttpRequest,
    HttpResponse,
    RetryingTransport,
    Transport,
    create_transport,
    is_retry_safe,
)

logger = logging.getLogger("thotsecure_sdk")

__all__ = ["DEFAULT_BASE_URL", "MAX_BATCH_SIZE", "ThotSecureClient"]

#: Taille maximale d'un lot d'ingestion imposée par le contrat §4.3.
MAX_BATCH_SIZE = 500

DEFAULT_BASE_URL = "http://127.0.0.1:8080"

_UNSET = object()

_TRUTHY = {"1", "true", "yes", "on", "y", "oui"}
_FALSY = {"0", "false", "no", "off", "n", "non"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    return default


def _env_float(name: str, default: float | None) -> float | None:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


class ThotSecureClient:
    """Client synchrone pour l'API Thot Secure.

    Paramètres
    ----------
    base_url :
        Racine du service, par défaut ``THOT_URL`` ou ``http://127.0.0.1:8080``.
        Le préfixe ``/api/v1`` est ajouté par le client pour les routes métier ; les routes
        publiques (``/healthz``, ``/readyz``, ``/version``, ``/metrics``) sont appelées à la racine,
        conformément au contrat §4.1.
    api_key :
        Clé ``ao_…``, par défaut ``THOT_API_KEY``. Transmise via l'en-tête ``X-API-Key``.
    tenant_id :
        Identifiant de tenant utilisé (a) comme valeur par défaut des routes préfixées par un
        tenant, (b) dans l'URL du WebSocket. Le cloisonnement réel est dérivé de la clé API côté
        serveur (contrat §1, invariant 4) : aucune en-tête non documentée n'est inventée.
    timeout : délai d'attente par requête, en secondes.
    max_retries : nombre de nouveaux essais (hors essai initial) sur 429/502/503/504 et erreurs réseau.
    verify_tls : vérification du certificat TLS (``True`` par défaut). ``False`` → avertissement.
    transport : transport injectable (tests, instrumentation, proxy maison).
    """

    #: Préfixe des routes métier (contrat §4).
    API_PREFIX = "/api/v1"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        tenant_id: str | None = None,
        *,
        timeout: float | None = None,
        max_retries: int | None = None,
        verify_tls: bool | None = None,
        transport: Transport | None = None,
        user_agent: str | None = None,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        max_retry_after: float = 60.0,
        prefer_httpx: bool = True,
        sleep: Any | None = None,
        rand: Any | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("THOT_URL") or DEFAULT_BASE_URL).rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url doit commencer par http:// ou https://")

        self.api_key = api_key if api_key is not None else os.environ.get("THOT_API_KEY")
        self.tenant_id = tenant_id if tenant_id is not None else os.environ.get("THOT_TENANT_ID")

        self.timeout = float(timeout if timeout is not None else (_env_float("THOT_TIMEOUT", None) or 30.0))
        self.max_retries = int(
            max_retries if max_retries is not None else (_env_float("THOT_MAX_RETRIES", None) or 3)
        )
        self.verify_tls = bool(verify_tls if verify_tls is not None else _env_bool("THOT_VERIFY_TLS", True))
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self._closed = False

        if not self.verify_tls:
            warnings.warn(
                "ThotSecureClient(verify_tls=False) : la vérification du certificat TLS est "
                "DÉSACTIVÉE. N'utilisez cette option que contre une instance locale de "
                "développement — jamais en production.",
                RuntimeWarning,
                stacklevel=2,
            )
            logger.warning("Thot Secure: vérification TLS désactivée (verify_tls=False)")

        base_transport = transport or create_transport(
            verify_tls=self.verify_tls, prefer_httpx=prefer_httpx, timeout=self.timeout
        )
        retry_kwargs: dict[str, Any] = {
            "max_retries": self.max_retries,
            "backoff_base": backoff_base,
            "backoff_max": backoff_max,
            "max_retry_after": max_retry_after,
        }
        if sleep is not None:
            retry_kwargs["sleep"] = sleep
        if rand is not None:
            retry_kwargs["rand"] = rand
        self._transport: Transport = RetryingTransport(base_transport, **retry_kwargs)

    # ==================================================================================
    # Cycle de vie
    # ==================================================================================

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        """Ferme le transport sous-jacent. Idempotent."""
        if not self._closed:
            try:
                self._transport.close()
            finally:
                self._closed = True

    def __repr__(self) -> str:  # pragma: no cover - jamais de secret dans le repr
        return "ThotSecureClient(base_url={!r}, tenant_id={!r}, api_key={})".format(
            self.base_url,
            self.tenant_id,
            "'***'" if self.api_key else "None",
        )

    # ==================================================================================
    # Bas niveau
    # ==================================================================================

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return self.base_url + path

    def _api(self, path: str) -> str:
        return self.API_PREFIX + path

    @staticmethod
    def _compact(**kwargs: Any) -> dict[str, Any]:
        """Retire les valeurs ``None`` d'un corps de requête."""
        return {k: v for k, v in kwargs.items() if v is not None}

    @staticmethod
    def _qparams(**kwargs: Any) -> dict[str, Any]:
        """Prépare les paramètres de requête (``None`` retiré, booléens en minuscules)."""
        params: dict[str, Any] = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            if isinstance(value, bool):
                params[key] = "true" if value else "false"
            else:
                params[key] = value
        return params

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = _UNSET,
        data: str | bytes | None = None,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        retry_safe: bool | None = None,
        auth: bool = True,
    ) -> HttpResponse:
        """Exécute une requête et lève une exception typée pour tout statut ≥ 400."""
        url = self._url(path)
        request_headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if auth and self.api_key:
            request_headers["X-API-Key"] = self.api_key

        content: bytes | None = None
        if json_body is not _UNSET:
            content = json.dumps(json_body, ensure_ascii=False, default=str).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif data is not None:
            content = data.encode("utf-8") if isinstance(data, str) else data
            request_headers["Content-Type"] = content_type or "application/json"

        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key
        if headers:
            request_headers.update(headers)

        request = HttpRequest(
            method=method.upper(),
            url=url,
            headers=request_headers,
            params=dict(params) if params else None,
            content=content,
            timeout=self.timeout,
            retry_safe=is_retry_safe(method, idempotency_key) if retry_safe is None else retry_safe,
        )
        logger.debug("Thot Secure %s %s", request.method, url.split("?")[0])

        response = self._transport.send(request)
        self._raise_for_status(response, method=method, url=request.full_url())
        return response

    @staticmethod
    def _raise_for_status(response: HttpResponse, *, method: str, url: str) -> None:
        if response.status_code < 400:
            return
        payload: Any = None
        text: str | None = None
        if response.content:
            try:
                payload = response.json()
            except (ValueError, UnicodeDecodeError):
                text = response.text
        raise error_from_response(
            response.status_code,
            payload,
            method=method,
            url=url,
            headers=response.headers,
            raw_text=text,
        )

    def _json(self, response: HttpResponse, *, required: bool = True) -> Any:
        """Décode le corps JSON d'une réponse (``None`` pour un ``204``)."""
        if not response.content:
            if required:
                return None
            return None
        try:
            return response.json()
        except (ValueError, UnicodeDecodeError) as exc:
            raise ThotSecureError(
                f"réponse non JSON ({response.status_code}) : {response.text[:200]}",
                code="invalid_response",
                status_code=response.status_code,
            ) from exc

    def _model(self, model: type, response: HttpResponse) -> Any:
        return model.from_dict(self._json(response) or {})

    def _page(self, model: type | None, response: HttpResponse) -> Page:
        return Page.from_payload(self._json(response), model)

    @staticmethod
    def _event_payload(event: Event | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(event, Event):
            return event.to_dict()
        if isinstance(event, Mapping):
            return dict(event)
        raise ValidationError(
            f"un événement doit être un Event ou un mapping, reçu {type(event).__name__!r}",
            code="validation_error",
            details={"type": type(event).__name__},
        )

    def _fill_tenant(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Renseigne ``tenant_id`` depuis la configuration du client si l'appelant l'a omis."""
        if not payload.get("tenant_id") and self.tenant_id:
            payload["tenant_id"] = self.tenant_id
        return payload

    # ==================================================================================
    # §4.1 Santé, méta, observabilité
    # ==================================================================================

    def whoami(self) -> dict[str, Any]:
        """``GET /api/v1/auth/whoami`` → tenant, rôle, capacités, mode d'autonomie."""
        return self._json(self._request("GET", self._api("/auth/whoami")))

    def healthz(self) -> dict[str, Any]:
        """``GET /healthz`` (public) → ``{"status","version","uptime_s"}``."""
        return self._json(self._request("GET", "/healthz", auth=False))

    def readyz(self, *, raise_on_error: bool = False) -> dict[str, Any]:
        """``GET /readyz`` (public) — vérifie DB + bus + règles.

        Par défaut, un ``503`` ne lève pas d'exception mais retourne un dictionnaire
        ``{"status": "unavailable", "http_status": 503, ...}`` : c'est le comportement attendu
        par une sonde d'orchestrateur. Mettre ``raise_on_error=True`` pour lever à la place.
        """
        try:
            return self._json(self._request("GET", "/readyz", auth=False))
        except ServerError as exc:
            if raise_on_error:
                raise
            return {
                "status": "unavailable",
                "http_status": exc.status_code,
                "error": exc.message,
                "details": exc.details,
            }

    def version(self) -> dict[str, Any]:
        """``GET /version`` (public) → version, commit, licence, mode d'autonomie global."""
        return self._json(self._request("GET", "/version", auth=False))

    def metrics(self) -> str:
        """``GET /metrics`` (public, réseau interne) → exposition Prometheus en texte."""
        response = self._request("GET", "/metrics", auth=False, headers={"Accept": "text/plain"})
        return response.text

    # ==================================================================================
    # §4.2 Tenants & clés
    # ==================================================================================

    def list_tenants(self) -> Page:
        """``GET /api/v1/tenants`` (capacité ``admin:tenants``)."""
        return self._page(Tenant, self._request("GET", self._api("/tenants")))

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        *,
        mode: str = "supervised",
        autonomy_allowlist: Sequence[str] | None = None,
        dry_run: bool | None = None,
    ) -> Tenant:
        """``POST /api/v1/tenants`` (capacité ``admin:tenants``).

        ``mode`` ∈ ``manual|supervised|auto``. ``dry_run`` n'est envoyé que s'il est précisé :
        le corps documenté du contrat ne le mentionne pas, le serveur applique son défaut sûr.
        """
        if mode not in Tenant.MODES:
            raise ValidationError(
                "mode invalide : {!r} (attendu : {})".format(mode, ", ".join(Tenant.MODES)),
                code="validation_error",
            )
        body = self._compact(
            tenant_id=tenant_id,
            name=name,
            mode=mode,
            autonomy_allowlist=list(autonomy_allowlist) if autonomy_allowlist is not None else None,
            dry_run=dry_run,
        )
        return self._model(Tenant, self._request("POST", self._api("/tenants"), json_body=body))

    def get_tenant(self, tenant_id: str | None = None) -> Tenant:
        """``GET /api/v1/tenants/{id}`` (capacité ``read:stats``, self)."""
        return self._model(
            Tenant, self._request("GET", self._api(f"/tenants/{self._require_tenant(tenant_id)}"))
        )

    def update_tenant(
        self,
        tenant_id: str | None = None,
        *,
        mode: str | None = None,
        dry_run: bool | None = None,
        name: str | None = None,
        autonomy_allowlist: Sequence[str] | None = None,
    ) -> Tenant:
        """``PATCH /api/v1/tenants/{id}`` (capacité ``admin:tenants``).

        ⚠️ Activer ``mode="auto"`` ou ``dry_run=False`` change le niveau d'autonomie d'un tenant :
        c'est une décision de sécurité qui doit être volontaire, limitée et journalisée.
        """
        if mode is not None and mode not in Tenant.MODES:
            raise ValidationError(
                "mode invalide : {!r} (attendu : {})".format(mode, ", ".join(Tenant.MODES)),
                code="validation_error",
            )
        body = self._compact(
            mode=mode,
            dry_run=dry_run,
            name=name,
            autonomy_allowlist=list(autonomy_allowlist) if autonomy_allowlist is not None else None,
        )
        if not body:
            raise ValidationError(
                "update_tenant : aucun champ à modifier (mode, dry_run, name, autonomy_allowlist)",
                code="validation_error",
            )
        path = self._api(f"/tenants/{self._require_tenant(tenant_id)}")
        return self._model(Tenant, self._request("PATCH", path, json_body=body))

    def create_key(
        self,
        role: str = "responder",
        *,
        label: str | None = None,
        tenant_id: str | None = None,
    ) -> ApiKey:
        """``POST /api/v1/tenants/{id}/keys`` (capacité ``admin:keys``).

        La valeur ``api_key`` n'est **affichée qu'une seule fois** : le client ne la journalise
        jamais et ne la conserve pas.
        """
        roles = ("viewer", "analyst", "responder", "admin")
        if role not in roles:
            raise ValidationError(
                "rôle invalide : {!r} (attendu : {})".format(role, ", ".join(roles)),
                code="validation_error",
            )
        path = self._api(f"/tenants/{self._require_tenant(tenant_id)}/keys")
        return self._model(
            ApiKey, self._request("POST", path, json_body=self._compact(role=role, label=label))
        )

    def list_keys(self, tenant_id: str | None = None) -> Page:
        """``GET /api/v1/tenants/{id}/keys`` (capacité ``admin:keys``)."""
        path = self._api(f"/tenants/{self._require_tenant(tenant_id)}/keys")
        return self._page(ApiKey, self._request("GET", path))

    def revoke_key(self, key_id: str) -> None:
        """``DELETE /api/v1/keys/{key_id}`` (capacité ``admin:keys``) → ``204``."""
        self._request("DELETE", self._api(f"/keys/{key_id}"))

    # ==================================================================================
    # §4.3 Événements
    # ==================================================================================

    def ingest_event(self, event: Event | Mapping[str, Any]) -> IngestResult:
        """``POST /api/v1/events`` avec un événement unique (capacité ``write:events``)."""
        body = self._fill_tenant(self._event_payload(event))
        return self._model(IngestResult, self._request("POST", self._api("/events"), json_body=body))

    def ingest_events(
        self,
        events: Iterable[Event | Mapping[str, Any]],
        *,
        chunk_size: int = MAX_BATCH_SIZE,
    ) -> IngestResult:
        """``POST /api/v1/events`` avec ``{"events": […]}`` (capacité ``write:events``).

        Le contrat impose **au plus 500 événements par lot** : les lots plus grands sont découpés
        automatiquement et les réponses fusionnées. Le découpage rend l'appel sûr côté réseau
        (contre-pression naturelle : chaque lot est un aller-retour distinct).
        """
        if chunk_size < 1 or chunk_size > MAX_BATCH_SIZE:
            raise ValidationError(
                "chunk_size doit être compris entre 1 et %d" % MAX_BATCH_SIZE,
                code="validation_error",
            )
        payloads = [self._fill_tenant(self._event_payload(e)) for e in events]
        if not payloads:
            return IngestResult()

        total = IngestResult()
        for start in range(0, len(payloads), chunk_size):
            chunk = payloads[start : start + chunk_size]
            response = self._request("POST", self._api("/events"), json_body={"events": chunk})
            total = total.merge(self._model(IngestResult, response))
        return total

    def list_events(
        self,
        *,
        kind: str | None = None,
        source_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        q: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page:
        """``GET /api/v1/events`` (capacité ``read:events``) — ``limit ≤ 500``, défaut 100."""
        params = self._qparams(
            kind=kind, source_type=source_type, since=since, until=until, q=q, limit=limit, cursor=cursor
        )
        return self._page(Event, self._request("GET", self._api("/events"), params=params))

    def get_event(self, event_id: str) -> Event:
        """``GET /api/v1/events/{event_id}`` (capacité ``read:events``)."""
        return self._model(Event, self._request("GET", self._api(f"/events/{event_id}")))

    def iter_events(self, *, max_pages: int = 1000, **filters: Any) -> Iterator[Event]:
        """Itère sur tous les événements en suivant le ``cursor``."""
        return self._paginate(lambda cursor: self.list_events(cursor=cursor, **filters), max_pages=max_pages)

    # ==================================================================================
    # §4.4 Findings
    # ==================================================================================

    def list_findings(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        min_risk: float | None = None,
        sort: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page:
        """``GET /api/v1/findings`` (capacité ``read:findings``).

        ``sort`` ∈ ``risk_score|last_seen``.
        """
        params = self._qparams(
            status=status,
            severity=severity,
            rule_id=rule_id,
            since=since,
            until=until,
            min_risk=min_risk,
            sort=sort,
            limit=limit,
            cursor=cursor,
        )
        return self._page(Finding, self._request("GET", self._api("/findings"), params=params))

    def get_finding(self, finding_id: str) -> Finding:
        """``GET /api/v1/findings/{id}`` → ``Finding`` + actions liées (dans ``extra['actions']``)."""
        return self._model(Finding, self._request("GET", self._api(f"/findings/{finding_id}")))

    def ack_finding(self, finding_id: str, *, comment: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/findings/{id}/ack`` (capacité ``write:findings``) → ``{"status":"acked"}``."""
        path = self._api(f"/findings/{finding_id}/ack")
        return self._json(self._request("POST", path, json_body=self._compact(comment=comment)))

    def close_finding(
        self,
        finding_id: str,
        resolution: str,
        *,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """``POST /api/v1/findings/{id}/close`` (capacité ``write:findings``).

        ``resolution`` ∈ ``true_positive|false_positive|mitigated``.
        """
        allowed = ("true_positive", "false_positive", "mitigated")
        if resolution not in allowed:
            raise ValidationError(
                "resolution invalide : {!r} (attendu : {})".format(resolution, ", ".join(allowed)),
                code="validation_error",
            )
        path = self._api(f"/findings/{finding_id}/close")
        return self._json(
            self._request("POST", path, json_body=self._compact(resolution=resolution, comment=comment))
        )

    def suppress_finding(
        self,
        finding_id: str,
        *,
        duration_seconds: int = 86400,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """``POST /api/v1/findings/{id}/suppress`` (capacité ``write:findings``).

        Crée une exception temporaire sur la règle : à utiliser avec un motif explicite.
        """
        path = self._api(f"/findings/{finding_id}/suppress")
        return self._json(
            self._request(
                "POST",
                path,
                json_body=self._compact(duration_seconds=duration_seconds, reason=reason),
            )
        )

    def get_report(self, finding_id: str, *, format: str = "md", as_bytes: bool = False) -> Any:
        """``GET /api/v1/findings/{id}/report?format=md|html|json|sarif`` (capacité ``read:findings``).

        Retourne le texte du rapport, ou des octets bruts si ``as_bytes=True``.
        """
        allowed = ("md", "html", "json", "sarif")
        if format not in allowed:
            raise ValidationError(
                "format invalide : {!r} (attendu : {})".format(format, ", ".join(allowed)),
                code="validation_error",
            )
        path = self._api(f"/findings/{finding_id}/report")
        response = self._request("GET", path, params={"format": format})
        return response.content if as_bytes else response.text

    def iter_findings(self, *, max_pages: int = 1000, **filters: Any) -> Iterator[Finding]:
        """Itère sur tous les findings en suivant le ``cursor``."""
        return self._paginate(
            lambda cursor: self.list_findings(cursor=cursor, **filters), max_pages=max_pages
        )

    # ==================================================================================
    # §4.5 Règles, politiques, playbooks
    # ==================================================================================

    def list_rules(self) -> Page:
        """``GET /api/v1/rules`` (capacité ``read:rules``)."""
        return self._page(Rule, self._request("GET", self._api("/rules")))

    def get_rule(self, rule_id: str) -> Rule:
        """``GET /api/v1/rules/{rule_id}`` → règle complète + YAML source (``rule.yaml_source``)."""
        return self._model(Rule, self._request("GET", self._api(f"/rules/{rule_id}")))

    def validate_rule(self, rule: str | Mapping[str, Any]) -> RuleValidation:
        """``POST /api/v1/rules/validate`` (capacité ``admin:rules``).

        ``rule`` peut être le YAML source (``str``) ou un dictionnaire JSON de règle.
        """
        if isinstance(rule, str):
            response = self._request(
                "POST",
                self._api("/rules/validate"),
                data=rule,
                content_type="application/yaml",
            )
        elif isinstance(rule, Mapping):
            response = self._request("POST", self._api("/rules/validate"), json_body=dict(rule))
        else:
            raise ValidationError(
                "validate_rule attend une chaîne YAML ou un mapping", code="validation_error"
            )
        return self._model(RuleValidation, response)

    def reload_rules(self) -> dict[str, Any]:
        """``POST /api/v1/rules/reload`` (capacité ``admin:rules``) → ``{"loaded":n,"errors":[…]}}``."""
        return self._json(self._request("POST", self._api("/rules/reload"), json_body={}))

    def list_policies(self) -> Any:
        """``GET /api/v1/policies`` (capacité ``read:policies``) : politiques + ordre de priorité."""
        return self._json(self._request("GET", self._api("/policies")))

    def reload_policies(self) -> dict[str, Any]:
        """``POST /api/v1/policies/reload`` (capacité ``admin:policies``)."""
        return self._json(self._request("POST", self._api("/policies/reload"), json_body={}))

    def list_playbooks(self) -> Page:
        """``GET /api/v1/playbooks`` (capacité ``read:rules``)."""
        return self._page(Playbook, self._request("GET", self._api("/playbooks")))

    # ==================================================================================
    # §4.6 Actions (SOAR)
    # ==================================================================================

    def plan_action(
        self,
        finding_id: str,
        playbook: str,
        *,
        params: Mapping[str, Any] | None = None,
        dry_run: bool = True,
        idempotency_key: str | None = None,
    ) -> Action:
        """``POST /api/v1/actions/plan`` (capacité ``execute:actions``) — aucun effet de bord.

        ``dry_run=True`` par défaut : la planification reste une simulation tant que l'appelant
        ne demande pas explicitement le contraire (contrat §1, invariant 1).
        """
        body = self._compact(
            finding_id=finding_id,
            playbook=playbook,
            params=dict(params or {}),
            dry_run=dry_run,
        )
        return self._model(
            Action,
            self._request(
                "POST",
                self._api("/actions/plan"),
                json_body=body,
                idempotency_key=idempotency_key,
            ),
        )

    def list_actions(
        self,
        *,
        status: str | None = None,
        playbook: str | None = None,
        finding_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page:
        """``GET /api/v1/actions`` (capacité ``read:findings``)."""
        params = self._qparams(
            status=status, playbook=playbook, finding_id=finding_id, limit=limit, cursor=cursor
        )
        return self._page(Action, self._request("GET", self._api("/actions"), params=params))

    def get_action(self, action_id: str) -> Action:
        """``GET /api/v1/actions/{id}`` (capacité ``read:findings``)."""
        return self._model(Action, self._request("GET", self._api(f"/actions/{action_id}")))

    def approve_action(self, action_id: str, *, comment: str | None = None) -> Action:
        """``POST /api/v1/actions/{id}/approve`` (capacité ``approve:actions``) → ``approved``."""
        path = self._api(f"/actions/{action_id}/approve")
        return self._model(Action, self._request("POST", path, json_body=self._compact(comment=comment)))

    def reject_action(self, action_id: str, *, reason: str | None = None) -> Action:
        """``POST /api/v1/actions/{id}/reject`` (capacité ``approve:actions``) → ``rejected`` (terminal)."""
        path = self._api(f"/actions/{action_id}/reject")
        return self._model(Action, self._request("POST", path, json_body=self._compact(reason=reason)))

    def execute_action(
        self,
        action_id: str,
        *,
        idempotency_key: str | None = None,
        dry_run: bool | None = None,
    ) -> Action:
        """``POST /api/v1/actions/{id}/execute`` (capacité ``execute:actions``).

        Le serveur refuse (``409``) une action encore ``pending_approval``. L'appel est idempotent
        dès qu'une ``idempotency_key`` est fournie : c'est la seule façon dont le SDK réessaiera
        automatiquement cette route (méthode ``POST``).
        """
        path = self._api(f"/actions/{action_id}/execute")
        body = self._compact(idempotency_key=idempotency_key, dry_run=dry_run)
        return self._model(
            Action,
            self._request("POST", path, json_body=body, idempotency_key=idempotency_key),
        )

    def rollback_action(
        self,
        action_id: str,
        *,
        reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> Action:
        """``POST /api/v1/actions/{id}/rollback`` (capacité ``execute:actions``).

        Refuse (``409``) une action déjà ``rolled_back``.
        """
        path = self._api(f"/actions/{action_id}/rollback")
        body = self._compact(reason=reason, idempotency_key=idempotency_key)
        return self._model(
            Action,
            self._request("POST", path, json_body=body, idempotency_key=idempotency_key),
        )

    def iter_actions(self, *, max_pages: int = 1000, **filters: Any) -> Iterator[Action]:
        """Itère sur toutes les actions en suivant le ``cursor``."""
        return self._paginate(lambda cursor: self.list_actions(cursor=cursor, **filters), max_pages=max_pages)

    # ==================================================================================
    # §4.7 Audit
    # ==================================================================================

    def list_audit(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page:
        """``GET /api/v1/audit`` (capacité ``read:audit``)."""
        params = self._qparams(
            since=since, until=until, action=action, actor=actor, limit=limit, cursor=cursor
        )
        return self._page(AuditRecord, self._request("GET", self._api("/audit"), params=params))

    def iter_audit(self, *, max_pages: int = 1000, **filters: Any) -> Iterator[AuditRecord]:
        """Itère sur tout le journal d'audit en suivant le ``cursor``."""
        return self._paginate(lambda cursor: self.list_audit(cursor=cursor, **filters), max_pages=max_pages)

    def verify_audit(self) -> AuditVerification:
        """``GET /api/v1/audit/verify`` (capacité ``read:audit``) → ``{"valid","records","broken_at"}``."""
        return self._model(AuditVerification, self._request("GET", self._api("/audit/verify")))

    def export_audit(
        self,
        *,
        format: str = "jsonl",
        since: str | None = None,
        until: str | None = None,
        as_bytes: bool = False,
    ) -> Any:
        """``GET /api/v1/audit/export?format=jsonl|cef`` (capacité ``read:audit``).

        Flux destiné à un SIEM/SOAR : retourne du texte, ou des octets si ``as_bytes=True``.
        """
        if format not in ("jsonl", "cef"):
            raise ValidationError(
                f"format invalide : {format!r} (attendu : jsonl, cef)", code="validation_error"
            )
        params = self._qparams(format=format, since=since, until=until)
        response = self._request("GET", self._api("/audit/export"), params=params)
        return response.content if as_bytes else response.text

    # ==================================================================================
    # §4.8 Stats, collecteurs
    # ==================================================================================

    def stats_overview(self) -> StatsOverview:
        """``GET /api/v1/stats/overview`` (capacité ``read:stats``)."""
        return self._model(StatsOverview, self._request("GET", self._api("/stats/overview")))

    def list_collectors(self) -> Page:
        """``GET /api/v1/collectors`` (capacité ``read:stats``)."""
        return self._page(CollectorStatus, self._request("GET", self._api("/collectors")))

    def run_collector(self, name: str) -> dict[str, Any]:
        """``POST /api/v1/collectors/{name}/run`` (capacité ``execute:actions``).

        Déclenche un run **sur les cibles déclarées du tenant** uniquement : le SDK n'offre aucune
        primitive de balayage arbitraire (contrat §10, « zéro capacité offensive »).
        """
        path = self._api(f"/collectors/{name}/run")
        return self._json(self._request("POST", path, json_body={}))

    # ==================================================================================
    # Flux temps réel (§4.8)
    # ==================================================================================

    def ws_url(self, *, types: Sequence[str] | None = None) -> str:
        """URL WebSocket ``/api/v1/ws/stream`` avec ``api_key`` et ``tenant_id``.

        Les navigateurs ne peuvent pas poser d'en-tête sur ``ws://`` : la clé passe donc en
        paramètre de requête (contrat §4). Utilisez ``wss://`` (base_url ``https://``) en production.
        """
        from .ws import build_ws_url

        return build_ws_url(
            base_url=self.base_url,
            api_key=self.api_key,
            tenant_id=self.tenant_id,
        )

    def stream(
        self,
        *,
        types: Sequence[str] | None = None,
        reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        heartbeat_seconds: float = 30.0,
    ) -> Iterator[Any]:
        """Itère sur les frames du WebSocket (``event``, ``finding``, ``action``, ``audit``, ``heartbeat``).

        Enveloppe :meth:`thotsecure_sdk.ws.WebSocketClient.stream` avec la configuration du client.
        """
        from .ws import WebSocketClient

        ws_client = WebSocketClient(
            base_url=self.base_url,
            api_key=self.api_key,
            tenant_id=self.tenant_id,
            verify_tls=self.verify_tls,
            reconnect=reconnect,
            max_reconnect_attempts=max_reconnect_attempts,
            heartbeat_seconds=heartbeat_seconds,
        )
        return ws_client.stream(types=types)

    # ==================================================================================
    # Helpers internes
    # ==================================================================================

    def _require_tenant(self, tenant_id: str | None) -> str:
        resolved = tenant_id or self.tenant_id
        if not resolved:
            raise ValidationError(
                "aucun tenant_id : passez-le en argument ou au constructeur (ou via THOT_TENANT_ID)",
                code="validation_error",
            )
        return resolved

    @staticmethod
    def _paginate(fetch: Any, *, max_pages: int = 1000) -> Iterator[Any]:
        """Suit ``next_cursor`` en se protégeant des boucles et des paginations infinies."""
        cursor: str | None = None
        seen: set = set()
        pages = 0
        while True:
            page = fetch(cursor)
            pages += 1
            yield from page.items
            cursor = page.next_cursor
            if not cursor or cursor in seen or pages >= max_pages:
                return
            seen.add(cursor)


# Réexport pratique : ``from thotsecure_sdk.client import normalize_event`` reste possible.
normalize_event = _helpers.normalize_event
