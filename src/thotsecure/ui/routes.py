"""Console web embarquée : rendu côté serveur, **aucun outil Node requis**.

Pourquoi une console intégrée plutôt qu'uniquement un SPA : un RSSI qui installe Thot Secure
sur un réseau cloisonné doit pouvoir l'utiliser immédiatement, sans chaîne de build front-end,
sans CDN, sans accès Internet. Cette console est donc servie par l'API elle-même.

Sécurité de la console :

* session **signée** (HMAC-SHA256) dans un cookie ``HttpOnly`` + ``SameSite=Strict`` ;
* protection CSRF par jeton lié à la session (double soumission) ;
* aucune donnée injectée sans échappement (les preuves contiennent des charges d'attaque) ;
* les actions sensibles (approbation, exécution, annulation) restent des POST explicites avec
  double confirmation côté interface, et les capacités RBAC sont vérifiées côté serveur.
"""

from __future__ import annotations

import hmac
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import (
    FUNDING_ADDRESSES,
    FUNDING_ANTISCAM,
    FUNDING_DISCLAIMER,
    FUNDING_NETWORKS,
    __license__,
    __version__,
)
from ..core.errors import AuthenticationError, PermissionDeniedError, ThotSecureError
from ..core.logging_setup import get_logger
from ..core.util import humanize_duration, iso_z, utcnow
from ..scoring.risk import risk_band
from ..service import Service

log = get_logger("ui")

UI_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR = UI_DIR / "static"

COOKIE_NAME = "thot_session"
CSRF_FIELD = "csrf_token"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# --------------------------------------------------------------------------------------
# Aides de session et CSRF
# --------------------------------------------------------------------------------------


def _csrf_token(service: Service, session_token: str) -> str:
    """Jeton CSRF dérivé de la session : un jeton volé sur une autre session est inutilisable."""
    return hmac.new(
        service.settings.secret_key.encode("utf-8"),
        f"csrf:{session_token}".encode(),
        sha256,
    ).hexdigest()[:32]


def _principal(request: Request, service: Service) -> Any | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return service.keys.verify_session(token)


def _require_ui(service: Service, principal: Any | None, capability: str) -> None:
    if principal is None:
        raise AuthenticationError("session requise")
    if capability not in principal.capabilities:
        raise PermissionDeniedError(
            f"votre rôle '{principal.role}' ne permet pas cette action dans la console",
            details={"required": capability},
        )


def _render(
    request: Request,
    template: str,
    *,
    service: Service,
    principal: Any | None,
    **context: Any,
) -> HTMLResponse:
    """Rend une page avec le contexte commun (bandeau de sûreté, version, dons)."""
    session_token = request.cookies.get(COOKIE_NAME, "")
    return templates.TemplateResponse(
        request,
        template,
        {
            "version": __version__,
            "license": __license__,
            "principal": principal,
            "csrf_token": _csrf_token(service, session_token) if session_token else "",
            "safety": service.safety_report(),
            "dry_run": service.settings.dry_run,
            "autonomy": principal.role if principal else None,
            "funding": {
                "addresses": FUNDING_ADDRESSES,
                "networks": FUNDING_NETWORKS,
                "disclaimer": FUNDING_DISCLAIMER,
                "antiscam": FUNDING_ANTISCAM,
            },
            "now": iso_z(utcnow()),
            "now_dt": utcnow(),
            **context,
        },
    )


def _check_csrf(service: Service, request: Request, submitted: str) -> None:
    session_token = request.cookies.get(COOKIE_NAME, "")
    expected = _csrf_token(service, session_token) if session_token else ""
    if not expected or not hmac.compare_digest(expected, submitted or ""):
        raise PermissionDeniedError(
            "jeton CSRF invalide ou expiré : rechargez la page et réessayez",
            details={"hint": "la session a peut-être expiré"},
        )


# --------------------------------------------------------------------------------------
# Routeur
# --------------------------------------------------------------------------------------


def build_ui_router() -> APIRouter:
    router = APIRouter(tags=["console"], include_in_schema=False)

    # -- authentification --------------------------------------------------------------

    @router.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        service = _service(request)
        if _principal(request, service) is None:
            return RedirectResponse("/ui/login", status_code=303)
        return RedirectResponse("/ui/dashboard", status_code=303)

    @router.get("/ui/login", response_class=HTMLResponse)
    def login_form(request: Request) -> Response:
        service = _service(request)
        if _principal(request, service) is not None:
            return RedirectResponse("/ui/dashboard", status_code=303)
        return _render(request, "login.html", service=service, principal=None, error=None)

    @router.post("/ui/login")
    def login(
        request: Request,
        api_key: str = Form(...),
    ) -> Response:
        service = _service(request)
        try:
            principal = service.keys.authenticate(api_key.strip())
        except AuthenticationError as exc:
            service.metrics.inc("thotsecure_ui_login_failures_total")
            return _render(
                request,
                "login.html",
                service=service,
                principal=None,
                error=str(exc.message),
            )
        session = service.keys.issue_session(principal)
        response = RedirectResponse("/ui/dashboard", status_code=303)
        response.set_cookie(
            COOKIE_NAME,
            session,
            max_age=service.settings.session_ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=service.settings.tls_enabled,
            path="/",
        )
        service.audit.record(
            tenant_id=principal.tenant_id,
            actor=f"console:{principal.key_id or 'session'}",
            actor_role=principal.role,
            action="auth.success",
            target={"type": "console_session", "id": principal.key_id or "session"},
            after={"role": principal.role},
            context={"channel": "console web"},
        )
        service.metrics.inc("thotsecure_ui_logins_total", role=principal.role)
        return response

    @router.post("/ui/logout")
    def logout(request: Request, csrf_token: str = Form(default="")) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        with _suppress_errors():
            _check_csrf(service, request, csrf_token)
        if principal is not None:
            service.audit.record(
                tenant_id=principal.tenant_id,
                actor=f"console:{principal.key_id or 'session'}",
                actor_role=principal.role,
                action="auth.logout",
                target={"type": "console_session", "id": principal.key_id or "session"},
            )
        response = RedirectResponse("/ui/login", status_code=303)
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    # -- tableau de bord ---------------------------------------------------------------

    @router.get("/ui/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request, window_hours: int = 24) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:stats")
        tenant = service.store.require_tenant(principal.tenant_id)
        window = max(1, min(window_hours, 24 * 30))
        overview = service.store.stats_overview(tenant.tenant_id, window_hours=window)
        return _render(
            request,
            "dashboard.html",
            service=service,
            principal=principal,
            tenant=tenant,
            overview=overview,
            collectors=service.collectors.status(tenant.tenant_id),
            stats=service.stats(),
            collections=service.collections_summary(),
            risk_band=risk_band,
            humanize=humanize_duration,
        )

    # -- findings ----------------------------------------------------------------------

    @router.get("/ui/findings", response_class=HTMLResponse)
    def findings(
        request: Request,
        status: str | None = None,
        severity: str | None = None,
        min_risk: float | None = None,
        limit: int = 50,
    ) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:findings")
        items, _ = service.store.list_findings(
            principal.tenant_id,
            status=[status] if status else None,
            severity=[severity] if severity else None,
            min_risk=min_risk,
            limit=max(1, min(limit, 200)),
        )
        return _render(
            request,
            "findings.html",
            service=service,
            principal=principal,
            findings=items,
            filters={
                "status": status or "",
                "severity": severity or "",
                "min_risk": min_risk or "",
            },
            risk_band=risk_band,
            humanize=humanize_duration,
        )

    @router.get("/ui/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(request: Request, finding_id: str) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:findings")
        finding = service.store.get_finding(principal.tenant_id, finding_id)
        if finding is None:
            return _render(
                request,
                "not_found.html",
                service=service,
                principal=principal,
                message=f"Finding introuvable : {finding_id}",
            )
        tenant = service.store.require_tenant(principal.tenant_id)
        actions = service.store.actions_for_finding(principal.tenant_id, finding_id)
        decision = service.decision.decide_for_finding(
            finding, tenant, environment=service.settings.env
        )
        audit = [
            record
            for record in service.audit.tail(principal.tenant_id, limit=300)
            if record.target.get("id") in {finding_id, *[action.action_id for action in actions]}
        ][:30]
        playbooks = [
            playbook.summary()
            for _, playbook in sorted(service.playbooks.items())
            if playbook.reversible or "execute:actions" not in principal.capabilities
        ]
        return _render(
            request,
            "finding.html",
            service=service,
            principal=principal,
            tenant=tenant,
            finding=finding,
            actions=actions,
            decision=decision,
            audit=audit,
            playbooks=playbooks,
            risk_band=risk_band,
            humanize=humanize_duration,
        )

    # -- actions -----------------------------------------------------------------------

    @router.get("/ui/actions", response_class=HTMLResponse)
    def actions(request: Request, status: str | None = None) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:findings")
        items, _ = service.actions.list(
            principal.tenant_id, status=[status] if status else None, limit=100
        )
        return _render(
            request,
            "actions.html",
            service=service,
            principal=principal,
            tenant=service.store.require_tenant(principal.tenant_id),
            actions=items,
            filter_status=status or "",
            humanize=humanize_duration,
        )

    @router.post("/ui/actions/{action_id}/{operation}")
    def action_operation(
        request: Request,
        action_id: str,
        operation: str,
        csrf_token: str = Form(...),
        comment: str = Form(default=""),
    ) -> Response:
        """Exécute une transition d'action depuis la console (approve/reject/execute/rollback)."""
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "execute:actions")
        _check_csrf(service, request, csrf_token)
        tenant = service.store.require_tenant(principal.tenant_id)
        actor = f"console:{principal.key_id or principal.role}"

        try:
            if operation == "approve":
                service.actions.approve(
                    tenant=tenant,
                    action_id=action_id,
                    actor=actor,
                    actor_role=principal.role,
                    comment=comment,
                )
            elif operation == "reject":
                service.actions.reject(
                    tenant=tenant,
                    action_id=action_id,
                    actor=actor,
                    actor_role=principal.role,
                    reason=comment,
                )
            elif operation == "execute":
                service.actions.execute(
                    tenant=tenant, action_id=action_id, actor=actor, actor_role=principal.role
                )
            elif operation == "rollback":
                service.actions.rollback(
                    tenant=tenant,
                    action_id=action_id,
                    actor=actor,
                    actor_role=principal.role,
                    reason=comment or "annulation depuis la console",
                )
            else:
                raise PermissionDeniedError(f"opération inconnue: {operation}")
        except ThotSecureError as exc:
            return _render(
                request,
                "action_error.html",
                service=service,
                principal=principal,
                action_id=action_id,
                operation=operation,
                message=exc.message,
                code=exc.code,
            )
        return RedirectResponse(f"/ui/actions?status=&highlight={action_id}", status_code=303)

    # -- audit, règles, collecteurs ----------------------------------------------------

    @router.get("/ui/audit", response_class=HTMLResponse)
    def audit(request: Request, action: str | None = None) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:audit")
        records, _ = service.store.list_audit(principal.tenant_id, action=action, limit=200)
        return _render(
            request,
            "audit.html",
            service=service,
            principal=principal,
            records=records,
            integrity=service.audit.integrity_summary(principal.tenant_id),
            filter_action=action or "",
        )

    @router.post("/ui/audit/verify")
    def audit_verify(request: Request, csrf_token: str = Form(...)) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:audit")
        _check_csrf(service, request, csrf_token)
        verdict = service.audit.verify(tenant_id=principal.tenant_id)
        return _render(
            request,
            "audit.html",
            service=service,
            principal=principal,
            records=service.audit.tail(principal.tenant_id, limit=200),
            integrity={
                "valid": verdict.valid,
                "records": verdict.records,
                "broken_at": verdict.broken_at,
                "reason": verdict.reason,
                "checked_at": iso_z(verdict.checked_at),
            },
            filter_action="",
        )

    @router.get("/ui/rules", response_class=HTMLResponse)
    def rules(request: Request) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:rules")
        return _render(
            request,
            "rules.html",
            service=service,
            principal=principal,
            rules=service.detection.summaries(),
            policies=[policy.summary() for policy in service.decision.policies],
            playbooks=[playbook.summary() for _, playbook in sorted(service.playbooks.items())],
            diagnostics=service.collections_summary(),
        )

    @router.get("/ui/collectors", response_class=HTMLResponse)
    def collectors(request: Request) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "read:stats")
        return _render(
            request,
            "collectors.html",
            service=service,
            principal=principal,
            collectors=service.collectors.status(principal.tenant_id),
            scope=service.targets.for_tenant(principal.tenant_id),
            scheduler_enabled=service.settings.collectors_enabled,
        )

    @router.post("/ui/collectors/{collector_name}/run")
    def run_collector(
        request: Request, collector_name: str, csrf_token: str = Form(...)
    ) -> Response:
        service = _service(request)
        principal = _principal(request, service)
        _require_ui(service, principal, "execute:actions")
        _check_csrf(service, request, csrf_token)
        service.collectors.run(
            collector_name, principal.tenant_id, actor=f"console:{principal.role}"
        )
        return RedirectResponse("/ui/collectors", status_code=303)

    # -- soutien -----------------------------------------------------------------------

    @router.get("/ui/support", response_class=HTMLResponse)
    def support(request: Request) -> Response:
        service = _service(request)
        return _render(
            request,
            "support.html",
            service=service,
            principal=_principal(request, service),
        )

    # -- jeton de flux temps réel ------------------------------------------------------

    @router.get("/ui/ws-token")
    def ws_token(request: Request) -> Response:
        """Retourne un jeton de session à usage unique pour ouvrir le WebSocket.

        Un navigateur ne peut pas positionner d'en-tête d'authentification sur ``ws://`` : la
        clé API ne doit donc **jamais** transiter dans l'URL (elle finirait dans les journaux
        du serveur web et l'historique du navigateur). On échange ici une session contre un
        jeton court.
        """
        service = _service(request)
        principal = _principal(request, service)
        if principal is None:
            raise AuthenticationError("session requise")
        token = service.keys.issue_session(principal, ttl_seconds=300)
        return JSONResponse({"token": token, "expires_in": 300, "tenant_id": principal.tenant_id})

    return router


# --------------------------------------------------------------------------------------


def _service(request: Request) -> Service:
    service = getattr(request.app.state, "service", None)
    if service is None:  # pragma: no cover
        raise RuntimeError("service non initialisé")
    return service


class _suppress_errors:
    """Ignore une erreur CSRF à la déconnexion : on doit toujours pouvoir se déconnecter."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, ThotSecureError)


__all__ = ["COOKIE_NAME", "CSRF_FIELD", "STATIC_DIR", "TEMPLATES_DIR", "build_ui_router"]
