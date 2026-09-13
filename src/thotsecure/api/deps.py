"""Dépendances FastAPI : accès au service, authentification, capacités, portée tenant.

Chaque route déclare **la capacité** dont elle a besoin. Il n'y a jamais de vérification de
rôle codée en dur dans un routeur : ajouter un rôle demain ne demandera pas de parcourir
l'API à la recherche de contrôles d'accès oubliés.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, Header, Query, Request

from ..core.models import Principal, Tenant
from ..service import Service
from ..tenancy.rbac import require_capability


def get_service(request: Request) -> Service:
    """Récupère le service applicatif attaché à l'application."""
    service = getattr(request.app.state, "service", None)
    if service is None:  # pragma: no cover - configuration impossible en pratique
        raise RuntimeError("service non initialisé : l'application n'a pas démarré correctement")
    return service


ServiceDep = Annotated[Service, Depends(get_service)]


def get_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str | None:
    """Extrait la clé API (en-tête ``X-API-Key``, ou ``Authorization: Bearer``)."""
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def current_principal(
    request: Request,
    service: ServiceDep,
    api_key: Annotated[str | None, Depends(get_api_key)] = None,
) -> Principal:
    """Authentifie l'appelant.

    L'échec d'authentification est **audité** : une tentative répétée sur une clé révoquée est
    un signal de sécurité, pas une simple erreur HTTP.
    """
    from ..core.errors import AuthenticationError

    if not api_key:
        raise AuthenticationError(
            "clé API absente : renseignez l'en-tête X-API-Key",
            details={"header": "X-API-Key"},
        )
    try:
        principal = service.keys.authenticate(
            api_key, request_id=getattr(request.state, "request_id", None)
        )
    except AuthenticationError:
        service.metrics.inc("thotsecure_auth_failures_total")
        raise
    request.state.principal = principal
    service.metrics.inc(
        "thotsecure_api_requests_total", method=request.method, status="authenticated"
    )
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def require(capability: str) -> Callable[[Principal], Principal]:
    """Construit une dépendance exigeant une capacité précise."""

    def dependency(principal: PrincipalDep) -> Principal:
        require_capability(principal.role, capability, actor=principal.actor)
        return principal

    return dependency


def resolve_tenant(
    service: Service,
    principal: Principal,
    requested: str | None,
    *,
    capability_for_cross_tenant: str = "admin:tenants",
) -> Tenant:
    """Détermine le tenant ciblé et vérifie que l'appelant a le droit d'y accéder.

    Par défaut, un appelant ne travaille que sur son propre tenant. Un accès inter-tenant
    exige à la fois un paramètre explicite **et** une capacité d'administration — et il est
    journalisé par les routes concernées.
    """
    if requested and requested != principal.tenant_id:
        require_capability(principal.role, capability_for_cross_tenant, actor=principal.actor)
        tenant = service.store.get_tenant(requested)
        if tenant is None:
            from ..core.errors import NotFoundError

            raise NotFoundError(f"tenant inconnu: {requested}", details={"tenant_id": requested})
        return tenant
    return service.store.require_tenant(principal.tenant_id)


def tenant_query(
    principal: PrincipalDep,
    service: ServiceDep,
    tenant_id: Annotated[str | None, Query(description="Tenant ciblé (admin uniquement)")] = None,
) -> Tenant:
    """Résout le tenant depuis le paramètre de requête (usage administrateur)."""
    return resolve_tenant(service, principal, tenant_id)


TenantDep = Annotated[Tenant, Depends(tenant_query)]


def client_identifier(request: Request, principal: Principal | None = None) -> str:
    """Identifiant utilisé pour la limitation de débit (clé API, sinon adresse source)."""
    if principal is not None and principal.key_id:
        return f"key:{principal.key_id}"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return f"ip:{forwarded.split(',')[0].strip()}"
    return f"ip:{request.client.host if request.client else 'inconnu'}"


def pagination(
    limit: Annotated[int, Query(ge=1, le=500, description="Taille de page")] = 100,
    cursor: Annotated[str | None, Query(description="Curseur de pagination opaque")] = None,
) -> dict[str, Any]:
    return {"limit": limit, "cursor": cursor}


PaginationDep = Annotated[dict[str, Any], Depends(pagination)]


__all__ = [
    "PaginationDep",
    "PrincipalDep",
    "ServiceDep",
    "TenantDep",
    "client_identifier",
    "current_principal",
    "get_api_key",
    "get_service",
    "pagination",
    "require",
    "resolve_tenant",
    "tenant_query",
]
