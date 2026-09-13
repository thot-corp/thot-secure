"""Gestion des tenants et des clés API (administration)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response

from ...core.models import Tenant
from ...tenancy.rbac import ROLE_DESCRIPTIONS, role_matrix
from ..deps import PrincipalDep, ServiceDep, require
from ..schemas import KeyCreateRequest, TenantCreateRequest, TenantUpdateRequest

router = APIRouter(prefix="/api/v1", tags=["tenants"])


@router.get("/tenants", summary="Lister les tenants")
def list_tenants(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("admin:tenants")(principal)
    tenants = service.store.list_tenants()
    return {
        "items": [
            {
                **tenant.model_dump(mode="json"),
                "keys": len(service.keys.list_keys(tenant.tenant_id)),
                "collectors_enabled": service.settings.collectors_enabled,
            }
            for tenant in tenants
        ],
        "count": len(tenants),
    }


@router.post("/tenants", status_code=201, summary="Créer un tenant")
def create_tenant(
    payload: TenantCreateRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    require("admin:tenants")(principal)
    tenant = Tenant(
        tenant_id=payload.tenant_id,
        name=payload.name,
        mode=payload.mode,
        dry_run=payload.dry_run,
        autonomy_allowlist=payload.autonomy_allowlist,
        protected_targets=payload.protected_targets,
        max_actions_per_hour=payload.max_actions_per_hour,
        cooldown_seconds=payload.cooldown_seconds,
        asset_criticality=payload.asset_criticality,
    )
    stored = service.store.upsert_tenant(tenant)
    service.audit.record(
        tenant_id=stored.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action="tenant.create",
        target={"type": "tenant", "id": stored.tenant_id},
        after=stored.model_dump(mode="json"),
        context={"created_by": principal.actor},
    )
    return stored.model_dump(mode="json")


@router.get("/tenants/{tenant_id}", summary="Détail d'un tenant")
def get_tenant(tenant_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:stats")(principal)
    from ..deps import resolve_tenant

    tenant = resolve_tenant(service, principal, tenant_id)
    return {
        **tenant.model_dump(mode="json"),
        "scope": service.targets.for_tenant(tenant.tenant_id).describe(),
        "capabilities": sorted(principal.capabilities),
        "role_descriptions": ROLE_DESCRIPTIONS if principal.role == "admin" else None,
        "roles": role_matrix() if principal.role == "admin" else None,
    }


@router.patch("/tenants/{tenant_id}", summary="Modifier un tenant (autonomie, dry-run, périmètre)")
def update_tenant(
    tenant_id: str, payload: TenantUpdateRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Modifie un tenant.

    Toute modification est auditée avec l'**avant/après**. Désactiver ``dry_run`` ou passer en
    mode ``auto`` change le niveau de risque de tout le tenant : c'est précisément le genre de
    changement qu'un auditeur doit pouvoir retrouver, avec son auteur et sa date.
    """
    require("admin:tenants")(principal)
    before = service.store.require_tenant(tenant_id).model_dump(mode="json")
    changes = payload.model_dump(exclude_none=True)
    updated = service.store.update_tenant(tenant_id, **changes)
    service.audit.record_state_change(
        tenant_id=updated.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action="tenant.update",
        target={"type": "tenant", "id": updated.tenant_id},
        before={key: before.get(key) for key in changes},
        after={key: updated.model_dump(mode="json").get(key) for key in changes},
        context={
            "dry_run_disabled": changes.get("dry_run") is False,
            "autonomy_changed": "mode" in changes,
        },
    )
    return updated.model_dump(mode="json")


@router.post("/tenants/{tenant_id}/keys", status_code=201, summary="Créer une clé API")
def create_key(
    tenant_id: str, payload: KeyCreateRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Crée une clé API. **Le secret n'est affiché qu'une seule fois.**"""
    require("admin:keys")(principal)
    from ..deps import resolve_tenant

    tenant = resolve_tenant(service, principal, tenant_id)
    info, api_key = service.keys.create(
        tenant_id=tenant.tenant_id,
        role=payload.role,
        label=payload.label,
        actor=principal.actor,
        actor_role=principal.role,
    )
    return {
        **info.model_dump(mode="json"),
        "api_key": api_key,
        "warning": (
            "Cette clé ne sera plus jamais affichée. Conservez-la dans un coffre de secrets "
            "(Vault, SOPS, gestionnaire de mots de passe d'équipe)."
        ),
    }


@router.get("/tenants/{tenant_id}/keys", summary="Lister les clés d'un tenant (sans secret)")
def list_keys(tenant_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("admin:keys")(principal)
    from ..deps import resolve_tenant

    tenant = resolve_tenant(service, principal, tenant_id)
    keys = service.keys.list_keys(tenant.tenant_id)
    return {
        "items": [key.model_dump(mode="json") for key in keys],
        "count": len(keys),
        "active": sum(1 for key in keys if key.active),
    }


@router.delete("/keys/{key_id}", status_code=204, summary="Révoquer une clé API")
def revoke_key(key_id: str, service: ServiceDep, principal: PrincipalDep) -> Response:
    require("admin:keys")(principal)
    service.keys.revoke(key_id=key_id, tenant_id=principal.tenant_id, actor=principal.actor)
    service.metrics.inc("thotsecure_keys_revoked_total")
    return Response(status_code=204)


@router.get("/tenants/{tenant_id}/scope", summary="Périmètre déclaré du tenant")
def get_scope(tenant_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    """Retourne le périmètre déclaré : c'est lui qui autorise (ou non) toute action."""
    require("read:findings")(principal)
    from ..deps import resolve_tenant

    tenant = resolve_tenant(service, principal, tenant_id)
    scope = service.targets.for_tenant(tenant.tenant_id)
    return {
        "declared": service.targets.has_tenant(tenant.tenant_id),
        "scope": scope.describe(),
        "protected_targets": tenant.protected_targets,
        "autonomy_allowlist": tenant.autonomy_allowlist,
        "require_target_declaration": service.settings.require_target_declaration,
        "generated_at": service.started_at.isoformat(),
    }


__all__ = ["router"]
