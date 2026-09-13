"""Actions SOAR : planification, approbation, exécution, annulation.

C'est l'API qui peut changer l'état de l'infrastructure. Elle est donc la plus contrainte :

* ``plan`` n'a **aucun** effet de bord (il est sûr d'appeler ``plan``) ;
* ``execute`` refuse une action non approuvée si elle n'est pas simulée ;
* ``rollback`` est audité comme une action à part entière ;
* chaque réponse contient l'état complet de l'action, y compris la disponibilité du rollback.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from ...core.errors import ConflictError, NotFoundError
from ...core.models import Action
from ..deps import PrincipalDep, ServiceDep, require
from ..schemas import ActionDecisionRequest, ActionPlanRequest, ActionRejectRequest

router = APIRouter(prefix="/api/v1", tags=["actions"])


@router.post("/actions/plan", status_code=201, summary="Planifier une contre-mesure (sans effet)")
def plan_action(
    payload: ActionPlanRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Prépare une action et retourne son plan complet.

    Utile pour relire une action avant de l'approuver, et pour faire des répétitions à blanc
    (``dry_run: true``) sans risque.
    """
    require("execute:actions")(principal)
    tenant = service.store.require_tenant(principal.tenant_id)

    finding = None
    if payload.finding_id:
        finding = service.store.get_finding(principal.tenant_id, payload.finding_id)
        if finding is None:
            raise NotFoundError(
                f"finding introuvable: {payload.finding_id}",
                details={"finding_id": payload.finding_id},
            )

    action = service.actions.plan(
        tenant=tenant,
        playbook_name=payload.playbook,
        actor=principal.actor,
        actor_role=principal.role,
        finding=finding,
        params=payload.params,
        mode="manual",
        dry_run=payload.dry_run,
        reason=payload.reason or f"planification via API par {principal.actor}",
    )
    return _action_payload(service, action, tenant)


@router.get("/actions", summary="Lister les actions")
def list_actions(
    service: ServiceDep,
    principal: PrincipalDep,
    status_filter: list[str] | None = Query(default=None, alias="status"),
    playbook: str | None = None,
    finding_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = None,
) -> dict[str, Any]:
    require("read:findings")(principal)
    actions, next_cursor = service.actions.list(
        principal.tenant_id,
        status=status_filter,
        playbook=playbook,
        finding_id=finding_id,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [action.model_dump(mode="json") for action in actions],
        "count": len(actions),
        "next_cursor": next_cursor,
        "pending_approval": sum(1 for action in actions if action.status == "pending_approval"),
    }


@router.get("/actions/{action_id}", summary="Détail d'une action")
def get_action(action_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:findings")(principal)
    action = _require_action(service, principal.tenant_id, action_id)
    tenant = service.store.require_tenant(principal.tenant_id)
    return _action_payload(service, action, tenant)


@router.post("/actions/{action_id}/approve", summary="Approuver une action")
def approve_action(
    action_id: str,
    payload: ActionDecisionRequest,
    service: ServiceDep,
    principal: PrincipalDep,
) -> dict[str, Any]:
    """Approuve une action. L'approbateur est enregistré nommément dans l'audit."""
    require("approve:actions")(principal)
    tenant = service.store.require_tenant(principal.tenant_id)
    action = service.actions.approve(
        tenant=tenant,
        action_id=action_id,
        actor=principal.actor,
        actor_role=principal.role,
        comment=payload.comment,
    )
    service.metrics.inc("thotsecure_actions_approved_total", playbook=action.playbook)
    return _action_payload(service, action, tenant)


@router.post("/actions/{action_id}/reject", summary="Rejeter une action")
def reject_action(
    action_id: str,
    payload: ActionRejectRequest,
    service: ServiceDep,
    principal: PrincipalDep,
) -> dict[str, Any]:
    require("approve:actions")(principal)
    tenant = service.store.require_tenant(principal.tenant_id)
    action = service.actions.reject(
        tenant=tenant,
        action_id=action_id,
        actor=principal.actor,
        actor_role=principal.role,
        reason=payload.reason,
    )
    service.metrics.inc("thotsecure_actions_rejected_total", playbook=action.playbook)
    return _action_payload(service, action, tenant)


@router.post("/actions/{action_id}/execute", summary="Exécuter une action approuvée")
def execute_action(action_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    """Exécute une action.

    Trois refus possibles, tous explicites :

    * l'action n'est pas approuvée et n'est pas simulée (``409``) ;
    * la cible est devenue protégée entre-temps (``403``) ;
    * l'action est déjà terminale (``409``).
    """
    require("execute:actions")(principal)
    tenant = service.store.require_tenant(principal.tenant_id)
    before = _require_action(service, principal.tenant_id, action_id)
    action = service.actions.execute(
        tenant=tenant, action_id=action_id, actor=principal.actor, actor_role=principal.role
    )
    service.metrics.inc("thotsecure_actions_total", playbook=action.playbook, status=action.status)
    if action.mode == "auto":
        service.metrics.inc("thotsecure_actions_auto_total", playbook=action.playbook)
    if action.status == "failed":
        service.metrics.inc("thotsecure_actions_failed_total", playbook=action.playbook)
    return {
        **_action_payload(service, action, tenant),
        "previous_status": before.status,
    }


@router.post("/actions/{action_id}/rollback", summary="Annuler une action (rollback)")
def rollback_action(
    action_id: str,
    service: ServiceDep,
    principal: PrincipalDep,
    reason: str = Query(default="annulation via API", max_length=300),
) -> dict[str, Any]:
    """Annule une action exécutée.

    L'annulation est une opération de première classe — pas une exception, pas un script
    manuel : elle est donc exposée, contrôlée par capacité et auditée.
    """
    require("execute:actions")(principal)
    tenant = service.store.require_tenant(principal.tenant_id)
    action = service.actions.rollback(
        tenant=tenant, action_id=action_id, actor=principal.actor, actor_role=principal.role, reason=reason
    )
    service.metrics.inc("thotsecure_rollbacks_total", playbook=action.playbook)
    return _action_payload(service, action, tenant)


@router.get("/playbooks", summary="Lister les playbooks disponibles")
def list_playbooks(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:rules")(principal)
    return {
        "items": [playbook.summary() for _, playbook in sorted(service.playbooks.items())],
        "count": len(service.playbooks),
        "connectors": {
            name: service.connectors.get(name).description
            for name in sorted(service.connectors.configuration)
        },
        "simulation_active": service.connectors.stats().get("simulated_only", True),
    }


# --------------------------------------------------------------------------------------


def _require_action(service: ServiceDep, tenant_id: str, action_id: str) -> Action:
    action = service.store.get_action(tenant_id, action_id)
    if action is None:
        raise NotFoundError(f"action introuvable: {action_id}", details={"action_id": action_id})
    return action


def _action_payload(service: ServiceDep, action: Action, tenant: Any) -> dict[str, Any]:
    """Réponse enrichie : l'appelant doit savoir ce qui va *réellement* se passer."""
    playbook = service.playbooks.get(action.playbook)
    payload = action.model_dump(mode="json")
    payload["effective_dry_run"] = bool(service.settings.dry_run or tenant.dry_run or action.dry_run)
    payload["playbook_reversible"] = bool(playbook.reversible) if playbook else None
    payload["playbook_params_schema"] = (
        {name: spec.model_dump() for name, spec in playbook.params.items()} if playbook else {}
    )
    payload["target_in_declared_scope"] = (
        service.targets.for_tenant(action.tenant_id).owns(action.target.value)
        or bool(service.targets.for_tenant(action.tenant_id).assets)
    )
    payload["protected_target"] = tenant.is_protected(action.target.value)
    if action.status == "pending_approval":
        payload["next_step"] = f"POST /api/v1/actions/{action.action_id}/approve"
    elif action.status == "approved":
        payload["next_step"] = f"POST /api/v1/actions/{action.action_id}/execute"
    elif action.status == "succeeded" and action.rollback.available:
        payload["next_step"] = f"POST /api/v1/actions/{action.action_id}/rollback"
    return payload


__all__ = ["router"]
