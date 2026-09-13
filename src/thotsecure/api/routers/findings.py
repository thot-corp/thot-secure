"""Consultation et qualification des findings, génération des rapports."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Query, Response

from ...core.errors import ConflictError, NotFoundError
from ...core.util import parse_dt, utcnow
from ...reports import render as render_report
from ..deps import PrincipalDep, ServiceDep, require
from ..schemas import FindingCloseRequest, FindingCommentRequest, FindingSuppressRequest

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

#: Statuts pour lesquels une transition est légitime.
TRANSITIONS: dict[str, set[str]] = {
    "ack": {"open"},
    "close": {"open", "acked", "suppressed"},
    "suppress": {"open", "acked"},
    "reopen": {"acked", "closed"},
}


@router.get("", summary="Lister les findings")
def list_findings(
    service: ServiceDep,
    principal: PrincipalDep,
    status_filter: list[str] | None = Query(default=None, alias="status"),
    severity: list[str] | None = Query(default=None),
    rule_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=100),
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="risk_score", pattern="^(risk_score|last_seen)$"),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = None,
) -> dict[str, Any]:
    require("read:findings")(principal)
    findings, next_cursor = service.store.list_findings(
        principal.tenant_id,
        status=status_filter,
        severity=severity,
        rule_id=rule_id,
        since=parse_dt(since),
        until=parse_dt(until),
        min_risk=min_risk,
        q=q,
        sort=sort,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [finding.model_dump(mode="json") for finding in findings],
        "count": len(findings),
        "next_cursor": next_cursor,
        "filters": {
            "status": status_filter or [],
            "severity": severity or [],
            "min_risk": min_risk,
            "sort": sort,
        },
    }


@router.get("/{finding_id}", summary="Détail d'un finding (avec ses actions)")
def get_finding(finding_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:findings")(principal)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    actions = service.store.actions_for_finding(principal.tenant_id, finding_id)
    decision = service.decision.decide_for_finding(
        finding, service.store.require_tenant(principal.tenant_id), environment=service.settings.env
    )
    return {
        **finding.model_dump(mode="json"),
        "actions": [action.model_dump(mode="json") for action in actions],
        "current_decision": decision.model_dump(mode="json"),
        "audit_trail": [
            record.model_dump(mode="json")
            for record in service.audit.tail(principal.tenant_id, limit=200)
            if record.target.get("id") == finding_id
        ][:50],
    }


@router.post("/{finding_id}/ack", summary="Acquitter un finding")
def ack_finding(
    finding_id: str, payload: FindingCommentRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    require("write:findings")(principal)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    _assert_transition(finding.status, "ack")
    updated = _transition(
        service,
        principal,
        finding_id,
        status="acked",
        comment=payload.comment,
        audit_action="finding.ack",
    )
    return {"status": updated.status, "finding_id": finding_id, "comment": payload.comment}


@router.post("/{finding_id}/close", summary="Clôturer un finding")
def close_finding(
    finding_id: str, payload: FindingCloseRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Clôture un finding.

    La résolution est **obligatoire et typée** : « vrai positif », « faux positif »,
    « atténué »… Sans cette information, impossible de mesurer la qualité des règles de
    détection — et donc de les améliorer.
    """
    require("write:findings")(principal)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    _assert_transition(finding.status, "close")
    updated = _transition(
        service,
        principal,
        finding_id,
        status="closed",
        resolution=payload.resolution,
        comment=payload.comment,
        audit_action="finding.close",
    )
    service.metrics.inc("thotsecure_findings_closed_total", resolution=payload.resolution)
    return {
        "status": updated.status,
        "finding_id": finding_id,
        "resolution": payload.resolution,
        "comment": payload.comment,
    }


@router.post("/{finding_id}/suppress", summary="Supprimer le bruit d'un finding (exception temporaire)")
def suppress_finding(
    finding_id: str,
    payload: FindingSuppressRequest,
    service: ServiceDep,
    principal: PrincipalDep,
) -> dict[str, Any]:
    """Crée une exception de bruit **datée**.

    Une suppression sans date d'expiration est une cécité permanente : elle est donc interdite
    (durée minimum 60 s, maximum un an), et chaque exception est auditée.
    """
    require("write:findings")(principal)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    _assert_transition(finding.status, "suppress")
    expires_at = utcnow() + timedelta(seconds=payload.duration_seconds)
    suppression_id = service.store.add_suppression(
        tenant_id=principal.tenant_id,
        rule_id=finding.rule_id,
        dedup_key=payload.dedup_key or finding.dedup_key,
        reason=payload.reason,
        expires_at=expires_at,
        created_by=principal.actor,
    )
    updated = _transition(
        service,
        principal,
        finding_id,
        status="suppressed",
        comment=payload.reason,
        audit_action="finding.suppress",
        context={"expires_at": expires_at.isoformat(), "suppression_id": suppression_id},
    )
    return {
        "status": updated.status,
        "finding_id": finding_id,
        "suppression_id": suppression_id,
        "expires_at": expires_at.isoformat(),
        "reason": payload.reason,
    }


@router.get("/{finding_id}/report", summary="Générer un rapport (md, html, json, sarif, cef)")
def finding_report(
    finding_id: str,
    service: ServiceDep,
    principal: PrincipalDep,
    format: str = Query(default="md", pattern="^(md|markdown|html|json|sarif|cef)$"),
) -> Response:
    require("read:findings")(principal)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    tenant = service.store.require_tenant(principal.tenant_id)
    actions = service.store.actions_for_finding(principal.tenant_id, finding_id)
    audit = [
        record
        for record in service.audit.tail(principal.tenant_id, limit=200)
        if record.target.get("id") in {finding_id, *[action.action_id for action in actions]}
    ][:30]
    try:
        content, media_type = render_report(
            finding, format, tenant=tenant, actions=actions, audit=audit
        )
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc
    filename = f"thotsecure-{finding_id}.{_extension(format)}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------------------


def _require_finding(service: ServiceDep, tenant_id: str, finding_id: str):
    finding = service.store.get_finding(tenant_id, finding_id)
    if finding is None:
        raise NotFoundError(f"finding introuvable: {finding_id}", details={"finding_id": finding_id})
    return finding


def _assert_transition(current: str, transition: str) -> None:
    allowed = TRANSITIONS.get(transition, set())
    if current not in allowed:
        raise ConflictError(
            f"transition '{transition}' impossible depuis le statut '{current}'",
            details={"current_status": current, "allowed_from": sorted(allowed)},
        )


def _transition(
    service: ServiceDep,
    principal: PrincipalDep,
    finding_id: str,
    *,
    status: str,
    audit_action: str,
    comment: str = "",
    resolution: str | None = None,
    context: dict[str, Any] | None = None,
):
    before = service.store.require_tenant(principal.tenant_id)
    finding = _require_finding(service, principal.tenant_id, finding_id)
    previous = {"status": finding.status, "resolution": finding.resolution}
    updated = service.store.update_finding(
        principal.tenant_id,
        finding_id,
        status=status,
        comment=comment or None,
        resolution=resolution,
    )
    service.audit.record_state_change(
        tenant_id=principal.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action=audit_action,
        target={"type": "finding", "id": finding_id},
        before=previous,
        after={"status": updated.status, "resolution": updated.resolution},
        context={"comment": comment[:500], "tenant": before.tenant_id, **(context or {})},
    )
    return updated


def _extension(fmt: str) -> str:
    return {"md": "md", "markdown": "md", "html": "html", "json": "json", "sarif": "sarif", "cef": "cef"}.get(
        fmt, "txt"
    )


__all__ = ["TRANSITIONS", "router"]
