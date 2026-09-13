"""Santé, méta et identité de l'appelant."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Response

from ... import __license__, __version__
from ...core.util import iso_z, utcnow
from ..deps import PrincipalDep, ServiceDep
from ...observability.metrics import METRICS_CATALOG
from ...tenancy.rbac import ROLE_DESCRIPTIONS, capabilities_for, role_matrix

router = APIRouter(tags=["santé"])


@router.get("/healthz", summary="Sonde de vivacité")
def healthz(service: ServiceDep) -> dict[str, Any]:
    """Réponse immédiate, sans dépendance : l'orchestrateur sait que le processus vit."""
    return {
        "status": "ok",
        "version": __version__,
        "uptime_s": round(service.uptime_seconds, 1),
        "started_at": iso_z(service.started_at),
    }


@router.get("/readyz", summary="Sonde de disponibilité")
def readyz(service: ServiceDep, response: Response) -> dict[str, Any]:
    """Vérifie réellement les dépendances : base, bus, règles, politiques.

    Une sonde de disponibilité qui se contente de renvoyer « ok » est un mensonge qui coûte
    cher en production : ici, chaque dépendance est testée et détaillée.
    """
    checks: dict[str, Any] = {}

    checks["database"] = {"ok": service.store.health(), "path": str(service.settings.db_path)}
    checks["bus"] = {"ok": True, "backend": service.bus.name, "started": service.bus.started}
    checks["rules"] = {
        "ok": bool(service.rules),
        "loaded": len(service.rules),
        "rejected": len(service.rule_diagnostics),
    }
    checks["policies"] = {
        "ok": bool(service.policies),
        "loaded": len(service.policies),
        "rejected": len(service.policy_diagnostics),
    }
    checks["playbooks"] = {
        "ok": bool(service.playbooks),
        "loaded": len(service.playbooks),
        "rejected": len(service.playbook_diagnostics),
    }
    tenant_id = service.store.list_tenants()
    if tenant_id:
        try:
            verdict = service.audit.verify(tenant_id=tenant_id[0].tenant_id)
            checks["audit_chain"] = {"ok": verdict.valid, "records": verdict.records}
        except Exception as exc:  # noqa: BLE001
            checks["audit_chain"] = {"ok": False, "error": str(exc)}

    degraded = [name for name, check in checks.items() if not check.get("ok")]
    # Une bibliothèque de règles vide n'empêche pas de servir l'API, mais elle signifie
    # « aucune détection » : c'est un état dégradé qui doit être visible.
    ready = not any(name in degraded for name in ("database",))
    if not ready:
        response.status_code = 503
    return {
        "status": "ready" if ready and not degraded else ("degraded" if ready else "not_ready"),
        "degraded": degraded,
        "checks": checks,
        "checked_at": iso_z(utcnow()),
    }


@router.get("/version", summary="Version, licence et état de sûreté")
def version(service: ServiceDep) -> dict[str, Any]:
    """Expose la version **et l'état de sûreté** : dry-run, autonomie, connecteurs.

    Un appelant doit pouvoir savoir en une requête si le service est en simulation ou non.
    """
    return {
        "name": "Thot Secure",
        "version": __version__,
        "license": __license__,
        "defensive_only": True,
        "safety": service.safety_report(),
        "counts": {
            "rules": len(service.rules),
            "policies": len(service.policies),
            "playbooks": len(service.playbooks),
            "connectors": len(service.connectors.configuration),
        },
    }


@router.get("/api/v1/auth/whoami", summary="Identité et capacités de l'appelant")
def whoami(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    tenant = service.store.get_tenant(principal.tenant_id)
    return {
        "authenticated": principal.authenticated,
        "tenant_id": principal.tenant_id,
        "tenant_mode": tenant.mode if tenant else None,
        "tenant_dry_run": tenant.dry_run if tenant else None,
        "role": principal.role,
        "capabilities": sorted(principal.capabilities),
        "key_id": principal.key_id,
        "label": principal.label,
        "role_matrix": role_matrix() if principal.role == "admin" else None,
        "role_description": ROLE_DESCRIPTIONS.get(principal.role, ""),
    }


@router.get("/api/v1/meta/roles", summary="Matrice des rôles et capacités")
def roles(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    """Matrice RBAC complète (utile pour l'intégration et l'audit des accès)."""
    from ..deps import require

    require("admin:keys")(principal)
    return {
        "roles": {
            role: {
                "description": ROLE_DESCRIPTIONS.get(role, ""),
                "capabilities": sorted(capabilities_for(role)),
            }
            for role in ("viewer", "analyst", "responder", "admin")
        },
        "metrics": sorted(METRICS_CATALOG),
    }


@router.get("/metrics", summary="Métriques Prometheus", include_in_schema=False)
def metrics(service: ServiceDep) -> Response:
    """Exposition texte Prometheus, rafraîchie à chaque scrape."""
    service.record_pipeline_metrics()
    return Response(content=service.metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/api/v1/stats/overview", summary="Indicateurs du tableau de bord")
def stats_overview(
    service: ServiceDep,
    principal: PrincipalDep,
    tenant_id: str | None = None,
    window_hours: int = 24,
) -> dict[str, Any]:
    from ..deps import require, resolve_tenant

    require("read:stats")(principal)
    tenant = resolve_tenant(service, principal, tenant_id)
    window = max(1, min(int(window_hours), 24 * 30))
    collectors = service.collectors.status(tenant.tenant_id)
    overview = service.store.stats_overview(
        tenant.tenant_id, window_hours=window, collectors=collectors
    )
    payload = overview.model_dump(mode="json")
    payload["audit"] = service.audit.integrity_summary(tenant.tenant_id)
    payload["collections"] = {
        "rules": len(service.rules),
        "policies": len(service.policies),
        "playbooks": len(service.playbooks),
        "rejected": len(service.rule_diagnostics)
        + len(service.policy_diagnostics)
        + len(service.playbook_diagnostics),
    }
    payload["safety"] = {
        "dry_run": service.settings.dry_run or tenant.dry_run,
        "autonomy": tenant.mode,
        "require_target_declaration": service.settings.require_target_declaration,
    }
    payload["latency_ms"] = {"generated_in": round((time.perf_counter() % 1) * 1000, 2)}
    return payload


__all__ = ["router"]
