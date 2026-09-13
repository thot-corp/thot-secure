"""Détection, politiques, playbooks, audit et collecteurs : les surfaces de configuration.

Ces routes sont réservées aux rôles disposant des capacités correspondantes : modifier une
règle de détection ou une politique de décision change le comportement du produit face à une
attaque, c'est donc une opération sensible et auditée.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Query, Response

from ...core.errors import RuleError
from ...core.util import parse_dt
from ...decision.policy_loader import validate_policy
from ...detection.rule_loader import RuleLoadError, dump_rule, load_rule_text, sigma_supported_subset
from ...audit.hashchain import to_cef
from ..deps import PrincipalDep, ServiceDep, require
from ..schemas import RuleValidateRequest

router = APIRouter(prefix="/api/v1", tags=["détection et configuration"])


# --------------------------------------------------------------------------------------
# Règles
# --------------------------------------------------------------------------------------


@router.get("/rules", summary="Lister les règles de détection chargées")
def list_rules(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:rules")(principal)
    return {
        "items": service.detection.summaries(),
        "count": len(service.rules),
        "enabled": sum(1 for rule in service.rules if rule.enabled),
        "diagnostics": [item.model_dump() for item in service.rule_diagnostics],
        "sigma_support": sigma_supported_subset(),
    }


@router.get("/rules/{rule_id}", summary="Détail d'une règle (avec sa source YAML)")
def get_rule(rule_id: str, service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:rules")(principal)
    from ...core.errors import NotFoundError

    rule = service.detection.get_rule(rule_id)
    if rule is None:
        raise NotFoundError(f"règle introuvable: {rule_id}", details={"rule_id": rule_id})
    return {**rule.summary(), "description": rule.description, "yaml": dump_rule(rule)}


@router.post("/rules/validate", summary="Valider une règle sans l'activer")
def validate_rule_endpoint(
    payload: RuleValidateRequest, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Valide une règle écrite en YAML ou JSON (utile en CI avant une PR)."""
    require("admin:rules")(principal)
    try:
        rule = load_rule_text(payload.text, path="<api>")
    except RuleLoadError as exc:
        return {"valid": False, "errors": [str(exc)], "rule_id": None}
    return {
        "valid": True,
        "errors": [],
        "rule_id": rule.id,
        "summary": rule.summary(),
        "sigma_compat": rule.sigma_compat,
    }


@router.post("/rules/reload", summary="Recharger la bibliothèque de règles depuis le disque")
def reload_rules(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("admin:rules")(principal)
    count, diagnostics = service.reload_rules()
    service.audit.record(
        tenant_id=principal.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action="rules.reload",
        target={"type": "rules", "id": "library"},
        after={"loaded": count, "rejected": len(diagnostics)},
        context={"diagnostics": [item.model_dump() for item in diagnostics][:20]},
    )
    return {
        "loaded": count,
        "rejected": len(diagnostics),
        "errors": [item.model_dump() for item in diagnostics],
    }


# --------------------------------------------------------------------------------------
# Politiques
# --------------------------------------------------------------------------------------


@router.get("/policies", summary="Lister les politiques de décision (ordre d'évaluation)")
def list_policies(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:policies")(principal)
    return {
        "items": [policy.summary() for policy in service.decision.policies],
        "count": len(service.policies),
        "enabled": len(service.decision.enabled_policies()),
        "diagnostics": [item.model_dump() for item in service.policy_diagnostics],
        "guards": [
            "protected_target",
            "out_of_scope",
            "scope_requires_approval",
            "tenant_manual",
            "critical_score_threshold",
            "autonomy_allowlist",
            "hourly_cap",
            "cooldown",
            "dry_run",
        ],
        "note": (
            "Les garde-fous sont appliqués après la sélection de la politique : "
            "une politique ne peut pas les désactiver."
        ),
    }


@router.post("/policies/reload", summary="Recharger les politiques depuis le disque")
def reload_policies(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("admin:policies")(principal)
    count, diagnostics = service.reload_policies()
    service.audit.record(
        tenant_id=principal.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action="policies.reload",
        target={"type": "policies", "id": "library"},
        after={"loaded": count, "rejected": len(diagnostics)},
        context={"diagnostics": [item.model_dump() for item in diagnostics][:20]},
    )
    return {
        "loaded": count,
        "rejected": len(diagnostics),
        "errors": [item.model_dump() for item in diagnostics],
    }


@router.post("/policies/validate", summary="Valider une politique sans l'activer")
def validate_policy_endpoint(
    service: ServiceDep,
    principal: PrincipalDep,
    text: str = Body(..., media_type="text/plain", description="Politique YAML à valider"),
) -> dict[str, Any]:
    require("admin:policies")(principal)
    import yaml

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {"valid": False, "errors": [f"YAML invalide: {exc}"]}
    if not isinstance(document, dict):
        return {"valid": False, "errors": ["la politique doit être un objet YAML"]}
    try:
        from ...decision.policy_loader import parse_policy

        policy = parse_policy(document, path="<api>", known_playbooks=set(service.playbooks))
    except Exception as exc:  # noqa: BLE001 - l'endpoint de validation renvoie les erreurs
        return {"valid": False, "errors": [str(exc)]}
    return {
        "valid": True,
        "errors": validate_policy(policy, known_playbooks=set(service.playbooks)),
        "policy": policy.summary(),
    }


# --------------------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------------------


@router.get("/audit", summary="Consulter le journal d'audit")
def list_audit(
    service: ServiceDep,
    principal: PrincipalDep,
    action: str | None = None,
    actor: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = None,
) -> dict[str, Any]:
    require("read:audit")(principal)
    records, next_cursor = service.store.list_audit(
        principal.tenant_id,
        action=action,
        actor=actor,
        since=parse_dt(since),
        until=parse_dt(until),
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [record.model_dump(mode="json") for record in records],
        "count": len(records),
        "next_cursor": next_cursor,
        "chained": True,
        "verify_endpoint": "/api/v1/audit/verify",
    }


@router.get("/audit/verify", summary="Vérifier l'intégrité de la chaîne d'audit")
def verify_audit(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    """Recalcule la chaîne complète : détecte toute modification ou suppression."""
    require("read:audit")(principal)
    verdict = service.audit.verify(tenant_id=principal.tenant_id)
    service.metrics.set("thotsecure_audit_chain_valid", 1 if verdict.valid else 0)
    if not verdict.valid:
        service.metrics.inc("thotsecure_audit_integrity_failures_total")
    return {**verdict.model_dump(mode="json"), "scope": "chaîne globale (tous tenants)"}


@router.get("/audit/export", summary="Exporter l'audit (jsonl ou cef) pour un SIEM")
def export_audit(
    service: ServiceDep,
    principal: PrincipalDep,
    format: str = Query(default="jsonl", pattern="^(jsonl|cef)$"),
    limit: int = Query(default=5000, ge=1, le=10000),
    since: str | None = None,
) -> Response:
    require("read:audit")(principal)
    lines = list(
        service.audit.export(
            principal.tenant_id, fmt=format, limit=limit, since=parse_dt(since)
        )
    )
    content = "\n".join(lines) + ("\n" if lines else "")
    media_type = "text/plain; charset=utf-8"
    extension = "cef" if format == "cef" else "jsonl"
    service.audit.record(
        tenant_id=principal.tenant_id,
        actor=principal.actor,
        actor_role=principal.role,
        action="audit.export",
        target={"type": "audit", "id": "export"},
        after={"format": format, "records": len(lines)},
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="thotsecure-audit.{extension}"',
            "X-Record-Count": str(len(lines)),
        },
    )


# --------------------------------------------------------------------------------------
# Collecteurs
# --------------------------------------------------------------------------------------


@router.get("/collectors", summary="État des collecteurs")
def list_collectors(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:stats")(principal)
    statuses = service.collectors.status(principal.tenant_id)
    return {
        "items": [status.model_dump(mode="json") for status in statuses],
        "count": len(statuses),
        "enabled": [status.name for status in statuses if status.enabled],
        "scheduler_enabled": service.settings.collectors_enabled,
        "syslog_enabled": service.settings.syslog_enabled,
        "note": (
            "Chaque collecteur n'agit que sur le périmètre déclaré du tenant "
            "(config/targets.yaml)."
        ),
    }


@router.post("/collectors/{collector_name}/run", summary="Exécuter un collecteur maintenant")
def run_collector(
    collector_name: str, service: ServiceDep, principal: PrincipalDep
) -> dict[str, Any]:
    """Déclenche une collecte immédiate sur les cibles déclarées du tenant."""
    require("execute:actions")(principal)
    result = service.collectors.run(collector_name, principal.tenant_id, actor=principal.actor)
    service.metrics.inc(
        "thotsecure_collector_runs_total", collector=collector_name, status=result.status
    )
    if result.errors:
        service.metrics.inc(
            "thotsecure_collector_errors_total", len(result.errors), collector=collector_name
        )
    findings, _ = service.store.list_findings(principal.tenant_id, limit=5, sort="last_seen")
    return {
        **result.to_dict(),
        "latest_findings": [
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
            }
            for finding in findings
        ],
    }


@router.get("/collectors/checks", summary="Contrôles de configuration disponibles")
def collector_checks(service: ServiceDep, principal: PrincipalDep) -> dict[str, Any]:
    require("read:rules")(principal)
    from ...collectors.config_audit import available_checks
    from ...collectors.web_probe import EXPOSED_PATHS, SECURITY_HEADERS

    return {
        "config_checks": available_checks(),
        "web_headers": {
            header: {"check": check, "severity": severity}
            for header, (check, severity, _) in SECURITY_HEADERS.items()
        },
        "exposed_paths": [
            {"path": path, "severity": severity} for path, severity, _ in EXPOSED_PATHS
        ],
    }


__all__ = ["router"]
