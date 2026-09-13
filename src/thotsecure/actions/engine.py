"""Moteur d'actions : cycle de vie complet d'une contre-mesure, avec audit et rollback.

Machine à états (contrat §3.4) :

```
                     plan (humain)                execute (dry-run autorisé)
  [planned] ─────────────────────────────────────────────┐
      │                                                  ▼
      │ plan (décision 'auto')                      [executing] ──► [succeeded]
      ▼                                                  │              │
  [approved] ── execute ─────────────────────────────────┘              │
      ▲                                                  │              ▼
      │ approve                                     [failed]     [rolled_back]
 [pending_approval] ── reject ──► [rejected]
      │
      └── expiration (TTL d'approbation) ──► [expired]
```

Trois règles de conception :

1. **Rien ne s'exécute sans une décision explicite** : soit une politique ``auto``, soit une
   approbation humaine enregistrée avec son auteur.
2. **La sûreté est réévaluée au moment de l'exécution**, pas seulement à la planification :
   entre-temps, le dry-run a pu être réactivé ou la cible ajoutée aux cibles protégées.
3. **Un playbook non réversible n'est jamais automatique**, quel que soit le mode d'autonomie
   du tenant. C'est la différence entre « automatisable » et « irréversible ».
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..audit.chain import AuditChain
from ..core.config import Settings
from ..core.errors import (
    AutonomyRefused,
    ConflictError,
    NotFoundError,
    PlaybookError,
    ProtectedTargetError,
)
from ..core.logging_setup import get_logger
from ..core.models import (
    Action,
    ActionRollback,
    ActionTarget,
    Decision,
    Finding,
    Playbook,
    Tenant,
)
from ..core.util import expiry_from_now, iso_z, new_id, safe_int, utcnow
from ..decision.engine import extract_targets, resolve_param_target
from ..scope import TargetRegistry
from ..storage.store import Store
from .executor import ExecutionOutcome, PlaybookExecutor
from .registry import ConnectorRegistry

log = get_logger("actions.engine")

#: Statuts à partir desquels une exécution est légitime.
EXECUTABLE_STATUSES = frozenset({"planned", "approved"})

#: Statuts à partir desquels une annulation est légitime.
ROLLBACK_STATUSES = frozenset({"succeeded", "failed"})

TARGET_TYPE_BY_PLAYBOOK: dict[str, str] = {
    "block-source-ip": "ip",
    "unblock-source-ip": "ip",
    "rate-limit-source": "ip",
    "remove-rate-limit": "ip",
    "isolate-host": "host",
    "unisolate-host": "host",
    "harden-endpoint": "host",
    "quarantine-artifact": "file",
    "restore-artifact": "file",
    "patch-dependency": "package",
    "rotate-secret": "secret",
    "revoke-session": "session",
}


class ActionEngine:
    """Planifie, approuve, exécute et annule les contre-mesures."""

    def __init__(
        self,
        store: Store,
        audit: AuditChain,
        playbooks: dict[str, Playbook],
        executor: PlaybookExecutor,
        *,
        settings: Settings,
        registry: TargetRegistry | None = None,
        connectors: ConnectorRegistry | None = None,
        on_change: Callable[[Action, str], None] | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.playbooks = playbooks
        self.executor = executor
        self.settings = settings
        self.registry = registry or TargetRegistry()
        self.connectors = connectors or executor.connectors
        self.on_change = on_change

    # ----------------------------------------------------------------------------------
    # Planification
    # ----------------------------------------------------------------------------------

    def plan(
        self,
        *,
        tenant: Tenant,
        playbook_name: str,
        actor: str,
        actor_role: str = "responder",
        finding: Finding | None = None,
        params: dict[str, Any] | None = None,
        mode: str = "manual",
        policy_id: str | None = None,
        reason: str = "",
        dry_run: bool | None = None,
        expires_in: int | None = None,
    ) -> Action:
        """Crée une action dans l'état ``planned`` ou ``pending_approval``.

        Aucun effet de bord : ``plan`` ne touche jamais à l'infrastructure. C'est
        volontairement une opération sûre, utilisable pour préparer et relire une action.
        """
        playbook = self.playbooks.get(playbook_name)
        if playbook is None:
            raise NotFoundError(
                f"playbook inconnu: {playbook_name}",
                details={"available": sorted(self.playbooks)},
            )

        # Les politiques expriment leurs paramètres sous forme de **chemins** sur le finding
        # (``target: labels.src_ip``). La résolution doit précéder la validation : sinon un
        # paramètre typé ``ip`` recevrait la chaîne « labels.src_ip » et serait rejeté.
        provided = self._resolve_param_paths(finding, dict(params or {}))
        resolved_params = validate_params(playbook, provided)
        target_value = self._resolve_target_value(playbook, resolved_params, finding)

        # Un playbook irréversible ne peut jamais être automatique.
        if not playbook.reversible and mode == "auto":
            mode = "manual"
            reason = f"{reason} | playbook non réversible : approbation humaine obligatoire".strip(" |")

        effective_dry_run = (
            self.settings.dry_run or tenant.dry_run if dry_run is None else bool(dry_run)
        )
        # Le dry-run global ne peut être levé par un appelant.
        if self.settings.dry_run:
            effective_dry_run = True

        cooldown = tenant.cooldown_seconds or self.settings.default_cooldown_seconds
        ticket_ttl = expires_in or self.settings.approve_ttl_seconds

        action = Action(
            action_id=new_id("ac_"),
            tenant_id=tenant.tenant_id,
            finding_id=finding.finding_id if finding else None,
            policy_id=policy_id,
            playbook=playbook.name,
            status="approved" if mode == "auto" else "planned",
            mode="auto" if mode == "auto" else "manual",
            dry_run=effective_dry_run,
            params=resolved_params,
            target=ActionTarget(
                type=TARGET_TYPE_BY_PLAYBOOK.get(playbook.name, "other"),  # type: ignore[arg-type]
                value=target_value or "",
            ),
            requested_by=actor,
            requested_at=utcnow(),
            expires_at=_parse_expiry(expiry_from_now(ticket_ttl)),
            rollback=ActionRollback(available=playbook.reversible),
            idempotency_key=self._idempotency_key(tenant.tenant_id, playbook.name, target_value, cooldown),
            reason=reason or f"planification manuelle du playbook '{playbook.name}'",
        )

        base_key = self._idempotency_key(tenant.tenant_id, playbook.name, target_value, cooldown)
        action.idempotency_key = base_key

        # Idempotence : on protège contre la **tempête d'actions actives** (une attaque
        # soutenue ne doit pas créer 10 000 demandes de blocage identiques), sans empêcher
        # une nouvelle action légitime une fois la précédente terminée.
        for attempt in range(5):
            try:
                self.store.insert_action(action)
                break
            except ConflictError as exc:
                existing_id = (exc.details or {}).get("action_id")
                existing = (
                    self.store.get_action(tenant.tenant_id, str(existing_id)) if existing_id else None
                )
                if existing is not None and not existing.is_terminal:
                    log.info(
                        "action idempotente réutilisée",
                        extra={
                            "tenant_id": tenant.tenant_id,
                            "action_id": existing.action_id,
                            "status": existing.status,
                        },
                    )
                    return existing
                # L'action précédente est terminale : une nouvelle demande est légitime.
                action.action_id = new_id("ac_")
                action.idempotency_key = f"{base_key}#{attempt + 1}"
        else:
            raise ConflictError(
                "impossible de créer l'action : collision d'idempotence répétée",
                details={"idempotency_key": base_key},
            )

        record = self.audit.record(
            tenant_id=tenant.tenant_id,
            actor=actor,
            actor_role=actor_role,
            action="action.plan",
            target={"type": "action", "id": action.action_id},
            after=action.to_audit_dict(),
            context={
                "playbook": playbook.name,
                "policy_id": policy_id,
                "finding_id": action.finding_id,
                "dry_run": action.dry_run,
                "mode": action.mode,
                "target": str(action.target),
            },
        )
        action.audit_seq = record.seq
        self.store.update_action(action)
        self._notify(action, "planned")
        return action

    def from_decision(
        self,
        *,
        tenant: Tenant,
        finding: Finding,
        decision: Decision,
        actor: str = "system:policy-engine",
        actor_role: str = "system",
    ) -> Action | None:
        """Traduit une décision en action. Retourne ``None`` si la décision n'agit pas."""
        if not decision.triggers_action or not decision.playbook:
            return None

        action = self.plan(
            tenant=tenant,
            playbook_name=decision.playbook,
            actor=actor,
            actor_role=actor_role,
            finding=finding,
            params=decision.params,
            mode="auto" if decision.decision == "auto" else "manual",
            policy_id=decision.policy_id,
            reason=decision.reason,
            dry_run=decision.dry_run,
        )

        if decision.decision == "require_approval" and action.status == "planned":
            action = self._set_status(
                action,
                "pending_approval",
                actor=actor,
                actor_role=actor_role,
                audit_action="action.plan",
                context={"decision": "require_approval", "policy_id": decision.policy_id},
            )

        if decision.decision == "auto" and action.status == "approved":
            action = self.execute(
                tenant=tenant, action_id=action.action_id, actor=actor, actor_role=actor_role
            )
        return action

    # ----------------------------------------------------------------------------------
    # Approbation
    # ----------------------------------------------------------------------------------

    def approve(
        self, *, tenant: Tenant, action_id: str, actor: str, actor_role: str = "responder", comment: str = ""
    ) -> Action:
        action = self.require(tenant.tenant_id, action_id)
        if action.status not in {"planned", "pending_approval"}:
            raise ConflictError(
                f"approbation impossible : l'action est dans l'état '{action.status}'",
                details={"action_id": action_id, "status": action.status},
            )
        action = self._set_status(
            action,
            "approved",
            actor=actor,
            actor_role=actor_role,
            audit_action="action.approve",
            extra={"approved_by": actor, "approved_at": utcnow()},
            context={"comment": comment[:500]},
        )
        log.info(
            "action approuvée",
            extra={"tenant_id": tenant.tenant_id, "action_id": action.action_id, "actor": actor},
        )
        return action

    def reject(
        self, *, tenant: Tenant, action_id: str, actor: str, actor_role: str = "responder", reason: str = ""
    ) -> Action:
        action = self.require(tenant.tenant_id, action_id)
        if action.is_terminal:
            raise ConflictError(
                f"rejet impossible : l'action est déjà terminale ('{action.status}')",
                details={"action_id": action_id, "status": action.status},
            )
        action = self._set_status(
            action,
            "rejected",
            actor=actor,
            actor_role=actor_role,
            audit_action="action.reject",
            extra={"rejected_by": actor, "rejected_at": utcnow(), "reason": reason[:500]},
        )
        log.info(
            "action rejetée",
            extra={"tenant_id": tenant.tenant_id, "action_id": action.action_id, "actor": actor},
        )
        return action

    # ----------------------------------------------------------------------------------
    # Exécution
    # ----------------------------------------------------------------------------------

    def execute(
        self, *, tenant: Tenant, action_id: str, actor: str, actor_role: str = "responder"
    ) -> Action:
        action = self.require(tenant.tenant_id, action_id)
        playbook = self.playbooks.get(action.playbook)
        if playbook is None:
            raise NotFoundError(f"playbook '{action.playbook}' introuvable")

        self._authorize_execution(action, playbook, tenant, actor, actor_role)

        action = self._set_status(
            action, "executing", actor=actor, actor_role=actor_role, audit_action="action.execute"
        )

        try:
            outcome = self.executor.execute(
                playbook,
                action.params,
                context=self._execution_context(tenant, action),
                dry_run=action.dry_run,
            )
        except PlaybookError as exc:
            return self._mark_failed(action, actor, actor_role, str(exc), {"error": str(exc)})

        result = outcome.to_dict()
        result["playbook"] = playbook.name
        result["reversible"] = playbook.reversible

        if outcome.ok:
            action.result = result
            action.rollback = ActionRollback(
                available=outcome.rollback_available and playbook.reversible,
                token=outcome.rollback_token,
                expires_at=action.expires_at,
            )
            action = self._set_status(
                action,
                "succeeded",
                actor=actor,
                actor_role=actor_role,
                audit_action="action.execute",
                extra={"executed_at": utcnow(), "result": result},
                context={"simulated": outcome.simulated, "steps": len(outcome.steps)},
            )
            log.info(
                "action exécutée",
                extra={
                    "tenant_id": tenant.tenant_id,
                    "action_id": action.action_id,
                    "playbook": playbook.name,
                    "simulated": outcome.simulated,
                },
            )
            return action

        return self._mark_failed(action, actor, actor_role, outcome.error or "échec", result)

    def _authorize_execution(
        self, action: Action, playbook: Playbook, tenant: Tenant, actor: str, actor_role: str
    ) -> None:
        """Réévalue les garde-fous **au moment de l'exécution**."""
        if action.status not in EXECUTABLE_STATUSES:
            raise ConflictError(
                f"exécution impossible : l'action est dans l'état '{action.status}'",
                details={"action_id": action.action_id, "status": action.status},
            )
        # Une action non approuvée ne s'exécute que si elle est simulée : c'est un galop
        # d'essai, pas une action réelle.
        if action.status == "planned" and not action.dry_run:
            raise AutonomyRefused(
                "l'action doit être approuvée avant toute exécution réelle "
                "(POST /actions/{id}/approve)",
                details={"action_id": action.action_id},
            )
        if not playbook.reversible and action.mode == "auto":
            raise AutonomyRefused(
                "un playbook non réversible ne peut pas être exécuté en mode automatique",
                details={"playbook": playbook.name},
            )
        if tenant.is_protected(action.target.value):
            raise ProtectedTargetError(
                f"la cible '{action.target.value}' est protégée par le tenant : exécution refusée",
                details={"action_id": action.action_id, "target": action.target.value},
            )
        if action.expires_at and action.expires_at < utcnow() and action.status == "pending_approval":
            self._set_status(
                action, "expired", actor="system", actor_role="system", audit_action="action.fail"
            )
            raise ConflictError(
                "l'action a expiré avant approbation", details={"action_id": action.action_id}
            )

    def rollback(
        self,
        *,
        tenant: Tenant,
        action_id: str,
        actor: str,
        actor_role: str = "responder",
        reason: str = "annulation manuelle",
    ) -> Action:
        action = self.require(tenant.tenant_id, action_id)
        if action.status not in ROLLBACK_STATUSES:
            raise ConflictError(
                f"annulation impossible : l'action est dans l'état '{action.status}' "
                f"(attendu: {sorted(ROLLBACK_STATUSES)})",
                details={"action_id": action_id, "status": action.status},
            )
        if not action.rollback.available:
            raise ConflictError(
                "cette action ne dispose pas d'annulation disponible",
                details={"action_id": action_id},
            )
        if not action.rollback.token:
            raise ConflictError(
                "aucune pile de rollback enregistrée pour cette action",
                details={"action_id": action_id},
            )

        playbook = self.playbooks.get(action.playbook)
        outcome = self.executor.rollback(
            playbook,
            action.rollback.token,
            context=self._execution_context(tenant, action),
            dry_run=action.dry_run,
        )
        result = outcome.to_dict()
        before = {"status": action.status, "rollback": action.rollback.model_dump(mode="json")}
        action.rollback.performed_at = utcnow()
        action.rollback.result = result
        action.rollback.available = False
        action.result = {**(action.result or {}), "rollback": result}
        action.reason = f"{action.reason} | {reason}"[:500]

        new_status = "rolled_back" if outcome.ok else "failed"
        action = self._set_status(
            action,
            new_status,
            actor=actor,
            actor_role=actor_role,
            audit_action="action.rollback",
            before=before,
            extra={"rollback_result": result, "rollback_performed_at": action.rollback.performed_at},
        )
        log.info(
            "action annulée",
            extra={
                "tenant_id": tenant.tenant_id,
                "action_id": action.action_id,
                "ok": outcome.ok,
                "simulated": outcome.simulated,
            },
        )
        return action

    # ----------------------------------------------------------------------------------
    # Maintenance
    # ----------------------------------------------------------------------------------

    def reap(self, *, tenant_id: str | None = None) -> dict[str, int]:
        """Tâche de fond : expire les approbations et applique les rollbacks programmés.

        Le rollback automatique à expiration est une fonctionnalité de sûreté : un blocage
        temporaire doit se lever tout seul, même si personne ne s'en occupe. Sans cela, une
        contre-mesure oubliée devient un déni de service permanent.
        """
        now = utcnow()
        expired = 0
        rolled_back = 0
        tenants = [tenant_id] if tenant_id else [tenant.tenant_id for tenant in self.store.list_tenants()]

        for current_tenant_id in tenants:
            tenant = self.store.get_tenant(current_tenant_id)
            if tenant is None:
                continue
            pending, _ = self.store.list_actions(
                current_tenant_id, status=["pending_approval"], limit=500
            )
            for action in pending:
                if action.expires_at and action.expires_at < now:
                    self._set_status(
                        action,
                        "expired",
                        actor="system:reaper",
                        actor_role="system",
                        audit_action="action.fail",
                        extra={"reason": "délai d'approbation dépassé"},
                    )
                    expired += 1

            succeeded, _ = self.store.list_actions(current_tenant_id, status=["succeeded"], limit=500)
            for action in succeeded:
                deadline = action.rollback.expires_at
                if (
                    action.rollback.available
                    and action.rollback.token
                    and deadline is not None
                    and deadline <= now
                ):
                    try:
                        self.rollback(
                            tenant=tenant,
                            action_id=action.action_id,
                            actor="system:reaper",
                            actor_role="system",
                            reason="rollback automatique à expiration",
                        )
                        rolled_back += 1
                    except (ConflictError, NotFoundError) as exc:
                        log.error(
                            "rollback automatique impossible",
                            extra={"action_id": action.action_id, "error": str(exc)},
                        )
        return {"expired": expired, "rolled_back": rolled_back}

    # ----------------------------------------------------------------------------------
    # Lecture
    # ----------------------------------------------------------------------------------

    def require(self, tenant_id: str, action_id: str) -> Action:
        action = self.store.get_action(tenant_id, action_id)
        if action is None:
            raise NotFoundError(f"action introuvable: {action_id}", details={"action_id": action_id})
        return action

    def list(
        self,
        tenant_id: str,
        *,
        status: list[str] | None = None,
        playbook: str | None = None,
        finding_id: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[Action], str | None]:
        return self.store.list_actions(
            tenant_id,
            status=status,
            playbook=playbook,
            finding_id=finding_id,
            limit=limit,
            cursor=cursor,
        )

    def stats(self) -> dict[str, Any]:
        return {
            "playbooks": len(self.playbooks),
            "connectors": self.connectors.stats(),
            "reversible_playbooks": sum(1 for item in self.playbooks.values() if item.reversible),
        }

    # ----------------------------------------------------------------------------------
    # Aides internes
    # ----------------------------------------------------------------------------------

    def _resolve_param_paths(
        self, finding: Finding | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Résout les paramètres exprimés sous forme de chemins vers les preuves du finding.

        Une valeur de la forme ``labels.src_ip`` / ``payload.user`` / ``source.host`` est
        remplacée par la valeur réellement présente dans l'événement. Si le chemin ne peut pas
        être résolu, la valeur d'origine est conservée : c'est la validation du playbook qui
        décidera, avec un message explicite.
        """
        if finding is None:
            return params
        resolved: dict[str, Any] = {}
        for key, value in params.items():
            if isinstance(value, str) and _looks_like_field_path(value):
                replacement = resolve_param_target(finding, value)
                resolved[key] = replacement if replacement is not None else value
            else:
                resolved[key] = value
        return resolved

    def _resolve_target_value(
        self, playbook: Playbook, params: dict[str, Any], finding: Finding | None
    ) -> str | None:
        raw = params.get("target") or params.get("ip") or params.get("path")
        if raw is None and finding is not None:
            _, inferred = extract_targets(finding)
            return inferred
        if raw is None:
            return None
        text = str(raw)
        # Un paramètre de type chemin (``labels.src_ip``) est résolu sur les preuves.
        if finding is not None and "." in text and "/" not in text and not text[0].isdigit():
            resolved = resolve_param_target(finding, text)
            if resolved:
                return resolved
        return text

    @staticmethod
    def _idempotency_key(tenant_id: str, playbook: str, target: str | None, cooldown: int) -> str:
        """Clé stable dans une fenêtre de cooldown.

        Deux demandes identiques dans la même fenêtre sont la même action : cela évite qu'une
        attaque soutenue génère des milliers de demandes de blocage redondantes.
        """
        window = max(safe_int(cooldown) or 60, 60)
        bucket = int(time.time()) // window
        return f"{tenant_id}:{playbook}:{target or 'n/a'}:{bucket}"

    def _execution_context(self, tenant: Tenant, action: Action) -> dict[str, Any]:
        """Contexte de rendu des placeholders d'un playbook.

        Il contient ``params`` (les paramètres de l'action) : sans cela, un bloc de rollback
        référençant ``${params.target}`` ne pourrait pas être résolu, et l'annulation d'une
        action deviendrait impossible — c'est-à-dire exactement ce qu'un SOAR ne doit pas
        être.
        """
        finding = (
            self.store.get_finding(tenant.tenant_id, action.finding_id) if action.finding_id else None
        )
        asset_host, _ = extract_targets(finding) if finding else (None, None)
        return {
            "params": dict(action.params),
            "finding": {
                "id": action.finding_id or "",
                "rule_id": finding.rule_id if finding else "",
                "severity": finding.severity if finding else "",
                "risk_score": finding.risk_score if finding else 0.0,
                "title": finding.title if finding else "",
                "host": asset_host or "",
            },
            "action": {
                "id": action.action_id,
                "playbook": action.playbook,
                "dry_run": action.dry_run,
                "target": action.target.value,
            },
            "tenant": {"id": tenant.tenant_id, "mode": tenant.mode},
        }

    def _set_status(
        self,
        action: Action,
        status: str,
        *,
        actor: str,
        actor_role: str,
        audit_action: str,
        before: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Action:
        previous = {"status": action.status} if before is None else before
        action.status = status  # type: ignore[assignment]
        if extra:
            for key, value in extra.items():
                if hasattr(action, key):
                    setattr(action, key, value)
        self.store.update_action(action)
        record = self.audit.record_state_change(
            tenant_id=action.tenant_id,
            actor=actor,
            actor_role=actor_role,
            action=audit_action,
            target={"type": "action", "id": action.action_id},
            before=previous,
            after=action.to_audit_dict(),
            context={"playbook": action.playbook, **(context or {})},
        )
        action.audit_seq = record.seq
        self.store.update_action(action)
        self._notify(action, status)
        return action

    def _mark_failed(
        self, action: Action, actor: str, actor_role: str, error: str, result: dict[str, Any]
    ) -> Action:
        action.result = result
        action = self._set_status(
            action,
            "failed",
            actor=actor,
            actor_role=actor_role,
            audit_action="action.fail",
            extra={"reason": error[:500]},
            context={"error": error[:500]},
        )
        log.error(
            "action en échec",
            extra={"tenant_id": action.tenant_id, "action_id": action.action_id, "error": error[:300]},
        )
        return action

    def _notify(self, action: Action, event: str) -> None:
        if self.on_change is None:
            return
        try:
            self.on_change(action, event)
        except Exception as exc:  # noqa: BLE001 - une notification ne casse jamais une action
            log.warning("notification d'action échouée", extra={"error": str(exc)})


# --------------------------------------------------------------------------------------
# Validation des paramètres
# --------------------------------------------------------------------------------------


def validate_params(playbook: Playbook, provided: dict[str, Any]) -> dict[str, Any]:
    """Valide et normalise les paramètres d'un playbook.

    Strict sur les champs inconnus : un ``target`` mal orthographié qui serait silencieusement
    ignoré ferait exécuter une action sans cible — c'est-à-dire n'importe quoi.
    """
    unknown = sorted(set(provided) - set(playbook.params))
    if unknown:
        raise PlaybookError(
            f"paramètres inconnus pour le playbook '{playbook.name}': {unknown}",
            details={"expected": sorted(playbook.params)},
        )

    resolved: dict[str, Any] = {}
    for name, spec in playbook.params.items():
        if name in provided and provided[name] is not None:
            value = provided[name]
        elif spec.default is not None:
            value = spec.default
        elif spec.required:
            raise PlaybookError(
                f"paramètre obligatoire manquant: '{name}' ({spec.description or 'sans description'})",
                details={"playbook": playbook.name, "param": name},
            )
        else:
            continue

        if spec.type in {"integer", "duration"}:
            parsed = safe_int(value, default=-1)
            if parsed < 0:
                raise PlaybookError(f"paramètre '{name}': entier attendu (reçu {value!r})")
            if spec.min is not None and parsed < spec.min:
                raise PlaybookError(f"paramètre '{name}': {parsed} < minimum {spec.min}")
            if spec.max is not None and parsed > spec.max:
                raise PlaybookError(f"paramètre '{name}': {parsed} > maximum {spec.max}")
            value = parsed
        elif spec.type == "boolean":
            value = bool(value)
        elif spec.type == "ip":
            from ..core.util import is_valid_cidr, is_valid_ip

            if not (is_valid_ip(str(value)) or is_valid_cidr(str(value))):
                raise PlaybookError(f"paramètre '{name}': IP ou CIDR attendu (reçu {value!r})")
            value = str(value)
        else:
            value = str(value)
            if spec.choices and value not in spec.choices:
                raise PlaybookError(
                    f"paramètre '{name}': valeur '{value}' hors choix {spec.choices}"
                )

        resolved[name] = value
    return resolved


def _parse_expiry(value: str) -> Any:
    from ..core.util import parse_dt

    return parse_dt(value)


def _looks_like_field_path(value: str) -> bool:
    """Vrai si la valeur ressemble à un chemin de champ d'événement (``labels.src_ip``)."""
    if "." not in value or " " in value or value.startswith(("http://", "https://")):
        return False
    root = value.split(".", 1)[0]
    return root in {"labels", "payload", "source", "evidence"}


__all__ = [
    "EXECUTABLE_STATUSES",
    "ROLLBACK_STATUSES",
    "TARGET_TYPE_BY_PLAYBOOK",
    "ActionEngine",
    "validate_params",
]
