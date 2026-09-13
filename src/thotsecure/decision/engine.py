"""Moteur de décision : *policy-as-code* + garde-fous non contournables.

Séparation stricte des responsabilités :

* **la politique** exprime une intention (« si attaque web à fort score, alors bloquer l'IP ») ;
* **le moteur** applique des garde-fous que la politique ne peut pas lever.

Les garde-fous sont appliqués **après** la sélection de la politique, dans cet ordre :

1. cible protégée du tenant → ``notify_only`` (jamais d'automatisation) ;
2. mode d'autonomie du tenant → ``auto`` rétrogradé en ``require_approval`` si nécessaire ;
3. dry-run global ou par tenant → la décision reste mais n'aura aucun effet réel ;
4. cooldown sur ``(tenant, playbook, cible)`` → évite la tempête d'actions répétées ;
5. plafond d'actions par heure → protège contre un faux positif massif qui bloquerait
   des milliers d'adresses en quelques minutes (le scénario catastrophe d'un SOAR) ;
6. périmètre déclaré → hors périmètre, approbation humaine obligatoire ;
7. score critique → en mode ``supervised``, au-delà d'un seuil, l'automatique est refusé :
   plus l'impact potentiel est grand, plus l'humain doit valider.

Rien de tout cela n'est exprimable dans le YAML des politiques, et c'est délibéré.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..core.config import Settings
from ..core.logging_setup import get_logger
from ..core.models import Decision, Finding, Tenant, severity_rank
from ..core.util import iso_z, utcnow
from ..detection.matchers import RegexTooComplexError, compile_regex
from ..scope import TargetRegistry
from ..storage.store import Store

log = get_logger("decision.engine")

#: Noms de jours pour ``time.weekday``.
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")

_NUMERIC_OPERATORS = {"gt", "gte", "lt", "lte"}


@dataclass(slots=True)
class DecisionContext:
    """Contexte d'évaluation : tout ce dont une politique peut dépendre."""

    finding: Finding
    tenant: Tenant
    environment: str = "dev"
    settings: Settings | None = None
    asset_host: str | None = None
    target_value: str | None = None
    declared_scope: Any | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def resolve(self, key: str) -> Any:
        """Résout une clé de ``when`` vers sa valeur courante."""
        finding = self.finding
        if key == "finding.severity":
            return finding.severity
        if key == "finding.risk_score":
            return finding.risk_score
        if key == "finding.confidence":
            return finding.confidence
        if key == "finding.rule_id":
            return finding.rule_id
        if key == "finding.tags":
            return list(finding.tags)
        if key == "finding.tags_any":
            return list(finding.tags)
        if key == "finding.status":
            return finding.status
        if key == "finding.count":
            return finding.count
        if key == "finding.title":
            return finding.title
        if key == "finding.mitre":
            return list(finding.mitre)
        if key == "tenant.id":
            return self.tenant.tenant_id
        if key == "tenant.mode":
            return self.tenant.mode
        if key == "environment":
            return self.environment
        if key == "time.hour_utc":
            return utcnow().hour
        if key == "time.weekday":
            return WEEKDAYS[utcnow().weekday()]
        if key == "action.playbook":
            return self.extra.get("playbook")
        return None


@dataclass(slots=True)
class PolicyEvaluation:
    """Résultat d'évaluation d'une politique, avec la raison lisible."""

    policy_id: str
    matched: bool
    reasons: list[str] = field(default_factory=list)

    def explain(self) -> str:
        status = "correspond" if self.matched else "ne correspond pas"
        return f"{self.policy_id} {status}: " + " ; ".join(self.reasons)


class DecisionEngine:
    """Sélectionne une décision à partir des politiques chargées."""

    def __init__(
        self,
        store: Store,
        policies: list[Any] | None = None,
        *,
        settings: Settings | None = None,
        registry: TargetRegistry | None = None,
    ) -> None:
        self.store = store
        self.policies: list[Any] = sorted(policies or [], key=lambda item: (-item.priority, item.id))
        self.settings = settings
        self.registry = registry or TargetRegistry()
        self.evaluations = 0

    # ----------------------------------------------------------------------------------
    # Chargement
    # ----------------------------------------------------------------------------------

    def reload(self, policies: list[Any]) -> None:
        self.policies = sorted(policies, key=lambda item: (-item.priority, item.id))
        log.info("politiques rechargées", extra={"policies": len(self.policies)})

    def enabled_policies(self) -> list[Any]:
        return [policy for policy in self.policies if policy.enabled]

    # ----------------------------------------------------------------------------------
    # Décision
    # ----------------------------------------------------------------------------------

    def decide(self, context: DecisionContext) -> Decision:
        """Sélectionne la première politique (par priorité) qui correspond, puis applique les
        garde-fous."""
        self.evaluations += 1
        evaluated: list[str] = []
        guards: list[str] = []

        selected: Any | None = None
        mismatch_notes: list[str] = []
        for policy in self.enabled_policies():
            evaluated.append(policy.id)
            matched, reasons = evaluate_when(policy.when, context)
            if matched:
                selected = policy
                break
            if len(mismatch_notes) < 5:
                mismatch_notes.append(PolicyEvaluation(policy.id, False, reasons).explain())

        if selected is None:
            return Decision(
                decision="notify_only",
                policy_id=None,
                reason=(
                    "aucune politique correspondante : notification seule par défaut "
                    f"({len(evaluated)} politique(s) évaluée(s))"
                ),
                risk_score=context.finding.risk_score,
                dry_run=True,
                evaluated_policies=evaluated,
                guards=["default_notify_only"],
            )

        decision = Decision(
            decision=selected.then.decision,
            policy_id=selected.id,
            playbook=selected.then.playbook,
            params=dict(selected.then.params or {}),
            reason=(
                f"politique '{selected.id}' (priorité {selected.priority}) : "
                + PolicyEvaluation(selected.id, True, evaluate_when(selected.when, context)[1]).explain()
            ),
            risk_score=context.finding.risk_score,
            cooldown_seconds=(
                selected.then.cooldown_seconds
                if selected.then.cooldown_seconds is not None
                else (context.tenant.cooldown_seconds if context.tenant else None)
            ),
            dry_run=bool(selected.then.dry_run) if selected.then.dry_run is not None else True,
            evaluated_policies=evaluated,
        )
        if selected.rollback.auto_after_seconds:
            decision.expires_at = utcnow() + timedelta(seconds=selected.rollback.auto_after_seconds)

        if decision.decision == "ignore":
            decision.guards.append("explicit_ignore")
            return decision

        if decision.decision == "notify_only":
            return decision

        # -- garde-fous -----------------------------------------------------------------
        return self._apply_guards(decision, context, selected, guards)

    def _apply_guards(
        self,
        decision: Decision,
        context: DecisionContext,
        policy: Any,
        guards: list[str],
    ) -> Decision:
        """Applique les garde-fous, en enrichissant **directement** ``decision.guards``.

        Les garde-fous sont inscrits dans la décision au fil de l'eau : chaque retour
        anticipé (cible protégée, plafond horaire, cooldown) doit laisser une trace
        exploitable. Un garde-fou appliqué mais non journalisé est invisible en incident —
        et c'est précisément ce qu'un analyste doit pouvoir expliquer.
        """
        decision.guards = [*decision.guards, *guards]
        finding = context.finding
        tenant = context.tenant
        settings = context.settings or self.settings
        dry_run_global = bool(settings.dry_run) if settings else True

        # 1. Cible protégée : aucune automatisation, jamais.
        protected = tenant.is_protected(context.target_value) or tenant.is_protected(context.asset_host)
        if self.registry and not protected:
            scope = self.registry.for_tenant(tenant.tenant_id)
            protected = scope.is_protected(context.target_value or "") or scope.is_protected(
                context.asset_host or ""
            )
        if protected:
            decision.guards.append("protected_target")
            decision.decision = "notify_only"
            decision.reason += (
                " | garde-fou : cible protégée (protected_targets) — automatisation refusée, "
                "une action manuelle reste possible"
            )
            return decision

        # 2. Périmètre déclaré.
        if settings and settings.require_target_declaration and decision.playbook:
            verdict = self.registry.check_action(
                tenant.tenant_id,
                playbook=decision.playbook,
                target_type=_target_type_for(decision.playbook),
                target_value=context.target_value,
                asset_host=context.asset_host,
            )
            if not verdict.allowed and not verdict.requires_approval:
                decision.guards.append("out_of_scope")
                decision.decision = "notify_only"
                decision.reason += f" | garde-fou : {verdict.reason}"
                return decision
            if verdict.requires_approval and decision.decision == "auto":
                decision.guards.append("scope_requires_approval")
                decision.decision = "require_approval"
                decision.reason += f" | garde-fou : {verdict.reason}"

        # 3. Mode d'autonomie du tenant.
        if decision.decision == "auto":
            if tenant.mode == "manual":
                decision.guards.append("tenant_manual")
                decision.decision = "require_approval"
                decision.reason += " | garde-fou : tenant en mode 'manual' (approbation obligatoire)"
            elif tenant.mode == "supervised":
                critical = settings.critical_score_threshold if settings else 85.0
                if finding.risk_score >= critical:
                    decision.guards.append("critical_score_threshold")
                    decision.decision = "require_approval"
                    decision.reason += (
                        f" | garde-fou : score {finding.risk_score:.1f} ≥ seuil critique "
                        f"{critical:.1f} en mode 'supervised' — validation humaine requise"
                    )
                elif not tenant.allows_automation_for(context.target_value):
                    decision.guards.append("autonomy_allowlist")
                    decision.decision = "require_approval"
                    decision.reason += (
                        " | garde-fou : cible hors de l'allowlist d'autonomie "
                        f"{tenant.autonomy_allowlist} — validation humaine requise"
                    )

        # 4. Plafond horaire.
        cap = policy.then.max_actions_per_hour or tenant.max_actions_per_hour
        since = utcnow() - timedelta(hours=1)
        recent = self.store.count_actions_since(tenant.tenant_id, since)
        if recent >= cap:
            decision.guards.append("hourly_cap")
            decision.decision = "notify_only"
            decision.reason += (
                f" | garde-fou : plafond de {cap} actions/heure atteint ({recent} déjà demandées) — "
                "protection contre un faux positif massif"
            )
            return decision

        # 5. Cooldown sur la cible.
        cooldown = decision.cooldown_seconds or tenant.cooldown_seconds
        if cooldown and context.target_value and decision.playbook:
            last = self.store.last_action_for(tenant.tenant_id, decision.playbook, context.target_value)
            if last is not None:
                elapsed = (utcnow() - last.requested_at).total_seconds()
                if elapsed < cooldown and last.status in {"succeeded", "executing", "approved"}:
                    decision.guards.append("cooldown")
                    decision.decision = "notify_only"
                    decision.reason += (
                        f" | garde-fou : cooldown actif pour "
                        f"'{decision.playbook}' sur '{context.target_value}' "
                        f"({int(elapsed)}s écoulées < {cooldown}s) — action déjà appliquée"
                    )
                    return decision

        # 6. Dry-run : la décision reste, l'effet réel est désactivé.
        effective_dry_run = dry_run_global or tenant.dry_run
        if policy.then.dry_run is False:
            effective_dry_run = dry_run_global  # une politique ne peut pas lever le dry-run global
        decision.dry_run = effective_dry_run
        if effective_dry_run:
            decision.guards.append("dry_run")
            decision.reason += (
                " | garde-fou : mode simulation actif"
                f" ({'global' if dry_run_global else 'tenant'}) — aucune action réelle ne sera appliquée"
            )

        return decision

    # ----------------------------------------------------------------------------------
    # Utilitaire : résolution d'une décision pour un finding déjà en base
    # ----------------------------------------------------------------------------------

    def decide_for_finding(
        self,
        finding: Finding,
        tenant: Tenant,
        *,
        environment: str = "dev",
        settings: Settings | None = None,
    ) -> Decision:
        asset_host, target_value = extract_targets(finding)
        return self.decide(
            DecisionContext(
                finding=finding,
                tenant=tenant,
                environment=environment,
                settings=settings,
                asset_host=asset_host,
                target_value=target_value,
            )
        )

    def stats(self) -> dict[str, Any]:
        return {
            "policies": len(self.policies),
            "enabled": len(self.enabled_policies()),
            "evaluations": self.evaluations,
        }


# --------------------------------------------------------------------------------------
# Évaluation des conditions
# --------------------------------------------------------------------------------------


def evaluate_when(when: dict[str, Any], context: DecisionContext) -> tuple[bool, list[str]]:
    """Évalue un bloc ``when``. Retourne ``(correspond, explications)``.

    Sémantique : **ET** entre les clés ; une liste est un **OU** d'égalités ; un mapping est
    un ensemble de comparateurs (eux-mêmes en ET).
    """
    if not when:
        return True, ["aucune condition (politique fourre-tout)"]

    reasons: list[str] = []
    for key, expected in when.items():
        actual = context.resolve(key)
        ok, reason = _evaluate_key(key, actual, expected)
        reasons.append(reason)
        if not ok:
            return False, reasons
    return True, reasons


def _evaluate_key(key: str, actual: Any, expected: Any) -> tuple[bool, str]:
    # Comparaison de sévérité : on compare les rangs, pas les chaînes.
    if key == "finding.severity":
        return _evaluate_severity(actual, expected)

    if isinstance(expected, dict):
        return _evaluate_operators(key, actual, expected)

    if isinstance(expected, (list, tuple, set)):
        if key in {"finding.tags", "finding.mitre"}:
            # Sémantique « toutes les étiquettes demandées sont présentes » pour 'tags',
            # « au moins une » pour 'tags_any'.
            required = {_norm(item) for item in expected}
            present = {_norm(item) for item in _as_list(actual)}
            if key == "finding.tags":
                missing = required - present
                ok = not missing
                return ok, f"{key}={sorted(present)} {'contient' if ok else 'ne contient pas'} {sorted(required)}"
            ok = bool(required & present)
            return ok, f"{key} ∩ {sorted(required)} = {sorted(required & present)}"
        if key == "finding.tags_any":
            required = {_norm(item) for item in expected}
            present = {_norm(item) for item in _as_list(actual)}
            ok = bool(required & present)
            return ok, f"{key} ∩ {sorted(required)} = {sorted(required & present)}"
        candidates = {_norm(item) for item in expected}
        ok = _norm(actual) in candidates
        return ok, f"{key}={actual!r} {'∈' if ok else '∉'} {sorted(candidates)}"

    ok = _norm(actual) == _norm(expected)
    return ok, f"{key}={actual!r} {'==' if ok else '!='} {expected!r}"


def _evaluate_severity(actual: Any, expected: Any) -> tuple[bool, str]:
    actual_rank = severity_rank(str(actual))
    if isinstance(expected, (list, tuple, set)):
        ranks = {severity_rank(str(item)) for item in expected}
        ok = actual_rank in ranks
        return ok, f"finding.severity={actual} {'∈' if ok else '∉'} {sorted(expected)}"
    if isinstance(expected, dict):
        for operator, value in expected.items():
            target_rank = severity_rank(str(value))
            if not _numeric_compare(actual_rank, target_rank, operator):
                return False, f"finding.severity={actual} ne satisfait pas '{operator} {value}'"
        return True, f"finding.severity={actual} satisfait {expected}"
    ok = actual_rank == severity_rank(str(expected))
    return ok, f"finding.severity={actual} {'==' if ok else '!='} {expected}"


def _evaluate_operators(key: str, actual: Any, expected: dict[str, Any]) -> tuple[bool, str]:
    for operator, value in expected.items():
        if operator in _NUMERIC_OPERATORS:
            if not _numeric_compare(_to_number(actual), _to_number(value), operator):
                return False, f"{key}={actual!r} ne satisfait pas '{operator} {value}'"
        elif operator == "eq":
            if _norm(actual) != _norm(value):
                return False, f"{key}={actual!r} != {value!r}"
        elif operator == "ne":
            if _norm(actual) == _norm(value):
                return False, f"{key}={actual!r} == {value!r} (attendu différent)"
        elif operator in {"in", "not_in"}:
            candidates = {_norm(item) for item in _as_list(value)}
            found = _norm(actual) in candidates
            if operator == "in" and not found:
                return False, f"{key}={actual!r} ∉ {sorted(candidates)}"
            if operator == "not_in" and found:
                return False, f"{key}={actual!r} ∈ {sorted(candidates)} (exclu)"
        elif operator == "matches":
            if not _regex_match(value, actual):
                return False, f"{key}={actual!r} ne correspond pas au motif {value!r}"
        else:
            return False, f"{key}: opérateur inconnu '{operator}'"
    return True, f"{key}={actual!r} satisfait {expected}"


def _numeric_compare(left: float | None, right: float | None, operator: str) -> bool:
    if left is None or right is None:
        return False
    if operator == "gt":
        return left > right
    if operator == "gte":
        return left >= right
    if operator == "lt":
        return left < right
    if operator == "lte":
        return left <= right
    return False


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _regex_match(pattern: Any, text: Any) -> bool:
    if text is None:
        return False
    try:
        compiled = compile_regex(str(pattern), case_sensitive=False)
    except RegexTooComplexError:
        log.error("motif de politique refusé", extra={"pattern": str(pattern)[:120]})
        return False
    return bool(compiled.search(str(text)[:4096]))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _norm(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


# --------------------------------------------------------------------------------------
# Extraction des cibles d'un finding
# --------------------------------------------------------------------------------------

_HOST_KEYS = ("host", "asset", "target_host", "vhost", "server", "fqdn")
_TARGET_HINTS = ("src_ip", "source_ip", "client_ip", "remote_addr", "attacker_ip")


def extract_targets(finding: Finding) -> tuple[str | None, str | None]:
    """Déduit ``(hôte de l'actif, valeur de cible)`` depuis les preuves du finding.

    On s'appuie sur le dernier échantillon d'évidence (le plus récent), en restant
    volontairement conservateur : si l'information n'est pas explicitement présente, on
    retourne ``None`` — et l'absence de cible fait retomber les garde-fous du côté sûr.
    """
    samples = finding.evidence.get("samples") or []
    labels: dict[str, Any] = {}
    if samples and isinstance(samples[-1], dict):
        labels = dict(samples[-1].get("labels") or {})
        source = samples[-1].get("source") or {}
        if isinstance(source, dict) and source.get("host") and not labels.get("host"):
            labels["host"] = source["host"]

    asset_host = None
    for key in _HOST_KEYS:
        value = labels.get(key)
        if value:
            asset_host = str(value)
            break

    target_value = None
    for key in _TARGET_HINTS:
        value = labels.get(key)
        if value:
            target_value = str(value)
            break
    if target_value is None:
        # Repli sur la règle qui a produit le finding : le chemin de cible est souvent
        # porté par la politique, pas par l'événement.
        target_value = None
    return asset_host, target_value


def resolve_param_target(finding: Finding, path: str | None) -> str | None:
    """Résout un paramètre de type chemin (``labels.src_ip``) sur les preuves du finding."""
    if not path:
        return None
    samples = finding.evidence.get("samples") or []
    if not samples:
        return None
    from ..core.util import deep_get

    for sample in reversed(samples):
        value = deep_get(sample, path)
        if value:
            return str(value)
    return None


def _target_type_for(playbook: str) -> str:
    if playbook in {"block-source-ip", "rate-limit-source", "unblock-source-ip", "remove-rate-limit"}:
        return "ip"
    if playbook in {"isolate-host", "unisolate-host", "harden-endpoint"}:
        return "host"
    if playbook in {"quarantine-artifact", "restore-artifact"}:
        return "file"
    if playbook == "patch-dependency":
        return "package"
    if playbook == "rotate-secret":
        return "secret"
    if playbook == "revoke-session":
        return "session"
    return "other"


IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


__all__ = [
    "DecisionContext",
    "DecisionEngine",
    "PolicyEvaluation",
    "WEEKDAYS",
    "evaluate_when",
    "extract_targets",
    "resolve_param_target",
]
