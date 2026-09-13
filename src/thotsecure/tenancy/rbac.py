"""RBAC : rôles, capacités, application.

Quatre rôles, du plus restreint au plus large. Le principe est celui du moindre privilège :
un analyste SOC doit pouvoir *lire et qualifier*, pas *agir sur l'infrastructure* ; c'est une
capacité distincte, accordée séparément (``responder``), et chaque usage est audité.

Les capacités sont plus fines que les rôles : le code vérifie toujours une **capacité**
(``execute:actions``), jamais un rôle en dur. Cela permet d'ajouter demain un rôle
``automation`` ou ``auditor`` sans réécrire les points de contrôle.
"""

from __future__ import annotations

from ..core.errors import PermissionDeniedError
from ..core.models import Principal, Role

#: Capacités élémentaires du produit.
CAP_READ_EVENTS = "read:events"
CAP_WRITE_EVENTS = "write:events"
CAP_READ_FINDINGS = "read:findings"
CAP_WRITE_FINDINGS = "write:findings"
CAP_READ_RULES = "read:rules"
CAP_READ_POLICIES = "read:policies"
CAP_READ_AUDIT = "read:audit"
CAP_READ_STATS = "read:stats"
CAP_EXECUTE_ACTIONS = "execute:actions"
CAP_APPROVE_ACTIONS = "approve:actions"
CAP_ADMIN_TENANTS = "admin:tenants"
CAP_ADMIN_KEYS = "admin:keys"
CAP_ADMIN_RULES = "admin:rules"
CAP_ADMIN_POLICIES = "admin:policies"
CAP_ADMIN_SYSTEM = "admin:system"

_ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "viewer": frozenset(
        {
            CAP_READ_EVENTS,
            CAP_READ_FINDINGS,
            CAP_READ_RULES,
            CAP_READ_POLICIES,
            CAP_READ_AUDIT,
            CAP_READ_STATS,
        }
    ),
    "analyst": frozenset(
        {
            CAP_READ_EVENTS,
            CAP_READ_FINDINGS,
            CAP_READ_RULES,
            CAP_READ_POLICIES,
            CAP_READ_AUDIT,
            CAP_READ_STATS,
            CAP_WRITE_EVENTS,
            CAP_WRITE_FINDINGS,
        }
    ),
    "responder": frozenset(
        {
            CAP_READ_EVENTS,
            CAP_READ_FINDINGS,
            CAP_READ_RULES,
            CAP_READ_POLICIES,
            CAP_READ_AUDIT,
            CAP_READ_STATS,
            CAP_WRITE_EVENTS,
            CAP_WRITE_FINDINGS,
            CAP_EXECUTE_ACTIONS,
            CAP_APPROVE_ACTIONS,
        }
    ),
    "admin": frozenset(
        {
            CAP_READ_EVENTS,
            CAP_READ_FINDINGS,
            CAP_READ_RULES,
            CAP_READ_POLICIES,
            CAP_READ_AUDIT,
            CAP_READ_STATS,
            CAP_WRITE_EVENTS,
            CAP_WRITE_FINDINGS,
            CAP_EXECUTE_ACTIONS,
            CAP_APPROVE_ACTIONS,
            CAP_ADMIN_TENANTS,
            CAP_ADMIN_KEYS,
            CAP_ADMIN_RULES,
            CAP_ADMIN_POLICIES,
            CAP_ADMIN_SYSTEM,
        }
    ),
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    "viewer": "Lecture seule : tableaux de bord, findings, audit, règles.",
    "analyst": "Lecture + qualification : acquitter, clôturer, supprimer du bruit, ingérer.",
    "responder": "Analyste + réponse : planifier, approuver, exécuter et annuler des actions.",
    "admin": "Administration complète : tenants, clés, règles, politiques, système.",
}

ALL_CAPABILITIES: frozenset[str] = frozenset(
    capability for capabilities in _ROLE_CAPABILITIES.values() for capability in capabilities
)


def capabilities_for(role: str) -> frozenset[str]:
    """Capacités d'un rôle. Un rôle inconnu n'obtient **rien** (échec fermé)."""
    return _ROLE_CAPABILITIES.get(str(role or "").lower(), frozenset())


def has_capability(role: str, capability: str) -> bool:
    return capability in capabilities_for(role)


def require_capability(role: str, capability: str, *, actor: str = "") -> None:
    """Lève ``PermissionDeniedError`` si le rôle ne porte pas la capacité."""
    if has_capability(role, capability):
        return
    raise PermissionDeniedError(
        f"le rôle '{role}' ne dispose pas de la capacité '{capability}'",
        details={"required": capability, "role": role, "actor": actor},
    )


def build_principal(
    *,
    tenant_id: str,
    role: Role | str,
    key_id: str | None = None,
    label: str = "",
    authenticated: bool = True,
) -> Principal:
    return Principal(
        tenant_id=tenant_id,
        role=str(role),  # type: ignore[arg-type]
        key_id=key_id,
        label=label,
        capabilities=capabilities_for(str(role)),
        authenticated=authenticated,
    )


def role_matrix() -> dict[str, list[str]]:
    """Matrice rôle → capacités (documentation et endpoint ``/auth/whoami``)."""
    return {role: sorted(capabilities) for role, capabilities in sorted(_ROLE_CAPABILITIES.items())}


__all__ = [
    "ALL_CAPABILITIES",
    "CAP_ADMIN_KEYS",
    "CAP_ADMIN_POLICIES",
    "CAP_ADMIN_RULES",
    "CAP_ADMIN_SYSTEM",
    "CAP_ADMIN_TENANTS",
    "CAP_APPROVE_ACTIONS",
    "CAP_EXECUTE_ACTIONS",
    "CAP_READ_AUDIT",
    "CAP_READ_EVENTS",
    "CAP_READ_FINDINGS",
    "CAP_READ_POLICIES",
    "CAP_READ_RULES",
    "CAP_READ_STATS",
    "CAP_WRITE_EVENTS",
    "CAP_WRITE_FINDINGS",
    "ROLE_DESCRIPTIONS",
    "build_principal",
    "capabilities_for",
    "has_capability",
    "require_capability",
    "role_matrix",
]
