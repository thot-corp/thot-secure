"""Périmètre déclaré (``config/targets.yaml``) — le garde-fou anti-abus d'Thot Secure.

Thot Secure applique des contre-mesures. La question la plus dangereuse d'un SOAR est donc :
« sur quoi a-t-il le droit d'agir ? ». La réponse est un fichier de périmètre explicite,
versionné, relu, et jamais déduit automatiquement d'un scan.

Deux notions distinctes, souvent confondues, sont séparées ici :

* **actif (asset)** : ce que le tenant possède et que l'on surveille (``shop.acme.fr``) ;
* **périmètre d'action (owned_cidrs / hosts)** : ce que l'on a le droit de modifier.

Un blocage d'IP attaquante agit sur une adresse qui **n'appartient pas** au tenant : ce qui
doit être vérifié, c'est que l'**actif attaqué** est bien déclaré. À l'inverse, isoler un hôte
ou patcher une dépendance modifie notre propre infrastructure : la cible elle-même doit être
déclarée. Cette distinction est implémentée dans :meth:`TargetRegistry.check_action`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .core.logging_setup import get_logger
from .core.util import ip_in_cidrs, is_valid_cidr, is_valid_ip, normalize_host

log = get_logger("scope")

#: Playbooks dont la cible est une entité **externe** (attaquant, source abusive). Le contrôle
#: porte alors sur l'actif protégé, pas sur la cible de l'action.
INBOUND_MITIGATION_PLAYBOOKS = frozenset(
    {
        "block-source-ip",
        "rate-limit-source",
        "unblock-source-ip",
        "remove-rate-limit",
    }
)

#: Playbooks qui modifient directement notre infrastructure : la cible doit être déclarée.
INFRASTRUCTURE_PLAYBOOKS = frozenset(
    {
        "isolate-host",
        "unisolate-host",
        "quarantine-artifact",
        "restore-artifact",
        "patch-dependency",
        "rotate-secret",
        "revoke-session",
        "harden-endpoint",
    }
)


@dataclass(slots=True)
class Asset:
    """Actif surveillé déclaré par le tenant."""

    host: str
    urls: list[str] = field(default_factory=list)
    criticality: float = 1.0
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def normalized_host(self) -> str:
        return normalize_host(self.host)


@dataclass(slots=True)
class ConfigFile:
    """Fichier de configuration à auditer et nature du contrôle à appliquer."""

    path: str
    kind: str = "auto"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LogSource:
    """Source de journal locale déclarée (fichier + format)."""

    path: str
    format: str = "auto"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TenantScope:
    """Périmètre déclaré d'un tenant."""

    tenant_id: str
    assets: list[Asset] = field(default_factory=list)
    owned_cidrs: list[str] = field(default_factory=list)
    protected_targets: list[str] = field(default_factory=list)
    allow_probe: bool = False
    #: Journaux locaux à surveiller (chemins explicites : on ne devine jamais où sont les logs).
    log_sources: list[LogSource] = field(default_factory=list)
    #: Fichiers de dépendances à analyser (requirements.txt, package.json, go.mod…).
    manifests: list[str] = field(default_factory=list)
    #: Fichiers de configuration à auditer (sshd_config, nginx.conf, docker-compose.yml…).
    config_files: list[ConfigFile] = field(default_factory=list)

    # -- interrogation ------------------------------------------------------------------

    @property
    def hosts(self) -> set[str]:
        return {asset.normalized_host for asset in self.assets}

    @property
    def urls(self) -> list[str]:
        out: list[str] = []
        for asset in self.assets:
            out.extend(asset.urls)
        return out

    def asset_for_host(self, host: str | None) -> Asset | None:
        if not host:
            return None
        candidate = normalize_host(host)
        for asset in self.assets:
            if asset.normalized_host == candidate:
                return asset
        return None

    def owns(self, value: str | None) -> bool:
        """Vrai si la valeur (IP, CIDR, hôte ou URL) appartient au périmètre d'action."""
        if not value:
            return False
        text = str(value).strip()
        if is_valid_cidr(text) and "/" in text:
            return any(text == cidr for cidr in self.owned_cidrs)
        if is_valid_ip(text):
            return ip_in_cidrs(text, self.owned_cidrs)
        return normalize_host(text) in self.hosts

    def is_protected(self, value: str | None) -> bool:
        if not value:
            return False
        text = str(value).strip()
        if is_valid_ip(text) or ("/" in text and is_valid_cidr(text)):
            return ip_in_cidrs(text, self.protected_targets)
        return normalize_host(text) in {normalize_host(item) for item in self.protected_targets}

    def asset_criticality(self, host: str | None) -> float:
        asset = self.asset_for_host(host)
        return asset.criticality if asset else 1.0

    def describe(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "assets": [asset.host for asset in self.assets],
            "owned_cidrs": list(self.owned_cidrs),
            "protected_targets": list(self.protected_targets),
            "allow_probe": self.allow_probe,
            "log_sources": [source.path for source in self.log_sources],
            "manifests": list(self.manifests),
            "config_files": [item.path for item in self.config_files],
        }


@dataclass(slots=True)
class ScopeDecision:
    """Verdict de périmètre, avec la raison exacte (affichée à l'analyste et auditée)."""

    allowed: bool
    reason: str
    requires_approval: bool = False

    def __bool__(self) -> bool:  # pragma: no cover - confort de lecture
        return self.allowed


class TargetRegistry:
    """Charge et interroge ``config/targets.yaml``.

    Le fichier est **la** source de vérité du périmètre. Il est volontairement en clair,
    relu et versionné (pas d'apprentissage automatique du périmètre, pas d'énumération
    réseau) : un outil qui découvre tout seul ce qu'il a le droit de bloquer finira par
    bloquer la mauvaise chose.
    """

    def __init__(self, scopes: dict[str, TenantScope] | None = None, *, source: str | None = None) -> None:
        self._scopes = scopes or {}
        self.source = source

    # ----------------------------------------------------------------------------------
    # Chargement
    # ----------------------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> TargetRegistry:
        file_path = Path(path)
        if not file_path.exists():
            log.warning(
                "aucun fichier de périmètre : aucune cible n'est déclarée",
                extra={"path": str(file_path)},
            )
            return cls({}, source=str(file_path))
        try:
            document = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            log.error("périmètre illisible : aucune cible déclarée", extra={"error": str(exc)})
            return cls({}, source=str(file_path))

        scopes: dict[str, TenantScope] = {}
        tenants = document.get("tenants") or {}
        if not isinstance(tenants, dict):
            log.error("bloc 'tenants' invalide dans le fichier de périmètre")
            return cls({}, source=str(file_path))

        for tenant_id, body in tenants.items():
            if not isinstance(body, dict):
                log.error("périmètre de tenant invalide", extra={"tenant_id": tenant_id})
                continue
            assets: list[Asset] = []
            for item in body.get("assets") or []:
                if isinstance(item, str):
                    assets.append(Asset(host=item))
                elif isinstance(item, dict) and item.get("host"):
                    assets.append(
                        Asset(
                            host=str(item["host"]),
                            urls=[str(url) for url in item.get("urls") or []],
                            criticality=float(item.get("criticality", 1.0)),
                            tags=[str(tag) for tag in item.get("tags") or []],
                            notes=str(item.get("notes") or ""),
                        )
                    )
                else:
                    log.error(
                        "actif ignoré (format invalide)",
                        extra={"tenant_id": tenant_id, "item": str(item)[:120]},
                    )
            owned = [str(item) for item in body.get("owned_cidrs") or [] if is_valid_cidr(str(item))]
            protected = [
                str(item)
                for item in body.get("protected_targets") or []
                if is_valid_cidr(str(item)) or is_valid_ip(str(item)) or "." in str(item)
            ]

            log_sources: list[LogSource] = []
            for item in body.get("log_sources") or []:
                if isinstance(item, str):
                    log_sources.append(LogSource(path=item))
                elif isinstance(item, dict) and item.get("path"):
                    log_sources.append(
                        LogSource(
                            path=str(item["path"]),
                            format=str(item.get("format") or "auto"),
                            tags=[str(tag) for tag in item.get("tags") or []],
                        )
                    )
                else:
                    log.error(
                        "source de journal ignorée (format invalide)",
                        extra={"tenant_id": tenant_id, "item": str(item)[:120]},
                    )

            manifests = [str(item) for item in body.get("manifests") or []]

            config_files: list[ConfigFile] = []
            for item in body.get("config_files") or []:
                if isinstance(item, str):
                    config_files.append(ConfigFile(path=item))
                elif isinstance(item, dict) and item.get("path"):
                    config_files.append(
                        ConfigFile(
                            path=str(item["path"]),
                            kind=str(item.get("kind") or "auto"),
                            tags=[str(tag) for tag in item.get("tags") or []],
                        )
                    )

            scopes[str(tenant_id).lower()] = TenantScope(
                tenant_id=str(tenant_id).lower(),
                assets=assets,
                owned_cidrs=owned,
                protected_targets=protected,
                allow_probe=bool(body.get("allow_probe", False)),
                log_sources=log_sources,
                manifests=manifests,
                config_files=config_files,
            )

        log.info(
            "périmètre chargé",
            extra={"tenants": len(scopes), "source": str(file_path)},
        )
        return cls(scopes, source=str(file_path))

    # ----------------------------------------------------------------------------------
    # Interrogation
    # ----------------------------------------------------------------------------------

    def for_tenant(self, tenant_id: str) -> TenantScope:
        return self._scopes.get(tenant_id.lower(), TenantScope(tenant_id=tenant_id.lower()))

    def has_tenant(self, tenant_id: str) -> bool:
        return tenant_id.lower() in self._scopes

    def tenants(self) -> list[str]:
        return sorted(self._scopes)

    def check_probe(self, tenant_id: str) -> ScopeDecision:
        """Autorise-t-on un audit de surface sur ce tenant ?

        Exige une déclaration **et** un opt-in explicite (``allow_probe: true``). Auditer la
        surface d'exposition est défensif, mais uniquement sur ce qu'on possède.
        """
        scope = self.for_tenant(tenant_id)
        if not scope.assets:
            return ScopeDecision(
                False,
                f"aucun actif déclaré pour le tenant '{tenant_id}' : "
                "renseignez config/targets.yaml avant toute collecte",
            )
        if not scope.allow_probe:
            return ScopeDecision(
                False,
                f"le tenant '{tenant_id}' n'a pas activé 'allow_probe' : "
                "l'audit de surface nécessite un opt-in explicite",
            )
        return ScopeDecision(True, f"{len(scope.assets)} actif(s) déclaré(s)")

    def check_action(
        self,
        tenant_id: str,
        *,
        playbook: str,
        target_type: str,
        target_value: str | None,
        asset_host: str | None = None,
    ) -> ScopeDecision:
        """Vérifie qu'une action reste dans le périmètre déclaré.

        Trois cas, du plus permissif au plus restrictif :

        1. **atténuation entrante** (blocage d'une IP attaquante) : l'actif attaqué doit être
           déclaré, sinon l'action est autorisée mais **soumise à approbation** ;
        2. **modification d'infrastructure** : la cible doit appartenir au périmètre
           (``owned_cidrs`` ou hôte déclaré), sinon approbation obligatoire ;
        3. **cible protégée** : jamais d'action automatique, quel que soit le playbook.
        """
        scope = self.for_tenant(tenant_id)

        if scope.is_protected(target_value or "") or scope.is_protected(asset_host or ""):
            return ScopeDecision(
                False,
                f"cible protégée par le tenant '{tenant_id}' "
                f"(protected_targets) : aucune action automatique n'est autorisée",
            )

        if playbook in INBOUND_MITIGATION_PLAYBOOKS:
            if asset_host and scope.asset_for_host(asset_host):
                return ScopeDecision(
                    True, f"actif '{asset_host}' déclaré pour le tenant '{tenant_id}'"
                )
            if not scope.assets:
                return ScopeDecision(
                    False,
                    f"aucun actif déclaré pour '{tenant_id}': une action de blocage ne peut pas "
                    "être justifiée par un périmètre vide",
                    requires_approval=True,
                )
            return ScopeDecision(
                True,
                f"actif source non identifié comme déclaré ({asset_host or 'inconnu'}) : "
                "action autorisée mais soumise à approbation humaine",
                requires_approval=True,
            )

        if playbook in INFRASTRUCTURE_PLAYBOOKS:
            if scope.owns(target_value):
                return ScopeDecision(
                    True, f"cible '{target_value}' appartient au périmètre de '{tenant_id}'"
                )
            return ScopeDecision(
                False,
                f"cible '{target_value}' absente du périmètre déclaré de '{tenant_id}' "
                "(owned_cidrs / assets) : une action sur notre propre infrastructure exige "
                "une cible déclarée",
                requires_approval=True,
            )

        # Playbook inconnu du périmètre : prudence maximale.
        return ScopeDecision(
            True,
            f"playbook '{playbook}' non classé : approbation humaine requise par défaut",
            requires_approval=True,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "tenants": {tenant_id: scope.describe() for tenant_id, scope in self._scopes.items()},
        }


__all__ = [
    "INFRASTRUCTURE_PLAYBOOKS",
    "INBOUND_MITIGATION_PLAYBOOKS",
    "Asset",
    "ConfigFile",
    "LogSource",
    "ScopeDecision",
    "TargetRegistry",
    "TenantScope",
]
