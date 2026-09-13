"""Registre des connecteurs : associe un nom **logique** (``waf``, ``notify``…) à un pilote.

Les playbooks ne connaissent que des noms logiques. C'est ce qui permet de livrer un
playbook ``block-source-ip`` qui fonctionne en simulation chez tout le monde, puis de le
brancher sur Cloudflare, Nginx ou une passerelle maison **sans modifier le playbook** — juste
``config/connectors.yaml``.

Sûreté : un nom logique inconnu retombe sur la simulation avec un avertissement. On ne
devine jamais un connecteur, et on n'échoue jamais au chargement à cause d'un connecteur
manquant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..core.logging_setup import get_logger
from .connectors.aws_waf import AwsWafConnector
from .connectors.base import Connector
from .connectors.cloudflare import CloudflareConnector
from .connectors.http_webhook import HttpWebhookConnector
from .connectors.local import (
    LocalQuarantineConnector,
    LocalTicketConnector,
    NginxLocalConnector,
)
from .connectors.notifications import GithubIssueConnector, SlackConnector
from .connectors.simulation import SimulationConnector

log = get_logger("actions.registry")

#: Réglages de connecteur qui désignent un **chemin de fichier ou de répertoire**, avec leur
#: valeur par défaut. Ils sont résolus depuis ``root_dir`` et **jamais** depuis le répertoire
#: courant du processus — même règle que ``THOT_DB_URL``, ``THOT_RULES_DIR`` et consorts.
#:
#: Sans cela, `thotsecure serve` lancé depuis un autre répertoire (unité systemd, tâche
#: planifiée, conteneur avec un WORKDIR différent) écrirait ses tickets, sa quarantaine et son
#: fichier de refus Nginx **ailleurs** : les preuves et les contre-mesures seraient alors
#: introuvables là où l'exploitant les attend, sans la moindre erreur affichée.
PATH_SETTINGS: dict[str, dict[str, str]] = {
    "nginx-local": {
        "deny_file": NginxLocalConnector.DEFAULT_DENY_FILE,
        "state_file": NginxLocalConnector.DEFAULT_STATE_FILE,
    },
    "local-quarantine": {"quarantine_dir": LocalQuarantineConnector.DEFAULT_DIR},
    "local-ticket": {"directory": LocalTicketConnector.DEFAULT_DIR},
}

#: Pilotes disponibles.
#:
#: Les pilotes natifs (``cloudflare``, ``aws-waf``, ``slack``, ``github-issues``) produisent un
#: effet réel **sur l'infrastructure du client** : ils ne sont jamais actifs par défaut, c'est
#: ``config/connectors.yaml`` qui les branche, un nom logique à la fois.
DRIVERS: dict[str, type[Connector]] = {
    "simulation": SimulationConnector,
    "nginx-local": NginxLocalConnector,
    "local-quarantine": LocalQuarantineConnector,
    "local-ticket": LocalTicketConnector,
    "http-webhook": HttpWebhookConnector,
    "cloudflare": CloudflareConnector,
    "aws-waf": AwsWafConnector,
    "slack": SlackConnector,
    "github-issues": GithubIssueConnector,
}

#: Configuration par défaut : **tout en simulation**, sauf la quarantaine et le ticketing
#: local, qui ne présentent aucun risque et sont immédiatement utiles.
#:
#: Comment brancher un pilote natif (aucune modification de playbook n'est nécessaire) :
#:
#: * ``waf``       : ``driver: cloudflare`` (IP Access Rules, jeton à portée minimale) ou
#:                   ``driver: aws-waf`` (IPSet WAFv2, clé dédiée ``wafv2:GetIPSet`` +
#:                   ``wafv2:UpdateIPSet``) — utilisé par ``block-source-ip``,
#:                   ``unblock-source-ip`` ;
#: * ``ratelimit`` : ``driver: cloudflare`` (ruleset de phase ``http_ratelimit``) — utilisé
#:                   par ``rate-limit-source``, ``remove-rate-limit`` ;
#: * ``notify``    : ``driver: slack`` (webhook entrant, message de correction au rollback) —
#:                   utilisé par ``notify-webhook`` ;
#: * ``ticketing`` : ``driver: github-issues`` (issues GitHub) au lieu de ``local-ticket`` —
#:                   utilisé par ``open-ticket``, ``close-ticket``, ``patch-dependency``.
#:
#: Le passage d'un nom logique en pilote natif est une décision **par tenant et par nom** :
#: on peut bloquer réellement côté Cloudflare tout en gardant ``notify`` en simulation. Le
#: mode simulation reste la valeur sûre si un pilote est mal configuré : un connecteur natif
#: sans credential retourne un échec explicite, jamais un faux succès.
DEFAULT_CONNECTORS: dict[str, dict[str, Any]] = {
    "waf": {"driver": "simulation", "settings": {}},
    "ratelimit": {"driver": "simulation", "settings": {}},
    "endpoint": {"driver": "simulation", "settings": {}},
    "network": {"driver": "simulation", "settings": {}},
    "iam": {"driver": "simulation", "settings": {}},
    "secretstore": {"driver": "simulation", "settings": {}},
    "ci": {"driver": "simulation", "settings": {}},
    "harden": {"driver": "simulation", "settings": {}},
    "notify": {"driver": "simulation", "settings": {}},
    "artifact": {"driver": "local-quarantine", "settings": {"quarantine_dir": "./data/quarantine"}},
    "ticketing": {"driver": "local-ticket", "settings": {"directory": "./data/tickets"}},
}


class ConnectorRegistry:
    """Résout les noms logiques vers des instances de connecteurs."""

    def __init__(
        self,
        configuration: dict[str, dict[str, Any]] | None = None,
        *,
        dry_run: bool = True,
        source: str | None = None,
        root_dir: str | Path | None = None,
    ) -> None:
        self.configuration = configuration or {key: dict(value) for key, value in DEFAULT_CONNECTORS.items()}
        self.dry_run = dry_run
        self.source = source
        #: Racine de résolution des chemins déclarés par les connecteurs (jamais le CWD).
        self.root_dir = Path(root_dir).expanduser() if root_dir is not None else None
        self._instances: dict[str, Connector] = {}
        self._unknown: set[str] = set()

    # ----------------------------------------------------------------------------------
    # Chargement
    # ----------------------------------------------------------------------------------

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        dry_run: bool = True,
        root_dir: str | Path | None = None,
    ) -> ConnectorRegistry:
        file_path = Path(path)
        if not file_path.exists():
            log.info(
                "aucun fichier de connecteurs : configuration par défaut (simulation)",
                extra={"path": str(file_path)},
            )
            return cls(dry_run=dry_run, source=str(file_path), root_dir=root_dir)
        try:
            document = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            log.error(
                "fichier de connecteurs illisible : repli sur la simulation",
                extra={"error": str(exc)},
            )
            return cls(dry_run=dry_run, source=str(file_path), root_dir=root_dir)

        configured = document.get("connectors") or {}
        if not isinstance(configured, dict):
            log.error("bloc 'connectors' invalide : repli sur la simulation")
            return cls(dry_run=dry_run, source=str(file_path), root_dir=root_dir)

        merged = {key: dict(value) for key, value in DEFAULT_CONNECTORS.items()}
        for name, body in configured.items():
            if isinstance(body, str):
                merged[str(name)] = {"driver": body, "settings": {}}
            elif isinstance(body, dict):
                merged[str(name)] = {
                    "driver": str(body.get("driver") or "simulation"),
                    "settings": body.get("settings") or {},
                }
            else:
                log.error("connecteur ignoré (format invalide)", extra={"connector": str(name)})
        log.info(
            "connecteurs configurés",
            extra={
                "source": str(file_path),
                "connectors": {name: body["driver"] for name, body in merged.items()},
            },
        )
        return cls(merged, dry_run=dry_run, source=str(file_path), root_dir=root_dir)

    # ----------------------------------------------------------------------------------
    # Résolution
    # ----------------------------------------------------------------------------------

    def get(self, name: str) -> Connector:
        """Retourne le connecteur d'un nom logique (jamais ``None``)."""
        key = str(name or "").strip().lower()
        cached = self._instances.get(key)
        if cached is not None:
            return cached

        body = self.configuration.get(key)
        if body is None:
            # Le nom est peut-être directement un pilote (``connector: nginx-local``).
            if key in DRIVERS:
                driver_name, settings = key, {}
            else:
                if key not in self._unknown:
                    self._unknown.add(key)
                    log.warning(
                        "connecteur logique inconnu : simulation utilisée par défaut",
                        extra={"connector": key, "known": sorted(self.configuration)},
                    )
                driver_name, settings = "simulation", {}
        else:
            driver_name = str(body.get("driver") or "simulation")
            settings = body.get("settings") or {}

        driver = DRIVERS.get(driver_name)
        if driver is None:
            log.error(
                "pilote de connecteur inconnu : simulation utilisée par défaut",
                extra={"connector": key, "driver": driver_name, "known_drivers": sorted(DRIVERS)},
            )
            driver = SimulationConnector
            driver_name = "simulation"

        instance = driver(self._resolve_paths(driver_name, settings), dry_run=self.dry_run)
        self._instances[key] = instance
        return instance

    def _resolve_paths(self, driver_name: str, settings: dict[str, Any]) -> dict[str, Any]:
        """Résout les réglages de type chemin depuis ``root_dir``.

        Les valeurs par défaut sont injectées au passage : le connecteur reçoit donc toujours
        un chemin **absolu**, et son propre repli relatif ne peut plus s'appliquer.
        """
        keys = PATH_SETTINGS.get(driver_name)
        if not keys:
            return settings
        resolved = dict(settings)
        for key, default in keys.items():
            raw = resolved.get(key) or default
            if isinstance(raw, (list, tuple)):
                resolved[key] = [
                    str(self._absolute(item)) if isinstance(item, str) and item else item
                    for item in raw
                ]
            elif isinstance(raw, str):
                resolved[key] = str(self._absolute(raw))
        return resolved

    def _absolute(self, value: str) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute() or self.root_dir is None:
            return path
        return (self.root_dir / path).resolve()

    def set_dry_run(self, dry_run: bool) -> None:
        """Propage un changement de mode à tous les connecteurs déjà instanciés."""
        self.dry_run = dry_run
        for instance in self._instances.values():
            instance.dry_run = dry_run

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dry_run": self.dry_run,
            "connectors": {
                name: self.get(name).description for name in sorted(self.configuration)
            },
            "unknown_requested": sorted(self._unknown),
        }

    def stats(self) -> dict[str, Any]:
        return {
            "connectors": len(self.configuration),
            "instantiated": len(self._instances),
            "calls": sum(instance.calls for instance in self._instances.values()),
            "failures": sum(instance.failures for instance in self._instances.values()),
            "simulated_only": all(
                isinstance(self.get(name), SimulationConnector) for name in self.configuration
            ),
        }


__all__ = ["DEFAULT_CONNECTORS", "DRIVERS", "ConnectorRegistry"]
