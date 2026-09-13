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
from .connectors.base import Connector
from .connectors.http_webhook import HttpWebhookConnector
from .connectors.local import (
    LocalQuarantineConnector,
    LocalTicketConnector,
    NginxLocalConnector,
)
from .connectors.simulation import SimulationConnector

log = get_logger("actions.registry")

#: Pilotes disponibles.
DRIVERS: dict[str, type[Connector]] = {
    "simulation": SimulationConnector,
    "nginx-local": NginxLocalConnector,
    "local-quarantine": LocalQuarantineConnector,
    "local-ticket": LocalTicketConnector,
    "http-webhook": HttpWebhookConnector,
}

#: Configuration par défaut : **tout en simulation**, sauf la quarantaine et le ticketing
#: local, qui ne présentent aucun risque et sont immédiatement utiles.
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
    ) -> None:
        self.configuration = configuration or {key: dict(value) for key, value in DEFAULT_CONNECTORS.items()}
        self.dry_run = dry_run
        self.source = source
        self._instances: dict[str, Connector] = {}
        self._unknown: set[str] = set()

    # ----------------------------------------------------------------------------------
    # Chargement
    # ----------------------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path, *, dry_run: bool = True) -> ConnectorRegistry:
        file_path = Path(path)
        if not file_path.exists():
            log.info(
                "aucun fichier de connecteurs : configuration par défaut (simulation)",
                extra={"path": str(file_path)},
            )
            return cls(dry_run=dry_run, source=str(file_path))
        try:
            document = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            log.error(
                "fichier de connecteurs illisible : repli sur la simulation",
                extra={"error": str(exc)},
            )
            return cls(dry_run=dry_run, source=str(file_path))

        configured = document.get("connectors") or {}
        if not isinstance(configured, dict):
            log.error("bloc 'connectors' invalide : repli sur la simulation")
            return cls(dry_run=dry_run, source=str(file_path))

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
        return cls(merged, dry_run=dry_run, source=str(file_path))

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

        instance = driver(settings, dry_run=self.dry_run)
        self._instances[key] = instance
        return instance

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
