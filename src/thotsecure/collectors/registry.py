"""Registre des collecteurs embarqués."""

from __future__ import annotations

from typing import Any

from ..core.logging_setup import get_logger
from .base import Collector
from .config_audit import ConfigAuditCollector
from .dependency_scan import DependencyScanCollector
from .log_tail import LogTailCollector
from .syslog import SyslogCollector
from .tls_cert import TlsCertCollector
from .web_probe import WebProbeCollector

log = get_logger("collectors.registry")


class CollectorRegistry:
    """Registre nom → instance de collecteur."""

    def __init__(self, collectors: list[Collector] | None = None) -> None:
        self._collectors: dict[str, Collector] = {}
        for collector in collectors or []:
            self.register(collector)

    def register(self, collector: Collector) -> None:
        if collector.name in self._collectors:
            log.warning("collecteur déjà enregistré, remplacement", extra={"collector": collector.name})
        self._collectors[collector.name] = collector

    def get(self, name: str) -> Collector | None:
        return self._collectors.get(name)

    def require(self, name: str) -> Collector:
        collector = self.get(name)
        if collector is None:
            from ..core.errors import NotFoundError

            raise NotFoundError(
                f"collecteur inconnu: {name}", details={"available": self.names()}
            )
        return collector

    def all(self) -> list[Collector]:
        return [self._collectors[name] for name in sorted(self._collectors)]

    def names(self) -> list[str]:
        return sorted(self._collectors)

    def describe(self) -> list[dict[str, Any]]:
        return [collector.describe() for collector in self.all()]

    def __len__(self) -> int:
        return len(self._collectors)


def default_registry() -> CollectorRegistry:
    """Registre des collecteurs livrés avec Thot Secure."""
    return CollectorRegistry(
        [
            WebProbeCollector(),
            TlsCertCollector(),
            LogTailCollector(),
            DependencyScanCollector(),
            ConfigAuditCollector(),
            SyslogCollector(),
        ]
    )


__all__ = ["CollectorRegistry", "default_registry"]
