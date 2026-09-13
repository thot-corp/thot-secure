"""Connecteur de simulation — **le pilote par défaut de Thot Secure**.

Il n'agit sur rien, et il le dit. C'est un choix produit assumé : on peut brancher Thot
Secure sur une infrastructure de production avant d'avoir configuré le moindre connecteur,
observer ses décisions pendant des semaines, puis activer les effets réels un par un.

Un connecteur de simulation qui prétendrait « avoir bloqué » une adresse serait dangereux par
mensonge : l'analyste croirait l'incident traité. Ici, ``simulated=True`` est propagé jusqu'au
rapport, à la console et au journal d'audit.

Propriété importante : la simulation reste simulée **même si ``dry_run=false``**. Désactiver
le mode simulation sans avoir configuré de connecteur réel ne peut donc produire aucun effet.
"""

from __future__ import annotations

import time
from typing import Any

from ...core.logging_setup import get_logger
from .base import OPERATIONS, Connector, ConnectorResult, redact_params

log = get_logger("actions.connector.simulation")


class SimulationConnector(Connector):
    """Journalise l'intention, produit un jeton de rollback, ne touche à rien."""

    driver = "simulation"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(OPERATIONS)

    def call(self, operation: str, params: dict[str, Any] | None = None) -> ConnectorResult:
        """Surcharge complète : aucune délégation à la classe de base.

        La classe de base exigerait un handler ``op_<operation>`` — or un connecteur de
        simulation n'en a pas, puisqu'il ne fait rien. Surcharger entièrement ``call`` évite
        qu'une simulation échoue avec « opération non supportée » dès que le dry-run est
        désactivé, ce qui serait un contresens complet.
        """
        params = dict(params or {})
        started = time.perf_counter()
        self.calls += 1

        if operation not in self.capabilities:
            self.failures += 1
            return ConnectorResult(
                ok=False,
                operation=operation,
                connector=self.driver,
                error=f"opération '{operation}' non supportée par le connecteur de simulation",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        if not self.dry_run:
            log.info(
                "connecteur de simulation sollicité hors dry-run : aucun effet réel appliqué",
                extra={"operation": operation},
            )

        return ConnectorResult(
            ok=True,
            operation=operation,
            connector=self.driver,
            detail=(
                f"[simulation] aucune action réelle : le connecteur 'simulation' est actif "
                f"(opération '{operation}'). Configurez config/connectors.yaml pour agir "
                "réellement."
            ),
            simulated=True,
            data={"params_echo": redact_params(params), "would_have_called": operation},
            duration_ms=(time.perf_counter() - started) * 1000,
            rollback_token=f"simulation:{operation}",
        )


__all__ = ["SimulationConnector"]
