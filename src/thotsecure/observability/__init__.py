"""Observabilité : métriques Prometheus et limitation de débit.

Ce sous-paquet est volontairement **hors de ``thotsecure.api``** : le service applicatif
(``thotsecure.service``) en a besoin, alors que le paquet API importe le service. Les placer
dans l'API créerait un cycle d'import (service → api → routeurs → service), et un cycle
d'import dans un produit de sécurité se paie en dépendances implicites impossibles à
raisonner en incident.
"""

from __future__ import annotations

from .metrics import METRICS_CATALOG, MetricsRegistry, register_catalog
from .ratelimit import RateLimiter

__all__ = ["METRICS_CATALOG", "MetricsRegistry", "RateLimiter", "register_catalog"]
