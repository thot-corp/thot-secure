"""Couche API : application FastAPI, dépendances, schémas, flux temps réel.

Ce module n'importe **pas** les routeurs : un import de ``thotsecure.api`` ne doit pas tirer
tout le graphe applicatif. C'est ce qui évite le cycle ``service → api → routeurs → service``
(voir ``thotsecure.observability``).
"""

from __future__ import annotations

__all__ = ["errors", "schemas", "ws"]
