"""Couche de persistance d'Thot Secure.

``Store`` est l'unique point d'accès aux données. Aucun autre module ne doit ouvrir de
connexion SQLite directement : c'est ce qui garantit le filtrage systématique par
``tenant_id`` et la chaîne d'audit transactionnelle.
"""

from __future__ import annotations

from .schema import POSTGRES_DDL, SCHEMA_VERSION, SQLITE_DDL, ddl_for
from .store import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Store

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "POSTGRES_DDL",
    "SCHEMA_VERSION",
    "SQLITE_DDL",
    "Store",
    "ddl_for",
]
