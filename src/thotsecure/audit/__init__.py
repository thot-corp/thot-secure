"""Journal d'audit : chaîne de hachage, vérification, export.

Ce sous-paquet est volontairement minimaliste à l'import : ``hashchain`` est un module pur
(sans dépendance), ``chain`` fournit le service transactionnel adossé au stockage.
"""

from __future__ import annotations

from .hashchain import (
    GENESIS_HASH,
    is_valid_hash_format,
    next_prev_hash,
    record_fingerprint,
    to_cef,
    verify_record,
)

__all__ = [
    "GENESIS_HASH",
    "is_valid_hash_format",
    "next_prev_hash",
    "record_fingerprint",
    "to_cef",
    "verify_record",
]
