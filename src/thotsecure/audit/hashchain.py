"""Chaîne de hachage du journal d'audit (fonctions pures, sans dépendance).

Le journal d'audit d'Thot Secure est *append-only* et chaîné : chaque enregistrement contient
l'empreinte du précédent. Modifier ou supprimer une ligne passée invalide toutes les
suivantes, ce que ``GET /api/v1/audit/verify`` détecte immédiatement.

Pourquoi pas une blockchain : voir ``docs/adr/0004-audit-log-chaine-par-hash-plutot-que-blockchain.md``.
En résumé : nous avons besoin d'**intégrité détectable**, pas de consensus distribué. Un
attaquant disposant d'un accès root peut réécrire la chaîne entière et la recalculer ; les
contre-mesures sont donc organisationnelles et architecturales (export SIEM continu,
ancrage horodaté, sauvegardes hors ligne), pas cryptographiques.
"""

from __future__ import annotations

from typing import Any

from ..core.util import canonical_json, sha256_hex

#: Empreinte du premier enregistrement de la chaîne.
GENESIS_HASH = "sha256:genesis"

_HASH_PREFIX = "sha256:"


def record_fingerprint(
    *,
    seq: int,
    ts: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    action: str,
    target: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    prev_hash: str,
) -> str:
    """Calcule l'empreinte d'un enregistrement, exactement comme spécifié au contrat §3.5.

    La sérialisation est **canonique** (clés triées, séparateurs compacts) : deux
    représentations logiquement identiques doivent produire la même empreinte, sinon la
    vérification produirait des faux positifs.
    """
    payload = "|".join(
        (
            str(seq),
            ts,
            tenant_id,
            actor,
            actor_role,
            action,
            canonical_json(target),
            canonical_json(before),
            canonical_json(after),
            prev_hash,
        )
    )
    return _HASH_PREFIX + sha256_hex(payload)


def next_prev_hash(last_hash: str | None) -> str:
    """Empreinte à inscrire dans ``prev_hash`` pour l'enregistrement suivant."""
    return last_hash or GENESIS_HASH


def is_valid_hash_format(value: str | None) -> bool:
    if not value or not value.startswith(_HASH_PREFIX):
        return False
    digest = value[len(_HASH_PREFIX) :]
    if value == GENESIS_HASH:
        return True
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def verify_record(
    record: dict[str, Any],
    *,
    expected_prev_hash: str,
) -> tuple[bool, str | None]:
    """Vérifie un enregistrement isolé.

    Retourne ``(valide, raison)``. La raison est destinée à l'analyste : « prev_hash ne
    correspond pas » et « empreinte recalculée différente » n'ont pas la même signification
    (suppression vs modification).
    """
    if record.get("prev_hash") != expected_prev_hash:
        return False, (
            f"chaîne rompue : prev_hash={record.get('prev_hash')!r} "
            f"alors que l'enregistrement précédent se termine par {expected_prev_hash!r}"
        )
    recomputed = record_fingerprint(
        seq=int(record["seq"]),
        ts=str(record["ts"]),
        tenant_id=str(record["tenant_id"]),
        actor=str(record["actor"]),
        actor_role=str(record.get("actor_role", "system")),
        action=str(record["action"]),
        target=dict(record.get("target") or {}),
        before=dict(record.get("before") or {}),
        after=dict(record.get("after") or {}),
        prev_hash=expected_prev_hash,
    )
    if recomputed != record.get("hash"):
        return False, (
            f"contenu modifié : empreinte recalculée {recomputed} "
            f"≠ empreinte stockée {record.get('hash')}"
        )
    return True, None


def to_cef(
    record: dict[str, Any], *, vendor: str = "Thot Secure", product: str = "Thot Secure"
) -> str:
    """Sérialise un enregistrement d'audit au format ArcSight CEF (export SIEM).

    CEF: ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension``
    """
    severity_map = {"debug": 1, "info": 3, "low": 4, "medium": 6, "high": 8, "critical": 10}
    level = severity_map.get(str(record.get("context", {}).get("severity", "info")), 3)
    extension = " ".join(
        (
            f"rt={_cef_escape(str(record.get('ts', '')))}",
            f"suser={_cef_escape(str(record.get('actor', '')))}",
            f"sproc={_cef_escape(str(record.get('actor_role', '')))}",
            f"cs1Label=tenant cs1={_cef_escape(str(record.get('tenant_id', '')))}",
            f"cs2Label=audit_seq cs2={record.get('seq', '')}",
            f"cs3Label=target cs3={_cef_escape(canonical_json(record.get('target') or {}))}",
            f"cs4Label=before cs4={_cef_escape(canonical_json(record.get('before') or {}))}",
            f"cs5Label=after cs5={_cef_escape(canonical_json(record.get('after') or {}))}",
            f"cs6Label=hash cs6={_cef_escape(str(record.get('hash', '')))}",
        )
    )
    return (
        f"CEF:0|{vendor}|{product}|0.1.0|{_cef_escape(str(record.get('action', 'audit')))}"
        f"|{_cef_escape(str(record.get('action', 'audit')))}|{level}|{extension}"
    )


def _cef_escape(value: str) -> str:
    """Échappe les caractères réservés de CEF (``\\``, ``|``, ``=``, retours ligne)."""
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


__all__ = [
    "GENESIS_HASH",
    "is_valid_hash_format",
    "next_prev_hash",
    "record_fingerprint",
    "to_cef",
    "verify_record",
]
