"""Fonctions utilitaires du cœur (stdlib uniquement : pas de dépendance externe)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import unicodedata
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

# --------------------------------------------------------------------------------------
# Temps
# --------------------------------------------------------------------------------------


def utcnow() -> datetime:
    """Horodatage UTC *aware* (jamais ``datetime.utcnow()``, déprécié)."""
    return datetime.now(UTC)


def iso_z(value: datetime) -> str:
    """Sérialise en ISO-8601 UTC avec suffixe ``Z`` (format du contrat d'interface)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso() -> str:
    return iso_z(utcnow())


def parse_dt(value: str | datetime | None) -> datetime | None:
    """Analyse une date ISO-8601 tolérante (accepte ``Z`` et les offsets)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def seconds_until(moment: datetime | str | None) -> float | None:
    parsed = parse_dt(moment) if isinstance(moment, str) else moment
    if parsed is None:
        return None
    return (parsed - utcnow()).total_seconds()


def humanize_duration(seconds: float | int | None) -> str:
    """``3725`` → ``1h 2m`` (utile pour les rapports et la console)."""
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    if seconds < 0:
        return "expiré"
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s" if sec else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}j {hours}h" if hours else f"{days}j"


def expiry_from_now(seconds: int) -> str:
    return iso_z(utcnow() + timedelta(seconds=seconds))


# --------------------------------------------------------------------------------------
# Identifiants, hachage, sérialisation canonique
# --------------------------------------------------------------------------------------


def new_id(prefix: str = "") -> str:
    """Identifiant unique trié par le temps, préfixé lisiblement."""
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


def short_id(value: str, length: int = 12) -> str:
    return (value or "")[:length]


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    """JSON canonique : clés triées, séparateurs compacts, non-ASCII échappé.

    C'est la base de la chaîne d'audit : deux représentations logiquement identiques
    doivent produire exactement la même empreinte.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_json_default
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso_z(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return str(value)


def stable_hash(value: Any) -> str:
    """Empreinte courte et déterministe d'une structure (déduplication, clés d'idempotence)."""
    return sha256_hex(canonical_json(value))[:32]


def constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left, right)


def token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# --------------------------------------------------------------------------------------
# Accès aux structures imbriquées (chemins pointés des règles de détection)
# --------------------------------------------------------------------------------------


def deep_get(source: Any, path: str, default: Any = None) -> Any:
    """Résout ``labels.src_ip`` / ``payload.items.0.id`` sur dicts et listes.

    Retourne ``default`` dès qu'un segment manque : les règles ne doivent jamais lever
    d'exception si un événement est incomplet.
    """
    if not path:
        return source
    current = source
    for segment in path.split("."):
        if current is None:
            return default
        if isinstance(current, Mapping):
            if segment not in current:
                return default
            current = current[segment]
        elif isinstance(current, (list, tuple)):
            if not segment.isdigit():
                return default
            index = int(segment)
            if index >= len(current):
                return default
            current = current[index]
        elif hasattr(current, segment):
            current = getattr(current, segment)
        else:
            return default
    return current


def deep_set(target: dict[str, Any], path: str, value: Any) -> None:
    segments = path.split(".")
    cursor = target
    for segment in segments[:-1]:
        nxt = cursor.get(segment)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[segment] = nxt
        cursor = nxt
    cursor[segments[-1]] = value


def flatten(source: Mapping[str, Any], prefix: str = "", *, max_depth: int = 4) -> dict[str, Any]:
    """Aplatit un mapping en chemins pointés (utile pour les exports SIEM)."""
    out: dict[str, Any] = {}
    if max_depth < 0:
        return out
    for key, value in source.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping) and max_depth:
            out.update(flatten(value, path, max_depth=max_depth - 1))
        else:
            out[path] = value
    return out


# --------------------------------------------------------------------------------------
# Réseau : le jugement « cette cible est-elle à moi ? » est un garde-fou de sûreté
# --------------------------------------------------------------------------------------


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return True


def ip_in_cidrs(ip: str, cidrs: Iterable[str]) -> bool:
    """Vrai si l'IP appartient à l'une des plages. Entrée invalide ⇒ ``False`` (jamais d'exception)."""
    try:
        address = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False
    for cidr in cidrs:
        try:
            if address in ipaddress.ip_network(str(cidr).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def normalize_host(value: str) -> str:
    """Normalise un hôte/cible : minuscules, sans schéma ni chemin ni port implicite."""
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0]
    text = text.split("@")[-1]
    if text.startswith("["):  # IPv6 littéral
        return text.split("]")[0].lstrip("[")
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text


def titleize(value: str) -> str:
    return " ".join(word.capitalize() for word in re.split(r"[_\-\s]+", value or "") if word)


# --------------------------------------------------------------------------------------
# Texte : assainissement défensif (les preuves contiennent des charges d'attaque)
# --------------------------------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Ordre **important** : les motifs les plus spécifiques d'abord. Un motif générique placé
#: avant ``Bearer`` masquerait le mot « Bearer » en laissant le jeton en clair juste après.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Clés privées PEM (multi-lignes).
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "<private-key-redacted>",
    ),
    # JWT (avant les motifs génériques de type "token=").
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"),
        "<jwt-redacted>",
    ),
    # Jetons préfixés connus (OpenAI, GitHub, GitLab, Slack, et les clés API de Thot Secure
    # au format `thot_<identifiant>_<secret>`).
    (
        re.compile(
            r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|glpat|xox[baprs]|thot)[-_][A-Za-z0-9_\-]{12,}\b"
        ),
        "<token-redacted>",
    ),
    # En-têtes sensibles : on consomme toute la fin de ligne, car un jeton suit presque toujours.
    (
        re.compile(r"(?i)\b(proxy-authorization|authorization)\b\s*[:=][^\r\n]*"),
        r"\1: <redacted>",
    ),
    (re.compile(r"(?i)\b(set-cookie|cookie)\b\s*[:=][^\r\n]*"), r"\1: <redacted>"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}"), "Bearer <redacted>"),
    (re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}"), "Basic <redacted>"),
    # Affectations de secrets (password=…, api_key: …, token=…) jusqu'au séparateur suivant.
    # « token » et « pass » sont inclus **en tant que mots entiers** : `\b` ne reconnaît pas de
    # frontière à l'intérieur de `access_token`, donc les variantes composées restent couvertes
    # par leurs propres alternatives, listées avant.
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|pass|secret|client[_-]?secret|api[_-]?key|apikey"
            r"|access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|token|jwt"
            r"|private[_-]?key|passphrase|credential[s]?|session[_-]?id)\b\s*[:=]\s*[^\s,;&\"'|]+"
        ),
        r"\1=<redacted>",
    ),
    # Paramètres d'URL porteurs de secrets.
    (
        re.compile(r"(?i)([?&](?:token|key|api_key|apikey|access_token|signature|sig)=)[^&\s\"']+"),
        r"\1<redacted>",
    ),
)


def redact_secrets(text: str, *, max_length: int = 4096) -> str:
    """Masque les secrets évidents. À appliquer **avant** toute persistance ou affichage."""
    if not text:
        return ""
    cleaned = _CONTROL_CHARS.sub("", str(text))
    for pattern, replacement in _SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + f"…<tronqué {len(cleaned) - max_length} car.>"
    return cleaned


def strip_html(text: str) -> str:
    """Neutralise le HTML : les preuves de finding sont une surface XSS réelle."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def slugify(value: str, *, max_length: int = 60) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_only).strip("-")
    return slug[:max_length] or "item"


# --------------------------------------------------------------------------------------
# Nombres
# --------------------------------------------------------------------------------------


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(result) or math.isinf(result):
        return default
    return result


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def truncate(value: str, length: int = 200) -> str:
    text = str(value or "")
    return text if len(text) <= length else text[: length - 1] + "…"


def chunked(items: Sequence[Any], size: int) -> list[list[Any]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


def dedupe(items: Iterable[Any]) -> list[Any]:
    """Déduplique en préservant l'ordre (les valeurs non hachables sont sérialisées)."""
    seen: set[str] = set()
    out: list[Any] = []
    for item in items:
        key = (
            item if isinstance(item, (str, int, float, bool, type(None))) else canonical_json(item)
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


__all__ = [
    "canonical_json",
    "chunked",
    "clamp",
    "constant_time_equals",
    "dedupe",
    "deep_get",
    "deep_set",
    "expiry_from_now",
    "flatten",
    "humanize_duration",
    "ip_in_cidrs",
    "is_private_ip",
    "is_valid_cidr",
    "is_valid_ip",
    "iso_z",
    "new_id",
    "normalize_host",
    "now_iso",
    "parse_dt",
    "redact_secrets",
    "safe_float",
    "safe_int",
    "seconds_until",
    "sha256_hex",
    "short_id",
    "slugify",
    "stable_hash",
    "strip_html",
    "titleize",
    "token",
    "truncate",
    "utcnow",
]
