"""Helpers d'intégration du SDK Thot Secure.

Ces fonctions évitent de réécrire la glue à chaque intégration :

* :func:`normalize_event` / :func:`parse_http_log_line` — transformer une ligne de log
  Nginx/Apache (ou un dict applicatif) en ``Event`` conforme au contrat §3.1 ;
* :func:`from_syslog_line` — même chose pour du syslog RFC 3164 / RFC 5424 ;
* :func:`redact_secrets` — masquage des en-têtes et champs sensibles **avant** toute
  journalisation ou ingestion (``authorization``, ``cookie``, ``set-cookie``, ``password``,
  ``token``, ``api_key``, JWT…) ;
* :func:`pseudonymize_ip` / :func:`pseudonymize_ip_fields` — pseudonymisation HMAC déterministe
  des adresses IP (**obligation RGPD** : une IP est une donnée à caractère personnel) ;
* :func:`iter_jsonl` / :func:`chunked` — lecture de fichiers JSONL et découpage en lots ≤ 500.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Event

__all__ = [
    "MAX_BATCH_SIZE",
    "MAX_PAYLOAD_BYTES",
    "REDACTED",
    "chunked",
    "env",
    "from_syslog_line",
    "iter_jsonl",
    "new_event_id",
    "normalize_event",
    "now_iso",
    "parse_http_log_line",
    "parse_timestamp",
    "pseudonymize_ip",
    "pseudonymize_ip_fields",
    "redact_secrets",
    "truncate_payload",
]

#: Contrainte du contrat §3.1 : un ``payload`` sérialisé ne dépasse pas 32 Kio.
MAX_PAYLOAD_BYTES = 32 * 1024

#: Contrainte du contrat §4.3 : au plus 500 événements par lot d'ingestion.
MAX_BATCH_SIZE = 500

REDACTED = "[REDACTED]"
REDACTED_JWT = "[REDACTED_JWT]"

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

#: Log « combined » Nginx/Apache : hôte virtuel optionnel, puis la ligne standard.
_COMBINED_RE = re.compile(
    r"^(?:(?P<vhost>[A-Za-z0-9_.\-]+(?::\d+)?)\s+)?"
    r"(?P<src_ip>[0-9A-Fa-f:.]+)\s+"
    r"(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r"(?:\s+(?P<extra>\S+))?\s*$"
)

_REQUEST_RE = re.compile(r"^(?P<method>[A-Za-z]+)\s+(?P<target>\S+)(?:\s+(?P<protocol>HTTP/[\d.]+))?$")

_SYSLOG_RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

_SYSLOG_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[[^\]]*\])\s*(?P<message>.*)$"
)

#: Sévérité syslog (0 = emergency … 7 = debug) → ``severity_hint`` du contrat.
_SYSLOG_SEVERITY_HINT = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "info",
}

_SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------

_SENSITIVE_EXACT = frozenset(
    {
        "authorization",
        "auth",
        "authentication",
        "proxy_authorization",
        "cookie",
        "cookies",
        "set_cookie",
        "setcookie",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "token",
        "jwt",
        "bearer",
        "secret",
        "secrets",
        "client_secret",
        "api_key",
        "apikey",
        "x_api_key",
        "access_key",
        "secret_key",
        "private_key",
        "credentials",
        "credential",
        "session",
        "session_id",
        "sessionid",
        "csrf",
        "csrf_token",
        "xsrf",
        "signature",
        "nonce",
        "refresh_token",
        "access_token",
        "id_token",
        "aws_secret_access_key",
    }
)

_SENSITIVE_PARTS = frozenset(
    {
        "authorization",
        "cookie",
        "cookies",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "token",
        "tokens",
        "jwt",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "session",
        "sessionid",
        "csrf",
        "xsrf",
        "nonce",
        "signature",
        "privatekey",
    }
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b")
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic|token|apikey|api[_-]?key)\s+([A-Za-z0-9._\-+/=]{6,})")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|token|access_token|password|passwd|secret|signature)=([^&\s\"';]+)"
)


def _normalize_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def is_sensitive_key(key: Any) -> bool:
    """``True`` si le nom de champ désigne une donnée à masquer.

    En cas de doute on masque (fail-closed) : un faux positif produit un log inexploitable,
    un faux négatif produit une fuite de secret.
    """
    normalized = _normalize_key(key)
    if not normalized:
        return False
    if normalized in _SENSITIVE_EXACT:
        return True
    parts = [part for part in normalized.split("_") if part]
    if any(part in _SENSITIVE_PARTS for part in parts):
        return True
    return bool("api" in parts and "key" in parts)


def _scrub_string(value: str) -> str:
    """Masque les secrets *contenus* dans une chaîne (JWT, ``Bearer …``, ``token=…``)."""
    scrubbed = _JWT_RE.sub(REDACTED_JWT, value)
    scrubbed = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", scrubbed)
    scrubbed = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", scrubbed)
    return scrubbed


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token", "apikey"):
            return f"{parts[0]} {REDACTED}"
        return REDACTED
    return REDACTED


def redact_secrets(data: Any, *, depth: int = 0, _seen: set | None = None) -> Any:
    """Retourne une copie de *data* où les champs sensibles sont masqués.

    Le traitement est récursif (dict, listes, tuples) et couvre :

    * les clés sensibles : ``authorization``, ``cookie``, ``set-cookie``, ``password``,
      ``token``, ``api_key``, ``secret``, ``session``, ``signature``… (insensible à la casse,
      ``-`` et ``_`` équivalents) ;
    * les JWT (``eyJ…``) et les schémas d'authentification (``Bearer …``) présents **dans les
      valeurs**, même sous une clé anodine comme ``raw`` ou ``query`` ;
    * les paires ``token=…``/``password=…`` d'une query string.

    Aucun secret en clair ne doit être journalisé : appelez ce helper avant tout log ou tout
    envoi d'événement contenant des en-têtes HTTP bruts.
    """
    if _seen is None:
        _seen = set()
    if depth > 32:
        return REDACTED
    if isinstance(data, Mapping):
        if id(data) in _seen:
            return REDACTED
        _seen.add(id(data))
        out: dict[Any, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(key):
                out[key] = _mask_value(value)
            else:
                out[key] = redact_secrets(value, depth=depth + 1, _seen=_seen)
        return out
    if isinstance(data, (list, tuple, set)):
        if id(data) in _seen:
            return REDACTED
        _seen.add(id(data))
        converted = [redact_secrets(item, depth=depth + 1, _seen=_seen) for item in data]
        # Les tuples/ensembles deviennent des listes : le résultat reste sérialisable en JSON.
        return converted
    if isinstance(data, str):
        return _scrub_string(data)
    return data


# --------------------------------------------------------------------------------------
# Pseudonymisation RGPD des adresses IP
# --------------------------------------------------------------------------------------

#: Champs traités par défaut par :func:`pseudonymize_ip_fields`.
DEFAULT_IP_FIELDS = (
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "client_ip",
    "remote_addr",
    "remote_ip",
    "real_ip",
    "forwarded_for",
    "x_forwarded_for",
    "host_ip",
    "server_ip",
    "peer_ip",
    "ip",
    "ip_address",
)


def pseudonymize_ip(ip: str, salt: str, *, keep_prefix: bool = False, prefix: str = "ip-") -> str:
    """Pseudonymise une adresse IP de façon **déterministe** (HMAC-SHA256 + sel).

    Pourquoi : une adresse IP est une donnée à caractère personnel (RGPD, art. 4.1). Le
    pseudonyme permet de corréler des événements d'une même source sans jamais stocker l'IP
    en clair. Le sel est un secret d'organisation : sans lui, un attaquant disposant du
    pseudonyme peut tester des IP candidates (attaque par dictionnaire sur un espace IPv4).

    Paramètres
    ----------
    ip : adresse IPv4/IPv6, éventuellement en notation CIDR.
    salt : sel secret non vide (jamais committé ; lisez-le depuis l'environnement).
    keep_prefix : conserve le réseau (``/24`` en IPv4, ``/64`` en IPv6) à côté du pseudonyme,
        ce qui permet des analyses par sous-réseau — à n'activer que si c'est nécessaire.
    prefix : préfixe lisible des pseudonymes (``ip-`` par défaut).

    Retour : ``ip-<32 hex>`` ou ``ip-<32 hex>@<réseau>`` si ``keep_prefix``.

    Lève ``ValueError`` si l'entrée n'est pas une IP/CIDR valide ou si le sel est vide.
    """
    if not salt or not isinstance(salt, str):
        raise ValueError(
            "pseudonymize_ip exige un sel non vide (secret d'organisation) : sans sel, la "
            "pseudonymisation est réversible par force brute"
        )
    if ip is None or not str(ip).strip():
        raise ValueError("pseudonymize_ip : adresse IP vide")

    raw = str(ip).strip()
    network_text = ""
    packed_str = raw
    try:
        if "/" in raw:
            network = ipaddress.ip_network(raw, strict=False)
            network_text = str(network)
            packed_str = str(network.network_address)
        else:
            addr = ipaddress.ip_address(raw)
            packed_str = str(addr)
            if keep_prefix:
                bits = 24 if addr.version == 4 else 64
                network_text = str(ipaddress.ip_network("%s/%d" % (addr, bits), strict=False))
    except ValueError as exc:
        raise ValueError(f"pseudonymize_ip : {raw!r} n'est pas une IP ni un CIDR valide") from exc

    digest = hmac.new(salt.encode("utf-8"), packed_str.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{prefix}{digest[:32]}"
    if keep_prefix and network_text:
        return f"{token}@{network_text}"
    return token


def pseudonymize_ip_fields(
    data: Any,
    salt: str,
    *,
    fields: Sequence[str] = DEFAULT_IP_FIELDS,
    keep_prefix: bool = False,
    depth: int = 0,
) -> Any:
    """Pseudonymise récursivement les champs d'adresse IP d'une structure.

    Les valeurs qui ne sont pas des IP valides sont laissées intactes (ex. ``"unknown"``,
    ``"-"``) : le helper ne doit jamais faire échouer une ingestion.
    """
    if depth > 32 or not salt:
        return data
    wanted = {_normalize_key(f) for f in fields}
    if isinstance(data, Mapping):
        out: dict[Any, Any] = {}
        for key, value in data.items():
            if _normalize_key(key) in wanted and isinstance(value, str) and value.strip() not in ("", "-"):
                try:
                    out[key] = pseudonymize_ip(value, salt, keep_prefix=keep_prefix)
                    continue
                except ValueError:
                    out[key] = value
                    continue
            out[key] = pseudonymize_ip_fields(
                value, salt, fields=fields, keep_prefix=keep_prefix, depth=depth + 1
            )
        return out
    if isinstance(data, list):
        return [
            pseudonymize_ip_fields(item, salt, fields=fields, keep_prefix=keep_prefix, depth=depth + 1)
            for item in data
        ]
    return data


# --------------------------------------------------------------------------------------
# Temps
# --------------------------------------------------------------------------------------


def now_iso() -> str:
    """Horodatage ISO 8601 UTC en millisecondes, au format du contrat (``…Z``)."""
    return _to_iso_utc(datetime.now(UTC))


def _to_iso_utc(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_clf_timestamp(value: str) -> datetime | None:
    """Analyse ``14/Feb/2026:10:00:00 +0100`` sans dépendre de la locale (Windows FR incluse)."""
    match = re.match(
        r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$", value.strip()
    )
    if not match:
        return None
    day, month_name, year, hour, minute, second, offset = match.groups()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    tzinfo = UTC
    if offset:
        sign = 1 if offset[0] == "+" else -1
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        tzinfo = timezone(sign * delta)
    try:
        return datetime(int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=tzinfo)
    except ValueError:
        return None


def _parse_iso_timestamp(value: str) -> datetime | None:
    """Analyse un horodatage ISO 8601 (suffixe ``Z`` accepté). Aucune récursion."""
    text = value.strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_syslog_timestamp(value: str, *, year: int | None = None) -> datetime | None:
    """Analyse ``Feb 14 10:00:00`` (RFC 3164, sans année) ou un horodatage ISO."""
    value = value.strip()
    iso = _parse_iso_timestamp(value)
    if iso is not None:
        return iso
    match = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", value)
    if not match:
        return None
    month_name, day, hour, minute, second = match.groups()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    reference = datetime.now(UTC)
    candidate = datetime(
        year or reference.year, month, int(day), int(hour), int(minute), int(second), tzinfo=UTC
    )
    # Un message de décembre lu en janvier appartient à l'année précédente.
    if candidate > reference + timedelta(days=2):
        candidate = candidate.replace(year=candidate.year - 1)
    return candidate


def parse_timestamp(value: Any) -> datetime | None:
    """Analyse un horodatage hétérogène (ISO 8601, epoch, CLF, syslog) → ``datetime`` UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e11:  # millisecondes
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,13}", text):
        return parse_timestamp(float(text))
    iso = _parse_iso_timestamp(text)
    if iso is not None:
        return iso
    clf = _parse_clf_timestamp(text)
    if clf is not None:
        return clf
    return _parse_syslog_timestamp(text)


# --------------------------------------------------------------------------------------
# Troncature du payload (contrat §3.1 : ≤ 32 Kio)
# --------------------------------------------------------------------------------------


def _serialized_size(payload: Any) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))


def truncate_payload(
    payload: Mapping[str, Any],
    *,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    keep_keys: Sequence[str] = ("status", "method", "path"),
) -> tuple[dict[str, Any], bool]:
    """Ramène *payload* sous *max_bytes* et indique si une troncature a eu lieu.

    Stratégie : troncature des chaînes les plus longues d'abord, puis retrait des clés les plus
    volumineuses (en préservant ``keep_keys``), puis remplacement par un marqueur si nécessaire.
    """
    result: dict[str, Any] = dict(payload)
    if _serialized_size(result) <= max_bytes:
        return result, False

    truncated = True
    # 1) troncature des longues chaînes
    for _ in range(64):
        if _serialized_size(result) <= max_bytes:
            break
        candidates = [(len(str(v)), k) for k, v in result.items() if isinstance(v, str) and len(v) > 256]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result[key] = str(result[key])[:256] + "…[tronqué]"

    # 2) retrait des clés les plus volumineuses
    for _ in range(64):
        if _serialized_size(result) <= max_bytes:
            break
        candidates = [(_serialized_size({k: v}), k) for k, v in result.items() if k not in keep_keys]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result.pop(key, None)

    # 3) dernier recours
    if _serialized_size(result) > max_bytes:
        result = {"_truncated": True, "_original_keys": sorted(str(k) for k in payload)}
    return result, truncated


# --------------------------------------------------------------------------------------
# Normalisation des journaux HTTP
# --------------------------------------------------------------------------------------


def parse_http_log_line(line: str) -> dict[str, Any] | None:
    """Analyse une ligne de log Nginx/Apache (formats ``combined`` et ``common``).

    Retourne un dictionnaire de champs bruts ou ``None`` si la ligne n'est pas reconnue.
    Le champ ``vhost`` (préfixe ``%v:%p``) est optionnel.
    """
    match = _COMBINED_RE.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    request = groups.get("request") or ""
    parsed_request = _REQUEST_RE.match(request) if request and request != "-" else None

    target = parsed_request.group("target") if parsed_request else None
    path = target
    query = None
    if target and "?" in target:
        path, query = target.split("?", 1)

    bytes_sent: int | None = None
    if groups.get("bytes") and groups["bytes"] != "-":
        try:
            bytes_sent = int(groups["bytes"])
        except ValueError:
            bytes_sent = None

    return {
        "src_ip": groups.get("src_ip"),
        "vhost": groups.get("vhost"),
        "ident": groups.get("ident"),
        "user": None if groups.get("user") in ("-", None) else groups.get("user"),
        "ts": groups.get("ts"),
        "method": parsed_request.group("method") if parsed_request else None,
        "path": path,
        "query": query,
        "protocol": parsed_request.group("protocol") if parsed_request else None,
        "status": int(groups["status"]) if groups.get("status") else None,
        "bytes": bytes_sent,
        "referer": None if groups.get("referer") in ("-", None) else groups.get("referer"),
        "user_agent": None if groups.get("user_agent") in ("-", None) else groups.get("user_agent"),
    }


#: Alias courants rencontrés dans les logs structurés (JSON) → champs canoniques.
_FIELD_ALIASES = {
    "src_ip": ("src_ip", "source_ip", "client_ip", "remote_addr", "remote_ip", "real_ip", "ip"),
    "host": ("host", "server_name", "vhost", "http_host", "hostname"),
    "ts": ("ts", "time", "timestamp", "@timestamp", "time_local", "datetime"),
    "method": ("method", "http_method", "request_method", "verb"),
    "path": ("path", "uri", "request_uri", "url_path", "endpoint"),
    "query": ("query", "query_string", "args", "search"),
    "protocol": ("protocol", "server_protocol", "http_version"),
    "status": ("status", "status_code", "response_status", "code"),
    "bytes": ("bytes", "body_bytes_sent", "bytes_sent", "size", "response_size"),
    "referer": ("referer", "referrer", "http_referer"),
    "user_agent": ("user_agent", "http_user_agent", "agent", "ua"),
    "message": ("message", "msg", "log", "event"),
    "user": ("user", "remote_user", "username", "auth_user"),
    "duration_ms": ("duration_ms", "request_time", "response_time", "elapsed_ms"),
}


def _pick(data: Mapping[str, Any], field: str) -> Any:
    for alias in _FIELD_ALIASES.get(field, (field,)):
        if alias in data and data[alias] not in (None, ""):
            return data[alias]
    return None


def _severity_hint_for_status(status: int | None) -> str | None:
    if status is None:
        return None
    if 500 <= status < 600:
        return "medium"
    if 400 <= status < 500:
        return "low"
    if 200 <= status < 400:
        return "info"
    return None


def _as_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def normalize_event(
    source: Any,
    *,
    tenant_id: str,
    source_name: str | None = None,
    source_type: str = "log_tail",
    source_host: str | None = None,
    kind: str | None = None,
    event_id: str | None = None,
    ts: Any | None = None,
    severity_hint: str | None = None,
    extra_labels: Mapping[str, Any] | None = None,
    extra_payload: Mapping[str, Any] | None = None,
    ip_salt: str | None = None,
    ip_fields: Sequence[str] = DEFAULT_IP_FIELDS,
    redact: bool = True,
    raw_ref: str | None = None,
    max_payload_bytes: int = MAX_PAYLOAD_BYTES,
) -> Event:
    """Construit un ``Event`` conforme au contrat §3.1 depuis un log HTTP brut.

    * ``source`` : ligne Nginx/Apache (``str``), ligne JSON structurée (``str``) ou mapping.
    * ``ip_salt`` : si fourni, **toutes les IP sont pseudonymisées** (obligation RGPD) dans les
      labels et le payload ; sinon elles sont conservées telles quelles.
    * ``redact=True`` (défaut) : les secrets présents dans la ligne (JWT, ``Bearer …``, ``token=``)
      sont masqués avant construction de l'événement.

    Le résultat respecte : ``kind`` énuméré, ``labels`` plat à valeurs scalaires, ``payload``
    ≤ 32 Kio (au-delà : troncature + ``raw_ref``).
    """
    if not tenant_id:
        raise ValueError("normalize_event exige un tenant_id (le contrat l'impose sur tout objet)")

    payload_extra: dict[str, Any] = {}
    record: dict[str, Any] = {}

    if isinstance(source, Mapping):
        record = dict(source)
    elif isinstance(source, str):
        text = source.strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, Mapping):
                record = dict(parsed)
        if not record:
            http_record = parse_http_log_line(text)
            if http_record is not None:
                record = http_record
            else:
                payload_extra["message"] = text
                record = {}
    else:
        raise TypeError(f"normalize_event attend une chaîne ou un mapping, reçu {type(source).__name__!r}")

    status = _pick(record, "status")
    try:
        status_int = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_int = None

    method = _pick(record, "method")
    path = _pick(record, "path")
    query = _pick(record, "query")
    protocol = _pick(record, "protocol")
    host = source_host or _pick(record, "host")
    user_agent = _pick(record, "user_agent")
    referer = _pick(record, "referer")
    raw_bytes = _pick(record, "bytes")
    user = _pick(record, "user")
    message = _pick(record, "message")
    duration = _pick(record, "duration_ms")
    request_ts = ts if ts is not None else _pick(record, "ts")

    if method is None and path is None and message is None and not payload_extra:
        # Aucun champ exploitable : on conserve au moins la ligne brute comme message.
        message = (
            json.dumps(source, ensure_ascii=False, default=str) if not isinstance(source, str) else source
        )

    resolved_kind = kind or ("http.request" if (method or path or status_int is not None) else "log.line")
    if resolved_kind not in Event.KINDS:
        raise ValueError("kind invalide : {!r} (attendu : {})".format(resolved_kind, ", ".join(Event.KINDS)))

    labels: dict[str, Any] = {}
    if method:
        labels["method"] = _as_scalar(method)
    if path:
        labels["path"] = _as_scalar(path)
    if protocol:
        labels["protocol"] = _as_scalar(protocol)
    if query:
        labels["query"] = _as_scalar(query)
    if host:
        labels["host"] = _as_scalar(host)
    if user:
        labels["user"] = _as_scalar(user)
    src_ip = _pick(record, "src_ip")
    if src_ip:
        labels["src_ip"] = str(src_ip)
    if extra_labels:
        for key, value in extra_labels.items():
            labels[str(key)] = _as_scalar(value)

    payload: dict[str, Any] = {}
    if status_int is not None:
        payload["status"] = status_int
    if raw_bytes not in (None, ""):
        try:
            payload["bytes"] = int(raw_bytes)
        except (TypeError, ValueError):
            payload["bytes"] = _as_scalar(raw_bytes)
    if user_agent:
        payload["user_agent"] = _as_scalar(user_agent)
    if referer:
        payload["referer"] = _as_scalar(referer)
    if message:
        payload["message"] = _as_scalar(message)
    if duration not in (None, ""):
        payload["duration_ms"] = _as_scalar(duration)
    payload.update(payload_extra)
    if extra_payload:
        payload.update({str(k): v for k, v in extra_payload.items()})

    payload, was_truncated = truncate_payload(payload, max_bytes=max_payload_bytes)
    if was_truncated and not raw_ref:
        raw_ref = "truncated:payload>%d" % max_payload_bytes

    parsed_ts = parse_timestamp(request_ts)
    iso_ts = _to_iso_utc(parsed_ts) if parsed_ts is not None else now_iso()
    if request_ts is not None and parsed_ts is None:
        payload.setdefault("raw_ts", _as_scalar(request_ts))

    event_dict: dict[str, Any] = {
        "event_id": event_id or new_event_id(),
        "schema_version": "1",
        "tenant_id": tenant_id,
        "ts": iso_ts,
        "kind": resolved_kind,
        "source": {
            "type": source_type,
            "name": source_name or "thotsecure-sdk",
            "host": host or source_name or "unknown",
        },
        "severity_hint": severity_hint
        if severity_hint is not None
        else _severity_hint_for_status(status_int),
        "labels": labels,
        "payload": payload,
        "raw_ref": raw_ref,
    }

    if redact:
        event_dict = redact_secrets(event_dict)
    if ip_salt:
        event_dict = pseudonymize_ip_fields(event_dict, ip_salt, fields=ip_fields)

    event = Event.from_dict(event_dict)
    if event.kind not in Event.KINDS:
        raise ValueError(f"kind invalide : {event.kind!r}")
    return event


def from_syslog_line(
    line: str,
    *,
    tenant_id: str,
    source_name: str | None = None,
    source_type: str = "syslog",
    source_host: str | None = None,
    ip_salt: str | None = None,
    redact: bool = True,
    extra_labels: Mapping[str, Any] | None = None,
    extra_payload: Mapping[str, Any] | None = None,
) -> Event:
    """Convertit une ligne syslog (RFC 3164 ou RFC 5424) en ``Event`` (``kind="syslog"``).

    La sévérité syslog (0-7) alimente ``severity_hint`` et la facilité (``local0``, ``auth``…)
    devient un label exploitable par les règles de détection.
    """
    if not line or not line.strip():
        raise ValueError("from_syslog_line : ligne vide")

    text = line.strip()
    pri: int | None = None
    fields: dict[str, Any] = {}
    payload_extra: dict[str, Any] = {}

    match5424 = _SYSLOG_RFC5424_RE.match(text)
    if match5424:
        pri = int(match5424.group("pri"))
        fields = {
            "ts": match5424.group("ts"),
            "host": match5424.group("host"),
            "tag": match5424.group("app"),
            "pid": match5424.group("pid"),
            "message": match5424.group("message"),
        }
        structured_data = match5424.group("sd")
        if structured_data and structured_data != "-":
            payload_extra["structured_data"] = structured_data
    else:
        match3164 = _SYSLOG_RFC3164_RE.match(text)
        if match3164:
            raw_pri = match3164.group("pri")
            pri = int(raw_pri) if raw_pri else None
            fields = {
                "ts": match3164.group("ts"),
                "host": match3164.group("host"),
                "tag": match3164.group("tag"),
                "pid": match3164.group("pid"),
                "message": match3164.group("message"),
            }
        else:
            fields = {"message": text}

    severity_hint: str | None = None
    labels: dict[str, Any] = {}
    if pri is not None:
        facility_code, severity_code = divmod(pri, 8)
        labels["syslog_facility"] = _SYSLOG_FACILITIES.get(facility_code, "facility%d" % facility_code)
        labels["syslog_severity"] = severity_code
        severity_hint = _SYSLOG_SEVERITY_HINT.get(severity_code)
    if fields.get("tag"):
        labels["syslog_tag"] = str(fields["tag"])
    if fields.get("pid") and fields["pid"] not in ("-", None):
        labels["syslog_pid"] = str(fields["pid"])

    record = {
        "ts": fields.get("ts"),
        "host": fields.get("host"),
        "message": fields.get("message"),
        "src_ip": _extract_ip(str(fields.get("message") or "")),
    }
    event = normalize_event(
        record,
        tenant_id=tenant_id,
        source_name=source_name or fields.get("host") or "syslog",
        source_type=source_type,
        source_host=source_host or fields.get("host"),
        kind="syslog",
        severity_hint=severity_hint,
        extra_labels={**labels, **(extra_labels or {})},
        extra_payload={**payload_extra, **(extra_payload or {})},
        ip_salt=ip_salt,
        redact=redact,
    )
    return event


_IPV4_IN_TEXT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_IN_TEXT_RE = re.compile(r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}|::[0-9A-Fa-f:]{1,}")


def _extract_ip(text: str) -> str | None:
    """Extrait la première IP d'un message, en privilégiant IPv4.

    Les candidats IPv6 sont validés par ``ipaddress`` : sans cela, un horodatage comme
    ``10:00:00`` serait pris pour une adresse IPv6.
    """
    if not text:
        return None
    match = _IPV4_IN_TEXT_RE.search(text)
    if match:
        return match.group(0)
    for candidate in _IPV6_IN_TEXT_RE.finditer(text):
        try:
            ipaddress.ip_address(candidate.group(0))
        except ValueError:
            continue
        return candidate.group(0)
    return None


# --------------------------------------------------------------------------------------
# Utilitaires divers
# --------------------------------------------------------------------------------------


def new_event_id() -> str:
    """Identifiant d'événement (UUID v4), comme dans l'exemple du contrat §3.1."""
    return str(uuid.uuid4())


def chunked(iterable: Iterable[Any], size: int = MAX_BATCH_SIZE) -> Iterator[list[Any]]:
    """Découpe un itérable en lots de *size* éléments (≤ 500 par défaut, contrat §4.3)."""
    if size < 1:
        raise ValueError("size doit être ≥ 1")
    batch: list[Any] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def iter_jsonl(
    path: Any,
    *,
    encoding: str = "utf-8",
    skip_invalid: bool = False,
    start_line: int = 1,
) -> Iterator[Any]:
    """Itère sur les objets JSON d'un fichier JSONL (une ligne = un JSON).

    Les lignes vides sont ignorées. Par défaut, une ligne invalide lève ``ValueError`` en
    indiquant le numéro de ligne ; ``skip_invalid=True`` l'ignore (utile pour un flux vivant
    dans lequel la dernière ligne peut être partielle).
    """
    file_path = Path(path)
    with file_path.open("r", encoding=encoding, errors="replace") as handle:
        for number, raw_line in enumerate(handle, start=start_line):
            line = raw_line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError as exc:
                if skip_invalid:
                    continue
                raise ValueError("%s:%d : JSON invalide (%s)" % (file_path, number, exc)) from exc


def env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    """Lecture d'une variable d'environnement, avec erreur explicite si ``required``.

    Ne journalise **jamais** la valeur : ``THOT_API_KEY`` transite par ici.
    """
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(
            f"variable d'environnement {name} manquante (voir docs/architecture/api-contract.md §9)"
        )
    return value
