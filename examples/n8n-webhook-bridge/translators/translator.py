#!/usr/bin/env python3
"""Traducteur de payloads tiers vers l'API Thot Secure (nom de code ``thotsecure``).

Ce script est un **pont webhook autonome** : il lit un payload produit par un outil tiers
(EDR/antivirus, fournisseur d'identité, WAF, CSPM, SIEM, n'importe quel émetteur JSON), le
traduit en ``Event`` conforme au contrat d'interface v0.1.0
(``docs/architecture/api-contract.md`` §3.1), le nettoie (masquage des secrets +
pseudonymisation des adresses IP) puis le poste sur ``POST /api/v1/events`` (§4.3).

Principes de conception
-----------------------

* **Zéro dépendance** : uniquement la bibliothèque standard Python (``urllib.request``,
  ``hmac``, ``json``…). Aucune installation, aucun accès réseau hors du POST final. C'est ce qui
  permet de l'appeler depuis une étape « Execute Command » de n8n ou depuis un conteneur minimal.
* **Aligné sur le SDK Python officiel** (``sdks/python/thotsecure_sdk``) : la redaction des secrets
  reproduit ``helpers.redact_secrets`` et la pseudonymisation des IP reproduit **exactement**
  ``helpers.pseudonymize_ip`` (même HMAC-SHA256, même sel, même format ``ip-<32 hex>``). Deux
  chemins d'ingestion produisent donc les **mêmes pseudonymes** pour une même IP et un même sel :
  les corrélations restent possibles entre une collecte via le SDK et une collecte via webhook.
* **Défensif** : ce script ne fait que *recevoir* et *normaliser*. Il n'exécute aucune action
  offensive (pas de scan, pas de test d'authentification, pas d'exploitation) et n'émet aucune
  requête vers la source : la seule sortie réseau est l'ingestion vers Thot Secure.
* **Sûr par défaut** : ``--dry-run`` n'envoie rien, et la clé API n'est jamais affichée.

Exemples
--------

::

    # 1. Traduire un payload EDR et vérifier le résultat sans rien envoyer
    python translator.py --source edr --input samples/edr-raw.json --dry-run \
        --tenant-id acme --ip-salt "$env:THOT_SECURE_IP_SALT"

    # 2. Poster réellement (la clé vient de l'environnement)
    python translator.py --source waf --input samples/waf-raw.json \
        --url "$env:THOT_SECURE_URL" --api-key "$env:THOT_SECURE_API_KEY"

    # 3. Mode n8n : le payload arrive sur stdin (JSON ou JSONL)
    Get-Content samples/siem-raw.json -Raw | python translator.py --source siem --stdin

Codes de sortie
---------------

==== ==========================================================================
0    tous les événements ont été acceptés (``rejected == 0``)
1    échec de transport/réseau, ou réponse 5xx après la nouvelle tentative
2    erreur d'usage ou de configuration (arguments invalides, 401/403)
3    le serveur a refusé au moins un événement (``rejected > 0``, ou 400/409/422)
==== ==========================================================================
"""

from __future__ import annotations
import contextlib as _contextlib
import sys as _sys

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

# --- Sortie Unicode sûre ---------------------------------------------------------------
# Sous Windows, une console en page de code cp1252 ne peut pas encoder « ✖ », « ✔ » ou « ─ » :
# `print()` lève alors UnicodeEncodeError et le script sort en code 1 alors que le travail a
# réussi. On force UTF-8 avec repli, sans jamais lever.
def _configure_safe_output() -> None:
    """Réglage d'encodage des flux standard (idempotent, sans effet hors Windows)."""
    for stream in (_sys.stdout, _sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with _contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


_configure_safe_output()
# ----------------------------------------------------------------------------------------


__all__ = ["main", "Translator", "redact_secrets", "pseudonymize_ip", "PROFILES"]

# --------------------------------------------------------------------------------------
# Constantes du contrat (§3.1, §4.3, §9)
# --------------------------------------------------------------------------------------

#: Énumération fermée de ``kind`` (contrat §3.1).
KINDS: tuple[str, ...] = (
    "http.request",
    "http.response",
    "log.line",
    "tls.cert",
    "dependency",
    "config.audit",
    "syslog",
    "generic",
)

#: Valeurs admises de ``severity_hint`` (contrat §3.1). ``None`` est également accepté.
SEVERITY_HINTS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Contrainte §4.3 : au plus 500 événements par lot.
MAX_BATCH_SIZE = 500

#: Contrainte §3.1 : ``payload`` ≤ 32 Kio sérialisé.
MAX_PAYLOAD_BYTES = 32 * 1024

#: Valeur par défaut de l'API locale (§4.1, §9 : ``THOT_HOST``/``THOT_PORT``).
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

DEFAULT_BATCH_SIZE = 100
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRY_AFTER_MAX = 30.0

USER_AGENT = "thotsecure-webhook-bridge/0.1.0 (+https://github.com/thot-corp/thot-secure)"

REDACTED = "[REDACTED]"
REDACTED_JWT = "[REDACTED_JWT]"

#: Champs d'adresse IP pseudonymisés par défaut (mêmes noms que ``helpers.DEFAULT_IP_FIELDS``).
DEFAULT_IP_FIELDS: tuple[str, ...] = (
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


# --------------------------------------------------------------------------------------
# Configuration : variables d'environnement
# --------------------------------------------------------------------------------------


def env_first(*names: str, default: str | None = None) -> str | None:
    """Première variable d'environnement définie et non vide parmi *names*.

    Les noms « Thot Secure » (``THOT_SECURE_*``) sont privilégiés, avec repli sur les noms
    historiques ``THOT_*`` (contrat §9) : les deux conventionnements restent acceptés.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


# --------------------------------------------------------------------------------------
# Redaction des secrets — reproduction de ``sdks/python/thotsecure_sdk/helpers.py``
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
    """Normalise un nom de champ : minuscules, séparateurs ``-``/``.``/espaces → ``_``."""
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def is_sensitive_key(key: Any) -> bool:
    """``True`` si le nom de champ désigne une donnée à masquer.

    En cas de doute on masque (*fail-closed*) : un faux positif produit un log inexploitable,
    un faux négatif produit une fuite de secret dans le SIEM.
    """
    normalized = _normalize_key(key)
    if not normalized:
        return False
    if normalized in _SENSITIVE_EXACT:
        return True
    parts = [part for part in normalized.split("_") if part]
    if any(part in _SENSITIVE_PARTS for part in parts):
        return True
    if "api" in parts and "key" in parts:
        return True
    return False


def _scrub_string(value: str) -> str:
    """Masque les secrets *contenus* dans une chaîne (JWT, ``Bearer …``, ``token=…``)."""
    scrubbed = _JWT_RE.sub(REDACTED_JWT, value)
    scrubbed = _AUTH_SCHEME_RE.sub(lambda match: "%s %s" % (match.group(1), REDACTED), scrubbed)
    scrubbed = _KV_SECRET_RE.sub(lambda match: "%s=%s" % (match.group(1), REDACTED), scrubbed)
    return scrubbed


def _mask_value(value: Any) -> Any:
    """Remplace une valeur sensible en conservant le schéma d'authentification lisible."""
    if isinstance(value, str):
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token", "apikey"):
            return "%s %s" % (parts[0], REDACTED)
        return REDACTED
    return REDACTED


def redact_secrets(data: Any, *, depth: int = 0, _seen: set[int] | None = None) -> Any:
    """Copie de *data* où les champs et valeurs sensibles sont masqués (récursif).

    Filtre documenté, aligné sur ``thotsecure_sdk.helpers.redact_secrets`` :

    * **clés sensibles** (insensibles à la casse, ``-``/``_``/``.`` équivalents) :
      ``authorization``, ``cookie``, ``set-cookie``, ``password``, ``token``, ``api_key``,
      ``secret``, ``session``, ``signature``, ``credentials``… ainsi que tout nom composé
      contenant un de ces fragments (``refresh_token``, ``x_api_key``, ``user_password``…) ;
    * **JWT** (motif ``eyJ…``) présents dans une valeur, même sous une clé anodine ;
    * **schémas d'authentification** ``Bearer …`` / ``Basic …`` / ``Api-Key …`` ;
    * **paires de query string** ``token=…``, ``password=…``, ``api_key=…``.

    Le résultat reste sérialisable en JSON (les tuples/ensembles deviennent des listes) et la
    récursion est bornée (profondeur 32, protection contre les structures cycliques).
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
        return [redact_secrets(item, depth=depth + 1, _seen=_seen) for item in data]
    if isinstance(data, str):
        return _scrub_string(data)
    return data


# --------------------------------------------------------------------------------------
# Pseudonymisation RGPD des adresses IP — reproduction EXACTE de helpers.pseudonymize_ip
# --------------------------------------------------------------------------------------


def pseudonymize_ip(ip: str, salt: str, *, keep_prefix: bool = False, prefix: str = "ip-") -> str:
    """Pseudonymise une adresse IP de façon **déterministe** (HMAC-SHA256 + sel).

    Alignement avec ``sdks/python/thotsecure_sdk/helpers.py::pseudonymize_ip`` : le message
    HMAC est la forme **canonique** de l'adresse (``str(ipaddress.ip_address(...))``, ou
    l'adresse réseau si l'entrée est un CIDR), la clé est le sel encodé en UTF-8, et le
    pseudonyme est ``prefix + hexdigest()[:32]``. Une IP donnée produit donc exactement le même
    pseudonyme qu'elle soit ingérée par le SDK, par la CLI ou par ce pont webhook.

    Pourquoi pseudonymiser : une adresse IP est une donnée à caractère personnel (RGPD
    art. 4.1). Le sel est un secret d'organisation : sans lui, un attaquant disposant du
    pseudonyme peut tester par dictionnaire les IP candidates d'un espace IPv4.

    Lève ``ValueError`` si l'entrée n'est pas une IP/ CIDR valide ou si le sel est vide.
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
            address = ipaddress.ip_address(raw)
            packed_str = str(address)
            if keep_prefix:
                bits = 24 if address.version == 4 else 64
                network_text = str(ipaddress.ip_network("%s/%d" % (address, bits), strict=False))
    except ValueError as exc:
        raise ValueError("pseudonymize_ip : %r n'est pas une IP ni un CIDR valide" % raw) from exc

    digest = hmac.new(salt.encode("utf-8"), packed_str.encode("utf-8"), hashlib.sha256).hexdigest()
    token = "%s%s" % (prefix, digest[:32])
    if keep_prefix and network_text:
        return "%s@%s" % (token, network_text)
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

    Les valeurs qui ne sont pas des IP valides (``"unknown"``, ``"-"``, un nom d'hôte) sont
    laissées intactes : le nettoyage ne doit jamais faire échouer une ingestion.
    """
    if depth > 32 or not salt:
        return data
    wanted = {_normalize_key(field) for field in fields}
    if isinstance(data, Mapping):
        out: dict[Any, Any] = {}
        for key, value in data.items():
            if (
                _normalize_key(key) in wanted
                and isinstance(value, str)
                and value.strip() not in ("", "-")
            ):
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
# Temps et sévérité
# --------------------------------------------------------------------------------------


def _to_iso_utc(moment: datetime) -> str:
    """ISO 8601 UTC en millisecondes, au format du contrat (``…Z``)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_iso() -> str:
    """Horodatage courant au format du contrat §3.1."""
    return _to_iso_utc(datetime.now(timezone.utc))


def parse_timestamp(value: Any) -> datetime | None:
    """Analyse un horodatage hétérogène (ISO 8601, epoch s/ms) → ``datetime`` UTC.

    Retourne ``None`` si la valeur est absente ou non reconnue : l'appelant retombe alors sur
    l'heure de réception, sans jamais faire échouer la traduction.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # millisecondes
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,13}", text):
        return parse_timestamp(float(text))
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


#: Niveaux fournisseur usuels → ``severity_hint`` du contrat.
_SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "fatal": "critical",
    "severe": "critical",
    "emergency": "critical",
    "5": "critical",
    "high": "high",
    "error": "high",
    "err": "high",
    "major": "high",
    "4": "high",
    "medium": "medium",
    "moderate": "medium",
    "warn": "medium",
    "warning": "medium",
    "3": "medium",
    "low": "low",
    "minor": "low",
    "notice": "low",
    "2": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "debug": "info",
    "trace": "info",
    "verbose": "info",
    "ok": "info",
    "1": "info",
}


def normalize_severity(value: Any) -> str | None:
    """Convertit une sévérité tierce en ``severity_hint`` du contrat, ou ``None``.

    Les niveaux numériques sont interprétés sur l'échelle fournisseur ``1 (info) → 5
    (critique)``. L'échelle syslog ``0-7`` (où 0 est le plus grave) n'est **pas** devinée :
    une valeur ambiguë est convertie en ``None`` plutôt qu'en une sévérité fausse. Pour du
    syslog, utilisez ``thotsecure_sdk.helpers.from_syslog_line``, qui connaît le PRI.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if float(value).is_integer():
            return _SEVERITY_MAP.get(str(int(value)))
        return None
    return _SEVERITY_MAP.get(str(value).strip().lower())


# --------------------------------------------------------------------------------------
# Profils de traduction
# --------------------------------------------------------------------------------------
#
# Chaque profil décrit, de façon déclarative, comment extraire d'un payload tiers les champs
# du contrat §3.1. Les listes sont des **alias ordonnés** (le premier trouvé gagne) et
# acceptent un chemin pointé (``"event.severity"``) pour les payloads imbriqués.

_UNWRAP_KEYS: tuple[str, ...] = ("event", "data", "alert", "detail", "details", "finding", "record", "item")

_GENERIC_LABELS: dict[str, tuple[str, ...]] = {
    "event_type": ("event_type", "event_name", "type", "category", "event.action", "action"),
    "user": ("user", "username", "user_name", "account", "principal", "actor"),
    "host": ("host", "hostname", "host_name", "device", "computer", "source_host"),
}

PROFILES: dict[str, dict[str, Any]] = {
    # ------------------------------------------------------------------ profil générique
    "generic": {
        "description": "payload JSON quelconque d'un émetteur tiers",
        "kind": "generic",
        "source_type": "webhook",
        "source_name": "third-party-webhook",
        "ts": ("ts", "timestamp", "@timestamp", "time", "event_time", "occurred_at", "created_at"),
        "host": ("host", "hostname", "host_name", "device", "computer", "source_host"),
        "name": ("source_name", "sensor", "collector", "product", "app", "vendor"),
        "severity": ("severity_hint", "severity", "level", "priority", "risk_level", "classification"),
        "message": ("message", "msg", "description", "summary", "detail", "reason", "event"),
        "ip": ("src_ip", "source_ip", "client_ip", "remote_addr", "remote_ip", "ip", "ip_address"),
        "labels": _GENERIC_LABELS,
        "payload": (
            "event_id",
            "id",
            "vendor",
            "product",
            "rule",
            "rule_id",
            "rule_name",
            "tags",
            "status",
        ),
    },
    # ------------------------------------------------------------------ EDR / antivirus
    "edr": {
        "description": "alerte de détection endpoint (EDR/antivirus)",
        "kind": "generic",
        "source_type": "edr",
        "source_name": "edr-endpoint-sensor",
        "ts": ("ts", "timestamp", "detected_at", "event_time", "@timestamp"),
        "host": ("hostname", "host", "device", "computer", "endpoint", "agent.hostname"),
        "name": ("sensor", "product", "vendor", "agent.name"),
        "severity": ("severity", "severity_hint", "level", "threat_level", "risk_level"),
        "message": ("description", "message", "summary", "threat_name", "detection"),
        "ip": ("src_ip", "host_ip", "device_ip", "ip_address", "remote_ip"),
        "labels": {
            **_GENERIC_LABELS,
            "alert_type": ("alert_type", "event_type", "detection_type", "category"),
            "malware_family": ("malware_family", "threat_name", "signature", "family"),
            "action_taken": ("action_taken", "action", "disposition", "response_action"),
            "file_hash_sha256": ("file_hash_sha256", "sha256", "hash.sha256", "file.hash"),
            "platform": ("platform", "os", "os_family", "operating_system"),
        },
        "payload": ("file_path", "process_name", "process_id", "quarantine_id", "detection_confidence", "user_notified"),
    },
    # ------------------------------------------------------------------ authentification
    "auth": {
        "description": "échec(s) d'authentification constaté(s) par un tiers (IdP, VPN, SSO)",
        "kind": "syslog",
        "source_type": "syslog",
        "source_name": "auth-gateway",
        "ts": ("ts", "timestamp", "last_failure_ts", "@timestamp", "event_time"),
        "host": ("host", "hostname", "gateway", "device"),
        "name": ("service", "auth_service", "app", "product"),
        "severity": ("severity", "severity_hint", "level"),
        "message": ("message", "description", "summary", "raw_line"),
        "ip": ("src_ip", "source_ip", "client_ip", "remote_addr", "remote_ip", "ip"),
        "labels": {
            **_GENERIC_LABELS,
            "auth_service": ("auth_service", "service", "protocol", "application"),
            "auth_result": ("auth_result", "result", "outcome", "status"),
            "auth_method": ("auth_method", "method", "mechanism"),
            "failure_count": ("failure_count", "count", "attempts", "failed_attempts"),
            "window_seconds": ("window_seconds", "window", "period_seconds"),
            "detected_by": ("detected_by", "detector", "vendor"),
            "detector_rule": ("detector_rule", "rule_id", "rule"),
        },
        "payload": ("detector_note", "source_port", "first_failure_ts", "last_failure_ts", "account_locked_by_detector"),
    },
    # ------------------------------------------------------------------ WAF
    "waf": {
        "description": "événement de pare-feu applicatif (WAF) : requête bloquée ou journalisée",
        "kind": "http.request",
        "source_type": "waf",
        "source_name": "edge-waf",
        "ts": ("ts", "timestamp", "@timestamp", "time", "transaction.time"),
        "host": ("host", "vhost", "hostname", "request.host", "server_name"),
        "name": ("waf_engine", "engine", "product", "vendor"),
        "severity": ("severity", "severity_hint", "level", "anomaly_severity"),
        "message": ("message", "rule_message", "description", "waf_rule_message"),
        "ip": ("src_ip", "client_ip", "source_ip", "remote_addr", "request.remote_addr"),
        "labels": {
            **_GENERIC_LABELS,
            "method": ("method", "request.method", "http_method"),
            "path": ("path", "request.path", "uri", "request_uri"),
            "query": ("query", "query_string", "request.query", "args"),
            "protocol": ("protocol", "request.protocol", "http_version"),
            "user_agent": ("user_agent", "request.headers.user-agent", "http_user_agent"),
            "waf_rule_id": ("waf_rule_id", "rule_id", "rule.id", "id"),
            "waf_rule_message": ("waf_rule_message", "rule_message", "rule.msg", "message"),
            "waf_action": ("waf_action", "action", "disposition", "rule.action"),
            "waf_engine": ("waf_engine", "engine", "product"),
        },
        "payload": ("status", "bytes", "matched_parameter", "anomaly_score", "request_id", "blocked_before_origin"),
    },
    # ------------------------------------------------------------------ CSPM / cloud
    "cspm": {
        "description": "constat de posture cloud (CSPM) : ressource non conforme",
        "kind": "config.audit",
        "source_type": "cspm",
        "source_name": "cloud-posture-scanner",
        "ts": ("ts", "timestamp", "detected_at", "@timestamp", "first_seen"),
        "host": ("host", "collector", "scanner", "hostname"),
        "name": ("scanner", "product", "vendor", "service"),
        "severity": ("severity", "severity_hint", "level", "risk_level"),
        "message": ("message", "description", "summary", "finding", "title"),
        "ip": ("resource_ip", "ip_address", "public_ip", "src_ip", "ip"),
        "labels": {
            **_GENERIC_LABELS,
            "provider": ("provider", "cloud", "cloud_provider"),
            "account_id": ("account_id", "account", "subscription_id", "project_id"),
            "region": ("region", "location", "zone"),
            "resource_type": ("resource_type", "resource.type", "type"),
            "resource_id": ("resource_id", "resource.id", "resource_name", "name"),
            "check_id": ("check_id", "control_id", "rule_id", "policy_id"),
            "control": ("control", "control_name", "benchmark"),
            "status": ("status", "result", "state", "compliance_status"),
            "compliance": ("compliance", "frameworks", "standard"),
            "detected_by": ("detected_by", "scanner", "vendor"),
        },
        "payload": (
            "previous_status",
            "current_status",
            "first_seen",
            "storage_class",
            "object_count",
            "remediation",
            "evidence_uri",
        ),
    },
    # ------------------------------------------------------------------ SIEM
    "siem": {
        "description": "détection corrélée produite par un SIEM tiers",
        "kind": "log.line",
        "source_type": "siem",
        "source_name": "correlation-engine",
        "ts": ("ts", "timestamp", "@timestamp", "time", "event_time"),
        "host": ("host", "hostname", "indexer", "device"),
        "name": ("siem_index", "index", "product", "vendor"),
        "severity": ("severity", "severity_hint", "level", "priority"),
        "message": ("message", "description", "summary", "rule_name", "signature"),
        "ip": ("src_ip", "source_ip", "client_ip", "remote_addr", "ip"),
        "labels": {
            **_GENERIC_LABELS,
            "siem_rule_id": ("siem_rule_id", "rule_id", "signature_id", "id"),
            "siem_rule_name": ("siem_rule_name", "rule_name", "signature", "title"),
            "siem_index": ("siem_index", "index", "sourcetype"),
            "correlation_count": ("correlation_count", "count", "event_count", "hits"),
            "mitre_technique": ("mitre_technique", "mitre_id", "technique", "mitre.technique"),
            "detected_by": ("detected_by", "detector", "vendor"),
        },
        "payload": ("window_seconds", "threshold", "event_count", "severity_raw", "ticket_ref"),
    },
}

#: Le profil ``jsonl`` applique le profil ``generic`` à chaque ligne d'un flux JSONL.
PROFILE_ALIASES = {"jsonl": "generic"}


# --------------------------------------------------------------------------------------
# Extraction de champs
# --------------------------------------------------------------------------------------


def dig(record: Mapping[str, Any], path: str) -> Any:
    """Lit un chemin pointé (``"request.method"``) dans un mapping ; ``None`` si absent."""
    current: Any = record
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def pick(record: Mapping[str, Any], aliases: Sequence[str]) -> Any:
    """Première valeur non vide parmi les alias ordonnés (sinon ``None``)."""
    for alias in aliases:
        value = dig(record, alias)
        if value is None or value == "" or value == [] or value == {}:
            continue
        return value
    return None


def unwrap(record: Mapping[str, Any]) -> dict[str, Any]:
    """Aplatit une enveloppe courante (``{"event": {...}}``) sans écraser les clés externes.

    Beaucoup d'émetteurs encapsulent le contenu utile sous ``event``/``data``/``alert``/``detail``.
    Les clés de l'enveloppe restent prioritaires (le contexte externe est réputé plus fiable),
    mais les champs internes deviennent accessibles aux alias.
    """
    merged: dict[str, Any] = {}
    for key in _UNWRAP_KEYS:
        inner = record.get(key)
        if isinstance(inner, Mapping):
            merged.update(inner)
    merged.update(record)
    return merged


def as_scalar(value: Any) -> Any:
    """Ramène une valeur à un scalaire JSON (exigence « ``labels`` plat » du contrat §3.1)."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def serialized_size(value: Any) -> int:
    """Taille en octets de la forme JSON compacte de *value* (UTF-8)."""
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def truncate_payload(
    payload: Mapping[str, Any],
    *,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    keep_keys: Sequence[str] = ("status", "method", "path", "message"),
) -> tuple[dict[str, Any], bool]:
    """Ramène *payload* sous *max_bytes* et indique si une troncature a eu lieu.

    Stratégie (identique à celle du SDK) : troncature des chaînes les plus longues, puis retrait
    des clés les plus volumineuses (en préservant *keep_keys*), puis remplacement par un marqueur.
    Le contrat §3.1 demande de renseigner ``raw_ref`` lorsque le payload est tronqué.
    """
    result: dict[str, Any] = dict(payload)
    if serialized_size(result) <= max_bytes:
        return result, False

    for _ in range(64):
        if serialized_size(result) <= max_bytes:
            break
        candidates = [
            (len(str(value)), key) for key, value in result.items() if isinstance(value, str) and len(value) > 256
        ]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result[key] = str(result[key])[:256] + "…[tronqué]"

    for _ in range(64):
        if serialized_size(result) <= max_bytes:
            break
        candidates = [(serialized_size({key: value}), key) for key, value in result.items() if key not in keep_keys]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result.pop(key, None)

    if serialized_size(result) > max_bytes:
        result = {"_truncated": True, "_original_keys": sorted(str(key) for key in payload)}
    return result, True


# --------------------------------------------------------------------------------------
# Traducteur
# --------------------------------------------------------------------------------------


class TranslationError(ValueError):
    """Payload tiers inutilisable (ni mapping, ni chaîne)."""


class Translator:
    """Transforme un payload tiers en ``Event`` conforme au contrat §3.1.

    Paramètres
    ----------
    profile :
        Nom du profil de traduction (voir :data:`PROFILES`).
    tenant_id :
        Valeur par défaut de ``tenant_id`` quand la source n'en fournit pas. Rappel du contrat
        §4.3 : le serveur **force** ``tenant_id`` depuis la clé API — cette valeur est donc
        indicative et ne peut pas servir à écrire dans un autre tenant.
    ip_salt :
        Sel de pseudonymisation. Si ``None`` ou vide, **aucune** IP n'est pseudonymisée : les
        adresses restent en clair dans les événements (à éviter en production, RGPD).
    keep_ip_prefix :
        Conserve le réseau (``/24`` IPv4, ``/64`` IPv6) à côté du pseudonyme.
    overrides :
        Surcharges explicites de ``kind``, ``source.type``, ``source.name``, ``source.host``.
    """

    def __init__(
        self,
        profile: str = "generic",
        *,
        tenant_id: str = "default",
        ip_salt: str | None = None,
        keep_ip_prefix: bool = False,
        overrides: Mapping[str, str | None] | None = None,
    ) -> None:
        name = PROFILE_ALIASES.get(profile, profile)
        if name not in PROFILES:
            raise TranslationError(
                "profil inconnu : %r (attendu : %s)" % (profile, ", ".join(sorted(PROFILES)))
            )
        self.profile_name = profile
        self.profile = PROFILES[name]
        self.tenant_id = tenant_id or "default"
        self.ip_salt = ip_salt or None
        self.keep_ip_prefix = bool(keep_ip_prefix)
        overrides = dict(overrides or {})
        self.kind = overrides.get("kind") or self.profile["kind"]
        self.source_type = overrides.get("source_type") or self.profile["source_type"]
        self.source_name = overrides.get("source_name") or self.profile["source_name"]
        self.source_host = overrides.get("source_host")
        if self.kind not in KINDS:
            raise TranslationError(
                "kind invalide : %r (énumération §3.1 : %s)" % (self.kind, ", ".join(KINDS))
            )

    # -- construction ------------------------------------------------------------------

    def _coerce_record(self, raw: Any) -> Mapping[str, Any]:
        """Accepte un mapping, une chaîne JSON, ou une chaîne quelconque (→ message)."""
        if isinstance(raw, Mapping):
            return raw
        if isinstance(raw, str):
            text = raw.strip()
            if text.startswith("{"):
                try:
                    parsed = json.loads(text)
                except ValueError:
                    parsed = None
                if isinstance(parsed, Mapping):
                    return parsed
            return {"message": text}
        raise TranslationError(
            "payload non pris en charge (attendu objet JSON ou chaîne, reçu %s)" % type(raw).__name__
        )

    def _labels(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Construit un ``labels`` **plat** à valeurs scalaires (contrat §3.1)."""
        profile = self.profile
        labels: dict[str, Any] = {}
        src_ip = pick(record, profile["ip"])
        if src_ip is not None:
            labels["src_ip"] = as_scalar(src_ip)
        for label_name, aliases in profile["labels"].items():
            if label_name in labels:
                continue
            value = pick(record, aliases)
            if value is None:
                continue
            labels[label_name] = as_scalar(value)
        return labels

    def _payload(self, record: Mapping[str, Any], message: Any) -> dict[str, Any]:
        """Construit le ``payload`` (libre) : message lisible + champs propres au profil."""
        payload: dict[str, Any] = {"message": as_scalar(message)}
        for key in self.profile["payload"]:
            value = dig(record, key)
            if value is None or value == "":
                continue
            payload[key] = value
        # Traçabilité : permet de savoir par quel pont l'événement est entré.
        payload["translator"] = "n8n-webhook-bridge/%s" % self.profile_name
        return payload

    def _already_event(self, record: Mapping[str, Any]) -> bool:
        """``True`` si le document est déjà un ``Event`` §3.1 (passe-plat re-validé)."""
        return (
            isinstance(record.get("source"), Mapping)
            and record.get("kind") in KINDS
            and record.get("ts") is not None
        )

    def translate(self, raw: Any) -> dict[str, Any]:
        """Traduit un payload tiers en dictionnaire ``Event`` prêt à être posté."""
        record = self._coerce_record(raw)

        if self._already_event(record):
            return self._clean(self._passthrough_event(record))

        flat = unwrap(record)
        message = pick(flat, self.profile["message"])
        if message is None:
            message = "Événement %s reçu via webhook (aucun champ « message » exploitable)" % self.profile_name

        host = self.source_host or pick(flat, self.profile["host"])
        name = self.source_name or pick(flat, self.profile["name"]) or self.profile["source_name"]
        severity = normalize_severity(pick(flat, self.profile["severity"]))
        parsed_ts = parse_timestamp(pick(flat, self.profile["ts"]))
        payload = self._payload(flat, message)
        payload, truncated = truncate_payload(payload)
        if truncated:
            payload["_truncated_note"] = "payload tronqué à %d octets (contrat §3.1)" % MAX_PAYLOAD_BYTES

        event = {
            "event_id": str(uuid.uuid4()),
            "schema_version": "1",
            "tenant_id": str(pick(flat, ("tenant_id",)) or self.tenant_id),
            "ts": _to_iso_utc(parsed_ts) if parsed_ts is not None else now_iso(),
            "kind": pick(flat, ("kind",)) if pick(flat, ("kind",)) in KINDS else self.kind,
            "source": {
                "type": str(pick(flat, ("source.type", "source_type")) or self.source_type),
                "name": str(name),
                "host": str(host or name),
            },
            "severity_hint": severity,
            "labels": self._labels(flat),
            "payload": payload,
            "raw_ref": "truncated:payload>%d" % MAX_PAYLOAD_BYTES if truncated else None,
        }
        return self._clean(event)

    def _passthrough_event(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Reconstruit un ``Event`` déjà conforme, en ne gardant que les champs du contrat."""
        source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
        event = {
            "event_id": str(record.get("event_id") or uuid.uuid4()),
            "schema_version": "1",
            "tenant_id": str(record.get("tenant_id") or self.tenant_id),
            "ts": record.get("ts"),
            "kind": record.get("kind") if record.get("kind") in KINDS else self.kind,
            "source": {
                "type": str(source.get("type") or self.source_type),
                "name": str(source.get("name") or self.source_name),
                "host": str(source.get("host") or source.get("name") or self.source_name),
            },
            "severity_hint": normalize_severity(record.get("severity_hint")),
            "labels": {str(key): as_scalar(value) for key, value in dict(record.get("labels") or {}).items()},
            "payload": dict(record.get("payload") or {}),
            "raw_ref": record.get("raw_ref"),
        }
        parsed_ts = parse_timestamp(event["ts"])
        event["ts"] = _to_iso_utc(parsed_ts) if parsed_ts is not None else now_iso()
        payload, truncated = truncate_payload(event["payload"])
        event["payload"] = payload
        if truncated and not event["raw_ref"]:
            event["raw_ref"] = "truncated:payload>%d" % MAX_PAYLOAD_BYTES
        return event

    def _clean(self, event: dict[str, Any]) -> dict[str, Any]:
        """Applique la redaction puis la pseudonymisation, et valide le résultat.

        L'ordre est celui du SDK (``redact`` puis ``ip_salt``) : masquer d'abord garantit qu'un
        secret ne peut pas être « protégé » par une pseudonymisation.
        """
        cleaned = redact_secrets(event)
        if self.ip_salt:
            cleaned = pseudonymize_ip_fields(
                cleaned, self.ip_salt, fields=DEFAULT_IP_FIELDS, keep_prefix=self.keep_ip_prefix
            )
        validate_event(cleaned)
        return cleaned


def validate_event(event: Mapping[str, Any]) -> None:
    """Vérifie les invariants du contrat §3.1 (lève ``ValueError`` avec un motif explicite)."""
    if event.get("schema_version") != "1":
        raise ValueError("schema_version doit valoir \"1\" (contrat §3.1)")
    if not event.get("tenant_id"):
        raise ValueError("tenant_id manquant (contrat §1 : tout objet porte un tenant_id)")
    if event.get("kind") not in KINDS:
        raise ValueError("kind invalide : %r (énumération §3.1 : %s)" % (event.get("kind"), ", ".join(KINDS)))
    if event.get("severity_hint") is not None and event["severity_hint"] not in SEVERITY_HINTS:
        raise ValueError("severity_hint invalide : %r" % (event.get("severity_hint"),))
    source = event.get("source")
    if not isinstance(source, Mapping) or not source.get("type") or not source.get("name"):
        raise ValueError("source.type et source.name sont obligatoires (contrat §3.1)")
    labels = event.get("labels")
    if not isinstance(labels, Mapping):
        raise ValueError("labels doit être un objet plat")
    for key, value in labels.items():
        if isinstance(value, (Mapping, list, tuple, set)):
            raise ValueError("labels.%s n'est pas scalaire : « labels » doit rester plat (contrat §3.1)" % key)
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload doit être un objet")
    if serialized_size(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload sérialisé > %d octets (contrat §3.1)" % MAX_PAYLOAD_BYTES)
    parsed = parse_timestamp(event.get("ts"))
    if parsed is None:
        raise ValueError("ts illisible : %r" % (event.get("ts"),))


# --------------------------------------------------------------------------------------
# Lecture de l'entrée
# --------------------------------------------------------------------------------------


def iter_documents(text: str, *, jsonl: bool) -> Iterator[Any]:
    """Itère sur les documents d'une entrée texte (JSON unique, JSONL, ou liste JSON).

    * ``jsonl=True`` : une ligne = un JSON (les lignes vides sont ignorées, une ligne invalide
      lève ``ValueError`` avec son numéro) ;
    * sinon : un document JSON ; une liste devient une liste de documents ; un objet contenant
      ``events``/``items``/``data`` en liste est éclaté de la même façon.
    """
    if jsonl:
        for number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError as exc:
                raise ValueError("ligne %d : JSON invalide (%s)" % (number, exc)) from exc
        return
    stripped = text.strip()
    if not stripped:
        return
    document = json.loads(stripped)
    if isinstance(document, list):
        for item in document:
            yield item
        return
    if isinstance(document, Mapping):
        for key in ("events", "items", "data", "records"):
            value = document.get(key)
            if isinstance(value, list):
                for item in value:
                    yield item
                return
    yield document


def read_documents(input_path: str | None, *, use_stdin: bool, jsonl: bool) -> list[Any]:
    """Lit le payload depuis stdin (mode n8n) ou depuis un fichier."""
    if use_stdin:
        return list(iter_documents(sys.stdin.read(), jsonl=jsonl))
    if not input_path:
        raise ValueError("aucune entrée : utilisez --input FICHIER ou --stdin")
    with open(input_path, "r", encoding="utf-8") as handle:
        return list(iter_documents(handle.read(), jsonl=jsonl))


# --------------------------------------------------------------------------------------
# Transport HTTP (urllib, stdlib uniquement)
# --------------------------------------------------------------------------------------


class TransportError(RuntimeError):
    """Échec réseau, DNS, TLS ou délai d'attente dépassé (aucune réponse HTTP exploitable)."""


def get_header(headers: Any, name: str) -> str | None:
    """Lecture insensible à la casse d'un en-tête (``http.client.HTTPMessage`` ou ``dict``)."""
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    value = getter(name)
    if value is None:
        lowered = name.lower()
        for key, candidate in dict(headers).items():
            if str(key).lower() == lowered:
                return candidate
    return value


def parse_retry_after(value: Any) -> float | None:
    """Convertit un en-tête ``Retry-After`` (secondes ou date HTTP) en délai en secondes."""
    if not value:
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return float(text)
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0.0, (moment - datetime.now(timezone.utc)).total_seconds())


def post_json(
    url: str,
    body: Any,
    *,
    api_key: str | None,
    timeout: float,
    user_agent: str = USER_AGENT,
) -> tuple[int, Any, str, Any]:
    """``POST`` JSON et retourne ``(statut, corps décodé, corps brut, en-têtes)``.

    Lève :class:`TransportError` si aucune réponse HTTP n'a pu être obtenue. La clé API est
    passée uniquement dans l'en-tête ``X-API-Key`` (jamais dans l'URL, qui finit dans les logs
    de proxy) et n'apparaît dans aucun message d'erreur.
    """
    data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    if api_key:
        headers["X-API-Key"] = api_key
    request = urlrequest.Request(url, data=data, headers=headers, method="POST")
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, _decode(raw), _text(raw), response.headers
    except urlerror.HTTPError as exc:
        raw = exc.read()
        return exc.code, _decode(raw), _text(raw), exc.headers
    except (urlerror.URLError, OSError, ValueError) as exc:
        raise TransportError("échec de la requête vers %s : %s" % (_safe_url(url), exc)) from exc


def _decode(raw: bytes) -> Any:
    """Décode un corps JSON, ou retourne ``None`` si le corps n'est pas du JSON."""
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _text(raw: bytes) -> str:
    """Corps brut en texte, tronqué pour rester lisible dans un log."""
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")[:2000]


def _safe_url(url: str) -> str:
    """URL expurgée de tout identifiant utilisateur (``http://user:pass@hôte``)."""
    without_credentials = re.sub(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@", r"\g<scheme>", url)
    return without_credentials


def error_summary(payload: Any, raw_text: str) -> str:
    """Résumé lisible d'une erreur normalisée du contrat §4.6."""
    if isinstance(payload, Mapping):
        error = payload.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            message = error.get("message")
            details = error.get("details")
            parts = [str(part) for part in (code, message) if part]
            if details:
                parts.append("details=%s" % json.dumps(details, ensure_ascii=False, default=str)[:300])
            if parts:
                return " · ".join(parts)
        return json.dumps(payload, ensure_ascii=False, default=str)[:300]
    return raw_text.strip()[:300] or "(corps vide)"


# --------------------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------------------


def chunk_events(events: Sequence[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    """Découpe une séquence d'événements en lots de *size* (≤ 500, contrat §4.3)."""
    if size < 1 or size > MAX_BATCH_SIZE:
        raise ValueError("batch_size doit être compris entre 1 et %d" % MAX_BATCH_SIZE)
    for start in range(0, len(events), size):
        yield list(events[start : start + size])


def post_events(
    events: Sequence[dict[str, Any]],
    *,
    url: str,
    api_key: str | None,
    timeout: float,
    batch_size: int,
    retry_after_max: float,
    log: Any,
    sleep: Any = time.sleep,
) -> tuple[int, dict[str, Any]]:
    """Poste les événements par lots et retourne ``(code_de_sortie, compteurs)``.

    Gestion des erreurs HTTP :

    * ``202`` → compteurs fusionnés ;
    * ``401``/``403`` → erreur de configuration (clé absente, révoquée, rôle sans
      ``write:events``) : arrêt immédiat, code 2 ;
    * ``429`` → respect de ``Retry-After`` (borné par *retry_after_max*), **une seule** nouvelle
      tentative, puis code 1 ;
    * ``5xx`` → une seule nouvelle tentative après un court délai, puis code 1 ;
    * ``400``/``409``/``422`` → l'événement est refusé : code 3 ;
    * autre ``4xx`` → code 1.
    """
    counters: dict[str, Any] = {"accepted": 0, "rejected": 0, "event_ids": [], "findings": []}
    total_batches = (len(events) + batch_size - 1) // batch_size

    for index, batch in enumerate(chunk_events(events, batch_size), start=1):
        body: Any = batch[0] if len(batch) == 1 else {"events": batch}
        status, payload, raw_text, headers = post_json(
            url, body, api_key=api_key, timeout=timeout
        )

        if status == 429 or 500 <= status < 600:
            delay = parse_retry_after(get_header(headers, "Retry-After"))
            if delay is None:
                delay = 1.0 if status == 429 else 2.0
            delay = max(0.0, min(delay, float(retry_after_max)))
            log(
                "lot %d/%d : HTTP %d — nouvelle tentative unique dans %.1f s (Retry-After honoré)"
                % (index, total_batches, status, delay)
            )
            if delay:
                sleep(delay)
            status, payload, raw_text, headers = post_json(
                url, body, api_key=api_key, timeout=timeout
            )

        if status in (200, 202):
            accepted = payload.get("accepted") if isinstance(payload, Mapping) else None
            rejected = payload.get("rejected") if isinstance(payload, Mapping) else None
            counters["accepted"] += int(accepted or 0)
            counters["rejected"] += int(rejected or 0)
            if isinstance(payload, Mapping):
                ids = payload.get("event_ids")
                if isinstance(ids, list):
                    counters["event_ids"].extend(str(item) for item in ids)
                findings = payload.get("findings")
                if isinstance(findings, list):
                    counters["findings"].extend(findings)
            if counters["rejected"]:
                log(
                    "lot %d/%d : HTTP %d — %s accepté(s), %s rejeté(s)"
                    % (index, total_batches, status, counters["accepted"], counters["rejected"])
                )
            continue

        if status in (401, 403):
            log(
                "HTTP %d : clé API absente, invalide, révoquée ou rôle sans capacité « write:events » "
                "(contrat §4.2) — vérifiez THOT_SECURE_API_KEY. %s"
                % (status, error_summary(payload, raw_text))
            )
            return 2, counters

        if status in (400, 409, 422):
            log(
                "HTTP %d : événement refusé par le serveur — %s"
                % (status, error_summary(payload, raw_text))
            )
            return 3, counters

        log("HTTP %d : réponse inattendue — %s" % (status, error_summary(payload, raw_text)))
        return 1, counters

    if counters["rejected"]:
        return 3, counters
    return 0, counters


# --------------------------------------------------------------------------------------
# Interface en ligne de commande
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (--help documente chaque option)."""
    parser = argparse.ArgumentParser(
        prog="translator.py",
        description=(
            "Traduit un payload tiers en Event Thot Secure (§3.1) et l'ingère via "
            "POST /api/v1/events (§4.3). Bibliothèque standard uniquement."
        ),
        epilog="Codes de sortie : 0 succès, 1 échec réseau/5xx, 2 usage ou configuration, 3 événement refusé.",
    )
    parser.add_argument(
        "--source",
        default="generic",
        choices=sorted(set(list(PROFILES) + list(PROFILE_ALIASES))),
        help="profil de traduction ; « jsonl » = lignes JSON traitées avec le profil générique",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--input", metavar="FICHIER", help="payload à lire (JSON ou JSONL)")
    source_group.add_argument("--stdin", action="store_true", help="lire le payload sur stdin (mode n8n)")
    parser.add_argument(
        "--url",
        default=env_first("THOT_SECURE_URL", "THOT_URL", default=DEFAULT_BASE_URL),
        help="base de l'API (défaut : $env:THOT_SECURE_URL, sinon $env:THOT_URL, sinon %s)" % DEFAULT_BASE_URL,
    )
    parser.add_argument(
        "--api-key",
        default=env_first("THOT_SECURE_API_KEY", "THOT_API_KEY"),
        help="clé ao_… (défaut : $env:THOT_SECURE_API_KEY) ; préférez l'environnement à la ligne de commande",
    )
    parser.add_argument(
        "--ip-salt",
        default=env_first("THOT_SECURE_IP_SALT", "THOT_IP_SALT"),
        help="sel de pseudonymisation des IP (défaut : $env:THOT_SECURE_IP_SALT) ; sans sel, les IP restent en clair",
    )
    parser.add_argument(
        "--keep-ip-prefix",
        action="store_true",
        help="conserve le réseau (/24 IPv4, /64 IPv6) à côté du pseudonyme",
    )
    parser.add_argument(
        "--tenant-id",
        default=env_first("THOT_SECURE_TENANT_ID", "THOT_TENANT_ID", default="default"),
        help="tenant_id par défaut si la source n'en fournit pas (le serveur le force depuis la clé)",
    )
    parser.add_argument("--kind", help="force le champ kind (énumération §3.1)")
    parser.add_argument("--source-type", help="force source.type")
    parser.add_argument("--source-name", help="force source.name")
    parser.add_argument("--source-host", help="force source.host")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="événements par lot (1 à %d, contrat §4.3)" % MAX_BATCH_SIZE,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="délai d'attente par requête en secondes (défaut %s)" % DEFAULT_TIMEOUT,
    )
    parser.add_argument(
        "--retry-after-max",
        type=float,
        default=DEFAULT_RETRY_AFTER_MAX,
        help="plafond d'attente imposé par Retry-After, en secondes (défaut %s)" % DEFAULT_RETRY_AFTER_MAX,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="affiche les événements traduits sur stdout et n'envoie AUCUNE requête",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="journalise la progression sur stderr")
    parser.add_argument("--version", action="version", version="thotsecure-webhook-bridge 0.1.0")
    return parser


def _stderr(message: str) -> None:
    """Journalise sur stderr : stdout reste réservé aux données (JSON en mode --dry-run)."""
    print("[translator] %s" % message, file=sys.stderr, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée CLI. Retourne le code de sortie (voir la docstring du module)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.batch_size < 1 or args.batch_size > MAX_BATCH_SIZE:
        _stderr("--batch-size doit être compris entre 1 et %d" % MAX_BATCH_SIZE)
        return 2
    if args.timeout <= 0:
        _stderr("--timeout doit être strictement positif")
        return 2

    jsonl = args.source == "jsonl" or bool(args.input and args.input.lower().endswith(".jsonl"))

    try:
        documents = read_documents(args.input, use_stdin=args.stdin, jsonl=jsonl)
    except (OSError, ValueError) as exc:
        _stderr("lecture de l'entrée impossible : %s" % exc)
        return 2

    if not documents:
        _stderr("aucun document à traduire (entrée vide)")
        return 2

    try:
        translator = Translator(
            args.source,
            tenant_id=args.tenant_id or "default",
            ip_salt=args.ip_salt,
            keep_ip_prefix=args.keep_ip_prefix,
            overrides={
                "kind": args.kind,
                "source_type": args.source_type,
                "source_name": args.source_name,
                "source_host": args.source_host,
            },
        )
    except TranslationError as exc:
        _stderr(str(exc))
        return 2

    events: list[dict[str, Any]] = []
    for index, document in enumerate(documents, start=1):
        try:
            events.append(translator.translate(document))
        except (TranslationError, ValueError) as exc:
            _stderr("document %d : traduction impossible — %s" % (index, exc))
            return 2

    if not args.ip_salt:
        _stderr(
            "avertissement : aucune pseudonymisation d'IP (THOT_SECURE_IP_SALT non défini) — "
            "les adresses IP seront stockées en clair, ce qui est une donnée à caractère personnel "
            "au sens du RGPD."
        )

    if args.dry_run:
        payload: Any = events[0] if len(events) == 1 else {"events": events}
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        _stderr(
            "--dry-run : %d événement(s) traduit(s), aucune requête envoyée vers %s"
            % (len(events), _safe_url(str(args.url)))
        )
        return 0

    if not args.api_key:
        _stderr(
            "clé API absente : définissez THOT_SECURE_API_KEY (ou THOT_API_KEY), "
            "ou utilisez --dry-run pour inspecter la traduction sans rien envoyer."
        )
        return 2

    endpoint = "%s/api/v1/events" % str(args.url).rstrip("/")
    if args.verbose:
        _stderr(
            "%d événement(s) → %s (lots de %d, profil %s)"
            % (len(events), _safe_url(endpoint), args.batch_size, args.source)
        )

    try:
        code, counters = post_events(
            events,
            url=endpoint,
            api_key=args.api_key,
            timeout=args.timeout,
            batch_size=args.batch_size,
            retry_after_max=args.retry_after_max,
            log=_stderr if args.verbose else (lambda _message: None),
        )
    except TransportError as exc:
        _stderr("échec réseau : %s" % exc)
        return 1

    _stderr(
        "ingestion terminée : %d accepté(s), %d rejeté(s), %d finding(s) créé(s)"
        % (
            counters.get("accepted", 0),
            counters.get("rejected", 0),
            len(counters.get("findings") or []),
        )
    )
    if args.verbose and counters.get("findings"):
        for finding in counters["findings"]:
            if isinstance(finding, Mapping):
                _stderr(
                    "  finding %s · règle %s · sévérité %s · risque %s · décision %s"
                    % (
                        finding.get("finding_id"),
                        finding.get("rule_id"),
                        finding.get("severity"),
                        finding.get("risk_score"),
                        finding.get("decision"),
                    )
                )
    return code


if __name__ == "__main__":
    sys.exit(main())
