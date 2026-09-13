#!/usr/bin/env python3
"""Collecteur Nginx → Thot Secure (nom de code ``thotsecure``).

Ce script **suit un journal Nginx en continu** (``access.log`` et/ou ``error.log``), normalise
chaque ligne en ``Event`` conforme au contrat d'interface v0.1.0
(``docs/architecture/api-contract.md`` §3.1), nettoie systématiquement l'événement
(**masquage des secrets** puis **pseudonymisation des adresses IP**) et l'ingère par lots vers
``POST /api/v1/events`` (§4.3).

Ce que fait le script, dans l'ordre
-----------------------------------

1. **Lecture incrémentale avec reprise** : chaque fichier est lu depuis l'offset mémorisé dans un
   fichier d'état JSON (``--state-file``). Après un redémarrage, la collecte reprend exactement où
   elle s'était arrêtée : aucun événement n'est perdu, aucun n'est rejoué. Les rotations
   (``logrotate``, changement d'inode) et les troncatures sont détectées et gérées.
2. **Normalisation** : une ligne ``combined`` Nginx devient un ``Event`` de ``kind``
   ``http.request`` ; une ligne de ``error.log`` devient un ``Event`` de ``kind`` ``log.line``.
   ``labels`` reste **plat** et à valeurs scalaires, comme l'exige le §3.1.
3. **Redaction** : ``redact_secrets()`` masque les secrets présents dans la ligne — en-tête
   ``Authorization: Bearer …``, JWT, jetons de *query string* (``?token=…``), cookies, mots de
   passe. Un secret ingéré est un secret à rotationner : mieux vaut un log inexploitable qu'une
   fuite. L'implémentation est alignée sur ``thotsecure_sdk.helpers.redact_secrets``.
4. **Pseudonymisation RGPD** : ``pseudonymize_ip()`` remplace chaque adresse IP par
   ``ip-<32 hex>`` (HMAC-SHA256 du sel + adresse canonique). Une adresse IP est une **donnée à
   caractère personnel** (RGPD art. 4.1) : sans pseudonymisation, ingérer un journal d'accès dans
   un SIEM revient à constituer un fichier de connexions nominatif. Le pseudonyme est
   déterministe : la corrélation entre événements d'une même source reste possible, y compris
   avec les événements ingérés via le SDK Python ou le pont n8n (même algorithme, même sel).
5. **Ingestion par lots de 100** (``--batch-size``, plafond 500 du §4.3) avec **contre-pression**
   : la file interne est **bornée** (``--queue-size``), donc un serveur lent ralentit la lecture au
   lieu de saturer la mémoire ; un ``429`` est honoré via l'en-tête ``Retry-After``.
6. **Récapitulatif** : lignes lues, lignes non reconnues, événements construits, acceptés,
   rejetés, lots envoyés, nouvelles tentatives, lots abandonnés.

Mode hors ligne (``--dry-run``)
-------------------------------

``--dry-run`` **n'émet aucune requête** et **n'écrit aucun fichier d'état** : les événements
construits sont imprimés sur stdout (un JSON compact par ligne, ou ``--pretty``). C'est le mode à
utiliser pour tester le collecteur sans serveur Thot Secure et sans réseau.

Aucune capacité offensive
-------------------------

Le script ne fait que **lire** un fichier de journal local et **émettre** des événements vers
Thot Secure. Il n'ouvre aucune connexion vers les adresses IP observées : ni scan, ni test
d'authentification, ni exploitation. L'invariant « zéro capacité offensive » du projet est
respecté par construction : le seul appel sortant va vers ``THOT_URL``.

Exemples
--------

::

    # 1. Vérification hors ligne : construire les événements sans rien envoyer
    python ingest_nginx_logs.py --file sample/access.log --dry-run --once --pretty

    # 2. Collecte réelle, en continu, avec reprise après redémarrage
    $env:THOT_SECURE_URL = "http://127.0.0.1:8080"
    $env:THOT_SECURE_API_KEY = "ao_..."
    $env:THOT_SECURE_IP_SALT = "sel-secret-d-organisation"
    python ingest_nginx_logs.py --file C:\\nginx\\logs\\access.log --file C:\\nginx\\logs\\error.log

    # 3. Traiter le contenu existant puis sortir (utile en cron / tâche planifiée)
    python ingest_nginx_logs.py --file C:\\nginx\\logs\\access.log --once

Codes de sortie
---------------

=== ==========================================================================
0   collecte terminée sans incident
1   échec réseau ou 5xx persistant (aucune réponse exploitable)
2   erreur d'usage ou de configuration (arguments, clé API absente, 401/403)
3   le serveur a refusé au moins un événement (400/409/422 ou ``rejected > 0``)
130 arrêt propre demandé par Ctrl-C (les lots en attente ont été vidés)
=== ==========================================================================
"""

from __future__ import annotations
import contextlib as _contextlib
import sys as _sys
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

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import signal
import sys
import threading
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

__all__ = [
    "main",
    "LogTailer",
    "IngestClient",
    "TailStateStore",
    "build_event",
    "redact_secrets",
    "pseudonymize_ip",
]

# --------------------------------------------------------------------------------------
# Constantes du contrat (§3.1, §4.3)
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

#: Valeurs admises de ``severity_hint`` (contrat §3.1) ; ``None`` est également accepté.
SEVERITY_HINTS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Contrainte §4.3 : au plus 500 événements par lot.
MAX_BATCH_SIZE = 500

#: Contrainte §3.1 : ``payload`` ≤ 32 Kio sérialisé.
MAX_PAYLOAD_BYTES = 32 * 1024

#: Défaut de l'API locale (§4.1, §9).
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

#: Taille de lot par défaut demandée par ce collecteur.
DEFAULT_BATCH_SIZE = 100

DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRY_AFTER_MAX = 60.0
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_FLUSH_INTERVAL = 5.0
DEFAULT_QUEUE_SIZE = 5000
DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_STATE_FILE = "ingest-nginx-state.json"

USER_AGENT = "thotsecure-nginx-ingest/0.1.0 (+https://github.com/thotsecure/thot-secure)"

REDACTED = "[REDACTED]"
REDACTED_JWT = "[REDACTED_JWT]"

#: Champs d'adresse IP pseudonymisés (mêmes noms que ``thotsecure_sdk.helpers.DEFAULT_IP_FIELDS``).
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

#: Balise posée sur chaque événement pour tracer le chemin d'ingestion.
INGEST_MARKER = "python-ingest-nginx-logs/0.1.0"


# --------------------------------------------------------------------------------------
# Configuration : variables d'environnement
# --------------------------------------------------------------------------------------


def env_first(*names: str, default: str | None = None) -> str | None:
    """Première variable d'environnement définie et non vide parmi *names*.

    Les noms « Thot Secure » (``THOT_SECURE_*``) sont prioritaires, avec repli sur les noms
    historiques ``THOT_*`` (contrat §9) : les deux conventionnements restent acceptés.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


# --------------------------------------------------------------------------------------
# Masquage des secrets — reproduction de ``thotsecure_sdk.helpers.redact_secrets``
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
    """``True`` si le nom de champ désigne une donnée à masquer (*fail-closed*)."""
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

    Le résultat reste sérialisable en JSON et la récursion est bornée (profondeur 32, protection
    contre les structures cycliques).
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

    Alignement avec ``sdks/python/thotsecure_sdk/helpers.py::pseudonymize_ip`` : le message HMAC est
    la forme **canonique** de l'adresse (``str(ipaddress.ip_address(...))``, ou l'adresse réseau si
    l'entrée est un CIDR), la clé est le sel encodé en UTF-8, et le pseudonyme est
    ``prefix + hexdigest()[:32]``. Une IP donnée produit donc exactement le même pseudonyme
    qu'elle soit ingérée par le SDK, par la CLI, par le pont n8n ou par ce collecteur.

    Pourquoi pseudonymiser : une adresse IP est une donnée à caractère personnel (RGPD art. 4.1).
    Le sel est un secret d'organisation : sans lui, un attaquant disposant du pseudonyme peut
    tester par dictionnaire l'espace IPv4 pour retrouver l'adresse d'origine.

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


#: Candidats d'adresses IP dans un texte libre. Les motifs sont volontairement **larges** :
#: la validation finale passe par ``ipaddress.ip_address()``, ce qui évite de transformer par
#: erreur un horodatage (``09:00:00``) ou un nom d'hôte en pseudonyme.
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def scrub_ips_in_text(text: str, salt: str) -> str:
    """Pseudonymise les adresses IP présentes dans un **texte libre**.

    Pourquoi c'est indispensable : la ligne de journal brute est conservée dans
    ``payload.message``. Sans ce nettoyage, l'adresse IP pseudonymisée dans ``labels.src_ip``
    resterait **en clair** dans le message — la pseudonymisation serait alors purement
    cosmétique et la donnée personnelle (RGPD art. 4.1) toujours ingérée.

    Les candidats sont validés par ``ipaddress.ip_address()`` avant remplacement : un
    horodatage, un nom d'hôte ou une version ne sont jamais touchés. Le pseudonyme produit est
    **identique** à celui des champs ``src_ip``/``client_ip`` (même HMAC, même sel), ce qui
    préserve la corrélation entre les deux représentations.
    """
    if not salt or not text:
        return text

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        try:
            return pseudonymize_ip(candidate, salt)
        except ValueError:
            return candidate

    # IPv6 d'abord (une forme ``::ffff:203.0.113.9`` doit être traitée d'un bloc), puis IPv4.
    scrubbed = _IPV6_CANDIDATE_RE.sub(replace, text)
    return _IPV4_CANDIDATE_RE.sub(replace, scrubbed)


def pseudonymize_ips_in_text(data: Any, salt: str, *, depth: int = 0) -> Any:
    """Applique :func:`scrub_ips_in_text` à toutes les chaînes d'une structure."""
    if depth > 32 or not salt:
        return data
    if isinstance(data, Mapping):
        return {key: pseudonymize_ips_in_text(value, salt, depth=depth + 1) for key, value in data.items()}
    if isinstance(data, list):
        return [pseudonymize_ips_in_text(item, salt, depth=depth + 1) for item in data]
    if isinstance(data, str):
        return scrub_ips_in_text(data, salt)
    return data


# --------------------------------------------------------------------------------------
# Horodatage et sévérité
# --------------------------------------------------------------------------------------

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


def _to_iso_utc(moment: datetime) -> str:
    """ISO 8601 UTC en millisecondes, au format du contrat (``…Z``)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_iso() -> str:
    """Horodatage courant au format du contrat §3.1."""
    return _to_iso_utc(datetime.now(timezone.utc))


def parse_clf_timestamp(value: str) -> datetime | None:
    """Analyse ``14/Feb/2026:10:00:00 +0100`` sans dépendre de la locale (Windows FR inclus)."""
    match = re.match(
        r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$", value.strip()
    )
    if not match:
        return None
    day, month_name, year, hour, minute, second, offset = match.groups()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    tzinfo = timezone.utc
    if offset:
        sign = 1 if offset[0] == "+" else -1
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        tzinfo = timezone(sign * delta)
    try:
        return datetime(int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=tzinfo)
    except ValueError:
        return None


def parse_error_timestamp(value: str) -> datetime | None:
    """Analyse ``2026/02/14 10:00:00`` (format de ``nginx error.log``), en UTC par défaut."""
    match = re.match(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})$", value.strip())
    if not match:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_timestamp(value: Any, *, default_year: int | None = None) -> datetime | None:
    """Analyse un horodatage hétérogène (ISO 8601, epoch s/ms, CLF, syslog) → ``datetime`` UTC.

    Retourne ``None`` si la valeur est absente ou non reconnue : l'appelant retombe alors sur
    l'heure de réception, sans jamais faire échouer la collecte.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
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

    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        parsed = None
    if parsed is not None:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    clf = parse_clf_timestamp(text)
    if clf is not None:
        return clf
    error_ts = parse_error_timestamp(text)
    if error_ts is not None:
        return error_ts

    match = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", text)
    if match:
        month_name, day, hour, minute, second = match.groups()
        month = _MONTHS.get(month_name.lower())
        if month is None:
            return None
        reference = datetime.now(timezone.utc)
        try:
            candidate = datetime(
                default_year or reference.year,
                month,
                int(day),
                int(hour),
                int(minute),
                int(second),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
        if candidate > reference + timedelta(days=2):
            candidate = candidate.replace(year=candidate.year - 1)
        return candidate
    return None


def severity_hint_for_status(status: int | None) -> str | None:
    """``severity_hint`` déduit du code HTTP (même barème que le SDK)."""
    if status is None:
        return None
    if 500 <= status < 600:
        return "medium"
    if 400 <= status < 500:
        return "low"
    if 200 <= status < 400:
        return "info"
    return None


#: Niveaux de ``nginx error.log`` → ``severity_hint`` du contrat §3.1.
_ERROR_LEVELS = {
    "emerg": "critical",
    "alert": "critical",
    "crit": "critical",
    "error": "high",
    "warn": "medium",
    "notice": "low",
    "info": "info",
    "debug": "info",
}


# --------------------------------------------------------------------------------------
# Analyse des lignes Nginx
# --------------------------------------------------------------------------------------

#: Log « combined » Nginx/Apache : hôte virtuel optionnel, puis la ligne standard.
#: Identique à ``thotsecure_sdk.helpers._COMBINED_RE`` afin que les deux collecteurs produisent
#: des événements strictement comparables.
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

#: Ligne de ``nginx error.log`` : ``2026/02/14 10:00:00 [error] 1234#1234: *5 message``.
_ERROR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>[a-z]+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s*"
    r"(?:\*(?P<conn>\d+)\s+)?"
    r"(?P<message>.*)$"
)


def serialized_size(value: Any) -> int:
    """Taille en octets de la forme JSON compacte de *value* (UTF-8)."""
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def truncate_payload(
    payload: Mapping[str, Any],
    *,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    keep_keys: Sequence[str] = ("status", "method", "path"),
) -> tuple[dict[str, Any], bool]:
    """Ramène *payload* sous *max_bytes* et indique si une troncature a eu lieu.

    Stratégie : troncature des chaînes les plus longues, puis retrait des clés les plus
    volumineuses (en préservant *keep_keys*), puis remplacement par un marqueur. Le contrat §3.1
    demande de renseigner ``raw_ref`` lorsque le payload est tronqué.
    """
    result: dict[str, Any] = dict(payload)
    if serialized_size(result) <= max_bytes:
        return result, False

    for _ in range(64):
        if serialized_size(result) <= max_bytes:
            break
        candidates = [
            (len(str(value)), key)
            for key, value in result.items()
            if isinstance(value, str) and len(value) > 256
        ]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result[key] = str(result[key])[:256] + "…[tronqué]"

    for _ in range(64):
        if serialized_size(result) <= max_bytes:
            break
        candidates = [
            (serialized_size({key: value}), key) for key, value in result.items() if key not in keep_keys
        ]
        if not candidates:
            break
        candidates.sort(reverse=True)
        _, key = candidates[0]
        result.pop(key, None)

    if serialized_size(result) > max_bytes:
        result = {"_truncated": True, "_original_keys": sorted(str(key) for key in payload)}
    return result, True


class LineUnparsed(ValueError):
    """Ligne de journal inutilisable (même comme message brut)."""


def parse_access_line(line: str) -> dict[str, Any] | None:
    """Analyse une ligne ``access.log`` (formats ``combined``/``common``) → champs bruts."""
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


def parse_error_line(line: str) -> dict[str, Any] | None:
    """Analyse une ligne de ``nginx error.log`` → champs bruts."""
    match = _ERROR_RE.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    return {
        "ts": groups.get("ts"),
        "level": groups.get("level"),
        "pid": int(groups["pid"]) if groups.get("pid") else None,
        "tid": int(groups["tid"]) if groups.get("tid") else None,
        "connection": int(groups["conn"]) if groups.get("conn") else None,
        "message": groups.get("message"),
    }


def _as_scalar(value: Any) -> Any:
    """Ramène une valeur à un scalaire JSON (exigence « ``labels`` plat » du §3.1)."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def build_event(
    line: str,
    *,
    tenant_id: str,
    source_name: str = "nginx-access",
    source_type: str = "log_tail",
    source_host: str | None = None,
    ip_salt: str | None = None,
    keep_ip_prefix: bool = False,
    redact: bool = True,
) -> dict[str, Any]:
    """Transforme une ligne de journal Nginx en ``Event`` conforme au §3.1.

    Étapes : analyse → construction ``labels``/``payload`` → **redaction** → **pseudonymisation
    des IP** → validation des invariants du contrat. L'ordre compte : masquer d'abord garantit
    qu'un secret ne peut pas être « protégé » par une pseudonymisation.

    Lève :class:`LineUnparsed` si la ligne ne peut pas devenir un événement exploitable.
    """
    if not tenant_id:
        raise LineUnparsed("tenant_id manquant (contrat §1 : tout objet porte un tenant_id)")

    text = line.rstrip("\r\n")
    if not text.strip():
        raise LineUnparsed("ligne vide")

    record: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    labels: dict[str, Any] = {}
    kind = "log.line"
    severity: str | None = None
    host = source_host

    access = parse_access_line(text)
    if access is not None:
        kind = "http.request"
        status = access.get("status")
        severity = severity_hint_for_status(status if isinstance(status, int) else None)
        host = source_host or access.get("vhost")
        if access.get("method"):
            labels["method"] = _as_scalar(access["method"])
        if access.get("path"):
            labels["path"] = _as_scalar(access["path"])
        if access.get("protocol"):
            labels["protocol"] = _as_scalar(access["protocol"])
        if access.get("query"):
            labels["query"] = _as_scalar(access["query"])
        if access.get("vhost"):
            labels["host"] = _as_scalar(access["vhost"])
        if access.get("user"):
            labels["user"] = _as_scalar(access["user"])
        if access.get("src_ip"):
            labels["src_ip"] = str(access["src_ip"])
        if isinstance(status, int):
            payload["status"] = status
        if access.get("bytes") is not None:
            payload["bytes"] = access["bytes"]
        if access.get("user_agent"):
            payload["user_agent"] = _as_scalar(access["user_agent"])
        if access.get("referer"):
            payload["referer"] = _as_scalar(access["referer"])
        payload["message"] = text
        record = access
    else:
        error = parse_error_line(text)
        if error is not None:
            kind = "log.line"
            severity = _ERROR_LEVELS.get(str(error.get("level") or "").lower())
            if error.get("level"):
                labels["level"] = _as_scalar(error["level"])
            if error.get("connection") is not None:
                labels["connection"] = error["connection"]
            if error.get("pid") is not None:
                payload["pid"] = error["pid"]
            payload["message"] = _as_scalar(error.get("message") or text)
            record = error
        else:
            # Ligne non reconnue : on conserve au moins la ligne brute, sans la perdre.
            labels["unparsed"] = True
            payload["message"] = text
            record = {}

    parsed_ts = parse_timestamp(record.get("ts"))
    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "schema_version": "1",
        "tenant_id": tenant_id,
        "ts": _to_iso_utc(parsed_ts) if parsed_ts is not None else now_iso(),
        "kind": kind if kind in KINDS else "log.line",
        "source": {
            "type": source_type,
            "name": source_name,
            "host": str(host or source_name),
        },
        "severity_hint": severity,
        "labels": labels,
        "payload": payload,
        "raw_ref": None,
    }

    event["payload"], truncated = truncate_payload(event["payload"])
    if truncated:
        event["raw_ref"] = "truncated:payload>%d" % MAX_PAYLOAD_BYTES

    if redact:
        event = redact_secrets(event)
    if ip_salt:
        # 1) champs identifiés comme des adresses (labels.src_ip, client_ip, remote_addr…)
        event = pseudonymize_ip_fields(event, ip_salt, fields=DEFAULT_IP_FIELDS, keep_prefix=keep_ip_prefix)
        # 2) adresses restées en clair dans le texte libre (message de la ligne brute) : sans
        #    cette passe, la pseudonymisation serait contournée par ``payload.message``.
        event["labels"] = pseudonymize_ips_in_text(event["labels"], ip_salt)
        event["payload"] = pseudonymize_ips_in_text(event["payload"], ip_salt)

    # Balise de traçabilité : quel collecteur a produit l'événement.
    event["payload"]["ingest"] = INGEST_MARKER
    validate_event(event)
    return event


def validate_event(event: Mapping[str, Any]) -> None:
    """Vérifie les invariants du contrat §3.1 (lève ``ValueError`` avec un motif explicite)."""
    if event.get("schema_version") != "1":
        raise ValueError('schema_version doit valoir "1" (contrat §3.1)')
    if not event.get("tenant_id"):
        raise ValueError("tenant_id manquant (contrat §1)")
    if event.get("kind") not in KINDS:
        raise ValueError("kind invalide : %r (énumération §3.1)" % (event.get("kind"),))
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
            raise ValueError("labels.%s n'est pas scalaire : « labels » doit rester plat (§3.1)" % key)
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload doit être un objet")
    if serialized_size(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload sérialisé > %d octets (contrat §3.1)" % MAX_PAYLOAD_BYTES)
    if parse_timestamp(event.get("ts")) is None:
        raise ValueError("ts illisible : %r" % (event.get("ts"),))


# --------------------------------------------------------------------------------------
# Suivi de fichier : reprise sur redémarrage, rotation, troncature
# --------------------------------------------------------------------------------------


class TailStateStore:
    """Fichier d'état JSON mémorisant l'offset de lecture de chaque journal suivi.

    Format ::

        {"version": 1, "files": {"C:\\\\nginx\\\\logs\\\\access.log": {"offset": 12345,
         "inode": 281474976712345, "size": 12345, "updated_at": "…Z"}}}

    L'écriture est **atomique** (fichier temporaire puis ``os.replace``) : une coupure de courant
    ne peut pas laisser un état à moitié écrit, ce qui provoquerait un rejeu ou une perte.
    """

    VERSION = 1

    def __init__(self, path: str | None) -> None:
        self.path = str(path) if path else None
        self._lock = threading.Lock()
        self._files: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Charge l'état existant ; un état illisible est ignoré (on repart de zéro)."""
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            return
        files = document.get("files") if isinstance(document, Mapping) else None
        if isinstance(files, Mapping):
            for key, value in files.items():
                if isinstance(value, Mapping):
                    self._files[str(key)] = dict(value)

    def get(self, path: str) -> dict[str, Any]:
        """État mémorisé pour *path* (dictionnaire vide s'il est inconnu)."""
        with self._lock:
            return dict(self._files.get(str(path), {}))

    def update(self, path: str, **fields: Any) -> None:
        """Mémorise les champs d'état de *path* (en mémoire)."""
        with self._lock:
            entry = dict(self._files.get(str(path), {}))
            entry.update(fields)
            entry["updated_at"] = now_iso()
            self._files[str(path)] = entry

    def save(self) -> None:
        """Écrit l'état sur disque de façon atomique (no-op sans ``--state-file``)."""
        if not self.path:
            return
        with self._lock:
            document = {"version": self.VERSION, "files": dict(self._files), "updated_at": now_iso()}
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        temporary = "%s.tmp" % self.path
        try:
            os.makedirs(directory, exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:  # l'état est un confort, pas une condition de fonctionnement
            print(
                "[ingest-nginx] état non enregistré (%s) : la reprise après redémarrage repartira "
                "du début du fichier" % exc,
                file=sys.stderr,
                flush=True,
            )

    def snapshot(self) -> dict[str, Any]:
        """Copie du contenu de l'état (pour le récapitulatif final)."""
        with self._lock:
            return {key: dict(value) for key, value in self._files.items()}


class LogTailer:
    """Lecture incrémentale d'un fichier journal, avec reprise et détection de rotation.

    Le lecteur produit des couples ``(ligne, offset)`` où *offset* est la position du **prochain**
    octet à lire : l'appelant peut donc persister l'avancement après chaque ligne traitée.

    * **Reprise** : au démarrage, la lecture reprend à l'offset mémorisé (``--from-start`` force
      la relecture complète depuis le début du fichier).
    * **Rotation** : si l'inode change (``logrotate`` a renommé le fichier et Nginx en a créé un
      nouveau), la lecture repart à l'offset 0 du nouveau fichier.
    * **Troncature** : si la taille devient inférieure à l'offset mémorisé, la lecture repart à 0.
    * **Ligne partielle** : en mode suivi, une dernière ligne sans ``\\n`` n'est **pas** émise :
      elle est encore en cours d'écriture et sera lue au prochain tour.
    """

    def __init__(
        self,
        path: str,
        state: TailStateStore,
        *,
        follow: bool = True,
        from_start: bool = False,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        encoding: str = "utf-8",
    ) -> None:
        self.path = str(path)
        self.state = state
        self.follow = follow
        self.from_start = from_start
        self.poll_interval = poll_interval
        self.encoding = encoding

    # -- interne -----------------------------------------------------------------------

    def stored_offset(self) -> int:
        """Offset de reprise mémorisé pour ce journal (0 si inconnu)."""
        entry = self.state.get(self.path)
        try:
            offset = int(entry.get("offset") or 0)
        except (TypeError, ValueError):
            offset = 0
        return max(0, offset)

    def _open(self, offset: int) -> tuple[Any, int | None]:
        """Ouvre le fichier à *offset* et retourne ``(handle, inode)``."""
        handle = open(self.path, "rb")
        inode: int | None = None
        try:
            stat = os.stat(self.path)
            inode = int(stat.st_ino) or None
            if offset and offset <= stat.st_size:
                handle.seek(offset)
            elif offset:
                # Fichier plus court que l'offset mémorisé : tronqué ou remplacé.
                offset = 0
        except OSError:
            pass
        return handle, inode

    # -- API publique ------------------------------------------------------------------

    def lines(self, stop_event: threading.Event) -> Iterator[tuple[str, int]]:
        """Itère sur les lignes nouvelles, en bloquant tant que ``stop_event`` n'est pas posé."""
        offset = 0 if self.from_start else self.stored_offset()
        handle, inode = self._open(offset)
        try:
            while True:
                position = handle.tell()
                raw = handle.readline()
                if raw:
                    next_offset = handle.tell()
                    if not raw.endswith(b"\n") and self.follow:
                        # Ligne partielle : le writer n'a pas encore terminé son écriture.
                        handle.seek(position)
                        if stop_event.wait(self.poll_interval):
                            return
                        continue
                    yield raw.decode(self.encoding, errors="replace"), next_offset
                    self.state.update(self.path, offset=next_offset)
                    continue

                # Fin de fichier atteinte.
                try:
                    stat = os.stat(self.path)
                except OSError:
                    stat = None

                if stat is not None:
                    current_inode = int(stat.st_ino) or None
                    if inode is not None and current_inode is not None and current_inode != inode:
                        # Rotation : le fichier suivi a été renommé, un nouveau a été créé.
                        handle.close()
                        self.state.update(self.path, offset=0, rotated_at=now_iso())
                        handle, inode = self._open(0)
                        continue
                    if stat.st_size < handle.tell():
                        # Troncature (copie de log, vide-fichier manuel…).
                        handle.close()
                        self.state.update(self.path, offset=0, truncated_at=now_iso())
                        handle, inode = self._open(0)
                        continue

                if not self.follow:
                    return
                if stop_event.wait(self.poll_interval):
                    return
        finally:
            try:
                handle.close()
            except OSError:
                pass


# --------------------------------------------------------------------------------------
# Transport HTTP (urllib, stdlib uniquement)
# --------------------------------------------------------------------------------------


class TransportError(RuntimeError):
    """Échec réseau, DNS, TLS ou délai d'attente dépassé (aucune réponse HTTP exploitable)."""


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


def safe_url(url: str) -> str:
    """URL expurgée de tout identifiant utilisateur (``http://user:pass@hôte``)."""
    return re.sub(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@", r"\g<scheme>", url)


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

    Lève :class:`TransportError` si aucune réponse HTTP n'a pu être obtenue. La clé API passe
    uniquement dans l'en-tête ``X-API-Key`` (jamais dans l'URL, qui finit dans les journaux de
    proxy) et n'apparaît dans aucun message d'erreur.
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
        raise TransportError("échec de la requête vers %s : %s" % (safe_url(url), exc)) from exc


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
# Client d'ingestion avec contre-pression
# --------------------------------------------------------------------------------------


class BatchResult:
    """Résultat d'un envoi de lot (vocabulaire fermé, utilisé par le récapitulatif)."""

    __slots__ = ("outcome", "http_status", "accepted", "rejected", "findings", "message", "attempts")

    def __init__(
        self,
        outcome: str,
        *,
        http_status: int | None = None,
        accepted: int = 0,
        rejected: int = 0,
        findings: int = 0,
        message: str = "",
        attempts: int = 1,
    ) -> None:
        #: ``accepted`` | ``rejected`` | ``auth`` | ``transport`` | ``exhausted`` | ``unexpected``
        #: | ``interrupted``
        self.outcome = outcome
        self.http_status = http_status
        self.accepted = accepted
        self.rejected = rejected
        #: Nombre de findings créés par le serveur pour ce lot (§4.3, champ ``findings``).
        self.findings = findings
        self.message = message
        self.attempts = attempts

    def __repr__(self) -> str:  # pragma: no cover - aide au débogage
        return "BatchResult(outcome=%r, http_status=%r, accepted=%d, rejected=%d, findings=%d)" % (
            self.outcome,
            self.http_status,
            self.accepted,
            self.rejected,
            self.findings,
        )


class IngestClient:
    """Envoie les lots vers ``POST /api/v1/events`` (§4.3) en gérant la contre-pression.

    Politique de reprise, alignée sur le pont n8n du dépôt :

    * ``202`` → lot accepté ;
    * ``429`` → attente imposée par ``Retry-After`` (bornée par ``--retry-after-max``), puis
      nouvelle tentative ; c'est la **contre-pression** demandée par le serveur ;
    * ``5xx`` et erreurs réseau → repli exponentiel borné, ``--max-attempts`` tentatives ;
    * ``401``/``403`` → arrêt immédiat (clé absente, révoquée, rôle sans ``write:events``) ;
    * ``400``/``409``/``422`` → lot refusé (données invalides) ;
    * autre statut → anomalie non prévue.

    La clé API n'est jamais journalisée ni incluse dans un message d'erreur.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        retry_after_max: float = DEFAULT_RETRY_AFTER_MAX,
        backoff_base: float = 1.0,
        log: Any = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.endpoint = "%s/api/v1/events" % base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = float(timeout)
        self.max_attempts = max(1, int(max_attempts))
        self.retry_after_max = float(retry_after_max)
        self.backoff_base = float(backoff_base)
        self._log = log or (lambda _message: None)
        self._stop = stop_event or threading.Event()

    def __repr__(self) -> str:  # pragma: no cover - jamais de secret dans le repr
        return "IngestClient(endpoint=%r, api_key=%s)" % (
            safe_url(self.endpoint),
            "'***'" if self.api_key else "None",
        )

    def _wait(self, seconds: float) -> bool:
        """Attente interruptible ; retourne ``True`` si un arrêt a été demandé pendant l'attente."""
        if seconds <= 0:
            return self._stop.is_set()
        return self._stop.wait(seconds)

    def post_batch(self, events: Sequence[Mapping[str, Any]]) -> BatchResult:
        """Envoie un lot (≤ 500 événements, §4.3) et retourne un :class:`BatchResult`."""
        if not events:
            return BatchResult("accepted", accepted=0)
        if len(events) > MAX_BATCH_SIZE:
            raise ValueError("un lot ne peut pas dépasser %d événements (contrat §4.3)" % MAX_BATCH_SIZE)

        body = {"events": list(events)}
        delay = self.backoff_base
        attempt = 0
        last_message = ""

        while True:
            attempt += 1
            try:
                status, payload, raw_text, headers = post_json(
                    self.endpoint, body, api_key=self.api_key, timeout=self.timeout
                )
            except TransportError as exc:
                last_message = str(exc)
                if attempt >= self.max_attempts:
                    self._log("lot : échec réseau après %d tentative(s) — %s" % (attempt, last_message))
                    return BatchResult("transport", message=last_message, attempts=attempt)
                wait = min(delay, self.retry_after_max)
                self._log("lot : %s — nouvelle tentative dans %.1f s" % (last_message, wait))
                if self._wait(wait):
                    return BatchResult("interrupted", message="arrêt demandé", attempts=attempt)
                delay = min(delay * 2, self.retry_after_max)
                continue

            if status in (200, 202):
                accepted = payload.get("accepted") if isinstance(payload, Mapping) else None
                rejected = payload.get("rejected") if isinstance(payload, Mapping) else None
                created = payload.get("findings") if isinstance(payload, Mapping) else None
                return BatchResult(
                    "accepted" if not rejected else "rejected",
                    http_status=status,
                    accepted=int(accepted or 0),
                    rejected=int(rejected or 0),
                    findings=len(created) if isinstance(created, list) else 0,
                    attempts=attempt,
                )

            if status == 429 or 500 <= status < 600:
                last_message = "HTTP %d — %s" % (status, error_summary(payload, raw_text))
                if attempt >= self.max_attempts:
                    self._log("lot : %s (tentatives épuisées)" % last_message)
                    return BatchResult(
                        "exhausted", http_status=status, message=last_message, attempts=attempt
                    )
                wait = parse_retry_after(get_header(headers, "Retry-After"))
                if wait is None:
                    wait = 1.0 if status == 429 else delay
                wait = max(0.0, min(wait, self.retry_after_max))
                self._log(
                    "lot : contre-pression HTTP %d — nouvelle tentative dans %.1f s (Retry-After honoré)"
                    % (status, wait)
                )
                if self._wait(wait):
                    return BatchResult("interrupted", message="arrêt demandé", attempts=attempt)
                delay = min(delay * 2, self.retry_after_max)
                continue

            if status in (401, 403):
                last_message = (
                    "HTTP %d : clé API absente, invalide, révoquée ou rôle sans capacité "
                    "« write:events » (contrat §4.2) — %s" % (status, error_summary(payload, raw_text))
                )
                self._log(last_message)
                return BatchResult("auth", http_status=status, message=last_message, attempts=attempt)

            if status in (400, 409, 422):
                last_message = "HTTP %d : lot refusé — %s" % (status, error_summary(payload, raw_text))
                self._log(last_message)
                return BatchResult("rejected", http_status=status, message=last_message, attempts=attempt)

            last_message = "HTTP %d : réponse inattendue — %s" % (status, error_summary(payload, raw_text))
            self._log(last_message)
            return BatchResult("unexpected", http_status=status, message=last_message, attempts=attempt)


# --------------------------------------------------------------------------------------
# Compteurs
# --------------------------------------------------------------------------------------


class Stats:
    """Compteurs de collecte, protégés par un verrou (plusieurs lecteurs en parallèle)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.lines_read = 0
        self.lines_unparsed = 0
        self.events_built = 0
        self.events_accepted = 0
        self.events_rejected = 0
        self.batches_sent = 0
        self.retries = 0
        self.batches_failed = 0
        self.findings = 0
        self.redacted_lines = 0
        self.pseudonymized = 0
        self.started_at = time.time()

    def add(self, **fields: int) -> None:
        """Incrémente plusieurs compteurs de façon atomique."""
        with self._lock:
            for key, value in fields.items():
                setattr(self, key, getattr(self, key) + value)

    def summary(self) -> dict[str, Any]:
        """Instantané des compteurs (pour le récapitulatif final)."""
        with self._lock:
            elapsed = max(0.0, time.time() - self.started_at)
            return {
                "lines_read": self.lines_read,
                "lines_unparsed": self.lines_unparsed,
                "events_built": self.events_built,
                "events_accepted": self.events_accepted,
                "events_rejected": self.events_rejected,
                "batches_sent": self.batches_sent,
                "retries": self.retries,
                "batches_failed": self.batches_failed,
                "findings": self.findings,
                "elapsed_s": round(elapsed, 3),
                "events_per_s": round(self.events_built / elapsed, 2) if elapsed > 0 else 0.0,
            }


# --------------------------------------------------------------------------------------
# Boucles d'exécution
# --------------------------------------------------------------------------------------


class _StopIngest(Exception):
    """Arrêt immédiat de la boucle d'ingestion (clé refusée, arrêt demandé pendant une reprise)."""


def write_dry_run_batch(events: Sequence[Mapping[str, Any]], *, pretty: bool, stream: Any) -> None:
    """Imprime un lot d'événements en mode ``--dry-run`` (aucune requête émise)."""
    if pretty:
        payload: Any = events[0] if len(events) == 1 else {"events": list(events)}
        stream.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        stream.write("\n")
        return
    for event in events:
        stream.write(json.dumps(event, ensure_ascii=False, default=str))
        stream.write("\n")
    stream.flush()


def run_follow(
    *,
    tailers: Sequence[LogTailer],
    client: IngestClient | None,
    state: TailStateStore,
    args: argparse.Namespace,
    stats: Stats,
    log: Any,
) -> int:
    """Boucle producteur/consommateur avec file **bornée** (contre-pression) et lots de 100.

    Un fil de lecture par fichier alimente une file bornée ; le fil principal constitue les lots,
    les envoie et gère les reprises. Si la file est pleine, les lecteurs **bloquent** : le serveur
    lent ralentit la lecture au lieu de faire grossir la mémoire sans limite.
    """
    stop_event = threading.Event()
    work: queue.Queue[Any] = queue.Queue(maxsize=max(1, args.queue_size))
    readers: list[threading.Thread] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        del signum
        if not stop_event.is_set():
            log("arrêt demandé : vidage des lots en attente puis sortie…")
            stop_event.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        candidate = getattr(signal, signal_name, None)
        if candidate is not None:
            try:
                signal.signal(candidate, handle_signal)
            except (ValueError, OSError):  # plateforme sans ce signal
                pass

    def reader_loop(tailer: LogTailer) -> None:
        """Lit une source et pousse les événements dans la file bornée."""
        try:
            for line, next_offset in tailer.lines(stop_event):
                stats.add(lines_read=1)
                if not _take_budget():
                    log("limite --max-events atteinte : arrêt de la collecte")
                    stop_event.set()
                    return
                try:
                    event = build_event(
                        line,
                        tenant_id=args.tenant_id,
                        source_name=Path(tailer.path).name or "nginx",
                        source_type="log_tail",
                        source_host=args.source_host,
                        ip_salt=args.ip_salt,
                        keep_ip_prefix=args.keep_ip_prefix,
                    )
                except (LineUnparsed, ValueError) as exc:
                    stats.add(lines_unparsed=1)
                    log("ligne ignorée dans %s : %s" % (Path(tailer.path).name, exc))
                    state.update(tailer.path, offset=next_offset)
                    continue
                if args.ip_salt:
                    stats.add(pseudonymized=1)
                stats.add(events_built=1)
                # L'événement est mis en file AVANT de mémoriser l'offset : si le processus est
                # tué entre les deux, l'événement sera relu au redémarrage (au pire un doublon,
                # jamais une perte — sémantique « au moins une fois »).
                if not _put(event):
                    return
                state.update(tailer.path, offset=next_offset)
        except Exception as exc:  # noqa: BLE001 - un lecteur ne doit jamais tuer le collecteur
            log("lecteur %s interrompu : %s" % (Path(tailer.path).name, exc))
        finally:
            try:
                work.put(_SENTINEL, timeout=5.0)
            except queue.Full:
                pass

    def _put(event: dict[str, Any]) -> bool:
        """Met un événement en file en bloquant si elle est pleine ; ``False`` si arrêt demandé."""
        while not stop_event.is_set():
            try:
                work.put((event,), timeout=0.5)
                return True
            except queue.Full:
                continue
        return False

    # Budget partagé par tous les lecteurs (``--max-events``), protégé par un verrou.
    budget = {"left": int(args.max_events or 0)}
    budget_lock = threading.Lock()

    def _take_budget() -> bool:
        """Consomme une unité de budget ; ``True`` tant que la limite n'est pas atteinte."""
        with budget_lock:
            if budget["left"] <= 0 and args.max_events:
                return False
            if args.max_events:
                budget["left"] -= 1
            return True

    for tailer in tailers:
        log("suivi de %s (reprise à l'offset %d)" % (tailer.path, tailer.stored_offset()))
        thread = threading.Thread(target=reader_loop, args=(tailer,), name="reader:%s" % tailer.path, daemon=True)
        thread.start()
        readers.append(thread)

    pending: list[dict[str, Any]] = []
    finished = 0
    exit_code = 0
    last_flush = time.time()
    last_save = 0.0

    def flush(reason: str) -> None:
        nonlocal pending, exit_code
        if not pending:
            return
        batch, pending = pending, []
        if client is None:  # dry-run
            write_dry_run_batch(batch, pretty=args.pretty, stream=sys.stdout)
            stats.add(batches_sent=1)
            log("lot de %d événement(s) affiché (%s)" % (len(batch), reason))
            return
        result = client.post_batch(batch)
        stats.add(batches_sent=1)
        stats.add(retries=max(0, result.attempts - 1))
        stats.add(events_accepted=result.accepted, events_rejected=result.rejected, findings=result.findings)
        if result.outcome == "accepted":
            log("lot de %d événement(s) accepté (%s)" % (len(batch), reason))
        elif result.outcome == "rejected":
            log("lot de %d événement(s) refusé par le serveur (%s)" % (len(batch), reason))
            exit_code = max(exit_code, 3)
            stats.add(batches_failed=1)
        elif result.outcome == "auth":
            exit_code = max(exit_code, 2)
            stats.add(batches_failed=1)
            stop_event.set()
        elif result.outcome == "interrupted":
            stats.add(batches_failed=1)
        else:
            log("lot de %d événement(s) perdu : %s" % (len(batch), result.message))
            exit_code = max(exit_code, 1)
            stats.add(batches_failed=1)

    try:
        while True:
            try:
                item = work.get(timeout=0.5)
            except queue.Empty:
                item = _EMPTY

            if item is not _EMPTY:
                if item is _SENTINEL:
                    finished += 1
                else:
                    pending.append(item[0])

            if len(pending) >= args.batch_size:
                flush("lot plein")
                last_flush = time.time()
                continue

            if pending and time.time() - last_flush >= args.flush_interval:
                flush("délai écoulé")
                last_flush = time.time()
                continue

            if not pending and time.time() - last_save >= max(2.0, args.flush_interval):
                # Persistance périodique de l'état : borne la relecture après un arrêt brutal.
                state.save()
                last_save = time.time()

            if finished >= len(tailers) and work.empty():
                break

        flush("arrêt")
    except KeyboardInterrupt:
        log("Ctrl-C : vidage des lots en attente…")
        stop_event.set()
        flush("Ctrl-C")
        exit_code = max(exit_code, 130)
    finally:
        stop_event.set()
        for thread in readers:
            thread.join(timeout=2.0)
        try:
            while True:
                leftover = work.get_nowait()
                if leftover is _SENTINEL or leftover is _EMPTY:
                    continue
                pending.append(leftover[0])
        except queue.Empty:
            pass
        flush("file résiduelle")
        state.save()

    return exit_code


def run_once(
    *,
    tailers: Sequence[LogTailer],
    client: IngestClient | None,
    state: TailStateStore,
    args: argparse.Namespace,
    stats: Stats,
    log: Any,
) -> int:
    """Lit chaque journal jusqu'à sa fin courante, par lots, puis s'arrête.

    Mode recommandé pour les tâches planifiées et pour les tests hors ligne (``--dry-run
    --once``) : aucune boucle infinie, aucune thread, comportement déterministe.
    """
    exit_code = 0
    pending: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal pending, exit_code
        if not pending:
            return
        batch, pending = pending, []
        if client is None:
            write_dry_run_batch(batch, pretty=args.pretty, stream=sys.stdout)
        else:
            result = client.post_batch(batch)
            stats.add(retries=max(0, result.attempts - 1))
            if result.outcome == "accepted":
                log("lot de %d événement(s) accepté" % len(batch))
            elif result.outcome == "rejected":
                log("lot de %d événement(s) refusé : %s" % (len(batch), result.message))
                exit_code = max(exit_code, 3)
                stats.add(batches_failed=1)
            elif result.outcome == "auth":
                exit_code = max(exit_code, 2)
                stats.add(batches_failed=1)
                raise _StopIngest("clé API refusée")
            elif result.outcome == "interrupted":
                stats.add(batches_failed=1)
                raise _StopIngest("arrêt demandé pendant une reprise")
            else:
                log("lot de %d événement(s) perdu : %s" % (len(batch), result.message))
                exit_code = max(exit_code, 1)
                stats.add(batches_failed=1)
            stats.add(events_accepted=result.accepted, events_rejected=result.rejected, findings=result.findings)
        stats.add(batches_sent=1)

    stop_event = threading.Event()
    try:
        for tailer in tailers:
            log("lecture de %s (reprise à l'offset %d)" % (tailer.path, tailer.stored_offset()))
            for line, next_offset in tailer.lines(stop_event):
                stats.add(lines_read=1)
                try:
                    event = build_event(
                        line,
                        tenant_id=args.tenant_id,
                        source_name=Path(tailer.path).name or "nginx",
                        source_type="log_tail",
                        source_host=args.source_host,
                        ip_salt=args.ip_salt,
                        keep_ip_prefix=args.keep_ip_prefix,
                    )
                except (LineUnparsed, ValueError) as exc:
                    stats.add(lines_unparsed=1)
                    log("ligne ignorée dans %s : %s" % (Path(tailer.path).name, exc))
                    state.update(tailer.path, offset=next_offset)
                    continue
                if args.ip_salt:
                    stats.add(pseudonymized=1)
                stats.add(events_built=1)
                state.update(tailer.path, offset=next_offset)
                pending.append(event)
                if len(pending) >= args.batch_size:
                    flush()
                if args.max_events and stats.events_built >= args.max_events:
                    log("limite --max-events atteinte (%d événement(s))" % args.max_events)
                    flush()
                    state.save()
                    return exit_code
        flush()
    except _StopIngest as exc:
        log("collecte interrompue : %s" % exc)
    except KeyboardInterrupt:
        log("interruption : vidage du lot en cours…")
        try:
            flush()
        except _StopIngest:
            log("lot en cours abandonné")
        exit_code = max(exit_code, 130)
    state.save()
    return exit_code


_SENTINEL = object()
_EMPTY = object()


# --------------------------------------------------------------------------------------
# Interface en ligne de commande
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (``--help`` documente chaque option)."""
    parser = argparse.ArgumentParser(
        prog="ingest_nginx_logs.py",
        description=(
            "Suit un ou plusieurs journaux Nginx, normalise chaque ligne en Event (§3.1), masque "
            "les secrets, pseudonymise les IP (RGPD) et ingère par lots vers POST /api/v1/events."
        ),
        epilog=(
            "Codes de sortie : 0 succès, 1 échec réseau/5xx, 2 usage ou configuration, "
            "3 événement refusé, 130 Ctrl-C."
        ),
    )
    parser.add_argument(
        "--file",
        dest="files",
        action="append",
        required=True,
        metavar="JOURNAL",
        help="journal à suivre (répétable) : access.log, error.log…",
    )
    parser.add_argument(
        "--url",
        default=env_first("THOT_SECURE_URL", "THOT_URL", default=DEFAULT_BASE_URL),
        help="base de l'API (défaut : $env:THOT_SECURE_URL, sinon $env:THOT_URL, sinon %s)"
        % DEFAULT_BASE_URL,
    )
    parser.add_argument(
        "--api-key",
        default=env_first("THOT_SECURE_API_KEY", "THOT_API_KEY"),
        help="clé ao_… (défaut : $env:THOT_SECURE_API_KEY) ; préférez l'environnement",
    )
    parser.add_argument(
        "--tenant-id",
        default=env_first("THOT_SECURE_TENANT_ID", "THOT_TENANT_ID", default="default"),
        help="tenant_id porté par les événements (le serveur le force depuis la clé, §4.3)",
    )
    parser.add_argument(
        "--ip-salt",
        default=env_first("THOT_SECURE_IP_SALT", "THOT_IP_SALT"),
        help="sel de pseudonymisation des IP (défaut : $env:THOT_SECURE_IP_SALT) ; "
        "sans sel, les IP restent en clair — à éviter (RGPD)",
    )
    parser.add_argument(
        "--keep-ip-prefix",
        action="store_true",
        help="conserve le réseau (/24 IPv4, /64 IPv6) à côté du pseudonyme",
    )
    parser.add_argument("--source-host", help="force source.host (sinon l'hôte virtuel de la ligne)")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="événements par lot (1 à %d, contrat §4.3 ; défaut %d)" % (MAX_BATCH_SIZE, DEFAULT_BATCH_SIZE),
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=DEFAULT_QUEUE_SIZE,
        help="taille de la file bornée entre lecteurs et émetteur (défaut %d) : "
        "c'est le levier de contre-pression mémoire" % DEFAULT_QUEUE_SIZE,
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=DEFAULT_FLUSH_INTERVAL,
        help="délai maximal avant envoi d'un lot incomplet, en secondes (défaut %s)" % DEFAULT_FLUSH_INTERVAL,
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="période d'interrogation du fichier en mode suivi, en secondes (défaut %s)"
        % DEFAULT_POLL_INTERVAL,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="délai d'attente par requête HTTP, en secondes (défaut %s)" % DEFAULT_TIMEOUT,
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help="nombre total de tentatives par lot sur 429/5xx/réseau (défaut %d)" % DEFAULT_MAX_ATTEMPTS,
    )
    parser.add_argument(
        "--retry-after-max",
        type=float,
        default=DEFAULT_RETRY_AFTER_MAX,
        help="plafond d'attente imposé par Retry-After, en secondes (défaut %s)" % DEFAULT_RETRY_AFTER_MAX,
    )
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help="fichier d'état JSON mémorisant l'offset de chaque journal (défaut %s) ; "
        "ignoré en --dry-run" % DEFAULT_STATE_FILE,
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="ignore l'état et relit chaque journal depuis le début",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="lit le contenu existant puis sort (mode tâche planifiée / test hors ligne)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="borne le nombre d'événements construits (0 = illimité)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="n'émet AUCUNE requête et n'écrit AUCUN état : imprime les événements construits",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="en --dry-run : sortie JSON indentée par lot au lieu d'un JSON compact par ligne",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="journalise la progression détaillée")
    parser.add_argument("--version", action="version", version="thotsecure-nginx-ingest 0.1.0")
    return parser


def _stderr(message: str) -> None:
    """Journalise sur stderr : stdout reste réservé aux données (JSON en ``--dry-run``)."""
    print("[ingest-nginx] %s" % message, file=sys.stderr, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée CLI. Retourne le code de sortie (voir la docstring du module)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.batch_size < 1 or args.batch_size > MAX_BATCH_SIZE:
        _stderr("--batch-size doit être compris entre 1 et %d (contrat §4.3)" % MAX_BATCH_SIZE)
        return 2
    if args.queue_size < 1:
        _stderr("--queue-size doit être au moins 1")
        return 2
    if args.flush_interval <= 0 or args.poll_interval <= 0:
        _stderr("--flush-interval et --poll-interval doivent être strictement positifs")
        return 2
    if args.timeout <= 0:
        _stderr("--timeout doit être strictement positif")
        return 2
    if args.max_attempts < 1:
        _stderr("--max-attempts doit être au moins 1")
        return 2

    missing = [path for path in args.files if not os.path.exists(path)]
    if missing:
        _stderr("journal introuvable : %s" % ", ".join(missing))
        return 2

    log = _stderr if args.verbose else (lambda _message: None)

    if not args.ip_salt:
        _stderr(
            "avertissement : aucune pseudonymisation d'IP (THOT_SECURE_IP_SALT non défini) — "
            "les adresses IP seront transmises en clair. Une adresse IP est une donnée à caractère "
            "personnel (RGPD art. 4.1) : définissez un sel d'organisation."
        )
    else:
        log("pseudonymisation des IP active (HMAC-SHA256 + sel, format ip-<32 hex>)")

    if not args.dry_run and not args.api_key:
        _stderr(
            "clé API absente : définissez THOT_SECURE_API_KEY (ou THOT_API_KEY), ou utilisez "
            "--dry-run pour construire et afficher les événements sans rien envoyer."
        )
        return 2

    # En --dry-run, l'état n'est jamais écrit : le mode hors ligne ne touche à rien.
    state = TailStateStore(None if args.dry_run else args.state_file)
    stats = Stats()
    stop_event = threading.Event()

    client: IngestClient | None = None
    if not args.dry_run:
        client = IngestClient(
            str(args.url),
            args.api_key,
            timeout=args.timeout,
            max_attempts=args.max_attempts,
            retry_after_max=args.retry_after_max,
            log=log,
            stop_event=stop_event,
        )
        log("ingestion vers %s (lots de %d)" % (safe_url(client.endpoint), args.batch_size))
    else:
        _stderr(
            "--dry-run : aucune requête ne sera émise et aucun fichier d'état ne sera écrit ; "
            "les événements construits sont imprimés sur stdout."
        )

    tailers = [
        LogTailer(
            path,
            state,
            follow=not args.once,
            from_start=args.from_start,
            poll_interval=args.poll_interval,
        )
        for path in args.files
    ]

    try:
        if args.once:
            code = run_once(
                tailers=tailers, client=client, state=state, args=args, stats=stats, log=log
            )
        else:
            code = run_follow(
                tailers=tailers, client=client, state=state, args=args, stats=stats, log=log
            )
    except KeyboardInterrupt:
        _stderr("Ctrl-C : arrêt propre.")
        code = 130
        state.save()

    summary = stats.summary()
    _stderr(
        "récapitulatif : %d ligne(s) lue(s), %d non reconnue(s), %d événement(s) construit(s), "
        "%d accepté(s), %d rejeté(s), %d finding(s) créé(s), %d lot(s) envoyé(s), %d reprise(s), "
        "%d lot(s) en échec, %.2f événement(s)/s"
        % (
            summary["lines_read"],
            summary["lines_unparsed"],
            summary["events_built"],
            summary["events_accepted"],
            summary["events_rejected"],
            summary["findings"],
            summary["batches_sent"],
            summary["retries"],
            summary["batches_failed"],
            summary["events_per_s"],
        )
    )
    if not args.dry_run:
        offsets = {path: entry.get("offset") for path, entry in state.snapshot().items()}
        if offsets:
            _stderr(
                "offsets mémorisés (reprise au prochain démarrage) : %s"
                % json.dumps(offsets, ensure_ascii=False)
            )
    return code


if __name__ == "__main__":
    sys.exit(main())
