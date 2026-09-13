#!/usr/bin/env python3
"""Forward d'audit et de findings Thot Secure vers un SIEM (CEF / JSONL, rotation, curseur).

Ce script est le **pont sortant** du produit : il exporte le journal d'audit chaîné et les
findings vers un SIEM (Splunk, QRadar, Elastic, Sentinel…) sous forme de fichiers tournants que
les agents habituels du SIEM savent lire — sans inventer de connecteur exotique.

Ce qu'il fait
-------------

1. **Export de l'audit** via ``GET /api/v1/audit/export?format=cef|jsonl`` (§4.7) : le serveur
   produit nativement le CEF, ce script ne le reformate pas (un CEF réécrit est un CEF dont on a
   perdu la garantie).
2. **Export des findings** via ``GET /api/v1/findings`` (§4.4) puis conversion locale en CEF ou
   JSONL : le contrat ne fournit l'export CEF que pour l'audit, les findings sont donc convertis
   ici (règle → ``signature_id``, sévérité → échelle CEF 0-10, cible → ``src``).
3. **Écriture dans un fichier avec rotation** (``--max-bytes``, ``--backups``) : le SIEM lit un
   fichier borné, jamais un fichier qui grossit sans fin.
4. **Reprise sur erreur par curseur** : l'export est demandé avec ``since`` et ``until`` ; le
   curseur n'est avancé **qu'après** écriture réussie. Une coupure réseau, un disque plein ou un
   redémarrage ne créent donc pas de trou : le cycle suivant repart exactement du dernier point
   confirmé. Un léger recouvrement (``--overlap-seconds``) absorbe les dérives d'horloge entre le
   serveur et le forwarder.
5. **Vérification périodique de la chaîne d'audit** via ``GET /api/v1/audit/verify`` (§4.7). Si la
   chaîne est **rompue**, c'est un **incident majeur** : le journal a été altéré ou tronqué, donc
   tout ce qui est transmis ensuite n'est plus attestable. Le script écrit un marqueur d'incident,
   journalise en CRITICAL, et **s'arrête** (code de sortie 3). ``--continue-on-chain-break``
   permet de poursuivre en connaissance de cause — option déconseillée, à documenter.

Pourquoi la vérification de chaîne est le cœur du dispositif
------------------------------------------------------------

Un SIEM qui ingère un audit non vérifié ingère une **affirmation non prouvée** : n'importe qui
ayant accès à la base pourrait supprimer la trace d'une action, et le SIEM la relayerait comme un
fait. ``hash = sha256(seq|ts|tenant|actor|role|action|target|before|after|prev_hash)`` rend la
falsification détectable : ``valid: false`` signifie que la continuité est rompue à ``broken_at``.
À partir de là, la bonne réaction n'est pas de « continuer à forwarder », c'est de **figer les
preuves** (sauvegardes, disque), d'ouvrir un incident, et de restaurer une copie saine.

Aucune capacité offensive
-------------------------

Le script lit et écrit des fichiers, et n'appelle que l'API de l'instance configurée : aucun scan,
aucune exploitation, aucune action sur les cibles mentionnées dans les journaux.

Exemples
--------

::

    # 1. Un cycle unique (test, tâche planifiée), CEF + JSONL, dossier dédié
    python forward_cef.py --once --format both --out-dir C:\\siem\\spool --sources audit,findings

    # 2. Service continu : un cycle par minute, vérification de chaîne toutes les 5 minutes
    python forward_cef.py --interval 60 --verify-interval 300 --format cef

    # 3. Repartir de zéro (ignorer le curseur) pour un rattrapage historique borné
    python forward_cef.py --once --from-start --since 2026-02-01T00:00:00Z --until 2026-02-14T00:00:00Z

Codes de sortie
---------------

=== ==========================================================================
0   cycles terminés sans incident (ou boucle interrompue proprement par Ctrl-C)
1   erreur d'exécution : réseau, I/O disque, réponse inexploitable
2   usage ou configuration : argument invalide, clé absente, 401/403
3   CHAÎNE D'AUDIT ROMPUE : incident majeur, transmission arrêtée
130 Ctrl-C : arrêt propre, curseur sauvegardé
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
import json
import os
import re
import sys
import time
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

__all__ = [
    "main",
    "RotatingFile",
    "ForwardState",
    "Dedupe",
    "audit_to_cef",
    "finding_to_cef",
    "cef_escape_value",
]

# --------------------------------------------------------------------------------------
# Constantes du contrat (§3.2, §3.5, §4.4, §4.7)
# --------------------------------------------------------------------------------------

DEFAULT_BASE_URL = "http://127.0.0.1:8080"

DEFAULT_TIMEOUT = 30.0
DEFAULT_INTERVAL = 60.0
DEFAULT_VERIFY_INTERVAL = 300.0
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_BACKUPS = 5
DEFAULT_OVERLAP_SECONDS = 5
DEFAULT_PAGE_LIMIT = 200
DEFAULT_MAX_PAGES = 200
DEFAULT_STATE_FILE = "siem-forwarder-state.json"
DEFAULT_DEDUPE_SIZE = 20000

USER_AGENT = "thotsecure-siem-forwarder/0.1.0 (+https://github.com/thotsecure/thot-secure)"

#: Produit et version annoncés dans l'en-tête CEF (``CEF:0|<vendor>|<product>|<version>|…``).
CEF_VENDOR = "Thot Secure"
CEF_PRODUCT = "thotsecure"
CEF_VERSION = "0.1.0"

#: Échelle CEF 0-10 (plus grand = plus grave) associée aux sévérités du contrat.
CEF_SEVERITY = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 0,
}

#: Statuts de finding qui ne doivent pas réveiller un analyste (§3.2).
BENIGN_STATUSES = frozenset({"acked", "closed", "suppressed"})


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


def env_first(*names: str, default: str | None = None) -> str | None:
    """Première variable d'environnement définie et non vide parmi *names*.

    Les noms ``THOT_SECURE_*`` sont prioritaires ; les noms ``THOT_*`` du contrat §9 restent
    acceptés.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def safe_url(url: str) -> str:
    """URL expurgée de tout identifiant utilisateur (``http://user:pass@hôte``)."""
    return re.sub(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@", r"\g<scheme>", url)


def now_iso() -> str:
    """Horodatage courant au format du contrat §3.1 (UTC, millisecondes)."""
    return _to_iso_utc(datetime.now(timezone.utc))


def _to_iso_utc(moment: datetime) -> str:
    """ISO 8601 UTC en millisecondes, suffixe ``Z``."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_iso(value: str) -> datetime | None:
    """Analyse un horodatage ISO 8601 (suffixe ``Z`` accepté) → ``datetime`` UTC."""
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def shift_iso(value: str, seconds: float) -> str:
    """Décale un horodatage ISO de *seconds* (négatif pour reculer), borné à maintenant."""
    moment = parse_iso(value) or datetime.now(timezone.utc)
    return _to_iso_utc(moment + timedelta(seconds=seconds))


def log(message: str, *, level: str = "INFO") -> None:
    """Journalise sur stderr, horodaté et nivelé (stdout reste libre pour l'automatisation).

    ``CRITICAL`` est utilisé pour l'incident majeur : une chaîne d'audit rompue doit être
    impossible à manquer dans le journal du service.
    """
    print("[siem-forwarder] %s %s %s" % (now_iso(), level, message), file=sys.stderr, flush=True)


# --------------------------------------------------------------------------------------
# Transport HTTP (bibliothèque standard)
# --------------------------------------------------------------------------------------


class TransportError(RuntimeError):
    """Échec réseau, DNS, TLS ou délai dépassé (aucune réponse HTTP exploitable)."""


class ApiError(RuntimeError):
    """Réponse HTTP d'erreur normalisée (§4.6)."""

    def __init__(self, status: int, code: str, message: str, details: Any = None) -> None:
        super().__init__("HTTP %d · %s · %s" % (status, code or "error", message))
        self.status = int(status)
        self.code = code
        self.message = message
        self.details = details


def error_summary(payload: Any, raw_text: str = "") -> tuple[str, str, Any]:
    """Extrait ``(code, message, details)`` d'une erreur normalisée du contrat §4.6."""
    if isinstance(payload, Mapping):
        error = payload.get("error")
        if isinstance(error, Mapping):
            return (
                str(error.get("code") or ""),
                str(error.get("message") or ""),
                error.get("details"),
            )
    text = raw_text.strip()[:300]
    return "", text or "(corps vide)", None


def http_request(
    method: str,
    url: str,
    *,
    api_key: str | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    """Requête HTTP → ``(statut, corps brut)``.

    Le corps est retourné **en octets** : l'export CEF/JSONL est recopié tel quel dans le fichier
    du SIEM, sans réencodage susceptible d'altérer un caractère. La clé API passe uniquement dans
    l'en-tête ``X-API-Key`` et n'apparaît dans aucun message.
    """
    if params:
        query = urlparse.urlencode({key: value for key, value in params.items() if value is not None})
        if query:
            url = "%s%s%s" % (url, "&" if "?" in url else "?", query)

    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    if api_key:
        headers["X-API-Key"] = api_key

    request = urlrequest.Request(url, headers=headers, method=method.upper())
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urlerror.HTTPError as exc:
        return exc.code, exc.read()
    except (urlerror.URLError, OSError, ValueError) as exc:
        raise TransportError("échec de la requête %s %s : %s" % (method, safe_url(url), exc)) from exc


def decode_json(raw: bytes) -> Any:
    """Décode un corps JSON, ou retourne ``None`` s'il n'est pas du JSON."""
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------------------
# Écriture tournante et état (curseurs)
# --------------------------------------------------------------------------------------


class RotatingFile:
    """Fichier en ajout, avec rotation par taille et nombre de sauvegardes borné.

    Rotation : ``audit-cef.log`` → ``audit-cef.log.1`` → ``audit-cef.log.2`` … Les sauvegardes
    au-delà de *backups* sont supprimées. La rotation est effectuée **avant** une écriture qui
    ferait dépasser le seuil, jamais au milieu d'une ligne : un agent de collecte ne lit donc
    jamais un enregistrement tronqué.
    """

    def __init__(self, path: str, *, max_bytes: int = DEFAULT_MAX_BYTES, backups: int = DEFAULT_BACKUPS) -> None:
        self.path = Path(path)
        self.max_bytes = max(1024, int(max_bytes))
        self.backups = max(1, int(backups))
        self.bytes_written = 0
        self.records_written = 0
        self.rotations = 0

    def _size(self) -> int:
        """Taille courante du fichier (0 s'il n'existe pas encore)."""
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def rotate(self) -> None:
        """Effectue la rotation si le seuil est atteint."""
        if self._size() < self.max_bytes:
            return
        oldest = Path("%s.%d" % (self.path, self.backups))
        try:
            if oldest.exists():
                oldest.unlink()
        except OSError as exc:
            log("rotation : suppression de %s impossible (%s)" % (oldest, exc), level="WARN")
        for index in range(self.backups - 1, 0, -1):
            source = Path("%s.%d" % (self.path, index))
            target = Path("%s.%d" % (self.path, index + 1))
            if source.exists():
                try:
                    os.replace(source, target)
                except OSError as exc:
                    log("rotation : %s → %s impossible (%s)" % (source, target, exc), level="WARN")
        try:
            if self.path.exists():
                os.replace(self.path, Path("%s.1" % self.path))
                self.rotations += 1
                log("rotation : %s → %s.1 (seuil %d octets)" % (self.path, self.path, self.max_bytes))
        except OSError as exc:
            log("rotation impossible (%s) : écriture en ajout malgré tout" % exc, level="WARN")

    def write_bytes(self, payload: bytes) -> int:
        """Écrit *payload* après rotation ; retourne le nombre d'octets écrits.

        L'écriture est suivie d'un ``flush`` + ``fsync`` : le SIEM qui lit le fichier ne doit pas
        pouvoir lire un tampon non vidé si le processus s'arrête juste après.
        """
        if not payload:
            return 0
        self.rotate()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "ab") as handle:
                handle.write(payload)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
        except OSError as exc:
            raise OSError("écriture dans %s impossible : %s" % (self.path, exc)) from exc
        self.bytes_written += len(payload)
        return len(payload)

    def write_lines(self, lines: Iterable[str]) -> int:
        """Écrit des lignes (une par enregistrement) et retourne le nombre d'enregistrements."""
        buffer = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
        if not buffer:
            return 0
        self.write_bytes(buffer.encode("utf-8"))
        count = buffer.count("\n")
        self.records_written += count
        return count


class ForwardState:
    """État persistant du forwarder : un curseur ``since`` par source (audit, findings).

    L'écriture est atomique (fichier temporaire + ``os.replace``) : un arrêt brutal ne peut pas
    laisser un curseur à moitié écrit, ce qui provoquerait un trou définitif dans le SIEM.
    """

    VERSION = 1

    def __init__(self, path: str | None) -> None:
        self.path = str(path) if path else None
        self._data: dict[str, Any] = {"audit_since": None, "findings_since": None}

    def load(self) -> None:
        """Charge l'état existant ; un état illisible est ignoré (on repart du début demandé)."""
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            return
        if isinstance(document, Mapping):
            for key in ("audit_since", "findings_since"):
                value = document.get(key)
                if isinstance(value, str) and value:
                    self._data[key] = value
            log(
                "état repris depuis %s (audit_since=%s, findings_since=%s)"
                % (self.path, self._data["audit_since"], self._data["findings_since"])
            )

    def get(self, key: str) -> str | None:
        """Curseur courant pour *key* (``audit_since`` ou ``findings_since``)."""
        value = self._data.get(key)
        return str(value) if value else None

    def set(self, key: str, value: str) -> None:
        """Met à jour un curseur **en mémoire** (l'écriture disque est explicite)."""
        self._data[key] = value

    def save(self) -> None:
        """Écrit l'état sur disque de façon atomique."""
        if not self.path:
            return
        document = {
            "version": self.VERSION,
            "audit_since": self._data.get("audit_since"),
            "findings_since": self._data.get("findings_since"),
            "updated_at": now_iso(),
        }
        temporary = "%s.tmp" % self.path
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            log("curseur non sauvegardé (%s) : le prochain cycle rejouera la fenêtre" % exc, level="WARN")

    def snapshot(self) -> dict[str, Any]:
        """Copie des curseurs (récapitulatif, tests)."""
        return dict(self._data)


class Dedupe:
    """Mémoire bornée des enregistrements déjà transmis (le recouvrement rejoue des lignes).

    Un SIEM préfère **un doublon à un trou** ; on les évite tout de même lorsqu'ils sont certains :
    le recouvrement (``--overlap-seconds``) et deux cycles qui se chevauchent produisent des
    enregistrements identiques. La mémoire est un simple ensemble borné (FIFO), donc sans
    consommation croissante.
    """

    def __init__(self, size: int = DEFAULT_DEDUPE_SIZE) -> None:
        self.size = max(1, int(size))
        self._seen: set[str] = set()
        self._order: deque[str] = deque()
        self.duplicates = 0

    def is_new(self, key: str) -> bool:
        """``True`` si *key* n'a jamais été vue (et l'enregistre) ; ``False`` si c'est un doublon."""
        if not key:
            return True
        if key in self._seen:
            self.duplicates += 1
            return False
        self._seen.add(key)
        self._order.append(key)
        while len(self._order) > self.size:
            self._seen.discard(self._order.popleft())
        return True


# --------------------------------------------------------------------------------------
# CEF : formatage et échappement
# --------------------------------------------------------------------------------------


def cef_escape_header(value: Any) -> str:
    """Échappe un champ d'en-tête CEF : ``\\`` → ``\\\\`` et ``|`` → ``\\|``."""
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|")


def cef_escape_value(value: Any) -> str:
    """Échappe une valeur d'extension CEF : ``\\``, ``=`` et retours à la ligne.

    Un ``=`` non échappé dans une valeur casse l'analyse côté SIEM : la valeur serait coupée et le
    reste interprété comme une nouvelle clé.
    """
    text = str(value if value is not None else "")
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", " ")
        .replace("\n", "\\n")
    )


def cef_line(
    *,
    signature_id: str,
    name: str,
    severity: int,
    extension: Mapping[str, Any],
    device_event_class_id: str = "",
) -> str:
    """Construit une ligne CEF complète (``CEF:0|…|``)."""
    parts = [
        "CEF:0",
        cef_escape_header(CEF_VENDOR),
        cef_escape_header(CEF_PRODUCT),
        cef_escape_header(CEF_VERSION),
        cef_escape_header(signature_id or "UNKNOWN"),
        cef_escape_header(name or signature_id or "Evenement Thot Secure"),
        str(int(severity)),
    ]
    header = "|".join(parts)
    if device_event_class_id:
        header = "%s|%s" % (header, cef_escape_header(device_event_class_id))
    extension_text = " ".join(
        "%s=%s" % (key, cef_escape_value(value))
        for key, value in extension.items()
        if value is not None and value != ""
    )
    return "%s|%s" % (header, extension_text)


def timestamp_to_cef_millis(value: Any) -> str:
    """Convertit un horodatage ISO en millisecondes epoch (clé CEF ``rt``)."""
    moment = parse_iso(str(value)) if value else None
    if moment is None:
        moment = datetime.now(timezone.utc)
    return str(int(moment.timestamp() * 1000))


def audit_to_cef(record: Mapping[str, Any]) -> str:
    """Convertit un ``AuditRecord`` (§3.5) en ligne CEF.

    Utilisé uniquement lorsque le serveur ne sait pas produire l'export CEF : la voie normale est
    ``GET /api/v1/audit/export?format=cef``, dont le flux est recopié sans réécriture.
    """
    target = record.get("target") if isinstance(record.get("target"), Mapping) else {}
    before = record.get("before")
    after = record.get("after")
    status_after = after.get("status") if isinstance(after, Mapping) else None
    status_before = before.get("status") if isinstance(before, Mapping) else None
    action = str(record.get("action") or "audit")

    extension: dict[str, Any] = {
        "rt": timestamp_to_cef_millis(record.get("ts")),
        "externalId": record.get("seq"),
        "suser": record.get("actor"),
        "act": action,
        "outcome": "success" if status_after in ("approved", "succeeded", "acked", "closed") else status_after,
        "msg": "%s par %s (%s) sur %s %s"
        % (
            action,
            record.get("actor") or "inconnu",
            record.get("actor_role") or "?",
            target.get("type") or "?",
            target.get("id") or "?",
        ),
        "cs1Label": "tenantId",
        "cs1": record.get("tenant_id"),
        "cs2Label": "actorRole",
        "cs2": record.get("actor_role"),
        "cs3Label": "targetType",
        "cs3": target.get("type"),
        "cs4Label": "targetId",
        "cs4": target.get("id"),
        "cn1Label": "auditSeq",
        "cn1": record.get("seq"),
        "cs5Label": "statusBefore",
        "cs5": status_before,
        "cs6Label": "statusAfter",
        "cs6": status_after,
        "cs7Label": "recordHash",
        "cs7": record.get("hash"),
        "cs8Label": "prevHash",
        "cs8": record.get("prev_hash"),
    }
    # Sérialise before/after en JSON compact : le SIEM conserve la transition exacte.
    if isinstance(before, Mapping) and before:
        extension["cs9Label"] = "before"
        extension["cs9"] = json.dumps(before, ensure_ascii=False, sort_keys=True)
    if isinstance(after, Mapping) and after:
        extension["cs10Label"] = "after"
        extension["cs10"] = json.dumps(after, ensure_ascii=False, sort_keys=True)

    return cef_line(
        signature_id="audit.%s" % action,
        name="Audit Thot Secure — %s" % action,
        severity=CEF_SEVERITY["medium"] if status_after == "failed" else CEF_SEVERITY["info"],
        extension=extension,
        device_event_class_id="audit",
    )


def finding_to_cef(finding: Mapping[str, Any]) -> str:
    """Convertit un ``Finding`` (§3.2) en ligne CEF (``signature_id`` = ``rule_id``)."""
    labels = finding.get("labels") if isinstance(finding.get("labels"), Mapping) else {}
    severity = str(finding.get("severity") or "info").strip().lower()
    status = str(finding.get("status") or "open").strip().lower()
    score = CEF_SEVERITY.get(severity, CEF_SEVERITY["info"])
    if status in BENIGN_STATUSES:
        # Un finding acquitté n'est pas une urgence : il reste transmis, mais en information.
        score = min(score, CEF_SEVERITY["low"])

    extension: dict[str, Any] = {
        "rt": timestamp_to_cef_millis(finding.get("last_seen") or finding.get("first_seen")),
        "start": timestamp_to_cef_millis(finding.get("first_seen")),
        "end": timestamp_to_cef_millis(finding.get("last_seen")),
        "externalId": finding.get("finding_id"),
        "src": labels.get("src_ip") or labels.get("source_ip") or labels.get("client_ip"),
        "dst": labels.get("host") or labels.get("dst_ip"),
        "requestUrl": labels.get("path"),
        "suser": labels.get("user"),
        "msg": finding.get("title") or finding.get("rule_id"),
        "cs1Label": "tenantId",
        "cs1": finding.get("tenant_id"),
        "cs2Label": "ruleId",
        "cs2": finding.get("rule_id"),
        "cs3Label": "status",
        "cs3": status,
        "cs4Label": "tags",
        "cs4": ",".join(str(tag) for tag in (finding.get("tags") or [])),
        "cs5Label": "mitre",
        "cs5": ",".join(str(item) for item in (finding.get("mitre") or [])),
        "cn1Label": "riskScore",
        "cn1": finding.get("risk_score"),
        "cn2Label": "confidence",
        "cn2": finding.get("confidence"),
        "cn3Label": "eventCount",
        "cn3": finding.get("count"),
    }
    description = finding.get("description")
    if description:
        extension["cs6Label"] = "description"
        extension["cs6"] = str(description)
    remediation = finding.get("remediation")
    if remediation:
        extension["cs7Label"] = "remediation"
        extension["cs7"] = str(remediation)

    return cef_line(
        signature_id=str(finding.get("rule_id") or "FINDING"),
        name=str(finding.get("rule_name") or finding.get("title") or "Finding Thot Secure"),
        severity=score,
        extension=extension,
        device_event_class_id="finding",
    )


# --------------------------------------------------------------------------------------
# Client d'API (lecture seule)
# --------------------------------------------------------------------------------------


class SiemClient:
    """Accès en lecture aux routes d'export, de findings et de vérification d'audit."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = float(timeout)
        #: Point d'injection pour les tests : ``transport(method, url, api_key=…, params=…, timeout=…, accept=…)``.
        self._transport = transport or http_request

    def _get(self, path: str, params: Mapping[str, Any] | None = None, *, accept: str = "application/json") -> tuple[int, bytes]:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        return self._transport("GET", url, api_key=self.api_key, params=params, timeout=self.timeout, accept=accept)

    def _json_or_raise(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        """GET JSON ; lève :class:`ApiError` sur statut ≥ 400, :class:`TransportError` sur panne réseau."""
        status, raw = self._get(path, params)
        payload = decode_json(raw)
        if status >= 400:
            code, message, details = error_summary(payload, raw.decode("utf-8", errors="replace")[:400])
            raise ApiError(status, code, message, details)
        return payload

    def verify_audit(self) -> dict[str, Any]:
        """``GET /api/v1/audit/verify`` (capacité ``read:audit``) → ``{"valid","records","broken_at"}``.

        En cas de ``5xx`` le résultat est marqué ``indeterminate`` : un contrôle impossible à
        exécuter n'est ni un succès ni une chaîne rompue.
        """
        try:
            payload = self._json_or_raise("/api/v1/audit/verify")
        except ApiError as exc:
            if exc.status >= 500:
                return {"valid": None, "indeterminate": True, "error": str(exc)}
            raise
        if isinstance(payload, Mapping):
            return dict(payload)
        return {"valid": None, "indeterminate": True, "error": "réponse non exploitable"}

    def export_audit(self, *, format: str, since: str | None, until: str | None) -> bytes:
        """``GET /api/v1/audit/export?format=cef|jsonl`` (§4.7) → corps brut (octets)."""
        accept = "text/plain" if format == "cef" else "application/x-ndjson"
        status, raw = self._get(
            "/api/v1/audit/export", {"format": format, "since": since, "until": until}, accept=accept
        )
        if status >= 400:
            payload = decode_json(raw)
            code, message, details = error_summary(payload, raw.decode("utf-8", errors="replace")[:400])
            raise ApiError(status, code, message, details)
        return raw

    def list_audit(self, *, since: str | None, until: str | None, limit: int = DEFAULT_PAGE_LIMIT, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict[str, Any]]:
        """``GET /api/v1/audit`` paginé — utilisé seulement si l'export CEF/JSONL est indisponible."""
        return self._paginate(
            "/api/v1/audit",
            {"since": since, "until": until, "limit": limit},
            max_pages=max_pages,
        )

    def list_findings(
        self,
        *,
        since: str | None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> list[dict[str, Any]]:
        """``GET /api/v1/findings`` paginé (§4.4), filtré par ``since``."""
        return self._paginate(
            "/api/v1/findings",
            {"since": since, "sort": "last_seen", "limit": limit},
            max_pages=max_pages,
        )

    def _paginate(self, path: str, params: Mapping[str, Any], *, max_pages: int) -> list[dict[str, Any]]:
        """Parcourt une route paginée en suivant ``next_cursor``."""
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _page in range(1, max(1, max_pages) + 1):
            current = dict(params)
            if cursor:
                current["cursor"] = cursor
            payload = self._json_or_raise(path, current)
            page_items, next_cursor = _split_page(payload)
            items.extend(page_items)
            if not next_cursor or next_cursor in seen:
                return items
            seen.add(next_cursor)
            cursor = next_cursor
        log("limite de %d pages atteinte sur %s : résultat possiblement partiel" % (max_pages, path), level="WARN")
        return items


def _split_page(payload: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Extrait ``(items, next_cursor)`` d'une page du contrat."""
    if isinstance(payload, Mapping):
        items = payload.get("items")
        next_cursor = payload.get("next_cursor") or payload.get("cursor")
        found = [dict(item) for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []
        return found, str(next_cursor) if next_cursor else None
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, Mapping)], None
    return [], None


# --------------------------------------------------------------------------------------
# Cycle de transfert
# --------------------------------------------------------------------------------------


class Forwarder:
    """Orchestre un cycle : vérification de chaîne, export, écriture, avance du curseur."""

    def __init__(self, args: argparse.Namespace, client: SiemClient) -> None:
        self.args = args
        self.client = client
        self.state = ForwardState(None if args.no_state else args.state_file)
        self.state.load()
        if args.from_start:
            self.state = ForwardState(None)
            log("--from-start : curseurs ignorés, reprise depuis le début demandé")
        self.dedupe = Dedupe(args.dedupe_size)
        self.outputs: dict[str, RotatingFile] = {}
        self.last_verify_at = 0.0
        self.verify_result: dict[str, Any] = {}
        self.chain_broken = False

    # -- sorties -----------------------------------------------------------------------

    def output(self, name: str, suffix: str) -> RotatingFile:
        """Retourne (et crée à la demande) le fichier tournant d'une source."""
        key = "%s-%s" % (name, suffix)
        if key not in self.outputs:
            path = Path(self.args.out_dir) / ("%s.%s" % (name, suffix))
            self.outputs[key] = RotatingFile(
                str(path), max_bytes=self.args.max_bytes, backups=self.args.backups
            )
        return self.outputs[key]

    def formats(self) -> list[str]:
        """Formats à produire d'après ``--format``."""
        if self.args.format == "both":
            return ["cef", "jsonl"]
        return [self.args.format]

    # -- vérification de la chaîne d'audit ---------------------------------------------

    def verify_chain(self, *, force: bool = False) -> bool:
        """Vérifie la chaîne d'audit si l'intervalle est écoulé ; ``False`` si elle est rompue.

        Une chaîne rompue déclenche : journalisation **CRITICAL**, écriture d'un marqueur
        d'incident dans le dossier de sortie (que le SIEM peut collecter), et arrêt de la
        transmission. Continuer à transmettre un audit non vérifiable reviendrait à blanchir des
        données dont l'intégrité n'est plus attestable.
        """
        now = time.monotonic()
        if not force and self.args.verify_interval > 0 and now - self.last_verify_at < self.args.verify_interval:
            return not self.chain_broken
        self.last_verify_at = now

        try:
            result = self.client.verify_audit()
        except ApiError as exc:
            if exc.status in (401, 403):
                raise
            log("vérification de chaîne impossible (%s) : poursuite, nouvelle tentative au prochain cycle" % exc, level="WARN")
            return not self.chain_broken
        except TransportError as exc:
            log("vérification de chaîne injoignable (%s) : poursuite" % exc, level="WARN")
            return not self.chain_broken

        self.verify_result = result
        valid = result.get("valid")
        if valid is True:
            log("chaîne d'audit vérifiée : %s enregistrement(s) intègre(s)" % result.get("records"))
            return True
        if valid is None:
            log(
                "chaîne d'audit INDÉTERMINÉE : %s"
                % (result.get("error") or "le serveur n'a pas tranché"),
                level="WARN",
            )
            return not self.chain_broken

        # valid is False → incident majeur
        self.chain_broken = True
        broken_at = result.get("broken_at")
        log(
            "INCIDENT MAJEUR — CHAÎNE D'AUDIT ROMPUE à l'enregistrement %s : le journal a été "
            "altéré ou tronqué. Transmission ARRÊTÉE. Figer les sauvegardes et ouvrir un incident."
            % broken_at,
            level="CRITICAL",
        )
        self.write_incident(result)
        return False

    def write_incident(self, result: Mapping[str, Any]) -> None:
        """Écrit un marqueur d'incident dans le dossier de sortie (collectable par le SIEM)."""
        marker = Path(self.args.out_dir) / "AUDIT_CHAIN_BROKEN.incident.json"
        document = {
            "detected_at": now_iso(),
            "severity": "critical",
            "kind": "audit_chain_broken",
            "verify": dict(result),
            "cursors": self.state.snapshot(),
            "action": "transmission arrêtée par examples/siem-forwarder/forward_cef.py",
            "runbook": [
                "1. FIGER l'état : sauvegarder la base et le journal d'audit, ne rien purger.",
                "2. Identifier broken_at : tout ce qui suit est postérieur à la rupture.",
                "3. Comparer avec les sauvegardes et les exports SIEM antérieurs.",
                "4. Restaurer une copie saine, ou documenter l'écart si la rupture est légitime.",
                "5. Ouvrir un incident de sécurité : l'intégrité de la traçabilité est en cause.",
            ],
        }
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            log("marqueur d'incident écrit : %s" % marker, level="CRITICAL")
        except OSError as exc:
            log("marqueur d'incident non écrit (%s)" % exc, level="CRITICAL")

    # -- sources -----------------------------------------------------------------------

    def forward_audit(self, since: str | None, until: str) -> int:
        """Transfère le journal d'audit de *since* à *until* ; retourne le nombre d'enregistrements.

        Le curseur d'état n'est **pas** touché ici : c'est :meth:`run_cycle` qui l'avance, et
        seulement après un retour sans exception. C'est ce qui garantit la reprise exacte après
        une coupure réseau ou un disque plein.
        """
        total = 0

        for fmt in self.formats():
            suffix = "cef" if fmt == "cef" else "jsonl"
            try:
                raw = self.client.export_audit(format=fmt, since=since, until=until)
            except ApiError as exc:
                if exc.status in (404, 405, 501):
                    # Repli explicite : l'instance n'expose pas cet export → construction locale.
                    log("export %s indisponible (%s) : repli sur GET /api/v1/audit" % (fmt, exc), level="WARN")
                    raw = self._audit_jsonl_fallback(since, until)
                else:
                    raise
            if isinstance(raw, str):
                # Robustesse : un transport qui aurait déjà décodé le corps ne doit pas casser la
                # déduplication ni l'écriture (le transport par défaut renvoie des octets).
                raw = raw.encode("utf-8")
            if not raw.strip():
                log("audit %s : aucun enregistrement sur la fenêtre (%s → %s)" % (fmt, since, until))
                continue

            if fmt == "cef":
                # Le CEF produit par le serveur est recopié **octet pour octet** (le réécrire
                # ferait perdre la garantie de conformité de l'émetteur) ; on se contente d'écarter
                # les lignes déjà transmises, en lisant ``externalId`` (le ``seq`` de l'audit).
                payload, count = self._filter_cef_lines(raw, source="audit-cef")
                if count:
                    output = self.output("audit", "cef")
                    output.write_bytes(payload)
                    output.records_written += count
                    total += count
                    log("audit CEF : %d enregistrement(s) → %s" % (count, output.path))
                else:
                    log("audit CEF : %d ligne(s) déjà transmise(s) (dédupliquées)" % raw.count(b"\n"))
            else:
                payload, count = self._filter_lines(raw, source="audit")
                if count:
                    output = self.output("audit", suffix)
                    output.write_bytes(payload)
                    output.records_written += count
                    total += count
                    log("audit JSONL : %d enregistrement(s) → %s" % (count, output.path))
        return total

    def _audit_jsonl_fallback(self, since: str | None, until: str | None) -> bytes:
        """Construit un flux JSONL d'audit depuis ``GET /api/v1/audit`` (repli)."""
        records = self.client.list_audit(since=since, until=until)
        return ("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)).encode("utf-8")

    def forward_findings(self, since: str | None, until: str) -> int:
        """Transfère les findings modifiés depuis *since* ; retourne le nombre d'enregistrements.

        Un finding est réémis dès que son ``updated_at`` (ou ``last_seen``) change : un changement
        de statut côté Thot Secure doit se voir dans le SIEM. La déduplication porte donc sur le
        couple ``(finding_id, updated_at)`` et non sur le seul identifiant.
        """
        findings = self.client.list_findings(since=since)
        if not findings:
            log("findings : aucun finding modifié sur la fenêtre (%s → %s)" % (since, until))
            return 0

        total = 0
        for fmt in self.formats():
            if fmt == "cef":
                lines = []
                for finding in findings:
                    key = "finding:%s:%s" % (
                        finding.get("finding_id"),
                        finding.get("updated_at") or finding.get("last_seen"),
                    )
                    if not self.dedupe.is_new(key):
                        continue
                    lines.append(finding_to_cef(finding))
                if not lines:
                    log("findings CEF : %d finding(s) déjà transmis (dédupliqués)" % len(findings))
                    continue
                output = self.output("findings", "cef")
                count = output.write_lines(lines)
                total += count
                log("findings CEF : %d enregistrement(s) → %s" % (count, output.path))
            else:
                payload_lines = []
                for finding in findings:
                    key = "finding-jsonl:%s:%s" % (
                        finding.get("finding_id"),
                        finding.get("updated_at") or finding.get("last_seen"),
                    )
                    if not self.dedupe.is_new(key):
                        continue
                    payload_lines.append(json.dumps(finding, ensure_ascii=False))
                if not payload_lines:
                    continue
                output = self.output("findings", "jsonl")
                count = output.write_lines(payload_lines)
                total += count
                log("findings JSONL : %d enregistrement(s) → %s" % (count, output.path))
        return total

    def _filter_lines(self, raw: bytes, *, source: str) -> tuple[bytes, int]:
        """Filtre un flux JSONL des enregistrements déjà transmis (déduplication)."""
        kept: list[str] = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                # Une ligne non JSON est transmise telle quelle : ne jamais perdre une donnée.
                kept.append(line)
                continue
            if not isinstance(record, Mapping):
                kept.append(line)
                continue
            key = "%s:%s:%s" % (source, record.get("seq"), record.get("hash"))
            if self.dedupe.is_new(key):
                kept.append(json.dumps(record, ensure_ascii=False))
        if not kept:
            return b"", 0
        return ("".join(line + "\n" for line in kept)).encode("utf-8"), len(kept)

    def _filter_cef_lines(self, raw: bytes, *, source: str) -> tuple[bytes, int]:
        """Écarte les lignes CEF déjà transmises, **sans les reformater**.

        La clé de déduplication est ``externalId`` (le ``seq`` du journal d'audit, §3.5), présent
        dans les extensions produites par l'export. À défaut, l'empreinte SHA-256 de la ligne sert
        de clé : une ligne identique est reconnue, une ligne différente passe toujours.
        """
        kept: list[str] = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            match = re.search(r"(?:^|\s)externalId=([^\s]+)", line)
            identifier = match.group(1) if match else hashlib.sha256(line.encode("utf-8")).hexdigest()
            if self.dedupe.is_new("%s:%s" % (source, identifier)):
                kept.append(line)
        if not kept:
            return b"", 0
        return ("".join(line + "\n" for line in kept)).encode("utf-8"), len(kept)

    # -- cycle -------------------------------------------------------------------------

    def cursor_window(self, key: str) -> tuple[str | None, str | None]:
        """Retourne ``(curseur_confirmé, since_à_demander)`` pour une source.

        Le ``since`` demandé recule de ``--overlap-seconds`` par rapport au curseur confirmé :
        cette marge absorbe une dérive d'horloge entre le serveur (qui horodate les
        enregistrements) et le forwarder (qui fixe ``until``). Les doublons éventuels sont écartés
        par :class:`Dedupe` : mieux vaut rejouer une seconde de journal que perdre une seconde de
        preuves.
        """
        cursor = self.state.get(key) or self.args.since
        if not cursor:
            return None, None
        return cursor, shift_iso(cursor, -self.args.overlap_seconds)

    def run_cycle(self) -> int:
        """Exécute un cycle complet ; retourne le nombre d'enregistrements transmis.

        Ordre des opérations, volontairement strict :

        1. vérification de la chaîne d'audit (on n'exporte pas des preuves non attestables) ;
        2. export et **écriture réussie** ;
        3. seulement alors, avance du curseur et sauvegarde atomique de l'état.

        Lève :class:`ApiError` / :class:`TransportError` / :class:`OSError` — l'appelant décide de
        poursuivre (boucle) ou de sortir (``--once``). Dans tous les cas d'erreur, le curseur n'a
        pas bougé : le cycle suivant reprend exactement au même point.
        """
        if not self.verify_chain():
            return 0

        until = self.args.until or now_iso()
        total = 0

        if "audit" in self.args.sources:
            _cursor, since = self.cursor_window("audit_since")
            total += self.forward_audit(since, until)
            self.state.set("audit_since", until)
            self.state.save()

        if "findings" in self.args.sources:
            _cursor, since = self.cursor_window("findings_since")
            total += self.forward_findings(since, until)
            self.state.set("findings_since", until)
            self.state.save()

        return total

    def summary(self) -> dict[str, Any]:
        """Récapitulatif des compteurs d'écriture et de déduplication."""
        return {
            "outputs": {
                key: {
                    "path": str(value.path),
                    "records": value.records_written,
                    "bytes": value.bytes_written,
                    "rotations": value.rotations,
                }
                for key, value in self.outputs.items()
            },
            "duplicatesIgnored": self.dedupe.duplicates,
            "cursors": self.state.snapshot(),
            "verify": self.verify_result,
            "chainBroken": self.chain_broken,
        }


# --------------------------------------------------------------------------------------
# Interface en ligne de commande
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (``--help`` documente chaque option)."""
    parser = argparse.ArgumentParser(
        prog="forward_cef.py",
        description=(
            "Exporte l'audit (CEF/JSONL) et les findings Thot Secure vers des fichiers tournants "
            "destinés à un SIEM, avec reprise par curseur et vérification de la chaîne d'audit."
        ),
        epilog=(
            "Codes de sortie : 0 succès, 1 erreur d'exécution, 2 usage/configuration, "
            "3 chaîne d'audit rompue (incident majeur), 130 Ctrl-C."
        ),
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
        help="clé ao_… portant « read:audit » et « read:findings » (défaut : $env:THOT_SECURE_API_KEY)",
    )
    parser.add_argument("--out-dir", default=".", help="dossier des fichiers de sortie (défaut : .)")
    parser.add_argument(
        "--format",
        choices=("cef", "jsonl", "both"),
        default="cef",
        help="format transmis au SIEM (les deux fichiers sont produits avec « both »)",
    )
    parser.add_argument(
        "--sources",
        default="audit,findings",
        help="sources à transférer, séparées par des virgules : audit,findings (défaut : les deux)",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="curseur initial ISO 8601 si aucun état n'existe (ex. 2026-02-01T00:00:00Z)",
    )
    parser.add_argument("--until", default=None, help="borne de fin fixe (tests, rattrapage borné)")
    parser.add_argument(
        "--overlap-seconds",
        type=float,
        default=DEFAULT_OVERLAP_SECONDS,
        help="recouvrement demandé avant le curseur, pour absorber les dérives d'horloge "
        "(défaut %s s ; les doublons sont dédupliqués localement)" % DEFAULT_OVERLAP_SECONDS,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="période entre deux cycles, en secondes (défaut %s)" % DEFAULT_INTERVAL,
    )
    parser.add_argument(
        "--verify-interval",
        type=float,
        default=DEFAULT_VERIFY_INTERVAL,
        help="période de vérification de la chaîne d'audit, en secondes (défaut %s ; 0 = à chaque "
        "cycle)" % DEFAULT_VERIFY_INTERVAL,
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="taille maximale d'un fichier avant rotation, en octets (défaut %s)" % DEFAULT_MAX_BYTES,
    )
    parser.add_argument(
        "--backups", type=int, default=DEFAULT_BACKUPS, help="nombre de fichiers conservés (défaut %s)" % DEFAULT_BACKUPS
    )
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help="fichier d'état des curseurs (défaut %s)" % DEFAULT_STATE_FILE,
    )
    parser.add_argument("--no-state", action="store_true", help="ne rien persister (tests, transfert jetable)")
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="ignorer l'état existant et repartir du début demandé (--since)",
    )
    parser.add_argument(
        "--dedupe-size",
        type=int,
        default=DEFAULT_DEDUPE_SIZE,
        help="nombre d'enregistrements mémorisés pour la déduplication (défaut %s)" % DEFAULT_DEDUPE_SIZE,
    )
    parser.add_argument("--once", action="store_true", help="exécuter un seul cycle puis sortir")
    parser.add_argument(
        "--continue-on-chain-break",
        action="store_true",
        help="poursuivre malgré une chaîne d'audit rompue (DÉCONSEILLÉ : documentez la décision)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(env_first("THOT_SECURE_TIMEOUT", "THOT_TIMEOUT", default=str(DEFAULT_TIMEOUT))),
        help="délai d'attente par requête, en secondes (défaut %s)" % DEFAULT_TIMEOUT,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="journalise les détails")
    parser.add_argument("--version", action="version", version="thotsecure-siem-forwarder 0.1.0")
    return parser


def parse_sources(value: str) -> list[str]:
    """Valide ``--sources`` (``audit``, ``findings``)."""
    items = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in items if item not in ("audit", "findings")]
    if unknown:
        raise ValueError("source(s) inconnue(s) : %s (attendu : audit, findings)" % ", ".join(unknown))
    if not items:
        raise ValueError("--sources est vide : indiquez audit, findings, ou les deux")
    return items


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée CLI. Retourne le code de sortie (voir la docstring du module)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        args.sources = parse_sources(args.sources)
    except ValueError as exc:
        log(str(exc), level="ERROR")
        return 2

    if args.timeout <= 0:
        log("--timeout doit être strictement positif", level="ERROR")
        return 2
    if args.interval < 0:
        log("--interval ne peut pas être négatif", level="ERROR")
        return 2
    if args.max_bytes < 1024:
        log("--max-bytes doit être au moins 1024", level="ERROR")
        return 2
    if args.overlap_seconds < 0:
        log("--overlap-seconds ne peut pas être négatif", level="ERROR")
        return 2
    if args.since and parse_iso(args.since) is None:
        log("--since doit être un horodatage ISO 8601 (ex. 2026-02-01T00:00:00Z)", level="ERROR")
        return 2
    if args.until and parse_iso(args.until) is None:
        log("--until doit être un horodatage ISO 8601", level="ERROR")
        return 2
    if not args.api_key:
        log(
            "clé API absente : définissez THOT_SECURE_API_KEY (ou THOT_API_KEY). "
            "L'export d'audit exige la capacité « read:audit », les findings « read:findings ».",
            level="ERROR",
        )
        return 2
    if not args.once and args.until:
        log("--until n'a de sens qu'avec --once (borne de rattrapage)", level="ERROR")
        return 2

    try:
        Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log("dossier de sortie %s inutilisable : %s" % (args.out_dir, exc), level="ERROR")
        return 2

    client = SiemClient(args.url, args.api_key, timeout=args.timeout)
    forwarder = Forwarder(args, client)

    log(
        "démarrage : %s → %s (sources=%s, format=%s, rotation=%d octets × %d)"
        % (
            safe_url(args.url),
            os.path.abspath(args.out_dir),
            ",".join(args.sources),
            args.format,
            args.max_bytes,
            args.backups,
        )
    )

    exit_code = 0
    cycles = 0
    try:
        while True:
            cycles += 1
            if not forwarder.verify_chain(force=cycles == 1):
                if not args.continue_on_chain_break:
                    log(
                        "arrêt du forwarder : la chaîne d'audit est rompue, la transmission "
                        "n'apporterait que des données non attestables.",
                        level="CRITICAL",
                    )
                    return 3
                log(
                    "--continue-on-chain-break : transmission poursuivie malgré la rupture. "
                    "Chaque enregistrement transmis reste un fait à vérifier manuellement.",
                    level="WARN",
                )
            try:
                count = forwarder.run_cycle()
                exit_code = 0
                log("cycle %d terminé : %d enregistrement(s) transmis" % (cycles, count))
            except ApiError as exc:
                exit_code = 2 if exc.status in (401, 403) else 1
                log("cycle %d : erreur d'API (%s)" % (cycles, exc), level="ERROR")
                if exc.status in (401, 403):
                    log(
                        "capacité manquante : « read:audit » (export du journal) et "
                        "« read:findings » (findings) sont nécessaires (§4).",
                        level="ERROR",
                    )
                    return 2
            except TransportError as exc:
                exit_code = 1
                log(
                    "cycle %d : réseau indisponible (%s) — curseur NON avancé, reprise au prochain cycle"
                    % (cycles, exc),
                    level="ERROR",
                )
            except OSError as exc:
                exit_code = 1
                log(
                    "cycle %d : écriture impossible (%s) — curseur NON avancé (le SIEM ne perdra rien)"
                    % (cycles, exc),
                    level="ERROR",
                )

            if args.once:
                break
            if args.interval <= 0:
                log("--interval 0 : un seul cycle en mode continu ; utilisez --once", level="WARN")
                break
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                raise
    except KeyboardInterrupt:
        log("Ctrl-C : arrêt propre, sauvegarde du curseur")
        forwarder.state.save()
        print(json.dumps(forwarder.summary(), ensure_ascii=False, indent=2))
        return 130

    forwarder.state.save()
    print(json.dumps(forwarder.summary(), ensure_ascii=False, indent=2))
    if not forwarder.chain_broken and args.once and exit_code == 0:
        log("cycle unique terminé sans incident")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
