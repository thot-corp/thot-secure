#!/usr/bin/env python3
"""Portail CI : findings Thot Secure → SARIF 2.1.0 agrégé → échec ou succès du pipeline.

Ce script est un **garde-fou de pipeline** : il transforme l'état de sécurité du tenant en un
artefact exploitable (SARIF 2.1.0, format natif de GitHub Code Scanning, Azure DevOps, GitLab…) et
en un **code de sortie** que l'intégration continue sait interpréter.

Ce qu'il fait
-------------

1. **Récupère les findings ouverts** : ``GET /api/v1/findings?status=open`` (§4.4), en suivant le
   ``cursor`` jusqu'à épuisement (et, avec ``--include-acked``, les findings acquittés — ils
   apparaîtront en ``suppressions`` dans le SARIF, sans bloquer la construction).
2. **Construit un SARIF 2.1.0 agrégé** : un seul ``run``, un ``tool.driver``, des règles dédupliquées
   par ``rule_id`` et des résultats enrichis (sévérité, ``risk_score``, tags, MITRE, ``finding_id``).
   Deux stratégies, choisies par ``--sarif-source`` :

   * ``auto`` (défaut) : demande d'abord le SARIF au serveur
     (``GET /api/v1/findings/{id}/report?format=sarif``, §4.8) et agrège les ``runs`` renvoyés ; au
     premier échec, bascule sur la conversion locale pour le reste de l'exécution ;
   * ``server`` : serveur uniquement (échec explicite si indisponible) ;
   * ``local`` : conversion locale uniquement — pratique en démonstration hors ligne, car le SARIF
     est alors produit uniquement à partir des champs de ``Finding`` (§3.2).

3. **Évalue le portail** : la construction échoue si un finding **non acquitté** d'une sévérité
   listée dans ``--fail-on`` (``critical`` par défaut) existe. Un finding ``acked``, ``closed`` ou
   ``suppressed`` ne bloque jamais.
4. **Émet un rapport lisible** : table de synthèse sur stdout, résumé Markdown dans
   ``$GITHUB_STEP_SUMMARY`` (``--step-summary``), et annotations GitHub ``::error::``
   (``--github-annotations``).

Adoption progressive : commencez par ``--warn-only``
---------------------------------------------------

Un portail bloquant activé du jour au lendemain sur un dépôt déjà rempli de findings rouges **finit
désactivé par l'équipe**. La séquence recommandée :

1. **semaine 1** : ``--warn-only`` + ``continue-on-error: true`` côté workflow, upload du SARIF
   activé → l'équipe voit les alertes dans l'onglet *Security* sans être bloquée ;
2. **semaine 2-3** : ``--warn-only`` retiré mais ``continue-on-error`` conservé → le job devient
   rouge visiblement, la fusion reste possible ;
3. **ensuite** : ``continue-on-error`` retiré → la fusion est bloquée par un finding critique non
   acquitté, ce qui est le but.

Le workflow complet est fourni dans ``.github-workflow-example.yml``.

Exemples
--------

::

    # 1. Générer le SARIF et n'échouer sur rien (semaine 1)
    python sarif_gate.py --url http://127.0.0.1:8080 --warn-only --out thotsecure.sarif

    # 2. Portail strict sur les critiques non acquittés
    python sarif_gate.py --out thotsecure.sarif --github-annotations --step-summary

    # 3. Démonstration hors ligne : SARIF construit localement, à partir d'un export JSONL
    python sarif_gate.py --from-file findings.jsonl --sarif-source local --out demo.sarif --warn-only

Codes de sortie
---------------

=== ==========================================================================
0   portail franchi (ou ``--warn-only``) : aucune sévérité bloquante non acquittée
1   erreur d'exécution : réseau, 5xx, réponse inexploitable, SARIF non productible
2   usage ou configuration : argument invalide, clé API absente, 401/403
3   portail échoué : au moins un finding de sévérité bloquante non acquitté
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
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

__all__ = ["main", "build_sarif", "evaluate_gate", "finding_to_result", "severity_level"]

# --------------------------------------------------------------------------------------
# Constantes du contrat (§3.2, §4.4, §4.8)
# --------------------------------------------------------------------------------------

DEFAULT_BASE_URL = "http://127.0.0.1:8080"

#: Ordre des sévérités du contrat §3.2, de la plus grave à la plus bénigne.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: Statuts qui ne bloquent jamais un pipeline (§3.2) : le finding a été traité ou assumé.
NON_BLOCKING_STATUSES: frozenset[str] = frozenset({"acked", "closed", "suppressed"})

#: Sévérité bloquante par défaut : un ``critical`` non acquitté casse la construction.
DEFAULT_FAIL_ON = "critical"

#: Nombre maximal de pages parcourues (protection contre une pagination infinie).
MAX_PAGES = 200

#: Taille de page demandée à l'API (≤ 500, §4.4).
PAGE_LIMIT = 200

DEFAULT_TIMEOUT = 20.0

USER_AGENT = "thotsecure-ci-sarif-gate/0.1.0 (+https://github.com/thot-corp/thot-secure)"

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: Gabarit d'URI de localisation. Les findings ne désignent pas un fichier du dépôt : GitHub Code
#: Scanning les classe alors en « other location », ce qui est le comportement attendu pour un
#: constat d'infrastructure. ``--artifact-uri-template`` permet de pointer un vrai fichier.
DEFAULT_URI_TEMPLATE = "thotsecure://finding/{finding_id}"

#: Score ``security-severity`` attendu par GitHub pour le tri des alertes.
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

#: Niveau SARIF (``error``/``warning``/``note``) associé à chaque sévérité.
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


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


def warn(message: str) -> None:
    """Message d'avertissement sur stderr (stdout reste réservé au rapport)."""
    print("[sarif-gate] %s" % message, file=sys.stderr, flush=True)


def info(args: argparse.Namespace, message: str) -> None:
    """Message d'information, uniquement avec ``--verbose``."""
    if getattr(args, "verbose", False):
        print("[sarif-gate] %s" % message, file=sys.stderr, flush=True)


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
) -> tuple[int, Any, str]:
    """Requête HTTP → ``(statut, corps décodé, corps brut)``.

    La clé API n'est transmise que par l'en-tête ``X-API-Key`` et n'apparaît dans aucun message.
    Aucune exception n'est levée pour un statut ≥ 400 : l'appelant décide.
    """
    if params:
        query = urlparse.urlencode({key: value for key, value in params.items() if value is not None})
        if query:
            url = "%s%s%s" % (url, "&" if "?" in url else "?", query)

    headers = {"Accept": "application/json, application/sarif+json", "User-Agent": USER_AGENT}
    if api_key:
        headers["X-API-Key"] = api_key

    request = urlrequest.Request(url, headers=headers, method=method.upper())
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, _decode(raw), _text(raw)
    except urlerror.HTTPError as exc:
        raw = exc.read()
        return exc.code, _decode(raw), _text(raw)
    except (urlerror.URLError, OSError, ValueError) as exc:
        raise TransportError("échec de la requête %s %s : %s" % (method, safe_url(url), exc)) from exc


def _decode(raw: bytes) -> Any:
    """Décode un corps JSON, ou retourne ``None`` si le corps n'est pas du JSON."""
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _text(raw: bytes) -> str:
    """Corps brut en texte, tronqué pour rester lisible."""
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")[:4000]


# --------------------------------------------------------------------------------------
# Lecture des findings
# --------------------------------------------------------------------------------------


def read_findings_file(path: str) -> list[dict[str, Any]]:
    """Lit des findings depuis un fichier JSON, JSONL, ou une enveloppe ``{"items": [...]}``.

    Mode **hors ligne** : permet de tester le portail, la conversion SARIF et les annotations sans
    aucune instance Thot Secure (utile en CI de démonstration et dans les tests du dépôt).
    """
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            document = json.loads(stripped)
        except ValueError:
            document = None
        if isinstance(document, list):
            return [dict(item) for item in document if isinstance(item, Mapping)]
        if isinstance(document, Mapping):
            for key in ("items", "findings", "data"):
                value = document.get(key)
                if isinstance(value, list):
                    return [dict(item) for item in value if isinstance(item, Mapping)]
            return [dict(document)]
        # JSON invalide : on tente le format JSONL ci-dessous.
    findings: list[dict[str, Any]] = []
    for number, line in enumerate(stripped.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ValueError("ligne %d : JSON invalide (%s)" % (number, exc)) from exc
        if isinstance(item, Mapping):
            findings.append(dict(item))
    return findings


class FindingsClient:
    """Accès en lecture aux findings et aux rapports SARIF (§4.4, §4.8)."""

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
        #: Point d'injection pour les tests : ``transport(method, url, api_key=…, params=…, timeout=…)``.
        self._transport = transport or http_request

    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> tuple[int, Any, str]:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        return self._transport("GET", url, api_key=self.api_key, params=params, timeout=self.timeout)

    def list_findings(
        self,
        *,
        status: str = "open",
        min_risk: float | None = None,
        max_pages: int = MAX_PAGES,
    ) -> list[dict[str, Any]]:
        """Parcourt ``GET /api/v1/findings`` en suivant le ``cursor`` jusqu'à épuisement.

        Le contrat borne ``limit`` à 500 : la pagination est donc la seule façon correcte de tout
        récupérer. Une boucle de curseurs identiques est interrompue (protection contre une
        pagination défaillante côté serveur).
        """
        findings: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()

        for page_number in range(1, max_pages + 1):
            status_code, payload, raw = self._get(
                "/api/v1/findings",
                {
                    "status": status,
                    "min_risk": min_risk,
                    "sort": "risk_score",
                    "limit": PAGE_LIMIT,
                    "cursor": cursor,
                },
            )
            if status_code >= 400:
                code, message, details = error_summary(payload, raw)
                raise ApiError(status_code, code, message, details)

            items, next_cursor = _split_page(payload)
            findings.extend(items)
            if not next_cursor:
                return findings
            if next_cursor in seen_cursors:
                warn("curseur répété (%s) : pagination interrompue par prudence." % next_cursor[:32])
                return findings
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        warn("limite de %d pages atteinte : la liste peut être incomplète (--max-pages)." % max_pages)
        return findings

    def get_server_sarif(self, finding_id: str) -> str | None:
        """``GET /api/v1/findings/{id}/report?format=sarif`` → texte SARIF, ou ``None``.

        Un ``404``/``405``/``501`` signifie que l'instance ne sait pas produire de SARIF : ce n'est
        pas une erreur fatale, la conversion locale prend le relais.
        """
        status_code, _payload, raw = self._get(
            "/api/v1/findings/%s/report" % urlparse.quote(str(finding_id)), {"format": "sarif"}
        )
        if status_code in (200, 201):
            return raw
        if status_code in (401, 403):
            raise ApiError(status_code, "forbidden", "capacité « read:findings » manquante")
        if status_code in (404, 405, 406, 501):
            return None
        if status_code >= 500:
            warn("rapport SARIF serveur indisponible (HTTP %d) : conversion locale." % status_code)
            return None
        warn("rapport SARIF serveur refusé (HTTP %d) : conversion locale." % status_code)
        return None


def _split_page(payload: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Extrait ``(items, next_cursor)`` d'une page du contrat (§4.4)."""
    if isinstance(payload, Mapping):
        items = payload.get("items")
        next_cursor = payload.get("next_cursor") or payload.get("cursor")
        found = [dict(item) for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []
        return found, str(next_cursor) if next_cursor else None
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, Mapping)], None
    return [], None


# --------------------------------------------------------------------------------------
# Conversion Finding → résultat SARIF (§3.2 → SARIF 2.1.0)
# --------------------------------------------------------------------------------------


def severity_level(severity: Any) -> str:
    """Niveau SARIF (``error``/``warning``/``note``) d'une sévérité du contrat."""
    return SARIF_LEVEL.get(str(severity or "").strip().lower(), "warning")


def as_float(value: Any, default: float = 0.0) -> float:
    """Conversion défensive en flottant (les champs de ``Finding`` peuvent être absents ou textuels)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def finding_title(finding: Mapping[str, Any]) -> str:
    """Titre lisible d'un finding (repli sur la règle, puis sur l'identifiant)."""
    for key in ("title", "rule_name", "rule_id"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Finding %s" % (finding.get("finding_id") or "inconnu")


def finding_message(finding: Mapping[str, Any]) -> str:
    """Message SARIF : titre + description + remédiation, sans donnée superflue."""
    parts = [finding_title(finding)]
    description = finding.get("description")
    if isinstance(description, str) and description.strip():
        parts.append(description.strip())
    remediation = finding.get("remediation")
    if isinstance(remediation, str) and remediation.strip():
        parts.append("Remédiation : %s" % remediation.strip())
    labels = finding.get("labels")
    if isinstance(labels, Mapping):
        interesting = {
            key: value
            for key, value in labels.items()
            if key in ("src_ip", "path", "host", "user", "resource_id", "check_id")
        }
        if interesting:
            parts.append("Contexte : %s" % json.dumps(interesting, ensure_ascii=False, sort_keys=True))
    return "\n".join(parts)


def finding_is_blocking(finding: Mapping[str, Any], fail_on: Sequence[str]) -> bool:
    """``True`` si le finding doit faire échouer le pipeline.

    Un finding **acquitté**, **clos** ou **supprimé** ne bloque jamais : quelqu'un l'a examiné et
    en a assumé la suite. Un statut inconnu est traité comme bloquant si la sévérité correspond —
    en cas de doute, on alerte plutôt que de laisser passer (*fail-closed*).
    """
    status = str(finding.get("status") or "").strip().lower()
    if status in NON_BLOCKING_STATUSES:
        return False
    severity = str(finding.get("severity") or "").strip().lower()
    return severity in {item.strip().lower() for item in fail_on}


def finding_to_result(
    finding: Mapping[str, Any],
    *,
    rule_index: int,
    uri_template: str = DEFAULT_URI_TEMPLATE,
) -> dict[str, Any]:
    """Convertit un ``Finding`` (§3.2) en résultat SARIF.

    Le résultat porte : la règle, le niveau, le message, une localisation (souvent symbolique : un
    finding n'est pas un fichier du dépôt), une empreinte partielle stable (déduplication entre
    exécutions) et des propriétés exploitables (``risk_score``, ``tags``, MITRE, identifiants).
    """
    finding_id = str(finding.get("finding_id") or "")
    rule_id = str(finding.get("rule_id") or "THOTSECURE-UNKNOWN")
    severity = str(finding.get("severity") or "").strip().lower()
    status = str(finding.get("status") or "open").strip().lower()

    uri = uri_template.format(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        tenant_id=str(finding.get("tenant_id") or ""),
    )

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": severity_level(severity),
        "message": {"text": finding_message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "description": {"text": "Constat Thot Secure (non rattaché à un fichier du dépôt)"},
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
        ],
        "partialFingerprints": {
            "thotsecureFindingId/v1": finding_id or rule_id,
            "thotsecureRuleId/v1": rule_id,
        },
        "properties": {
            "finding_id": finding_id,
            "tenant_id": finding.get("tenant_id"),
            "rule_id": rule_id,
            "severity": severity,
            "status": status,
            "risk_score": finding.get("risk_score"),
            "confidence": finding.get("confidence"),
            "count": finding.get("count"),
            "first_seen": finding.get("first_seen"),
            "last_seen": finding.get("last_seen"),
            "tags": list(finding.get("tags") or []),
            "mitre": list(finding.get("mitre") or []),
        },
    }

    if status in NON_BLOCKING_STATUSES:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": "Finding « %s » côté Thot Secure : hors périmètre du portail CI." % status,
            }
        ]

    return result


def finding_to_rule(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Construit la description de règle SARIF associée à un finding (§3.2, §5)."""
    rule_id = str(finding.get("rule_id") or "THOTSECURE-UNKNOWN")
    severity = str(finding.get("severity") or "").strip().lower()
    tags = [str(tag) for tag in (finding.get("tags") or [])]
    mitre = [str(item) for item in (finding.get("mitre") or [])]

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": str(finding.get("rule_name") or rule_id),
        "shortDescription": {"text": finding_title(finding)},
        "fullDescription": {
            "text": str(finding.get("description") or finding_title(finding))[:2000],
        },
        "defaultConfiguration": {"level": severity_level(severity)},
        "properties": {
            "tags": sorted({"security", "thotsecure", *tags, *(("mitre:%s" % item) for item in mitre)}),
            "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
            "problem.severity": severity_level(severity),
            "precision": "high" if as_float(finding.get("confidence")) >= 0.8 else "medium",
        },
    }
    remediation = finding.get("remediation")
    if isinstance(remediation, str) and remediation.strip():
        rule["help"] = {"text": remediation.strip()[:2000], "markdown": remediation.strip()[:2000]}
    return rule


def extract_from_server_sarif(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extrait ``(results, rules)`` d'un SARIF produit par le serveur.

    Tolérant par construction : un SARIF mal formé renvoie des listes vides plutôt qu'une
    exception, afin que l'agrégation ne fasse jamais échouer le pipeline sur un artefact annexe.
    """
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return [], []
    if not isinstance(document, Mapping):
        return [], []
    results: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    runs = document.get("runs")
    if not isinstance(runs, list):
        return [], []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), Mapping) else {}
        run_rules = driver.get("rules") if isinstance(driver, Mapping) else None
        if isinstance(run_rules, list):
            rules.extend([dict(rule) for rule in run_rules if isinstance(rule, Mapping)])
        run_results = run.get("results")
        if isinstance(run_results, list):
            results.extend([dict(item) for item in run_results if isinstance(item, Mapping)])
    return results, rules


# --------------------------------------------------------------------------------------
# Agrégation SARIF
# --------------------------------------------------------------------------------------


def build_sarif(
    findings: Sequence[Mapping[str, Any]],
    *,
    server_sarif: Mapping[str, str] | None = None,
    uri_template: str = DEFAULT_URI_TEMPLATE,
    tool_version: str = "0.1.0",
    information_uri: str = "https://github.com/thot-corp/thot-secure",
) -> dict[str, Any]:
    """Construit un SARIF 2.1.0 **agrégé** à partir des findings et des SARIF serveur éventuels.

    * les règles sont dédupliquées par ``rule_id`` (la première description rencontrée gagne) ;
    * les résultats provenant du serveur (``--sarif-source auto|server``) sont conservés **tels
      quels** — ils peuvent contenir des détails que la conversion locale ne sait pas produire —
      mais leur ``ruleIndex`` est réindexé sur le tableau de règles agrégé ;
    * un résultat serveur manquant pour un finding est reconstruit localement : **aucun finding
      n'est perdu**, le portail reste donc fiable même si le serveur ne sait pas produire de SARIF.
    """
    server_sarif = server_sarif or {}

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    def ensure_rule(finding: Mapping[str, Any], fallback_rule: Mapping[str, Any] | None = None) -> int:
        """Enregistre (une seule fois) la règle associée et retourne son index.

        L'identifiant de la règle agrégée est **toujours** le ``rule_id`` du finding (§3.2). Un
        SARIF produit par le serveur n'est utilisé que pour enrichir la description : s'il
        annonçait un autre identifiant, on obtiendrait deux règles homonymes dans le même ``run``,
        ce que la spécification SARIF interdit (identifiants de règle uniques) et que GitHub
        rejette à l'import.
        """
        rule_id = str(finding.get("rule_id") or "THOTSECURE-UNKNOWN")
        if rule_id in rule_index:
            return rule_index[rule_id]
        rule = dict(fallback_rule) if isinstance(fallback_rule, Mapping) else finding_to_rule(finding)
        rule["id"] = rule_id
        rule.setdefault("name", rule_id)
        rule.setdefault("shortDescription", {"text": finding_title(finding)})
        rule.setdefault("defaultConfiguration", {"level": severity_level(finding.get("severity"))})
        properties = rule.get("properties")
        if not isinstance(properties, Mapping):
            properties = {}
        merged_properties = dict(properties)
        merged_properties.setdefault("tags", ["security", "thotsecure"])
        merged_properties.setdefault(
            "security-severity",
            SECURITY_SEVERITY.get(str(finding.get("severity") or "").lower(), "5.5"),
        )
        rule["properties"] = merged_properties
        rule_index[rule_id] = len(rules)
        rules.append(rule)
        return rule_index[rule_id]

    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        server_text = server_sarif.get(finding_id)
        server_results: list[dict[str, Any]] = []
        server_rules: list[dict[str, Any]] = []
        if server_text:
            server_results, server_rules = extract_from_server_sarif(server_text)

        if server_results:
            for position, server_result in enumerate(server_results):
                result = dict(server_result)
                fallback_rule = server_rules[position] if position < len(server_rules) else None
                result["ruleIndex"] = ensure_rule(finding, fallback_rule)
                # Le ``ruleId`` du résultat doit désigner une règle réellement présente dans
                # ``rules`` : celui du finding fait foi.
                result["ruleId"] = str(finding.get("rule_id") or "THOTSECURE-UNKNOWN")
                if not isinstance(result.get("message"), Mapping):
                    result["message"] = {"text": finding_message(finding)}
                fingerprints = result.get("partialFingerprints")
                if not isinstance(fingerprints, Mapping):
                    fingerprints = {}
                merged_fingerprints = dict(fingerprints)
                merged_fingerprints.setdefault("thotsecureFindingId/v1", finding_id)
                result["partialFingerprints"] = merged_fingerprints
                properties = result.get("properties")
                if not isinstance(properties, Mapping):
                    properties = {}
                merged = dict(properties)
                merged.setdefault("finding_id", finding_id)
                merged.setdefault("severity", finding.get("severity"))
                merged.setdefault("status", finding.get("status"))
                merged.setdefault("risk_score", finding.get("risk_score"))
                result["properties"] = merged
                if str(finding.get("status") or "").lower() in NON_BLOCKING_STATUSES:
                    result.setdefault(
                        "suppressions",
                        [
                            {
                                "kind": "external",
                                "status": "accepted",
                                "justification": "Finding acquitté côté Thot Secure.",
                            }
                        ],
                    )
                results.append(result)
        else:
            results.append(
                finding_to_result(
                    finding, rule_index=ensure_rule(finding), uri_template=uri_template
                )
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Thot Secure",
                        "organization": "Thot Secure",
                        "version": tool_version,
                        "informationUri": information_uri,
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
                "properties": {
                    "generatedBy": "examples/ci-sarif-gate/sarif_gate.py",
                    "findingsCount": len(findings),
                },
            }
        ],
    }


# --------------------------------------------------------------------------------------
# Évaluation du portail et restitution
# --------------------------------------------------------------------------------------


def evaluate_gate(
    findings: Sequence[Mapping[str, Any]], fail_on: Sequence[str]
) -> tuple[list[Mapping[str, Any]], Counter]:
    """Retourne ``(findings_bloquants, compteurs_par_sévérité)``.

    Les compteurs portent sur l'ensemble des findings examinés ; les findings bloquants sont ceux
    dont la sévérité figure dans *fail_on* et qui ne sont ni acquittés, ni clos, ni supprimés.
    """
    counts: Counter = Counter()
    for finding in findings:
        counts[str(finding.get("severity") or "inconnue").strip().lower()] += 1
    blocking = [finding for finding in findings if finding_is_blocking(finding, fail_on)]
    blocking.sort(key=lambda item: as_float(item.get("risk_score")), reverse=True)
    return blocking, counts


def print_summary(
    findings: Sequence[Mapping[str, Any]],
    blocking: Sequence[Mapping[str, Any]],
    counts: Counter,
    *,
    fail_on: Sequence[str],
    sarif_path: str | None,
) -> None:
    """Affiche la synthèse destinée à l'humain qui lit les journaux de CI."""
    print("=" * 78)
    print("PORTAIL CI — FINDINGS THOT SECURE")
    print("=" * 78)
    print("  Findings examinés : %d" % len(findings))
    for severity in SEVERITIES:
        if counts.get(severity):
            print("    %-8s : %d" % (severity, counts[severity]))
    for severity, total in sorted(counts.items()):
        if severity not in SEVERITIES:
            print("    %-8s : %d" % (severity, total))
    if sarif_path:
        print("  SARIF agrégé      : %s" % sarif_path)
    print("  Sévérités bloquantes : %s" % ", ".join(fail_on))

    if not blocking:
        print("\n  ✔ Aucun finding bloquant non acquitté : portail franchi.")
        return

    print("\n  ✖ %d finding(s) bloquant(s) non acquitté(s) :" % len(blocking))
    for finding in blocking:
        print(
            "    - [%s] risque %s · %s · %s"
            % (
                finding.get("severity"),
                finding.get("risk_score"),
                finding.get("rule_id"),
                str(finding.get("title") or "")[:70],
            )
        )
        print("      finding_id : %s" % finding.get("finding_id"))
        print(
            "      régularisation : thotsecure findings show %s  (puis ack/close, ou correction)"
            % finding.get("finding_id")
        )


def step_summary_markdown(
    findings: Sequence[Mapping[str, Any]],
    blocking: Sequence[Mapping[str, Any]],
    counts: Counter,
    *,
    fail_on: Sequence[str],
    warn_only: bool,
) -> str:
    """Résumé Markdown pour ``$GITHUB_STEP_SUMMARY`` (tableau lisible dans l'onglet Actions)."""
    lines = ["## Portail Thot Secure — findings", ""]
    if blocking:
        verdict = "⚠️ avertissement seul (`--warn-only`)" if warn_only else "❌ **portail échoué**"
    else:
        verdict = "✅ portail franchi"
    lines.append("**Verdict** : %s" % verdict)
    lines.append("")
    lines.append("| Sévérité | Findings |")
    lines.append("|---|---|")
    for severity in SEVERITIES:
        lines.append("| %s | %d |" % (severity, counts.get(severity, 0)))
    lines.append("| **total** | **%d** |" % len(findings))
    lines.append("")
    lines.append("Sévérités bloquantes configurées : `%s`" % ", ".join(fail_on))
    lines.append("")
    if blocking:
        lines.append("### Findings bloquants")
        lines.append("")
        lines.append("| Sévérité | Risque | Règle | Titre | finding_id |")
        lines.append("|---|---|---|---|---|")
        for finding in blocking:
            lines.append(
                "| %s | %s | `%s` | %s | `%s` |"
                % (
                    finding.get("severity"),
                    finding.get("risk_score"),
                    finding.get("rule_id"),
                    str(finding.get("title") or "").replace("|", "\\|")[:80],
                    finding.get("finding_id"),
                )
            )
        lines.append("")
        lines.append(
            "Régularisation : `thotsecure findings ack <finding_id>` (assumé), "
            "`close` (traité) ou correction à la source."
        )
    return "\n".join(lines) + "\n"


def github_escape(value: str, *, property_value: bool = False) -> str:
    """Échappe une valeur pour les *workflow commands* GitHub Actions.

    GitHub n'accepte qu'un jeu d'échappements restreint : ``%25`` (pourcent), ``%0D`` (CR),
    ``%0A`` (LF) — et, **dans une valeur de propriété uniquement**, ``%3A`` (deux-points) et
    ``%2C`` (virgule). Un message échappé comme une propriété afficherait des ``%3A`` parasites.
    """
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def emit_github_annotations(
    findings: Sequence[Mapping[str, Any]],
    blocking: Sequence[Mapping[str, Any]],
    *,
    warn_only: bool,
) -> None:
    """Émet des annotations GitHub Actions (``::error``/``::warning``) sur les findings.

    Ces annotations apparaissent **directement sur la page du workflow**, ce qui évite d'obliger
    l'équipe à ouvrir l'onglet *Security* pour comprendre ce qui a échoué.
    """
    for finding in blocking:
        command = "warning" if warn_only else "error"
        print(
            "::%s title=%s::%s"
            % (
                command,
                github_escape(
                    "Thot Secure %s (risque %s)" % (finding.get("severity"), finding.get("risk_score")),
                    property_value=True,
                ),
                github_escape(
                    "%s — règle %s — finding_id %s"
                    % (
                        finding_title(finding),
                        finding.get("rule_id"),
                        finding.get("finding_id"),
                    )
                ),
            )
        )
    if not blocking and findings:
        print(
            "::notice title=%s::%s"
            % (
                github_escape("Thot Secure", property_value=True),
                github_escape("%d finding(s) examiné(s), aucun bloquant." % len(findings)),
            )
        )


# --------------------------------------------------------------------------------------
# Interface en ligne de commande
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (``--help`` documente chaque option)."""
    parser = argparse.ArgumentParser(
        prog="sarif_gate.py",
        description=(
            "Agrège les findings Thot Secure en SARIF 2.1.0 et fait échouer le pipeline si un "
            "finding bloquant non acquitté existe."
        ),
        epilog=(
            "Codes de sortie : 0 portail franchi, 1 erreur d'exécution, 2 usage/configuration, "
            "3 portail échoué."
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
        help="clé ao_… portant « read:findings » (défaut : $env:THOT_SECURE_API_KEY)",
    )
    parser.add_argument(
        "--from-file",
        metavar="FICHIER",
        help="lit les findings depuis un JSON/JSONL au lieu de l'API (mode hors ligne)",
    )
    parser.add_argument(
        "--status",
        default="open",
        help="statut interrogé (défaut : open ; les acquittés n'ont pas à bloquer la CI)",
    )
    parser.add_argument(
        "--include-acked",
        action="store_true",
        help="ajoute aussi les findings acquittés (ils apparaîtront en « suppressions » dans le SARIF)",
    )
    parser.add_argument(
        "--min-risk",
        type=float,
        default=None,
        help="score de risque minimal interrogé (transmis à l'API, §4.4)",
    )
    parser.add_argument(
        "--fail-on",
        default=DEFAULT_FAIL_ON,
        help="sévérités qui font échouer le pipeline, séparées par des virgules "
        "(défaut : %s ; « any » = toutes)" % DEFAULT_FAIL_ON,
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="n'échoue jamais : signale les findings bloquants sans casser la construction "
        "(mode recommandé la première semaine)",
    )
    parser.add_argument(
        "--sarif-source",
        choices=("auto", "server", "local"),
        default="auto",
        help="origine du SARIF : auto (serveur puis repli local), server, local (défaut : auto)",
    )
    parser.add_argument(
        "--out",
        default="thotsecure.sarif",
        help="fichier SARIF agrégé à écrire (défaut : thotsecure.sarif)",
    )
    parser.add_argument(
        "--no-sarif",
        action="store_true",
        help="n'écrit aucun fichier SARIF (portail seul)",
    )
    parser.add_argument(
        "--artifact-uri-template",
        default=DEFAULT_URI_TEMPLATE,
        help="gabarit d'URI des localisations ; variables : {finding_id}, {rule_id}, {severity}, "
        "{tenant_id} (défaut : %s)" % DEFAULT_URI_TEMPLATE,
    )
    parser.add_argument(
        "--github-annotations",
        action="store_true",
        help="émet des annotations GitHub Actions (::error/::warning)",
    )
    parser.add_argument(
        "--step-summary",
        action="store_true",
        help="écrit un résumé Markdown dans le fichier de $GITHUB_STEP_SUMMARY",
    )
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES, help="pages maximales parcourues")
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(env_first("THOT_SECURE_TIMEOUT", "THOT_TIMEOUT", default=str(DEFAULT_TIMEOUT))),
        help="délai d'attente par requête, en secondes (défaut %s)" % DEFAULT_TIMEOUT,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="journalise les détails")
    parser.add_argument("--version", action="version", version="thotsecure-ci-sarif-gate 0.1.0")
    return parser


def parse_fail_on(value: str) -> list[str]:
    """Convertit ``--fail-on`` en liste de sévérités (``any`` = toutes)."""
    items = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not items:
        return [DEFAULT_FAIL_ON]
    if "any" in items or "all" in items:
        return list(SEVERITIES)
    unknown = [item for item in items if item not in SEVERITIES]
    if unknown:
        raise ValueError(
            "sévérité(s) inconnue(s) : %s (attendu : %s, ou « any »)"
            % (", ".join(unknown), ", ".join(SEVERITIES))
        )
    return items


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée CLI. Retourne le code de sortie (voir la docstring du module)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        fail_on = parse_fail_on(args.fail_on)
    except ValueError as exc:
        warn(str(exc))
        return 2

    if args.max_pages < 1:
        warn("--max-pages doit être au moins 1")
        return 2
    if args.timeout <= 0:
        warn("--timeout doit être strictement positif")
        return 2
    if not args.from_file and not args.api_key:
        warn(
            "clé API absente : définissez THOT_SECURE_API_KEY (ou THOT_API_KEY), ou utilisez "
            "--from-file pour travailler sur un export local."
        )
        return 2

    client = FindingsClient(args.url, args.api_key, timeout=args.timeout)

    # ------------------------------------------------------------------ 1. lecture
    findings: list[dict[str, Any]] = []
    if args.from_file:
        try:
            findings = read_findings_file(args.from_file)
        except (OSError, ValueError) as exc:
            warn("lecture de %s impossible : %s" % (args.from_file, exc))
            return 2
        info(args, "%d finding(s) lus depuis %s" % (len(findings), args.from_file))
    else:
        try:
            findings = client.list_findings(status=args.status, min_risk=args.min_risk, max_pages=args.max_pages)
            if args.include_acked:
                findings.extend(
                    client.list_findings(status="acked", min_risk=args.min_risk, max_pages=args.max_pages)
                )
        except ApiError as exc:
            warn("lecture des findings refusée : %s" % exc)
            if exc.status in (401, 403):
                warn("capacité « read:findings » manquante : rôle viewer minimum (§4).")
                return 2
            return 1
        except TransportError as exc:
            warn("instance injoignable : %s" % exc)
            return 1

    # ------------------------------------------------------------------ 2. SARIF
    server_sarif: dict[str, str] = {}
    sarif_path: str | None = None
    if not args.no_sarif:
        if args.sarif_source in ("auto", "server"):
            failures = 0
            for finding in findings:
                finding_id = str(finding.get("finding_id") or "")
                if not finding_id:
                    continue
                try:
                    text = client.get_server_sarif(finding_id)
                except ApiError as exc:
                    warn("rapport SARIF serveur refusé (%s)" % exc)
                    text = None
                except TransportError as exc:
                    warn("rapport SARIF serveur injoignable (%s)" % exc)
                    text = None
                if text:
                    server_sarif[finding_id] = text
                else:
                    failures += 1
                    if args.sarif_source == "server":
                        warn("--sarif-source server : le SARIF serveur est indisponible, arrêt.")
                        return 1
                    if failures == 1:
                        info(
                            args,
                            "SARIF serveur indisponible : conversion locale pour les findings restants.",
                        )
                    if failures >= 3:
                        # Inutile d'insister : l'instance ne produit manifestement pas de SARIF.
                        break

        if args.sarif_source == "local":
            server_sarif = {}

        sarif = build_sarif(
            findings,
            server_sarif=server_sarif,
            uri_template=args.artifact_uri_template,
        )
        try:
            Path(args.out).write_text(
                json.dumps(sarif, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            sarif_path = args.out
        except OSError as exc:
            warn("écriture du SARIF impossible (%s) : le portail continue, l'artefact sera absent." % exc)
            sarif_path = None
        else:
            info(
                args,
                "SARIF écrit : %d résultat(s), %d règle(s) (source : %s)"
                % (
                    len(sarif["runs"][0]["results"]),
                    len(sarif["runs"][0]["tool"]["driver"]["rules"]),
                    "serveur + local" if server_sarif else "local",
                ),
            )

    # ------------------------------------------------------------------ 3. portail
    blocking, counts = evaluate_gate(findings, fail_on)
    print_summary(findings, blocking, counts, fail_on=fail_on, sarif_path=sarif_path)

    if args.github_annotations:
        emit_github_annotations(findings, blocking, warn_only=args.warn_only)

    if args.step_summary:
        summary_path = env_first("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                with open(summary_path, "a", encoding="utf-8") as handle:
                    handle.write(
                        step_summary_markdown(
                            findings, blocking, counts, fail_on=fail_on, warn_only=args.warn_only
                        )
                    )
            except OSError as exc:
                warn("résumé d'étape non écrit (%s)" % exc)
        else:
            info(args, "GITHUB_STEP_SUMMARY non défini : aucun résumé d'étape écrit.")

    if blocking and args.warn_only:
        warn(
            "%d finding(s) bloquant(s) détecté(s), mais --warn-only est actif : sortie en succès. "
            "Retirez --warn-only (et continue-on-error) une fois les findings traités." % len(blocking)
        )
        return 0
    if blocking:
        warn("portail échoué : %d finding(s) bloquant(s) non acquitté(s)." % len(blocking))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
