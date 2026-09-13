#!/usr/bin/env python3
"""Boucle complète de contre-mesure assistée : findings → plan → approbation → exécution → rollback.

Ce script déroule **le chemin d'action complet** du SOAR Thot Secure, en gardant l'humain dans la
boucle à chaque étape sensible :

1. ``GET /version`` (§4.1) : **état de sûreté affiché en clair** avant toute chose — mode
   d'autonomie global et ``dry_run``.
2. ``GET /api/v1/findings?status=open&min_risk=70`` (§4.4) : liste des findings ouverts les plus
   risqués, triés par ``risk_score``.
3. ``POST /api/v1/actions/plan`` (§4.6) : construction du plan d'action. **Aucun effet de bord** :
   le plan est un objet ``Action`` à l'état ``planned``.
4. **Affichage du plan complet** (JSON intégral) puis **confirmation interactive explicite** :
   l'opérateur doit taper un mot de confirmation. En mode non interactif (CI, cron, redirection),
   ``--yes`` est **obligatoire** — aucune exécution silencieuse n'est possible.
5. ``approve`` puis ``execute`` (§4.6), avec affichage du statut et du résultat.
6. **Rollback proposé systématiquement** : toute action doit rester réversible (invariant 3 du
   contrat).

Le mode ``auto`` : une décision consciente, journalisée et réversible
--------------------------------------------------------------------

Le mode ``auto`` d'un tenant (``mode: auto`` dans le §4.2, ou ``THOT_AUTONOMY=auto``) permet au
moteur de décision d'exécuter une contre-mesure **sans approbation humaine**. Ce script ne l'active
**jamais** et ne le contourne **jamais** — il se contente de l'afficher. Activer ``auto`` est une
décision d'ingénierie et de gouvernance qui doit être :

* **consciente** : assumée par une personne nommée, tracée dans un changement, avec une date de
  revue. Personne ne doit découvrir que son infrastructure bloque des adresses « toute seule » ;
* **limitée** : périmètre restreint (un playbook, un type de sévérité, un environnement), plafond
  horaire (``max_actions_per_hour``, garde-fou §6) et liste de cibles protégées
  (``autonomy_allowlist``) à jour ;
* **journalisée** : chaque décision porte ``policy_id``, chaque action un ``audit_seq``, et
  ``GET /api/v1/audit/verify`` doit rester ``valid`` ;
* **réversible** : le playbook doit être ``reversible: true`` et le rollback possible dans la
  fenêtre annoncée.

Le mode ``supervised`` reste le défaut recommandé : c'est celui que ce script implémente.

``dry_run`` : ne jamais laisser croire qu'une action a eu lieu
-------------------------------------------------------------

Si le tenant (ou l'instance) est en ``dry_run``, l'API **simule** : elle renvoie un ``Action`` avec
``dry_run: true`` et ``result.simulated: true``, et **rien n'est réellement appliqué**. Ce script
le dit en haut, le répète au moment du plan, et remplace le message final « action exécutée » par
« **simulation** : aucune action réelle n'a été exécutée ». Un opérateur ne doit jamais pouvoir
croire qu'un blocage a eu lieu alors qu'il n'en est rien.

Capacités requises (§4)
-----------------------

``read:findings`` (lister les findings et lire une action), ``execute:actions`` (plan + execute) et
``approve:actions`` (approve) → rôle ``responder`` minimum. Les commandes exactes de création :

::

    thotsecure key create --tenant acme --role responder --label mitigation

Exemples
--------

::

    # 1. Simulation complète : le plan est construit en dry_run, rien n'est appliqué
    python auto_mitigation.py --min-risk 70

    # 2. Contre-mesure réelle, avec confirmation interactive
    python auto_mitigation.py --min-risk 70 --live

    # 3. Pipeline non interactif : --yes est obligatoire (et engage son auteur)
    python auto_mitigation.py --finding-id f1c2 --playbook block-source-ip --live --yes

    # 4. Enchaîner sur un rollback immédiat (fenêtre d'exposition minimale)
    python auto_mitigation.py --min-risk 80 --live --yes --rollback

Codes de sortie
---------------

=== ==========================================================================
0   déroulé terminé (plan seul, exécution, ou exécution + rollback)
1   erreur d'exécution : réseau, 5xx, réponse inexploitable
2   usage ou configuration : argument invalide, clé absente, 401/403, aucun finding
3   refus de l'opérateur (confirmation déclinée) ou action laissée en attente
130 Ctrl-C : interruption propre, sans exécution supplémentaire
=== ==========================================================================
"""

from __future__ import annotations

import argparse
import contextlib as _contextlib
import json
import os
import re
import sys
import sys as _sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
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


__all__ = ["HttpApi", "SdkApi", "build_api", "describe_safety_state", "main"]

# --------------------------------------------------------------------------------------
# Constantes du contrat (§4)
# --------------------------------------------------------------------------------------

DEFAULT_BASE_URL = "http://127.0.0.1:8080"

#: Findings visés par défaut : ouverts, score de risque ≥ 70 (§4.4).
DEFAULT_MIN_RISK = 70.0

#: Playbook le plus courant pour une contre-mesure réseau (§7).
DEFAULT_PLAYBOOK = "block-source-ip"

#: Durée de blocage demandée par défaut, en secondes.
DEFAULT_DURATION_SECONDS = 3600

DEFAULT_TIMEOUT = 15.0

USER_AGENT = "thotsecure-auto-mitigation/0.1.0 (+https://github.com/thot-corp/thot-secure)"

#: Mot attendu pour la confirmation interactive. Volontairement explicite : « oui » vite tapé ne
#: doit pas suffire à bloquer une adresse.
CONFIRMATION_WORD = "OUI"

#: États d'une ``Action`` (§3.4) tels qu'exploités par le déroulé.
ACTION_STATES = (
    "planned",
    "pending_approval",
    "approved",
    "rejected",
    "executing",
    "succeeded",
    "failed",
    "expired",
    "rolled_back",
)


# --------------------------------------------------------------------------------------
# Configuration : variables d'environnement
# --------------------------------------------------------------------------------------


def env_first(*names: str, default: str | None = None) -> str | None:
    """Première variable d'environnement définie et non vide parmi *names*.

    Les noms ``THOT_SECURE_*`` sont prioritaires ; les noms ``THOT_*`` du contrat §9 restent
    acceptés pour ne casser aucune installation existante.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def env_bool(*names: str, default: bool = False) -> bool:
    """Lit un booléen d'environnement (``1/true/yes/on/oui``), insensible à la casse."""
    value = env_first(*names)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "oui", "y")


def safe_url(url: str) -> str:
    """URL expurgée de tout identifiant utilisateur (``http://user:pass@hôte``)."""
    return re.sub(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@", r"\g<scheme>", url)


# --------------------------------------------------------------------------------------
# Transport HTTP (urllib, bibliothèque standard)
# --------------------------------------------------------------------------------------


class TransportError(RuntimeError):
    """Échec réseau, DNS, TLS ou délai d'attente dépassé (aucune réponse HTTP exploitable)."""


class ApiError(RuntimeError):
    """Réponse HTTP d'erreur normalisée (§4.6) : ``{"error": {"code", "message", "details"}}``."""

    def __init__(self, status: int, code: str, message: str, details: Any = None) -> None:
        super().__init__(f"HTTP {status} · {code or 'error'} · {message}")
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
    json_body: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, Any, str, Any]:
    """Requête HTTP générique → ``(statut, corps décodé, corps brut, en-têtes)``.

    * la clé API passe **uniquement** dans l'en-tête ``X-API-Key`` (jamais en paramètre d'URL, qui
      finit dans les journaux de proxy) et n'apparaît dans aucun message d'erreur ;
    * aucune exception n'est levée pour un statut ≥ 400 : l'appelant décide (l'API renvoie des
      erreurs normalisées ``409``/``429`` que le déroulé doit expliquer).
    """
    if params:
        query = urlparse.urlencode(
            {key: value for key, value in params.items() if value is not None}
        )
        if query:
            url = "{}{}{}".format(url, "&" if "?" in url else "?", query)

    data = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False, default=str).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["X-API-Key"] = api_key

    # S310 : `urlopen` ouvrirait n'importe quel schéma (`file:`, `ftp:`, `data:`…) alors que
    # cette URL vient de la ligne de commande. Les deux `# noqa: S310` ci-dessous pointent sur
    # ce contrôle, seule barrière avant la connexion.
    scheme = urlparse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise TransportError(
            f"schéma d'URL refusé : {scheme or '(absent)'} — seuls http et https sont acceptés."
        )

    request = urlrequest.Request(url, data=data, headers=headers, method=method.upper())  # noqa: S310
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
            return response.status, _decode(raw), _text(raw), response.headers
    except urlerror.HTTPError as exc:
        raw = exc.read()
        return exc.code, _decode(raw), _text(raw), exc.headers
    except (urlerror.URLError, OSError, ValueError) as exc:
        raise TransportError(f"échec de la requête {method} {safe_url(url)} : {exc}") from exc


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
    return raw.decode("utf-8", errors="replace")[:2000]


# --------------------------------------------------------------------------------------
# Clients d'API : SDK officiel si présent, sinon client embarqué (bibliothèque standard)
# --------------------------------------------------------------------------------------


class HttpApi:
    """Client d'API minimal, embarqué, sans dépendance : ``urllib`` uniquement.

    Il couvre exactement les routes utilisées par le déroulé (§4.1, §4.4, §4.5, §4.6). Toutes les
    méthodes retournent des dictionnaires JSON bruts : le script travaille sur le contrat, pas sur
    des objets internes.
    """

    #: Nom affiché du client (utile pour expliquer à l'opérateur *comment* l'API est appelée).
    label = "client embarqué (urllib, bibliothèque standard)"

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
        #: Point d'injection pour les tests (monkeypatch) : ``transport(method, url, **kwargs)``.
        self._transport = transport or http_request

    def __repr__(self) -> str:  # pragma: no cover - jamais de secret dans le repr
        return "HttpApi(base_url={!r}, api_key={})".format(
            safe_url(self.base_url),
            "'***'" if self.api_key else "None",
        )

    # -- bas niveau --------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        status, payload, raw_text, _headers = self._transport(
            method, url, api_key=self.api_key, timeout=self.timeout, **kwargs
        )
        if status >= 400:
            code, message, details = error_summary(payload, raw_text)
            raise ApiError(status, code, message, details)
        return payload

    def _items(self, payload: Any) -> list[dict[str, Any]]:
        """Normalise une page ``{"items": [...]}`` (ou une liste nue) en liste de dictionnaires."""
        if isinstance(payload, Mapping):
            items = payload.get("items")
            if isinstance(items, list):
                return [dict(item) for item in items if isinstance(item, Mapping)]
            return []
        if isinstance(payload, list):
            return [dict(item) for item in payload if isinstance(item, Mapping)]
        return []

    # -- §4.1 santé / méta -------------------------------------------------------------

    def version(self) -> dict[str, Any]:
        """``GET /version`` (public) : version, licence, mode d'autonomie global, ``dry_run``."""
        payload = self._request("GET", "/version")
        return dict(payload) if isinstance(payload, Mapping) else {}

    def whoami(self) -> dict[str, Any]:
        """``GET /api/v1/auth/whoami`` : tenant, rôle, capacités, mode d'autonomie."""
        payload = self._request("GET", "/api/v1/auth/whoami")
        return dict(payload) if isinstance(payload, Mapping) else {}

    # -- §4.4 findings -----------------------------------------------------------------

    def list_findings(
        self,
        *,
        status: str = "open",
        min_risk: float | None = None,
        limit: int = 50,
        sort: str = "risk_score",
    ) -> list[dict[str, Any]]:
        """``GET /api/v1/findings`` (capacité ``read:findings``)."""
        payload = self._request(
            "GET",
            "/api/v1/findings",
            params={"status": status, "min_risk": min_risk, "limit": limit, "sort": sort},
        )
        return self._items(payload)

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        """``GET /api/v1/findings/{id}``."""
        payload = self._request("GET", f"/api/v1/findings/{urlparse.quote(finding_id)}")
        return dict(payload) if isinstance(payload, Mapping) else {}

    # -- §4.5 playbooks ----------------------------------------------------------------

    def list_playbooks(self) -> list[dict[str, Any]]:
        """``GET /api/v1/playbooks`` (capacité ``read:rules``)."""
        return self._items(self._request("GET", "/api/v1/playbooks"))

    # -- §4.6 actions ------------------------------------------------------------------

    def plan_action(
        self,
        finding_id: str,
        playbook: str,
        *,
        params: Mapping[str, Any] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """``POST /api/v1/actions/plan`` (capacité ``execute:actions``) — aucun effet de bord."""
        payload = self._request(
            "POST",
            "/api/v1/actions/plan",
            json_body={
                "finding_id": finding_id,
                "playbook": playbook,
                "params": dict(params or {}),
                "dry_run": bool(dry_run),
            },
        )
        return dict(payload) if isinstance(payload, Mapping) else {}

    def approve_action(self, action_id: str, *, comment: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/approve`` (capacité ``approve:actions``)."""
        payload = self._request(
            "POST",
            f"/api/v1/actions/{urlparse.quote(action_id)}/approve",
            json_body={"comment": comment} if comment else {},
        )
        return dict(payload) if isinstance(payload, Mapping) else {}

    def execute_action(self, action_id: str) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/execute`` (capacité ``execute:actions``)."""
        payload = self._request(
            "POST", f"/api/v1/actions/{urlparse.quote(action_id)}/execute", json_body={}
        )
        return dict(payload) if isinstance(payload, Mapping) else {}

    def rollback_action(self, action_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/rollback`` (capacité ``execute:actions``)."""
        payload = self._request(
            "POST",
            f"/api/v1/actions/{urlparse.quote(action_id)}/rollback",
            json_body={"reason": reason} if reason else {},
        )
        return dict(payload) if isinstance(payload, Mapping) else {}

    def get_action(self, action_id: str) -> dict[str, Any]:
        """``GET /api/v1/actions/{id}`` (capacité ``read:findings``)."""
        payload = self._request("GET", f"/api/v1/actions/{urlparse.quote(action_id)}")
        return dict(payload) if isinstance(payload, Mapping) else {}

    def close(self) -> None:
        """Aucune ressource à libérer (client sans connexion persistante)."""
        return None


class SdkApi:
    """Adaptateur au-dessus du **SDK Python officiel** (``sdks/python/thotsecure_sdk``).

    Le SDK est utilisé lorsqu'il est importable : il apporte la reprise automatique, la
    sérialisation des modèles du contrat et le suivi des capacités. L'interface exposée ici est
    identique à :class:`HttpApi`, si bien que le reste du script ignore lequel est employé.
    """

    label = "SDK Python officiel (thotsecure_sdk)"

    def __init__(self, client: Any) -> None:
        self._client = client

    def __repr__(self) -> str:  # pragma: no cover
        return f"SdkApi(client={self._client!r})"

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        """Convertit un modèle du SDK (``to_dict()``) ou un mapping en dictionnaire."""
        if value is None:
            return {}
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return dict(to_dict())
        if isinstance(value, Mapping):
            return dict(value)
        return {}

    @staticmethod
    def _page_items(page: Any) -> list[dict[str, Any]]:
        """Extrait ``page.items`` (ou une liste) sous forme de dictionnaires."""
        items = getattr(page, "items", page)
        if isinstance(items, (list, tuple)):
            return [SdkApi._as_dict(item) for item in items]
        return []

    # -- surface identique à HttpApi ---------------------------------------------------

    def version(self) -> dict[str, Any]:
        """``GET /version`` via le SDK."""
        return self._as_dict(self._client.version())

    def whoami(self) -> dict[str, Any]:
        """``GET /api/v1/auth/whoami`` via le SDK."""
        return self._as_dict(self._client.whoami())

    def list_findings(
        self,
        *,
        status: str = "open",
        min_risk: float | None = None,
        limit: int = 50,
        sort: str = "risk_score",
    ) -> list[dict[str, Any]]:
        """``GET /api/v1/findings`` via le SDK."""
        return self._page_items(
            self._client.list_findings(status=status, min_risk=min_risk, limit=limit, sort=sort)
        )

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        """``GET /api/v1/findings/{id}`` via le SDK."""
        return self._as_dict(self._client.get_finding(finding_id))

    def list_playbooks(self) -> list[dict[str, Any]]:
        """``GET /api/v1/playbooks`` via le SDK."""
        return self._page_items(self._client.list_playbooks())

    def plan_action(
        self,
        finding_id: str,
        playbook: str,
        *,
        params: Mapping[str, Any] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """``POST /api/v1/actions/plan`` via le SDK (``dry_run=True`` par défaut)."""
        return self._as_dict(
            self._client.plan_action(
                finding_id, playbook, params=dict(params or {}), dry_run=dry_run
            )
        )

    def approve_action(self, action_id: str, *, comment: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/approve`` via le SDK."""
        return self._as_dict(self._client.approve_action(action_id, comment=comment))

    def execute_action(self, action_id: str) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/execute`` via le SDK."""
        return self._as_dict(self._client.execute_action(action_id))

    def rollback_action(self, action_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/actions/{id}/rollback`` via le SDK."""
        return self._as_dict(self._client.rollback_action(action_id, reason=reason))

    def get_action(self, action_id: str) -> dict[str, Any]:
        """``GET /api/v1/actions/{id}`` via le SDK."""
        return self._as_dict(self._client.get_action(action_id))

    def close(self) -> None:
        """Ferme le transport du SDK."""
        closer = getattr(self._client, "close", None)
        if callable(closer):
            closer()


def sdk_search_paths() -> list[Path]:
    """Emplacements où chercher le SDK Python officiel (du plus explicite au plus implicite)."""
    paths: list[Path] = []
    for variable in ("THOT_SECURE_SDK_PATH", "THOT_SDK_PATH", "THOT_SDK_PATH"):
        value = env_first(variable)
        if value:
            paths.append(Path(value))
    here = Path(__file__).resolve()
    # examples/python-auto-mitigation/auto_mitigation.py → racine du dépôt
    for parent in here.parents:
        candidate = parent / "sdks" / "python"
        if candidate.is_dir():
            paths.append(candidate)
            break
        if (parent / "pyproject.toml").is_file():
            break
    return paths


def load_sdk_client() -> Any | None:
    """Importe ``ThotSecureClient`` depuis le SDK officiel, ou retourne ``None``.

    Toute erreur d'import est traitée comme « SDK indisponible » : l'exemple doit fonctionner
    partout, y compris sans le dépôt complet (le client embarqué prend alors le relais).
    """
    for path in sdk_search_paths():
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))
    for module_name in ("thotsecure_sdk", "thotsecure_sdk"):
        # Un nom de module absent n'est pas une erreur : on passe au suivant, et l'absence
        # totale laisse le client embarqué prendre le relais (voir `sdk_search_paths`).
        module = None
        with _contextlib.suppress(Exception):
            module = __import__(module_name, fromlist=["*"])
        if module is None:
            continue
        for attribute in ("ThotSecureClient", "ThotSecureClient"):
            client_class = getattr(module, attribute, None)
            if client_class is not None:
                return client_class
    return None


def build_api(args: argparse.Namespace) -> Any:
    """Construit le client d'API : SDK officiel si disponible, sinon client embarqué."""
    if not args.no_sdk:
        client_class = load_sdk_client()
        if client_class is not None:
            try:
                client = client_class(
                    base_url=args.url,
                    api_key=args.api_key,
                    tenant_id=args.tenant_id,
                    timeout=args.timeout,
                )
                return SdkApi(client)
            except Exception as exc:
                warn(
                    f"SDK Python présent mais inutilisable ({exc}) : repli sur le client embarqué."
                )
    return HttpApi(args.url, args.api_key, timeout=args.timeout)


# --------------------------------------------------------------------------------------
# Affichage : état de sûreté, findings, plan
# --------------------------------------------------------------------------------------


def warn(message: str) -> None:
    """Avertissement sur stderr (jamais de secret dans les messages)."""
    print(f"[mitigation] {message}", file=sys.stderr, flush=True)


def info(message: str) -> None:
    """Information sur stderr."""
    print(f"[mitigation] {message}", file=sys.stderr, flush=True)


def info_verbose(args: argparse.Namespace, message: str) -> None:
    """Information détaillée, uniquement avec ``--verbose``."""
    if getattr(args, "verbose", False):
        info(message)


def rule(title: str = "") -> None:
    """Séparateur lisible (les déroulés d'incident sont lus dans la panique : la lisibilité compte)."""
    print("\n" + "=" * 78)
    if title:
        print(title)
        print("=" * 78)


def read_bool(mapping: Mapping[str, Any], *keys: str) -> bool | None:
    """Lit le premier booléen défini parmi *keys* (``None`` si absent)."""
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in ("true", "1", "yes", "on", "oui"):
                    return True
                if lowered in ("false", "0", "no", "off", "non"):
                    return False
    return None


def describe_safety_state(version: Mapping[str, Any], whoami: Mapping[str, Any]) -> dict[str, Any]:
    """Résume l'état de sûreté renvoyé par ``GET /version`` (+ ``whoami`` s'il est disponible).

    Retourne ``{"dry_run": bool|None, "autonomy": str|None, "tenant_mode": str|None,
    "environment": str|None, "role": str|None, "capabilities": list[str]}``.
    """
    autonomy = None
    for key in ("autonomy", "autonomy_mode", "tenant_mode", "mode", "default_mode"):
        value = version.get(key) or whoami.get(key)
        if isinstance(value, str) and value:
            autonomy = value
            break

    dry_run = read_bool(version, "dry_run", "dryrun", "DRY_RUN")
    if dry_run is None:
        dry_run = read_bool(whoami, "dry_run", "dryrun")

    capabilities = whoami.get("capabilities")
    return {
        "dry_run": dry_run,
        "autonomy": autonomy,
        "tenant_mode": version.get("tenant_mode") or whoami.get("tenant_mode"),
        "environment": version.get("environment") or whoami.get("environment"),
        "version": version.get("version"),
        "role": whoami.get("role"),
        "capabilities": list(capabilities) if isinstance(capabilities, (list, tuple)) else [],
    }


def print_safety_state(state: Mapping[str, Any], *, api_label: str, url: str) -> None:
    """Affiche **en clair** l'état de sûreté avant toute action.

    C'est la première chose que l'opérateur doit voir : dans quel mode l'instance fonctionne, si
    les actions sont simulées, avec quel rôle il agit. Une contre-mesure déclenchée sans savoir
    dans quel mode on se trouve est exactement ce qu'il ne faut pas faire.
    """
    rule("ÉTAT DE SÛRETÉ DE L'INSTANCE (GET /version, §4.1)")
    print(f"  Instance            : {safe_url(url)}")
    print(f"  Client d'API        : {api_label}")
    print("  Version             : %s" % (state.get("version") or "inconnue"))
    if state.get("environment"):
        print("  Environnement       : {}".format(state["environment"]))
    if state.get("role"):
        print("  Rôle de la clé      : {}".format(state["role"]))
    if state.get("capabilities"):
        print("  Capacités           : {}".format(", ".join(str(c) for c in state["capabilities"])))

    autonomy = state.get("autonomy")
    print("  Mode d'autonomie    : %s" % (autonomy or "non annoncé par l'API"))
    if autonomy == "auto":
        print(
            "    ⚠ mode « auto » : le moteur de décision peut exécuter des contre-mesures SANS\n"
            "      approbation humaine. Ce script n'en déclenche aucune de lui-même — vérifiez que\n"
            "      ce mode est bien une décision consciente, limitée, journalisée et réversible."
        )
    elif autonomy == "supervised":
        print("    ✔ mode « supervised » : approbation humaine requise (défaut recommandé).")
    elif autonomy == "manual":
        print("    ✔ mode « manual » : aucune action automatique.")
    else:
        print(
            "    ? mode d'autonomie illisible : considérez que l'approbation humaine est\n"
            "      obligatoire et vérifiez la configuration du tenant avant d'aller plus loin."
        )

    dry_run = state.get("dry_run")
    if dry_run is True:
        print(
            "  Dry-run             : ACTIVÉ (true)\n"
            "    ⚠ AUCUNE action réelle ne sera exécutée. L'API renverra une SIMULATION :\n"
            "      le plan sera construit, approuvé et « exécuté » sans aucun effet de bord.\n"
            "      Ne concluez jamais qu'une adresse a été bloquée dans ce mode."
        )
    elif dry_run is False:
        print(
            "  Dry-run             : désactivé (false)\n"
            "    ⚠ Les actions réellement exécutées AURONT un effet sur la production.\n"
            "      Vérifiez la cible et le playbook avant de confirmer."
        )
    else:
        print(
            "  Dry-run             : non annoncé par l'API — supposez le pire et considérez que\n"
            "                        les actions peuvent être réelles."
        )


def format_finding_line(finding: Mapping[str, Any]) -> str:
    """Ligne de synthèse d'un finding (sévérité, score, règle, titre, cible)."""
    labels = finding.get("labels") if isinstance(finding.get("labels"), Mapping) else {}
    target = extract_target(finding) or labels.get("src_ip") or "?"
    return "#{:<3} {:<8} risque {:<6} {:<12} {} (cible : {})".format(
        _short_id(finding.get("finding_id")),
        finding.get("severity") or "?",
        _format_score(finding.get("risk_score")),
        finding.get("rule_id") or "?",
        _truncate(str(finding.get("title") or ""), 60),
        target,
    )


def _short_id(value: Any) -> str:
    """Identifiant abrégé (les UUID complets saturent l'affichage)."""
    text = str(value or "?")
    return text[:8]


def _format_score(value: Any) -> str:
    """Score de risque lisible (``78.5`` → ``78.5``, ``None`` → ``?``)."""
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return "?"


def _truncate(text: str, width: int) -> str:
    """Tronque une chaîne à *width* caractères, avec ellipse."""
    return text if len(text) <= width else text[: width - 1] + "…"


def extract_target(finding: Mapping[str, Any]) -> str | None:
    """Déduit la cible d'une action depuis un finding (``labels.src_ip``, preuves, description).

    Le contrat §6 indique ``target: labels.src_ip`` : c'est la convention que l'on applique, avec
    repli sur les échantillons de preuve, puis sur la première IP citée dans le titre.
    """
    labels = finding.get("labels")
    if isinstance(labels, Mapping):
        for key in ("src_ip", "source_ip", "client_ip", "remote_addr", "ip", "target"):
            value = labels.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    evidence = finding.get("evidence")
    if isinstance(evidence, Mapping):
        samples = evidence.get("samples")
        if isinstance(samples, list):
            for sample in samples:
                if isinstance(sample, Mapping):
                    sample_labels = sample.get("labels")
                    if isinstance(sample_labels, Mapping):
                        for key in ("src_ip", "source_ip", "client_ip", "remote_addr", "ip"):
                            value = sample_labels.get(key)
                            if isinstance(value, str) and value.strip():
                                return value.strip()

    haystack = "{} {}".format(finding.get("title") or "", finding.get("description") or "")
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\bip-[0-9a-f]{32}\b", haystack)
    return match.group(0) if match else None


def guess_target_type(target: str) -> str:
    """Type de cible annoncé dans ``Action.target`` (§3.4) : ``ip`` ou ``unknown``."""
    if re.fullmatch(r"ip-[0-9a-f]{32}", target or ""):
        return "ip"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", target or ""):
        return "ip"
    if ":" in (target or "") and re.fullmatch(r"[0-9A-Fa-f:]+(?:/\d{1,3})?", target or ""):
        return "ip"
    return "unknown"


def print_plan(action: Mapping[str, Any], *, live: bool) -> None:
    """Affiche **l'intégralité** du plan d'action, puis sa lecture en français.

    L'opérateur doit approuver ce qu'il voit : le JSON complet est donc imprimé, suivi d'une
    synthèse (playbook, cible, durée, réversibilité, expiration) — pas l'inverse.
    """
    rule("PLAN D'ACTION COMPLET (Action §3.4, aucun effet de bord à ce stade)")
    print(json.dumps(action, ensure_ascii=False, indent=2, default=str))

    params = action.get("params") if isinstance(action.get("params"), Mapping) else {}
    target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
    rollback = action.get("rollback") if isinstance(action.get("rollback"), Mapping) else {}

    print("\n  Lecture du plan :")
    print("    action_id        : %s" % (action.get("action_id") or "?"))
    print("    playbook         : %s" % (action.get("playbook") or "?"))
    print("    statut           : %s" % (action.get("status") or "?"))
    print("    mode             : %s" % (action.get("mode") or "?"))
    print("    policy_id        : %s" % (action.get("policy_id") or "?"))
    print(
        "    cible            : {} ({})".format(
            target.get("value") or params.get("target") or "?", target.get("type") or "?"
        )
    )
    if params.get("duration_seconds") is not None:
        print("    durée            : {} s".format(params.get("duration_seconds")))
    print("    demandé par      : %s" % (action.get("requested_by") or "?"))
    print("    demandé le       : %s" % (action.get("requested_at") or "?"))
    print("    expire le        : %s" % (action.get("expires_at") or "?"))
    print("    idempotency_key  : %s" % (action.get("idempotency_key") or "?"))
    print(
        "    audit_seq        : %s"
        % (action.get("audit_seq") if action.get("audit_seq") is not None else "?")
    )
    print("    rollback prévu   : %s" % ("oui" if rollback.get("available") else "NON"))

    plan_dry_run = read_bool(action, "dry_run")
    print(
        "    dry_run (plan)   : %s"
        % ("true — simulation" if plan_dry_run else "false — effet réel si exécuté")
    )
    if plan_dry_run and live:
        print(
            "    ⚠ Vous avez demandé --live (dry_run=false) mais l'API a renvoyé un plan en\n"
            "      simulation : le garde-fou global DRY_RUN est prioritaire (§6, garde-fou 4).\n"
            "      Rien ne sera appliqué, quoi qu'il arrive."
        )
    elif plan_dry_run:
        print(
            "    i Plan construit en simulation (--live non demandé) : l'exécution sera une\n"
            "      répétition à blanc. Ajoutez --live pour une contre-mesure réelle."
        )

    if not rollback.get("available"):
        print(
            "    ⚠ Ce playbook ne semble PAS réversible. L'invariant 3 du contrat exige un rollback :\n"
            "      refusez d'exécuter un playbook non réversible sans décision explicite documentée."
        )

    if not params.get("duration_seconds"):
        print(
            "    ⚠ Aucune durée de contre-mesure : préférez un blocage temporaire et borné\n"
            "      (--duration-seconds) à un blocage permanent."
        )


# --------------------------------------------------------------------------------------
# Confirmations interactives
# --------------------------------------------------------------------------------------


def is_interactive() -> bool:
    """``True`` si l'entrée standard est un terminal (donc si l'on peut demander confirmation)."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (ValueError, OSError):  # flux fermé ou redirigé
        return False


def confirm_plan(args: argparse.Namespace) -> bool:
    """Demande une confirmation **explicite** avant d'approuver le plan.

    Trois cas, volontairement stricts :

    * ``--yes`` : l'opérateur a déjà assumé la décision (pipeline revu, journalisé) ;
    * terminal interactif **sans** ``--yes`` : il faut taper exactement ``OUI`` ;
    * mode non interactif **sans** ``--yes`` : refus. Un script ne peut pas approuver une
      contre-mesure par accident parce que personne ne regardait.
    """
    if args.yes:
        info("--yes : confirmation fournie en ligne de commande (décision assumée et journalisée).")
        return True

    if not is_interactive():
        warn(
            "entrée standard non interactive et --yes absent : refus d'approuver automatiquement.\n"
            "  Une contre-mesure ne s'approuve pas par accident. Relancez dans un terminal, ou\n"
            "  utilisez --yes en assumant explicitement la décision (et sa journalisation)."
        )
        return False

    print(f"\n  Pour approuver ce plan, tapez {CONFIRMATION_WORD} (toute autre réponse annule) :")
    try:
        answer = input("  confirmation > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        warn("confirmation interrompue : plan non approuvé.")
        return False
    if answer != CONFIRMATION_WORD:
        warn(f"confirmation refusée (réponse : {answer[:20]!r}) : plan non approuvé.")
        return False
    return True


def ask_rollback(args: argparse.Namespace) -> bool:
    """Propose le rollback après une exécution réussie (``--rollback`` ou interaction)."""
    if args.no_rollback:
        info(
            "--no-rollback : action laissée en place (le rollback reste possible depuis l'API/CLI)."
        )
        return False
    if args.rollback:
        info("--rollback : rollback immédiat demandé.")
        return True
    if not is_interactive():
        info(
            "mode non interactif : aucun rollback déclenché automatiquement. L'action reste "
            "réversible via « thotsecure actions rollback <id> » tant que le rollback n'a pas expiré."
        )
        return False
    print("\n  Annuler immédiatement cette contre-mesure (rollback) ? [o/N]")
    try:
        answer = input("  rollback > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        warn("réponse non lue : rollback non déclenché.")
        return False
    return answer in ("o", "oui", "y", "yes")


# --------------------------------------------------------------------------------------
# Déroulé principal
# --------------------------------------------------------------------------------------


def select_finding(
    findings: Sequence[Mapping[str, Any]], args: argparse.Namespace
) -> Mapping[str, Any] | None:
    """Sélectionne le finding à traiter : ``--finding-id``, ``--index``, sinon le plus risqué."""
    if not findings:
        return None
    if args.finding_id:
        wanted = str(args.finding_id)
        for finding in findings:
            if str(finding.get("finding_id")) == wanted or str(
                finding.get("finding_id")
            ).startswith(wanted):
                return finding
        warn(
            f"finding {wanted} introuvable parmi les findings ouverts retournés (min_risk={args.min_risk})."
        )
        return None
    index = max(0, int(args.index) - 1)
    if index >= len(findings):
        warn(f"--index {args.index} hors bornes : {len(findings)} finding(s) disponible(s).")
        return None
    return findings[index]


def playbook_flags(playbooks: Sequence[Mapping[str, Any]], name: str) -> dict[str, Any]:
    """Retourne les métadonnées d'un playbook (``reversible``, ``dry_run_capable``…), ou ``{}``."""
    for playbook in playbooks:
        if str(playbook.get("name")) == name:
            return dict(playbook)
    return {}


def execute_workflow(args: argparse.Namespace, api: Any) -> int:
    """Déroulé complet : état de sûreté → findings → plan → approbation → exécution → rollback."""
    # ------------------------------------------------------------------ 1. état de sûreté
    try:
        version = api.version()
    except ApiError as exc:
        warn(f"GET /version a échoué : {exc}")
        warn("vérifiez l'URL (--url) et que l'instance Thot Secure répond sur /version (§4.1).")
        return 2
    except TransportError as exc:
        warn(f"instance injoignable : {exc}")
        return 1

    whoami: dict[str, Any] = {}
    try:
        whoami = api.whoami()
    except (ApiError, TransportError) as exc:
        info_verbose(
            args,
            f"GET /api/v1/auth/whoami indisponible ({exc}) : poursuite sans capacités détaillées.",
        )

    state = describe_safety_state(version, whoami)
    print_safety_state(state, api_label=getattr(api, "label", "client inconnu"), url=args.url)

    if state.get("dry_run") is True:
        warn(
            "DRY_RUN est actif sur cette instance : rien de ce qui suit n'aura d'effet réel. "
            "Le déroulé reste utile pour valider le plan et l'enchaînement des décisions."
        )

    # ------------------------------------------------------------------ 2. findings ouverts
    rule(
        f"FINDINGS OUVERTS (GET /api/v1/findings?status={args.status}&min_risk={args.min_risk}, §4.4)"
    )
    try:
        findings = api.list_findings(
            status=args.status, min_risk=args.min_risk, limit=args.limit, sort="risk_score"
        )
    except ApiError as exc:
        warn(f"lecture des findings refusée : {exc}")
        if exc.status in (401, 403):
            warn(
                "capacité « read:findings » manquante : créez une clé de rôle responder+ "
                "(thotsecure key create --tenant <id> --role responder --label mitigation)."
            )
            return 2
        return 1
    except TransportError as exc:
        warn(f"lecture des findings impossible : {exc}")
        return 1

    if not findings:
        print(f"  Aucun finding {args.status} avec risk_score ≥ {args.min_risk} : rien à traiter.")
        print("  C'est le résultat attendu quand la détection n'a rien remonté au-dessus du seuil.")
        return 0

    for finding in findings:
        print(f"  {format_finding_line(finding)}")

    finding = select_finding(findings, args)
    if finding is None:
        return 2

    rule("FINDING RETENU")
    print(json.dumps(dict(finding), ensure_ascii=False, indent=2, default=str))

    finding_id = str(finding.get("finding_id") or "")
    if not finding_id:
        warn("le finding retourné n'a pas de finding_id : réponse d'API inexploitable.")
        return 1

    # ------------------------------------------------------------------ 3. plan d'action
    target = args.target or extract_target(finding)
    if not target and args.playbook in ("block-source-ip", "rate-limit-source"):
        warn(
            "aucune cible (IP source) trouvée dans le finding : précisez --target explicitement.\n"
            "  Rappel : la cible doit appartenir au périmètre déclaré du tenant ; les cibles de\n"
            "  l'autonomy_allowlist (infra propre) sont protégées et refusées par le moteur (§6)."
        )
        return 2

    params: dict[str, Any] = {}
    if target:
        params["target"] = target
    if args.duration_seconds:
        params["duration_seconds"] = int(args.duration_seconds)
    if args.reason:
        params["reason"] = args.reason

    playbooks: list[dict[str, Any]] = []
    try:
        playbooks = api.list_playbooks()
    except (ApiError, TransportError) as exc:
        info_verbose(
            args,
            f"liste des playbooks indisponible ({exc}) : poursuite sans validation du playbook.",
        )
    flags = playbook_flags(playbooks, args.playbook)
    if flags:
        print(
            "\n  Playbook « {} » : réversible={}, dry_run_capable={}, connecteurs={}".format(
                args.playbook,
                flags.get("reversible"),
                flags.get("dry_run_capable"),
                ", ".join(str(c) for c in (flags.get("connectors") or [])) or "?",
            )
        )
        if flags.get("reversible") is False:
            warn(
                "ce playbook est annoncé NON réversible : l'invariant 3 du contrat exige un "
                "rollback. N'exécutez pas sans décision explicite et documentée."
            )
            if not args.force_irreversible:
                warn("arrêt : ajoutez --force-irreversible après avoir assumé cette décision.")
                return 3
    elif playbooks:
        warn(
            f"playbook « {args.playbook} » inconnu de l'instance : le plan sera refusé par le serveur."
        )

    live = bool(args.live)
    if live:
        warn(
            "--live : le plan est demandé en dry_run=false. Si l'instance est en DRY_RUN global, "
            "le garde-fou reste prioritaire et l'exécution sera simulée."
        )

    try:
        action = api.plan_action(finding_id, args.playbook, params=params, dry_run=not live)
    except ApiError as exc:
        warn(f"POST /api/v1/actions/plan refusé : {exc}")
        if exc.details:
            warn(f"détails : {json.dumps(exc.details, ensure_ascii=False, default=str)[:600]}")
        if exc.status == 409:
            warn(
                "conflit : cooldown en cours, plafond horaire atteint, ou cible protégée par "
                "l'autonomy_allowlist (garde-fous §6, non contournables par une politique)."
            )
        return 1 if exc.status >= 500 else 2
    except TransportError as exc:
        warn(f"planification impossible : {exc}")
        return 1

    if not action.get("action_id"):
        warn("la réponse de planification ne contient pas d'action_id : réponse inexploitable.")
        return 1

    print_plan(action, live=live)
    action_id = str(action["action_id"])

    # ------------------------------------------------------------------ 4. confirmation
    rule("CONFIRMATION HUMAINE OBLIGATOIRE")
    print(
        "  Vous allez approuver puis exécuter le playbook « {} » sur la cible « {} ».\n"
        "  Vérifiez que cette cible est bien celle que vous voulez neutraliser, et qu'elle\n"
        "  n'appartient pas à votre propre infrastructure.".format(
            action.get("playbook") or args.playbook,
            (action.get("target") or {}).get("value") or target or "?",
        )
    )
    if not confirm_plan(args):
        warn(
            "plan laissé à l'état « {} » : rien n'a été approuvé ni exécuté. L'action expire "
            "d'elle-même et reste consultable via GET /api/v1/actions/{}.".format(
                action.get("status"), action_id
            )
        )
        return 3

    # ------------------------------------------------------------------ 5. approbation
    status = str(action.get("status") or "")
    rule(f"APPROBATION (POST /api/v1/actions/{action_id}/approve, §4.6)")
    if status in ("planned", "pending_approval"):
        try:
            approved = api.approve_action(
                action_id,
                comment=args.comment
                or "Approbation explicite via examples/python-auto-mitigation (opérateur %s)"
                % (state.get("role") or "inconnu"),
            )
        except ApiError as exc:
            warn(f"approbation refusée : {exc}")
            if exc.status in (401, 403):
                warn("capacité « approve:actions » manquante (rôle responder minimum, §4).")
            return 2 if exc.status < 500 else 1
        except TransportError as exc:
            warn(f"approbation impossible : {exc}")
            return 1
        print(
            "  Statut après approbation : {} (approved_by={} à {})".format(
                approved.get("status"), approved.get("approved_by"), approved.get("approved_at")
            )
        )
        action = approved or action
    elif status == "approved":
        warn(
            "l'action est déjà « approved » : une politique en mode auto l'a approuvée sans "
            "intervention. C'est exactement ce que fait le mode auto — vérifiez que c'est voulu."
        )
    else:
        warn(f"statut inattendu avant exécution : {status!r} — arrêt par prudence.")
        return 1

    # ------------------------------------------------------------------ 6. exécution
    rule(f"EXÉCUTION (POST /api/v1/actions/{action_id}/execute, §4.6)")
    try:
        executed = api.execute_action(action_id)
    except ApiError as exc:
        warn(f"exécution refusée : {exc}")
        if exc.status == 409:
            warn("conflit : action non approuvée, déjà exécutée, ou rollback déjà effectué.")
        return 1
    except TransportError as exc:
        warn(f"exécution impossible : {exc}")
        warn(
            "l'état réel de l'action est incertain : vérifiez avec "
            f"« thotsecure actions list » ou GET /api/v1/actions/{action_id} avant toute nouvelle tentative."
        )
        return 1

    print(json.dumps(dict(executed), ensure_ascii=False, indent=2, default=str))
    final_status = str(executed.get("status") or "")
    executed_dry_run = read_bool(executed, "dry_run")
    result = executed.get("result") if isinstance(executed.get("result"), Mapping) else {}
    simulated = bool(result.get("simulated")) if isinstance(result, Mapping) else False

    print("\n  Résultat :")
    print("    statut      : %s" % (final_status or "?"))
    print("    dry_run     : %s" % ("true (simulation)" if executed_dry_run else "false"))
    print("    executed_at : %s" % (executed.get("executed_at") or "?"))
    if isinstance(result, Mapping) and result:
        print(f"    result      : {json.dumps(result, ensure_ascii=False, default=str)[:600]}")

    if executed_dry_run or simulated:
        rule("⚠ SIMULATION — AUCUNE ACTION RÉELLE N'A ÉTÉ EXÉCUTÉE")
        print(
            "  L'instance est en dry_run (garde-fou §6, prioritaire sur toute politique) :\n"
            "  le playbook a été parcouru sans effet de bord et aucun connecteur n'a été appelé.\n"
            "  Ne considérez donc PAS la cible comme bloquée. Pour une contre-mesure réelle :\n"
            "    - lever DRY_RUN au niveau du tenant (THOT_DRY_RUN=false, décision tracée),\n"
            "    - puis relancer ce script avec --live."
        )
    elif final_status == "succeeded":
        print(
            "\n  ✔ Contre-mesure appliquée. Le rollback reste disponible jusqu'à %s."
            % (executed.get("expires_at") or "l'expiration annoncée")
        )
    elif final_status in ("failed", "expired"):
        warn(f"l'exécution s'est terminée en « {final_status} » : inspectez « result » ci-dessus.")
    else:
        warn(f"statut final inattendu « {final_status} » : vérifiez l'état de l'action.")

    # ------------------------------------------------------------------ 7. rollback
    rollback_info = (
        executed.get("rollback") if isinstance(executed.get("rollback"), Mapping) else {}
    )
    rule(f"ROLLBACK (POST /api/v1/actions/{action_id}/rollback, §4.6)")
    if not rollback_info.get("available"):
        print("  Ce playbook ne propose pas de rollback : l'action est définitive. Notez-le.")
        return 0
    print(
        "  Toute action doit rester réversible tant que le rollback n'a pas expiré (invariant 3)."
    )
    if not ask_rollback(args):
        print(
            "  Rollback non déclenché. Pour l'annuler plus tard :\n"
            f"    thotsecure actions rollback {action_id}\n"
            f"  ou : python auto_mitigation.py --rollback-action {action_id}"
        )
        return 0

    try:
        rolled_back = api.rollback_action(
            action_id, reason=args.rollback_reason or "Rollback demandé par l'opérateur"
        )
    except ApiError as exc:
        warn(f"rollback refusé : {exc}")
        if exc.status == 409:
            warn("rollback déjà effectué ou expiré (409, §4.6).")
        return 1
    except TransportError as exc:
        warn(f"rollback impossible : {exc}")
        return 1

    print(
        "  Statut après rollback : {} (performed_at={})".format(
            rolled_back.get("status"), (rolled_back.get("rollback") or {}).get("performed_at")
        )
    )
    if read_bool(rolled_back, "dry_run"):
        print("  (simulation : le rollback aussi a été parcouru à blanc, sans effet réel.)")
    return 0


def rollback_only(args: argparse.Namespace, api: Any) -> int:
    """Mode ``--rollback-action`` : annule une action existante sans redérouler tout le workflow.

    Utile en runbook d'incident : on annule d'abord, on analyse ensuite.
    """
    action_id = str(args.rollback_action)
    rule(f"ROLLBACK DIRECT DE L'ACTION {action_id}")
    try:
        action = api.get_action(action_id)
    except ApiError as exc:
        warn(f"action illisible : {exc}")
        return 1
    except TransportError as exc:
        warn(f"action illisible (réseau) : {exc}")
        return 1

    print(json.dumps(dict(action), ensure_ascii=False, indent=2, default=str))
    rollback_info = action.get("rollback") if isinstance(action.get("rollback"), Mapping) else {}
    if not rollback_info.get("available"):
        warn("cette action n'annonce pas de rollback disponible : rien à annuler.")
        return 3
    if not args.yes:
        if not is_interactive():
            warn("--yes requis pour un rollback non interactif (l'annulation doit être assumée).")
            return 2
        print(f"\n  Annuler cette action ? Tapez {CONFIRMATION_WORD} pour confirmer :")
        try:
            answer = input("  confirmation > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            warn("confirmation interrompue : rollback annulé.")
            return 130
        if answer != CONFIRMATION_WORD:
            warn("confirmation refusée : rollback annulé.")
            return 3

    try:
        rolled_back = api.rollback_action(
            action_id, reason=args.rollback_reason or "Rollback direct demandé"
        )
    except ApiError as exc:
        warn(f"rollback refusé : {exc}")
        return 1
    except TransportError as exc:
        warn(f"rollback impossible : {exc}")
        return 1
    print("  Statut après rollback : {}".format(rolled_back.get("status")))
    if read_bool(rolled_back, "dry_run"):
        print("  (simulation : aucun effet réel — l'instance est en dry_run.)")
    return 0


# --------------------------------------------------------------------------------------
# Interface en ligne de commande
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (``--help`` documente chaque option)."""
    parser = argparse.ArgumentParser(
        prog="auto_mitigation.py",
        description=(
            "Déroule une contre-mesure Thot Secure : état de sûreté, findings ouverts, plan, "
            "confirmation explicite, approbation, exécution, puis rollback proposé."
        ),
        epilog=(
            "Codes de sortie : 0 succès, 1 erreur d'exécution, 2 usage/configuration, "
            "3 refus de l'opérateur, 130 Ctrl-C."
        ),
    )
    parser.add_argument(
        "--url",
        default=env_first("THOT_SECURE_URL", "THOT_URL", default=DEFAULT_BASE_URL),
        help=f"base de l'API (défaut : $env:THOT_SECURE_URL, sinon $env:THOT_URL, sinon {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--api-key",
        default=env_first("THOT_SECURE_API_KEY", "THOT_API_KEY"),
        help="clé ao_… (défaut : $env:THOT_SECURE_API_KEY) ; préférez l'environnement",
    )
    parser.add_argument(
        "--tenant-id",
        default=env_first("THOT_SECURE_TENANT_ID", "THOT_TENANT_ID"),
        help="tenant ciblé (facultatif : le serveur le dérive de la clé)",
    )
    parser.add_argument(
        "--min-risk",
        type=float,
        default=DEFAULT_MIN_RISK,
        help=f"score de risque minimal des findings retenus (défaut {DEFAULT_MIN_RISK})",
    )
    parser.add_argument(
        "--status", default="open", help="statut des findings interrogés (défaut : open)"
    )
    parser.add_argument(
        "--limit", type=int, default=50, help="nombre de findings demandés (défaut 50)"
    )
    parser.add_argument("--finding-id", help="traiter ce finding précis (préfixe accepté)")
    parser.add_argument(
        "--index", type=int, default=1, help="rang du finding à traiter (défaut 1 = plus risqué)"
    )
    parser.add_argument(
        "--playbook",
        default=DEFAULT_PLAYBOOK,
        help=f"playbook à planifier (défaut : {DEFAULT_PLAYBOOK}, §7)",
    )
    parser.add_argument(
        "--target", help="cible explicite (IP/CIDR) ; par défaut : labels.src_ip du finding"
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=DEFAULT_DURATION_SECONDS,
        help=f"durée de la contre-mesure en secondes (défaut {DEFAULT_DURATION_SECONDS} ; 60 ≤ n ≤ 604800)",
    )
    parser.add_argument("--reason", help="motif transmis au playbook (journalisé)")
    parser.add_argument("--comment", help="commentaire d'approbation journalisé dans l'audit")
    parser.add_argument(
        "--live",
        action="store_true",
        help="demander un plan réel (dry_run=false) ; sans cette option, le plan est une simulation",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirmation explicite sans interaction (obligatoire en mode non interactif)",
    )
    parser.add_argument(
        "--rollback", action="store_true", help="déclencher le rollback juste après l'exécution"
    )
    parser.add_argument(
        "--no-rollback", action="store_true", help="ne pas proposer de rollback en fin de déroulé"
    )
    parser.add_argument("--rollback-reason", help="motif du rollback (journalisé dans l'audit)")
    parser.add_argument(
        "--rollback-action",
        metavar="ACTION_ID",
        help="mode autonome : annuler cette action et sortir (sans lister les findings)",
    )
    parser.add_argument(
        "--force-irreversible",
        action="store_true",
        help="autorise un playbook annoncé non réversible (décision à assumer et à documenter)",
    )
    parser.add_argument(
        "--no-sdk",
        action="store_true",
        help="ne pas utiliser le SDK Python officiel, même s'il est disponible",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(
            env_first("THOT_SECURE_TIMEOUT", "THOT_TIMEOUT", default=str(DEFAULT_TIMEOUT))
        ),
        help=f"délai d'attente par requête, en secondes (défaut {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="journalise les détails")
    parser.add_argument("--version", action="version", version="thotsecure-auto-mitigation 0.1.0")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> str | None:
    """Valide les arguments ; retourne un message d'erreur, ou ``None`` si tout est correct."""
    if args.timeout <= 0:
        return "--timeout doit être strictement positif"
    if args.duration_seconds and not (60 <= args.duration_seconds <= 604800):
        return (
            "--duration-seconds doit être compris entre 60 et 604800 (§7, playbook block-source-ip)"
        )
    if args.index < 1:
        return "--index commence à 1"
    if args.limit < 1:
        return "--limit doit être au moins 1"
    if args.rollback and args.no_rollback:
        return "--rollback et --no-rollback sont exclusifs"
    if not args.api_key:
        return (
            "clé API absente : définissez THOT_SECURE_API_KEY (ou THOT_API_KEY). "
            "Aucune action ne peut être planifiée ou annulée sans authentification (§4)."
        )
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée CLI. Retourne le code de sortie (voir la docstring du module)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    problem = validate_args(parser, args)
    if problem:
        warn(problem)
        return 2

    api = build_api(args)
    info_verbose(args, "client d'API : {}".format(getattr(api, "label", "inconnu")))
    info_verbose(args, f"instance : {safe_url(args.url)}")

    try:
        if args.rollback_action:
            return rollback_only(args, api)
        return execute_workflow(args, api)
    except KeyboardInterrupt:
        warn("Ctrl-C : interruption. Aucune nouvelle action n'a été déclenchée.")
        warn(
            "si une action venait d'être exécutée, vérifiez son état (GET /api/v1/actions) et "
            "annulez-la si nécessaire — une interruption ne doit pas laisser une contre-mesure "
            "orpheline."
        )
        return 130
    except TransportError as exc:
        warn(f"échec réseau : {exc}")
        return 1
    except ApiError as exc:
        warn(f"erreur d'API : {exc}")
        return 1
    finally:
        closer = getattr(api, "close", None)
        if callable(closer):
            with _contextlib.suppress(Exception):
                closer()


if __name__ == "__main__":
    sys.exit(main())
