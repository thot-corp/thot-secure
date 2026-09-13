# SDK Python Thot Secure

SDK officiel pour l'API REST Thot Secure v0.1.0 (SOAR/CSPM **défensif**).
Il couvre **l'intégralité** de la surface décrite par le contrat d'interface
(`docs/architecture/api-contract.md` §4), sans inventer de route.

## Zéro dépendance par défaut

* Aucune dépendance obligatoire : le SDK s'exécute sur la **bibliothèque standard** seule
  (`urllib.request`, `socket`, `hmac`, `json`…).
* Si `httpx` est importable, il est utilisé automatiquement (pool de connexions, HTTP/2 possible) ;
  sinon le SDK **bascule tout seul** sur `urllib.request`. Aucun changement de code requis.
* Le client WebSocket est écrit en stdlib pur (handshake RFC 6455 + trames) : pas besoin de
  `websockets` ni de `websocket-client`.
* Python ≥ 3.11.

## Installation

```powershell
# depuis le dépôt, sans rien installer (le paquet est importable tel quel)
$env:PYTHONPATH = "D:\niang\Documents\thotsecure\sdks\python"

# ou installation « éditable » classique
python -m pip install -e sdks/python

# avec l'accélération httpx (facultative)
python -m pip install -e "sdks/python[httpx]"
```

## Démarrage

```python
import os
from thotsecure_sdk import ThotSecureClient, normalize_event

with ThotSecureClient(
    base_url=os.environ["THOT_URL"],        # http://127.0.0.1:8080 par défaut
    api_key=os.environ["THOT_API_KEY"],     # ao_… — jamais en dur dans le code
    tenant_id="acme",
) as client:
    print(client.whoami())                       # rôle, capacités, mode d'autonomie
    print(client.healthz(), client.version())

    # 1) ingestion d'un événement normalisé depuis un log Nginx
    event = normalize_event(
        '203.0.113.9 - - [14/Feb/2026:10:00:00 +0000] "POST /login HTTP/1.1" 403 512 "-" "curl/8.5"',
        tenant_id="acme",
        source_name="prod-edge",
        ip_salt=os.environ.get("THOT_IP_SALT"),   # pseudonymisation RGPD des IP
    )
    print(client.ingest_event(event))

    # 2) findings
    for finding in client.iter_findings(status="open", severity="high", sort="risk_score"):
        print(finding.finding_id, finding.risk_score, finding.title)

    # 3) actions supervisées (dry-run par défaut)
    action = client.plan_action("f1c2", "block-source-ip", params={"target": "203.0.113.9"})
    client.approve_action(action.action_id, comment="validé par l'astreinte")
    client.execute_action(action.action_id, idempotency_key="acme:block:203.0.113.9:1")
    client.rollback_action(action.action_id)
```

Le client est un **context manager** (`__enter__` / `__exit__`) : `close()` libère le pool de
connexions. Il est utilisable sans `with` également (`client.close()` explicite).

### Configuration

| Paramètre | Variable d'environnement | Défaut |
|---|---|---|
| `base_url` | `THOT_URL` | `http://127.0.0.1:8080` |
| `api_key` | `THOT_API_KEY` | *(aucune — en-tête `X-API-Key`)* |
| `tenant_id` | `THOT_TENANT_ID` | *(aucun)* |
| `timeout` | `THOT_TIMEOUT` | `30.0` s |
| `max_retries` | `THOT_MAX_RETRIES` | `3` |
| `verify_tls` | `THOT_VERIFY_TLS` | `True` |

`verify_tls=False` **affiche un avertissement explicite** (et lève un `RuntimeWarning`) : à réserver
au développement local. En production, laissez la vérification active et utilisez `https://`.

> `tenant_id` sert de valeur par défaut aux routes préfixées par un tenant et à l'URL du WebSocket.
> Le cloisonnement réel est dérivé de la clé API côté serveur (contrat §1, invariant 4) : le SDK
> n'invente aucune en-tête non documentée.

## Couverture des familles de routes

| Famille (contrat) | Méthodes du client |
|---|---|
| §4.1 santé / méta | `healthz`, `readyz`, `version`, `metrics`, `whoami` |
| §4.2 tenants & clés | `list_tenants`, `create_tenant`, `get_tenant`, `update_tenant`, `create_key`, `list_keys`, `revoke_key` |
| §4.3 événements | `ingest_event`, `ingest_events` (≤ 500/lot, découpage auto), `list_events`, `get_event`, `iter_events` |
| §4.4 findings | `list_findings`, `get_finding`, `iter_findings`, `ack_finding`, `close_finding`, `suppress_finding`, `get_report` |
| §4.5 règles / politiques / playbooks | `list_rules`, `get_rule`, `validate_rule`, `reload_rules`, `list_policies`, `reload_policies`, `list_playbooks` |
| §4.6 actions SOAR | `plan_action`, `list_actions`, `get_action`, `iter_actions`, `approve_action`, `reject_action`, `execute_action`, `rollback_action` |
| §4.7 audit | `list_audit`, `iter_audit`, `verify_audit`, `export_audit` |
| §4.8 stats / collecteurs / flux | `stats_overview`, `list_collectors`, `run_collector`, `stream` (WebSocket) |

### Exemples par famille

```python
# --- tenants et clés (admin) ---
client.create_tenant("acme", "ACME SAS", mode="supervised", autonomy_allowlist=["10.0.0.0/8"])
created = client.create_key(role="responder", label="ci", tenant_id="acme")
print(created.key_id, created.api_key)     # api_key n'est affichée qu'UNE seule fois
for key in client.list_keys("acme"):
    print(key.key_id, key.role, key.revoked_at)
client.revoke_key(created.key_id)

# --- ingestion par lots (contre-pression maîtrisée) ---
for batch in chunked(iter_jsonl("events.jsonl"), 500):
    result = client.ingest_events(batch)
    print(result.accepted, result.rejected, len(result.findings))

# --- règles et politiques (admin) ---
print(client.validate_rule("id: AO-WEB-001\ntitle: Injection SQL\n").valid)
print(client.reload_rules())        # {"loaded": 12, "errors": []}
print(client.list_policies())       # politiques + ordre de priorité
print([p.name for p in client.list_playbooks()])

# --- rapport exploitable (Markdown/HTML/JSON/SARIF) ---
sarif = client.get_report("f1c2", format="sarif")           # à écrire dans un artefact CI
html = client.get_report("f1c2", format="html")

# --- audit ---
verification = client.verify_audit()                        # {"valid", "records", "broken_at"}
print(verification.valid, verification.records)
with open("audit.cef", "w", encoding="utf-8") as fh:
    fh.write(client.export_audit(format="cef", since="2026-02-14T00:00:00Z"))

# --- statistiques ---
stats = client.stats_overview()
print(stats.findings_by_severity, stats.autonomy_mode)

# --- collecteurs (toujours sur les cibles déclarées du tenant) ---
for collector in client.list_collectors():
    print(collector.name, collector.last_run_at)
client.run_collector("nginx")
```

### Flux temps réel (WebSocket stdlib pur)

```python
for frame in client.stream(types=["finding", "action"]):     # heartbeat filtré par défaut
    if frame.type == "finding":
        print(frame.data["finding_id"], frame.data["severity"], frame.data["risk_score"])
```

Le client gère la **reconnexion** (backoff exponentiel + jitter), le **ping/pong** et la détection
de connexion morte. Utilisation bas niveau :

```python
from thotsecure_sdk import WebSocketClient

with WebSocketClient(base_url="https://aegis.example", api_key=key, tenant_id="acme") as ws:
    for frame in ws.stream(types=["finding"], include_heartbeat=True):
        ...
```

L'URL du flux contient la clé API (les navigateurs ne posent pas d'en-tête sur `ws://`) :
utilisez `thotsecure_sdk.errors.redact_url(url)` **avant tout log**.

## Modèles typés

`Event`, `Finding`, `Decision`, `Action`, `AuditRecord`, `Tenant`, `ApiKey`, `Rule`, `Playbook`,
`StatsOverview`, `CollectorStatus`, `IngestResult`, `AuditVerification`, `Page`.

* Noms de champs **strictement** ceux du contrat §3 (`risk_score`, `severity_hint`, `audit_seq`…).
* `from_dict()` est **tolérant** : tout champ inconnu est conservé dans `extra` et réémis par
  `to_dict()` — une montée de version du serveur ne casse pas l'intégration.
* `to_dict(omit_none=True)` produit un corps de requête compact.

```python
finding = client.get_finding("f1c2")
print(finding.risk_score, finding.extra.get("actions"))   # actions liées
```

## Erreurs

```python
from thotsecure_sdk import (
    ThotSecureError, AuthenticationError, PermissionDeniedError, NotFoundError,
    ConflictError, ValidationError, RateLimitedError, ServerError, TransportError,
)

try:
    client.execute_action(action_id)
except ConflictError as exc:              # 409 : action non approuvée / déjà exécutée
    print(exc.code, exc.message, exc.details)
except RateLimitedError as exc:           # 429 : respectez `retry_after`
    time.sleep(exc.retry_after or 5)
except PermissionDeniedError:             # 403 : capacité RBAC manquante
    ...
except ServerError:                       # 5xx
    ...
```

| Exception | HTTP | `error.code` du contrat |
|---|---|---|
| `ValidationError` | 400 / 422 | `validation_error`, `unprocessable` |
| `AuthenticationError` | 401 | `unauthenticated` |
| `PermissionDeniedError` | 403 | `forbidden` |
| `NotFoundError` | 404 | `not_found` |
| `ConflictError` | 409 | `conflict` |
| `RateLimitedError` | 429 | `rate_limited` (+ attribut `retry_after`) |
| `ServerError` | 5xx | `internal_error` |
| `TransportError` / `WebSocketError` | — | erreur réseau, DNS, TLS, handshake |

Le code `error.code` du contrat prime sur le statut HTTP. Aucune exception, aucun `repr()` de
client et aucune trace de log ne contient la clé API.

## Retries et idempotence

* Réessai automatique sur `429`, `502`, `503`, `504` et sur erreur réseau.
* Backoff exponentiel plafonné avec jitter multiplicatif (`[0.5, 1.0]`).
* En-tête `Retry-After` respecté lorsqu'il est présent (plafonné à 60 s par défaut).
* **Une méthode non idempotente n'est jamais réessayée sans clé d'idempotence explicite** :

```python
client.execute_action(action_id, idempotency_key="acme:block-source-ip:203.0.113.9:1739527200")
# → envoyée en en-tête `Idempotency-Key` et dans le corps ; l'appel devient réessayable en sécurité.
```

## Helpers d'intégration

```python
from thotsecure_sdk import (
    normalize_event, from_syslog_line, redact_secrets,
    pseudonymize_ip, pseudonymize_ip_fields, iter_jsonl, chunked, truncate_payload,
)

# Log HTTP (Nginx/Apache combined & common, ou ligne JSON structurée) → Event conforme
event = normalize_event(nginx_line, tenant_id="acme", source_name="edge-01")

# Syslog RFC 3164 / RFC 5424 → Event kind="syslog" (sévérité PRI → severity_hint)
syslog_event = from_syslog_line("<34>Feb 14 10:00:00 edge sshd[123]: Failed password…", tenant_id="acme")

# Masquage : authorization, cookie, set-cookie, password, token, api_key, JWT…
safe = redact_secrets({"headers": {"Authorization": "Bearer …", "Cookie": "sid=1"}})

# RGPD : pseudonymisation HMAC-SHA256 déterministe des adresses IP
pseudo = pseudonymize_ip("203.0.113.9", salt=os.environ["THOT_IP_SALT"])
```

**RGPD — à lire.** Une adresse IP est une donnée à caractère personnel. Si vous ingérez des logs
contenant des IP de personnes (clients, salariés), pseudonymisez-les à la source avec un sel
d'organisation stocké hors du dépôt :

* `normalize_event(..., ip_salt=SALT)` pseudonymise automatiquement `labels.src_ip` et tous les
  champs d'adresse (`src_ip`, `dst_ip`, `client_ip`, `remote_addr`, `x_forwarded_for`…) ;
* sans sel, la pseudonymisation serait réversible par force brute : le SDK **refuse** un sel vide ;
* conservez le sel dans un coffre-fort de secrets, jamais dans le code ni dans un log.

## Tests

```powershell
python -m unittest discover -s sdks/python/tests -t sdks/python -v
```

134 tests, **aucun réseau** : la couche transport est simulée (`FakeTransport` injecté), et la
logique WebSocket est testée sur une paire de sockets locale (`socket.socketpair`) et sur les
fonctions pures d'encodage de trames.

## Conception, en bref

* `thotsecure_sdk/transport.py` — transport HTTP injectable (`urllib` par défaut, `httpx` si présent)
  + décorateur de retry. Injecter un transport, c'est ce qui rend le SDK testable hors ligne.
* `thotsecure_sdk/client.py` — surface REST complète, pagination par curseur, découpage des lots.
* `thotsecure_sdk/models.py` — dataclasses du contrat, tolérantes aux champs inconnus.
* `thotsecure_sdk/errors.py` — hiérarchie typée + mapping `error.code`.
* `thotsecure_sdk/ws.py` — WebSocket RFC 6455 en stdlib pure.
* `thotsecure_sdk/helpers.py` — normalisation de logs, redaction, pseudonymisation, JSONL.

Licence : Apache-2.0.
