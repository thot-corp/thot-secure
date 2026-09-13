# Thot Secure — Contrat d'interface v0.1.0 (MVP)

> **Statut : GELÉ pour le sprint 1.** Tout code (API, CLI, SDK, UI, IaC, docs) doit se conformer
> exactement à ce document. Toute divergence doit être discutée avant merge.
>
> Thot Secure est un **SOAR/CSPM défensif** : collecte, détection, scoring, décision, contre-mesure
> réversible. **Aucune capacité offensive** (pas de scan agressif, pas de brute force, pas de
> hack-back, pas de DoS, pas d'exploitation de tiers).

---

## 1. Vocabulaire et invariants

| Terme | Définition |
|---|---|
| **Tenant** | Frontière d'isolation (un client MSP, un BU, un labo). Tout objet porte `tenant_id`. |
| **Événement** | Fait brut normalisé émis par un collecteur. Immuable. |
| **Finding** | Agrégat d'événements déclenché par une règle, porteur d'un `risk_score`. |
| **Politique** | Règle de décision *policy-as-code* (YAML, ou Rego via OPA si binaire présent). |
| **Playbook** | Procédure d'action nommée, **toujours** accompagnée d'un rollback. |
| **Action** | Instance d'exécution d'un playbook sur un finding, avec cycle de vie et audit. |
| **Audit log** | Journal append-only chaîné par hash (détection de falsification). |

**Invariants non négociables**

1. `DRY_RUN=true` par défaut. Aucune action réelle n'est exécutée sans levée explicite.
2. Toute action critique passe par `require_approval` **ou** par un mode `auto` explicitement
   activé au niveau du tenant, et est journalisée (`actor`, `policy_id`, `before`, `after`).
3. Toute action est **réversible** : `POST /actions/{id}/rollback` doit réussir tant que le
   rollback n'a pas expiré.
4. Isolation stricte : un appelant ne voit jamais les données d'un autre tenant (testé en CI).
5. Le core (`thotsecure.core`) ne dépend que de la **stdlib** + `pydantic`/`PyYAML`. FastAPI,
   Jinja2 et uvicorn sont des dépendances de la couche API.

---

## 2. Arborescence cible

```
thotsecure/
├── src/thotsecure/            # code applicatif (package installable)
│   ├── core/                # config, modèles, erreurs, utils (stdlib + pydantic)
│   ├── storage/             # persistance SQLite (+ DDL PostgreSQL/TimescaleDB)
│   ├── bus/                 # bus d'événements: memory | sqlite | nats
│   ├── audit/               # journal chaîné immuable
│   ├── tenancy/             # tenants, clés API, RBAC
│   ├── collectors/          # collecteurs défensifs + normalisation
│   ├── detection/           # moteur de règles YAML (+ compat Sigma-lite)
│   ├── scoring/             # scoring de risque
│   ├── decision/            # policy-as-code + gate d'approbation
│   ├── actions/             # playbooks, exécuteurs, rollback
│   ├── reports/             # markdown | html | json | sarif | cef
│   ├── api/                 # FastAPI (v1), WebSocket, /metrics
│   ├── ui/                  # console embarquée (Jinja2 + JS, zéro build)
│   ├── cli.py
│   └── sdk/                 # client Python officiel (utilisable en lib)
├── rules/                   # bibliothèque de détection YAML (livrée)
├── policies/                # politiques de décision YAML + rego/
├── playbooks/               # playbooks YAML (action + rollback)
├── sdks/{python,typescript,go}/
├── web/                     # dashboard React+TS (build Vite, optionnel)
├── deploy/                  # Dockerfile, compose, k8s, helm, terraform, ansible
├── docs/                    # MkDocs Material
├── content/                 # artefacts éditoriaux (blog, forums, réseaux, vidéo)
└── tests/                   # unittest (compatible pytest)
```

---

## 3. Schémas de données (JSON canonique)

### 3.1 Event

```json
{
  "event_id": "e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11",
  "schema_version": "1",
  "tenant_id": "acme",
  "ts": "2026-02-14T10:00:00.123Z",
  "kind": "http.request",
  "source": { "type": "web_probe", "name": "prod-edge", "host": "shop.acme.fr" },
  "severity_hint": "info",
  "labels": { "src_ip": "203.0.113.9", "path": "/login", "method": "POST" },
  "payload": { "status": 403, "bytes": 512, "user_agent": "curl/8.5" },
  "raw_ref": null
}
```

* `kind` (énuméré) : `http.request`, `http.response`, `log.line`, `tls.cert`, `dependency`,
  `config.audit`, `syslog`, `generic`.
* `severity_hint` ∈ `info|low|medium|high|critical|null`.
* `labels` : **plat**, valeurs scalaires uniquement → sert d'espace de nommage aux règles
  (`labels.src_ip`, `payload.status`).
* Contrainte de taille : `payload` ≤ 32 Kio sérialisé ; au-delà, tronqué et `raw_ref` renseigné.

### 3.2 Finding

```json
{
  "finding_id": "f1c2…",
  "tenant_id": "acme",
  "rule_id": "AO-WEB-001",
  "rule_name": "SQL injection attempt in query string",
  "severity": "high",
  "risk_score": 78.5,
  "confidence": 0.85,
  "status": "open",
  "title": "Tentative d'injection SQL depuis 203.0.113.9",
  "description": "…",
  "remediation": "…",
  "tags": ["web", "owasp:a03", "mitre:T1190"],
  "mitre": ["T1190"],
  "evidence": { "samples": [ { "ts": "…", "labels": {…} } ] },
  "first_seen": "2026-02-14T10:00:00Z",
  "last_seen": "2026-02-14T10:04:12Z",
  "count": 7,
  "event_ids": ["e6f0…"],
  "created_at": "2026-02-14T10:00:01Z",
  "updated_at": "2026-02-14T10:04:13Z"
}
```

`status` ∈ `open|acked|closed|suppressed`. `severity` ∈ `info|low|medium|high|critical`.

### 3.3 Decision

```json
{
  "decision": "auto",
  "policy_id": "auto-block-high-web",
  "playbook": "block-source-ip",
  "params": { "target": "labels.src_ip", "duration_seconds": 3600 },
  "reason": "severity=high risk=78.5 tags∈{web} tenant.mode=auto",
  "risk_score": 78.5,
  "expires_at": "2026-02-14T11:04:12Z",
  "cooldown_seconds": 300,
  "dry_run": false
}
```

`decision` ∈ `auto | require_approval | notify_only | ignore`.

### 3.4 Action

```json
{
  "action_id": "a91b…",
  "tenant_id": "acme",
  "finding_id": "f1c2…",
  "policy_id": "auto-block-high-web",
  "playbook": "block-source-ip",
  "status": "pending_approval",
  "mode": "manual",
  "dry_run": true,
  "params": { "target": "203.0.113.9", "duration_seconds": 3600 },
  "target": { "type": "ip", "value": "203.0.113.9" },
  "requested_by": "api-key:ci",
  "requested_at": "2026-02-14T10:00:02Z",
  "approved_by": null,
  "approved_at": null,
  "executed_at": null,
  "expires_at": "2026-02-14T11:00:02Z",
  "result": null,
  "rollback": { "available": true, "token": null, "performed_at": null, "result": null },
  "idempotency_key": "acme:block-source-ip:203.0.113.9:1739527200",
  "audit_seq": 42
}
```

`status` ∈ `planned | pending_approval | approved | rejected | executing | succeeded | failed |
expired | rolled_back`.

### 3.5 AuditRecord

```json
{
  "seq": 42,
  "ts": "2026-02-14T10:00:02.331Z",
  "tenant_id": "acme",
  "actor": "api-key:ci",
  "actor_role": "responder",
  "action": "action.approve",
  "target": { "type": "action", "id": "a91b…" },
  "before": { "status": "pending_approval" },
  "after": { "status": "approved" },
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```

`hash = sha256( f"{seq}|{ts}|{tenant_id}|{actor}|{actor_role}|{action}|{canonical(target)}|" \
        f"{canonical(before)}|{canonical(after)}|{prev_hash}" )`
où `canonical()` = JSON trié, séparateurs compacts, UTF-8. Le genesis a `prev_hash = "sha256:genesis"`.

---

## 4. API REST — préfixe `/api/v1`

Authentification : en-tête **`X-API-Key: ao_…`**. Le WebSocket accepte en plus
`?api_key=…` (les navigateurs ne posent pas d'en-tête sur `ws://`).

Rôles et capacités :

| Rôle | Capacités |
|---|---|
| `viewer` | `read:events read:findings read:rules read:policies read:audit read:stats` |
| `analyst` | viewer + `write:events write:findings` |
| `responder` | analyst + `execute:actions approve:actions` |
| `admin` | responder + `admin:tenants admin:rules admin:keys admin:policies` |

### 4.1 Santé, méta, observabilité

| Méthode | Chemin | Capacité | Description |
|---|---|---|---|
| GET | `/healthz` | public | `{"status":"ok","version":"0.1.0","uptime_s":12}` |
| GET | `/readyz` | public | Vérifie DB + bus + règles → `200` ou `503` |
| GET | `/version` | public | Version, commit, licence, mode d'autonomie global |
| GET | `/metrics` | public (réseau interne) | Exposition Prometheus texte |
| GET | `/api/v1/auth/whoami` | authentifié | Tenant, rôle, capacités, mode d'autonomie |

### 4.2 Tenants & clés

| Méthode | Chemin | Capacité | Corps / Réponse |
|---|---|---|---|
| GET | `/api/v1/tenants` | `admin:tenants` | `{"items":[Tenant]}` |
| POST | `/api/v1/tenants` | `admin:tenants` | `{"tenant_id","name","mode":"manual\|supervised\|auto","autonomy_allowlist":["10.0.0.0/8"]}` |
| GET | `/api/v1/tenants/{id}` | `read:stats` (self) | `Tenant` |
| PATCH | `/api/v1/tenants/{id}` | `admin:tenants` | `{"mode":"auto","dry_run":false}` |
| POST | `/api/v1/tenants/{id}/keys` | `admin:keys` | `{"role":"responder","label":"ci"}` → `{"key_id","api_key":"ao_…"}` **affiché une seule fois** |
| GET | `/api/v1/tenants/{id}/keys` | `admin:keys` | `{"items":[{key_id,label,role,created_at,last_used_at,revoked_at}]}` |
| DELETE | `/api/v1/keys/{key_id}` | `admin:keys` | Révocation immédiate → `204` |

**Tenant** : `{"tenant_id","name","mode","dry_run","autonomy_allowlist","created_at","updated_at"}`.

### 4.3 Événements

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| POST | `/api/v1/events` | `write:events` | Un `Event` **ou** `{"events":[Event,…]}` (≤ 500). `tenant_id` forcé depuis la clé. `202` → `{"accepted":n,"rejected":n,"event_ids":[…],"findings":[{"finding_id","rule_id","severity","risk_score","decision"}]}` |
| GET | `/api/v1/events` | `read:events` | Filtres `kind, source_type, since, until, q, limit (≤500, def 100), cursor` |
| GET | `/api/v1/events/{event_id}` | `read:events` | `Event` |

### 4.4 Findings

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| GET | `/api/v1/findings` | `read:findings` | `status,severity,rule_id,since,until,min_risk,sort=risk_score\|last_seen,limit,cursor` |
| GET | `/api/v1/findings/{id}` | `read:findings` | `Finding` + `actions` liées |
| POST | `/api/v1/findings/{id}/ack` | `write:findings` | `{"comment":"…"}` → `{"status":"acked"}` |
| POST | `/api/v1/findings/{id}/close` | `write:findings` | `{"resolution":"true_positive\|false_positive\|mitigated","comment":"…"}` |
| POST | `/api/v1/findings/{id}/suppress` | `write:findings` | `{"duration_seconds":86400,"reason":"…"}` (créé une exception sur la règle) |

### 4.5 Règles, politiques, playbooks

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| GET | `/api/v1/rules` | `read:rules` | `{"items":[{rule_id,title,severity,enabled,tags,source_types,kinds,path}]}` |
| GET | `/api/v1/rules/{rule_id}` | `read:rules` | Règle complète + YAML source |
| POST | `/api/v1/rules/validate` | `admin:rules` | Corps = YAML/JSON de règle → `{"valid":true,"errors":[]}` |
| POST | `/api/v1/rules/reload` | `admin:rules` | Recharge depuis `THOT_RULES_DIR` → `{"loaded":n,"errors":[…]}` |
| GET | `/api/v1/policies` | `read:policies` | Politiques chargées + ordre de priorité |
| POST | `/api/v1/policies/reload` | `admin:policies` | Rechargement |
| GET | `/api/v1/playbooks` | `read:rules` | `{"items":[{name,description,params_schema,reversible,dry_run_capable,connectors}]}` |

### 4.6 Actions (SOAR)

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| POST | `/api/v1/actions/plan` | `execute:actions` | `{"finding_id","playbook","params":{…},"dry_run":true}` → `Action` en `planned` (aucun effet de bord) |
| GET | `/api/v1/actions` | `read:findings` | `status,playbook,finding_id,limit,cursor` |
| GET | `/api/v1/actions/{id}` | `read:findings` | `Action` |
| POST | `/api/v1/actions/{id}/approve` | `approve:actions` | `{"comment":"…"}` → `approved` |
| POST | `/api/v1/actions/{id}/reject` | `approve:actions` | `{"reason":"…"}` → `rejected` (terminal) |
| POST | `/api/v1/actions/{id}/execute` | `execute:actions` | Exécute ; refuse si `pending_approval` non approuvé → `409`. Idempotent via `idempotency_key` |
| POST | `/api/v1/actions/{id}/rollback` | `execute:actions` | Undo ; refuse si déjà `rolled_back` → `409` |

Erreurs normalisées : `{"error":{"code":"forbidden","message":"…","details":{…}}}` avec
`400 validation_error`, `401 unauthenticated`, `403 forbidden`, `404 not_found`,
`409 conflict`, `422 unprocessable`, `429 rate_limited`, `500 internal_error`.

### 4.7 Audit

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| GET | `/api/v1/audit` | `read:audit` | `since,until,action,actor,limit,cursor` |
| GET | `/api/v1/audit/verify` | `read:audit` | `{"valid":true,"records":n,"broken_at":null}` |
| GET | `/api/v1/audit/export?format=jsonl\|cef` | `read:audit` | Flux téléchargeable (SIEM/SOAR) |

### 4.8 Stats, rapports, collecteurs, flux temps réel

| Méthode | Chemin | Capacité | Détails |
|---|---|---|---|
| GET | `/api/v1/stats/overview` | `read:stats` | Compteurs 24 h/7 j : événements, findings par sévérité, MTTA/MTTR, top règles, actions réussies/rollback, **mode d'autonomie** |
| GET | `/api/v1/findings/{id}/report?format=md\|html\|json\|sarif` | `read:findings` | Artefact exploitable (SARIF 2.1.0 pour GitHub Code Scanning) |
| GET | `/api/v1/collectors` | `read:stats` | État des collecteurs (dernier run, items, erreurs) |
| POST | `/api/v1/collectors/{name}/run` | `execute:actions` | Déclenche un run manuel **sur les cibles déclarées du tenant** |
| WS | `/api/v1/ws/stream` | `read:events` | Frames : `{"type":"event\|finding\|action\|audit\|heartbeat","data":{…}}` |

### 4.9 Console embarquée

| Méthode | Chemin | Détails |
|---|---|---|
| GET | `/` | Console HTML (Jinja2 + JS, **aucun build Node requis**) : flux live, findings, actions, audit, règles |
| GET | `/ui/support` | Page de soutien : adresses BTC/SOL en clair + avertissement anti-arnaque + alternatives |
| GET | `/ui/static/*` | CSS/JS embarqués |
| GET | `/openapi.json` | Schéma OpenAPI 3.1 généré par FastAPI |

---

## 5. Format des règles de détection (YAML)

```yaml
id: AO-WEB-001
title: SQL injection attempt in query string
description: Détecte les motifs d'injection SQL dans les paramètres de requête.
status: stable            # draft | test | stable | deprecated
severity: high            # info | low | medium | high | critical
confidence: 0.85          # 0.0 → 1.0
enabled: true
tags: [web, owasp:a03, mitre:T1190]
source_types: [web_probe, log_tail]
kinds: [http.request]
match:
  all:                    # ET logique
    - field: labels.path
      op: regex
      value: "(?i)(union[\\s/*]+select|or\\s+1=1|sleep\\(\\d+\\)|benchmark\\()"
  any: []                 # OU logique (au moins un)
  not: []                 # NI (aucun)
  threshold:              # optionnel : agrégation
    count: 3
    window_seconds: 60
    group_by: [labels.src_ip, labels.path]
dedup:
  key: [rule_id, labels.src_ip]
  ttl_seconds: 900        # fenêtre de regroupement dans un même finding
risk:
  base: 60                # base du score, modulée par severity/confidence/asset_criticality
  asset_criticality: 1.0  # multiplicateur
false_positives:
  - Requêtes contenant le mot "union" dans un champ de recherche libre.
remediation: Bloquer l'IP source au WAF 1 h, vérifier les logs applicatifs, patcher l'entrée.
references:
  - https://owasp.org/Top10/A03_2021-Injection/
```

**Opérateurs supportés** : `eq, ne, gt, gte, lt, lte, in, not_in, contains, icontains,
startswith, endswith, regex, exists, cidr, len_gt, len_lt`.
`field` est un chemin pointé sur `event` (`labels.x`, `payload.y`, `source.host`, `kind`, `ts`…).
Une règle invalide **ne casse pas** le chargement : elle est rejetée avec un diagnostic.

**Compatibilité Sigma-lite** : un sous-ensemble de clés Sigma (`title, id, level, logsource,
detection.selection|condition|filter`) est traduit automatiquement, avec avertissement.

---

## 6. Format des politiques (policy-as-code)

```yaml
version: 1
id: auto-block-high-web
priority: 100              # plus grand = évalué d'abord
description: Blocage automatique des attaques web à fort score.
when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  finding.tags_any: [web, exploit-attempt]
  tenant.mode: [auto]
  environment: [prod, staging]
then:
  decision: auto           # auto | require_approval | notify_only | ignore
  playbook: block-source-ip
  params:
    target: labels.src_ip
    duration_seconds: 3600
  dry_run: false
  cooldown_seconds: 300
  max_actions_per_hour: 10
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
```

Sémantique : `when` = ET entre clés ; une liste = OU d'égalités ; un mapping = comparateurs
(`gt, gte, lt, lte, in, not_in, matches`). Clés disponibles : `finding.*`
(`severity, risk_score, confidence, rule_id, tags, tags_any, status, count, title`),
`tenant.*` (`id, mode`), `environment`, `time.hour_utc`, `day.weekday`.
Si **aucune** politique ne matche → `decision = notify_only`. Une politique `ignore` explicite
est requise pour le silence total. Un mode Rego est disponible si `THOT_OPA_BIN` est défini
et le binaire présent (`policies/rego/thotsecure.rego`).

**Garde-fous d'exécution** (appliqués par le moteur de décision, non contournables par une politique) :
1. `max_actions_per_hour` par tenant (défaut 20) ;
2. `cooldown` par `(tenant, playbook, cible)` ;
3. **jamais** d'action sur une cible de l'`autonomy_allowlist` protégée (infra propre) ;
4. `dry_run` global prioritaire sur toute politique ;
5. toute action sur une cible hors périmètre déclaré du tenant → `require_approval`.

---

## 7. Format des playbooks (YAML)

```yaml
name: block-source-ip
description: Bloque une IP source au niveau du connecteur WAF/pare-feu configuré.
reversible: true
dry_run_capable: true
connectors: [cloudflare, aws-waf, modsecurity, nginx-local, null]
params:
  target: { type: ip, required: true, description: "IP ou CIDR à bloquer" }
  duration_seconds: { type: integer, default: 3600, min: 60, max: 604800 }
  reason: { type: string, default: "Thot Secure auto-mitigation" }
execute:
  - connector: waf
    call: block_ip
    with: { ip: "${params.target}", ttl: "${params.duration_seconds}", note: "${params.reason}" }
rollback:
  - connector: waf
    call: unblock_ip
    with: { ip: "${params.target}" }
audit:
  severity: high
  notify: [webhook, ticket]
```

Playbooks livrés : `block-source-ip` (+ `unblock-source-ip`), `rate-limit-source`,
`quarantine-artifact`, `revoke-session`, `rotate-secret`, `isolate-host`, `patch-dependency`
(ouvre une PR, jamais de merge auto), `harden-endpoint` (applique un profil de durcissement),
`notify`, `open-ticket`.

Un connecteur non configuré fonctionne en **mode simulé** (`null` / `simulation`) : il retourne
un `rollback_token` et journalise `simulated: true`. **C'est le comportement par défaut du MVP** :
Thot Secure est sûr à brancher avant d'avoir des credentials.

---

## 8. CLI `thotsecure`

```
thotsecure serve [--host --port --reload]
thotsecure init-db
thotsecure doctor
thotsecure tenant create --id acme --name "ACME SAS" --mode supervised
thotsecure tenant list
thotsecure key create --tenant acme --role responder [--label ci]
thotsecure key revoke --key-id <id>
thotsecure rules list | rules validate [--path rules]
thotsecure policies validate
thotsecure ingest --tenant acme --file events.jsonl | --stdin
thotsecure findings list --tenant acme [--severity high] [--min-risk 70]
thotsecure findings show <finding_id>
thotsecure actions list | actions plan --finding <id> --playbook block-source-ip
                  | actions approve <id> | actions execute <id> | actions rollback <id>
thotsecure audit verify | audit tail
thotsecure report <finding_id> --format md|html|json|sarif [-o out.md]
thotsecure probe --tenant acme --target https://shop.acme.fr    # audit de SA propre surface
thotsecure demo --tenant demo                                   # jeu de données + findings + actions
```
Codes de sortie : `0` succès, `1` erreur, `2` usage, `3` vérification négative (ex. audit corrompu).
`--json` disponible sur toutes les commandes pour l'automatisation.

---

## 9. Variables d'environnement

> Toutes les variables ci-dessous portent le préfixe **`THOT_`** (ex. `THOT_DRY_RUN`).
> Les noms sont donnés sans préfixe dans le tableau pour rester lisibles.

| Variable | Défaut | Rôle |
|---|---|---|
| `THOT_ENV` | `dev` | `dev` \| `staging` \| `prod` (durcit les défauts, masque les erreurs) |
| `THOT_ROOT_DIR` | `.` | Racine de résolution des chemins relatifs (jamais le CWD du processus) |
| `THOT_HOST` / `THOT_PORT` | `0.0.0.0` / `8080` | Écoute |
| `THOT_SECRET_KEY` | *persistée dans `data/secret.key`, sinon éphémère + avertissement* | Poivre des clés API + signature des sessions. **Doit être partagée entre processus.** |
| `THOT_BOOTSTRAP_API_KEY` | `thot_BOOTSTRAP_changemebeforefirstuse` | Clé admin initiale (⚠️ à changer) |
| `THOT_SESSION_TTL_SECONDS` | `28800` | Durée de vie d'une session de console |
| `THOT_DB_URL` | `sqlite:///./data/thotsecure.db` | `sqlite://` (aucune dépendance) ou `postgresql://` / `postgresql+psycopg://` (extra `postgres`, pilote `psycopg` 3 ou `psycopg2`) |
| `THOT_DB_SSLMODE` | *(vide = automatique : `prefer` hors prod, `require` en `prod`)* | `disable` \| `allow` \| `prefer` \| `require` \| `verify-ca` \| `verify-full` — PostgreSQL uniquement |
| `THOT_DB_POOL_MAX_SIZE` | `8` | Taille maximale du pool de connexions PostgreSQL |
| `THOT_DATA_DIR` | `./data` | Données locales (base, quarantaine, état des collecteurs, tickets) |
| `THOT_RULES_DIR` | `./rules` | Bibliothèque de règles |
| `THOT_POLICIES_DIR` | `./policies` | Politiques |
| `THOT_PLAYBOOKS_DIR` | `./playbooks` | Playbooks |
| `THOT_TARGETS_FILE` | `./config/targets.yaml` | Périmètre déclaré par tenant (actifs, plages possédées, cibles protégées) |
| `THOT_CONNECTORS_FILE` | `./config/connectors.yaml` | Association connecteur logique → pilote réel |
| `THOT_BUS` | `memory` | `memory` \| `sqlite` \| `nats` |
| `THOT_NATS_URL` | `nats://127.0.0.1:4222` | Bus distribué (client stdlib embarqué) |
| `THOT_BUS_QUEUE_SIZE` | `5000` | Taille de file par abonné (au-delà : écartement du plus ancien) |
| `THOT_BUS_SUBJECT_PREFIX` | `thotsecure.events` | Sujet NATS |
| `THOT_AUTONOMY` | `supervised` | `manual` \| `supervised` \| `auto` (défaut global, surchargeable par tenant) |
| `THOT_DRY_RUN` | `true` | **Sécurité** : aucune action réelle si `true` |
| `THOT_REQUIRE_TARGET_DECLARATION` | `true` | Hors périmètre déclaré ⇒ approbation humaine obligatoire |
| `THOT_CRITICAL_SCORE_THRESHOLD` | `85` | En mode `supervised`, au-delà : approbation humaine imposée |
| `THOT_MAX_ACTIONS_PER_HOUR` | `20` | Plafond global (par tenant : `max_actions_per_hour`) |
| `THOT_DEFAULT_COOLDOWN_SECONDS` | `300` | Anti-rafale par `(tenant, playbook, cible)` |
| `THOT_APPROVE_TTL_SECONDS` | `3600` | Délai au-delà duquel une approbation en attente expire |
| `THOT_ANOMALY_ENABLED` | `false` | Détecteur statistique (EWMA + z-score). **Additif et opt-in** : désactivé, aucun comportement ne change par rapport à la 0.1.0 initiale |
| `THOT_ANOMALY_BUCKET_SECONDS` | `60` | Intervalle d'agrégation du détecteur |
| `THOT_ANOMALY_WARMUP_SAMPLES` | `30` | Intervalles observés avant d'émettre (protection anti-faux-positifs au démarrage) |
| `THOT_ANOMALY_ZSCORE_THRESHOLD` | `4.0` | Écart type minimal (seuil par défaut, surchargeable par règle) |
| `THOT_ANOMALY_MIN_OBSERVED` | `20` | Volume minimal dans l'intervalle pour conclure |
| `THOT_ANOMALY_ENTITY_FIELDS` | `["labels.src_ip"]` | Chemins servant d'identité de suivi (volume, cardinalité, première vue) |
| `THOT_ANOMALY_MAX_ENTITIES` | `20000` | Plafond de compteurs suivis (borne mémoire) |
| `THOT_ANOMALY_ENTITY_TTL_SECONDS` | `86400` | Oubli d'une entité silencieuse (`0` = illimité) |
| `THOT_ANOMALY_DETECT_NEW_SOURCES` | `true` | Signale la première apparition d'une entité |
| `THOT_COLLECTORS_ENABLED` | `false` | Planification automatique des collecteurs |
| `THOT_COLLECTOR_INTERVAL_SECONDS` | `300` | Intervalle par défaut du planificateur |
| `THOT_HTTP_PROBE_TIMEOUT_SECONDS` | `8` | Délai par requête de l'audit de surface |
| `THOT_HTTP_PROBE_MAX_TARGETS` | `200` | Nombre maximal d'URL auditées par passe |
| `THOT_HTTP_PROBE_DELAY_SECONDS` | `0.2` | Espacement entre deux requêtes (on n'inonde pas une cible) |
| `THOT_SYSLOG_ENABLED` | `false` | Écoute syslog UDP embarquée (opt-in : on n'ouvre pas un port par défaut) |
| `THOT_SYSLOG_HOST` / `THOT_SYSLOG_PORT` | `0.0.0.0` / `5514` | Écoute syslog |
| `THOT_MAINTENANCE_INTERVAL_SECONDS` | `60` | Passe de maintenance (expirations, rollbacks programmés, métriques) |
| `THOT_RETENTION_DAYS` | `30` | Purge des événements |
| `THOT_AUDIT_RETENTION_DAYS` | `365` | Purge du journal d'audit (jamais au rythme des événements) |
| `THOT_OPA_BIN` | *(vide)* | Chemin du binaire OPA pour le mode Rego |
| `THOT_LOG_LEVEL` | `INFO` | `DEBUG`…`CRITICAL` |
| `THOT_LOG_FORMAT` | `json` | `json` \| `console` |
| `THOT_TLS_ENABLED` | `false` | HTTPS direct (sinon reverse-proxy) — exige `THOT_TLS_CERT_FILE` et `THOT_TLS_KEY_FILE` |
| `THOT_RATE_LIMIT_PER_MIN` | `600` | Garde-fou anti-abus par clé API (par processus, cf. `docs/operations/deployment.md`) |
| `THOT_MAX_INGEST_BATCH` | `500` | Taille maximale d'un lot d'ingestion |
| `THOT_MAX_BODY_BYTES` | `2097152` | Taille maximale d'un corps de requête |
| `THOT_CORS_ORIGINS` | `[]` | Origines autorisées (vide = aucune : le SPA est servi par la même origine) |
| `THOT_INSTANCE_NAME` | `thotsecure` | Nom d'instance (journaux, métriques, audit) |
| `THOT_BASE_URL` | `http://127.0.0.1:8080` | URL publique (liens des rapports et des tickets) |

---

## 10. Sécurité produit (exigences à implémenter)

* **RBAC** appliqué par dépendance FastAPI + vérifié dans le core (`capabilities`).
* **Isolation multi-tenant** : toute requête SQL filtre `tenant_id`; test dédié en CI.
* **Audit immuable** : chaîne de hash + `GET /audit/verify` + export SIEM.
* **Chiffrement** : TLS en transit (reverse-proxy ou direct) ; au repos, `THOT_SECRET_KEY`
  + disque chiffré documenté ; clés API stockées **hachées** (`scrypt`) jamais en clair.
* **Anti-abus** : rate limit sur `POST /events` ; taille de corps limitée ; pas d'eval de
  template utilisateur ; regex de règle compilées avec timeout d'exécution.
* **Sûreté par défaut** : `DRY_RUN=true`, `AUTONOMY=supervised`, allowlist de cibles,
  cibles protégées non modifiables.
* **Traçabilité** : chaque décision référence `policy_id`, chaque action `audit_seq`.
* **Zéro capacité offensive** : aucun code de scan agressif/exploitation ; `probe` n'audite que
  des cibles déclarées possédées par le tenant (opt-in explicite dans `targets.yaml`).

---

## 11. Tests attendus (unittest, exécutables sans dépendance externe)

| Fichier | Couverture |
|---|---|
| Fichier | Couverture |
|---|---|
| `tests/support.py` | Socle : pile complète isolée (règles, politiques, playbooks et périmètre **écrits sur disque** pour exercer les chargeurs réels) |
| `tests/test_smoke_e2e.py` | Chaîne complète : seuil → finding → décision → action → rollback → audit ; isolation inter-tenant ; cible protégée ; mode `auto` ; RBAC des clés |
| `tests/test_library.py` | **Garde-fou éditorial** : les 21 règles, 7 politiques et 15 playbooks livrés se chargent sans diagnostic, sources de collecte couvertes, remédiation obligatoire en sévérité haute, playbooks réversibles avec rollback, exemples de configuration sans secret |
| `tests/test_api.py` | Authentification 401, RBAC 403, isolation inter-tenant (404 indistinguable), ingestion 202, cycle `plan → approve → execute → rollback`, refus en mode réel non approuvé, rapports SARIF, export CEF, WebSocket, console (session, CSRF, page de soutien) |
| `tests/test_collectors.py` | Analyse de journaux (Nginx, JSON, syslog RFC 3164/5424), dépendances (requirements/package.json/go.mod/pom), versions, audit de configuration, `tail` incrémental + rotation, `web_probe` contre un **vrai serveur HTTP local** (en-têtes, cookies, chemins exposés, opt-in refusé) |
| `tests/test_config_cli.py` | Défauts sûrs, surcharge par variables d'environnement, refus de la clé publique en production, **persistance et partage de la clé de signature**, résolution des chemins, `--json`, codes de sortie (0/1/3), `doctor`, `funding` |

Commande : `python -m unittest discover -s tests -t . -v` (et `pytest` en CI).

> Les tests sont écrits en `unittest` (stdlib) et restent compatibles `pytest`. Aucun test ne
> nécessite de réseau : l'audit de surface est vérifié contre un serveur HTTP local démarré
> par le test lui-même, et les clients HTTP sont simulés.

---

## 12. Adresses de dons officielles (source unique de vérité)

```
Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
Solana  (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
```

> Dons **volontaires, sans contrepartie**. Vérifiez toujours ces adresses depuis le dépôt
> officiel. Thot Secure ne demandera **jamais** de clé privée ni de phrase de récupération.

Elles doivent apparaître dans : `README.md` (section dédiée), `.github/FUNDING.yml`,
`GET /ui/support`, `docs/support.md`, fin des articles (jamais en accroche).
