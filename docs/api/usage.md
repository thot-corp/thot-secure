# Utiliser l'API REST

*Mode d'emploi pratique de l'API Thot Secure v0.1.0 : authentification, capacités, exemples copiables-collables et pièges de production.*

!!! warning "Ce guide n'est pas la référence"
    La référence **exhaustive et gelée** de l'interface est
    [`../architecture/api-contract.md`](../architecture/api-contract.md). Toute divergence entre cette
    page et le contrat se tranche **en faveur du contrat**. Cette page est un mode d'emploi : elle
    montre les parcours courants, les codes d'erreur et les réflexes d'exploitation.

Pour la vue d'ensemble de l'architecture, voir [`../architecture/overview.md`](../architecture/overview.md) ;
pour les objets manipulés, voir [`../architecture/data-model.md`](../architecture/data-model.md).

## 1. Conventions d'appel

### 1.1 URL de base et préfixe

| Élément | Valeur |
|---|---|
| Préfixe fonctionnel | `/api/v1` |
| Écoute par défaut | `THOT_HOST=0.0.0.0`, `THOT_PORT=8080` |
| Base URL locale typique | `http://127.0.0.1:8080` |
| Hors préfixe | `/healthz`, `/readyz`, `/version`, `/metrics`, `/`, `/ui/*`, `/openapi.json` |
| Schéma OpenAPI | `GET /openapi.json` (**OpenAPI 3.1**, généré par FastAPI) |

```bash
export AO_URL="http://127.0.0.1:8080"
export AO_KEY="ao_..."   # la clé n'est affichée qu'une seule fois, à la création
```

!!! note "Variables des exemples ≠ variables du produit"
    `AO_URL`, `AO_KEY`, `AO_ADMIN_KEY` et `AO_APPROVER_KEY` sont des variables **de shell** créées
    par les exemples de cette page pour rester lisibles. Les variables du **produit** sont les
    `THOT_*` du §9 du contrat (par exemple `THOT_BOOTSTRAP_API_KEY` pour la clé admin
    initiale) — ne mélangez pas les deux dans un même script.

!!! tip "L'OpenAPI est la source de vérité mécanique"
    Le contrat décrit l'intention ; `/openapi.json` décrit **ce que le serveur expose réellement**
    (paramètres exacts, schémas, codes de réponse). En cas de doute sur un nom de champ — notamment
    le curseur de pagination (§6) — générez un client ou inspectez ce document :
    `curl -sS "$AO_URL/openapi.json" | python -m json.tool | less`

    C'est aussi lui qui tranche les **codes de succès des créations** (`200` ou `201`), que le
    contrat ne fige pas route par route.

### 1.2 Authentification par clé API

Toute route authentifiée attend l'en-tête `X-API-Key: ao_…`. Une seule exception : le WebSocket
accepte `?api_key=…` en paramètre de requête, car les navigateurs ne permettent pas de poser un
en-tête sur une connexion `ws://` (§1.5).

```bash
curl -sS "$AO_URL/api/v1/auth/whoami" \
  -H "X-API-Key: $AO_KEY"
# → 200
```

Réponse (`200`) :

```json
{
  "tenant_id": "acme",
  "role": "responder",
  "capabilities": ["read:events", "read:findings", "read:rules", "read:policies",
                   "read:audit", "read:stats", "write:events", "write:findings",
                   "execute:actions", "approve:actions"],
  "mode": "supervised"
}
```

`whoami` est l'appel de diagnostic à faire **avant** tout script : il confirme le tenant, le rôle, les
capacités effectives et le mode d'autonomie. Un test qui échoue avec `403` se diagnostique en
comparant `capabilities` à la capacité exigée par la route.

### 1.3 Créer une clé API

`POST /api/v1/tenants/{id}/keys` — capacité `admin:keys`.

```bash
curl -sS -X POST "$AO_URL/api/v1/tenants/acme/keys" \
  -H "X-API-Key: $AO_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"role": "responder", "label": "ci"}'
# → 201/200 selon l'implémentation ; 401 ; 403 ; 404 ; 409 ; 422
```

```json
{
  "key_id": "k_7f3a91c2",
  "api_key": "ao_9f1c…"
}
```

!!! danger "`api_key` n'est visible qu'une seule fois"
    Le secret n'est **jamais** relisible : la base ne stocke qu'un hachage `scrypt` (§10 du contrat).
    Si vous perdez la valeur, créez une nouvelle clé et révoquez l'ancienne. Le listing
    `GET /api/v1/tenants/{id}/keys` renvoie `key_id, label, role, created_at, last_used_at, revoked_at`
    — **pas** le secret.

### 1.4 Révoquer une clé

`DELETE /api/v1/keys/{key_id}` — capacité `admin:keys`. Révocation **immédiate**, réponse `204`
sans corps.

```bash
curl -sS -X DELETE "$AO_URL/api/v1/keys/k_7f3a91c2" \
  -H "X-API-Key: $AO_ADMIN_KEY" \
  -i | head -n 1
# → 204 ; 401 ; 403 ; 404
```

!!! warning "Une clé divulguée se révoque d'abord, s'analyse ensuite"
    Les clés sont hachées (`scrypt`) et affichées une seule fois. En cas de fuite (dépôt public, log
    de CI, capture d'écran), révoquez **sans attendre** puis faites tourner les secrets — procédure
    dans [`../operations/runbook.md`](../operations/runbook.md).

### 1.5 Où placer la clé — et où ne pas la placer

| Contexte | Emplacement correct |
|---|---|
| Requête REST | En-tête `X-API-Key: ao_…` |
| WebSocket (navigateur) | `?api_key=ao_…` (seule exception admise) |
| Scripts, CI | Variable d'environnement / coffre de secrets — jamais en dur |
| Logs, URL de reverse-proxy, `Referer` | **Jamais** : les journaux d'accès proxys conservent les URL |

## 2. Rôles, capacités et moindre privilège

### 2.1 Hiérarchie des rôles (contrat §4)

| Rôle | Capacités |
|---|---|
| `viewer` | `read:events read:findings read:rules read:policies read:audit read:stats` |
| `analyst` | viewer + `write:events write:findings` |
| `responder` | analyst + `execute:actions approve:actions` |
| `admin` | responder + `admin:tenants admin:rules admin:keys admin:policies` |

### 2.2 Capacité requise par opération sensible

| Opération | Route | Capacité |
|---|---|---|
| Envoyer des événements | `POST /api/v1/events` | `write:events` |
| Lever/clore/suspendre un finding | `POST /api/v1/findings/{id}/ack`, `/close`, `/suppress` | `write:findings` |
| Planifier une action | `POST /api/v1/actions/plan` | `execute:actions` |
| Approuver / rejeter | `POST /api/v1/actions/{id}/approve`, `/reject` | `approve:actions` |
| Exécuter / annuler une action | `POST /api/v1/actions/{id}/execute`, `/rollback` | `execute:actions` |
| Lire les actions | `GET /api/v1/actions`, `/actions/{id}` | `read:findings` |
| Déclencher un collecteur | `POST /api/v1/collectors/{name}/run` | `execute:actions` |
| Gérer tenants et clés | `/api/v1/tenants*`, `/api/v1/keys/{key_id}` | `admin:tenants`, `admin:keys` |
| Éditer les règles | `POST /api/v1/rules/validate`, `/rules/reload` | `admin:rules` |
| Recharger les politiques | `POST /api/v1/policies/reload` | `admin:policies` |
| Vérifier/exporter l'audit | `GET /api/v1/audit/verify`, `/audit/export` | `read:audit` |
| Consulter le flux temps réel | `WS /api/v1/ws/stream` | `read:events` |

!!! tip "Deux capacités distinctes pour une même action"
    `execute:actions` (planifier / exécuter / annuler) et `approve:actions` (approuver / rejeter) sont
    deux capacités **séparées** : une clé peut porter l'une sans l'autre. Attention toutefois : le
    rôle `responder` est le premier à cumuler les deux, et il n'existe pas de rôle « responder sans
    approbation » au MVP. Concrètement, le contrôle à quatre yeux s'obtient en **distribuant les
    clés** (un opérateur planifie avec sa clé, un second approuve avec la sienne), pas en comptant
    sur une séparation que les rôles seuls n'offrent pas.

## 3. Exemples par famille de routes

!!! note "Identifiants des exemples"
    Les identifiants (`f1c2a4d6-…`, `a91b3c7e-…`, `e6f0f0c4-…`) et la clé `ao_…` sont illustratifs.
    Récupérez les vôtres via les routes de liste, et gardez `X-API-Key: ao_…` réel côté client.

### 3.1 Santé, méta, observabilité (§4.1)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/healthz` | public |
| GET | `/readyz` | public |
| GET | `/version` | public |
| GET | `/metrics` | public (réseau interne) |
| GET | `/api/v1/auth/whoami` | authentifié |

```bash
# Sonde de vivacité — 200 attendu
curl -sS "$AO_URL/healthz"
# → {"status":"ok","version":"0.1.0","uptime_s":12}

# Sonde de disponibilité (DB + bus + règles) — 200 ou 503
curl -sS -o /dev/null -w '%{http_code}\n' "$AO_URL/readyz"

# Version, commit, licence, mode d'autonomie global
curl -sS "$AO_URL/version"

# Métriques Prometheus (à n'exposer que sur le réseau interne)
curl -sS "$AO_URL/metrics" | head -n 20

# Identité de l'appelant
curl -sS "$AO_URL/api/v1/auth/whoami" -H "X-API-Key: $AO_KEY"
```

Codes attendus : `200`, `503` (`/readyz` seulement), `401` (`whoami` sans clé valide).

### 3.2 Tenants et clés (§4.2)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/api/v1/tenants` | `admin:tenants` |
| POST | `/api/v1/tenants` | `admin:tenants` |
| GET | `/api/v1/tenants/{id}` | `read:stats` (self) |
| PATCH | `/api/v1/tenants/{id}` | `admin:tenants` |
| POST | `/api/v1/tenants/{id}/keys` | `admin:keys` |
| GET | `/api/v1/tenants/{id}/keys` | `admin:keys` |
| DELETE | `/api/v1/keys/{key_id}` | `admin:keys` |

```bash
# Lister les tenants
curl -sS "$AO_URL/api/v1/tenants" -H "X-API-Key: $AO_ADMIN_KEY"
# → {"items":[Tenant,...]}

# Créer un tenant en mode supervisé, avec allowlist d'infra propre
curl -sS -X POST "$AO_URL/api/v1/tenants" \
  -H "X-API-Key: $AO_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","name":"ACME SAS","mode":"supervised",
       "autonomy_allowlist":["10.0.0.0/8"]}'

# Lire un tenant (self : un tenant peut lire le sien avec read:stats)
curl -sS "$AO_URL/api/v1/tenants/acme" -H "X-API-Key: $AO_KEY"

# Basculer en autonomie auto SANS dry-run — à ne faire qu'après revue de la §10
curl -sS -X PATCH "$AO_URL/api/v1/tenants/acme" \
  -H "X-API-Key: $AO_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"mode":"auto","dry_run":false}'

# Créer puis révoquer une clé
curl -sS -X POST "$AO_URL/api/v1/tenants/acme/keys" \
  -H "X-API-Key: $AO_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"role":"responder","label":"ci"}'
curl -sS -X DELETE "$AO_URL/api/v1/keys/k_7f3a91c2" -H "X-API-Key: $AO_ADMIN_KEY"
```

Codes attendus : `200`, `204` (révocation), `401`, `403`, `404` (tenant inconnu), `409`, `422`
(`mode` hors `manual|supervised|auto`).

!!! warning "`dry_run:false` est une décision d'exploitation"
    `THOT_DRY_RUN=true` reste le défaut et **prime** sur toute politique (§6 du contrat). Le
    passage à `false` doit être accompagné d'une cible déclarée, d'une allowlist d'infra propre et
    d'un canal de notification testé.

### 3.3 Événements (§4.3)

| Méthode | Chemin | Capacité |
|---|---|---|
| POST | `/api/v1/events` | `write:events` |
| GET | `/api/v1/events` | `read:events` |
| GET | `/api/v1/events/{event_id}` | `read:events` |

```bash
# Soumettre un événement unique (objet Event) — 202 attendu
curl -sS -X POST "$AO_URL/api/v1/events" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d '{"schema_version":"1","ts":"2026-02-14T10:00:00.123Z","kind":"http.request",
       "source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},
       "severity_hint":"info",
       "labels":{"src_ip":"203.0.113.9","path":"/login","method":"POST"},
       "payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}'

# Lister avec filtres et pagination
curl -sS -G "$AO_URL/api/v1/events" \
  -H "X-API-Key: $AO_KEY" \
  --data-urlencode 'kind=http.request' \
  --data-urlencode 'source_type=web_probe' \
  --data-urlencode 'since=2026-02-14T00:00:00Z' \
  --data-urlencode 'q=203.0.113.9' \
  --data-urlencode 'limit=100'

# Lire un événement précis
curl -sS "$AO_URL/api/v1/events/e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11" \
  -H "X-API-Key: $AO_KEY"
# → 200 ; 404 si l'événement n'existe pas ou appartient à un autre tenant
```

Codes attendus : `202` (ingestion), `200` (lectures), `401`, `403`, `404`, `422` (schéma `Event`
invalide), `429` (quota d'ingestion), `500`.

!!! info "Roadmap"
    Le MVP v0.1.0 n'expose **aucune route de mise à jour ni de suppression d'événement** : un
    événement est **immuable** (contrat §1). La seule réduction de volume prévue est la purge par
    rétention (`THOT_RETENTION_DAYS`, défaut 30 jours), qui n'est pas déclenchable par l'API.
    Pour « écarter » un événement du bruit, agissez sur la **règle** ou **suspendre** le finding
    correspondant (§3.4).

### 3.4 Findings (§4.4)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/api/v1/findings` | `read:findings` |
| GET | `/api/v1/findings/{id}` | `read:findings` |
| POST | `/api/v1/findings/{id}/ack` | `write:findings` |
| POST | `/api/v1/findings/{id}/close` | `write:findings` |
| POST | `/api/v1/findings/{id}/suppress` | `write:findings` |

```bash
# Findings ouverts les plus risqués
curl -sS -G "$AO_URL/api/v1/findings" \
  -H "X-API-Key: $AO_KEY" \
  --data-urlencode 'status=open' \
  --data-urlencode 'severity=high' \
  --data-urlencode 'rule_id=AO-WEB-001' \
  --data-urlencode 'min_risk=70' \
  --data-urlencode 'sort=risk_score' \
  --data-urlencode 'limit=50'

# Détail + actions liées
curl -sS "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f" \
  -H "X-API-Key: $AO_KEY"

# Prise en compte
curl -sS -X POST "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f/ack" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d '{"comment":"Pris en charge par l’astreinte réseau"}'
# → {"status":"acked"}

# Clôture (résolution obligatoire)
curl -sS -X POST "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f/close" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d '{"resolution":"true_positive","comment":"IP bloquée au WAF"}'

# Suspension : crée une exception sur la règle pendant la durée demandée
curl -sS -X POST "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f/suppress" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d '{"duration_seconds":86400,"reason":"Scan interne planifié (change CHG-4211)"}'
```

Codes attendus : `200`, `401`, `403`, `404`, `409` (`suppress` sur un finding déjà clos), `422`
(`resolution` hors `true_positive|false_positive|mitigated`).

Statuts de finding : `open|acked|closed|suppressed` ; sévérités : `info|low|medium|high|critical`.

!!! info "Roadmap"
    Il n'existe **pas** de route `DELETE /api/v1/findings/{id}`. Le cycle de vie se ferme avec
    `ack` / `close` / `suppress`, et les données disparaissent par rétention. Pour un faux positif
    récurrent, corrigez la règle (champ `false_positives`, voir
    [`../detection/rules.md`](../detection/rules.md)) plutôt que d'empiler des suppressions.

### 3.5 Règles, politiques, playbooks (§4.5)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/api/v1/rules` | `read:rules` |
| GET | `/api/v1/rules/{rule_id}` | `read:rules` |
| POST | `/api/v1/rules/validate` | `admin:rules` |
| POST | `/api/v1/rules/reload` | `admin:rules` |
| GET | `/api/v1/policies` | `read:policies` |
| POST | `/api/v1/policies/reload` | `admin:policies` |
| GET | `/api/v1/playbooks` | `read:rules` |

```bash
# Inventaire des règles chargées
curl -sS "$AO_URL/api/v1/rules" -H "X-API-Key: $AO_KEY"
# → {"items":[{rule_id,title,severity,enabled,tags,source_types,kinds,path},...]}

# Règle complète + YAML source
curl -sS "$AO_URL/api/v1/rules/AO-WEB-001" -H "X-API-Key: $AO_KEY"

# Valider une règle AVANT de la committer (YAML ou JSON)
curl -sS -X POST "$AO_URL/api/v1/rules/validate" \
  -H "X-API-Key: $AO_ADMIN_KEY" -H "Content-Type: application/yaml" \
  --data-binary @rules/web/AO-WEB-001.yaml
# → {"valid":true,"errors":[]}

# Recharger les règles depuis THOT_RULES_DIR
curl -sS -X POST "$AO_URL/api/v1/rules/reload" -H "X-API-Key: $AO_ADMIN_KEY"
# → {"loaded":42,"errors":[]}

# Politiques et ordre de priorité, puis rechargement
curl -sS "$AO_URL/api/v1/policies" -H "X-API-Key: $AO_KEY"
curl -sS -X POST "$AO_URL/api/v1/policies/reload" -H "X-API-Key: $AO_ADMIN_KEY"

# Playbooks disponibles
curl -sS "$AO_URL/api/v1/playbooks" -H "X-API-Key: $AO_KEY"
```

Codes attendus : `200`, `401`, `403`, `404` (règle inconnue), `422` (corps non parsable).

!!! tip "La validation en pré-merge est le meilleur usage de ces routes"
    `POST /rules/validate` renvoie `valid:false` avec des `errors` détaillées sans casser le
    chargement en cours : idéal en CI avant merge. Voir
    [`../detection/rules.md`](../detection/rules.md), [`../detection/sigma.md`](../detection/sigma.md)
    et [`../decision/policies.md`](../decision/policies.md).

### 3.6 Actions (§4.6)

| Méthode | Chemin | Capacité |
|---|---|---|
| POST | `/api/v1/actions/plan` | `execute:actions` |
| GET | `/api/v1/actions` | `read:findings` |
| GET | `/api/v1/actions/{id}` | `read:findings` |
| POST | `/api/v1/actions/{id}/approve` | `approve:actions` |
| POST | `/api/v1/actions/{id}/reject` | `approve:actions` |
| POST | `/api/v1/actions/{id}/execute` | `execute:actions` |
| POST | `/api/v1/actions/{id}/rollback` | `execute:actions` |

Cycle nominal complet (`planned` → `approved` → `succeeded` → `rolled_back`) :

```bash
FID="f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f"

# 1. Planifier : aucun effet de bord, l'action est créée en "planned"
curl -sS -X POST "$AO_URL/api/v1/actions/plan" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d "{\"finding_id\":\"$FID\",\"playbook\":\"block-source-ip\",
       \"params\":{\"target\":\"203.0.113.9\",\"duration_seconds\":3600},
       \"dry_run\":true}"
# → 200/201 avec un Action en "planned"

# 2. Approuver (capacité approve:actions)
curl -sS -X POST "$AO_URL/api/v1/actions/a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c/approve" \
  -H "X-API-Key: $AO_APPROVER_KEY" -H "Content-Type: application/json" \
  -d '{"comment":"Validation astreinte — ticket INC-88121"}'

# 3. Exécuter (refusé si non approuvée → 409)
curl -sS -X POST "$AO_URL/api/v1/actions/a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c/execute" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" -d '{}'

# 4. Annuler (rollback) — refusé si déjà annulé → 409
curl -sS -X POST "$AO_URL/api/v1/actions/a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c/rollback" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" -d '{}'

# Rejeter une action en attente (terminal)
curl -sS -X POST "$AO_URL/api/v1/actions/a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c/reject" \
  -H "X-API-Key: $AO_APPROVER_KEY" -H "Content-Type: application/json" \
  -d '{"reason":"Cible dans l’infra propre (allowlist)"}'

# Lister / consulter
curl -sS -G "$AO_URL/api/v1/actions" -H "X-API-Key: $AO_KEY" \
  --data-urlencode 'status=pending_approval' --data-urlencode 'limit=50'
curl -sS "$AO_URL/api/v1/actions/a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c" \
  -H "X-API-Key: $AO_KEY"
```

Codes attendus : `200`, `401`, `403`, `404`, `409`, `422`, `500`.

Statuts d'action : `planned | pending_approval | approved | rejected | executing | succeeded |
failed | expired | rolled_back`. `execute` est **idempotent** via `idempotency_key` : réutiliser la
même clé ne rejoue pas l'action.

!!! info "Roadmap"
    Il n'existe **pas** de route d'annulation d'une action en cours (`/cancel`) ni de route de
    suppression d'action. Une action en vol se termine ; on la **rollback** ensuite tant que
    `rollback.available` est `true` et que le rollback n'a pas expiré. Les transitions interdites
    renvoient `409`, jamais un succès silencieux.

### 3.7 Audit (§4.7)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/api/v1/audit` | `read:audit` |
| GET | `/api/v1/audit/verify` | `read:audit` |
| GET | `/api/v1/audit/export?format=jsonl\|cef` | `read:audit` |

```bash
# Journal filtré
curl -sS -G "$AO_URL/api/v1/audit" -H "X-API-Key: $AO_KEY" \
  --data-urlencode 'since=2026-02-14T00:00:00Z' \
  --data-urlencode 'until=2026-02-15T00:00:00Z' \
  --data-urlencode 'action=action.approve' \
  --data-urlencode 'actor=api-key:ci' \
  --data-urlencode 'limit=100'

# Vérification de la chaîne de hachage
curl -sS "$AO_URL/api/v1/audit/verify" -H "X-API-Key: $AO_KEY"
# → {"valid":true,"records":1284,"broken_at":null}

# Export SIEM (flux téléchargeable)
curl -sS "$AO_URL/api/v1/audit/export?format=jsonl" -H "X-API-Key: $AO_KEY" -o audit.jsonl
curl -sS "$AO_URL/api/v1/audit/export?format=cef"  -H "X-API-Key: $AO_KEY" -o audit.cef
```

Codes attendus : `200`, `401`, `403`, `404`, `422` (`format` hors `jsonl|cef`).

!!! danger "Un audit invalide est un incident"
    `valid:false` avec un `broken_at` renseigné signifie que la chaîne est rompue (`hash` ≠
    recalcul). Cessez les écritures, isolez la base, suivez
    [`../operations/runbook.md`](../operations/runbook.md), et conservez l'export `jsonl` avant toute
    manipulation. La CLI expose le même contrôle avec un code de sortie dédié (`3`), voir
    [`../cli.md`](../cli.md).

### 3.8 Stats, rapports, collecteurs, flux temps réel (§4.8)

| Méthode | Chemin | Capacité |
|---|---|---|
| GET | `/api/v1/stats/overview` | `read:stats` |
| GET | `/api/v1/findings/{id}/report?format=md\|html\|json\|sarif` | `read:findings` |
| GET | `/api/v1/collectors` | `read:stats` |
| POST | `/api/v1/collectors/{name}/run` | `execute:actions` |
| WS | `/api/v1/ws/stream` | `read:events` |

```bash
# Tableau de bord 24 h / 7 j (dont le mode d'autonomie courant)
curl -sS "$AO_URL/api/v1/stats/overview" -H "X-API-Key: $AO_KEY"

# Rapport de finding — markdown puis SARIF 2.1.0
curl -sS "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f/report?format=md" \
  -H "X-API-Key: $AO_KEY" -o finding.md
curl -sS "$AO_URL/api/v1/findings/f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f/report?format=sarif" \
  -H "X-API-Key: $AO_KEY" -o thotsecure.sarif

# État des collecteurs, puis run manuel sur les cibles déclarées du tenant
curl -sS "$AO_URL/api/v1/collectors" -H "X-API-Key: $AO_KEY"
curl -sS -X POST "$AO_URL/api/v1/collectors/web_probe/run" -H "X-API-Key: $AO_KEY"
# → 202 ; 403 si execute:actions manque ; 404 si le collecteur n'existe pas
```

Codes attendus : `200`, `202` (run de collecteur), `401`, `403`, `404`, `422` (`format` invalide),
`500`.

!!! warning "Un run de collecteur n'est pas un scan offensif"
    `POST /collectors/{name}/run` ne travaille que sur les cibles **déclarées et possédées** par le
    tenant (`THOT_TARGETS_FILE`, défaut `./config/targets.yaml`, opt-in explicite — contrat §10).
    Aucune capacité de scan agressif, d'exploitation ou de tiers n'existe dans le produit.

### 3.9 Console embarquée (§4.9)

| Méthode | Chemin | Note |
|---|---|---|
| GET | `/` | Console HTML (Jinja2 + JS, aucun build Node requis) |
| GET | `/ui/support` | Page de soutien (adresses BTC/SOL en clair) |
| GET | `/ui/static/*` | CSS/JS embarqués |
| GET | `/openapi.json` | Schéma OpenAPI 3.1 généré par FastAPI |

```bash
# Ces routes sont hors /api/v1 et servent le HTML : vérifier surtout le code de retour
curl -sS -o /dev/null -w '%{http_code}\n' "$AO_URL/"
curl -sS -o /dev/null -w '%{http_code}\n' "$AO_URL/ui/support"
curl -sS -o /dev/null -w '%{http_code}\n' "$AO_URL/ui/static/app.css"
curl -sS "$AO_URL/openapi.json" -o openapi.json

# Équivalent PowerShell (même chose, sans curl)
Invoke-WebRequest -Uri "$AO_URL/openapi.json" -OutFile openapi.json
```

La console est **embarquée** : elle ne remplace pas l'API et n'ajoute pas de route métier. Les
capacités RBAC s'appliquent aux appels qu'elle émet depuis le navigateur.

## 4. Rôles des codes HTTP

| HTTP | `error.code` | Quand |
|---|---|---|
| `200` | — | Lecture ou transition réussie |
| `202` | — | Ingestion acceptée (traitement asynchrone) |
| `204` | — | Succès sans corps (révocation de clé) |
| `400` | `validation_error` | Requête malformée, paramètres incohérents |
| `401` | `unauthenticated` | `X-API-Key` absente, inconnue ou révoquée |
| `403` | `forbidden` | Clé valide mais **capacité manquante** |
| `404` | `not_found` | Ressource inexistante — ou appartenant à un autre tenant |
| `409` | `conflict` | Transition d'état interdite (exécuter une action non approuvée) |
| `422` | `unprocessable` | Corps bien formé mais invalide (schéma / domaine) |
| `429` | `rate_limited` | Quota dépassé (ingestion) |
| `500` | `internal_error` | Erreur interne ; en `THOT_ENV=prod` les détails sont masqués |
| `503` | — | `/readyz` : dépendance indisponible (DB, bus, règles) |

## 5. Erreurs normalisées

Forme unique :

```json
{
  "error": {
    "code": "forbidden",
    "message": "…",
    "details": {}
  }
}
```

`details` est **libre** : ne codez jamais contre son contenu, seulement contre `code`.

Exemple réel — `403` : planification d'une action avec une clé `analyst`.

```json
{
  "error": {
    "code": "forbidden",
    "message": "capacité requise manquante : execute:actions",
    "details": {
      "required_capability": "execute:actions",
      "role": "analyst",
      "tenant_id": "acme"
    }
  }
}
```

Exemple réel — `409` : exécution d'une action encore en `pending_approval`.

```json
{
  "error": {
    "code": "conflict",
    "message": "action a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c non approuvée : exécution refusée",
    "details": {
      "action_id": "a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c",
      "status": "pending_approval",
      "expected_status": "approved"
    }
  }
}
```

!!! note "Deux formes coexistent en pratique"
    La validation de schéma déléguée à FastAPI peut produire un `422` au format
    `{"detail": [ … ]}`. La forme **contractuelle** reste `{"error":{"code":…}}` : vos clients
    doivent savoir lire la première sans se briser, et se reposer sur la seconde.

### Traiter les erreurs côté client

| Code | Réaction recommandée |
|---|---|
| `400` / `422` | Bug d'appel : corrigez la requête, ne réessayez pas à l'identique |
| `401` | Clé absente/révoquée → régénérer, **ne pas** boucler |
| `403` | Vérifier `capabilities` via `whoami` ; changer de clé, pas de logique |
| `404` | Vérifier l'identifiant **et** le tenant de la clé (isolation) |
| `409` | Relire l'objet (`GET`) avant de retenter : l'état a changé |
| `429` | Backoff exponentiel + jitter ; respecter `Retry-After` s'il est présent |
| `500` | Réessayer avec parcimonie (2-3 fois) puis alerter |

## 6. Pagination par curseur

| Route | `limit` | Défaut documenté | Filtres |
|---|---|---|---|
| `/api/v1/events` | ≤ 500 | **100** (contrat §4.3) | `kind, source_type, since, until, q, cursor` |
| `/api/v1/findings` | (borner comme ci-dessus) | non figé | `status, severity, rule_id, since, until, min_risk, sort, cursor` |
| `/api/v1/actions` | (borner comme ci-dessus) | non figé | `status, playbook, finding_id, cursor` |
| `/api/v1/audit` | (borner comme ci-dessus) | non figé | `since, until, action, actor, cursor` |

`sort` accepte `risk_score` ou `last_seen` sur les findings.

!!! warning "Nom exact du curseur : à confirmer par /openapi.json"
    Le contrat impose un curseur **opaque** (`cursor` en entrée, `limit` en entrée) mais ne fige pas
    le nom du champ de sortie (`next_cursor` ? `cursor` ? `has_more` ?) pour **toutes** les routes.
    Vérifiez la forme exacte dans `GET /openapi.json` avant d'écrire un client définitif. Le
    raisonnement ci-dessous reste valable quel que soit le nom : boucler tant que le curseur renvoyé
    est non nul.

Boucle générique, telle qu'on peut l'écrire dès aujourd'hui — l'extraction du curseur est isolée dans
une seule expression, à ajuster selon l'OpenAPI :

```bash
# Pagination complète des findings, du plus risqué au moins risqué
CURSOR=""
: > findings.jsonl
while :; do
  RESP=$(curl -sS -G "$AO_URL/api/v1/findings" \
    -H "X-API-Key: $AO_KEY" \
    --data-urlencode 'status=open' \
    --data-urlencode 'sort=risk_score' \
    --data-urlencode 'limit=500' \
    ${CURSOR:+--data-urlencode "cursor=$CURSOR"})

  echo "$RESP" | python -c 'import json,sys; [print(json.dumps(i,ensure_ascii=False)) for i in json.load(sys.stdin)["items"]]' >> findings.jsonl

  # ⚠️ adapter le nom du champ à /openapi.json
  CURSOR=$(echo "$RESP" | python -c 'import json,sys; print(json.load(sys.stdin).get("next_cursor") or "")')
  [ -z "$CURSOR" ] && break
done
wc -l findings.jsonl
```

Règles d'or de la pagination :

1. **Toujours** fixer `limit` explicitement : un défaut implicite change la charge serveur.
2. Traiter `limit` comme une **borne haute** : le serveur peut en renvoyer moins.
3. Ne jamais fabriquer un curseur à la main : c'est un jeton opaque propre à la requête et au tri.
4. Boucler avec un garde-fou (nombre maximal de pages) pour éviter une boucle infinie si le champ de
   curseur n'est pas celui attendu.
5. Pour les exports massifs, préférez les flux dédiés : `/api/v1/audit/export` (audit) et les
   rapports de finding (par finding).

## 7. Ingestion par lot

`POST /api/v1/events` accepte **un objet `Event`** ou **`{"events":[Event,…]}`** avec **au plus 500
événements** par appel. Le champ `tenant_id` est **forcé depuis la clé API** : une valeur dans le
corps est ignorée (jamais une source d'autorité).

```bash
curl -sS -X POST "$AO_URL/api/v1/events" \
  -H "X-API-Key: $AO_KEY" -H "Content-Type: application/json" \
  -d '{"events":[
        {"schema_version":"1","ts":"2026-02-14T10:00:00.123Z","kind":"http.request",
         "source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},
         "severity_hint":"info",
         "labels":{"src_ip":"203.0.113.9","path":"/login","method":"POST"},
         "payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null},
        {"schema_version":"1","ts":"2026-02-14T10:00:04.000Z","kind":"log.line",
         "source":{"type":"log_tail","name":"nginx-edge","host":"shop.acme.fr"},
         "severity_hint":"medium",
         "labels":{"src_ip":"203.0.113.9","path":"/login"},
         "payload":{"line":"POST /login?id=1 UNION SELECT …"},"raw_ref":null}
      ]}'
# → 202 ; 400/422 (un ou plusieurs événements invalides) ; 401 ; 403 ; 429
```

Réponse `202` :

```json
{
  "accepted": 2,
  "rejected": 0,
  "event_ids": ["e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11", "7b21c9d0-5a44-4f1e-9c33-8d9e0a1b2c3d"],
  "findings": [
    {
      "finding_id": "f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f",
      "rule_id": "AO-WEB-001",
      "severity": "high",
      "risk_score": 78.5,
      "decision": "require_approval"
    }
  ]
}
```

`rejected > 0` signifie qu'une partie du lot a été refusée : le détail est à chercher côté
diagnostic serveur, et le lot doit être réémis **sans** les éléments acceptés (les `event_ids`
listés sont ceux retenus).

### 7.1 Fichier `.jsonl` et CLI d'ingestion

Un fichier JSON Lines contient **un objet `Event` par ligne**, 500 lignes maximum par appel :

```text
{"schema_version":"1","ts":"2026-02-14T10:00:00.123Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"info","labels":{"src_ip":"203.0.113.9","path":"/login","method":"POST"},"payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}
{"schema_version":"1","ts":"2026-02-14T10:00:04.000Z","kind":"log.line","source":{"type":"log_tail","name":"nginx-edge","host":"shop.acme.fr"},"severity_hint":"medium","labels":{"src_ip":"203.0.113.9","path":"/login"},"payload":{"line":"POST /login?id=1 UNION SELECT …"},"raw_ref":null}
```

```bash
# Depuis un fichier
thotsecure ingest --tenant acme --file events.jsonl

# Depuis un flux (traitement de pipeline)
tail -n 500 /var/log/nginx/access.jsonl | thotsecure ingest --tenant acme --stdin
```

```powershell
# Équivalent PowerShell : alimenter la CLI depuis un pipeline
Get-Content .\events.jsonl -Tail 500 | thotsecure ingest --tenant acme --stdin
```

### 7.2 Garde-fous d'ingestion

| Garde-fou | Valeur / variable |
|---|---|
| Taille maximale d'un lot | 500 événements par appel |
| Taille maximale de `payload` | 32 Kio sérialisé ; au-delà tronqué et `raw_ref` renseigné |
| Limitation de débit | `THOT_RATE_LIMIT_PER_MIN` (défaut `600`) → `429` au-delà |
| Taille de corps HTTP | limitée par la couche API (§10, anti-abus) |
| Isolation | `tenant_id` déduit de la clé, filtrage systématique par tenant |

!!! tip "Ingérer en petits lots plutôt qu'en gros"
    Un lot de 500 événements volumineux (`payload` proche de 32 Kio) peut dépasser la limite de
    taille de corps avant d'atteindre la limite de comptage. Visez 100 à 200 événements par appel,
    activez un backoff sur `429`, et surveillez `rejected` plutôt que de supposer que tout est passé.

## 8. Clients Python

### 8.1 Exemple autonome (stdlib ou `requests`)

Le core Thot Secure ne dépend que de la stdlib : l'exemple ci-dessous l'est aussi, et reste valable sur
toute installation.

```python
"""Ingestion, lecture des findings et cycle d'action complet — stdlib uniquement."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("AO_URL", "http://127.0.0.1:8080")
KEY = os.environ["AO_KEY"]  # jamais en dur dans le code source
TENANT = "acme"


def call(method: str, path: str, body=None, params=None, timeout: float = 30.0):
    """Appel API minimal : renvoie (status, payload) ou lève une erreur normalisée."""
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"X-API-Key": KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        if raw:
            error = json.loads(raw).get("error", {})
            raise RuntimeError(
                "HTTP %s %s: %s" % (exc.code, error.get("code"), error.get("message"))
            ) from exc
        raise RuntimeError("HTTP %s" % exc.code) from exc


# 1. Vérifier qui je suis et ce que je peux faire
_, me = call("GET", "/api/v1/auth/whoami")
print("tenant=%s role=%s mode=%s" % (me["tenant_id"], me["role"], me["mode"]))
assert "execute:actions" in me["capabilities"]

# 2. Ingérer un lot d'événements (tenant_id forcé depuis la clé)
status, ingest = call(
    "POST",
    "/api/v1/events",
    {
        "events": [
            {
                "schema_version": "1",
                "ts": "2026-02-14T10:00:00.123Z",
                "kind": "http.request",
                "source": {"type": "web_probe", "name": "prod-edge", "host": "shop.acme.fr"},
                "severity_hint": "info",
                "labels": {"src_ip": "203.0.113.9", "path": "/login", "method": "POST"},
                "payload": {"status": 403, "bytes": 512, "user_agent": "curl/8.5"},
                "raw_ref": None,
            }
        ]
    },
)
assert status == 202, status
print("acceptés=%s rejetés=%s" % (ingest["accepted"], ingest["rejected"]))

# 3. Lire les findings ouverts les plus risqués
_, page = call(
    "GET",
    "/api/v1/findings",
    params={"status": "open", "min_risk": 70, "sort": "risk_score", "limit": 50},
)
for finding in page["items"]:
    print(finding["finding_id"], finding["severity"], finding["risk_score"], finding["title"])

finding_id = page["items"][0]["finding_id"]

# 4. Planifier une contre-mesure réversible (aucun effet de bord)
_, action = call(
    "POST",
    "/api/v1/actions/plan",
    {
        "finding_id": finding_id,
        "playbook": "block-source-ip",
        "params": {"target": "203.0.113.9", "duration_seconds": 3600},
        "dry_run": True,
    },
)
action_id = action["action_id"]
print("action=%s statut=%s" % (action_id, action["status"]))

# 5. Approuver (capacité approve:actions), exécuter, puis annuler
call("POST", "/api/v1/actions/%s/approve" % action_id, {"comment": "Validation astreinte"})
call("POST", "/api/v1/actions/%s/execute" % action_id, {})
call("POST", "/api/v1/actions/%s/rollback" % action_id, {})

# 6. Vérifier la chaîne d'audit (doit rester valide)
_, audit = call("GET", "/api/v1/audit/verify")
print("audit valide=%s enregistrements=%s" % (audit["valid"], audit["records"]))
```

Avec `requests` installé, le même parcours se résume à :

```python
import os, requests

session = requests.Session()
session.headers.update({"X-API-Key": os.environ["AO_KEY"]})

me = session.get("http://127.0.0.1:8080/api/v1/auth/whoami", timeout=30).json()
findings = session.get(
    "http://127.0.0.1:8080/api/v1/findings",
    params={"status": "open", "min_risk": 70, "limit": 50},
    timeout=30,
).json()
```

### 8.2 SDK Python officiel — à confirmer dans le code

!!! note "La signature du SDK n'est pas figée par le contrat"
    Le contrat (§2) indique que le **client Python officiel, utilisable en lib**, vit dans
    `src/thotsecure/sdk/`. Le contrat décrit les **routes**, pas les noms de classes ni de méthodes du
    SDK. Cette page montre donc volontairement de l'HTTP brut, qui reste exact quelle que soit la
    surface publique du SDK.

    Au moment de la rédaction, le dépôt contient `sdks/python/thotsecure_sdk/` avec ses modules
    `transport.py` (transport `httpx` avec repli `urllib`, retries bornés sur `429/502/503/504`,
    respect de `Retry-After`) et `errors.py` (hiérarchie `ThotSecureError`, `AuthenticationError`,
    `PermissionDeniedError`, `ConflictError`, `RateLimitedError`, …). Aucune façade client publique
    n'y est encore arrêtée : **vérifiez `src/thotsecure/sdk/` et `sdks/python/` avant d'écrire du code
    qui dépend d'un nom de méthode.** Les types d'erreur du SDK correspondent aux huit codes du
    §5, ce qui permet de traiter `401/403/409/429` sans analyser les messages.

Deux réflexes valables avec n'importe quel client Python :

1. Une seule fabrique de client par processus (pool de connexions), une clé par usage.
2. `idempotency_key` sur les `POST /actions/*` rejoués : le serveur déduplique (`execute` idempotent).

## 9. Clients TypeScript

!!! note "Dépôt SDK séparé — API à confirmer"
    Le contrat mentionne `sdks/{python,typescript,go}/` comme dépôts de SDK, distincts de l'API. Le
    client TypeScript publié doit être confirmé dans le dépôt SDK ; l'exemple ci-dessous n'utilise
    que l'API `fetch` standard, disponible dans Node 18+ et dans tous les navigateurs récents.

```typescript
const BASE = process.env.AO_URL ?? "http://127.0.0.1:8080";
const KEY = process.env.AO_KEY!;

interface ApiErrorBody {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

/** Erreur d'API portant le code contractuel (forbidden, conflict, ...). */
export class ThotSecureApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ThotSecureApiError";
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { "X-API-Key": KEY, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 204) return undefined as T;

  const payload = (await response.json().catch(() => undefined)) as ApiErrorBody | undefined;

  if (!response.ok) {
    const code = payload?.error?.code ?? "internal_error";
    const message = payload?.error?.message ?? `HTTP ${response.status}`;
    // 401 : clé absente/révoquée — régénérer la clé, ne pas boucler.
    // 403 : capacité manquante — vérifier whoami().capabilities et changer de clé.
    // 409 : transition d'état interdite — relire l'objet avant de retenter.
    throw new ThotSecureApiError(response.status, code, message, payload?.error?.details);
  }

  return payload as T;
}

// Parcours : qui suis-je → ingérer → lire les findings → planifier
const me = await call<{ tenant_id: string; role: string; capabilities: string[] }>(
  "GET",
  "/api/v1/auth/whoami",
);

const ingested = await call<{ accepted: number; rejected: number; findings: unknown[] }>(
  "POST",
  "/api/v1/events",
  {
    events: [
      {
        schema_version: "1",
        ts: "2026-02-14T10:00:00.123Z",
        kind: "http.request",
        source: { type: "web_probe", name: "prod-edge", host: "shop.acme.fr" },
        severity_hint: "info",
        labels: { src_ip: "203.0.113.9", path: "/login", method: "POST" },
        payload: { status: 403, bytes: 512, user_agent: "curl/8.5" },
        raw_ref: null,
      },
    ],
  },
);

const findings = await call<{ items: Array<{ finding_id: string; risk_score: number }> }>(
  "GET",
  "/api/v1/findings?status=open&min_risk=70&sort=risk_score&limit=50",
);

const action = await call<{ action_id: string; status: string }>("POST", "/api/v1/actions/plan", {
  finding_id: findings.items[0].finding_id,
  playbook: "block-source-ip",
  params: { target: "203.0.113.9", duration_seconds: 3600 },
  dry_run: true,
});

console.log(me.tenant_id, ingested.accepted, action.action_id, action.status);
```

!!! warning "Ne stockez jamais la clé API dans un bundle navigateur"
    Un client TypeScript exécuté dans un navigateur expose tout ce qu'il contient. Les appels REST
    authentifiés doivent passer par un backend intermédiaire ; seul le WebSocket, avec
    `?api_key=…`, est prévu pour un usage navigateur en MVP.

## 10. Flux temps réel : `WS /api/v1/ws/stream`

| Élément | Valeur |
|---|---|
| Chemin | `/api/v1/ws/stream` |
| Capacité | `read:events` |
| Authentification | `?api_key=ao_…` (en-tête impossible sur `ws://` côté navigateur) |
| Frames | `{"type":"event\|finding\|action\|audit\|heartbeat","data":{…}}` |

### 10.1 Inspection rapide avec `wscat`

```bash
# wscat est un outil de développement (Node) : jamais en production ni en CI bloquante
npx wscat -c "ws://127.0.0.1:8080/api/v1/ws/stream?api_key=ao_..."
# En TLS / derrière un reverse-proxy :
npx wscat -c "wss://thotsecure.acme.fr/api/v1/ws/stream?api_key=ao_..."
```

### 10.2 Client JavaScript complet (reconnexion + heartbeat)

```javascript
// Reconnexion avec backoff exponentiel et surveillance du heartbeat.
const WS_BASE = "ws://127.0.0.1:8080"; // "wss://" si TLS / reverse-proxy
const API_KEY = "ao_..."; // en MVP, seule la WS accepte la clé en query string

let delayMs = 1000;
let lastFrameAt = Date.now();
let socket;

function handleFrame(frame) {
  if (frame.type === "heartbeat") return; // sert à détecter un flux muet
  switch (frame.type) {
    case "finding":
      console.log("nouveau finding", frame.data.finding_id, frame.data.severity);
      break;
    case "action":
      console.log("action", frame.data.action_id, frame.data.status);
      break;
    case "event":
    case "audit":
      console.log(frame.type, frame.data);
      break;
    default:
      console.warn("type de frame inconnu", frame);
  }
}

function connect() {
  const url = `${WS_BASE}/api/v1/ws/stream?api_key=${encodeURIComponent(API_KEY)}`;
  socket = new WebSocket(url);

  socket.onopen = () => {
    delayMs = 1000; // réinitialiser le backoff après une connexion réussie
    lastFrameAt = Date.now();
    console.log("flux ouvert");
  };

  socket.onmessage = (event) => {
    lastFrameAt = Date.now();
    try {
      handleFrame(JSON.parse(event.data));
    } catch (err) {
      console.error("frame illisible", err);
    }
  };

  socket.onerror = () => socket.close();

  socket.onclose = (event) => {
    console.warn(`flux fermé (code ${event.code}) — reconnexion dans ${delayMs} ms`);
    setTimeout(connect, delayMs);
    delayMs = Math.min(delayMs * 2, 30000); // plafond : 30 s
  };
}

connect();

// Surveillance : un flux sans aucune frame (heartbeat compris) est suspect.
setInterval(() => {
  const silenceMs = Date.now() - lastFrameAt;
  if (silenceMs > 90000) console.warn(`flux silencieux depuis ${Math.round(silenceMs / 1000)} s`);
}, 30000);
```

!!! note "Un `401` sur WebSocket se voit à la fermeture, pas dans un corps JSON"
    Un handshake refusé pour clé absente ou invalide se manifeste par une fermeture immédiate côté
    navigateur : testez d'abord `GET /api/v1/auth/whoami` avec la même clé pour distinguer un
    problème d'authentification d'un problème réseau.

### 10.3 Variante PowerShell

PowerShell n'a pas de client WebSocket natif simple ; on utilise la classe .NET `ClientWebSocket`
(disponible dans PowerShell 7 et Windows PowerShell 5.1) :

```powershell
# Lecture du flux temps réel avec System.Net.WebSockets.ClientWebSocket
$apiKey = 'ao_...'
$uri = [Uri]"ws://127.0.0.1:8080/api/v1/ws/stream?api_key=$apiKey"

$ws = [System.Net.WebSockets.ClientWebSocket]::new()
$ws.ConnectAsync($uri, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

$buffer  = New-Object byte[] 16384
$segment = [ArraySegment[byte]]::new($buffer)

try {
    while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        $result = $ws.ReceiveAsync($segment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { break }

        $text  = [Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
        $frame = $text | ConvertFrom-Json
        if ($frame.type -eq 'heartbeat') { continue }

        [pscustomobject]@{ Type = $frame.type; Data = ($frame.data | ConvertTo-Json -Compress) }
    }
}
finally {
    $ws.Dispose()
}
```

Deux limites honnêtes de cet exemple : il ne réassemble pas les trames fragmentées
(`$result.EndOfMessage`) et n'implémente pas de reconnexion. Pour un usage durable, préférez un
client Node/Python ou l'outil `wscat` dans un terminal d'exploitation.

## 11. Notes de production

### 11.1 TLS

| Situation | Réglage |
|---|---|
| Terminaison TLS par un reverse-proxy (recommandé) | `THOT_TLS_ENABLED=false` ; TLS/redirection gérés par le proxy |
| TLS direct par Thot Secure | `THOT_TLS_ENABLED=true` (le certificat et la clé se configurent aussi par l'environnement — voir [`../configuration.md`](../configuration.md)) |
| Développement local | `http://127.0.0.1:8080`, aucune exposition réseau |

Le SDK Python **vérifie TLS par défaut** ; désactiver la vérification (`verify_tls=False`) produit un
avertissement explicite et ne doit servir que contre une instance locale. Voir
[`../operations/deployment.md`](../operations/deployment.md).

### 11.2 Reverse-proxy et WebSocket

Un proxy qui ne relaie pas l'`Upgrade` coupe le flux temps réel (le REST continue de fonctionner, ce
qui rend la panne discrète).

- Transmettre `Upgrade: websocket` et `Connection: upgrade` ;
- prévoir des timeouts longs sur la route `/api/v1/ws/stream` et laisser passer les `ping`/`pong` :
  un proxy qui coupe les connexions inactives tuera un flux légitimement calme ;
- transmettre `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` et journaliser l'IP
  d'origine, utile pour les rapports et l'audit ;
- éviter de journaliser l'URL complète du WebSocket au niveau du proxy : elle contient la clé API.

### 11.3 Observabilité

| Endpoint | Exposition |
|---|---|
| `/healthz` | Sondes du proxy / orchestrateur |
| `/readyz` | Sondes de disponibilité (`503` si DB, bus ou règles indisponibles) |
| `/metrics` | **Réseau interne uniquement** — « public (réseau interne) » au §4.1 du contrat |

```yaml
# Extrait indicatif de configuration de scrape (réseau interne seulement)
scrape_configs:
  - job_name: thotsecure
    metrics_path: /metrics
    static_configs:
      - targets: ["thotsecure.internal:8080"]
```

Le tableau de bord agrégé (dont le mode d'autonomie courant) est exposé par
`GET /api/v1/stats/overview`, avec la capacité `read:stats`.

### 11.4 Rotation des clés

1. Créer la nouvelle clé : `POST /api/v1/tenants/{id}/keys` (le secret n'apparaît **qu'une fois**).
2. Déployer le nouveau secret dans les clients et vérifier `whoami`.
3. Surveiller `last_used_at` de l'ancienne clé via `GET /api/v1/tenants/{id}/keys`.
4. Révoquer : `DELETE /api/v1/keys/{key_id}` → `204`.
5. En cas de fuite, inverser l'ordre : **révoquer d'abord**, redéployer ensuite.

### 11.5 Débit, taille et journalisation client

| Point de vigilance | Recommandation |
|---|---|
| Limitation de débit | `THOT_RATE_LIMIT_PER_MIN` (défaut `600`) ; backoff exponentiel + jitter sur `429` |
| Taille de corps | Lots de 100 à 200 événements ; `payload` ≤ 32 Kio |
| Timeouts client | 30 s par défaut ; au-delà, considérer l'appel comme suspect et journaliser |
| Journalisation client | `méthode chemin statut durée` — **jamais** la clé API ni les corps contenant des données personnelles |
| Multi-tenant | Une clé par tenant ; ne jamais mutualiser une clé entre tenants |
| `THOT_ENV=prod` | Durcit les défauts et masque les détails d'erreur (`500`) : indispensable hors dev |

!!! info "Roadmap"
    Les routes de facturation, de quotas par tenant et de rotation automatique de clés ne font pas
    partie du MVP v0.1.0. Suivez [`../roadmap.md`](../roadmap.md) et
    [`../changelog.md`](../changelog.md) pour l'ouverture éventuelle de ces capacités.

## 12. Voir aussi

- Référence gelée : [`../architecture/api-contract.md`](../architecture/api-contract.md)
- CLI (mêmes opérations, sans HTTP) : [`../cli.md`](../cli.md)
- Règles et detections : [`../detection/rules.md`](../detection/rules.md), [`../detection/sigma.md`](../detection/sigma.md)
- Politiques et playbooks : [`../decision/policies.md`](../decision/policies.md), [`../actions/playbooks.md`](../actions/playbooks.md)
- Déploiement et exploitation : [`../operations/deployment.md`](../operations/deployment.md), [`../operations/runbook.md`](../operations/runbook.md)
- Sécurité et données : [`../architecture/threat-model.md`](../architecture/threat-model.md), [`../compliance/rgpd.md`](../compliance/rgpd.md)
- Glossaire : [`../glossary.md`](../glossary.md)

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
