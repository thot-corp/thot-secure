# Référence CLI `thotsecure`

*Référence des commandes de la CLI Thot Secure v0.1.0 : options, sorties attendues, codes de sortie et automatisation CI.*

La CLI est le moyen le plus direct d'exploiter Thot Secure : elle parle à la même base et au même
moteur que l'API, sans dépendance réseau. Les commandes listées ici sont **exactement** celles du
§8 du contrat d'interface ([`../architecture/api-contract.md`](architecture/api-contract.md)) ;
les correspondances avec les routes REST sont données au §9 de cette page.

!!! warning "N'utilisez pas d'option non documentée en production"
    Le contrat ne documente que les options ci-dessous (plus le drapeau global `--json`). Un script
    qui s'appuie sur une option non listée casse au premier changement d'implémentation : vérifiez
    `thotsecure --help` sur la version déployée avant de figer un pipeline.

## 1. Installation et invocation

```bash
# Installation depuis les sources du dépôt
# (extra "dev" pour les tests et le lint : pip install -e ".[dev]")
pip install -e .

# Vérifier l'installation et lister les commandes
thotsecure --help

# Lancer l'API + la console embarquée
thotsecure serve --host 0.0.0.0 --port 8080
```

Toutes les commandes peuvent s'exécuter hors ligne sur une base locale — `serve` n'est nécessaire que
pour l'API et la console. Détails d'installation (paquets, dépendances optionnelles, Docker) :
[`../installation.md`](installation.md).

!!! note "Aide détaillée d'une sous-commande"
    `thotsecure --help` liste les commandes ; chaque sous-commande expose sa propre aide
    (`thotsecure <commande> --help`), selon le comportement standard d'`argparse`. En cas de doute,
    l'aide de la version installée fait foi.

## 2. Variables d'environnement et fichier `.env`

La configuration est lue depuis l'environnement (`THOT_*`) et depuis un fichier **`.env`** à la
racine du projet. Le fichier `.env` est pratique en développement ; en production, préférez
l'injection par l'orchestrateur ou un coffre de secrets.

| Variable | Défaut | Rôle |
|---|---|---|
| `THOT_ENV` | `dev` | `dev` \| `prod` (durcit les défauts, masque les erreurs) |
| `THOT_HOST` / `THOT_PORT` | `0.0.0.0` / `8080` | Écoute de `serve` |
| `THOT_SECRET_KEY` | *généré + avertissement* | Pepper des clés API + signature |
| `THOT_BOOTSTRAP_API_KEY` | `ao_dev_local_change_me` | Clé admin initiale — **à changer** |
| `THOT_DB_URL` | `sqlite:///./data/thotsecure.db` | Persistance (SQLite en MVP) |
| `THOT_RULES_DIR` | `./rules` | Bibliothèque de règles |
| `THOT_POLICIES_DIR` | `./policies` | Politiques de décision |
| `THOT_PLAYBOOKS_DIR` | `./playbooks` | Playbooks |
| `THOT_BUS` | `memory` | `memory` \| `sqlite` \| `nats` |
| `THOT_NATS_URL` | `nats://127.0.0.1:4222` | Bus distribué |
| `THOT_AUTONOMY` | `supervised` | `manual` \| `supervised` \| `auto` (surchargeable par tenant) |
| `THOT_DRY_RUN` | `true` | **Sécurité** : aucune action réelle si `true` |
| `THOT_RETENTION_DAYS` | `30` | Purge des événements |
| `THOT_OPA_BIN` | *(vide)* | Binaire OPA pour le mode Rego |
| `THOT_LOG_LEVEL` | `INFO` | `DEBUG`…`CRITICAL` |
| `THOT_LOG_FORMAT` | `json` | `json` \| `console` |
| `THOT_TLS_ENABLED` | `false` | HTTPS direct (sinon reverse-proxy) |
| `THOT_RATE_LIMIT_PER_MIN` | `600` | Garde-fou anti-abus sur l'ingestion |
| `THOT_TARGETS_FILE` | `./config/targets.yaml` | Cibles déclarées par tenant (périmètre autorisé) |

Exemple de `.env` de développement :

```ini
THOT_ENV=dev
THOT_LOG_LEVEL=DEBUG
THOT_LOG_FORMAT=console
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised
THOT_BUS=sqlite
```

```powershell
# PowerShell : injecter les variables pour la session courante (pas de fichier .env)
$env:THOT_LOG_LEVEL = 'DEBUG'
$env:THOT_DRY_RUN     = 'true'
thotsecure doctor
```

Référence complète : [`../configuration.md`](configuration.md).

## 3. Vue d'ensemble des commandes

| Commande | Rôle équivalent (REST) | Effet | Code de sortie typique |
|---|---|---|---|
| `serve [--host --port --reload]` | — | Démarre l'API, la console et le flux WS | `0` à l'arrêt propre ; `1` si l'écoute échoue |
| `init-db` | — | Crée/migre le schéma de persistance | `0` ; `1` si la base est inaccessible |
| `doctor` | `read:stats` + `read:audit` | Diagnostic de l'installation | `0` si tout est vert ; non nul sinon |
| `tenant create --id --name --mode` | `admin:tenants` | Crée un tenant | `0` ; `1` si l'identifiant existe déjà |
| `tenant list` | `admin:tenants` | Liste les tenants | `0` ; `1` |
| `key create --tenant --role [--label]` | `admin:keys` | Émet une clé API (**affichée une fois**) | `0` ; `1` si le tenant est inconnu |
| `key revoke --key-id` | `admin:keys` | Révoque immédiatement une clé | `0` ; `1` si la clé est inconnue |
| `rules list` | `read:rules` | Inventaire des règles chargées | `0` ; `1` |
| `rules validate [--path rules]` | `admin:rules` | Valide des règles sans les activer | `0` si toutes valides ; `1` sinon |
| `policies validate` | `admin:policies` | Valide les politiques | `0` si toutes valides ; `1` sinon |
| `ingest --tenant --file \| --stdin` | `write:events` | Ingère des événements → findings | `0` ; `1` ; `2` si ni `--file` ni `--stdin` |
| `findings list --tenant [--severity] [--min-risk]` | `read:findings` | Liste les findings | `0` ; `1` |
| `findings show <finding_id>` | `read:findings` | Détail d'un finding | `0` ; `1` si introuvable |
| `actions list` | `read:findings` | Liste les actions | `0` ; `1` |
| `actions plan --finding <id> --playbook <nom>` | `execute:actions` | Prépare une action (**sans effet**) | `0` ; `1` si finding/playbook inconnu |
| `actions approve <id>` | `approve:actions` | Approuve une action en attente | `0` ; `1` si transition interdite |
| `actions execute <id>` | `execute:actions` | Exécute une action approuvée | `0` ; `1` si non approuvée ou déjà exécutée |
| `actions rollback <id>` | `execute:actions` | Annule une action exécutée | `0` ; `1` si rollback indisponible/expiré |
| `audit verify` | `read:audit` | Vérifie la chaîne de hachage | `0` valide ; **`3` chaîne rompue** ; `1` erreur |
| `audit tail` | `read:audit` | Suit le journal en direct | `0` à l'arrêt ; `1` |
| `report <finding_id> --format … [-o]` | `read:findings` | Produit un rapport (md/html/json/sarif) | `0` ; `1` ; `2` si `--format` manquant/invalide |
| `probe --tenant --target` | `execute:actions` | Audite **sa propre** surface déclarée | `0` rapport produit ; non nul si la cible est refusée ou l'audit échoue |
| `demo --tenant` | `admin:tenants` | Jeu de démonstration + findings + actions | `0` ; `1` |

!!! note "Ce que signifie « rôle équivalent »"
    La CLI s'exécute avec les privilèges **locaux** du processus (accès direct à la base) : elle
    n'applique pas elle-même le RBAC des clés API. La colonne indique la **capacité REST
    correspondante**, à utiliser comme référence quand la même opération est déléguée à l'API ou à
    une clé de service — voir [`api/usage.md`](api/usage.md).

## 4. Commandes en détail

### 4.1 `thotsecure serve`

Démarre l'API FastAPI (préfixe `/api/v1`), la console embarquée (`/`) et le flux temps réel
(`/api/v1/ws/stream`).

| Option | Rôle |
|---|---|
| `--host` | Adresse d'écoute (défaut `THOT_HOST`, `0.0.0.0`) |
| `--port` | Port d'écoute (défaut `THOT_PORT`, `8080`) |
| `--reload` | Rechargement automatique — **développement uniquement** |

```bash
# Développement
thotsecure serve --host 127.0.0.1 --port 8080 --reload

# Production : pas de --reload, derrière un reverse-proxy TLS
THOT_ENV=prod thotsecure serve --host 0.0.0.0 --port 8080
```

```text
INFO  thotsecure.api     démarrage — env=prod version=0.1.0
INFO  thotsecure.storage sqlite:///./data/thotsecure.db (tenant isolation: on)
INFO  thotsecure.rules   42 règles chargées (0 erreur)
INFO  uvicorn          Uvicorn running on http://0.0.0.0:8080
```

```powershell
# Variante PowerShell (production locale)
$env:THOT_ENV = 'prod'
thotsecure serve --host 0.0.0.0 --port 8080
```

!!! warning "`--reload` n'est pas pour la production"
    Le rechargement automatique surveille les fichiers et redémarre le processus : il masque des
    erreurs de démarrage et consomme des ressources. En production, utilisez le service systemd /
    conteneur décrit dans [`../operations/deployment.md`](operations/deployment.md).

### 4.2 `thotsecure init-db`

Crée ou migre le schéma de persistance (tables, index, journal d'audit avec son enregistrement
genesis). Idempotent : relancer la commande sur une base à jour ne détruit rien.

```bash
thotsecure init-db
```

```text
INFO  thotsecure.storage schéma appliqué : 14 tables, 21 index
INFO  thotsecure.audit   genesis présent (prev_hash="sha256:genesis")
```

```powershell
thotsecure init-db
```

### 4.3 `thotsecure doctor`

Diagnostic de bout en bout : configuration, base, bus, répertoires de règles/politiques/playbooks,
clé bootstrap, mode d'autonomie et `dry_run`, cohérence de la chaîne d'audit. **Première commande à
lancer** devant tout comportement inattendu — procédure complète dans
[`../operations/runbook.md`](operations/runbook.md).

```bash
thotsecure doctor
```

```text
[ok]   configuration        env=dev autonomy=supervised dry_run=true
[ok]   base de données      sqlite:///./data/thotsecure.db (lecture/écriture)
[ok]   bus                  memory (non durable en dev — attendu)
[ok]   règles               42 chargées, 0 erreur
[ok]   politiques           6 chargées (priorité max=100)
[ok]   playbooks            11 disponibles, tous réversibles
[warn] THOT_SECRET_KEY absente : clé éphémère générée (dev uniquement)
[warn] THOT_BOOTSTRAP_API_KEY utilise la valeur de développement publique
[ok]   audit                chaîne valide (1284 enregistrements)
```

```bash
# Version machine, puis filtrage des avertissements
thotsecure doctor --json | jq '.checks[] | select(.status != "ok")'
```

```powershell
# PowerShell : n'afficher que les contrôles en échec
(thotsecure doctor --json | ConvertFrom-Json).checks |
  Where-Object { $_.status -ne 'ok' } |
  Format-Table name, status, message -AutoSize
```

!!! tip "`doctor` avant tout le reste"
    Un `403` inattendu, un flux muet ou une ingestion qui « ne produit pas de finding » se
    diagnostiquent presque toujours en trois lignes de `doctor` : répertoires de règles, bus, et
    mode d'autonomie.

### 4.4 `thotsecure tenant create` / `thotsecure tenant list`

| Option | Rôle |
|---|---|
| `--id` | Identifiant du tenant (`acme`) — sert de frontière d'isolation |
| `--name` | Nom lisible (« ACME SAS ») |
| `--mode` | `manual` \| `supervised` \| `auto` |

```bash
thotsecure tenant create --id acme --name "ACME SAS" --mode supervised
thotsecure tenant list
```

```text
tenant_id  name       mode        dry_run  created_at
acme       ACME SAS   supervised  true     2026-02-14T09:58:11Z
demo       Demo Corp  supervised  true     2026-02-13T17:22:04Z
```

```powershell
thotsecure tenant create --id acme --name "ACME SAS" --mode supervised
thotsecure tenant list --json | ConvertFrom-Json | Format-Table tenant_id, mode, dry_run
```

!!! warning "`auto` est le mode le plus permissif"
    En mode `auto`, une politique peut déclencher une contre-mesure sans approbation humaine. Ne
    basculez un tenant en `auto` qu'après avoir posé l'`autonomy_allowlist` (infra propre protégée),
    vérifié le parc de playbooks réversibles et testé le rollback. Voir
    [`../decision/policies.md`](decision/policies.md).

### 4.5 `thotsecure key create` / `thotsecure key revoke`

| Option | Rôle |
|---|---|
| `--tenant` | Tenant propriétaire de la clé |
| `--role` | `viewer` \| `analyst` \| `responder` \| `admin` |
| `--label` | Étiquette libre (`ci`, `soc-n1`, `sre`) |

```bash
thotsecure key create --tenant acme --role responder --label ci
```

```text
key_id   : k_7f3a91c2
tenant   : acme
role     : responder
api_key  : ao_9f1c4b7e2d8a…          <-- affichée UNE SEULE FOIS, notez-la maintenant
```

```bash
thotsecure key revoke --key-id k_7f3a91c2
```

```text
clé k_7f3a91c2 révoquée (tenant=acme)
```

```powershell
$key = thotsecure key create --tenant acme --role responder --label ci --json | ConvertFrom-Json
$key.api_key | Set-Content -NoNewline .\acme-responder.key   # coffre/secret manager en production
thotsecure key revoke --key-id $key.key_id
```

!!! danger "Le secret n'est jamais relisible"
    Les clés sont stockées **hachées (`scrypt`)**. Si l'affichage est perdu, il n'existe aucun moyen
    de retrouver la clé : créez-en une nouvelle et révoquez l'ancienne. Une clé divulguée se révoque
    **immédiatement** — procédure dans [`../operations/runbook.md`](operations/runbook.md).

### 4.6 `thotsecure rules list` / `thotsecure rules validate`

```bash
# Inventaire
thotsecure rules list
```

```text
rule_id        severity  enabled  source_types           kinds
AO-WEB-001     high      true     web_probe, log_tail    http.request
AO-AUTH-004    medium    true     log_tail               log.line
AO-TLS-002     low       true     cert_watch             tls.cert
AO-DEP-011     high      true     dependency_scan        dependency
```

```bash
# Validation avant merge (le chemin est optionnel : --path rules par défaut)
thotsecure rules validate --path rules
```

```text
42 règles analysées : 42 valides, 0 invalide
```

Sortie en échec (la règle fautive est nommée, le chargement en cours n'est pas cassé) :

```text
41 règles valides, 1 invalide
[erreur] rules/web/AO-WEB-017.yaml
         match.all[0].op = "regexp" → opérateur inconnu (attendu: regex)
```

```powershell
thotsecure rules validate --path rules
if ($LASTEXITCODE -ne 0) { throw "règles invalides : merge bloqué" }
```

!!! tip "La validation ne remplace pas la revue"
    `rules validate` vérifie la **forme** (opérateurs, types, champs pointés), pas la pertinence de
    la détection. Voir [`../detection/rules.md`](detection/rules.md) et, pour l'import de règles
    Sigma, [`../detection/sigma.md`](detection/sigma.md).

### 4.7 `thotsecure policies validate`

Valide les politiques de décision (YAML ; mode Rego si `THOT_OPA_BIN` est défini et le binaire
présent).

```bash
thotsecure policies validate
```

```text
6 politiques analysées : 6 valides (priorité max=100, doublon de priorité: aucun)
```

```bash
# Détail machine des politiques chargées, telles que l'API les expose
thotsecure policies validate --json | jq '.policies[] | {id, priority, decision: .then.decision}'
```

```powershell
thotsecure policies validate --json | ConvertFrom-Json |
  Select-Object -ExpandProperty policies |
  Select-Object id, priority, @{ n = 'decision'; e = { $_.then.decision } }
```

!!! note "Pas d'option --path documentée"
    Le contrat §8 documente `rules validate [--path rules]` mais **pas** de `--path` sur
    `policies validate` : le répertoire lu est `THOT_POLICIES_DIR` (défaut `./policies`). Si un
    pipeline a besoin d'un autre répertoire, il faut passer par la variable d'environnement.

### 4.8 `thotsecure ingest`

| Option | Rôle |
|---|---|
| `--tenant` | Tenant cible — **obligatoire** (le tenant n'est jamais deviné) |
| `--file` | Fichier JSON Lines (un `Event` par ligne) |
| `--stdin` | Lecture depuis l'entrée standard (exclusif avec `--file`) |

```bash
thotsecure ingest --tenant acme --file events.jsonl
tail -n 200 /var/log/nginx/access.jsonl | thotsecure ingest --tenant acme --stdin
```

```text
tenant=acme
  lus        : 500
  acceptés   : 500
  rejetés    : 0
  findings   : 3 créés, 1 mis à jour
    f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f  AO-WEB-001  high    78.5  require_approval
    f2b3c5e7-2c3d-4e6f-9a01-1b2c3d4e5f60  AO-AUTH-004 medium  54.0  notify_only
    f3c4d6e8-3d4e-4f70-ab12-2c3d4e5f6071  AO-WEB-001  high    72.1  require_approval
```

```powershell
# Ingestion depuis un fichier, puis résumé JSON exploitable par un pipeline
Get-Content .\events.jsonl -Tail 500 | thotsecure ingest --tenant acme --stdin --json |
  ConvertFrom-Json | Format-List tenant_id, accepted, rejected
```

Format attendu d'un fichier `.jsonl` (un objet `Event` par ligne, `payload` ≤ 32 Kio) :

```text
{"schema_version":"1","ts":"2026-02-14T10:00:00.123Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"info","labels":{"src_ip":"203.0.113.9","path":"/login","method":"POST"},"payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}
```

!!! warning "`--tenant` est obligatoire, et c'est volontaire"
    Le tenant n'est jamais déduit du contenu : il vient de l'option (CLI) ou de la clé API (REST).
    Un `--tenant` erroné écrit dans la mauvaise frontière d'isolation — impossible à corriger par une
    suppression (les événements sont **immuables**). Vérifiez vos scripts avec `thotsecure tenant list`.

### 4.9 `thotsecure findings list` / `thotsecure findings show`

| Option | Rôle |
|---|---|
| `--tenant` | Tenant interrogé (obligatoire) |
| `--severity` | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `--min-risk` | Score de risque minimal (`0`–`100`) |

```bash
thotsecure findings list --tenant acme --severity high --min-risk 70
```

```text
finding_id                            severity  risk  status     rule_id     last_seen
f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f  high      78.5  open       AO-WEB-001  2026-02-14T10:04:12Z
f3c4d6e8-3d4e-4f70-ab12-2c3d4e5f6071  high      72.1  acked      AO-WEB-001  2026-02-14T09:41:55Z
```

```bash
thotsecure findings show f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f
```

```text
finding  f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f
titre    Tentative d'injection SQL depuis 203.0.113.9
règle    AO-WEB-001 (SQL injection attempt in query string)
sévérité high        risque 78.5        confiance 0.85       statut open
premier/dernier vu   2026-02-14T10:00:00Z → 2026-02-14T10:04:12Z   (7 occurrences)
tags     web, owasp:a03, mitre:T1190
actions  a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c  block-source-ip  approved
rapport  thotsecure report f1c2a4d6-… --format md
```

```powershell
# Findings à fort risque en JSON, prêts pour un ticket
thotsecure findings list --tenant acme --severity high --min-risk 70 --json |
  ConvertFrom-Json | Select-Object -ExpandProperty items |
  Select-Object finding_id, severity, risk_score, status | Format-Table -AutoSize
```

!!! note "Le cycle de vie se pilote côté API ou console"
    La CLI expose la **lecture** des findings ; les transitions (`ack`, `close`, `suppress`) sont
    documentées côté API ([`api/usage.md`](api/usage.md), §3.4). Il n'existe pas de commande de
    suppression de finding au MVP v0.1.0.

!!! info "Roadmap"
    Les filtres CLI au-delà de `--severity` et `--min-risk` (par règle, par plage de dates, tri
    explicite) ne sont pas documentés au §8 : utilisez `--json` et filtrez côté shell, ou interrogez
    l'API (`GET /api/v1/findings` accepte `status, severity, rule_id, since, until, min_risk, sort`).

### 4.10 `thotsecure actions`

| Commande | Rôle | Effet |
|---|---|---|
| `actions list` | `read:findings` | Liste les actions et leur statut |
| `actions plan --finding <id> --playbook <nom>` | `execute:actions` | Crée une action `planned` — **aucun effet de bord** |
| `actions approve <id>` | `approve:actions` | `pending_approval` → `approved` |
| `actions execute <id>` | `execute:actions` | Exécute (refus si non approuvée) |
| `actions rollback <id>` | `execute:actions` | Annule (refus si déjà annulée) |

```bash
thotsecure actions list
```

```text
action_id                             playbook         cible           statut            dry_run
a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c  block-source-ip  203.0.113.9     pending_approval  true
b02c4d8f-3a55-4b2c-8d88-6e7f901b2c3d  notify           soc@acme.fr     succeeded         false
```

Cycle complet — la planification n'a **aucun** effet, l'exécution est refusée sans approbation :

```bash
FID=f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f

thotsecure actions plan --finding $FID --playbook block-source-ip
thotsecure actions approve a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c
thotsecure actions execute a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c
thotsecure actions rollback a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c
```

```text
action planifiée a91b3c7e-2f44-4a1b-9c77-5d6e8f0a1b2c (statut=planned, dry_run=true)
  playbook : block-source-ip
  cible    : 203.0.113.9 (ip)
  rollback : disponible
action a91b3c7e-… approuvée par cli:local (statut=approved)
action a91b3c7e-… exécutée (statut=succeeded, connecteur=waf mode=simulation)
  rollback_token : rb_2f9c…
action a91b3c7e-… annulée (statut=rolled_back)
```

Échecs attendus, explicites et non silencieux :

```text
$ thotsecure actions execute a91b3c7e-…        # action encore en pending_approval
erreur : action a91b3c7e-… non approuvée (statut=pending_approval) — exécution refusée
$ echo $?
1
```

```powershell
# Automatisation PowerShell : planifier puis approuver en vérifiant chaque étape
$plan = thotsecure actions plan --finding f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f `
                              --playbook block-source-ip --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "planification impossible" }
Write-Output "action=$($plan.action_id) statut=$($plan.status) dry_run=$($plan.dry_run)"
```

!!! danger "Aucun connecteur configuré = mode simulé"
    Par défaut, un connecteur non configuré fonctionne en **mode simulé** (`null` / `simulation`) :
    il retourne un `rollback_token` et journalise `simulated: true`. C'est le comportement voulu du
    MVP — Thot Secure est sûr à brancher avant d'avoir des credentials. Ne concluez pas d'un
    `succeeded` qu'un pare-feu a réellement changé d'état : vérifiez le mode du connecteur.

### 4.11 `thotsecure audit verify` / `thotsecure audit tail`

```bash
thotsecure audit verify
```

```text
chaîne d'audit valide : 1284 enregistrements, genesis=sha256:genesis
```

```text
$ thotsecure audit verify                      # chaîne rompue
chaîne d'audit CORROMPUE à seq=812 (hash attendu sha256:4c1f…, calculé sha256:9ab0…)
$ echo $?
3
```

```bash
# Suivi en direct (Ctrl+C pour quitter)
thotsecure audit tail
```

```text
2026-02-14T10:00:02.331Z  api-key:ci     responder  action.approve  action a91b3c7e-…  pending_approval → approved
2026-02-14T10:00:03.104Z  api-key:ci     responder  action.execute  action a91b3c7e-…  approved → succeeded
2026-02-14T10:00:07.882Z  cli:local      admin      policy.reload   policies/           6 politiques
```

```powershell
# Vérification non bloquante avec rapport JSON
$verify = thotsecure audit verify --json | ConvertFrom-Json
if (-not $verify.valid) { Write-Error "audit rompu à seq=$($verify.broken_at)" }
```

!!! danger "Un code `3` n'est pas une erreur d'exécution : c'est un verdict"
    `3` signifie « la vérification est **négative** » : la chaîne de hachage ne se recalcule pas.
    Traitez-le comme un incident de sécurité (arrêt des écritures, isolement de la base, export
    `jsonl` conservé), pas comme un bug de script à contourner. Voir
    [`../operations/runbook.md`](operations/runbook.md).

### 4.12 `thotsecure report`

| Option | Rôle |
|---|---|
| `--format` | `md` \| `html` \| `json` \| `sarif` |
| `-o` | Fichier de sortie (sinon sortie standard) |

```bash
thotsecure report f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f --format md -o finding.md
thotsecure report f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f --format html -o finding.html
thotsecure report f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f --format json | jq '.risk_score'
thotsecure report f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f --format sarif -o thotsecure.sarif
```

```text
rapport écrit : finding.md (format=md, 3 812 octets, finding f1c2a4d6-…)
```

```powershell
thotsecure report f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f --format sarif -o .\thotsecure.sarif
Get-Item .\thotsecure.sarif | Select-Object Name, Length
```

!!! note "SARIF 2.1.0"
    Le format `sarif` produit du **SARIF 2.1.0**, directement exploitable par GitHub Code Scanning
    (contrat §4.8 et test `tests/test_reports.py`). Un rapport porte sur **un** finding identifié :
    pour un lot, itérez sur `thotsecure findings list --json`.

### 4.13 `thotsecure probe`

| Option | Rôle |
|---|---|
| `--tenant` | Tenant propriétaire de la cible |
| `--target` | URL/hôte **déclaré** dans `config/targets.yaml` |

```bash
thotsecure probe --tenant acme --target https://shop.acme.fr
```

```text
cible déclarée : https://shop.acme.fr (tenant=acme)
[ok]   TLS            certificat valide jusqu'au 2026-05-02 (72 j), chaîne complète
[ok]   en-têtes       HSTS présent, X-Content-Type-Options présent
[warn] en-têtes       Content-Security-Policy absente
[info] exposition     /server-status → 404 (attendu)
[info] dépendances    2 composants obsolètes détectés (voir findings AO-DEP-011)
findings créés : 1 (AO-TLS-014, low)
```

!!! danger "`probe` audite **votre** surface, jamais celle d'un tiers"
    `probe` n'existe que pour l'auto-évaluation : la cible doit être **possédée par le tenant** et
    **déclarée** dans `config/targets.yaml` (`THOT_TARGETS_FILE`), opt-in explicite (contrat §10).
    Une cible non déclarée est refusée. Thot Secure ne contient **aucune capacité offensive** : pas de
    scan agressif, pas de brute force, pas de hack-back, pas d'exploitation, pas de DoS, aucun test
    sur un tiers — même « juste pour vérifier ». En cas de doute sur le périmètre, arrêtez-vous et
    lisez [`../architecture/threat-model.md`](architecture/threat-model.md) et
    [`../governance.md`](governance.md).

### 4.14 `thotsecure demo`

Peuple un tenant de démonstration avec un jeu de données, des findings et des actions — utile pour
une démonstration locale ou une prise en main, **jamais** sur un tenant de production.

```bash
thotsecure demo --tenant demo
```

```text
tenant demo préparé : 1 200 événements, 9 findings, 3 actions (dry_run=true)
console : http://127.0.0.1:8080/   (clé : THOT_BOOTSTRAP_API_KEY)
```

```powershell
thotsecure demo --tenant demo
# Puis : ouvrir la console embarquée pour explorer les findings
Start-Process "http://127.0.0.1:8080/"
```

## 5. Codes de sortie

| Code | Signification | Usage dans un pipeline |
|---|---|---|
| `0` | Succès | Étape verte |
| `1` | Erreur (base, configuration, ressource inconnue, transition interdite) | Étape rouge ; journaliser la sortie |
| `2` | Erreur d'usage (option manquante, argument invalide, combinaison impossible) | Bug de script → corriger, ne pas réessayer |
| `3` | **Vérification négative** (ex. chaîne d'audit corrompue) | Étape rouge **bloquante** + alerte sécurité |

```bash
#!/usr/bin/env bash
# Distinguer un usage incorrect d'un vrai verdict négatif
set -uo pipefail

thotsecure audit verify --json
case $? in
  0) echo "audit intègre" ;;
  3) echo "ALERTE : chaîne d'audit corrompue" >&2; exit 3 ;;
  2) echo "usage invalide : corriger le script" >&2; exit 2 ;;
  *) echo "erreur d'exécution de la CLI" >&2; exit 1 ;;
esac
```

```powershell
# Même logique en PowerShell
thotsecure audit verify --json | Out-Null
switch ($LASTEXITCODE) {
    0 { Write-Output 'audit intègre' }
    3 { Write-Error 'ALERTE : chaîne d’audit corrompue'; exit 3 }
    2 { Write-Error 'usage invalide : corriger le script'; exit 2 }
    default { Write-Error 'erreur d’exécution de la CLI'; exit 1 }
}
```

!!! tip "`3` ne doit jamais être avalé par un `|| true`"
    Un pipeline qui masque le code `3` transforme un incident de sécurité en étape verte. Faites de
    `audit verify` une étape **bloquante explicite** (§7.1).

## 6. `--json` : automatiser proprement

`--json` est disponible sur **toutes** les commandes (contrat §8) : c'est la forme à privilégier
dès qu'une sortie est consommée par un programme, car la présentation humaine peut changer.

```bash
thotsecure findings list --tenant acme --json
```

```json
{
  "tenant_id": "acme",
  "items": [
    {
      "finding_id": "f1c2a4d6-1b2c-4d5e-8f90-0a1b2c3d4e5f",
      "rule_id": "AO-WEB-001",
      "severity": "high",
      "risk_score": 78.5,
      "status": "open",
      "title": "Tentative d'injection SQL depuis 203.0.113.9",
      "first_seen": "2026-02-14T10:00:00Z",
      "last_seen": "2026-02-14T10:04:12Z"
    }
  ]
}
```

Consommation sous bash :

```bash
# Les 5 findings les plus risqués, au format CSV
thotsecure findings list --tenant acme --json |
  jq -r '.items | sort_by(-.risk_score) | .[:5][] | [.finding_id, .rule_id, .severity, .risk_score] | @csv'

# Nombre de findings ouverts
thotsecure findings list --tenant acme --json | jq '.items | length'
```

Consommation sous PowerShell :

```powershell
# Les 5 findings les plus risqués, au format tableau
thotsecure findings list --tenant acme --json |
  ConvertFrom-Json |
  Select-Object -ExpandProperty items |
  Sort-Object risk_score -Descending |
  Select-Object -First 5 finding_id, rule_id, severity, risk_score |
  Format-Table -AutoSize
```

!!! note "`--json` masque-t-il quelque chose ?"
    Non : `--json` change la **présentation**, pas les droits ni le périmètre. Les secrets ne sont
    jamais inclus (une clé API créée s'affiche une seule fois, à la création, quel que soit le
    format de sortie).

## 7. Automatisation CI

!!! note "Exemples génériques"
    Les extraits ci-dessous montrent **comment** intégrer la CLI dans un pipeline ; l'orchestration
    CI de ce dépôt (workflows, runners, secrets) relève d'un autre lot de travail et n'est pas
    décrite ici.

### 7.1 Bloquer le pipeline si la chaîne d'audit est rompue

```bash
#!/usr/bin/env bash
# ci/thotsecure-gate.sh — bloque le pipeline tant que l'audit n'est pas intègre.
set -uo pipefail

thotsecure doctor --json > doctor.json || true   # informatif : ne bloque pas
thotsecure audit verify --json > audit-verify.json
status=$?

cat doctor.json
cat audit-verify.json

case "$status" in
  0) echo "audit intègre" ;;
  3) echo "::error::Chaîne d'audit rompue — intervention requise" >&2; exit 3 ;;
  *) echo "::error::thotsecure audit verify a échoué (code $status)" >&2; exit "$status" ;;
esac
```

```powershell
# ci/ThotSecureGate.ps1 — même garde-fou en PowerShell.
$ErrorActionPreference = 'Stop'

if (-not (Get-Command thotsecure -ErrorAction SilentlyContinue)) {
    Write-Error 'CLI thotsecure introuvable dans le PATH'
    exit 1
}

$doctor = thotsecure doctor --json          # informatif
$doctor

$raw    = thotsecure audit verify --json
$status = $LASTEXITCODE
$raw

switch ($status) {
    0 { Write-Output 'audit intègre' }
    3 {
        $verify = $raw | ConvertFrom-Json
        Write-Error "Chaîne d'audit rompue (broken_at=$($verify.broken_at))"
        exit 3
    }
    default {
        Write-Error "thotsecure audit verify a échoué (code $status)"
        exit $status
    }
}
```

### 7.2 Rapport SARIF et GitHub Code Scanning

```bash
# Sélectionner un finding puis produire un SARIF 2.1.0
FINDING_ID=$(thotsecure findings list --tenant acme --severity high --min-risk 70 --json |
             jq -r '.items[0].finding_id')

thotsecure report "$FINDING_ID" --format sarif -o thotsecure.sarif
```

```powershell
# Variante PowerShell
$findingId = (thotsecure findings list --tenant acme --severity high --min-risk 70 --json |
              ConvertFrom-Json).items[0].finding_id

thotsecure report $findingId --format sarif -o .\thotsecure.sarif
```

Étape de workflow correspondante (exemple générique) :

```yaml
- name: Rapport SARIF Thot Secure
  run: thotsecure report "$FINDING_ID" --format sarif -o thotsecure.sarif
  env:
    FINDING_ID: ${{ vars.AO_FINDING_ID }}
    AO_API_KEY: ${{ secrets.AO_API_KEY }}

- name: Publier dans GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: thotsecure.sarif
```

### 7.3 Valider règles et politiques avant merge

```yaml
- name: Valider les règles et politiques (pré-merge)
  run: |
    thotsecure rules validate --path rules
    thotsecure policies validate
```

```bash
# Équivalent local : exactement ce que la CI exécute
thotsecure rules validate --path rules && thotsecure policies validate
```

```powershell
# Équivalent local sous PowerShell
thotsecure rules validate --path rules
if ($LASTEXITCODE -ne 0) { throw 'règles invalides' }
thotsecure policies validate
if ($LASTEXITCODE -ne 0) { throw 'politiques invalides' }
```

## 8. Bonnes pratiques d'automatisation

!!! tip "Six réflexes qui évitent la plupart des incidents de script"
    1. **`--json` partout** dans un pipeline : la présentation humaine n'est pas un contrat.
    2. **`--tenant` explicite** toujours : un tenant par défaut implicite finit par écrire au mauvais
       endroit, et les événements sont immuables.
    3. **Aucune action réelle depuis un runner CI** sans approbation : gardez `THOT_DRY_RUN=true`,
       `THOT_AUTONOMY=supervised` et n'appelez `actions execute` qu'après un `actions approve`
       humain. Un runner compromis ne doit pas pouvoir modifier votre infrastructure.
    4. **`doctor` en première étape de diagnostic** avant toute escalade ; suite dans
       [`../operations/runbook.md`](operations/runbook.md).
    5. **Codes de sortie traités explicitement**, en particulier `3` (verdict négatif) qui doit
       bloquer le pipeline.
    6. **Secrets jamais en clair** : ni dans les scripts, ni dans les logs, ni dans les URL — voir
       [`api/usage.md`](api/usage.md) et [`../compliance/soc2-iso27001.md`](compliance/soc2-iso27001.md).

## 9. Correspondances CLI ↔ REST ↔ SDK

| Commande CLI | Route REST équivalente | Capacité | SDK |
|---|---|---|---|
| `ingest --tenant --file\|--stdin` | `POST /api/v1/events` | `write:events` | à confirmer (`src/thotsecure/sdk/`, `sdks/python/`) |
| `findings list --tenant` | `GET /api/v1/findings` | `read:findings` | à confirmer |
| `findings show <id>` | `GET /api/v1/findings/{id}` | `read:findings` | à confirmer |
| `actions list` | `GET /api/v1/actions` | `read:findings` | à confirmer |
| `actions plan --finding --playbook` | `POST /api/v1/actions/plan` | `execute:actions` | à confirmer |
| `actions approve <id>` | `POST /api/v1/actions/{id}/approve` | `approve:actions` | à confirmer |
| `actions execute <id>` | `POST /api/v1/actions/{id}/execute` | `execute:actions` | à confirmer |
| `actions rollback <id>` | `POST /api/v1/actions/{id}/rollback` | `execute:actions` | à confirmer |
| `audit verify` | `GET /api/v1/audit/verify` | `read:audit` | à confirmer |
| `audit tail` | `GET /api/v1/audit` (+ `WS /api/v1/ws/stream`) | `read:audit`, `read:events` | à confirmer |
| `report <id> --format sarif` | `GET /api/v1/findings/{id}/report?format=sarif` | `read:findings` | à confirmer |
| `rules list` | `GET /api/v1/rules` | `read:rules` | — |
| `rules validate` | `POST /api/v1/rules/validate` | `admin:rules` | — |
| `policies validate` | `GET /api/v1/policies` (contrôle local) | `read:policies` | — |
| `tenant create` / `tenant list` | `POST` / `GET /api/v1/tenants` | `admin:tenants` | — |
| `key create` / `key revoke` | `POST /api/v1/tenants/{id}/keys`, `DELETE /api/v1/keys/{key_id}` | `admin:keys` | — |
| `probe --tenant --target` | `POST /api/v1/collectors/{name}/run` | `execute:actions` | — |
| `serve` | — (démarre l'API elle-même) | — | — |
| `init-db`, `doctor`, `demo` | — (opérations locales, hors API) | — | — |

!!! note "Colonne SDK « à confirmer »"
    Le contrat (§2) indique que le client Python officiel vit dans `src/thotsecure/sdk/` et qu'un
    dépôt de SDK séparé existe (`sdks/{python,typescript,go}/`). Les **noms de méthodes** du SDK ne
    sont pas figés par le contrat : cette colonne est volontairement prudente. Pour un script,
    utilisez la CLI (locale, sans réseau) ou l'API REST — les deux sont contractuelles.

Voir aussi : [`../architecture/api-contract.md`](architecture/api-contract.md) (référence gelée),
[`api/usage.md`](api/usage.md) (mode d'emploi REST),
[`../quickstart.md`](quickstart.md) (premiers pas),
[`../faq.md`](faq.md), [`../glossary.md`](glossary.md),
[`../roadmap.md`](roadmap.md), [`../contributing.md`](contributing.md),
[`../support.md`](support.md).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
