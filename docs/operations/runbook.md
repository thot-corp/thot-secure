# Runbook d'incident

*Sept incidents, une même règle : d'abord couper l'automatisation, ensuite comprendre — jamais l'inverse.*

Ce runbook suppose une instance Thot Secure en production, une base SQLite locale (`THOT_DB_URL=sqlite:///./data/thotsecure.db` par défaut), et une astreinte qui a accès à la sauvegarde et à `THOT_SECRET_KEY`. Référence normative : [`../architecture/api-contract.md`](../architecture/api-contract.md) — §4.1 (sondes), §4.2 (tenants et clés), §4.6 (actions et erreurs `409`), §4.7 (audit), §6 (garde-fous), §8 (CLI et codes de sortie), §9 (variables d'environnement). L'exploitation courante (dimensionnement, sauvegarde, montée de version) est décrite dans [`deployment.md`](deployment.md) ; les manifestes exacts dans `deploy/README.md`.

Exemples d'appels — adaptez l'hôte et la clé :

```bash
export BASE_URL="http://127.0.0.1:8080"
export ADMIN_KEY="ao_…"   # rôle admin : requis pour tenants, clés, règles
```

```powershell
$env:BASE_URL = "http://127.0.0.1:8080"
$env:ADMIN_KEY = "ao_…"
```

!!! info "Conventions de ces exemples"
    `BASE_URL`, `ADMIN_KEY` et `INGEST_KEY` sont des **variables de coquille définies ici pour les exemples** — elles ne font pas partie des variables d'environnement du produit (`THOT_*`, §9). La référence des variables `THOT_*` est [`../configuration.md`](../configuration.md).

---

## 0. Premier réflexe : couper l'automatisation

!!! danger "Avant tout diagnostic : passer tous les tenants en `manual` et `dry_run=true`"
    Tant que l'automatisation tourne, chaque minute de diagnostic produit de nouveaux effets réels sur vos systèmes. **Coupez d'abord**, analysez ensuite. `dry_run=true` est un garde-fou global prioritaire sur toute politique (§6, garde-fou 4) ; `mode=manual` empêche toute exécution sans intervention humaine.

    **La voie fiable est un `PATCH` par tenant** (§4.2) : `PATCH /api/v1/tenants/{id}` avec `{"mode":"manual","dry_run":true}`, capacité `admin:tenants`.

### 0.1 Boucle PowerShell sur `thotsecure tenant list --json` (le plus rapide)

```powershell
$base = $env:BASE_URL
$headers = @{ "X-API-Key" = $env:ADMIN_KEY; "Content-Type" = "application/json" }

$thotsecureJson = thotsecure tenant list --json | ConvertFrom-Json
$tenants = if ($thotsecureJson.items) { $thotsecureJson.items } else { $thotsecureJson }

foreach ($t in $tenants) {
    $body = '{"mode":"manual","dry_run":true}'
    Invoke-RestMethod -Method Patch -Uri "$base/api/v1/tenants/$($t.tenant_id)" -Headers $headers -Body $body | Out-Null
    Write-Host " -> $($t.tenant_id) en mode=manual dry_run=true"
}
```

### 0.2 Boucle bash équivalente

```bash
thotsecure tenant list --json \
  | python -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(t['tenant_id'] for t in (d.get('items') or d)))" \
  | while read -r tenant; do
      curl -sS -X PATCH "$BASE_URL/api/v1/tenants/$tenant" \
        -H "X-API-Key: $ADMIN_KEY" \
        -H 'Content-Type: application/json' \
        -d '{"mode":"manual","dry_run":true}'
      echo " -> $tenant en mode=manual dry_run=true"
    done
```

!!! tip "Vérifier que la coupure est effective"
    ```bash
    curl -sS "$BASE_URL/version"                              # mode d'autonomie global
    curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/tenants"
    ```
    Chaque tenant doit afficher `"mode":"manual"` et `"dry_run":true`. Le format exact retourné par `thotsecure tenant list --json` peut varier selon l'enveloppe : **adaptez la boucle au format observé** plutôt que de la supposer.

### 0.3 Voie CLI et voie « variables d'environnement »

```bash
# CLI : énumérer, puis agir tenant par tenant
thotsecure tenant list
thotsecure tenant list --json
# (les commandes disponibles sont listées par `thotsecure --help` ; le contrat §8 documente
#  `tenant create` et `tenant list` — vérifiez l'existence d'une commande de modification)
```

```bash
# Défaut global : nécessite un REDÉMARRAGE du service
THOT_AUTONOMY=manual
THOT_DRY_RUN=true
```

```powershell
$env:THOT_AUTONOMY = "manual"
$env:THOT_DRY_RUN   = "true"
Restart-Service thotsecure
Get-Service thotsecure
```

!!! warning "Les variables d'environnement ne remplacent pas le `PATCH`"
    `THOT_AUTONOMY` est décrit comme un **défaut global**, surchargeable par tenant (§9) : un tenant dont le `mode` a été fixé explicitement peut donc conserver le sien. De plus, un changement de variable exige un **redémarrage** — donc une interruption — et s'applique à *tous* les tenants à la fois. **Le `PATCH` par tenant reste la voie fiable** ; le comportement exact de la surcharge par tenant est à confirmer dans le code.

### 0.4 Critères de déclenchement

* pic d'actions automatiques, ou doute sur un faux positif massif (incident 2) ;
* `audit verify` en échec (incident 3) ;
* suspicion de compromission de clé API (incident 7) ;
* base corrompue ou `/readyz` bloqué à `503` (incidents 4 et 5) ;
* toute situation où vous ne savez pas encore *ce que le système est en train de faire*.

### 0.5 Ce que cela ne coupe pas

| Composant | Continue de tourner ? |
|---|---|
| **Détection** (règles → findings, scoring de risque) | **oui** — c'est voulu : vous ne perdez pas la visibilité |
| **Collecte** (collecteurs, ingestion `POST /api/v1/events`) | **oui** |
| **Audit** (journal append-only chaîné) | **oui** — rien n'est effacé |
| Exécution d'actions sur les systèmes | **non** — c'est l'objet de la coupure |
| Planification d'actions (`POST /api/v1/actions/plan`, statut `planned`) | possible, mais sans effet réel |

---

## 1. Aucune détection ne remonte

### Symptômes

* Thot Secure répond, mais aucun nouveau finding n'apparaît ;
* le flux live (`WS /api/v1/ws/stream`) ne montre que des `heartbeat` ;
* l'ingestion renvoie `202` mais `findings: []` ;
* `thotsecure rules list` est vide ou anormalement court.

### Diagnostic

```bash
# 1) le service est-il prêt ? (vérifie DB + bus + règles)
curl -sS -i "$BASE_URL/readyz"

# 2) les règles sont-elles chargées et valides ?
thotsecure rules list
thotsecure rules validate --path rules

# 3) recharger les règles et lire les erreurs
curl -sS -X POST "$BASE_URL/api/v1/rules/reload" \
  -H "X-API-Key: $ADMIN_KEY"
# réponse attendue : {"loaded":n,"errors":[…]}

# 4) les collecteurs tournent-ils ? (dernier run, items, erreurs)
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/collectors"

# 5) déclencher un run manuel sur les cibles déclarées du tenant
curl -sS -X POST "$BASE_URL/api/v1/collectors/<nom>/run" \
  -H "X-API-Key: $ADMIN_KEY"

# 6) tester la chaîne d'ingestion de bout en bout
curl -sS -X POST "$BASE_URL/api/v1/events" \
  -H "X-API-Key: $INGEST_KEY" -H 'Content-Type: application/json' \
  -d '{"tenant_id":"acme","kind":"generic","source":{"type":"web_probe","name":"test"},"labels":{"src_ip":"203.0.113.9"}}'
# réponse 202 : {"accepted":n,"rejected":n,"event_ids":[…],"findings":[…]}
```

```powershell
# logs détaillés
Get-Content .\logs\thotsecure.log -Tail 200 -Wait
$env:THOT_LOG_LEVEL = "DEBUG"
Restart-Service thotsecure
```

Vérifier aussi `THOT_RULES_DIR` (défaut `./rules`, §9) : un répertoire mal monté dans le conteneur est la cause la plus banale.

### Remédiation

Corriger la cause, puis vérifier les pièges classiques :

| Piège | Comment le repérer | Correction |
|---|---|---|
| Règle `enabled: false` | `thotsecure rules list` → colonne `enabled` | réactiver dans le YAML, puis `rules reload` |
| `source_types` / `kinds` non correspondants | la règle ne matche jamais le `kind` réel de l'événement (§3.1) | aligner `source_types`/`kinds` sur les événements observés (`GET /api/v1/events`) |
| `tenant_id` de la clé ≠ tenant attendu | les événements sont créés sous un autre tenant (`tenant_id` **forcé depuis la clé**, §4.3) | utiliser la clé du bon tenant ; vérifier `GET /api/v1/auth/whoami` |
| Seuil jamais atteint | `threshold.count` / `window_seconds` trop stricts, ou `group_by` trop fin (§5) | assouplir le seuil ou élargir la fenêtre |
| `dedup.ttl_seconds` trop long | un finding existe déjà et absorbe les nouveaux événements | ajuster le `dedup` |
| Règle rejetée silencieusement | `errors` non vide dans la réponse de `rules reload` | corriger le YAML : `rules validate` avant `reload` |
| Files d'attente d'ingestion | `rejected` élevé dans la réponse `202` | vérifier les tailles (`payload` ≤ 32 Kio, §3.1) et `THOT_RATE_LIMIT_PER_MIN` (défaut 600) |

### Escalade

Si les règles sont chargées, les collecteurs tournent et l'ingestion est acceptée sans qu'aucun finding ne sorte : escalader à l'équipe détection (anomalie du moteur) et ouvrir un ticket de bug avec les sorties de `rules list`, `rules reload` et le test d'ingestion.

### Retour d'expérience (post-mortem)

Établir : quand la détection s'est-elle arrêtée ? Quelle est la fenêtre d'aveuglement (aucun finding pendant N heures) ? Faut-il une alerte sur « absence de finding » (voir [`deployment.md`](deployment.md) §8.3) ? La règle ou le collecteur fautif doit être couvert par un test (§11 : `tests/test_rules_engine.py`, `tests/test_collectors.py`).

---

## 2. Pic d'actions automatiques (faux positif massif)

### Symptômes

* hausse brutale des actions en `succeeded` ;
* `max_actions_per_hour` atteint (défaut **20** par tenant, §6 garde-fou 1) : les actions suivantes sont bloquées, mais les premières sont déjà passées ;
* alertes de tickets/webhooks (`playbook: open-ticket`, `notify` — §7) ;
* plaintes d'utilisateurs ou d'un partenaire bloqué.

### Diagnostic

!!! danger "Avant toute analyse : appliquer la §0 (couper l'automatisation)"
    Puis seulement, mesurer l'ampleur.

```bash
# 1) quelles actions sont passées
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/actions?status=succeeded&limit=500"

# 2) vue d'ensemble (24 h / 7 j), dont le mode d'autonomie
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/stats/overview"

# 3) quels findings ont déclenché (les plus risqués d'abord)
curl -sS -H "X-API-Key: $ADMIN_KEY" \
  "$BASE_URL/api/v1/findings?sort=risk_score&min_risk=70&limit=500"

# 4) la trace d'audit des exécutions
curl -sS -H "X-API-Key: $ADMIN_KEY" \
  "$BASE_URL/api/v1/audit?action=action.execute&limit=500"
```

Identifier la **`rule_id` et la `policy_id` communes** : c'est presque toujours une seule règle trop large associée à une politique `then.decision: auto` trop permissive (§6). Le champ `reason` de la `Decision` (§3.3) indique la politique appliquée.

### Remédiation

1. **Couper l'automatisation** (§0).
2. **Rollback massif** des actions indésirables : `POST /api/v1/actions/{id}/rollback`.
   ```bash
   thotsecure actions rollback <action_id>
   ```
   !!! warning "Tolérer le `409` : le rollback est idempotent par nature, pas par réponse"
       `POST /api/v1/actions/{id}/rollback` **refuse avec `409`** si l'action est déjà `rolled_back` (§4.6). Une boucle de rollback doit donc traiter `409` comme un **succès** (l'état visé est atteint), sinon elle s'arrêtera au premier doublon. Vérifiez aussi `rollback.available` (§3.4) avant d'appeler.
   ```bash
   for id in $(cat actions-a-annuler.txt); do
     code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/v1/actions/$id/rollback" \
              -H "X-API-Key: $ADMIN_KEY")
     echo "$id -> $code"   # 200/204 attendu ; 409 = deja rolled_back, considerer comme OK
   done
   ```
   ```powershell
   $headers = @{ "X-API-Key" = $env:ADMIN_KEY }
   foreach ($id in Get-Content .\actions-a-annuler.txt) {
       try {
           $r = Invoke-WebRequest -Method Post -Uri "$env:BASE_URL/api/v1/actions/$id/rollback" -Headers $headers
           Write-Host "$id -> $($r.StatusCode)"
       } catch {
           if ($_.Exception.Response.StatusCode.value__ -eq 409) { Write-Host "$id -> 409 (deja rolled_back, OK)" }
           else { Write-Host "$id -> ERREUR $($_.Exception.Message)" }
       }
   }
   ```
3. **Corriger la règle** : durcir les conditions, compléter `false_positives`, relever le `threshold`, ajuster le `dedup` (§5).
4. **Durcir la politique** : passer temporairement à `then.decision: notify_only`, remonter le `when.finding.risk_score`, abaisser `max_actions_per_hour`, ou restreindre `params`.
   !!! note "Silence total = `ignore` explicite"
       Si **aucune** politique ne matche, la décision par défaut est `notify_only` (§6). Pour un silence total, une politique `decision: ignore` **explicite** est requise — il ne suffit pas de supprimer la politique `auto`.
5. Rejouer en `dry_run=true` jusqu'à obtenir un volume attendu, puis réactiver progressivement.

!!! warning "Risque de déni de service interne"
    Bloquer des IP légitimes est un **DoS infligé à votre propre organisation** : IP sortante de votre siège ou de votre VPN, sonde de supervision interne, CDN ou répartiteur légitime, partenaire, robots d'indexation. Les cibles de l'`autonomy_allowlist` et les cibles protégées ne sont **jamais** touchées (§6, garde-fou 3) — mais une IP légitime **non listée** le sera. Avant tout rollback massif, vérifiez l'impact métier réel : un rollback tardif vaut mieux qu'un blocage prolongé d'un partenaire.

### Escalade

Prévenir le responsable métier du ou des tenants concernés (l'action a peut-être touché la production), et l'équipe détection pour la correction de règle. Si des systèmes tiers ont été impactés, informer le point de contact partenaire.

### Retour d'expérience (post-mortem)

**Obligatoire** pour tout faux positif massif. À documenter : nombre d'actions exécutées, nombre réellement annulées, durée d'exposition, cause racine (règle ou politique), garde-fou qui aurait dû l'arrêter, et l'ajout d'un test de non-régression sur la règle.

---

## 3. `audit verify` échoue

### Symptômes

* `thotsecure audit verify` retourne le **code de sortie `3`** (« vérification négative », §8) ;
* `GET /api/v1/audit/verify` renvoie `{"valid":false,"records":n,"broken_at":…}` ;
* l'export SIEM montre des `seq` manquants ou un `prev_hash` incohérent.

### Diagnostic

```bash
# 1) vérification locale (code 0 = OK, 3 = rupture)
thotsecure audit verify; echo "exit=$?"

# 2) vérification par l'API : où la chaîne casse-t-elle ?
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/audit/verify"

# 3) inspecter les enregistrements autour du point de rupture
curl -sS -H "X-API-Key: $ADMIN_KEY" \
  "$BASE_URL/api/v1/audit?since=2026-09-13T00:00:00Z&limit=500"

# 4) suivre la chaîne en continu
thotsecure audit tail
```

Points à contrôler, dans cet ordre :

1. **`seq` consécutifs** : une rupture de séquence est le signe le plus simple (enregistrement supprimé) ;
2. **recalcul de la chaîne** : pour chaque enregistrement, vérifier
   `hash = sha256(f"{seq}|{ts}|{tenant_id}|{actor}|{actor_role}|{action}|{canonical(target)}|{canonical(before)}|{canonical(after)}|{prev_hash}")`
   avec `canonical()` = JSON trié, séparateurs compacts, UTF-8 (§3.5). Le genesis a `prev_hash = "sha256:genesis"` ;
3. **écritures concurrentes** : deux instances Thot Secure (ou deux processus) écrivant dans la même base — voir l'avertissement « un seul écrivain » dans [`deployment.md`](deployment.md) §1.1 ;
4. **restauration de sauvegarde** récente : une base restaurée *plus ancienne* que la chaîne attendue peut sembler incohérente ;
5. **modification manuelle** : requête `UPDATE`/`DELETE` directe dans `data/thotsecure.db`, import d'un dump partiel, ou script tiers sur le fichier.

```bash
# reperer les trous de sequence sans supposer le nom des tables :
# le schema physique est decrit dans ../architecture/data-model.md
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/audit?limit=500" \
  | python -c "import json,sys; d=json.load(sys.stdin); s=sorted(r['seq'] for r in d.get('items', d if isinstance(d,list) else [])); print('trous:', [(a,b) for a,b in zip(s,s[1:]) if b-a!=1])"
```

!!! note "Schéma physique"
    Les noms exacts des tables et colonnes de persistance ne sont pas figés par ce runbook : ils relèvent de [`../architecture/data-model.md`](../architecture/data-model.md) et de `src/thotsecure/storage/`. Préférez toujours l'API ou la CLI pour inspecter l'audit plutôt qu'une requête SQL écrite de mémoire.

### Remédiation

1. **Isoler la base** : arrêter le service, retirer l'accès partagé. Ne laissez personne d'autre écrire.
2. **Préserver les preuves** : copie bit-à-bit du fichier (et du `-wal`/`-shm`) + empreinte SHA-256, horodatée.
   ```bash
   cp data/thotsecure.db "forensic/thotsecure.db.$(date -u +%Y%m%dT%H%M%SZ)"
   sha256sum forensic/thotsecure.db.* | tee forensic/empreintes.txt
   ```
   ```powershell
   Copy-Item data\thotsecure.db "forensic\thotsecure.db.$(Get-Date -Format yyyyMMddTHHmmss)"
   Get-ChildItem forensic\thotsecure.db.* | Get-FileHash -Algorithm SHA256
   ```
3. **Ne jamais « réparer » la chaîne** en recalculant les hash : le journal est **append-only** (§3.5) ; réécrire une entrée, c'est falsifier la preuve et transformer un incident technique en incident de sécurité.
4. **Restaurer** depuis une sauvegarde vérifiée (procédure : [`deployment.md`](deployment.md) §4.4), puis relancer `thotsecure audit verify`.
5. **Qualifier l'événement comme incident de sécurité** et consigner : c'est l'objet même du contrôle d'intégrité.
6. **Notifier** selon votre cadre de conformité : voir [`../compliance/soc2-iso27001.md`](../compliance/soc2-iso27001.md) (journalisation, intégrité, gestion des incidents).

### Escalade

**RSSI** systématiquement, dès la confirmation d'une rupture. **DPO** si les données concernées comportent des données personnelles (adresses IP, identifiants, journaux d'accès) : voir [`../compliance/rgpd.md`](../compliance/rgpd.md). En cas de suspicion d'origine malveillante (accès non autorisé à l'hôte), traiter comme une compromission : préserver, ne pas nettoyer.

### Retour d'expérience (post-mortem)

Documenter : `broken_at` exact, cause racine (bug, manipulation, compromission), existence d'un accès direct à la base hors Thot Secure, et les mesures de durcissement (permissions du fichier, retrait des outils SQLite sur l'hôte de production, alerting sur `valid:false`).

---

## 4. Bus NATS indisponible

### Symptômes

* `GET /readyz` → **`503`** (le bus fait partie des trois piliers vérifiés, §4.1) ;
* retards de traitement : les événements arrivent mais les findings tardent ;
* perte du flux temps réel (`WS /api/v1/ws/stream` sans frames `event`/`finding`) ;
* logs en erreur de connexion au bus.

### Diagnostic

```bash
echo "THOT_BUS=$THOT_BUS"          # memory | sqlite | nats
echo "THOT_NATS_URL=$THOT_NATS_URL" # defaut : nats://127.0.0.1:4222

curl -sS -i "$BASE_URL/readyz"

# connectivite reseau vers le bus
nc -vz 127.0.0.1 4222
```

```powershell
Write-Host "THOT_BUS=$env:THOT_BUS"
Write-Host "THOT_NATS_URL=$env:THOT_NATS_URL"
Test-NetConnection -ComputerName 127.0.0.1 -Port 4222
Get-Content .\logs\thotsecure.log -Tail 100 |
    Where-Object { $_ -match 'bus|nats|connection' }
```

Le contrat décrit **trois** bus (§2, §9) : `memory`, `sqlite`, `nats`. Confirmer lequel est réellement configuré avant de conclure.

### Remédiation

1. **Bascule temporaire du bus** — en **assumant explicitement la perte de distribution** :
   ```bash
   # durable localement (recommande) : les messages survivent au redemarrage
   THOT_BUS=sqlite
   # ou, non durable : perte des messages en vol au redemarrage
   THOT_BUS=memory
   ```
   ```powershell
   $env:THOT_BUS = "sqlite"
   Restart-Service thotsecure
   ```
   !!! warning "Ce que vous perdez en basculant"
       * `memory` : les messages en vol sont **perdus au redémarrage**, et la distribution entre processus disparaît ;
       * `sqlite` : durable localement, mais la file vit sur le **même disque** que la base — surveillez l'espace et le WAL ;
       * dans les deux cas, un `nats` distant n'est plus alimenté : les consommateurs externes branchés sur NATS **ne reçoivent plus rien** tant que vous n'êtes pas revenu à `nats`.

2. **Relancer NATS** :
   ```bash
   systemctl status nats-server
   systemctl restart nats-server
   ```
   ```powershell
   Get-Service nats
   Restart-Service nats
   Get-Service nats
   ```
3. **Revenir au bus distribué** : reposer `THOT_BUS=nats` (avec le bon `THOT_NATS_URL`), redémarrer, puis vérifier `GET /readyz` → **`200`** avant de considérer l'incident clos.
4. Traiter les messages accumulés pendant l'indisponibilité (rejeu depuis le bus d'origine, ou ré-ingestion) — décision à consigner.

Pour la question « que se passe-t-il si le bus tombe ? », voir [`../faq.md`](../faq.md).

### Escalade

Équipe infrastructure si NATS est tombé pour une cause d'infrastructure (mémoire, certificats, réseau). Escalade au responsable de plateforme si la bascule temporaire doit durer : la perte de distribution est un état dégradé, pas une cible.

### Retour d'expérience (post-mortem)

Relever la durée d'indisponibilité, le volume de messages perdus ou rejoués, et vérifier que `/readyz` a bien fait son travail (retrait du trafic). Si la bascule `sqlite` a été nécessaire, évaluer la mise en place d'un second nœud NATS — hors périmètre MVP (voir [`../roadmap.md`](../roadmap.md)).

---

## 5. Base corrompue

### Symptômes

* `database disk image is malformed` (ou `SQLITE_CORRUPT`) dans les logs ;
* `GET /readyz` → `503` ; `GET /healthz` toujours `ok` ;
* erreurs `500 internal_error` sur les routes qui lisent la base ;
* croissance anormale du fichier `-wal`.

### Diagnostic

```bash
# 1) integrite (lecture seule, peut etre long sur une grosse base)
sqlite3 data/thotsecure.db "PRAGMA integrity_check;"
sqlite3 data/thotsecure.db "PRAGMA quick_check;"

# 2) taille du fichier, du WAL et espace disque
ls -lh data/thotsecure.db*
df -h .
```

```powershell
sqlite3 data\thotsecure.db "PRAGMA integrity_check;"
Get-ChildItem data\thotsecure.db* | Select-Object Name,Length,LastWriteTime
Get-PSDrive -Name D | Select-Object Used,Free
```

`integrity_check` retourne `ok` ou une liste d'anomalies : **notez-les**, elles orientent la récupération. Vérifiez d'abord l'espace disque — une base « corrompue » est souvent une base tronquée par un disque plein (§8.3 de [`deployment.md`](deployment.md)).

### Remédiation

1. **Arrêter le service** (une écriture pendant la réparation aggrave les dégâts) :
   ```bash
   systemctl stop thotsecure
   ```
   ```powershell
   Stop-Service thotsecure
   ```
2. **Copier le fichier corrompu pour analyse** — jamais travailler sur l'original :
   ```bash
   cp data/thotsecure.db "forensic/thotsecure-corrompu-$(date -u +%Y%m%dT%H%M%SZ).db"
   ```
3. **Restauration chiffrée** : déchiffrer la dernière sauvegarde vérifiée, contrôler l'empreinte, la poser à la place de la base (procédure complète : [`deployment.md`](deployment.md) §4.4).
4. **Récupération partielle** si la sauvegarde est trop ancienne et que les données récentes comptent :
   ```bash
   # VACUUM INTO sur la copie : tente de produire une base saine
   sqlite3 forensic/thotsecure-corrompu.db "VACUUM INTO 'data/thotsecure-recup.db';"

   # .recover, si disponible dans votre version de sqlite3
   sqlite3 forensic/thotsecure-corrompu.db ".recover" > dump.sql
   ```
   !!! warning "La récupération partielle peut casser la chaîne d'audit"
       Une récupération partielle perd des enregistrements : elle **produit une rupture de chaîne**. C'est acceptable en dernier recours, mais vous devez alors **exécuter `thotsecure audit verify` et documenter explicitement la rupture** (`broken_at`, plage de `seq` manquante, cause) — sinon vous découvrirez l'incohérence au pire moment.
5. **Vérifier** après restauration :
   ```bash
   thotsecure doctor
   thotsecure audit verify          # code 0 attendu, ou 3 avec rupture documentee
   ```
   Puis redémarrer et contrôler `GET /readyz` → `200`.

### Prévention

* **rétention** cohérente (`THOT_RETENTION_DAYS`) et purge surveillée ;
* **disque surveillé** (base **et** WAL) avec alerte avant saturation ;
* **sauvegardes testées** régulièrement — « une sauvegarde non testée n'est pas une sauvegarde » ;
* **arrêt propre** du service avant toute copie ou mise à jour ;
* **aucun partage réseau/NFS** du fichier de base : SQLite et les systèmes de fichiers réseau ne font pas bon ménage ;
* **un seul écrivain** ([`deployment.md`](deployment.md) §1.1).

### Escalade

Équipe infrastructure si la cause est matérielle (disque, RAID, hyperviseur) ; éditeur/mainteneurs si `PRAGMA integrity_check` échoue sur une base dont la chaîne d'audit était valide la veille. Voir [`../support.md`](../support.md).

### Retour d'expérience (post-mortem)

Quantifier la perte : RPO réellement atteint, fenêtre de données absente, impact sur la chaîne d'audit et sur les obligations de conservation. Si la cause est un disque plein non alerté, corriger l'alerte avant de clore l'incident.

---

## 6. Action bloquée en `executing`

### Symptômes

* une action reste indéfiniment en statut `executing` (§3.4) au lieu de passer à `succeeded` ou `failed` ;
* un connecteur (WAF, pare-feu) est lent ou ne répond plus ;
* le service a été redémarré ou la tâche tuée pendant l'exécution ;
* `/readyz` peut rester `200` : le blocage d'une action n'est pas un problème de préparation.

### Diagnostic

```bash
# 1) quelles actions sont bloquees
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/actions?status=executing"

# 2) detail d'une action : resultat, rollback, idempotence
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/actions/<action_id>"

# 3) etat des collecteurs/connecteurs
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/collectors"

# 4) trace d'audit de l'execution
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/audit?action=action.execute"
```

Vérifiez sur l'action : `executed_at`, `result`, `target` (`type`/`value`), `idempotency_key`, `rollback.available` (§3.4). Puis **allez voir l'état réel du connecteur** : l'IP est-elle bloquée, oui ou non ?

### Remédiation

!!! danger "Ne supprimez pas l'enregistrement de l'action"
    Supprimer la ligne « pour débloquer l'interface » détruit la traçabilité d'une contre-mesure réelle et crée une rupture dans le raisonnement d'audit. **La traçabilité prime** : on réconcilie, on documente, on clôt — on n'efface pas.

1. **Si `rollback.available` est vrai** : exécuter le rollback et vérifier côté connecteur.
   ```bash
   curl -sS -X POST "$BASE_URL/api/v1/actions/<action_id>/rollback" -H "X-API-Key: $ADMIN_KEY"
   thotsecure actions rollback <action_id>
   ```
2. **Sinon, réconcilier avec l'état réel** : si le connecteur a bien appliqué le blocage, l'action est en pratique un succès ; si non, elle est un échec. Notez la conclusion.
3. **Clore l'enregistrement** selon le comportement réel du code (transition vers `succeeded`/`failed` depuis `executing`) : **ce chemin exact est à confirmer** dans `src/thotsecure/actions/` — le contrat décrit les statuts et les transitions nominales (§3.4) mais pas la reprise après incident.
4. **Rejouer sans double effet** grâce à `idempotency_key` (§3.4) : l'exécution est idempotente via cette clé (§4.6), donc un rejeu sur la même clé ne doit pas produire un second blocage.
5. Si l'action est restée `executing` à cause d'un connecteur en panne, traiter la panne du connecteur comme l'incident principal.

!!! warning "L'écart entre Thot Secure et le connecteur est le vrai danger"
    Le scénario dangereux n'est pas l'action bloquée : c'est **« le WAF bloque, mais Thot Secure croit l'action en cours »** — ou l'inverse, « Thot Secure croit avoir bloqué, le WAF n'a rien fait ». Dans le premier cas, un rollback déclenché plus tard peut échouer (le token de rollback a expiré) alors que le blocage est toujours actif côté connecteur : le déblocage doit alors être fait **manuellement** dans le connecteur, et consigné. Ne clôturez jamais sur la seule foi de l'affichage d'Thot Secure.

### Escalade

Équipe réseau/sécurité pour l'état du connecteur, mainteneurs si le blocage se reproduit systématiquement (fuite de tâche, absence de timeout d'exécution). Rappel : l'`expires_at` de l'action et `rollback.auto_after_seconds` des politiques (§6) bornent l'effet — vérifier qu'ils n'ont pas déjà purgé votre fenêtre d'annulation.

### Retour d'expérience (post-mortem)

Documenter : durée de blocage, méthode de réconciliation retenue, état final réel côté connecteur, et l'écart entre les deux systèmes. Vérifier qu'un test couvre l'idempotence et l'expiration (§11 : `tests/test_actions_rollback.py`).

---

## 7. Fuite suspectée de clé API

### Symptômes

* usage anormal d'une clé : pic d'appels, actions non demandées ;
* `last_used_at` inattendu (nuit, week-end, hors fenêtre de la CI) ;
* appel depuis une **IP inconnue** (à corréler dans le journal d'audit) ;
* rafale de `401 unauthenticated` / `403 forbidden` (tentatives avec une clé révoquée ou un rôle insuffisant) ;
* clé trouvée en clair : variables de CI, fichier `.env`, image de conteneur, journal de build, dépôt Git.

### Diagnostic

```bash
# 1) inventaire des cles du tenant : label, role, created_at, last_used_at, revoked_at
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/tenants/acme/keys"

# 2) ce que la cle suspecte a fait
curl -sS -H "X-API-Key: $ADMIN_KEY" \
  "$BASE_URL/api/v1/audit?actor=api-key:ci&limit=500"

# 3) ce que son role permettait
curl -sS -H "X-API-Key: $ADMIN_KEY" "$BASE_URL/api/v1/auth/whoami"
```

Corréler `actor` et `actor_role` ; l'`actor` d'un appel par clé API a la forme `api-key:<label>` (§3.5). Rappel des capacités par rôle (§4) : `viewer` (lecture), `analyst` (+ écriture événements/findings), `responder` (+ exécution et approbation d'actions), `admin` (+ tenants, règles, clés, politiques). Une clé `admin` fuitée peut créer ou révoquer des clés : considérez alors **tout** l'ensemble des clés comme suspect.

### Remédiation (immédiate)

1. **Révoquer** la clé compromise :
   ```bash
   curl -sS -i -X DELETE "$BASE_URL/api/v1/keys/<key_id>" -H "X-API-Key: $ADMIN_KEY"
   # 204 attendu : revocation immediate
   thotsecure key revoke --key-id <key_id>
   ```
2. **Créer une nouvelle clé** de moindre privilège :
   ```bash
   curl -sS -X POST "$BASE_URL/api/v1/tenants/acme/keys" \
     -H "X-API-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
     -d '{"role":"responder","label":"ci-2026-09"}'
   # -> {"key_id","api_key":"ao_…"} : affichee UNE SEULE FOIS
   thotsecure key create --tenant acme --role responder --label ci-2026-09
   ```
   Redéployer immédiatement le consommateur légitime avec la nouvelle clé.
3. **Revoir les actions prises avec la clé compromise** et **annuler** celles qui n'étaient pas désirées (`POST /api/v1/actions/{id}/rollback`, en tolérant le `409`).
4. **Chercher d'autres clés exposées** : variables de CI (y compris historiques de build), fichiers `.env` et scripts d'exploitation, images et couches de conteneur, dépôt Git (l'ajout au `.gitignore` ne retire pas un secret déjà committé), tickets, captures d'écran, wiki interne.
5. **Rotation de `THOT_SECRET_KEY`** si le pepper lui-même est suspecté compromis — procédure prudente en fenêtre de maintenance : [`deployment.md`](deployment.md) §5.3.
   !!! warning "Une rotation de pepper peut invalider toutes les clés"
       Le contrat **ne décrit pas de rotation à chaud** de `THOT_SECRET_KEY` : vérifiez le comportement exact dans le code avant de la régénérer en production. Des clés API hachées avec l'ancien pepper peuvent devenir invalides d'un coup — prévoyez la recréation de toutes les clés.
6. **Notifier** : responsable sécurité, et DPO si les données accédées comportent des données personnelles ([`../compliance/rgpd.md`](../compliance/rgpd.md)) ; consigner dans le registre d'incidents ([`../compliance/soc2-iso27001.md`](../compliance/soc2-iso27001.md)).

!!! note "Une clé n'est jamais « récupérée »"
    Les clés API sont stockées **hachées (`scrypt`)** et affichées **une seule fois** à la création (§4.2, §10) : elles ne sont pas réaffichables, même par un administrateur. En cas de fuite, la seule issue est **révoquer puis recréer**. Voir [`../glossary.md`](../glossary.md) et [`../configuration.md`](../configuration.md).

### Escalade

RSSI immédiatement. DPO si données personnelles concernées. Équipe plateforme/CI si la fuite provient d'un pipeline. Si la clé compromise était `admin`, considérer l'instance comme potentiellement compromise (règles et politiques modifiables) et auditer `POST /api/v1/rules/reload` / `POST /api/v1/policies/reload` dans le journal.

### Retour d'expérience (post-mortem)

Documenter le vecteur de fuite, la fenêtre d'exposition, les actions prises par l'attaquant, et les mesures : rotation systématique des clés CI, passage des secrets au coffre, une clé par usage et par rôle, alerting sur `last_used_at` anormal.

---

## Récapitulatif

| Incident | Premier geste | Commande clé | Section |
|---|---|---|---|
| Aucune détection ne remonte | vérifier `/readyz` et recharger les règles | `thotsecure rules validate --path rules` puis `POST /api/v1/rules/reload` | §1 |
| Pic d'actions automatiques | **couper l'automatisation** (§0) | `GET /api/v1/actions?status=succeeded` puis rollbacks | §2 |
| `audit verify` échoue | isoler la base, préserver les preuves | `thotsecure audit verify` (code `3`) | §3 |
| Bus NATS indisponible | bascule temporaire assumée | `THOT_BUS=sqlite` puis redémarrage | §4 |
| Base corrompue | arrêter le service, copier l'original | `PRAGMA integrity_check` | §5 |
| Action bloquée en `executing` | réconcilier avec le connecteur | `GET /api/v1/actions?status=executing` | §6 |
| Fuite suspectée de clé API | **révoquer immédiatement** | `DELETE /api/v1/keys/{key_id}` → `204` | §7 |

---

## Préparation

Un runbook ne vaut que si l'astreinte peut l'exécuter **sans chercher un accès**.

* [ ] **Astreinte identifiée** : qui est de garde, comment le joindre, qui décide de couper l'automatisation.
* [ ] **Accès à la sauvegarde** testé par la personne d'astreinte (pas seulement par l'équipe plateforme).
* [ ] **Accès à `THOT_SECRET_KEY`** : coffre accessible 24/7, procédure d'accès d'urgence connue, **séparé de la sauvegarde** de la base.
* [ ] **Accès au coffre** et aux identifiants des connecteurs (WAF, pare-feu) pour la réconciliation manuelle.
* [ ] **Accès en lecture à `deploy/README.md`** : c'est lui qui porte les manifestes et les seuils d'alerte.
* [ ] **Clé `admin` d'astreinte** disponible (hors CI), et une clé par usage par ailleurs.
* [ ] **Test de restauration trimestriel** : restauration réelle + `thotsecure doctor` + `thotsecure audit verify`, avec relevé du RTO réellement obtenu ([`deployment.md`](deployment.md) §4.4).
* [ ] **Alertes actives** et dirigées vers l'astreinte ([`deployment.md`](deployment.md) §9).
* [ ] **Procédure §0 répétée au moins une fois** à blanc, chronomètre en main.

---

## Ce que ce runbook ne couvre pas

* **Les incidents purement infrastructure ou cloud** : réseau, DNS, hyperviseur, stockage, panne d'un fournisseur. Ils relèvent de l'équipe infrastructure ; ce runbook ne traite que ce qu'Thot Secure voit et subit.
* **La compromission du SI lui-même** : poste de travail, annuaire, chaîne CI, hôte de production compromis. Cela relève d'une cellule de réponse à incident et d'investigation forensic — Thot Secure est un outil **strictement défensif** (pas de scan agressif, pas de hack-back, aucune capacité offensive) et n'est pas un outil de réponse à compromission.
* **La décision juridique** : qualification réglementaire, notification à une autorité de contrôle, information des personnes concernées, dépôt de plainte. Le runbook fournit les **faits** (fenêtre, données touchées, `broken_at`, clés révoquées) ; la décision appartient au DPO et au service juridique ([`../compliance/rgpd.md`](../compliance/rgpd.md)).
* **La modification des manifestes et des seuils d'alerte** : c'est le **lot déploiement** (`deploy/README.md`).
* **Le dimensionnement et la montée de version** : voir [`deployment.md`](deployment.md).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
