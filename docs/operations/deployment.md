# Déploiement et exploitation

*Déployer Thot Secure, c'est d'abord décider où vit l'état local — dimensionnement, sauvegarde, montée de version et observabilité en découlent.*

!!! note "Cette page complète `deploy/README.md`"
    Les manifestes exacts (`Dockerfile`, `compose.yaml`, Kubernetes, Helm, Terraform, Ansible) et les **seuils d'alerte définitifs** appartiennent au **lot déploiement** : leur référence est `deploy/README.md`. Cette page décrit la *démarche d'exploitation* (modèles, dimensionnement, sauvegarde, rotation de clés, montée de version, observabilité). En cas de divergence sur un manifeste ou un seuil, c'est `deploy/README.md` qui fait foi.

Référence normative : [`docs/architecture/api-contract.md`](../architecture/api-contract.md) — §2 (arborescence, dont `deploy/`), §4.1 (sondes, `/metrics`), §8 (CLI), §9 (variables d'environnement), §10 (sécurité produit). Les éléments d'infrastructure cités ici comme *illustratifs* ne sont pas garantis par le contrat gelé.

---

## 1. Modèle de déploiement

| Forme | Ce que c'est | Ce qu'elle implique | Limite dans le MVP v0.1.0 |
|---|---|---|---|
| **Mono-nœud** | un processus `thotsecure serve` et sa base SQLite locale | sauvegarde = un fichier + la configuration versionnée | pas de coordinations réseau, pas de bascule |
| **Conteneur** | une image + un volume persistant monté sur `data/` | l'état vit dans le **volume**, jamais dans l'image | un seul conteneur écrivain |
| **Kubernetes** | un `Deployment` (1 réplique) + PVC + sondes HTTP | `livenessProbe` → `/healthz`, `readinessProbe` → `/readyz` | `replicas: 1` obligatoire avec SQLite |

`thotsecure serve [--host --port --reload]` est le point d'entrée unique (contrat §8) ; l'écoute par défaut est `THOT_HOST=0.0.0.0` / `THOT_PORT=8080` (§9).

### 1.1 Avec SQLite : un seul écrivain, donc une seule réplique

`THOT_DB_URL` vaut par défaut `sqlite:///./data/thotsecure.db` (§9). Une base SQLite accepte **un seul écrivain** à la fois.

* **Conséquence directe** : jamais de `replicas: 2`, jamais de `docker compose up --scale thotsecure=2`, jamais deux nœuds partageant le même fichier sur un volume réseau.
* Un déploiement à plusieurs instances derrière un répartiteur produirait des verrous d'écriture, des files d'attente et des erreurs `500 internal_error` — pas une haute disponibilité.

!!! info "PostgreSQL : la voie de la haute disponibilité — et son état réel"
    La haute disponibilité **réelle** passe par PostgreSQL/TimescaleDB (`THOT_DB_URL` non-SQLite),
    puis par plusieurs réplicas sans état partagé : **l'adaptateur est écrit et validé en CI** sur un
    serveur TimescaleDB, avec les deux backends exercés par la même suite de conformité
    (`tests/test_storage_conformance.py`). Il n'a en revanche **pas encore été éprouvé en production
    à grande échelle** : aucune campagne de charge n'a été menée, et les repères de dimensionnement
    de la §2.2 sont des estimations. Tant que le basculement n'a pas été répété sur votre
    infrastructure : **une réplique** suffit, et le passage à plusieurs instances se décide avec la
    §3.3 en main.

### 1.2 Autonomie et `dry_run` : des paramètres de déploiement de premier ordre

Deux réglages changent la nature du déploiement et doivent être décidés *avant* la mise en production :

| Réglage | Défaut | Effet en production |
|---|---|---|
| `THOT_AUTONOMY` | `supervised` | `manual` = aucune exécution sans intervention ; `supervised` = approbation humaine ; `auto` = exécution par politique |
| `THOT_DRY_RUN` | `true` | `true` = **aucun effet réel** ; garde-fou global prioritaire sur toute politique (§6, garde-fou 4) |

Le `mode` et le `dry_run` sont aussi surchargeables **par tenant** via `PATCH /api/v1/tenants/{id}` (§4.2). Recommandation de démarrage : `THOT_ENV=prod`, `THOT_AUTONOMY=supervised`, `THOT_DRY_RUN=true`, puis lever le dry-run tenant par tenant.

Voir aussi [`../configuration.md`](../configuration.md) pour la référence complète des variables et [`../architecture/threat-model.md`](../architecture/threat-model.md) pour l'analyse des risques liés à l'automatisation.

---

### 1.3 Choisir le backend

| Critère | SQLite (défaut) | PostgreSQL + TimescaleDB |
|---|---|---|
| Installation | aucune dépendance | extra optionnel : `pip install "thotsecure[postgres]"` (psycopg 3 ; `psycopg2` accepté en repli) |
| Débit d'ingestion | quelques centaines d'événements/s, **un seul écrivain** | plusieurs écrivains concurrents, partitionnement par le temps |
| Instances applicatives | `replicas: 1` obligatoire | plusieurs réplicas possibles (le magasin est sans état) |
| Rétention | purge applicative + `VACUUM` | politique de rétention native (`drop_chunks`) en plus de la purge applicative |
| Compression | aucune | compression des chunks anciens (si la version de TimescaleDB l'accepte : voir `docs/architecture/data-model.md` §8.6) |
| Sauvegarde | copie de fichier / `VACUUM INTO` | `pg_dump` ou `pg_basebackup` (§4.6) |
| RPO / RTO | minutes à heures, dépend de la fréquence de copie | RPO ≈ 0 avec une réplique en streaming (§3.3), RTO de quelques minutes à la main |

Le choix est **explicite** : `create_store()` refuse un schéma non supporté plutôt que de retomber
silencieusement sur SQLite — un exploitant ne doit jamais croire écrire dans sa base de production
alors que les données partent dans un fichier local.

!!! warning "Trois lignes à adapter avant un déploiement PostgreSQL"
    `thotsecure doctor` et `thotsecure init-db` affichent `settings.db_path`, dont la résolution
    **lève une erreur** quand `THOT_DB_URL` n'est pas SQLite. De plus, `build_service()` construit
    encore le magasin SQLite directement. Les lignes à changer sont les suivantes (elles ne
    modifient aucun comportement SQLite) :

    ```diff
    --- a/src/thotsecure/service.py
    +++ b/src/thotsecure/service.py
    -from .storage.store import Store
    +from .storage import create_store
    @@
    -    store = Store(settings.db_path)
    +    store = create_store(settings)
    ```

    Côté CLI, remplacez `str(settings.db_path)` (et `settings.db_path.exists()`) par
    `storage.store_location(store)` : la fonction rend le chemin du fichier SQLite **ou** le DSN
    PostgreSQL masqué, sans jamais supposer le moteur — et sans jamais afficher de mot de passe.
    En attendant, vérifiez une base PostgreSQL par `GET /readyz`, par `store.health()` ou par
    l'extrait Python de [`../architecture/data-model.md`](../architecture/data-model.md) §8.7.

## 2. Dimensionnement

!!! warning "Des ordres de grandeur, pas des garanties"
    Tous les chiffres de cette section sont des **estimations de dimensionnement à valider par un test de charge** sur votre propre flux (taille d'événement, nombre de règles, nombre de tenants). Aucun n'est garanti par le contrat.

Hypothèse de conversion utilisée partout : **~1 Kio par événement sérialisé** (le contrat borne `payload` à 32 Kio maximum, §3.1 ; la moyenne réelle est bien plus basse). À remplacer par votre mesure.

| Profil | Volume de logs/jour | vCPU | RAM | Disque (base + marge + sauvegardes) | IOPS soutenues |
|---|---|---|---|---|---|
| **Labo / pilote** | ~10 Go/jour | 2 | 4 Go | 300 Go SSD (≈ 60–100 Go de base, le reste en marge et sauvegardes) | ~500 |
| **MSP moyen** | ~100 Go/jour | 4–8 | 16 Go | 1,5–2 To NVMe | 2 000–3 000 |
| **MSSP** | ~1 To/jour | 16+ | 64 Go | 20–30 To NVMe, ou sortie du mono-nœud | 10 000+ |

**Remarque structurante : le goulot est l'écriture SQLite et l'ingestion, pas le CPU.** Ajouter des vCPU à un mono-nœud SQLite n'accélère presque rien tant que le disque sature : privilégiez le NVMe, le débit d'écriture et la latence, et surveillez le WAL (§8).

### 2.1 Coût de la rétention dans le calcul disque

`THOT_RETENTION_DAYS` (défaut **30**) pilote la purge des événements. La formule de base :

```text
disque_base ≈ (événements/jour × taille moyenne d'un événement) × jours de rétention
```

Exemple illustratif avec l'hypothèse ~1 Kio/événement (les deux termes sont vos propres mesures) :

```text
10 Go/jour × 30 jours                          = 300 Go de données brutes
+ index SQLite + WAL                           ≈ ×1,3 à ×1,5  →  ~400–450 Go
+ marge de croissance, VACUUM, imports         ≈ 15 à 20 %
+ 2 à 4 sauvegardes locales en rotation        →  prévoir ×2 en pratique
```

Toujours dimensionner **le total mesuré, jamais la seule valeur brute** :

* réduire `THOT_RETENTION_DAYS` réduit le disque, mais aussi la profondeur d'investigation et la valeur des statistiques 7 jours de `GET /api/v1/stats/overview` ;
* augmenter la rétention au-delà de 30 jours se paie en IOPS de purge autant qu'en gigaoctets ;
* `THOT_RATE_LIMIT_PER_MIN` (défaut 600) borne l'abus d'ingestion, pas le volume légitime : c'est le volume légitime qu'il faut dimensionner.

### 2.2 Dimensionnement TimescaleDB

!!! warning "Toujours des ordres de grandeur, jamais des mesures"
    Les chiffres ci-dessous viennent des hypothèses de la §2.1 et des ordres de grandeur
    communément observés sur TimescaleDB. **Aucune campagne de charge n'a été menée sur ce
    backend** : mesurez `hypertable_size('events')` sur votre instance avant de dimensionner.

**Découpage en chunks et compression**

| Réglage | Valeur livrée | Conséquence pratique |
|---|---|---|
| `chunk_time_interval` | `1 day` | un chunk par jour et par hypertable : la granularité de la rétention par `drop_chunks` **et** de la compression |
| `compress_segmentby` | `tenant_id` | un segment par tenant : une requête mono-tenant ne décompresse que son segment |
| `compress_orderby` | `ts DESC` | lectures récentes plus rapides dans un chunk compressé |
| `add_compression_policy` | au-delà de **7 jours** | un chunk compressé devient **non modifiable** : c'est cohérent avec l'immuabilité des événements (§1 du modèle de données), mais interdit toute correction de données au-delà de la fenêtre |
| `add_retention_policy` | **30 jours** | aligné sur `THOT_RETENTION_DAYS` par défaut ; à ajuster si vous changez cette variable (la purge applicative, elle, suit toujours la configuration) |

La compression divise typiquement le stockage des événements par 5 à 10 selon la redondance des
`labels`/`payload`. Elle n'est **pas garantie** : certaines versions de TimescaleDB refusent de
compresser une hypertable dont la clé primaire contient des colonnes absentes de
`compress_segmentby`. L'adaptateur applique la compression dans sa propre transaction : si elle est
refusée, il journalise un avertissement, n'annonce pas la capacité `compression`, et continue (la
rétention par chunks reste valide). Vérifiez-le sur votre instance :

```sql
SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';
-- Doit réussir, sinon ajustez compress_segmentby ou renoncez à la compression :
SELECT compress_chunk(c) FROM show_chunks('events') c LIMIT 1;
```

**Formule de disque (à remplacer par vos mesures)**

```text
événements/jour × 1 Kio                              (avant compression)
÷ 5 à 10                                             (chunks de plus de 7 jours compressés)
× 30 jours de rétention
+ index (GIN inclus) et surcoût de pages             ≈ ×1,2 à ×1,4
+ findings et audit_log, non purgés                  voir §2.1
+ WAL, 2 à 4 sauvegardes en rotation                 → prévoir ×2 en pratique
```

**Réglages serveur qui comptent le plus**

| Paramètre | Point de départ | Pourquoi |
|---|---|---|
| `shared_buffers` | 25 % de la RAM | la base travaille surtout sur des lectures récentes (24 h / 7 j) |
| `work_mem` | 64–256 Mo | `drop_chunks` et la compression trient de gros chunks |
| `maintenance_work_mem` | 512 Mo–1 Gio | compression et autovacuum |
| `max_connections` | `≥ max_size du pool applicatif + marge` | le pool maison **bloque** au-delà (`pool saturé`) plutôt que d'écraser le serveur : mieux vaut le dimensionner |
| `statement_timeout` | 60 s (posé par l'adaptateur) | une requête qui dérape est interrompue par le serveur, au lieu de tenir des verrous |
| `checkpoint_timeout` / `max_wal_size` | 15 min / 4–8 Go | l'ingestion par lots produit de gros pics de WAL |

**À surveiller (requêtes utiles)**

```sql
-- Volumétrie de l'hypertable et des index
SELECT pg_size_pretty(hypertable_size('events'));
-- Nombre de chunks et état de compression (compressés / non compressés)
SELECT count(*) FILTER (WHERE is_compressed) AS compressés, count(*) AS total
FROM timescaledb_information.chunks WHERE hypertable_name = 'events';
-- Derniers jobs (rétention, compression, agrégats continus) et leurs échecs
SELECT job_id, proc_name, last_run_status, last_successful_finish
FROM timescaledb_information.job_stats ORDER BY job_id;
-- Connexions et requêtes longues
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;
SELECT pid, now() - query_start AS durée, left(query, 80) FROM pg_stat_activity
WHERE state <> 'idle' ORDER BY durée DESC LIMIT 10;
-- Fraîcheur de l'agrégat continu alimentant le tableau de bord
SELECT * FROM timescaledb_information.continuous_aggregates;
```

!!! note "Deux rétentions qui coexistent"
    La politique TimescaleDB (30 jours, par chunks entiers) et la purge applicative
    (`purge(retention_days=…)`, exacte à la ligne près mais par lots bornés) visent la même donnée.
    C'est voulu : si un opérateur abaisse `THOT_RETENTION_DAYS`, la purge applicative est le
    mécanisme qui s'applique réellement ; la politique native garantit, elle, qu'un service arrêté
    pendant deux mois ne se retrouve pas avec une hypertable qui grossit sans fin. En cas de
    divergence, **alarmez sur le plus court des deux seuils**.

---

## 3. Haute disponibilité

### 3.1 Ce qui est honnêtement possible dans le MVP

| Mécanisme | Ce que ça apporte | Ce que ça n'apporte pas |
|---|---|---|
| **Redémarrage automatique** | le service revient après un crash (supervision système, `restart: always`) | pas de continuité de service pendant l'arrêt |
| **Sondes `/healthz` + `/readyz`** | détection d'échec et retrait du trafic | pas de réparation automatique |
| **Sauvegardes fréquentes** | réduction du RPO réel | pas de disponibilité |
| **Nœud de secours « froid »** | reprise manuelle sur une machine déjà préparée | pas de bascule automatique |

Un **redémarrage ne perd pas la chaîne d'audit** : le journal est *append-only* et chaîné par hash (§3.5), les enregistrements déjà écrits restent vérifiables. Ce qui peut être perdu, c'est ce qui n'était pas encore persisté (événements en mémoire dans le bus `memory`, actions en cours d'exécution, voir §8 et le runbook).

**Règle de remise en trafic** : après tout redémarrage, `/readyz` doit repasser à **`200`**. La sonde vérifie **DB + bus + règles** (§4.1) ; un `503` signifie qu'un de ces trois piliers n'est pas opérationnel et que le service ne doit pas recevoir de trafic.

### 3.2 Le bus comme brique de découplage

Thot Secure décrit trois bus (§2, §9) : `memory`, `sqlite`, `nats`.

```yaml
# extrait de configuration — les valeurs exactes sont du ressort de deploy/README.md
THOT_BUS: nats
THOT_NATS_URL: nats://127.0.0.1:4222
```

* `memory` : le plus simple, non durable (perte au redémarrage).
* `sqlite` : durable localement, cohérent avec le mono-nœud.
* `nats` : découple collecteurs et traitement ; c'est la brique qui permet, plus tard, de déplacer l'ingestion hors du nœud applicatif.

!!! info "Ce que la HA active demande encore"
    La **bascule automatique** (et la conscience du rôle primaire/secondaire côté application) n'est
    pas implémentée : l'adaptateur PostgreSQL ouvre des connexions sur **un** DSN, sans réessayer sur
    un second hôte. Une bascule reste donc une opération d'exploitation (voir §3.3).

### 3.3 Réplication minimale (PostgreSQL)

L'objectif de cette section n'est pas la HA automatique, mais **le RPO** : ne pas perdre les
écritures des dernières minutes en cas de perte du nœud primaire.

```conf
# postgresql.conf du primaire
wal_level = replica
max_wal_senders = 5
wal_keep_size = 1GB
# RPO ≈ 0 au prix de la latence d'écriture (à mesurer avant d'activer) :
synchronous_standby_names = 'thot_standby'
synchronous_commit = remote_apply      # 'on' est moins coûteux, 'off' accepte une perte
```

```bash
# Sur le secondaire, une seule fois :
pg_basebackup -h primaire -D /var/lib/postgresql/16/main -U replicator -Fp -Xs -P -R
# -R écrit primary_conninfo et standby.signal : le secondaire démarre alors en lecture seule.
```

| Ce que ça apporte | Ce que ça n'apporte pas |
|---|---|
| RPO ≈ 0 avec `synchronous_commit = remote_apply` | bascule automatique (à faire à la main) |
| un secondaire déjà chaud pour un test de restauration | continuité de service pendant la bascule |
| réplication vérifiable (`pg_stat_replication`) | répartition de charge applicative (le secondaire est en lecture seule) |

**Bascule manuelle, côté Thot Secure** — l'application est sans état, l'opération est donc
volontairement simple :

1. promouvoir le secondaire : `pg_ctl promote -D /var/lib/postgresql/16/main` ;
2. repointer `THOT_DB_URL` sur le nouveau primaire (DNS, VIP, ou modification du secret) ;
3. redémarrer `thotsecure serve` : le pool rouvre ses connexions (il n'y a **pas** de reprise
   transparente d'une connexion coupée — c'est le pool qui la remplace, et `health()` qui le signale) ;
4. vérifier `GET /readyz` → `200`, puis la chaîne d'audit : `GET /api/v1/audit/verify` doit rester
   `valid: true`. **Un `valid: false` après bascule signifie que le secondaire a reçu des écritures
   incomplètes** : isolez la base et traitez-le comme un incident de sécurité (runbook, incident 3).

!!! warning "Le chaînage d'audit et la bascule"
    `append_audit` sérialise les écrivains par un verrou consultatif de transaction
    (`pg_advisory_xact_lock`). Ce verrou est **local au serveur primaire** : il n'est pas répliqué.
    C'est sans risque — un secondaire promu n'a, par construction, reçu aucun maître d'audit dont le
    `prev_hash` aurait été calculé par un autre écrivain en cours — mais cela interdit de faire
    écrire **deux primaires** en parallèle (réplication bidirectionnelle, multi-maître) : la chaîne
    d'audit se romprait. Un seul primaire accepte des écritures.

---

## 4. Sauvegarde et restauration chiffrée

### 4.1 Ce qu'il faut sauvegarder

| Élément | Emplacement par défaut | Méthode |
|---|---|---|
| **Base** | `data/thotsecure.db` (`THOT_DB_URL`) | instantané cohérent (ci-dessous) |
| **Base (PostgreSQL/TimescaleDB)** | le serveur PostgreSQL (`THOT_DB_URL=postgresql://…`) | `pg_dump` **ou** `pg_basebackup` + archivage WAL (§4.6) |
| **Configuration** | `config/targets.yaml` (`THOT_TARGETS_FILE`) | copie de fichier |
| **Règles** | `rules/` (`THOT_RULES_DIR`) | copie de fichier (idéalement versionnée) |
| **Politiques** | `policies/` (`THOT_POLICIES_DIR`) | copie de fichier |
| **Playbooks** | `playbooks/` (`THOT_PLAYBOOKS_DIR`) | copie de fichier |
| **`THOT_SECRET_KEY`** | hors base | **coffre séparé** — voir l'encadré `danger` |

### 4.2 Instantané cohérent de la base SQLite

Ne **jamais** copier un fichier SQLite en cours d'écriture sans précaution : le WAL peut être désynchronisé. Deux voies sûres — arrêt du service, ou instantané logique.

**Option A — service à l'arrêt (la plus simple)**

```bash
# arrêt propre : laisse le WAL se vider avant la copie
systemctl stop thotsecure
cp data/thotsecure.db "backup/thotsecure-$(date -u +%Y%m%dT%H%M%SZ).db"
systemctl start thotsecure
```

```powershell
# Windows, si Thot Secure est enregistré comme service
Get-Service thotsecure
Stop-Service thotsecure
Copy-Item data\thotsecure.db "backup\thotsecure-$(Get-Date -Format yyyyMMddTHHmmss).db"
Start-Service thotsecure
Get-Service thotsecure
```

**Option B — à chaud : `VACUUM INTO` ou `.backup`**

```bash
# VACUUM INTO : produit une base compacte et cohérente, sans arrêt du service
sqlite3 data/thotsecure.db "VACUUM INTO 'backup/thotsecure-2026-09-13.db';"

# ou, depuis le shell sqlite3 (équivalent d'un .backup)
sqlite3 data/thotsecure.db ".backup 'backup/thotsecure-2026-09-13.db'"
```

```powershell
sqlite3 data\thotsecure.db ".backup 'backup\thotsecure-2026-09-13.db'"
```

Le `VACUUM INTO` a l'avantage d'être compact (il ne transporte pas les pages libres) et lisible par un test de restauration immédiat.

### 4.3 Archiver, chiffrer, vérifier, stocker hors site

```bash
# 1) archive (base + configuration versionnée)
tar czf backup/thotsecure-2026-09-13.tar.gz \
    backup/thotsecure-2026-09-13.db config/targets.yaml rules/ policies/ playbooks/

# 2) chiffrement symetrique AES256
gpg --symmetric --cipher-algo AES256 --output backup/thotsecure-2026-09-13.tar.gz.gpg \
    backup/thotsecure-2026-09-13.tar.gz

# variante age (phrase secrete)
age -p -o backup/thotsecure-2026-09-13.tar.gz.age backup/thotsecure-2026-09-13.tar.gz

# 3) empreinte d'integrite
sha256sum backup/thotsecure-2026-09-13.tar.gz.gpg > backup/thotsecure-2026-09-13.sha256

# 4) hors site
#    (rsync, objet S3 chiffre, bande...) — jamais sur le meme hote que la base
```

```powershell
# 1) archive
Compress-Archive -Path backup\thotsecure-2026-09-13.db,config\targets.yaml,rules,policies,playbooks `
                 -DestinationPath backup\thotsecure-2026-09-13.zip

# 2) chiffrement (gpg symetrique AES256)
gpg --symmetric --cipher-algo AES256 --output backup\thotsecure-2026-09-13.zip.gpg backup\thotsecure-2026-09-13.zip

# 3) empreinte d'integrite
Get-FileHash -Algorithm SHA256 backup\thotsecure-2026-09-13.zip.gpg |
    Select-Object -ExpandProperty Hash | Out-File backup\thotsecure-2026-09-13.sha256
```

Trois exigences non négociables :

1. **chiffrée** (gpg symétrique AES256, `age`, ou coffre managé) : une sauvegarde en clair équivaut à une fuite de l'inventaire de vos tenants ;
2. **vérifiée** : empreinte connue et comparée à chaque restauration (`sha256sum` / `Get-FileHash`) ;
3. **hors site** : la sauvegarde ne doit pas disparaître avec l'hôte qu'elle protège.

!!! danger "`THOT_SECRET_KEY` : à sauvegarder, mais **séparément** de la base"
    `THOT_SECRET_KEY` est le **pepper des clés API** et sert à la signature (§9, §10). Les clés API sont stockées **hachées** (`scrypt`, §10) : sans le pepper d'origine, une base restaurée conserve des empreintes que **personne ne peut plus valider** — vos clés deviennent inutilisables.

    * ne stockez **jamais** `THOT_SECRET_KEY` dans la même archive, le même coffre au même niveau d'accès, ni le même site que la base ;
    * notez aussi la **date** de la clé utilisée pour chaque sauvegarde : elle conditionne la procédure de rotation (§5) ;
    * le coffre à secrets (Vault, KMS, gestionnaire de mots de passe d'entreprise) est le bon endroit, avec des accès journalisés et distincts de ceux de la base.

### 4.4 Test de restauration (obligatoire)

> **Une sauvegarde non testée n'est pas une sauvegarde.**

1. **Préparer un hôte de test** (jamais en production) et y restaurer le binaire de la *même version* que celle de la sauvegarde.
2. **Déchiffrer** l'archive et **vérifier l'empreinte** :
   ```bash
   sha256sum -c backup/thotsecure-2026-09-13.sha256
   gpg --decrypt --output /tmp/thotsecure-restore.tar.gz backup/thotsecure-2026-09-13.tar.gz.gpg
   tar xzf /tmp/thotsecure-restore.tar.gz -C /srv/thotsecure-restore/
   ```
3. **Poser la configuration attendue** : `THOT_DB_URL` pointant sur la base restaurée, `THOT_SECRET_KEY` **celle d'origine**, `THOT_ENV=prod`, `THOT_DRY_RUN=true`.
4. **Diagnostiquer** : `thotsecure doctor` — il valide la configuration, l'accès base et la cohérence des répertoires.
5. **Vérifier la chaîne d'audit** : `thotsecure audit verify` — doit retourner un succès (code de sortie `0`). Un code `3` signifie « vérification négative » (§8) et doit bloquer la bascule.
6. **Vérifier le fonctionnel** : `GET /readyz` → `200`, puis `thotsecure findings list --tenant acme` et `GET /api/v1/stats/overview` (compteurs 24 h/7 j).
7. **Consigner** : date, version, RPO réellement constaté, durée totale, anomalies. Un test trimestriel est un minimum.

### 4.5 RPO / RTO par scénario

Estimations à valider par un exercice réel (elles dépendent de votre fréquence de sauvegarde et de votre procédure interne) :

| Scénario | RPO visé (données perdues) | RTO visé (temps d'arrêt) | Dépend surtout de |
|---|---|---|---|
| Corruption de la base | 0 si `.backup`/`VACUUM INTO` à chaud récent ; sinon l'intervalle de sauvegarde | 30–60 min | vitesse de restauration + test `audit verify` |
| Perte du disque | dernière sauvegarde hors site | 1–4 h | disponibilité d'un nœud de secours froid |
| Erreur de manipulation (mauvaise règle, purge trop agressive) | dernière sauvegarde + rechargement des règles versionnées | 30 min | règles et politiques sous gestion de version |
| Compromission du nœud | dernière sauvegarde **antérieure** à la compromission | 4–24 h | forensic + rotation de `THOT_SECRET_KEY` (§5) |
| Perte du site | dernière sauvegarde hors site | > 4 h | plan de continuité (hors périmètre MVP) |

### 4.6 Sauvegarde PostgreSQL / TimescaleDB

Deux méthodes, à choisir selon le RPO visé (elles se combinent : `pg_basebackup` pour le socle,
`pg_dump` pour un export logique portable et relisible).

**Option A — `pg_dump` (logique, portable, suffisant jusqu'à quelques dizaines de Go)**

```bash
# Base complète, format custom (compressé, restaurable sélectivement)
pg_dump -Fc -d thotsecure -f backup/thotsecure-$(date -u +%Y%m%dT%H%M%SZ).dump

# Rôles et mots de passe (à stocker séparément de la base !)
pg_dumpall --roles-only -f backup/roles-$(date -u +%Y%m%dT%H%M%SZ).sql

# Empreinte d'intégrité, puis chiffrement (identique à la §4.3)
sha256sum backup/*.dump > backup/thotsecure.sha256
```

```bash
# Restauration dans une base NEUVE (jamais dans une base en service)
psql -c "CREATE DATABASE thotsecure_restore OWNER thot;"
psql -d thotsecure_restore -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
psql -d thotsecure_restore -c "SELECT timescaledb_pre_restore();"
pg_restore -d thotsecure_restore --no-owner --role=thot backup/thotsecure-….dump
psql -d thotsecure_restore -c "SELECT timescaledb_post_restore();"
```

!!! warning "L'extension doit exister **avant** la restauration"
    Un `pg_dump` d'une hypertable contient les chunks sous forme de tables ; sans l'extension
    `timescaledb` déjà créée, la restauration échoue ou produit des tables ordinaires. Les appels
    `timescaledb_pre_restore()` / `timescaledb_post_restore()` désactivent temporairement la
    gestion des chunks pendant l'import : ce sont eux qui font passer une restauration de plusieurs
    dizaines de Go de « plusieurs heures » à « quelques dizaines de minutes ».

**Option B — `pg_basebackup` + archivage WAL (physique, restauration à un instant précis)**

```conf
# postgresql.conf du primaire
archive_mode = on
archive_command = 'test ! -f /srv/wal/%f && cp %p /srv/wal/%f'   # à durcir : vérifié, hors site
```

```bash
pg_basebackup -h primaire -D /srv/backup/base -Ft -z -Xs -P
```

C'est la seule méthode qui permet la **restauration à un instant précis** — indispensable face au
scénario « une purge trop agressive a supprimé 25 jours d'événements » (§4.5, ligne « erreur de
manipulation ») : `recovery_target_time = '2026-09-13 08:00:00+00'`.

| Méthode | RPO | RTO indicatif | Usage |
|---|---|---|---|
| `pg_dump` quotidien | 24 h | minutes à dizaines de minutes | développement, labo, petite instance |
| `pg_dump` + `pg_basebackup` quotidien | 24 h | dizaines de minutes | socle recommandé |
| `pg_basebackup` + archivage WAL continu | quelques minutes | minutes | production, avec possibilité de PITR |

**Vérification obligatoire après restauration** (§4.4, adaptée) :

1. lancer `/readyz` **contre la base restaurée** → `200` (la sonde appelle `health()`, qui exécute un
   vrai `SELECT 1`) ;
2. comparer les volumes : `SELECT count(*) FROM events;`, `SELECT count(*) FROM findings;`,
   `SELECT count(*) FROM audit_log;` — et, si vous les avez relevés avant l'incident, les mêmes
   compteurs sur la base d'origine ;
3. vérifier la chaîne d'audit : `GET /api/v1/audit/verify` doit répondre
   `{"valid":true,"records":n,"broken_at":null}`. En exploitation dégradée (API arrêtée), utilisez
   l'extrait Python de [`../architecture/data-model.md`](../architecture/data-model.md) §8.7 :
   `AuditChain(store).verify()` ;
4. vérifier les jobs TimescaleDB : `SELECT job_id, last_run_status FROM
   timescaledb_information.job_stats;` — les politiques de rétention et de compression doivent être
   présentes et en succès après restauration (`pg_dumpall` ne les transporte pas : ce sont des
   métadonnées de l'extension) ;
5. consigner date, version de TimescaleDB, RPO constaté et durée — **ce test n'est pas facultatif :
   la chaîne d'audit restaurée est votre seule preuve en cas d'incident**.

!!! danger "Ce qui n'a pas été testé"
    Les commandes ci-dessus sont la documentation officielle de PostgreSQL et TimescaleDB, mais elles
    **n'ont pas été exécutées dans la CI d'Thot Secure** (le job `postgres` exécute la suite de
    conformité, pas une restauration). Le test de restauration est donc à faire, puis à répéter
    trimestriellement, sur **votre** infrastructure avant de considérer la procédure comme acquise.

Ce sont **deux procédures distinctes**, à ne pas confondre.

| Clé | Fréquence recommandée | Impact | Procédure |
|---|---|---|---|
| Clé API d'un usage (CI, intégration, astreinte) | 90 jours, ou immédiatement en cas de doute | l'appelant doit être redéployé avec la nouvelle clé | créer la nouvelle clé, redéployer, **révoquer l'ancienne** (§5.1) |
| `THOT_BOOTSTRAP_API_KEY` (clé admin initiale) | **à la première mise en production**, puis jamais laissée par défaut | accès admin total au tenant | remplacer la valeur, créer des clés nominatives, révoquer la clé d'amorçage si possible (§5.2) |
| `THOT_SECRET_KEY` (pepper + signature) | rare — seulement sur suspicion de compromission | **toutes** les clés API peuvent devenir invalides | fenêtre de maintenance, régénération, recréation des clés (§5.3) |

## 5. Rotation des clés API et de `THOT_SECRET_KEY`

Ce sont **deux procédures distinctes**, à ne pas confondre.

| Clé | Fréquence recommandée | Impact | Procédure |
|---|---|---|---|
| Clé API d'un usage (CI, intégration, astreinte) | 90 jours, ou immédiatement en cas de doute | l'appelant doit être redéployé avec la nouvelle clé | créer la nouvelle clé, redéployer, **révoquer l'ancienne** (§5.1) |
| `THOT_BOOTSTRAP_API_KEY` (clé admin initiale) | **à la première mise en production**, puis jamais laissée par défaut | accès admin total au tenant | remplacer la valeur, créer des clés nominatives, révoquer la clé d'amorçage si possible (§5.2) |
| `THOT_SECRET_KEY` (pepper + signature) | rare — seulement sur suspicion de compromission | **toutes** les clés API peuvent devenir invalides | fenêtre de maintenance, régénération, recréation des clés (§5.3) |

### 5.1 Rotation d'une clé API (à chaud, sans interruption)

1. **Créer** la nouvelle clé : `POST /api/v1/tenants/{id}/keys` avec `{"role":"responder","label":"ci-2026-09"}` → `{"key_id","api_key":"ao_…"}` — **affichée une seule fois** (§4.2).
   ```bash
   thotsecure key create --tenant acme --role responder --label ci-2026-09
   ```
2. **Déployer** la nouvelle clé dans le consommateur (CI, script, intégration) et vérifier par `GET /api/v1/auth/whoami` (tenant, rôle, capacités, mode d'autonomie).
3. **Révoquer** l'ancienne : `DELETE /api/v1/keys/{key_id}` → `204`.
   ```bash
   thotsecure key revoke --key-id <ancien_key_id>
   ```
4. **Contrôler** : `GET /api/v1/tenants/{id}/keys` doit montrer `revoked_at` renseigné.

### 5.2 `THOT_BOOTSTRAP_API_KEY`

Le défaut `ao_dev_local_change_me` (§9) est **public** : il doit être remplacé avant toute exposition réseau. Créez ensuite des clés nominatives par usage et par personne ; révoquez la clé d'amorçage dès que les clés nominatives sont en place.

### 5.3 Rotation de `THOT_SECRET_KEY` : procédure prudente

!!! warning "Le contrat ne décrit pas de rotation à chaud de `THOT_SECRET_KEY`"
    Le contrat en fait le **pepper des clés API** et une clé de signature (§9, §10) sans documenter de mécanisme de double-pepper ou de migration d'empreintes. **Vérifiez le comportement exact dans le code avant de faire tourner cette clé en production : des clés API hachées avec l'ancien pepper peuvent devenir invalides du jour au lendemain.**

Procédure prudente, en **fenêtre de maintenance** :

1. **Annoncer** la fenêtre et prévenir les consommateurs (CI, intégrations, astreinte).
2. **Sauvegarder** base + configuration, et **noter l'ancienne valeur** de `THOT_SECRET_KEY` (elle reste nécessaire pour valider d'éventuelles restaurations antérieures).
3. **Arrêter** le service proprement.
4. **Régénérer** la clé (valeur aléatoire longue, générée par un CSPRNG) et la poser dans l'environnement ou le coffre.
5. **Redémarrer** et vérifier `GET /readyz` → `200`, puis `GET /api/v1/auth/whoami` avec chaque clé en service.
6. **Recréer** les clés API devenues invalides : `POST /api/v1/tenants/{id}/keys`, redéploiement des consommateurs, puis `DELETE /api/v1/keys/{key_id}` pour les clés mortes.
7. **Changer** `THOT_BOOTSTRAP_API_KEY`.
8. **Vérifier** qu'aucun `401`/`403` résiduel ne subsiste dans les logs (`THOT_LOG_LEVEL=INFO` suffit ; `DEBUG` pour creuser).
9. **Sauvegarder hors site** la nouvelle clé dans le coffre, séparément de la base.

### 5.4 Bonnes pratiques

* **une clé par usage et par rôle** — moindre privilège : `viewer` ⊂ `analyst` ⊂ `responder` ⊂ `admin` (§4) ;
* jamais de clé `admin` dans un pipeline sans nécessité : l'exécution d'actions relève de `responder` ;
* **révocation immédiate** au départ d'une personne, à la rotation d'un runner CI, ou au moindre doute — la révocation est instantanée (`204`), il n'y a pas de raison d'attendre ;
* une clé ne se « récupère » jamais : elle se révoque et se remplace (§10 : stockage haché `scrypt`, affichage unique). Voir le runbook, incident 7.

---

## 6. Montée de version

### 6.1 Procédure pas à pas

1. **Sauvegarder** (§4) et **vérifier** l'empreinte de l'archive.
2. **Lire le changelog** : [`../changelog.md`](../changelog.md) (source : `CHANGELOG.md` à la racine du dépôt). Sous `1.0.0`, toute rupture du contrat gelé est publiée en version **mineure** avec un préfixe `BREAKING` — lisez cette section en entier avant de mettre à jour.
3. **Arrêter** le service proprement (laissez le WAL se vider).
4. **Mettre à jour** le binaire/paquet ou l'image, en notant la version cible exacte.
5. **Migrer** : `thotsecure init-db` (voir §7).
6. **Diagnostiquer** : `thotsecure doctor`.
7. **Vérifier la préparation** : `GET /readyz` → `200` (DB + bus + règles).
8. **Vérifier le fonctionnel** : `thotsecure findings list --tenant acme`, `GET /api/v1/stats/overview`, `thotsecure audit verify` (code `0` attendu).
9. **Surveiller 24 h** : erreurs 5xx, taux de rejet d'ingestion, `429 rate_limited`, findings/jour vs la veille, actions échouées.

### 6.2 Retour arrière

1. **Arrêter** le service.
2. **Revenir à la version précédente** (paquet ou image taggée connue).
3. **Restaurer** la sauvegarde prise à l'étape 1 — obligatoire si `thotsecure init-db` a modifié le schéma : une base migrée n'est pas garantie lisible par une version antérieure.
4. **Diagnostiquer** : `thotsecure doctor`, puis `thotsecure audit verify`.
5. **Remettre en trafic** seulement après `/readyz` → `200`.

### 6.3 Impact et réversibilité des changements

| Changement | Impact | Réversible ? | Précaution |
|---|---|---|---|
| Nouvelle version applicative | comportement, perf, format de sortie | oui (retour au binaire précédent) | sauvegarde + lecture du changelog |
| Migration de schéma (`thotsecure init-db`) | structure de la base | **partiellement** — dépend de la migration | sauvegarde **avant**, test sur copie |
| Modification de `rules/` | détections (plus ou moins de findings) | oui (rechargement) | `thotsecure rules validate --path rules`, puis `POST /api/v1/rules/reload` |
| Modification de `policies/` | décisions (`auto`, seuils, plafonds) | oui (rechargement) | revue à deux ; attention aux décisions `auto` |
| Modification de `config/targets.yaml` | périmètre autorisé des actions | oui | une cible retirée du périmètre passe en `require_approval` (§6, garde-fou 5) |
| Changement de `THOT_BUS` | distribution des événements | oui, avec perte possible des messages en vol | fenêtre calme ; voir runbook, incident 4 |
| Rotation de `THOT_SECRET_KEY` | validité des clés API | **non** sans recréation des clés | procédure §5.3 en fenêtre de maintenance |
| Baisse de `THOT_RETENTION_DAYS` | purge irréversible d'événements | **non** | vérifier l'espace disque et la politique de rétention légale |

!!! info "Roadmap"
    L'outillage de migration n'est pas figé par le contrat : `thotsecure init-db` est la commande documentée (§8), mais la présence d'un système de versions de schéma, de migrations descendantes ou d'un mode `--dry-run` de migration **n'est pas garantie** et doit être confirmée dans le code avant de bâtir une procédure d'exploitation dessus.

---

## 7. Migrations

`thotsecure init-db` (§8) prépare la base : création des tables puis des index nécessaires. C'est l'unique commande de migration documentée par le contrat.

| Point | Ce que dit le contrat | Ce qu'il faut confirmer dans le code |
|---|---|---|
| Ordre d'application | non spécifié | l'ordre exact (tables → index → éventuelles données de référence) est à lire dans `src/thotsecure/storage/` |
| Idempotence | non spécifiée | réexécuter `init-db` sur une base à jour doit être sans effet — **à vérifier** |
| Migrations destructives | non spécifiées | toute colonne supprimée/renommée change la procédure de retour arrière (§6.2) |
| Rétention / purge | `THOT_RETENTION_DAYS` (défaut 30) purge les événements | planification (tâche interne ou externe ?), granularité et journalisation de la purge — **à vérifier** |
| Réindexation | non spécifiée | `VACUUM`/`ANALYZE` périodiques peuvent être nécessaires à la performance |

**Règles d'exploitation retenues :**

* exécuter `thotsecure init-db` **après chaque mise à jour** (même mineure), avant le redémarrage du service ;
* toujours après une sauvegarde vérifiée, jamais avant ;
* sur une base volumineuse, prévoir une fenêtre : la création d'index peut être longue et bloquante ;
* surveiller la purge de rétention comme une alerte à part entière (§9) : une purge silencieusement en échec remplit le disque.

---

## 8. Observabilité

### 8.1 Les trois sondes

| Sonde | Usage exact | Réponse |
|---|---|---|
| `GET /healthz` | **liveness** : le processus répond-il ? | `{"status":"ok","version":"0.1.0","uptime_s":12}` |
| `GET /readyz` | **readiness** : le service peut-il recevoir du trafic ? vérifie **DB + bus + règles** | `200` ou **`503`** |
| `GET /version` | version, commit, licence, **mode d'autonomie** global | objet JSON |

Les trois sont **publiques** (§4.1) : ne les exposez pas plus largement que nécessaire, mais elles doivent rester accessibles à la supervision (et sans authentification).

### 8.2 `GET /metrics`

`/metrics` expose du **texte Prometheus** (§4.1). À exposer **uniquement sur le réseau interne** : la route est publique et peut révéler le volume, le rythme et la nature de votre activité de détection.

!!! warning "Les noms de métriques se relèvent, ils ne se devinent pas"
    Le contrat **ne fige pas** les noms des séries Prometheus. Toute la section ci-dessous raisonne donc en **signaux**. Relevez les noms exacts sur votre instance :

    ```bash
    curl -sS http://127.0.0.1:8080/metrics | grep -i thotsecure | head -50
    ```

    Un nom tel que `thotsecure_events_ingested_total` est donné à titre **illustratif, à confirmer sur `/metrics`** : ne l'inscrivez pas dans un tableau de bord ou une règle d'alerte sans l'avoir constaté sur votre instance.

### 8.3 Signaux → seuil recommandé → action

| Signal | Source | Seuil d'alerte recommandé | Action |
|---|---|---|---|
| Disponibilité du service | `/healthz` (supervision HTTP) | 2 échecs consécutifs sur 3 minutes | redémarrer, puis vérifier `/readyz` → runbook 1 |
| Préparation au trafic | `/readyz` = `503` | plus de 2 minutes en `503` | identifier le pilier en cause (DB, bus, règles) → runbook 1 / 4 / 5 |
| Ingestion — débit | compteur d'événements ingérés sur `/metrics` | chute > 50 % vs même heure la veille | vérifier les collecteurs (`GET /api/v1/collectors`) → runbook 1 |
| Ingestion — rejets | taux de rejet de `POST /api/v1/events` (`rejected` vs `accepted`) | > 5 % sur 15 minutes | règle/format/schéma d'événement → runbook 1 |
| Ingestion — saturation | réponses `429 rate_limited` (§4.6) | présence soutenue, ou > 1 % des appels | revoir `THOT_RATE_LIMIT_PER_MIN` et le client fautif |
| Détection — volume | findings créés (24 h) vs `GET /api/v1/stats/overview` | ± 3× la médiane 7 jours | faux positif massif ou panne de détection → runbook 1 / 2 |
| Détection — erreurs | erreurs de règles : `POST /api/v1/rules/reload` renvoie `{"loaded":n,"errors":[…]}` non vide | toute erreur au chargement | corriger/réactiver la règle, `thotsecure rules validate --path rules` |
| Décision — dérive d'automatisation | compteur d'actions / décisions `auto` | > 2× la médiane horaire, ou `max_actions_per_hour` atteint (défaut 20, §6) | couper l'automatisation → **runbook 2** |
| Décision — garde-fous | déclenchements de garde-fous (plafond horaire, cooldown, cible protégée, hors périmètre) | toute hausse brutale | indique une politique trop agressive → runbook 2 |
| Action — échecs | taux d'échec d'exécution | > 10 % sur 30 minutes | état du connecteur → runbook 6 |
| Action — rollbacks | nombre d'actions exécutées / rollback effectués | pic anormal, ou rollback > exécutions | corriger la politique/le playbook → runbook 2 |
| Action — blocage | actions en statut `executing` (§3.4) | > 15 minutes sans transition | réconciliation avec le connecteur → **runbook 6** |
| Audit — intégrité | `GET /api/v1/audit/verify` → `valid:false` | **toute** occurrence | incident de sécurité → **runbook 3** |
| Audit — retard de séquence | écart entre le dernier `seq` et le débit attendu | retard croissant sur 10 minutes | écritures concurrentes/verrous → runbook 3 / 5 |
| Ressources — disque | espace libre, taille de la base et du **WAL SQLite** | < 20 % libre, ou WAL en croissance continue | purger, archiver, agrandir → runbook 5 |
| Ressources — rétention | purge `THOT_RETENTION_DAYS` en échec ou absente | 2 exécutions manquées | corriger la purge, sinon saturation disque → runbook 5 |
| Ressources — chunks *(PostgreSQL)* | `timescaledb_information.chunks` : chunk non compressé de plus de 7 jours | 2 jours consécutifs | compression refusée ou en échec → §2.2 |
| Ressources — jobs *(PostgreSQL)* | `timescaledb_information.job_stats` : `last_run_status` | 2 exécutions `failed` (compression, rétention, agrégats continus) | rejouer à la main (`compress_chunk`, `add_retention_policy`) → §2.2 |
| Base — pool épuisé *(PostgreSQL)* | log `pool de connexions PostgreSQL saturé`, ou `/readyz` en `503` | toute occurrence | augmenter le `max_size` du pool ou `max_connections` → §2.2 |
| Bus | `THOT_BUS=nats` : `/readyz` `503`, logs bus, débit nul | indisponibilité > 2 minutes | bascule temporaire → **runbook 4** |

### 8.4 Journaux

Deux variables pilotent les logs : `THOT_LOG_FORMAT` (`json` par défaut, ou `console`) et `THOT_LOG_LEVEL` (`INFO` par défaut, `DEBUG`…`CRITICAL`).

```bash
# production : JSON, exploitable par un collecteur de logs
THOT_LOG_FORMAT=json THOT_LOG_LEVEL=INFO

# incident : passer en DEBUG temporairement (volume important)
THOT_LOG_FORMAT=json THOT_LOG_LEVEL=DEBUG
```

```powershell
$env:THOT_LOG_FORMAT = "json"
$env:THOT_LOG_LEVEL  = "DEBUG"
Get-Content .\logs\thotsecure.log -Tail 200 -Wait
```

Exemple de ligne JSON (illustratif — la forme exacte des champs est à confirmer sur votre instance) :

```json
{"ts":"2026-09-13T08:12:44.512Z","level":"INFO","logger":"thotsecure.actions","msg":"action executed","tenant_id":"acme","action_id":"a91b…","playbook":"block-source-ip","status":"succeeded","dry_run":false,"audit_seq":1042}
```

Envoyez ces logs vers le même SIEM que `GET /api/v1/audit/export?format=jsonl|cef` (§4.7) et **n'y écrivez jamais** de clé API, de pepper ni de secret.

### 8.5 Tableau de bord métier : `GET /api/v1/stats/overview`

Cette route (§4.8) est le tableau de bord de direction, à suivre quotidiennement :

| Indicateur | Ce qu'il révèle |
|---|---|
| Compteurs d'événements 24 h / 7 j | santé de la collecte et de l'ingestion |
| Findings par sévérité | charge de travail de l'équipe |
| **MTTA / MTTR** | réactivité et efficacité de la réponse |
| Top règles | quelles détections produisent le plus (et donc, souvent, le bruit) |
| Actions réussies / rollback | efficacité des contre-mesures et taux de retour arrière |
| **Mode d'autonomie** | doit correspondre à ce que vous croyez avoir configuré — à contrôler à chaque changement |

---

## 9. Alertes recommandées (6)

Ces six alertes couvrent les signaux réellement documentés par le contrat. **Les noms et les seuils ci-dessous sont des propositions d'exploitation**, pas des alertes livrées.

| Nom recommandé | Signal | Seuil proposé | Gravité | Première action | Runbook |
|---|---|---|---|---|---|
| `ThotSecureDown` | `/healthz` ne répond pas | 2 échecs sur 3 min | critique | redémarrer, vérifier `/readyz` | [runbook.md](runbook.md) — incident 1 |
| `ThotSecureNotReady` | `/readyz` = `503` (DB, bus ou règles) | 2 min consécutives | critique | identifier le pilier en échec (DB → incident 5, bus → incident 4) | [runbook.md](runbook.md) — incidents 1, 4, 5 |
| `ThotSecureAuditChainBroken` | `GET /api/v1/audit/verify` → `valid:false` | toute occurrence | critique | isoler la base, préserver les preuves, escalader le RSSI | [runbook.md](runbook.md) — incident 3 |
| `ThotSecureBusUnavailable` | bus `nats` indisponible (`/readyz` 503 + logs bus) | 2 min sans connexion | critique | bascule temporaire `memory`/`sqlite` en assumant la perte de distribution | [runbook.md](runbook.md) — incident 4 |
| `ThotSecureAutoActionSpike` | pic d'actions `auto` (`succeeded`, plafond horaire atteint) | > 2× la médiane horaire 7 j | haute | **couper l'automatisation** puis rollback | [runbook.md](runbook.md) — incident 2 |
| `ThotSecureStorageCapacity` | disque/WAL saturés ou purge de rétention en échec | < 20 % libre, ou 2 purges manquées | haute | purger/archiver, vérifier `PRAGMA integrity_check` | [runbook.md](runbook.md) — incident 5 |

!!! note "Noms et seuils définitifs : lot déploiement"
    Les identifiants ci-dessus (`ThotSecureDown`, `ThotSecureNotReady`, …) sont des **propositions d'exploitation**, pas des alertes livrées ni des noms officiels. Les noms d'alertes définitifs, les expressions exactes (qui dépendent des noms de métriques relevés sur `/metrics`) et les seuils sont fixés par le **lot déploiement** dans `deploy/README.md` et dans ses artefacts Prometheus/Helm. Cette section propose une couverture minimale ; elle doit être **alignée** avec `deploy/README.md` avant mise en production — n'activez pas deux jeux d'alertes divergents sur la même instance.

Pour chaque alerte, la conduite à tenir est décrite dans [`runbook.md`](runbook.md) (section indiquée dans le tableau). Les tableaux de bord et l'agrégation de logs relèvent également du lot déploiement.

---

## 10. Checklist de mise en production

- [ ] `THOT_ENV=prod` (durcit les défauts, masque les erreurs)
- [ ] `THOT_DRY_RUN=true` **au départ** — levée explicite, tenant par tenant, après validation
- [ ] `THOT_AUTONOMY=supervised` (jamais `auto` dès le premier jour)
- [ ] `THOT_BOOTSTRAP_API_KEY` remplacée (le défaut `ao_dev_local_change_me` est public)
- [ ] `THOT_SECRET_KEY` définie (générée) **et** sauvegardée dans un coffre séparé de la base
- [ ] TLS actif : `THOT_TLS_ENABLED=true` ou terminaison par un reverse-proxy
- [ ] `/metrics` restreint au réseau interne
- [ ] `THOT_RETENTION_DAYS` fixée selon la volumétrie et les obligations de conservation, purge surveillée
- [ ] *(PostgreSQL)* rôle dédié non `superuser`, `sslmode=require` (posé par défaut en `THOT_ENV=prod`), extension `timescaledb` créée **avant** toute restauration
- [ ] *(PostgreSQL)* `max_size` du pool ≤ `max_connections` − marge, et politique de rétention TimescaleDB alignée sur `THOT_RETENTION_DAYS`
- [ ] *(PostgreSQL)* sauvegarde `pg_dump`/`pg_basebackup` **testée** : restauration dans une base neuve, `/readyz` → `200`, chaîne d'audit `valid: true`
- [ ] `config/targets.yaml` relu : périmètre exact, cibles protégées cohérentes avec l'infrastructure propre
- [ ] Sauvegarde chiffrée **testée** (restauration + `thotsecure doctor` + `thotsecure audit verify`)
- [ ] `thotsecure audit verify` retourne une chaîne valide (code `0`)
- [ ] Alertes de la §9 branchées et testées (au moins une alerte déclenchée à blanc)
- [ ] Runbook connu de l'astreinte, avec accès à `THOT_SECRET_KEY`, à la sauvegarde et au coffre
- [ ] Procédure « couper l'automatisation » répétée au moins une fois ([`runbook.md`](runbook.md))

Pour la conformité et les preuves attendues, voir [`../compliance/soc2-iso27001.md`](../compliance/soc2-iso27001.md) et [`../compliance/rgpd.md`](../compliance/rgpd.md).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
