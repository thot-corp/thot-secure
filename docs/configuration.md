# Configuration

*Référence des variables d'environnement `THOT_*`, du périmètre autorisé (`config/targets.yaml`) et des règles de précédence — avec, pour chaque réglage, son impact sur la sûreté.*

Thot Secure se configure presque entièrement par variables d'environnement. C'est délibéré : une
configuration lisible dans un fichier d'unité systemd, un `compose.yaml` ou un manifeste
Kubernetes se relit en revue, se versionne et se compare entre environnements.

!!! danger "Les deux réglages qui changent la nature du produit"

    * **`THOT_DRY_RUN=false`** : Thot Secure cesse de simuler. Les connecteurs configurés
      peuvent alors modifier votre infrastructure (blocage d'IP, révocation de session,
      isolation d'hôte…). Le [garde-fou](decision/policies.md#6-garde-fous-non-contournables)
      « dry-run global prioritaire » n'a plus rien à protéger.
    * **`THOT_AUTONOMY=auto`** : les politiques marquées `decision: auto` s'exécutent
      **sans approbation humaine**. Combiné au dry-run levé, c'est une exécution automatique
      sur votre production.

    Ces deux réglages ne se posent pas « parce que ça marche mieux ». Ils se posent après
    avoir observé le comportement des règles sur des données réelles, avec des cibles
    protégées déclarées, un plafond horaire volontairement bas, et une personne capable
    d'annuler une action dans l'heure.

## Comment Thot Secure lit sa configuration

| Source | Statut |
|---|---|
| Valeurs par défaut sûres (voir tableau ci-dessous) | Toujours appliquées en premier |
| Variables d'environnement `THOT_*` du processus | Surchargent les défauts |
| Fichier `.env` | **Convention de déploiement**, pas un mécanisme décrit par le contrat |
| Surcharge par tenant (`PATCH /api/v1/tenants/{id}`, `autonomy_allowlist`) | S'applique au tenant concerné : `mode`, `dry_run` |
| Politique de décision (`then.dry_run`, `then.decision`) | Ne peut **jamais** contourner un garde-fou |

!!! note "Le fichier `.env` n'est pas lu « magiquement »"

    Le contrat d'interface définit les variables d'environnement, mais **ne décrit pas de
    chargement automatique d'un fichier `.env` par l'application**. Selon votre mode de
    déploiement, ce fichier est consommé par Docker Compose (`env_file:`), par systemd
    (`EnvironmentFile=`), par votre shell (`set -a; . ./.env; set +a`), ou pas du tout.
    Les exemples ci-dessous supposent donc que **vous** exportez ces variables. Le
    chargement éventuel par l'application doit être confirmé par lecture de
    `src/thotsecure/core/` — ne comptez pas dessus avant de l'avoir vérifié.

## Tableau exhaustif des variables `THOT_*`

Les vingt variables du contrat d'interface (section 9). La colonne « impact sûreté » indique
ce qu'une erreur de réglage peut coûter.

| Variable | Défaut | Type | Rôle | Impact sûreté |
|---|---|---|---|---|
| `THOT_ENV` | `dev` | `dev` \| `prod` | Durcit les valeurs par défaut et **masque les erreurs détaillées** en `prod` | **Élevé** — en `dev`, les messages d'erreur peuvent révéler des détails internes ; `prod` réduit cette fuite |
| `THOT_HOST` | `0.0.0.0` | adresse IP | Interface d'écoute | **Élevé** — `0.0.0.0` expose le service sur **toutes** les interfaces. Derrière un reverse-proxy, préférez `127.0.0.1` ou une interface interne |
| `THOT_PORT` | `8080` | entier | Port d'écoute | Faible — purement fonctionnel, à aligner avec le pare-feu et le proxy |
| `THOT_SECRET_KEY` | *généré, avec avertissement* | chaîne secrète | **Pepper des clés API** et matériel de signature | **Critique** — s'il est généré au démarrage, les clés API deviennent invalides à chaque redémarrage ; s'il fuite, un attaquant peut tenter de retrouver des clés API hachées. **À définir explicitement en production, à stocker dans un coffre, à sauvegarder séparément de la base** |
| `THOT_BOOTSTRAP_API_KEY` | `ao_dev_local_change_me` | chaîne secrète | Clé administrateur initiale | **Critique** — une valeur publique par défaut. À changer **avant** toute exposition réseau, sous peine de compromission immédiate |
| `THOT_DB_URL` | `sqlite:///./data/thotsecure.db` | URL | Base de données (`sqlite://` pour le MVP ; PostgreSQL/TimescaleDB documenté) | **Élevé** — la base contient les événements, les findings et le journal d'audit : elle doit être sur un disque chiffré, avec des droits restreints |
| `THOT_RULES_DIR` | `./rules` | chemin | Bibliothèque de règles de détection | **Moyen** — un dossier accessible en écriture par un tiers permet d'injecter des règles (voir [modèle de menaces](architecture/threat-model.md)) |
| `THOT_POLICIES_DIR` | `./policies` | chemin | Politiques de décision | **Élevé** — c'est ici que se décide « automatique ou pas » : écriture = pouvoir d'exécution |
| `THOT_PLAYBOOKS_DIR` | `./playbooks` | chemin | Playbooks (action + rollback) | **Élevé** — même raison : un playbook modifié change ce que fait une action |
| `THOT_BUS` | `memory` | `memory` \| `sqlite` \| `nats` | Bus d'événements | **Moyen** — `memory` ne persiste rien et ne distribue rien (perte au redémarrage) ; `nats` ajoute une brique à sécuriser (authentification, TLS) |
| `THOT_NATS_URL` | `nats://127.0.0.1:4222` | URL | Bus distribué | **Moyen** — sans TLS ni authentification, le trafic du bus est lisible et injectable sur le réseau |
| `THOT_AUTONOMY` | `supervised` | `manual` \| `supervised` \| `auto` | Mode d'autonomie **global** par défaut (surchargeable par tenant) | **Critique** — `auto` autorise l'exécution sans approbation humaine |
| `THOT_DRY_RUN` | `true` | booléen | **Sécurité** : aucune action réelle si `true` | **Critique** — c'est le dernier filet. À `false`, les contre-mesures sont appliquées pour de vrai |
| `THOT_RETENTION_DAYS` | `30` | entier (jours) | Purge des événements | **Moyen** — conservation trop longue : risque RGPD et volume disque ; trop courte : perte de capacité d'investigation. Voir [RGPD](compliance/rgpd.md) |
| `THOT_OPA_BIN` | *(vide)* | chemin | Binaire OPA pour le mode Rego | **Moyen** — active l'évaluation de politiques Rego ; si le binaire est absent, retour au YAML |
| `THOT_LOG_LEVEL` | `INFO` | `DEBUG`…`CRITICAL` | Verbosité des journaux | **Moyen** — `DEBUG` peut écrire dans les journaux des données sensibles (payloads, identifiants). À réserver au diagnostic |
| `THOT_LOG_FORMAT` | `json` | `json` \| `console` | Format des journaux | Faible — `json` est recommandé pour l'ingestion par un SIEM ; `console` est plus lisible à la main |
| `THOT_TLS_ENABLED` | `false` | booléen | HTTPS direct (sinon délégation à un reverse-proxy) | **Élevé** — sans TLS, la clé API circule en clair. Le reverse-proxy est la voie recommandée en production |
| `THOT_RATE_LIMIT_PER_MIN` | `600` | entier (requêtes/minute) | Garde-fou anti-abus sur l'ingestion | **Moyen** — trop haut : l'API d'ingestion devient un levier de déni de service et de saturation disque ; trop bas : rejets légitimes (`429 rate_limited`) |
| `THOT_TARGETS_FILE` | `./config/targets.yaml` | chemin | Cibles déclarées par tenant (**périmètre autorisé**) | **Critique** — c'est la définition du périmètre. Un périmètre trop large élargit ce qu'une action automatique peut toucher ; voir la section dédiée ci-dessous |

!!! warning "Une variable oubliée n'est pas anodine"

    Le défaut `THOT_BOOTSTRAP_API_KEY=ao_dev_local_change_me` et le défaut
    `THOT_HOST=0.0.0.0` se cumulent dangereusement : un service exposé avec la clé
    d'amorçage publique est une compromission, pas un risque. **La première action après
    l'installation est de changer cette clé.**

## Ordre de précédence

Du plus faible au plus fort :

```text
1. Défauts sûrs du produit
      └─ dry_run=true · autonomy=supervised · env=dev · bus=memory
2. Variables d'environnement THOT_* du processus
      └─ (alimentées selon votre déploiement par .env, systemd, compose, Kubernetes…)
3. Surcharge par tenant  (PATCH /api/v1/tenants/{id} → mode, dry_run ; autonomy_allowlist)
      └─ le grain tenant gagne sur le global POUR CE TENANT
4. Politique de décision (then.decision, then.dry_run, then.playbook, then.params)
      └─ choisit l'action… mais ne contourne JAMAIS un garde-fou d'exécution
5. Garde-fous non contournables du moteur de décision
      └─ plafond horaire · cooldown · cibles protégées · dry-run global · hors périmètre
         → toujours gagnants, quel que soit l'empilement précédent
```

Deux conséquences pratiques :

* **Le niveau 3 explique les surprises.** Un tenant basculé en `auto` continue de l'être même
  si vous remettez `THOT_AUTONOMY=supervised` — le réglage global ne sert que de défaut.
  Pour reprendre la main, il faut agir **par tenant** (voir
  [Couper l'automatisation en urgence](#couper-lautomatisation-en-urgence)).
* **Le niveau 5 est le seul endroit sans échappatoire.** Aucune politique, aussi
  soigneusement écrite soit-elle, ne peut exécuter une action sur une cible protégée, ni
  dépasser le plafond horaire, ni ignorer le dry-run global. Détail :
  [les 5 garde-fous](decision/policies.md#6-garde-fous-non-contournables).

!!! note "Articulation exacte global / tenant pour le dry-run"

    Le contrat garantit qu'un **dry-run global prime sur toute politique**. La combinaison
    fine entre `THOT_DRY_RUN` (global) et `Tenant.dry_run` (par tenant) — c'est-à-dire
    « le plus restrictif gagne » ou « le tenant écrase le global » — n'est pas explicitée
    au-delà de cette garantie. **Traitez-les comme « si l'un dit `true`, rien n'est exécuté »**
    et vérifiez le comportement réel dans `src/thotsecure/decision/` avant de vous appuyer
    dessus en production.

## Périmètre autorisé (`config/targets.yaml`)

C'est le fichier le plus important de votre configuration : il **déclare ce qu'Thot Secure a le
droit de considérer comme étant à vous**. Deux fonctions en dépendent :

* `thotsecure probe --tenant acme --target https://shop.acme.fr` n'audite **que** des cibles
  déclarées et possédées par le tenant (opt-in explicite) ;
* toute action visant une cible **hors** de ce périmètre déclaré bascule automatiquement en
  `require_approval` (garde-fou 5).

```yaml
# config/targets.yaml — périmètre autorisé, par tenant.
# Règle d'or : n'y figure que ce que vous possédez et exploitez réellement.
tenants:
  acme:
    # Domaines et URL appartenant au tenant (audit de SA propre surface, jamais d'un tiers).
    web:
      - https://shop.acme.fr
      - https://www.acme.fr
    # Plages réseau que le tenant exploite (blocage, limitation de débit, isolation).
    networks:
      - 203.0.113.0/24
      - 198.51.100.0/24
    # Cibles protégées : l'infrastructure propre ne doit JAMAIS être modifiée par une action.
    # Le contrat les porte aussi au niveau du tenant (autonomy_allowlist).
    protected:
      - 10.0.0.0/8
      - 192.168.0.0/16
      - https://vpn.acme.fr
  demo:
    web:
      - http://127.0.0.1:8080
    networks:
      - 127.0.0.0/8
    protected: []
```

!!! warning "Le schéma exact de `config/targets.yaml` doit être confirmé par le code"

    Le contrat d'interface définit la **finalité** de ce fichier et la variable qui le
    pointe (`THOT_TARGETS_FILE`), mais **pas son schéma clé par clé**. La forme
    ci-dessus est celle attendue par la documentation ; vérifiez-la contre le fichier
    livré dans `config/` et le code de chargement **avant** de vous appuyer dessus. Ne
    recopiez pas cet exemple en production sans l'avoir validé : un périmètre mal lu peut
    produire l'effet inverse de celui recherché.

!!! danger "Ne jamais élargir un périmètre « pour que ça marche »"

    Mettre `0.0.0.0/0` ou un domaine d'hébergeur entier dans le périmètre, c'est donner à
    une automatisation le droit d'agir sur des systèmes qui ne sont pas les vôtres —
    exactement le scénario que le [modèle de menaces](architecture/threat-model.md) classe
    comme le plus grave. Un blocage d'IP large peut couper votre propre accès, vos clients,
    ou un service partagé : c'est un déni de service que vous vous infligez.

## Cibles protégées et `autonomy_allowlist`

Le tenant porte une liste `autonomy_allowlist` (créée avec
`POST /api/v1/tenants`, modifiable via `PATCH /api/v1/tenants/{id}`) :

| Élément | Sémantique contractuelle |
|---|---|
| `autonomy_allowlist` | Contient les **cibles protégées** — l'infrastructure propre. Le moteur de décision **n'exécute jamais** d'action sur une cible qui s'y trouve (garde-fou 3). Ces cibles ne sont pas modifiables par une politique. |
| `mode` | `manual`, `supervised` ou `auto` — le niveau d'autonomie **de ce tenant** |
| `dry_run` | Surcharge le dry-run global pour ce tenant |

!!! warning "Le nom `autonomy_allowlist` est trompeur — retenez la sémantique du contrat"

    Malgré son nom, cette liste n'autorise pas l'automatisation : elle désigne les cibles
    **protégées**, sur lesquelles aucune action n'est jamais appliquée. C'est le garde-fou de
    l'« infra propre ». Une lecture inverse (« c'est la liste où j'ai le droit d'agir »)
    conduit exactement au comportement dangereux que le contrat interdit. En cas de doute sur
    le contenu, préférez une liste large : trop de protection ne casse rien.

```bash
# Ajouter une cible protégée au tenant acme
curl -s -X PATCH http://127.0.0.1:8080/api/v1/tenants/acme \
  -H "X-API-Key: ao_..." \
  -H "Content-Type: application/json" \
  -d '{"autonomy_allowlist":["10.0.0.0/8","192.168.0.0/16"]}'
```

## Surcharge par tenant

| Ce que vous voulez | Où agir | Effet |
|---|---|---|
| Un tenant plus prudent que le global | `PATCH /api/v1/tenants/{id}` → `{"mode":"manual","dry_run":true}` | Ce tenant n'exécute rien sans approbation explicite |
| Un tenant pilote en autonomie | `PATCH /api/v1/tenants/{id}` → `{"mode":"auto"}` + dry-run levé | Les politiques `auto` s'exécutent pour ce tenant (sous garde-fous) |
| Restreindre ce qui est protégé | `autonomy_allowlist` | Cibles jamais modifiées |
| Restreindre ce qui est **dans le périmètre** | `config/targets.yaml` | Définit ce qui est « à vous » ; hors périmètre ⇒ approbation |

Une clé API est liée à **un** tenant : `POST /api/v1/events` **force** le `tenant_id` depuis
la clé, jamais depuis le corps de la requête. Le cloisonnement ne dépend donc pas de la
bonne volonté de l'appelant.

## Exemple de fichier `.env`

```bash
# ---------------------------------------------------------------------------
# Thot Secure — exemple de configuration.
# Rappel : ce fichier n'est chargé que par votre outil de déploiement
# (compose `env_file:`, systemd `EnvironmentFile=`, ou votre shell).
# Droits attendus : 0600, propriétaire = utilisateur du service. Jamais dans Git.
# ---------------------------------------------------------------------------

# --- Environnement ----------------------------------------------------------
THOT_ENV=prod
THOT_HOST=127.0.0.1          # derrière un reverse-proxy
THOT_PORT=8080

# --- Secrets (à sortir d'ici et à mettre dans un coffre si possible) --------
THOT_SECRET_KEY=remplacez-par-une-valeur-aleatoire-de-32-octets-minimum
THOT_BOOTSTRAP_API_KEY=remplacez-egalement-cette-valeur

# --- Données ---------------------------------------------------------------
THOT_DB_URL=sqlite:///./data/thotsecure.db
THOT_RETENTION_DAYS=30

# --- Détection et décision --------------------------------------------------
THOT_RULES_DIR=./rules
THOT_POLICIES_DIR=./policies
THOT_PLAYBOOKS_DIR=./playbooks
THOT_TARGETS_FILE=./config/targets.yaml

# --- Sûreté : on ne lève ces deux réglages qu'en connaissance de cause ------
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised
# THOT_OPA_BIN=/usr/local/bin/opa

# --- Bus --------------------------------------------------------------------
THOT_BUS=sqlite
# THOT_NATS_URL=nats://127.0.0.1:4222

# --- Exposition et journalisation -------------------------------------------
THOT_TLS_ENABLED=false        # TLS terminé par le reverse-proxy
THOT_RATE_LIMIT_PER_MIN=600
THOT_LOG_LEVEL=INFO
THOT_LOG_FORMAT=json
```

!!! tip "Vérifier l'absence de secret dans le dépôt"

    Un `.env` committé est la fuite la plus banale et la plus coûteuse. Avant de pousser :
    vérifiez que `.env` est bien ignoré par Git, et préférez les variables injectées par
    votre orchestrateur ou un coffre (Vault, secrets Kubernetes, SSM).

## Vérifier sa configuration

| Objectif | Commande / route |
|---|---|
| Diagnostic global (config, base, bus, règles) | `thotsecure doctor` |
| Version, commit, licence, **mode d'autonomie global** | `GET /version` |
| Tenant, rôle, capacités, **mode d'autonomie effectif** | `GET /api/v1/auth/whoami` |
| Préparation réelle (base + bus + règles) | `GET /readyz` (`200` ou `503`) |
| Mode d'autonomie et activité (MTTA/MTTR, actions, rollback) | `GET /api/v1/stats/overview` |
| Politiques chargées et ordre de priorité | `GET /api/v1/policies` |
| Règles chargées, erreurs de chargement | `GET /api/v1/rules` · `POST /api/v1/rules/reload` |

## Couper l'automatisation en urgence

À exécuter **sans attendre** dès qu'une automatisation produit un effet non désiré, ou dès
que vous doutez de l'état réel de la configuration.

1. **Passer tous les tenants en `manual` + `dry_run=true`** — c'est la voie fiable, car le
   réglage global ne suffit pas à reprendre la main sur un tenant basculé en `auto` :

    ```bash
    curl -s -X PATCH http://127.0.0.1:8080/api/v1/tenants/mon-tenant \
      -H "X-API-Key: ao_..." -H "Content-Type: application/json" \
      -d '{"mode":"manual","dry_run":true}'
    ```

2. **Poser aussi les variables globales** (pour les tenants qui seraient créés ensuite) et
   redémarrer le service :

    === "bash"

        ```bash
        export THOT_AUTONOMY=manual
        export THOT_DRY_RUN=true
        # puis redémarrer le service
        ```

    === "PowerShell"

        ```powershell
        $env:THOT_AUTONOMY = "manual"
        $env:THOT_DRY_RUN = "true"
        Restart-Service Thot Secure
        ```

3. **Annuler les actions indésirables**, puis vérifier l'audit :

    ```bash
    thotsecure actions list
    thotsecure actions rollback <action_id>
    thotsecure audit verify
    ```

!!! note "Ce que cela ne coupe pas"

    La **collecte** et la **détection** continuent : c'est voulu. On coupe la capacité
    d'agir, pas la capacité de voir — sinon on perd précisément l'information nécessaire
    au diagnostic. La procédure complète, avec les incidents associés, est dans le
    [Runbook d'incident](operations/runbook.md#0-premier-reflexe-couper-lautomatisation).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
