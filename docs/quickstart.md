# Démarrage rapide : du zéro à un finding mitigé

*Objectif : installer Thot Secure, générer un jeu de démonstration, produire un finding, planifier une action, l'exécuter, la **annuler** (`rollback`) et vérifier le journal d'audit — en cinq minutes, sans écrire une seule règle.*

!!! note "Ce que vous obtiendrez à la fin"

    Un finding réel produit par une règle livrée, une action **planifiée puis exécutée puis
    annulée**, et un journal d'audit chaîné vérifié. Le tout **sans aucun effet de bord sur
    un système réel** : tant que le dry-run est actif, aucune contre-mesure n'est appliquée
    pour de vrai.

    Le parcours ci-dessous suit exactement l'ordre des commandes de la CLI `thotsecure`
    (référence complète : [Référence CLI](cli.md)). Si vous préférez les conteneurs,
    sautez directement à la section **[Variante Docker Compose](#variante-docker-compose)**.

## Prérequis

| Élément | Minimum | Remarque |
|---|---|---|
| Python | **3.11+** | `python --version` |
| `git` | n'importe quelle version récente | Pour cloner le dépôt (ou téléchargez une archive signée, voir [Installation](installation.md)) |
| Réseau | requise **une fois** | Pour récupérer les dépendances Python (FastAPI, uvicorn, Jinja2, pydantic, PyYAML). Ensuite, Thot Secure fonctionne hors-ligne. |
| Port | **8080** libre | Modifiable via `THOT_PORT` |

Thot Secure **n'attaque rien**. La démonstration ci-dessous ne contacte aucun système externe :
elle travaille sur des données synthétiques locales.

## Étape 1 — Récupérer le code

=== "bash"

    ```bash
    git clone https://github.com/thotsecure/thot-secure.git
    cd thot-secure
    ```

=== "PowerShell"

    ```powershell
    git clone https://github.com/thotsecure/thot-secure.git
    Set-Location thotsecure
    ```

## Étape 2 — Créer l'environnement Python et installer Thot Secure

=== "bash"

    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -e .
    ```

=== "PowerShell"

    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    pip install -e .
    ```

`pip install -e .` installe le paquet en mode éditable et expose la commande `thotsecure`.
Vérifiez qu'elle répond :

```bash
thotsecure --help
```

!!! tip "PowerShell refuse d'activer l'environnement virtuel ?"

    Si vous voyez une erreur de stratégie d'exécution, autorisez les scripts pour la
    session courante uniquement :

    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    ```

## Étape 3 — Initialiser la base

```bash
thotsecure init-db
```

La base SQLite est créée à l'emplacement défini par `THOT_DB_URL`
(défaut : `sqlite:///./data/thotsecure.db`). Toutes les tables et index sont créés au premier
appel ; l'opération est rejouable sans risque.

## Étape 4 — Créer un tenant

Un **tenant** est une frontière d'isolation : tout objet lui appartient (`tenant_id`).
Pour une démonstration, créez un tenant dédié.

```bash
thotsecure tenant create --id demo --name "Démonstration Thot Secure" --mode supervised
thotsecure tenant list
```

| Mode | Comportement |
|---|---|
| `manual` | Aucune action automatique : tout passe par une approbation humaine. |
| `supervised` | Les politiques décident ; les cas sensibles demandent une approbation. **C'est le défaut.** |
| `auto` | Les politiques marquées `decision: auto` s'exécutent sans approbation (sous les garde-fous). |

!!! warning "Restez en `supervised` pendant la découverte"

    Le mode `auto` n'a de sens qu'après avoir observé le comportement de vos règles sur
    vos vraies données — et il ne doit être activé qu'avec un dry-run levé en connaissance
    de cause. Voir [Configuration](configuration.md#couper-lautomatisation-en-urgence).

## Étape 5 — Créer une clé API

L'API REST s'authentifie par en-tête `X-API-Key`. La clé en clair est **affichée une seule
fois** : elle est stockée hachée (scrypt) et ne peut jamais être réaffichée.

```bash
thotsecure key create --tenant demo --role responder --label "poste-local"
```

Conservez la valeur `ao_…` retournée. Rôles disponibles : `viewer`, `analyst`, `responder`,
`admin` (voir [Utiliser l'API REST](api/usage.md#roles-et-capacites)).

!!! tip "Différence entre clé de démarrage et clé de travail"

    `THOT_BOOTSTRAP_API_KEY` (défaut : `ao_dev_local_change_me`) est une clé
    d'amorçage destinée au tout premier accès. **Changez-la** et utilisez des clés
    nominatives par usage, avec le rôle minimal nécessaire.

## Étape 6 — Générer le jeu de démonstration

```bash
thotsecure demo --tenant demo
```

Cette commande produit des événements, des findings issus des règles livrées, ainsi que des
actions — le tout dans le tenant indiqué, sans toucher à un système réel.

## Étape 7 — Démarrer le service

```bash
thotsecure serve --host 127.0.0.1 --port 8080
```

| Point d'entrée | Adresse |
|---|---|
| Console embarquée (flux live, findings, actions, audit) | `http://127.0.0.1:8080/` |
| Page de soutien | `http://127.0.0.1:8080/ui/support` |
| Santé | `http://127.0.0.1:8080/healthz` |
| Préparation (DB + bus + règles) | `http://127.0.0.1:8080/readyz` |
| Métriques Prometheus | `http://127.0.0.1:8080/metrics` |
| Schéma OpenAPI 3.1 | `http://127.0.0.1:8080/openapi.json` |

Laissez ce terminal ouvert, puis travaillez dans un **second terminal** (en réactivant
l'environnement virtuel si nécessaire).

## Étape 8 — Lire les findings

```bash
thotsecure findings list --tenant demo
thotsecure findings list --tenant demo --severity high --min-risk 70
```

Repérez un `finding_id`. Pour l'examiner en détail :

```bash
thotsecure findings show <finding_id>
```

Le finding contient la règle qui l'a produit (`rule_id`), un score de risque (`risk_score`),
une confiance, des tags (dont le cas échéant des références MITRE ATT&CK) et des échantillons
de preuve. Le format exact est décrit dans le [contrat d'interface](architecture/api-contract.md#32-finding).

## Étape 9 — Planifier une action

Planifier **n'a aucun effet de bord** : l'action est créée à l'état `planned`.

```bash
thotsecure actions plan --finding <finding_id> --playbook block-source-ip
```

```bash
thotsecure actions list
```

Le playbook `block-source-ip` est **réversible** : il dispose d'un `unblock-source-ip`
comme contrepartie. La liste complète est dans [Playbooks et connecteurs](actions/playbooks.md).

!!! tip "Forcer explicitement le dry-run"

    Ajoutez `THOT_DRY_RUN=true` à l'environnement pour garantir, quel que soit l'état de
    la configuration, qu'aucune contre-mesure réelle ne sera appliquée :

    === "bash"

        ```bash
        export THOT_DRY_RUN=true
        thotsecure actions plan --finding <finding_id> --playbook block-source-ip
        ```

    === "PowerShell"

        ```powershell
        $env:THOT_DRY_RUN = "true"
        thotsecure actions plan --finding <finding_id> --playbook block-source-ip
        ```

## Étape 10 — Approuver, exécuter, puis annuler

```bash
# 1. Approbation humaine (capacité approve:actions)
thotsecure actions approve <action_id>

# 2. Exécution (capacité execute:actions)
thotsecure actions execute <action_id>

# 3. Annulation — la contre-mesure est retirée
thotsecure actions rollback <action_id>
```

Cycle de vie complet d'une action (les neuf états) :
`planned → pending_approval → approved → executing → succeeded | failed → rolled_back`,
plus `rejected` et `expired`.

!!! example "Ce que vous devez observer"

    * Sur une action **simulée**, le résultat indique `simulated: true` et un
      `rollback_token` est retourné : c'est le comportement normal quand aucun connecteur
      n'est configuré.
    * Sur une action **réelle**, vous verrez la transition jusqu'à `succeeded`, puis
      `rolled_back` après l'annulation.
    * Un second `rollback` sur la même action est refusé (`409`) : l'opération est
      idempotente et ne peut pas « défaire deux fois ».

## Étape 11 — Vérifier le journal d'audit

```bash
thotsecure audit verify
thotsecure audit tail
```

`audit verify` recalcule la chaîne de hash de bout en bout. Sortie attendue : `valid: true`.
Un échec renvoie le **code de sortie `3`** (vérification négative) — ce code existe
précisément pour qu'un pipeline CI puisse alerter sans confondre une erreur technique avec
une rupture d'intégrité. Voir [Journal d'audit chaîné](architecture/threat-model.md#menaces-liees-a-laudit).

## Étape 12 — Diagnostic

```bash
thotsecure doctor
```

`thotsecure doctor` vérifie la configuration, la base, le bus, la bibliothèque de règles et
l'état général de l'installation. **C'est le premier réflexe en cas de doute**, avant
d'ouvrir le runbook.

---

## Variante Docker Compose

Si vous ne voulez rien installer localement, le profil `demo` fournit une pile complète
(API + console embarquée + jeu de démonstration).

```bash
docker compose --profile demo up
```

Puis, depuis un autre terminal :

```bash
docker compose exec thotsecure thotsecure findings list --tenant demo
docker compose exec thotsecure thotsecure audit verify
```

| Point d'entrée | Adresse |
|---|---|
| Console embarquée | `http://127.0.0.1:8080/` |
| Santé / préparation | `http://127.0.0.1:8080/healthz` · `/readyz` |

!!! note "Les manifestes appartiennent au lot déploiement"

    Le contenu exact de `deploy/` (`Dockerfile`, `compose.yaml`, chart Helm, Ansible,
    Terraform) est décrit dans `deploy/README.md`. Les détails de dimensionnement, de
    sauvegarde et de montée de version sont dans [Déploiement](operations/deployment.md).

---

## Vérifier que le dry-run est bien actif

**À faire avant toute autre chose.** Le dry-run est la garantie qu'Thot Secure observe sans agir.

### 1. Vérifier la valeur effective de la variable

=== "bash"

    ```bash
    echo "${THOT_DRY_RUN:-<non définie>}"
    ```

=== "PowerShell"

    ```powershell
    if ($env:THOT_DRY_RUN) { $env:THOT_DRY_RUN } else { "<non définie>" }
    ```

`<non définie>` signifie que la valeur par défaut s'applique — et le défaut est **`true`**.

### 2. Vérifier ce que le service annonce

```bash
curl -s http://127.0.0.1:8080/version
curl -s -H "X-API-Key: ao_..." http://127.0.0.1:8080/api/v1/auth/whoami
```

`/version` expose la version, le commit, la licence et le **mode d'autonomie global** ;
`whoami` renvoie votre tenant, votre rôle, vos capacités et le mode d'autonomie effectif.
`GET /api/v1/stats/overview` affiche également le mode d'autonomie courant — utile pour
vérifier qu'un tenant n'a pas été basculé en `auto` à votre insu.

### 3. Vérifier sur une action réelle

```bash
thotsecure findings list --tenant demo --json
thotsecure actions plan --finding <finding_id> --playbook block-source-ip --json
```

Dans le JSON retourné, l'action doit porter **`"dry_run": true`**. C'est la preuve la plus
directe : l'objet d'action lui-même indique qu'il simulera.

### 4. Le réflexe d'urgence

Si vous constatez que le dry-run n'est **pas** actif et que vous n'êtes pas certain du
comportement attendu, coupez l'automatisation immédiatement :

```bash
thotsecure tenant list --json
# puis, pour chaque tenant, via l'API :
curl -s -X PATCH http://127.0.0.1:8080/api/v1/tenants/demo \
  -H "X-API-Key: ao_..." -H "Content-Type: application/json" \
  -d '{"mode":"manual","dry_run":true}'
```

La procédure complète (« couper l'automatisation ») est le **premier réflexe** du
[Runbook d'incident](operations/runbook.md#procedure-durgence-couper-lautomatisation).

!!! danger "Ne levez le dry-run qu'avec une raison écrite"

    Passer `THOT_DRY_RUN=false` ou un tenant en `auto` donne à Thot Secure le pouvoir de
    modifier votre infrastructure. Faites-le progressivement (un tenant, un playbook, une
    cible à la fois), avec les [cinq garde-fous](decision/policies.md#les-5-garde-fous-non-contournables)
    en place, des cibles protégées déclarées, et une personne capable d'annuler l'action.

---

## Et ensuite ?

| Sujet | Page |
|---|---|
| Écrire vos propres règles de détection | [Écrire une règle](detection/rules.md) |
| Décider automatiquement ou demander une approbation | [Politiques](decision/policies.md) |
| Brancher un vrai connecteur (WAF, EDR, IAM…) | [Playbooks et connecteurs](actions/playbooks.md) |
| Déclarer votre périmètre autorisé | [Configuration](configuration.md#perimetre-autorise-configtargetsyaml) |
| Intégrer à vos outils (curl, Python, TypeScript, CI) | [Utiliser l'API REST](api/usage.md) · [Référence CLI](cli.md) |
| Passer en production | [Déploiement](operations/deployment.md) |

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
