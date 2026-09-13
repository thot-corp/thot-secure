# Installation d'Thot Secure

*Comment installer, vérifier et mettre à jour Thot Secure (MVP v0.1.0) — d'un poste de travail à un cluster Kubernetes — dans un contexte 100 % défensif.*

Thot Secure est un **SOAR/CSPM défensif**. L'installation ne déploie aucune capacité offensive : `thotsecure probe` n'audite que les cibles **déclarées et possédées** par le tenant (`THOT_TARGETS_FILE`, opt-in explicite), et **toute action réelle est désactivée par défaut** (`THOT_DRY_RUN=true`, `THOT_AUTONOMY=supervised`).

!!! note "Source de vérité"
    Ce guide décrit l'installation du contrat d'interface v0.1.0 : [`architecture/api-contract.md`](architecture/api-contract.md).
    Les noms de variables, d'options CLI et de chemins proviennent de ce contrat (§2, §8, §9, §10, §11).
    Les fichiers d'infrastructure (`Dockerfile`, `compose.yaml`, `k8s/`, `helm/`, `terraform/`, `ansible/`) appartiennent au répertoire `deploy/` et sont détenus par un autre lot : leur **référence est `deploy/README.md`**. Les exemples IaC de cette page sont **génériques et illustratifs**, jamais normatifs.

---

## 1. Prérequis

### 1.1 Composants

| Composant | Minimum | Recommandé | Remarque |
|---|---|---|---|
| **Python** | 3.11 | 3.12 ou 3.13 | 3.11 est le plancher exigé (`requires-python = ">=3.11"`). Le cœur `thotsecure.core` n'utilise que la **stdlib**. |
| **pip** | Fourni avec Python 3.11 | Dernière version (`python -m pip install --upgrade pip`) | Indispensable pour `pip install -e .`. |
| **`venv`** | Module `venv` de la stdlib | — | Isolement des dépendances ; sous Debian/Ubuntu, le paquet `python3-venv` peut être nécessaire. |
| **SQLite** | Module `sqlite3` fourni avec Python | Disque local (pas de partage réseau) | **Aucun serveur à installer.** Base par défaut : `sqlite:///./data/thotsecure.db`. |
| **Dépendances applicatives** | — | Installées automatiquement | `pydantic` / `pydantic-settings`, `PyYAML` (cœur) ; `fastapi`, `uvicorn`, `Jinja2` (couche API). |
| **CPU / RAM** | 1 vCPU / 512 Mo | 2 vCPU / 2 Go | Ordre de grandeur indicatif : dépend du volume d'événements ingérés et de la rétention. |
| **Espace disque** | ~0,5 Go | ≥ 2 Go | Environnement Python + dépendances ; la base SQLite croît avec les événements et `THOT_RETENTION_DAYS` (défaut 30). Valeurs **indicatives**, à ajuster selon votre volume. |
| **Réseau sortant** | **Non requis à l'exécution** pour le cœur | Requis uniquement pour l'installation | L'installation et les mises à jour nécessitent un accès (ou un miroir, voir §11). Le cœur fonctionne en air-gap. |
| **Navigateur** | Navigateur récent | — | La console embarquée (Jinja2 + JS, **zéro build Node**) est servie par l'API. |

!!! tip "Invariant de dépendances"
    Le cœur `thotsecure.core` ne dépend que de la **stdlib** + `pydantic` / `PyYAML` (contrat §1, invariant 5).
    FastAPI, Jinja2 et uvicorn ne sont nécessaires que pour la couche API : c'est ce qui permet d'utiliser la CLI, les règles, le scoring et l'audit dans un environnement minimal.

### 1.2 Ports

| Port | Protocole | Usage | Écoute par défaut | Remarque |
|---|---|---|---|---|
| **8080** | TCP/HTTP | API REST `/api/v1`, console `/`, `/healthz`, `/readyz`, `/metrics`, `/openapi.json` | `THOT_HOST=0.0.0.0` / `THOT_PORT=8080` | Port par défaut. En production, exposez plutôt derrière un reverse-proxy TLS (ou `THOT_TLS_ENABLED=true`). |
| **4222** | TCP | Bus d'événements **NATS** | `THOT_NATS_URL=nats://127.0.0.1:4222` | **Uniquement** si `THOT_BUS=nats`. Inutile avec `memory` (défaut) ou `sqlite`. |

!!! warning "Exposition réseau"
    `THOT_HOST=0.0.0.0` écoute sur toutes les interfaces. Si l'instance n'est pas encore protégée par TLS et par une clé API dédiée, liez-la à `127.0.0.1` et passez par un reverse-proxy, ou restreignez l'accès au réseau interne.

### 1.3 Variables utiles dès l'installation

Liste exhaustive et rôle détaillé : [`configuration.md`](configuration.md) et contrat §9.

| Variable | Défaut | À retenir à l'installation |
|---|---|---|
| `THOT_ENV` | `dev` | Passez à `prod` : durcit les défauts et masque les erreurs. |
| `THOT_SECRET_KEY` | *généré + avertissement* | **Définissez-la explicitement** en production (pepper des clés API + signature). |
| `THOT_BOOTSTRAP_API_KEY` | `ao_dev_local_change_me` | ⚠️ Valeur publique : **à changer** avant toute exposition. |
| `THOT_DRY_RUN` | `true` | Sécurité : aucune action réelle si `true`. |
| `THOT_AUTONOMY` | `supervised` | `manual` \| `supervised` \| `auto` (défaut global, surchargeable par tenant). |
| `THOT_DB_URL` | `sqlite:///./data/thotsecure.db` | Chemin **relatif au répertoire de travail**. |
| `THOT_RULES_DIR` / `THOT_POLICIES_DIR` / `THOT_PLAYBOOKS_DIR` | `./rules` / `./policies` / `./playbooks` | Chemins relatifs : lancez la CLI depuis la racine du projet, ou fixez des chemins absolus. |

---

## 2. Systèmes d'exploitation supportés

| Système | Statut | Remarques |
|---|---|---|
| **Linux x86_64** (Debian/Ubuntu, RHEL/Rocky) | Cible principale | Chemins POSIX, `source venv/bin/activate`, unité `systemd` pour le service. |
| **Linux aarch64 / ARM64** | Supporté | Vérifiez que les dépendances publient des *wheels* pour votre plateforme ; sinon compilation locale (voir §11). |
| **macOS Intel (x86_64)** | Supporté | `source venv/bin/activate` ; `launchd` ou conteneur pour un service persistant. |
| **macOS Apple Silicon (arm64)** | Supporté | Idem ; vérifiez la disponibilité des *wheels* arm64. |
| **Windows 10 / 11** | Supporté | PowerShell, `.\venv\Scripts\Activate.ps1`, séparateur `\`. Gardez la forme `/` dans les URL (ex. `sqlite:///./data/thotsecure.db`). |
| **WSL2** | Recommandé sous Windows | Vous bénéficiez du chemin Linux (systemd, chemins POSIX) ; les fichiers du projet doivent rester dans le système de fichiers Linux pour les performances SQLite. |
| **Conteneur Docker / Podman** | Supporté | Image construite depuis `deploy/` (voir §6 et `deploy/README.md`). |
| **Kubernetes** | Supporté (déploiement de référence via le chart Helm de `deploy/helm/`) | Voir §8 et [`operations/deployment.md`](operations/deployment.md). |

!!! note "Portée de ce tableau"
    Ce tableau décrit une **intention de support**, pas une garantie contractuelle. La matrice réellement exercée est celle des workflows CI du dépôt : consultez-les (et `CHANGELOG.md`) avant de considérer une plateforme comme validée. **Linux x86_64 est le chemin le mieux établi** ; les autres combinaisons peuvent nécessiter des ajustements (compilation de dépendances, permissions, pare-feu).

!!! info "Roadmap"
    Les paquets natifs (`.deb`, `.rpm`, MSI), un paquet **Homebrew** et des charts publiés sur un registre public **ne font pas partie du MVP v0.1.0**. Leur disponibilité future doit être confirmée par `CHANGELOG.md` et le dépôt officiel.

---

## 3. Installation depuis les sources (recommandée)

C'est la méthode recommandée : elle installe le paquet `src/thotsecure` en mode **éditable** et fournit le point d'entrée `thotsecure`. Adaptez l'URL de clone au dépôt officiel.

### 3.1 Bash (Linux, macOS, WSL2)

```bash
git clone https://github.com/thotsecure/thot-secure.git
cd thot-secure

python -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
pip install -e .

# Initialisation de la base SQLite puis diagnostic
thotsecure init-db
thotsecure doctor
```

### 3.2 PowerShell (Windows)

```powershell
git clone https://github.com/thotsecure/thot-secure.git
Set-Location thotsecure

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e .

# Initialisation de la base SQLite puis diagnostic
thotsecure init-db
thotsecure doctor
```

!!! tip "Script d'activation bloqué par la stratégie d'exécution"
    Si `.\venv\Scripts\Activate.ps1` est refusé, autorisez-le pour **la session courante uniquement** :

    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\venv\Scripts\Activate.ps1
    ```

### 3.3 Ce que fait `pip install -e .`

| Élément | Effet |
|---|---|
| Mode éditable | Le paquet `src/thotsecure` est installé par référence : vos modifications du code source sont prises en compte sans réinstallation. |
| Point d'entrée | La commande `thotsecure` est créée dans le `venv` (`thotsecure = thotsecure.cli:main`). |
| Dépendances | `pydantic`, `pydantic-settings`, `PyYAML`, `fastapi`, `uvicorn`, `Jinja2` sont installées depuis `pyproject.toml`. |
| Données embarquées | Modèles de la console, CSS/JS et données livrées sont inclus dans le paquet (`package-data`). |

### 3.4 Vérifier l'installation

```bash
thotsecure doctor                      # diagnostic : config, base, règles, politiques, playbooks
thotsecure rules validate --path rules # valide la bibliothèque de détection livrée
thotsecure --help                      # toutes les commandes du contrat §8
```

```powershell
thotsecure doctor
thotsecure rules validate --path rules
thotsecure --help
```

Puis démarrez l'API et la console embarquée :

```bash
thotsecure serve --host 127.0.0.1 --port 8080
```

Le premier parcours fonctionnel (création de tenant, clé API, ingestion, finding) est décrit dans [`quickstart.md`](quickstart.md) ; la référence des commandes est dans [`cli.md`](cli.md).

!!! note "Environnement de développement"
    Pour exécuter les tests et les outils de qualité, installez l'extra `dev` :

    ```bash
    pip install -e ".[dev]"
    python -m unittest discover -s tests -t . -v
    ```

---

## 4. Installation avec pipx

`pipx` installe la CLI dans un environnement isolé, sans polluer le Python système.

=== "Depuis un clone (méthode sûre)"

    ```bash
    git clone https://github.com/thotsecure/thot-secure.git
    cd thot-secure
    pipx install .
    thotsecure doctor
    ```

=== "Depuis PyPI (à confirmer)"

    ```bash
    pipx install thotsecure
    ```

    ```powershell
    pipx install thotsecure
    ```

!!! note "Publication PyPI : à vérifier, pas à supposer"
    `pipx install thotsecure` ne fonctionne que si une distribution est **effectivement publiée** sur un index. Ne considérez pas cette disponibilité comme acquise : vérifiez `CHANGELOG.md` et le dépôt officiel (`pyproject.toml` déclare le projet sous le nom `thotsecure`, mais cela ne prouve pas qu'un *release* PyPI existe pour la 0.1.0). En cas de doute, utilisez `pipx install .` depuis un clone.

!!! warning "Chemins relatifs et répertoire de travail"
    Avec `pipx`, la CLI s'exécute depuis **n'importe quel répertoire**, mais les défauts `THOT_DB_URL=sqlite:///./data/thotsecure.db`, `THOT_RULES_DIR=./rules`, `THOT_POLICIES_DIR=./policies` et `THOT_PLAYBOOKS_DIR=./playbooks` restent relatifs au répertoire courant. Placez-vous dans le répertoire de travail voulu, ou définissez des chemins absolus avant de lancer `thotsecure init-db`, `serve` ou `doctor`.

!!! info "Roadmap"
    Aucun canal de distribution natif (Homebrew, `.deb`/`.rpm`, MSI) n'est annoncé pour le MVP v0.1.0. `pipx` et `pip` sont les deux seuls canaux documentés ici.

---

## 5. Binaire signé : téléchargement et vérification

Le projet **vise** la publication de binaires signés (archive + sommes de contrôle + signature). Procédure générique, applicable à toute *release* qui fournirait ces artefacts.

!!! info "Roadmap"
    La disponibilité effective des binaires signés, les noms exacts des fichiers, l'algorithme/empreinte de la **clé publique de signature** et l'identité OIDC de l'émetteur doivent être vérifiés dans la **dernière *release* du dépôt officiel**. Cette page ne fournit **aucune empreinte, aucune URL de *release* et aucun identifiant d'émetteur** : ils ne peuvent pas être devinés, et une empreinte inventée serait un risque de sécurité.

### 5.1 Télécharger l'archive et ses preuves

Les noms ci-dessous sont des **placeholders** : remplacez-les par les noms exacts publiés dans la *release*.

| Fichier (exemple) | Rôle |
|---|---|
| `thotsecure_0.1.0_linux_amd64.tar.gz` | Archive du binaire/paquet. |
| `SHA256SUMS` | Sommes de contrôle SHA-256 de tous les artefacts. |
| `thotsecure_0.1.0_linux_amd64.tar.gz.sig` | Signature détachée. |
| `thotsecure_0.1.0_linux_amd64.tar.gz.pem` | Certificat (signature *keyless* Sigstore uniquement). |
| `cosign.pub` | Clé publique de signature (signature par clé). |

### 5.2 Vérification par somme de contrôle (SHA-256)

=== "Bash"

    ```bash
    # Vérifie toutes les archives listées dans SHA256SUMS
    sha256sum -c SHA256SUMS --ignore-missing

    # Ou uniquement l'artefact téléchargé
    sha256sum thotsecure_0.1.0_linux_amd64.tar.gz
    ```

    Comparez la valeur obtenue **caractère par caractère** avec la ligne correspondante de `SHA256SUMS`.

=== "PowerShell"

    ```powershell
    $fichier  = ".\thotsecure_0.1.0_linux_amd64.tar.gz"
    $attendu  = (Get-Content .\SHA256SUMS |
                 Select-String ([regex]::Escape((Split-Path $fichier -Leaf)))).Line.Split(" ")[0]
    $obtenu   = (Get-FileHash -Algorithm SHA256 $fichier).Hash

    if ($obtenu.ToLower() -ne $attendu.ToLower()) {
        throw "Somme SHA-256 invalide : NE PAS INSTALLER cet artefact."
    }
    "Somme SHA-256 vérifiée : $obtenu"
    ```

!!! warning "La somme de contrôle ne suffit pas toujours"
    Une somme de contrôle téléchargée **depuis la même source** que l'archive ne protège pas contre une compromission de cette source. C'est la **signature** (§5.3) qui apporte cette garantie — vérifiez les deux.

### 5.3 Vérification de la signature avec cosign

=== "Signature keyless (Sigstore)"

    ```bash
    cosign verify-blob \
      --key cosign.pub \
      --signature thotsecure_0.1.0_linux_amd64.tar.gz.sig \
      --certificate thotsecure_0.1.0_linux_amd64.tar.gz.pem \
      --certificate-identity "<identité OIDC publiée dans la release>" \
      --certificate-oidc-issuer "<émetteur OIDC publié dans la release>" \
      thotsecure_0.1.0_linux_amd64.tar.gz
    ```

    Remplacez `--certificate-identity` et `--certificate-oidc-issuer` par les valeurs **exactes** annoncées dans la *release*. Ne déduisez jamais ces valeurs de cette documentation.

=== "Signature par clé"

    ```bash
    cosign verify-blob \
      --key cosign.pub \
      --signature thotsecure_0.1.0_linux_amd64.tar.gz.sig \
      thotsecure_0.1.0_linux_amd64.tar.gz
    ```

    Vérifiez d'abord l'empreinte de `cosign.pub` (via un canal indépendant : le dépôt officiel, `SECURITY.md`), puis conservez-la comme référence.

=== "PowerShell (équivalent)"

    ```powershell
    cosign verify-blob `
      --key .\cosign.pub `
      --signature .\thotsecure_0.1.0_linux_amd64.tar.gz.sig `
      --certificate .\thotsecure_0.1.0_linux_amd64.tar.gz.pem `
      --certificate-identity "<identité OIDC publiée dans la release>" `
      --certificate-oidc-issuer "<émetteur OIDC publié dans la release>" `
      .\thotsecure_0.1.0_linux_amd64.tar.gz
    ```

Une vérification réussie affiche les identités validées. Toute erreur (`Error: no matching signatures`, identité inattendue, certificat expiré) doit être traitée comme un **échec de confiance**.

### 5.4 En cas d'échec de vérification

1. **N'installez rien.** Supprimez l'archive et les fichiers de preuve téléchargés.
2. Retéléchargez uniquement depuis la page de *release* officielle du dépôt.
3. Si l'écart persiste, **n'exécutez pas** le binaire : ouvrez un rapport via le canal indiqué dans `SECURITY.md` (`docs` : [`support.md`](support.md)).

!!! danger "Règle absolue"
    **Ne jamais installer ni exécuter un binaire dont la signature ne correspond pas.** Un artefact non vérifié peut contenir du code malveillant ; aucune fonctionnalité d'Thot Secure ne justifie de contourner cette étape.

---

## 6. Docker

Le `Dockerfile` de référence appartient à `deploy/` (voir `deploy/README.md`) : les commandes ci-dessous sont **génériques et illustratives**.

### 6.1 Construire l'image

```bash
# Contexte de build = racine du dépôt cloné
docker build -t thotsecure:0.1.0 .
```

```powershell
docker build -t thotsecure:0.1.0 .
```

### 6.2 Lancer le conteneur

```bash
docker volume create thotsecure-data

docker run -d --name thotsecure \
  --restart unless-stopped \
  -p 8080:8080 \
  -v thotsecure-data:/app/data \
  -e THOT_ENV=prod \
  -e THOT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e THOT_DRY_RUN=true \
  -e THOT_AUTONOMY=supervised \
  -e THOT_DB_URL="sqlite:///./data/thotsecure.db" \
  thotsecure:0.1.0
```

```powershell
docker volume create thotsecure-data

docker run -d --name thotsecure `
  --restart unless-stopped `
  -p 8080:8080 `
  -v thotsecure-data:/app/data `
  -e THOT_ENV=prod `
  -e THOT_SECRET_KEY="<clé-aléatoire-longue-générée-localement>" `
  -e THOT_DRY_RUN=true `
  -e THOT_AUTONOMY=supervised `
  -e THOT_DB_URL="sqlite:///./data/thotsecure.db" `
  thotsecure:0.1.0
```

| Élément | Rôle |
|---|---|
| `-v thotsecure-data:/app/data` | **Volume de données persistant** : la base SQLite `sqlite:///./data/thotsecure.db` et le journal d'audit doivent survivre au conteneur. |
| `-p 8080:8080` | Expose l'API et la console embarquée sur le port par défaut. |
| `THOT_ENV=prod` | Durcit les défauts et masque les erreurs. |
| `THOT_SECRET_KEY` | Obligatoire en production (pepper des clés API + signature). À injecter par un coffre de secrets, jamais en clair dans un historique de commandes. |
| `THOT_DRY_RUN` | Laissez `true` tant que vous n'avez pas validé vos playbooks et vos connecteurs. |
| `THOT_DB_URL` | Peut pointer vers un autre chemin monté, à condition de rester en `sqlite://` pour le MVP. |

!!! warning "Chemin de montage"
    `/app/data` est le chemin attendu par l'image de référence ; si le `WORKDIR` du `Dockerfile` livré diffère, adaptez le point de montage. La référence est `deploy/README.md`.

### 6.3 Initialiser et vérifier dans le conteneur

```bash
docker exec thotsecure thotsecure init-db
docker exec thotsecure thotsecure doctor
docker logs -f thotsecure
```

Selon le point d'entrée de l'image, `init-db` peut déjà être exécuté au démarrage : consultez `deploy/README.md` avant de dupliquer l'appel.

!!! tip "Contrôle de santé"
    `curl http://127.0.0.1:8080/healthz` renvoie `{"status":"ok","version":"0.1.0","uptime_s":…}` et `curl http://127.0.0.1:8080/readyz` renvoie `200` ou `503` selon l'état de la base, du bus et des règles (contrat §4.1).

---

## 7. Docker Compose

Le fichier `compose.yaml` appartient au lot déploiement. La commande utilisateur pour l'essai complet est :

```bash
docker compose --profile demo up
```

```powershell
docker compose --profile demo up
```

Elle démarre, avec le profil `demo`, une instance immédiatement explorable : **API + console embarquée + jeu de démonstration** (findings et actions pré-remplis, l'équivalent de `thotsecure demo --tenant demo`). Le mode `dry_run` reste actif : aucune action réelle n'est exécutée.

| Profil / service (attendu) | Contenu | Usage |
|---|---|---|
| `demo` | API (port **8080**) + console `/` + données de démonstration | Découverte, formation, tests d'intégration. |
| Service `db`-like | **Aucun pour le MVP** : SQLite est un fichier dans un volume | Aucun serveur de base à démarrer (`postgresql` relève de la Roadmap). |

!!! note "Le contenu exact du `compose.yaml` est détenu par `deploy/`"
    Les noms de profils, de services, les variables exposées et la présence éventuelle d'autres profils (`prod`, observabilité, bus NATS…) sont définis dans `deploy/`. **Consultez `deploy/README.md`** : ne supposez pas que la table ci-dessus est exhaustive.

### 7.1 Exemple minimal (illustratif)

!!! example "Exemple, la référence est `deploy/`"
    Ce fichier est un **exemple pédagogique**, pas le fichier livré. Il montre la forme attendue : volume persistant et *healthcheck* sur `/healthz`.

```yaml
# Exemple illustratif — la référence est deploy/ (lot déploiement)
services:
  api:
    image: thotsecure:0.1.0          # ou "build: ." selon le compose livré
    ports:
      - "8080:8080"
    environment:
      THOT_ENV: prod
      THOT_HOST: 0.0.0.0
      THOT_PORT: "8080"
      THOT_DB_URL: sqlite:///./data/thotsecure.db
      THOT_BUS: sqlite          # memory | sqlite | nats
      THOT_DRY_RUN: "true"      # sûreté par défaut : on ne change pas ça à la légère
      THOT_AUTONOMY: supervised
      THOT_SECRET_KEY: ${THOT_SECRET_KEY:?definir THOT_SECRET_KEY}
    volumes:
      - thotsecure-data:/app/data
    healthcheck:
      test:
        - CMD
        - python
        - -c
        - "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status == 200 else 1)"
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped

volumes:
  thotsecure-data:
```

!!! warning "Secrets dans Compose"
    `${THOT_SECRET_KEY:?...}` force l'échec si la variable n'est pas fournie : c'est volontaire. N'écrivez jamais la clé en clair dans un fichier suivi par Git ; utilisez un fichier `.env` non versionné ou votre coffre de secrets.

---

## 8. Kubernetes et Helm

Le chart vit dans `deploy/helm/thotsecure` (lot déploiement). **Sûreté par défaut : gardez le *dry-run* actif à l'installation.**

```bash
helm install thotsecure ./deploy/helm/thotsecure \
  --namespace thotsecure --create-namespace \
  --set image.tag=0.1.0 \
  --set dryRun=true \
  --set autonomy=supervised
```

```powershell
helm install thotsecure ./deploy/helm/thotsecure `
  --namespace thotsecure --create-namespace `
  --set image.tag=0.1.0 `
  --set dryRun=true `
  --set autonomy=supervised
```

| Option | Effet | Conseil |
|---|---|---|
| `--set dryRun=true` | Aucune action réelle n'est exécutée | **À conserver** jusqu'à validation des playbooks, des connecteurs et du périmètre de cibles. |
| `--set autonomy=supervised` | Toute action critique passe par une approbation humaine | Sûreté par défaut ; `auto` exige une décision explicite au niveau du tenant. |
| `--set image.tag=0.1.0` | Fige la version de l'image (version du contrat) | Les versions publiées sont dans `CHANGELOG.md`. |

### 8.1 `values.yaml` minimal (illustratif)

!!! example "Exemple, la référence est `deploy/README.md`"
    Les clés ci-dessous illustrent les réglages de sûreté à connaître ; **les noms exacts et la structure complète du chart appartiennent au lot déploiement**.

```yaml
# Exemple illustratif — la référence est deploy/helm/thotsecure
image:
  repository: thotsecure        # remplacez par le nom d'image de la release
  tag: "0.1.0"
  pullPolicy: IfNotPresent

replicaCount: 1               # SQLite : restez à 1 réplica (voir l'avertissement ci-dessous)

resources:
  requests:
    cpu: 250m
    memory: 256Mi
  limits:
    cpu: "1"
    memory: 1Gi

# Sûreté
dryRun: true                  # équivalent de THOT_DRY_RUN
autonomy: supervised          # manual | supervised | auto
bus: sqlite                   # memory | sqlite | nats

# Secret : jamais de clé en clair dans le chart (voir ci-dessous)
existingSecret: thotsecure-secrets

probes:
  livenessPath: /healthz
  readinessPath: /readyz
```

### 8.2 Secret de `THOT_SECRET_KEY`

!!! danger "Jamais de secret en clair dans le chart"
    `THOT_SECRET_KEY` ne doit **jamais** apparaître dans `values.yaml`, dans un `ConfigMap`, ni dans Git. Créez un `Secret` Kubernetes (idéalement via un External Secrets Operator ou un coffre) et référencez-le par `existingSecret`.

```bash
kubectl -n thotsecure create secret generic thotsecure-secrets \
  --from-literal=THOT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

```powershell
kubectl -n thotsecure create secret generic thotsecure-secrets `
  --from-literal=THOT_SECRET_KEY="<clé-aléatoire-longue-générée-localement>"
```

Changez également `THOT_BOOTSTRAP_API_KEY` (valeur par défaut publique `ao_dev_local_change_me`) et créez des clés nominatives : `thotsecure key create --tenant acme --role responder --label ci`.

### 8.3 Sondes

| Sonde | Chemin | Sémantique |
|---|---|---|
| *Liveness* | `/healthz` | Le processus répond : `{"status":"ok","version":"0.1.0","uptime_s":…}`. |
| *Readiness* | `/readyz` | Vérifie **DB + bus + règles** → `200` si tout est prêt, **`503`** sinon (contrat §4.1). Un Pod en `503` doit être retiré du trafic, pas redémarré en boucle. |

!!! note "SQLite et multi-réplicas"
    Le MVP utilise SQLite (`sqlite://`). **Aucun PVC partagé ne permet à plusieurs réplicas d'écrire la même base de manière sûre** : conservez `replicaCount: 1`. Le passage à PostgreSQL/TimescaleDB (documenté dans le contrat, §9) conditionne la mise à l'échelle horizontale.

!!! info "Roadmap"
    Le support PostgreSQL/TimescaleDB avec montée en charge horizontale, ainsi que d'éventuels charts publiés sur un registre public, ne font pas partie du MVP v0.1.0 : à confirmer par `CHANGELOG.md` et `deploy/README.md`.

Pour la stratégie de déploiement, les sauvegardes et la montée de version, voir [`operations/deployment.md`](operations/deployment.md).

---

## 9. Ansible

Le playbook réel vit dans `deploy/ansible/` (lot déploiement). L'exemple ci-dessous est **générique et illustratif** : il montre les tâches attendues et, surtout, la manière de rester **idempotent**.

### 9.1 Exécution

```bash
# Toujours commencer par un essai à blanc
ansible-playbook -i inventory.ini deploy/ansible/install.yml --check --diff

# Puis appliquer
ansible-playbook -i inventory.ini deploy/ansible/install.yml
```

!!! tip "Idempotence"
    Un second passage **sans modification** doit afficher `changed=0`. Utilisez les modules (`package`, `user`, `file`, `copy`, `template`, `pip`, `systemd_service`) plutôt que `shell`/`command`, ajoutez `creates:` sur les commandes ponctuelles et `changed_when: false` pour les vérifications. En mode `--check`, les tâches `command`/`shell` peuvent échouer ou être signalées comme non idempotentes : c'est attendu.

### 9.2 Playbook illustratif

```yaml
# Exemple illustratif — la référence est deploy/ansible/ (lot déploiement)
- name: Installer Thot Secure
  hosts: thotsecure
  become: true

  vars:
    thotsecure_user: thotsecure
    thotsecure_home: /opt/thotsecure
    thotsecure_version: "0.1.0"          # versions publiées : voir CHANGELOG.md
    thotsecure_src: /opt/thotsecure/src    # copie du dépôt, ou artefact de release vérifié

  tasks:
    - name: Installer les paquets système requis
      ansible.builtin.package:
        name:
          - python3
          - python3-venv
          - git
        state: present

    - name: Créer l'utilisateur de service
      ansible.builtin.user:
        name: "{{ thotsecure_user }}"
        system: true
        create_home: true
        home: "{{ thotsecure_home }}"
        shell: /usr/sbin/nologin

    - name: Créer les répertoires de données et de configuration
      ansible.builtin.file:
        path: "{{ item.path }}"
        state: directory
        owner: "{{ item.owner }}"
        group: "{{ item.group }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "{{ thotsecure_home }}/data", owner: "{{ thotsecure_user }}", group: "{{ thotsecure_user }}", mode: "0750" }
        - { path: "/etc/thotsecure", owner: "root", group: "{{ thotsecure_user }}", mode: "0750" }

    - name: Créer l'environnement virtuel (idempotent)
      ansible.builtin.command:
        cmd: python3 -m venv {{ thotsecure_home }}/venv
        creates: "{{ thotsecure_home }}/venv/bin/python"

    - name: Installer Thot Secure dans l'environnement virtuel
      ansible.builtin.pip:
        name: "{{ thotsecure_src }}"
        virtualenv: "{{ thotsecure_home }}/venv"
        editable: true

    - name: Initialiser la base SQLite
      ansible.builtin.command:
        cmd: "{{ thotsecure_home }}/venv/bin/thotsecure init-db"
        chdir: "{{ thotsecure_home }}"
        creates: "{{ thotsecure_home }}/data/thotsecure.db"

    - name: Écrire le fichier d'environnement (0600, secret issu d'un coffre)
      ansible.builtin.copy:
        dest: /etc/thotsecure/thotsecure.env
        owner: root
        group: "{{ thotsecure_user }}"
        mode: "0600"
        content: |
          THOT_ENV=prod
          THOT_HOST=127.0.0.1
          THOT_PORT=8080
          THOT_DB_URL=sqlite:///./data/thotsecure.db
          THOT_BUS=sqlite
          THOT_DRY_RUN=true
          THOT_AUTONOMY=supervised
          THOT_LOG_FORMAT=json
          THOT_SECRET_KEY={{ vault_thotsecure_secret_key }}
      no_log: true
      notify: Redémarrer thotsecure

    - name: Installer l'unité systemd
      ansible.builtin.copy:
        dest: /etc/systemd/system/thotsecure.service
        owner: root
        group: root
        mode: "0644"
        content: |
          [Unit]
          Description=Thot Secure (SOAR/CSPM défensif)
          After=network-online.target

          [Service]
          Type=simple
          User={{ thotsecure_user }}
          WorkingDirectory={{ thotsecure_home }}
          EnvironmentFile=/etc/thotsecure/thotsecure.env
          ExecStart={{ thotsecure_home }}/venv/bin/thotsecure serve --host 127.0.0.1 --port 8080
          Restart=on-failure
          NoNewPrivileges=true
          PrivateTmp=true
          ProtectSystem=strict
          ReadWritePaths={{ thotsecure_home }}/data

          [Install]
          WantedBy=multi-user.target
      notify: Redémarrer thotsecure

    - name: Activer et démarrer le service
      ansible.builtin.systemd_service:
        name: thotsecure
        enabled: true
        state: started
        daemon_reload: true

    - name: Vérifier l'installation (lecture seule)
      ansible.builtin.command:
        cmd: "{{ thotsecure_home }}/venv/bin/thotsecure doctor"
        chdir: "{{ thotsecure_home }}"
      changed_when: false
      register: thotsecure_doctor

    - name: Afficher le diagnostic
      ansible.builtin.debug:
        var: thotsecure_doctor.stdout_lines

  handlers:
    - name: Redémarrer thotsecure
      ansible.builtin.systemd_service:
        name: thotsecure
        state: restarted
        daemon_reload: true
```

!!! warning "Secrets Ansible"
    La clé `THOT_SECRET_KEY` doit venir d'**Ansible Vault** ou d'un coffre externe (`vault_thotsecure_secret_key`), jamais d'un `vars` en clair. `no_log: true` évite la fuite dans les logs du playbook, mais ne remplace pas le chiffrement à la source. Ne déployez pas le conteneur ou le venv avant d'avoir vérifié votre configuration.

!!! tip "Aucune action offensive"
    Ce playbook installe un service **défensif** : il n'ouvre aucun port vers l'extérieur (l'écoute par défaut est liée à `127.0.0.1`), ne lance aucun scan et ne modifie aucun système tiers. `thotsecure probe` n'est jamais invoqué automatiquement : il exige des cibles déclarées dans `THOT_TARGETS_FILE`.

---

## 10. Terraform

Le module réel vit dans `deploy/terraform/`. L'exemple ci-dessous est **générique et illustratif** : il expose les variables de sûreté (`dryRun = true`, `autonomy = "supervised"` **par défaut**) et la méthode pour ne pas faire fuiter de secret.

```hcl
# Exemple illustratif — la référence est deploy/terraform/ (lot déploiement)
terraform {
  required_version = ">= 1.5"
}

# --- Entrées ---------------------------------------------------------------

variable "environment" {
  type        = string
  description = "Environnement cible (dev, staging, prod)."
  default     = "prod"
}

variable "instance_size" {
  type        = string
  description = "Taille de l'hôte/VM à provisionner, selon votre fournisseur."
  default     = "small"
}

variable "data_volume_gb" {
  type        = number
  description = "Taille du volume de données (base SQLite + journal d'audit)."
  default     = 20
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "CIDR autorisés à joindre l'API (port 8080). Vide = aucun accès public."
  default     = []
}

variable "bus" {
  type        = string
  description = "Bus d'événements : memory | sqlite | nats."
  default     = "sqlite"
}

variable "dry_run" {
  type        = bool
  description = "Sûreté : true = aucune action réelle exécutée."
  default     = true
}

variable "autonomy" {
  type        = string
  description = "Mode d'autonomie global : manual | supervised | auto."
  default     = "supervised"

  validation {
    condition     = contains(["manual", "supervised", "auto"], var.autonomy)
    error_message = "autonomy doit valoir manual, supervised ou auto."
  }
}

variable "secret_key_ref" {
  type        = string
  description = "Référence vers un coffre (jamais la clé en clair)."
  sensitive   = true
  default     = ""
}

# --- Ressources ------------------------------------------------------------
# Les ressources concrètes dépendent du fournisseur (VM/hôte, règles de
# sécurité réseau, volume de données, éventuel cluster Kubernetes).
# Remplacez ce bloc par les ressources de votre fournisseur.

locals {
  thotsecure_settings = {
    environment = var.environment
    host        = "0.0.0.0"
    port        = 8080
    bus         = var.bus
    db_url      = "sqlite:///./data/thotsecure.db"
    dry_run     = var.dry_run
    autonomy    = var.autonomy
  }
}

# --- Sorties ---------------------------------------------------------------

output "thotsecure_runtime_settings" {
  description = "Réglages à injecter dans l'environnement d'exécution (sans secret)."
  value       = local.thotsecure_settings
}

output "ingress_allowed_cidrs" {
  description = "CIDR autorisés vers l'API ; vide = instance non exposée."
  value       = var.allowed_ingress_cidrs
}
```

```bash
terraform init
terraform plan  -var 'environment=prod' -var 'dry_run=true' -var 'autonomy=supervised'
terraform apply
```

| Point d'attention | Règle |
|---|---|
| **Défauts sûrs** | `dry_run = true` et `autonomy = "supervised"` dans le module : on ne les desserre qu'après validation explicite. |
| **Aucun secret dans le `state`** | `sensitive = true` masque la valeur dans la sortie console mais **ne l'empêche pas d'être écrite dans le fichier `state`**. Ne passez donc jamais une clé en clair : `secret_key_ref` ne doit contenir qu'une **référence** (nom de secret dans Vault, AWS Secrets Manager, GCP Secret Manager…), résolue à l'exécution par l'hôte ou le cluster. |
| **Volume de données** | Prévoyez un volume persistant pour `data/` : la base SQLite et le journal d'audit chaîné ne doivent pas vivre sur un disque éphémère. |
| **Exposition réseau** | Par défaut, aucun ingress public (`allowed_ingress_cidrs = []`). Ouvrez le strict nécessaire, et jamais `0.0.0.0/0` sur le port 8080 sans TLS ni clé API dédiée. |
| **Backend d'état** | Utilisez un backend distant chiffré et verrouillé (`state` local = risque de fuite et de corruption). |

!!! warning "Le module livré fait foi"
    Les noms de ressources, de variables et de sorties du module réel peuvent différer de cet exemple. Consultez `deploy/terraform/` et `deploy/README.md` avant tout `apply`.

---

## 11. Build reproductible et installation hors-ligne

Objectif : installer et exécuter Thot Secure **sans aucun accès réseau**, sur un réseau cloisonné (air-gap) ou derrière un proxy restrictif.

!!! note "Le cœur ne dépend pas du réseau"
    À l'exécution, `thotsecure.core` n'a besoin que de la **stdlib** + `pydantic`/`PyYAML`. Aucun appel réseau sortant n'est requis pour la collecte locale, la détection, le scoring, l'audit ou la CLI. Le bus `memory`/`sqlite` fonctionne hors-ligne ; seul `THOT_BUS=nats` suppose un serveur NATS joignable.

### 11.1 Constituer un miroir local de dépendances (wheelhouse)

À exécuter **sur une machine connectée**, de préférence de même OS/architecture que la cible :

```bash
mkdir -p wheelhouse

# Dépendances du projet, à partir de pyproject.toml
python -m pip download -d ./wheelhouse .

# Outils de build nécessaires si la cible installe en mode éditable
python -m pip download -d ./wheelhouse "setuptools>=68" wheel
```

```powershell
New-Item -ItemType Directory -Force .\wheelhouse | Out-Null

python -m pip download -d .\wheelhouse .

python -m pip download -d .\wheelhouse "setuptools>=68" wheel
```

Transférez ensuite le dossier `wheelhouse/` par un canal maîtrisé (dépôt interne, clé chiffrée). `pip download` récupère des *wheels* correspondant à la plateforme courante : pour une cible différente (autre OS, autre architecture), relancez le téléchargement depuis une machine équivalente ou utilisez `--platform` / `--python-version` / `--only-binary=:all:`.

### 11.2 Installer hors-ligne

```bash
export PIP_NO_INDEX=1
python -m pip install --no-index --find-links ./wheelhouse -e .
# ou, à partir d'une distribution préparée :
# python -m pip install --no-index --find-links ./wheelhouse thotsecure==0.1.0

thotsecure init-db
thotsecure doctor
```

```powershell
$env:PIP_NO_INDEX = "1"
python -m pip install --no-index --find-links .\wheelhouse -e .
# ou : python -m pip install --no-index --find-links .\wheelhouse thotsecure==0.1.0

thotsecure init-db
thotsecure doctor
```

`PIP_NO_INDEX=1` coupe tout accès à un index distant : si une dépendance manque dans `wheelhouse/`, pip échoue immédiatement — c'est le comportement souhaité en air-gap.

### 11.3 Reproductibilité

```bash
# Valeur d'exemple : figez un horodatage pour rendre les artefacts reproductibles
export SOURCE_DATE_EPOCH=1700000000
python -m pip install --no-index --find-links ./wheelhouse -e .
```

```powershell
$env:SOURCE_DATE_EPOCH = "1700000000"
python -m pip install --no-index --find-links .\wheelhouse -e .
```

!!! note "`SOURCE_DATE_EPOCH`"
    `SOURCE_DATE_EPOCH` (spécification *Reproducible Builds*) fige l'horodatage utilisé par les outils de construction. La valeur ci-dessus est un **exemple** : celle employée par les artefacts officiels doit être publiée avec la *release* — à confirmer dans le dépôt.

### 11.4 Verrouillage par hachage

```bash
python -m pip install --require-hashes -r requirements.lock.txt
```

!!! info "Roadmap"
    L'existence d'un fichier de verrouillage avec hachages (`requirements.lock.txt`) **n'est pas acquise pour la v0.1.0**. Il doit être produit par le lot packaging (avec les hachages de toutes les dépendances et de leurs dépendances transitives). En son absence, utilisez l'approche `wheelhouse` (§11.1) et conservez le dossier comme référence d'intégrité : `pip download` enregistre les noms et versions exactes des fichiers téléchargés.

### 11.5 Images Docker hors-ligne

```bash
docker build -t thotsecure:0.1.0 .

# Sur la machine connectée : exporter l'image
docker save thotsecure:0.1.0 -o thotsecure_0.1.0_image.tar

# Sur la machine isolée : importer, puis lancer
docker load -i thotsecure_0.1.0_image.tar
docker images | grep thotsecure
```

```powershell
docker save thotsecure:0.1.0 -o .\thotsecure_0.1.0_image.tar
docker load -i .\thotsecure_0.1.0_image.tar
```

| Point d'attention | Détail |
|---|---|
| Image de base | L'image de base du `Dockerfile` doit être **présente localement** sur la machine isolée (`docker images`), sinon le `build` échouera faute de réseau ; transportez-la aussi avec `docker save`. |
| `--pull=false` | Évite toute tentative de récupération depuis un registre. |
| `--network=none` | Possible une fois les images de base disponibles localement ; sinon le `build` échoue (comportement attendu en air-gap). |
| Étiquetage | Figez un tag explicite (`thotsecure:0.1.0`) plutôt que `latest`, pour que l'artefact transporté soit identifiable. |

### 11.6 Contraintes d'environnement et solutions

| Contrainte | Solution |
|---|---|
| **Proxy HTTP/HTTPS obligatoire** | Renseignez `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` pour l'installation, ou passez `--proxy` à pip ; le proxy n'est pas nécessaire à l'exécution du cœur. |
| **Air-gap total (aucun réseau)** | `wheelhouse/` (§11.1) + `PIP_NO_INDEX=1` + `--no-index --find-links` ; images via `docker save`/`docker load` ; aucune action sortante à l'exécution. |
| **Miroir PyPI interne** | Pointez `PIP_INDEX_URL` (et éventuellement `PIP_TRUSTED_HOST`) vers votre miroir ; vérifiez l'authenticité des paquets avec des hachages (§11.4) lorsque disponibles. |
| **Pas de résolution DNS** | Utilisez `--find-links` sur un chemin local (aucun nom à résoudre) ; pour un bus NATS distant, adressez-le par IP (`THOT_NATS_URL=nats://<ip>:4222`) ; pour un serveur HTTP interne, utilisez son IP. |
| **Répertoires en lecture seule** | Placez `data/` (base SQLite, journal d'audit) sur un volume inscriptible et fixez `THOT_DB_URL` en conséquence ; les règles, politiques et playbooks peuvent rester en lecture seule. |

### 11.7 Validation finale d'une installation hors-ligne

```bash
thotsecure doctor
python -m unittest discover -s tests -t . -v
```

```powershell
thotsecure doctor
python -m unittest discover -s tests -t . -v
```

`thotsecure doctor` doit confirmer la configuration, la base, les règles, les politiques et les playbooks. La suite `unittest` (contrat §11) s'exécute sans dépendance externe et couvre la configuration, le stockage, la chaîne d'audit, le bus, le moteur de règles, le scoring, la décision, les actions/rollback, les collecteurs, l'API, les rapports et la CLI.

!!! tip "Interpréter les codes de sortie"
    `0` succès, `1` erreur, `2` usage, `3` vérification négative (par exemple un audit corrompu). Les tests d'API peuvent nécessiter l'extra `dev` (`pip install -e ".[dev]"`) ; en air-gap, installez-le depuis votre `wheelhouse`.

---

## 12. Mise à jour et désinstallation

!!! warning "Sauvegardez avant de mettre à jour"
    La base SQLite contient vos findings, vos actions et votre **journal d'audit chaîné par hash**. Une mise à jour peut faire évoluer le schéma : sauvegardez toujours avant.

```bash
# 1. Sauvegarde de la base (service arrêté, ou copie cohérente)
cp data/thotsecure.db "data/thotsecure-$(date +%Y%m%d).db"
# ou, service démarré : sqlite3 data/thotsecure.db ".backup 'data/thotsecure-backup.db'"

# 2. Mise à jour du code et du paquet
git pull
source venv/bin/activate
pip install -e .

# 3. Vérification
thotsecure doctor
```

```powershell
# 1. Sauvegarde de la base
Copy-Item .\data\thotsecure.db ".\data\thotsecure-$(Get-Date -Format yyyyMMdd).db"

# 2. Mise à jour du code et du paquet
git pull
.\venv\Scripts\Activate.ps1
pip install -e .

# 3. Vérification
thotsecure doctor
```

Pour une montée de version en production (ordre des étapes, fenêtre d'interruption, retour arrière, déploiement progressif, migration de base), suivez [`operations/deployment.md`](operations/deployment.md) ; les procédures d'incident sont dans [`operations/runbook.md`](operations/runbook.md).

### 12.1 Désinstallation

```bash
deactivate
pip uninstall thotsecure
rm -rf venv
# Conservez data/ : base SQLite + journal d'audit
```

```powershell
deactivate
pip uninstall thotsecure
Remove-Item -Recurse -Force .\venv
# Conservez .\data : base SQLite + journal d'audit
```

| Étape | Remarque |
|---|---|
| `pip uninstall thotsecure` | Retire le paquet et le point d'entrée du `venv` courant. |
| Suppression du `venv` | Supprime uniquement l'environnement ; le code source cloné reste intact. |
| **Conservation de `data/`** | La base SQLite et le journal d'audit contiennent votre historique. Conservez-les pour la rétention légale et l'analyse post-incident (voir `THOT_RETENTION_DAYS`). |
| Révocation des clés | Avant de décommissionner, révoquez les clés API (`thotsecure key revoke --key-id <id>`) : elles sont stockées **hachées** (`scrypt`) et ne peuvent pas être « relues ». |
| Secrets | Supprimez ou révoquez `THOT_SECRET_KEY` dans votre coffre : elle sert de pepper aux clés API. Ne supprimez jamais `data/` **et** la clé sans avoir exporté votre audit (`GET /api/v1/audit/export?format=jsonl`). |

---

## 13. Dépannage rapide

**Commencez toujours par `thotsecure doctor`** : il diagnostique la configuration, la base, les règles, les politiques et les playbooks, et affiche des remèdes ciblés. Diagnostic détaillé : [`operations/runbook.md`](operations/runbook.md).

| Symptôme | Cause probable | Action |
|---|---|---|
| Diagnostic général incertain | Configuration incomplète ou chemin relatif inattendu | `thotsecure doctor` ; vérifiez `THOT_RULES_DIR`, `THOT_POLICIES_DIR`, `THOT_PLAYBOOKS_DIR` et votre répertoire de travail. |
| `thotsecure : commande introuvable` (ou `is not recognized`) | `venv` non activé, ou autre interpréteur Python | Activez le `venv` (`source venv/bin/activate` / `.\venv\Scripts\Activate.ps1`) puis `pip show thotsecure` et `pip install -e .`. |
| Le port 8080 est déjà utilisé | Autre service (proxy, autre instance) | Linux : `ss -ltnp \| grep :8080` ; Windows : `netstat -ano \| findstr :8080` puis `Get-Process -Id <PID>`. Ou démarrez sur un autre port : `THOT_PORT=8081 thotsecure serve` / en PowerShell `$env:THOT_PORT="8081"; thotsecure serve`. |
| `401 unauthenticated` | En-tête `X-API-Key` absent ou clé inconnue | Envoyez `X-API-Key: ao_…` ; recréez une clé si nécessaire (`thotsecure key create --tenant acme --role responder --label ci`). |
| `403 forbidden` | Rôle sans la capacité requise | Vérifiez le rôle (`viewer` < `analyst` < `responder` < `admin`, contrat §4) ; créez une clé au bon rôle. |
| Clé API par défaut encore active | `THOT_BOOTSTRAP_API_KEY=ao_dev_local_change_me` (valeur publique) | **Changez-la immédiatement**, créez des clés nominatives, révoquez l'ancienne (`thotsecure key revoke --key-id <id>`). |
| Base non initialisée / erreurs de stockage | `thotsecure init-db` jamais exécuté, ou `data/` non inscriptible | `thotsecure init-db` ; vérifiez les droits du répertoire `data/` et la valeur de `THOT_DB_URL`. |
| `/readyz` renvoie **503** | Échec d'un des trois contrôles : **DB**, **bus** ou **règles** | Vérifiez `thotsecure init-db` (DB), `THOT_BUS`/`THOT_NATS_URL` (bus), `THOT_RULES_DIR` et `thotsecure rules validate --path rules` (règles). |
| Une action ne produit aucun effet | `THOT_DRY_RUN=true` (défaut) ou audit `simulated: true` | **Comportement attendu et voulu** (invariant 1). Le connecteur non configuré fonctionne en mode simulé. Ne désactivez le *dry-run* qu'après validation. |
| Une action reste en `pending_approval` | `THOT_AUTONOMY=supervised` : approbation humaine requise | Approuvez explicitement (`POST /api/v1/actions/{id}/approve` ou `thotsecure actions approve <id>`). |
| `400`/`404`/`409` sur des actions | Requête invalide, objet absent, ou transition interdite (déjà `rolled_back`, approbation manquante) | Vérifiez l'état de l'action (`thotsecure actions list`) et le contrat §4.6. |
| `429 rate_limited` | Ingestion trop rapide (`THOT_RATE_LIMIT_PER_MIN`, défaut 600) | Lissez l'envoi ou ajustez le plafond ; vérifiez l'erreur normalisée renvoyée. |
| `thotsecure doctor` échoue sur les règles | Règle invalide ou répertoire vide | `thotsecure rules validate --path rules` : une règle invalide est **rejetée avec un diagnostic** sans casser le chargement — corrigez la règle signalée. |
| Erreurs masquées en production | `THOT_ENV=prod` masque détail et trace | Reproduisez avec `THOT_ENV=dev` **et** `THOT_LOG_LEVEL=DEBUG` dans un environnement de test. |
| Aucun accès sortant et installation impossible | Réseau cloisonné | Voir §11 : `wheelhouse/`, `PIP_NO_INDEX=1`, images via `docker save`/`docker load`. |

!!! danger "En cas de doute, la sûreté par défaut"
    Si vous hésitez sur un réglage d'autonomie ou de périmètre, **restez en `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised`**. Thot Secure n'exécute aucune action offensive : en cas d'anomalie, coupez le service (`systemctl stop thotsecure`, `docker stop thotsecure`) plutôt que de desserrer un garde-fou.

---

## 14. Pour aller plus loin

| Document | Contenu |
|---|---|
| [`quickstart.md`](quickstart.md) | Premier tenant, première clé, premier finding en quelques minutes. |
| [`configuration.md`](configuration.md) | Toutes les variables `THOT_*` et leurs effets. |
| [`cli.md`](cli.md) | Référence complète de la CLI `thotsecure`. |
| [`architecture/api-contract.md`](architecture/api-contract.md) | Contrat d'interface gelé v0.1.0 (API, CLI, schémas, sécurité, tests). |
| [`operations/deployment.md`](operations/deployment.md) | Déploiement, montée de version, exploitation. |
| [`operations/runbook.md`](operations/runbook.md) | Procédures d'incident et diagnostics avancés. |
| [`faq.md`](faq.md) | Questions fréquentes. |
| [`support.md`](support.md) | Soutien du projet et canaux de contact. |
| `deploy/README.md` (dépôt) | Référence du `Dockerfile`, de Compose, de Kubernetes/Helm, de Terraform et d'Ansible. |

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
