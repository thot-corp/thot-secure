# ADR-0002 — Python + FastAPI et SQLite pour le MVP

*Nous construisons le cœur d'Thot Secure en Python (stdlib + `pydantic`/`PyYAML`), exposons la couche
API avec FastAPI et persistons dans SQLite par défaut, en livrant le DDL PostgreSQL/TimescaleDB
comme cible de production non encore implémentée.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté** pour la version 0.1.0 (MVP). La décision porte sur le langage du cœur, la pile de la
couche API et la base de données par défaut. Elle **ne prétend pas** que SQLite est la cible de
production : le DDL PostgreSQL/TimescaleDB est fourni comme cible documentée, et la migration est
un travail identifié, non réalisé, décrit dans les conséquences négatives et dans la section
Roadmap.

Les invariants concernés sont l'invariant 5 du contrat (« le core ne dépend que de la stdlib +
`pydantic`/`PyYAML` », [`../architecture/api-contract.md`](../architecture/api-contract.md) §1) et la
variable `THOT_DB_URL` (§9).

---

## Contexte

Le projet démarre avec une équipe réduite et un objectif précis : livrer un MVP **installable,
exécutable et auditable par un tiers** — un RSSI, un consultant, un étudiant, un MSSP qui veut
évaluer le produit sans engagement. Plusieurs contraintes se combinent :

1. **Installation sans chaîne de build complexe.** L'expérience cible tient en deux commandes :
   installation du paquet puis initialisation de la base (`thotsecure init-db`, §8). Un produit de
   sécurité qui exige Docker, Kubernetes, un broker de messages et un service de base de données
   avant d'afficher son premier finding ne sera pas essayé. La friction d'installation est un
   critère de conception, pas un détail.
2. **Cœur portable et testable.** Le contrat impose un cœur (`thotsecure.core`) limité à la
   **stdlib** plus `pydantic` et `PyYAML` (§1, invariant 5) ; FastAPI, Jinja2 et uvicorn sont des
   dépendances de la couche API uniquement. Le cœur doit pouvoir être testé et importé sans serveur
   web ni base de données, ce qui a une conséquence directe sur les tests : la suite §11 s'exécute
   sans dépendance externe.
3. **Contenus déclaratifs en YAML.** Règles de détection (§5), politiques de décision (§6) et
   playbooks (§7) sont des fichiers YAML relus à chaud `POST /api/v1/rules/reload` et
   `POST /api/v1/policies/reload`. Écrire une règle ne doit **jamais** nécessiter de compilation,
   et la validation (`thotsecure rules validate`, `POST /api/v1/rules/validate`) doit produire des
   diagnostics lisibles.
4. **Console sans toolchain.** L'UI embarquée est décrite comme « Jinja2 + JS, **aucun build Node
   requis** » (§4.9). Le dashboard `web/` en React+TS est explicitement optionnel : il ne doit pas
   conditionner l'usage du produit.
5. **Origine du public.** Thot Secure vise des équipes SOC, qui écrivent massivement du Python :
   parsers de logs, scripts de réponse, notebooks d'analyse. Aligner le langage du produit sur
   celui de ses utilisateurs réduit la barrière d'écriture des collecteurs et des playbooks.

Le compromis à trancher est donc : vélocité de livraison et simplicité d'exploitation contre
performance brute d'ingestion et capacités de la base.

---

## Décision

### Langage et découpage

* **Python 3.11+** comme langage unique du cœur, de la CLI, de la couche API et des SDK de
  référence.
* `thotsecure.core` (config, modèles, erreurs, utilitaires) : **stdlib + `pydantic` + `PyYAML`**
  exclusivement, conformément à l'invariant 5.
* Couche API : **FastAPI** + **uvicorn**, avec **Jinja2** pour la console embarquée (§4.9). Ces
  dépendances ne remontent jamais dans le cœur.
* Arborescence conforme au §2 du contrat : `src/thotsecure/{core,storage,bus,audit,tenancy,collectors,detection,scoring,decision,actions,reports,api,ui,sdk}`.

### Persistance

* **SQLite par défaut**, via `THOT_DB_URL=sqlite:///./data/thotsecure.db` (§9). Une base = un
  fichier, aucune administration, aucun service à démarrer.
* **DDL PostgreSQL/TimescaleDB fourni** dans `src/thotsecure/storage/` comme cible de production
  documentée — c'est une cible écrite, pas une cible implémentée dans le MVP.
* Rétention des événements pilotée par `THOT_RETENTION_DAYS` (défaut 30, §9).

### Interfaces dérivées

* Console embarquée « Jinja2 + JS, zéro build » (§4.9) : utilisable dès l'installation.
* Dashboard **React+TS optionnel** dans `web/` : il n'est **pas** requis pour utiliser le produit,
  et son absence ne dégrade aucune fonctionnalité côté serveur.

| Couche | Choix | Dépendances |
|---|---|---|
| Cœur | Python 3.11+, `thotsecure.core` | stdlib, `pydantic`, `PyYAML` |
| Persistance | SQLite (MVP) | stdlib (`sqlite3`), aucune brique externe |
| Persistance (cible) | PostgreSQL / TimescaleDB | DDL fourni, non implémenté en v0.1.0 |
| API | FastAPI + uvicorn | + `Jinja2` pour la console |
| Console | Jinja2 + JS, zéro build | aucune chaîne Node |
| Dashboard | React+TS dans `web/` | optionnel, non requis |
| Moteur de politique alternatif | OPA/Rego si `THOT_OPA_BIN` est défini et le binaire présent | optionnel, externe |

!!! note "Pourquoi le YAML est un choix d'architecture"
    Le format YAML des règles, politiques et playbooks est indissociable du choix de langage : il
    permet à un analyste de livrer une détection **sans compilateur** et sans redéploiement, via
    `POST /api/v1/rules/reload` ou `thotsecure rules validate`. Ce serait beaucoup plus difficile à
    reproduire proprement avec des règles embarquées dans un binaire compilé.

---

## Conséquences

### Positives

* **Installation en deux commandes.** `pip install -e .` puis `thotsecure init-db` : un fichier de
  base, aucun service à administrer, aucune migration à jouer. L'évaluation dure quelques minutes.
* **Un seul fichier de base.** Sauvegarde, copie, inspection et remise à zéro sont triviales
  (`thotsecure demo --tenant demo`, §8). C'est décisif pour les démonstrations et pour les tests.
* **Zéro serveur à administrer.** Pas de service de base à superviser, à mettre à jour ou à
  sécuriser dans un pilote. La surface d'exploitation se réduit à un processus.
* **Écriture de règles sans compilation.** Les contenus YAML (§5, §6, §7) sont relus à chaud et
  validés avec diagnostics ; une règle invalide ne casse pas le chargement.
* **Tests sans dépendance externe.** `python -m unittest discover -s tests -t . -v` (§11) tourne
  sans service externe, donc en CI sans conteneur de base de données — un gain de fiabilité et de
  temps de CI, et la condition pour que `tests/test_config.py` et `tests/test_storage.py` restent
  hermétiques.
* **Surface d'attaque réduite.** Pas de conteneur Node en production, pas de broker, pas de moteur
  de base exposé sur le réseau : la seule surface est l'API FastAPI derrière TLS
  (`THOT_TLS_ENABLED` ou reverse-proxy, §9 et §10).
* **Alignement avec le public SOC.** Un analyste peut lire et modifier les collecteurs, les
  playbooks et les parsers en Python, langage dominant dans les SOC.

### Négatives

Ces points sont des limites réelles du MVP, pas des risques hypothétiques.

* **SQLite = un seul écrivain.** Le verrou d'écriture sérialise les insertions : le débit
  d'ingestion de `POST /api/v1/events` plafonne bien avant les limites de la machine, et les
  écritures concurrentes (collecteurs, ingestion API, journal d'audit, actions) se contentionnent.
  C'est la limite la plus structurante du choix.
* **Pas de multi-réplicas avec état partagé.** On ne peut pas lancer deux instances d'Thot Secure
  derrière un répartiteur en partageant le même fichier SQLite de façon fiable ; le modèle de
  déploiement du MVP est **un processus**. Toute montée en charge horizontale exige d'abord la
  migration de base.
* **Pas de type strict ni de `jsonb`.** SQLite ne propose ni le typage fort ni les index sur
  documents JSON de PostgreSQL. Les `labels` et `payload` d'un `Event` (§3.1) sont stockés et
  filtrés avec des moyens plus frustes ; les requêtes d'analyse resteront moins expressives.
* **Pas de haute disponibilité native.** Un fichier ne se réplique pas tout seul : pas de bascule,
  pas de failover, pas de réplique de lecture. La sauvegarde est une copie, la restauration une
  procédure manuelle, et ces deux points doivent figurer dans
  [`../operations/deployment.md`](../operations/deployment.md) et
  [`../operations/runbook.md`](../operations/runbook.md).
* **Migration PostgreSQL à prévoir, travail non trivial.** Passer de SQLite à PostgreSQL ne se
  limite pas au DDL : il faut reprendre les requêtes, les types, la gestion des transactions, les
  index, la purge de rétention et la configuration de la concurrence. Le DDL livré réduit
  l'incertitude, il ne réalise pas la migration.
* **Performance d'ingestion inférieure à Go/Rust.** Pour des volumes de type MSSP — plusieurs
  collecteurs à haute fréquence, agrégation multi-tenant — Python et SQLite ne tiennent pas la
  charge qu'un binaire compilé avec un stockage adapté encaisserait. Le produit est aujourd'hui
  dimensionné pour un poste, un labo ou un pilote, pas pour un SOC de grande taille.
* **Dépendance à l'écosystème Python pour la chaîne d'approvisionnement.** `pip` et l'écosystème
  `pydantic`/`FastAPI`/`uvicorn` introduisent des dépendances transitives qu'il faut épingler,
  auditer et suivre — un point de vigilance réel pour un produit de sécurité, d'autant que les
  clés API sont hachées avec `scrypt` et que `THOT_SECRET_KEY` protège la signature (§10).
* **Frontière cœur/API à tenir à la main.** L'invariant 5 n'est pas vérifié par un outil dans le
  MVP : rien n'empêche mécaniquement un import de `fastapi` dans `thotsecure.core`. La discipline de
  revue est la seule barrière.

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : **PostgreSQL/TimescaleDB comme cible de production effective** (le DDL
    est déjà fourni), **outillage de migration** (script de conversion SQLite → PostgreSQL et
    versionnement de schéma), vérification automatique de l'invariant 5 en CI, et
    réévaluation du stockage d'événements au-delà de certaines volumétries — voir
    [`../architecture/data-model.md`](../architecture/data-model.md).

---

## Alternatives envisagées

| Alternative | Ce qu'elle apportait | Raison du rejet |
|---|---|---|
| **Go ou Rust** | Performance d'ingestion élevée, binaire unique, empreinte mémoire faible, déploiement sans interpréteur. | Rejeté : la vélocité de développement est le facteur limitant d'un MVP à équipe réduite, et la lisibilité du parsing YAML (règles, politiques, playbooks) est bien meilleure en Python. Surtout, l'écosystème SOC est majoritairement Python : un produit Go imposerait aux analystes d'écrire leurs collecteurs dans un langage qu'ils n'utilisent pas. Le binaire unique est un vrai avantage, mais il ne compense pas ces coûts au stade du MVP. |
| **Node.js / TypeScript** | Un seul langage pour le serveur et le dashboard React+TS, écosystème riche. | Rejeté : double toolchain (`npm` **et** `pip`) pour un produit qui revendique une UI sans build, ce qui contredit directement l'objectif « Jinja2 + JS, zéro build » (§4.9). Le typage structurel de TypeScript ne remplace pas `pydantic` pour la validation de schémas au runtime, et l'écosystème SOC est moins fourni en Python qu'en bibliothèques de parsing réseau et de sécurité. |
| **PostgreSQL dès le MVP** | Écritures concurrentes, `jsonb`, typage strict, HA, requêtes analytiques, cohérence avec la cible de production — donc pas de migration à faire plus tard. | Rejeté : la friction d'installation devient rédhibitoire pour un pilote (il faut un service, des identifiants, un schéma initialisé) et pour la CI, qui devrait démarrer un service externe alors que le §11 exige des tests exécutables **sans dépendance externe**. Le DDL PostgreSQL/TimescaleDB est toutefois **fourni** dès le MVP pour ne pas retarder la cible de production et pour valider la modélisation. Le compromis assumé : on paie plus tard une migration, pour gagner maintenant une installation en deux commandes. |
| **DuckDB ou Elasticsearch pour les événements** | DuckDB : analytique colonne performante sur fichier. Elasticsearch : recherche plein texte et agrégations à grande échelle. | Rejeté **au MVP** pour la complexité opérationnelle : Elasticsearch ajoute une grappe, du dimensionnement mémoire et de l'exploitation — l'exact opposé de « sûr à brancher avant d'avoir des credentials » ; DuckDB ne résout pas le besoin d'écriture concurrente et ajoute un modèle de stockage à maîtriser. À reconsidérer au-delà de certaines volumétries : voir [`../architecture/data-model.md`](../architecture/data-model.md). |
| **Django (+ Django REST Framework)** | Framework complet : ORM, migrations, admin, authentification, écosystème mature. | Rejeté : plus lourd, orienté application web avec gabarits et sessions, moins adapté à une API minimaliste et à un cœur qui doit rester **stdlib + `pydantic`/`PyYAML`**. Les migrations et l'admin intégrés apportent peu ici (un seul fichier SQLite), tandis que l'ORM imposerait sa couche dans le cœur et rendrait l'invariant 5 difficile à tenir. FastAPI + `pydantic` colle mieux au contrat : schéma OpenAPI 3.1 généré (`GET /openapi.json`, §4.9) et validation alignée sur les modèles. |
| **UI uniquement React (sans console embarquée)** | Une base de code front unique, plus moderne et évolutive. | Rejeté : exigerait `npm`/Vite pour toute utilisation du produit, y compris en air-gap et dans un conteneur minimal. La console Jinja2 + JS garantit qu'un `pip install` suffit ; le dashboard `web/` reste disponible comme option pour ceux qui veulent une interface riche. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
