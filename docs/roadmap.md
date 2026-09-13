# Feuille de route

*Orientation du projet par horizons — ce qui est livré dans le MVP v0.1.0, ce qui est à l'étude, et ce qui n'est pas planifié — sans engagement de date.*

!!! warning
    Cette feuille de route est **indicative**. Elle ne constitue **aucun engagement de délai**, ni
    contractuel, ni commercial. Les priorités dépendent des contributions reçues et des retours
    d'usage. Une ligne marquée « à l'étude » n'est **pas** une fonctionnalité annoncée : c'est une
    piste examinée, qui peut être écartée. Seul le
    [contrat d'interface](architecture/api-contract.md) décrit ce qui existe réellement.

---

## 1. Comment lire cette page

Trois horizons, sans dates :

| Horizon | Signification |
|---|---|
| **Maintenant** | Livré dans le MVP v0.1.0, décrit par le contrat gelé pour le sprint 1. |
| **Ensuite** | Étudié pour une version mineure suivante (v0.2). Priorité probable, sans garantie. |
| **Plus tard** | Exploré, non ordonnancé. Peut rester à l'étude durablement. |
| **Non planifié** | Explicitement hors du périmètre, y compris à long terme. |

L'ordre de présentation n'indique ni l'ordre d'arrivée, ni l'importance relative.

## 2. Livré dans le MVP v0.1.0

| Domaine | Ce qui est livré |
|---|---|
| Collecte | Collecteurs défensifs et normalisation des événements (schéma `Event` immuable, `labels` plats, `payload` borné à 32 Kio) |
| Bus | Trois implémentations : `memory`, `sqlite`, `nats` (`THOT_BUS`) |
| Détection | Moteur de règles YAML : 18 opérateurs (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `icontains`, `startswith`, `endswith`, `regex`, `exists`, `cidr`, `len_gt`, `len_lt`), logique `all`/`any`/`not`, seuils d'agrégation, déduplication |
| Compatibilité | Traduction **Sigma-lite** d'un sous-ensemble de clés Sigma, avec avertissement |
| Scoring | Score de risque 0–100 modulé par sévérité, confiance et criticité de l'actif |
| Décision | Policy-as-code YAML (+ Rego optionnel via OPA) et **5 garde-fous non contournables** (plafond horaire, cooldown, cibles protégées, priorité du dry-run, périmètre déclaré) |
| Sûreté | `DRY_RUN=true` par défaut, mode `supervised` par défaut, gate d'approbation, mode simulé des connecteurs non configurés |
| Playbooks | Bibliothèque livrée : `block-source-ip`, `rate-limit-source`, `quarantine-artifact`, `revoke-session`, `rotate-secret`, `isolate-host`, `patch-dependency`, `harden-endpoint`, `notify`, `open-ticket` — **chacun avec rollback** |
| Actions | Cycle de vie complet (`planned` → … → `succeeded`/`rolled_back`), idempotence par `idempotency_key`, expiration, rollback |
| Audit | Journal chaîné par hash, `GET /audit/verify`, export `jsonl` et `cef` |
| Accès | RBAC à 4 rôles, isolation multi-tenant testée en CI, clés API hachées (`scrypt`) affichées une seule fois |
| API | REST `/api/v1`, WebSocket `ws/stream`, `/metrics` Prometheus, sondes `/healthz` et `/readyz` |
| Console | Interface embarquée Jinja2 + JS, **aucun build Node requis** |
| CLI | `serve`, `init-db`, `doctor`, `tenant`, `key`, `rules`, `policies`, `ingest`, `findings`, `actions`, `audit`, `report`, `probe`, `demo` (`--json` partout, codes de sortie 0/1/2/3) |
| Rapports | `md`, `html`, `json`, `sarif` (SARIF 2.1.0) |
| Tests | Suite `unittest` exécutable sans dépendance externe, 12 fichiers couvrant config, stockage, audit, bus, règles, scoring, décision, actions, collecteurs, API, rapports, CLI |

## 3. Ensuite (v0.2, à l'étude)

| Piste | Ce que cela impliquerait |
|---|---|
| PostgreSQL / TimescaleDB en production | Hypertables sur les événements, compression, agrégats continus, exploitation outillée |
| Audit renforcé | Vérification incrémentale ou par arbre de Merkle, et ancrage externe (horodatage prouvable) |
| Politiques Rego durcies | Mode OPA traité comme un chemin de première classe, et non comme une option marginale |
| Connecteurs supplémentaires | Élargissement de la couverture d'exécution au-delà des WAF et pare-feux du MVP |
| Éditeur de politiques | Assistance à l'écriture et à la validation, sans introduire de configuration hors dépôt |
| Conversions Sigma plus complètes | Couverture élargie au-delà du sous-ensemble Sigma-lite actuel |
| Migrations outillées | Montée de schéma reproductible et testée, au lieu d'un `init-db` seul |
| SDK publiés | L'arborescence cible prévoit `sdks/{python,typescript,go}/` ; la **publication** sur des registres publics reste à confirmer |
| Double approbation | Deux personnes distinctes pour les actions critiques (isolation d'hôte, révocation de secret) |
| Soak time | Délai d'observation avant exécution automatique, pour laisser une chance à l'annulation |
| Garde-fous supplémentaires | Nouvelles limites non contournables, par exemple par type de playbook ou par fenêtre horaire |

!!! info "Roadmap"
    Toutes les lignes de ce tableau sont **à l'étude**. Aucune n'est disponible dans le MVP
    v0.1.0 et aucune n'a de date. Vérifiez la page [changelog.md](changelog.md) et le fichier
    `CHANGELOG.md` du dépôt pour ce qui est réellement publié.

## 4. Plus tard / à l'étude

Ces sujets sont explorés sans ordonnancement :

* **Stockage WORM / append-only** — support matériel ou logiciel d'écriture unique pour l'audit.
* **Haute disponibilité active** — plusieurs instances actives, avec le bus `nats` comme socle.
* **Multi-région** — répartition géographique et latence, avec les contraintes de résidence des données.
* **Tableaux de bord analytiques avancés** — tendances longues, comparaison entre tenants, revue de posture.
* **Marketplace de règles communautaires** — partage et installation de règles tierces, avec les questions de confiance que cela pose.
* **Pack de conformité pré-rempli** — politiques et règles prêtes à l'emploi pour SOC 2, ISO 27001, NIS2.
* **Intégrations SOAR tierces** — interopérabilité avec des plateformes de gestion de cas existantes.
* **Connecteur de tickets enrichi** — cycle de vie bidirectionnel avec un outil de tickets.

## 5. Non planifié et assumé

| Écarté | Pourquoi |
|---|---|
| **Toute capacité offensive** : scan actif, brute force, pulvérisation de mots de passe, fuzzing, « hack-back », déni de service, exploitation de tiers | C'est la contrainte constitutive du projet. Thot Secure n'agit que sur des cibles déclarées et possédées, avec des contre-mesures locales et réversibles. Voir l'ADR 0006 et les [invariants](architecture/api-contract.md) |
| **Déploiement SaaS hébergé par l'éditeur** | Le produit est **auto-hébergé** à ce stade : vos données restent chez vous (voir la [FAQ](faq.md), question 16) |

Ces deux points ne sont pas des « pas encore » : ils ne sont pas au programme.

!!! danger
    Une contribution qui ajoute une capacité offensive est refusée sans revue de fond.
    Voir [contributing.md](contributing.md) et [governance.md](governance.md).

## 6. Comment influencer la feuille de route

* **Ouvrir une discussion ou une issue** — un besoin d'usage argumenté pèse plus qu'un vote.
* **Contribuer une règle de détection** — c'est la contribution la plus directement utile (voir [detection/rules.md](detection/rules.md)).
* **Contribuer un connecteur ou un playbook** — avec rollback obligatoire et mode simulé par défaut (voir [actions/playbooks.md](actions/playbooks.md)).
* **Participer à la revue** — relire les pull requests, en particulier celles qui touchent `audit/`, `tenancy/`, `decision/` et `actions/`.
* **Suivre la gouvernance** — le canal et les règles de décision sont décrits dans [governance.md](governance.md).

Les dons financent l'infrastructure du projet (CI, hébergement des artefacts) et, le cas échéant,
des audits externes. Ils sont volontaires, sans contrepartie, et n'achètent ni priorité ni
influence sur la sécurité du produit. Détails : [support.md](support.md).

## 7. Correspondance roadmap → document

| Élément de roadmap | Où c'est documenté |
|---|---|
| Invariants non négociables | [architecture/api-contract.md](architecture/api-contract.md) §1 |
| Dry-run par défaut | [ADR 0003](adr/0003-dry-run-par-defaut-et-approbation-humaine.md), [architecture/api-contract.md](architecture/api-contract.md) §1 |
| Bus d'événements `memory`/`sqlite`/`nats` | [ADR 0005](adr/0005-bus-pluggable-memory-sqlite-nats.md) |
| Postgres / TimescaleDB | [architecture/data-model.md](architecture/data-model.md) |
| Garde-fous de décision | [decision/policies.md](decision/policies.md) |
| Playbooks et rollback | [actions/playbooks.md](actions/playbooks.md) |
| Règles et Sigma-lite | [detection/rules.md](detection/rules.md) |
| Exploitation, montée de version | [operations/deployment.md](operations/deployment.md) |
| Conformité SOC 2 / ISO 27001 / NIS2 | [compliance/soc2-iso27001.md](compliance/soc2-iso27001.md) |
| Zéro capacité offensive (ADR 0006) | Série d'ADR : [adr/0001-record-architecture-decisions.md](adr/0001-record-architecture-decisions.md) |
| Processus de décision et contributions | [governance.md](governance.md), [contributing.md](contributing.md) |
| Publications de versions | [changelog.md](changelog.md) et `CHANGELOG.md` (racine) |

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
