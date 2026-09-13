# Architecture — vue d'ensemble

*Comment Thot Secure est construit : contexte, conteneurs, composants du pipeline, séquence d'une mitigation automatique, cycle de vie d'une action et modèles de déploiement.*

Cette page explique le **fonctionnement**. Elle ne redéfinit **aucun** schéma de données, **aucune**
route et **aucune** variable : la référence normative est le
[contrat d'interface](api-contract.md) (gelé pour le sprint 1), complété par le
[modèle de données](data-model.md) pour les tables et le DDL. Quand une information n'est pas
fixée par le contrat, elle est signalée comme telle plutôt que devinée.

## Principes de conception

| Principe | Traduction concrète |
|---|---|
| **Défensif par construction** | Il n'existe pas de code d'attaque dans le produit : pas de scan agressif, pas de brute force, pas de hack-back. Voir l'[ADR 0006](../adr/0006-zero-capacite-offensive-comme-invariant.md). |
| **Sûr par défaut** | `DRY_RUN=true`, `AUTONOMY=supervised`, connecteurs non configurés en **mode simulé**, cibles protégées déclarées. |
| **Réversible** | Tout playbook est accompagné d'un rollback ; `POST /actions/{id}/rollback` doit réussir tant que le rollback n'a pas expiré. |
| **Traçable** | Journal **append-only chaîné par hash** ; chaque décision référence sa `policy_id`, chaque action son `audit_seq`. |
| **Isolé** | Tout objet porte un `tenant_id` ; toute requête SQL filtre dessus ; un test dédié le vérifie en CI. |
| **Portable** | Le cœur (`thotsecure.core`) ne dépend que de la **stdlib** + `pydantic`/`PyYAML`. FastAPI, Jinja2 et uvicorn sont des dépendances de la couche API. |
| **Enfichable** | Bus `memory` \| `sqlite` \| `nats` ; persistance SQLite au MVP, PostgreSQL/TimescaleDB comme cible de production ; Rego/OPA en option. |

## 1. Contexte (C4 niveau 1)

Qui utilise Thot Secure, et avec quoi il interagit. Rien de ce qui est à droite n'est attaqué :
ce sont soit des **sources** de signaux, soit des **destinations** d'actions autorisées.

```mermaid
flowchart TB
  subgraph Humains["Utilisateurs"]
    AN["Analyste SOC<br/>trie, qualifie, approuve"]
    ING["Ingénieur sécurité<br/>écrit règles et politiques"]
    MSSP["MSSP<br/>exploite plusieurs tenants"]
  end

  AO["<b>Thot Secure</b><br/>SOAR/CSPM défensif<br/>collecte · détection · scoring<br/>décision · action réversible · audit"]

  subgraph Sources["Sources de signaux (lecture seule)"]
    EDGE["Reverse-proxy / WAF<br/>logs HTTP"]
    HOSTS["Serveurs et applications<br/>journaux, syslog"]
    TLS["Certificats TLS<br/>expiration, chaîne"]
    DEPS["Dépendances<br/>manifestes, avis"]
    CFG["Configurations<br/>durcissement, exposition"]
  end

  subgraph Actions["Destinations d'actions (périmètre déclaré)"]
    WAF["WAF / pare-feu<br/>Cloudflare, AWS WAF,<br/>ModSecurity, Nginx local"]
    EDR["EDR<br/>isolation d'hôte"]
    IAM["IAM / coffre<br/>révocation, rotation"]
    TICK["Ticketing / webhook<br/>notification"]
  end

  SIEM["SIEM<br/>export jsonl / cef"]
  OPA["OPA (option)<br/>politiques Rego"]
  NATS["NATS (option)<br/>bus distribué"]

  AN --> AO
  ING --> AO
  MSSP --> AO

  EDGE --> AO
  HOSTS --> AO
  TLS --> AO
  DEPS --> AO
  CFG --> AO

  AO --> WAF
  AO --> EDR
  AO --> IAM
  AO --> TICK
  AO --> SIEM
  AO -.-> OPA
  AO -.-> NATS
```

!!! warning "Lire ce schéma correctement"

    Les flèches sortantes ne signifient pas « Thot Secure peut agir partout ». Une action n'est
    exécutée que si **cinq garde-fous** l'autorisent : plafond horaire par tenant, cooldown
    par couple (playbook, cible), cibles protégées jamais modifiées, dry-run global
    prioritaire, et approbation obligatoire hors périmètre déclaré. Voir
    [les 5 garde-fous](../decision/policies.md#les-5-garde-fous-non-contournables).

## 2. Conteneurs (C4 niveau 2)

Les briques exécutables et leur responsabilité. Les noms de modules correspondent à
l'arborescence cible du contrat (section 2).

```mermaid
flowchart TB
  subgraph Interfaces["Interfaces"]
    UI["Console embarquée<br/>Jinja2 + JS — aucun build Node"]
    WEB["Dashboard React + TS<br/>optionnel, build Vite"]
    API["API FastAPI — /api/v1<br/>REST + WebSocket + /metrics"]
    CLI["CLI thotsecure"]
    SDK["SDK Python officiel<br/>+ sdks/{typescript,go}"]
  end

  subgraph Coeur["Cœur applicatif — stdlib + pydantic/PyYAML"]
    COLL["collectors/<br/>collecte + normalisation"]
    DET["detection/<br/>règles YAML + Sigma-lite"]
    SCO["scoring/<br/>risk_score 0-100"]
    DEC["decision/<br/>policy-as-code + garde-fous"]
    ACT["actions/<br/>playbooks, exécuteurs, rollback"]
    TEN["tenancy/<br/>tenants, clés API, RBAC"]
    AUD["audit/<br/>journal chaîné append-only"]
    REP["reports/<br/>md · html · json · sarif · cef"]
    BUS["bus/<br/>memory | sqlite | nats"]
    STO["storage/<br/>SQLite (MVP) + DDL PostgreSQL"]
  end

  subgraph Externe["Externe (optionnel ou cible)"]
    PG["PostgreSQL / TimescaleDB<br/>cible de production"]
    NATS2["NATS"]
    OPAS["Binaire OPA"]
  end

  UI --> API
  WEB --> API
  CLI --> API
  SDK --> API
  API --> TEN
  API --> COLL
  API --> DET
  API --> DEC
  API --> ACT
  API --> AUD
  API --> REP
  COLL --> BUS
  BUS --> DET
  DET --> SCO
  SCO --> DEC
  DEC --> ACT
  ACT --> AUD
  DEC --> AUD
  TEN --> STO
  COLL --> STO
  DET --> STO
  ACT --> STO
  AUD --> STO
  STO -.-> PG
  BUS -.-> NATS2
  DEC -.-> OPAS
```

### Responsabilités par module

| Module | Rôle | Points d'attention |
|---|---|---|
| `core/` | Configuration, modèles, erreurs, utilitaires | Ne dépend que de la stdlib + `pydantic`/`PyYAML` (invariant) |
| `storage/` | Persistance SQLite, DDL, rétention | Un seul écrivain avec SQLite → voir [dimensionnement](../operations/deployment.md) |
| `bus/` | Transport des événements | `memory` ne persiste **rien** ; `nats` ajoute une dépendance à exploiter |
| `audit/` | Journal chaîné, vérification, export | Append-only : aucune mise à jour, aucune suppression applicative |
| `tenancy/` | Tenants, clés API (hachées scrypt), capacités | Frontière d'isolation de tout le produit |
| `collectors/` | Collecte défensive + normalisation en `Event` | `probe` n'audite que les cibles déclarées du tenant |
| `detection/` | Moteur de règles YAML, seuils, dédup, Sigma-lite | Une règle invalide est rejetée avec diagnostic, sans casser le chargement |
| `scoring/` | Score de risque borné (sévérité, confiance, criticité d'actif) | Monotonie et bornes testées |
| `decision/` | Policy-as-code + gate d'approbation + garde-fous | Aucune politique ne contourne un garde-fou |
| `actions/` | Playbooks, exécuteurs, connecteurs, rollback | Mode simulé par défaut ; rollback obligatoire |
| `reports/` | Artefacts `md`, `html`, `json`, `sarif`, `cef` | SARIF 2.1.0 exploitable par GitHub Code Scanning |
| `api/` | REST v1, WebSocket, `/metrics`, RBAC | Exige `X-API-Key` ; le WS accepte `?api_key=` |
| `ui/` | Console embarquée sans étape de build | Utile en air-gap et sur un serveur sans Node |
| `cli.py` | Interface d'exploitation et d'automatisation | Codes de sortie 0/1/2/3, `--json` partout |

## 3. Composants du pipeline

Le trajet d'un fait brut jusqu'à la trace d'audit. Chaque flèche est un point où l'on peut
**observer** (métriques, journaux, WebSocket) et **rejouer** (idempotence, rollback).

```mermaid
flowchart LR
  SRC["Sources<br/>HTTP · logs · TLS · deps · config"] --> COL["Collecteurs<br/>défensifs"]
  COL --> NORM["Normalisation<br/>schema_version, tenant_id"]
  NORM --> BUS2["Bus<br/>memory · sqlite · nats"]
  BUS2 --> DET2["Détection<br/>règles YAML + Sigma-lite"]
  DET2 --> SCO2["Scoring<br/>risk_score 0-100"]
  SCO2 --> DEC2["Décision<br/>politiques par priorité"]
  DEC2 --> GF{"5 garde-fous"}
  GF -->|refus| AUD2["Audit<br/>trace du refus"]
  GF -->|auto| EXE["Exécution<br/>playbook"]
  GF -->|require_approval| APPR["Approbation<br/>humaine"]
  APPR -->|approved| EXE
  APPR -->|rejected| AUD2
  GF -->|notify_only| NOT["Notification<br/>webhook · ticket"]
  EXE --> CONN["Connecteurs<br/>WAF · EDR · IAM · ticketing<br/>ou mode simulé"]
  CONN --> RB["Rollback<br/>disponible, expiration"]
  RB --> AUD2
  NOT --> AUD2
  AUD2 --> EXP["Export<br/>jsonl · cef"]
  AUD2 --> REP2["Rapports<br/>md · html · json · sarif"]
```

| Étape | Entrée | Sortie | Où c'est défini |
|---|---|---|---|
| Collecte | Système source | `Event` normalisé | [Contrat §3.1](api-contract.md#31-event) |
| Détection | `Event` + règles | `Finding` | [Contrat §5](api-contract.md#5-format-des-regles-de-detection-yaml) · [guide des règles](../detection/rules.md) |
| Scoring | `Finding` | `risk_score` ∈ [0, 100] | [Contrat §5](api-contract.md#5-format-des-regles-de-detection-yaml) (`risk.base`) |
| Décision | `Finding` + politiques + tenant | `Decision` | [Contrat §6](api-contract.md#6-format-des-politiques-policy-as-code) · [politiques](../decision/policies.md) |
| Action | `Decision` | `Action` + rollback | [Contrat §3.4](api-contract.md#34-action) · [playbooks](../actions/playbooks.md) |
| Audit | Toute transition | `AuditRecord` chaîné | [Contrat §3.5](api-contract.md#35-auditrecord) |

## 4. Séquence d'une mitigation automatique

Le cas nominal : une attaque web détectée sur un actif critique, une politique `auto`, un
connecteur réel, puis un rollback automatique après expiration.

```mermaid
sequenceDiagram
  autonumber
  participant C as Collecteur
  participant A as API /api/v1
  participant B as Bus
  participant D as Détection + Scoring
  participant P as Décision (politiques + garde-fous)
  participant X as Exécuteur de playbook
  participant K as Connecteur (WAF)
  participant AU as Audit chaîné
  participant W as Console / WebSocket

  C->>A: POST /events (Event normalisé)
  A->>A: tenant_id forcé depuis la clé API
  A->>AU: écriture du record d'ingestion (chaîné)
  A->>B: publication de l'événement
  A-->>C: 202 {accepted, rejected, findings[]}
  B->>D: consommation
  D->>D: évaluation des règles (all / any / not, seuils)
  D->>D: création/mise à jour du Finding + risk_score
  D->>AU: trace de détection (rule_id, risk_score)
  D->>W: frame {"type":"finding"}
  D->>P: finding à décider
  P->>P: politiques par priorité (première correspondance)
  P->>P: 5 garde-fous (plafond, cooldown, cibles protégées,<br/>dry-run global, périmètre déclaré)
  alt décision = auto et garde-fous OK
    P->>X: Action (planned → approved)
  else décision = require_approval ou hors périmètre
    P->>W: Action en pending_approval (attente humaine)
    Note over W,X: l'exécution n'a lieu qu'après POST /actions/{id}/approve
  else décision = notify_only ou ignore
    P->>AU: trace du non-agissement (policy_id)
  end
  X->>K: block_ip(ip, ttl, note)
  alt connecteur configuré
    K-->>X: résultat réel + rollback_token
  else connecteur non configuré (défaut du MVP)
    K-->>X: mode simulé — simulated: true + rollback_token
  end
  X->>AU: before/after de l'action (chaîné)
  X->>W: frame {"type":"action"}
  Note over X,K: rollback planifié (auto_after_seconds)
  X->>K: unblock_ip(ip) après expiration
  X->>AU: trace du rollback (chaîné)
  W-->>W: frames {"type":"audit"} et {"type":"heartbeat"}
```

| Point de contrôle | Ce que le contrat garantit |
|---|---|
| `tenant_id` | **Forcé depuis la clé API**, jamais depuis le corps de la requête |
| Réponse d'ingestion | `202` avec `accepted`, `rejected`, `event_ids` et la liste des findings produits (avec leur `decision`) |
| Idempotence d'exécution | `execute` est idempotent via `idempotency_key` |
| Approbation manquante | `execute` sur une action `pending_approval` non approuvée → **`409`** |
| Rollback | Refusé si déjà `rolled_back` → **`409`** ; il doit réussir tant que le rollback n'a pas expiré |
| Traçabilité | Chaque décision porte `policy_id` ; chaque action porte `audit_seq` |

!!! note "Détails laissés à l'implémentation"

    Le contrat fixe les **transitions et les contrats d'interface**, pas l'ordonnancement
    interne (écriture de l'audit avant ou après l'appel au connecteur, exécution synchrone
    ou en tâche de fond, comportement exact en cas d'échec partiel d'un playbook). Ces
    points se lisent dans `src/thotsecure/actions/` et `src/thotsecure/decision/` : la page
    [playbooks](../actions/playbooks.md) décrit le comportement attendu et signale les zones
    à confirmer.

## 5. Cycle de vie d'une Action

Les neuf états du contrat (section 3.4) et leurs transitions. Le détail opérationnel, les
codes d'erreur et les routes est dans [Playbooks et connecteurs](../actions/playbooks.md).

```mermaid
stateDiagram-v2
  [*] --> planned: POST /actions/plan
  planned --> pending_approval: politique = require_approval
  planned --> approved: politique = auto (mode auto du tenant)
  pending_approval --> approved: POST /actions/{id}/approve
  pending_approval --> rejected: POST /actions/{id}/reject
  approved --> executing: POST /actions/{id}/execute
  executing --> succeeded: exécution réussie
  executing --> failed: erreur du connecteur
  planned --> expired: délai dépassé
  approved --> expired: délai dépassé avant exécution
  succeeded --> rolled_back: POST /actions/{id}/rollback
  failed --> rolled_back: rollback de nettoyage
  rejected --> [*]
  expired --> [*]
  rolled_back --> [*]
  succeeded --> [*]
  failed --> [*]
```

| État | Signification | Sortie possible |
|---|---|---|
| `planned` | Action préparée, **aucun effet de bord** | `pending_approval`, `approved`, `expired` |
| `pending_approval` | En attente d'un humain | `approved`, `rejected` |
| `approved` | Autorisée, pas encore exécutée | `executing`, `expired` |
| `rejected` | Refusée — **terminal** | — |
| `executing` | En cours d'exécution | `succeeded`, `failed` |
| `succeeded` | Appliquée (réellement ou en simulation, selon `dry_run`/`simulated`) | `rolled_back` |
| `failed` | Échec d'exécution | `rolled_back` (nettoyage) |
| `expired` | Fenêtre d'exécution dépassée | — |
| `rolled_back` | Annulée — **terminal** | — |

!!! warning "Une action `executing` qui ne se termine jamais est un incident"

    C'est le cas le plus insidieux : le connecteur a peut-être appliqué la contre-mesure alors
    qu'Thot Secure croit encore l'action en cours. Procédure :
    [action bloquée en `executing`](../operations/runbook.md#6-action-bloquee-en-executing).

## 6. Modèle de déploiement

```mermaid
flowchart TB
  subgraph M["A. Mono-nœud (labo, PME, pilote)"]
    direction LR
    M1["thotsecure serve<br/>+ SQLite<br/>+ bus memory/sqlite"]
  end

  subgraph D2["B. Conteneur (recommandé pour un pilote)"]
    direction LR
    D3["Image Thot Secure"] --> D4["Volume de données<br/>data/thotsecure.db"]
    D5["Reverse-proxy TLS"] --> D3
  end

  subgraph K["C. Kubernetes / Helm"]
    direction LR
    K1["Ingress TLS"] --> K2["Deployment<br/>replicaCount 1 (SQLite)"]
    K2 --> K3["PVC — base SQLite"]
    K4["Secrets<br/>THOT_SECRET_KEY"] --> K2
  end

  subgraph N2["D. MSSP multi-sites"]
    direction LR
    N3["Collecteurs sur site"] --> N4["Bus NATS"]
    N4 --> N5["Thot Secure central<br/>un tenant par client"]
    N5 --> N6["PostgreSQL / TimescaleDB<br/>cible de production"]
  end
```

| Modèle | Adapté à | Limite à connaître |
|---|---|---|
| **A. Mono-nœud** | Découverte, labo, PME | Un seul écrivain (SQLite) ; pas de haute disponibilité |
| **B. Conteneur** | Pilote, déploiement reproductible | TLS délégué au reverse-proxy ; état sur un volume |
| **C. Kubernetes** | Industrialisation, GitOps | **`replicaCount: 1`** tant que la base est SQLite (pas de PVC partagé) |
| **D. MSSP multi-sites** | Plusieurs clients | Nécessite NATS ; PostgreSQL/TimescaleDB pour tenir la charge (roadmap) |

!!! info "Roadmap"

    La haute disponibilité active (plusieurs réplicas applicatifs, bascule automatique) et le
    stockage PostgreSQL/TimescaleDB en production ne font pas partie du MVP v0.1.0 : le DDL
    PostgreSQL est fourni **comme cible** dans le [modèle de données](data-model.md), mais
    l'exploitation reste mono-nœud. Voir [Déploiement](../operations/deployment.md) et la
    [feuille de route](../roadmap.md).

## Pour aller plus loin

| Sujet | Où |
|---|---|
| Toutes les routes, schémas et variables (référence normative) | [Contrat d'interface](api-contract.md) |
| Tables, index, DDL SQLite et PostgreSQL | [Modèle de données](data-model.md) |
| Menaces, abuse cases, invariants de conception | [Modèle de menaces (STRIDE)](threat-model.md) |
| Pourquoi ces choix techniques (et leurs inconvénients) | [ADR](../adr/0001-record-architecture-decisions.md) |
| Politiques et garde-fous | [Politiques de décision](../decision/policies.md) |
| Playbooks, connecteurs, mode simulé | [Playbooks et connecteurs](../actions/playbooks.md) |
| Dimensionnement, sauvegarde, supervision | [Déploiement](../operations/deployment.md) |

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
