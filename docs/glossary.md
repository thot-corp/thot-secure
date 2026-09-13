# Glossaire FR/EN

*Vocabulaire partagé d'Thot Secure : chaque terme est défini en français, avec son sigle développé en anglais et l'endroit du produit où il apparaît.*

Les définitions reprennent le [contrat d'interface v0.1.0](architecture/api-contract.md). Quand un
terme est d'usage courant mais **absent** du contrat, c'est signalé : il ne faut pas le supposer
implémenté.

---

## 1. Architecture, tenants et périmètre

| Terme | Sigle développé (EN) | Définition | Où dans Thot Secure |
|---|---|---|---|
| **tenant** | — | Frontière d'isolation : un client MSP, une business unit, un laboratoire. Tout objet (événement, finding, action, enregistrement d'audit) porte un `tenant_id`. | Modèle `Tenant`, `/api/v1/tenants`, `thotsecure tenant create` |
| **isolation multi-tenant** | Multi-tenant isolation | Garantie qu'un appelant ne voit jamais les données d'un autre tenant : chaque requête SQL filtre `tenant_id`. C'est l'invariant n° 4, vérifié par des tests dédiés. | `tests/test_storage.py`, `tests/test_api.py`, paquet `tenancy/` |
| **bus d'événements** | Event bus | Canal de transport interne des événements, entre collecte et détection. Trois implémentations : `memory`, `sqlite`, `nats`. | `THOT_BUS`, `GET /readyz`, paquet `bus/` |
| **NATS** | NATS Messaging System *(nom propre)* | Serveur de messagerie léger utilisé comme bus distribué, pour plusieurs instances Thot Secure. Client embarqué, sans dépendance lourde. | `THOT_BUS=nats`, `THOT_NATS_URL` |
| **collecteur** | Collector | Composant défensif qui produit des événements normalisés depuis une source autorisée (sonde HTTP sur ses propres cibles, suivi de fichiers de logs, inventaire de dépendances, audit de configuration). | `GET /api/v1/collectors`, `POST /api/v1/collectors/{name}/run`, paquet `collectors/` |
| **connecteur** | Connector | Adaptateur d'exécution vers un système externe (WAF, pare-feu, fournisseur cloud, messagerie, outil de tickets). Un connecteur non configuré fonctionne en **mode simulé**. | Bloc `connectors` des playbooks, `connectors: [cloudflare, aws-waf, modsecurity, nginx-local, null]` |
| **périmètre déclaré** | Declared scope | Liste des cibles qu'un tenant possède ou est autorisé à opérer, dans `config/targets.yaml`. Hors de ce périmètre, toute action devient `require_approval` (garde-fou n° 5). | `THOT_TARGETS_FILE`, `thotsecure probe` |
| **CIDR** | Classless Inter-Domain Routing | Notation d'une plage d'adresses IP (`10.0.0.0/8`). Utilisée pour les allowlists de cibles protégées et pour l'opérateur de règle `cidr`. | `autonomy_allowlist`, opérateur `cidr` (contrat §5) |
| **SOAR** | Security Orchestration, Automation and Response | Catégorie d'outils qui orchestrent détection, décision et réponse. Thot Secure est un SOAR **défensif**, avec contre-mesures réversibles uniquement. | Positionnement du projet, `actions/` |
| **CSPM** | Cloud Security Posture Management | Suivi de la conformité et de la configuration des environnements cloud (exposition, mauvaises configurations). | Collecteur `config_audit`, kind `config.audit` |
| **SIEM** | Security Information and Event Management | Plateforme centrale de collecte, corrélation et rétention de journaux. Thot Secure s'y intègre par l'ingestion d'événements et l'export du journal d'audit. | `POST /api/v1/events`, `GET /api/v1/audit/export` |
| **EDR** | Endpoint Detection and Response | Détection et réponse sur les postes et serveurs. Thot Secure s'y connecte comme orchestrateur, il n'est pas un agent EDR. | Playbooks `isolate-host`, `harden-endpoint` |
| **WAF** | Web Application Firewall | Pare-feu applicatif web. Principal point d'application des contre-mesures réseau du MVP. | Playbook `block-source-ip`, connecteurs `cloudflare`, `aws-waf`, `modsecurity` |

## 2. Données, détection et scoring

| Terme | Sigle développé (EN) | Définition | Où dans Thot Secure |
|---|---|---|---|
| **événement** | Event | Fait brut **normalisé** et **immuable** émis par un collecteur : `event_id`, `tenant_id`, `ts`, `kind`, `source`, `severity_hint`, `labels`, `payload`. | `POST /api/v1/events`, schéma 3.1 |
| **finding** | Finding | **Agrégat d'événements** déclenché par une règle, porteur d'un `risk_score`, d'une `confidence`, d'un statut et d'une `evidence`. C'est l'unité de travail d'un analyste. | `GET /api/v1/findings`, schéma 3.2 |
| **règle de détection** | Detection rule | Règle YAML qui décrit ce qu'il faut détecter : `match` (`all`/`any`/`not`, 18 opérateurs), seuil d'agrégation, `dedup`, base de risque, faux positifs connus, remédiation. | `rules/`, `POST /api/v1/rules/validate`, [detection/rules.md](detection/rules.md) |
| **déduplication** | Deduplication | Regroupement d'événements identiques ou proches dans un même finding, selon une clé et une fenêtre de temps (`dedup.key`, `dedup.ttl_seconds`, défaut 900 s). | Bloc `dedup` des règles, compteur `count` du finding |
| **scoring de risque** | Risk score | Note de 0 à 100 calculée à partir de la base de la règle, modulée par la sévérité, la confiance et la criticité de l'actif. Détermine les politiques applicables. | `risk_score`, paquet `scoring/`, `tests/test_risk_scoring.py` |
| **evidence** | Evidence | Échantillons d'événements conservés avec le finding pour permettre la revue a posteriori, sans avoir à rejouer toute la collecte. | `finding.evidence.samples` |
| **Sigma** | Sigma *(nom propre)* | Format ouvert et générique de règles de détection, largement échangeable entre outils. | Compatibilité **Sigma-lite** (contrat §5) |
| **logsource** | Log source | Description de la source de journal visée par une règle (produit, service, catégorie). Clé du sous-ensemble Sigma traduit automatiquement. | Clé `logsource` en Sigma-lite |
| **ReDoS** | Regular Expression Denial of Service | Déni de service provoqué par une expression régulière pathologique sur une entrée forgée. Thot Secure compile les regex de règle avec un **timeout d'exécution**. | Contrat §10, moteur de règles, `tests/test_rules_engine.py` |
| **IOC** | Indicator of Compromise | Indicateur technique de compromission (adresse, empreinte, domaine) utilisé pour la détection. | *Non décrit par le contrat v0.1.0* : aucun flux d'IOC n'est livré au MVP |
| **curseur** | Cursor pagination | Jeton opaque de pagination, plus stable qu'un décalage numérique sur des données qui arrivent en continu. | Paramètre `cursor` des listes : événements, findings, actions, audit (`limit` ≤ 500) |

!!! info "Roadmap"
    La gestion de flux d'IOC (import, enrichissement, expiration) n'est pas au programme du MVP.
    Une règle YAML peut en revanche exprimer une détection sur liste explicite via l'opérateur
    `in`. Voir [roadmap.md](roadmap.md).

## 3. Décision, action et garde-fous

| Terme | Sigle développé (EN) | Définition | Où dans Thot Secure |
|---|---|---|---|
| **politique** | Policy | Règle de **décision** écrite en YAML (ou en Rego via OPA) : `when` décrit la condition, `then` la décision et ses paramètres, `rollback` l'annulation. | `policies/`, [decision/policies.md](decision/policies.md) |
| **policy-as-code** | Policy as Code | Principe de gestion : les politiques de décision vivent dans le dépôt, sont versionnées, revues et testées comme du code — pas cliquées dans une interface. | `THOT_POLICIES_DIR`, `thotsecure policies validate` |
| **decision** | Decision | Verdict du moteur, l'une de quatre valeurs : `auto` (exécuter), `require_approval` (attendre un humain), `notify_only` (signaler sans agir), `ignore` (silence explicite). | Schéma 3.3, `Decision.decision` |
| **autonomy** | Autonomy mode | Niveau d'autonomie du tenant : `manual`, `supervised` (défaut), `auto`. Un mode `auto` peut n'être activé qu'explicitement, au niveau du tenant. | `THOT_AUTONOMY`, `Tenant.mode` |
| **playbook** | Playbook | Procédure d'action nommée, **toujours** accompagnée d'un rollback : paramètres typés, étapes d'exécution, étapes d'annulation, sévérité d'audit et notifications. | `playbooks/`, `GET /api/v1/playbooks`, [actions/playbooks.md](actions/playbooks.md) |
| **rollback** | Rollback | Annulation d'une action déjà exécutée. Invariant n° 3 : `POST /api/v1/actions/{id}/rollback` doit réussir tant que le rollback n'a pas expiré. | `Action.rollback`, `thotsecure actions rollback`, `tests/test_actions_rollback.py` |
| **garde-fou** | Guardrail | Contrôle appliqué par le **moteur de décision**, non contournable par une politique : plafond horaire, cooldown, cibles protégées, priorité du dry-run global, périmètre déclaré. | Contrat §6, paquet `decision/`, `tests/test_decision.py` |
| **cooldown** | Cooldown | Délai minimal entre deux actions identiques sur un triplet `(tenant, playbook, cible)`, pour empêcher les boucles de riposte. | `then.cooldown_seconds`, `Decision.cooldown_seconds` |
| **DRY_RUN** | Dry run | Mode simulation global : aucune action réelle n'est exécutée. **Vrai par défaut** (invariant n° 1) et **prioritaire sur toute politique** (garde-fou n° 4). | `THOT_DRY_RUN`, `Action.dry_run`, `Decision.dry_run` |
| **idempotence** | Idempotency / idempotency key | Propriété d'une opération qui, rejouée avec la même clé, ne produit pas un second effet. Évite les doubles blocages lors d'un retry réseau. | `Action.idempotency_key` (ex. `acme:block-source-ip:203.0.113.9:1739527200`) |
| **action** | Action | **Instance d'exécution** d'un playbook sur un finding, avec cycle de vie (`planned`, `pending_approval`, `approved`, `rejected`, `executing`, `succeeded`, `failed`, `expired`, `rolled_back`) et `audit_seq`. | Schéma 3.4, `POST /api/v1/actions/plan` |
| **least privilege** | Principle of Least Privilege | Principe de moindre privilège : chaque rôle et chaque jeton ne reçoit que les capacités nécessaires. | Rôles `viewer`/`analyst`/`responder`/`admin`, capacités `read:*`, `write:*`, `execute:actions`, `approve:actions`, `admin:*` |

## 4. Sécurité, accès et audit

| Terme | Sigle développé (EN) | Définition | Où dans Thot Secure |
|---|---|---|---|
| **audit log** / **hash chain** | Audit log / Hash chain | Journal **append-only** où chaque enregistrement contient le hash du précédent : `hash = sha256(seq\|ts\|tenant_id\|actor\|actor_role\|action\|target\|before\|after\|prev_hash)`. Toute modification casse la chaîne. | `GET /api/v1/audit`, `GET /api/v1/audit/verify`, paquet `audit/` |
| **RBAC** | Role-Based Access Control | Contrôle d'accès par rôle : quatre rôles, chacun cumulant les capacités du précédent, appliqué par dépendance FastAPI **et** revérifié dans le core. | Contrat §4, `tests/test_api.py` |
| **API key** | Application Programming Interface Key | Jeton d'authentification préfixé `ao_`, présenté dans l'en-tête `X-API-Key`. **Affiché une seule fois** à la création, stocké **haché**, révocable immédiatement. | `POST /api/v1/tenants/{id}/keys`, `thotsecure key create`, `DELETE /api/v1/keys/{key_id}` |
| **scrypt** | scrypt *(nom propre)* | Fonction de dérivation de clé, lente et coûteuse en mémoire, utilisée pour le stockage **haché** des clés API — jamais en clair. | Contrat §10, paquet `tenancy/` |
| **pseudonymisation** | Pseudonymisation | Traitement qui rend une donnée personnelle non attribuable directement à une personne sans information supplémentaire conservée séparément. Un `actor` d'audit ou une adresse IP source en sont des exemples typiques en contexte RGPD. | Journal d'audit, `labels.src_ip`, [compliance/rgpd.md](compliance/rgpd.md) |
| **AIPD** / **DPIA** | Data Protection Impact Assessment | Analyse d'impact relative à la protection des données : obligatoire lorsqu'un traitement est susceptible d'engendrer un risque élevé, notamment en cas de surveillance systématique. | Démarche de conformité, [compliance/rgpd.md](compliance/rgpd.md) |
| **MTTA** | Mean Time To Acknowledge | Temps moyen entre la création d'un finding et sa prise en charge (`acked`). Mesure la réactivité humaine, pas la performance du moteur. | `GET /api/v1/stats/overview` |
| **MTTR** | Mean Time To Respond / Resolve | Temps moyen de traitement d'un finding, de la détection à la clôture ou à la remédiation. | `GET /api/v1/stats/overview` |
| **MTTD** | Mean Time To Detect | Temps moyen entre l'occurrence réelle d'un incident et sa détection. | *Non exposé par le contrat v0.1.0* : il suppose une vérité terrain que le MVP ne modélise pas |
| **TLS** | Transport Layer Security | Chiffrement en transit. Assuré par un reverse-proxy, ou en direct avec `THOT_TLS_ENABLED=true`. | `THOT_TLS_ENABLED`, [operations/deployment.md](operations/deployment.md) |

## 5. Formats, interopérabilité et interfaces

| Terme | Sigle développé (EN) | Définition | Où dans Thot Secure |
|---|---|---|---|
| **CEF** | Common Event Format | Format d'export de journaux d'événements, lisible par la plupart des SIEM. Utilisé pour l'export du journal d'audit. | `GET /api/v1/audit/export?format=cef`, `reports/cef` |
| **SARIF** | Static Analysis Results Interchange Format | Format d'échange de résultats d'analyse statique (version 2.1.0), exploité par GitHub Code Scanning. Pertinent pour les findings d'analyse de dépendances et de configuration. | `GET /api/v1/findings/{id}/report?format=sarif`, `tests/test_reports.py` |
| **webhook** | Webhook | Appel HTTP sortant déclenché par un événement (notification, création de ticket), sans protocole dédié. | Bloc `audit.notify: [webhook, ticket]` des playbooks |
| **WebSocket** | WebSocket | Canal bidirectionnel persistant, ici pour le flux temps réel (nouveaux événements, findings, actions, audit, battement de cœur). | `WS /api/v1/ws/stream`, `?api_key=…` |
| **OPA** / **Rego** | Open Policy Agent / Rego | Moteur de politiques générique et son langage déclaratif. Mode **optionnel** : il faut définir `THOT_OPA_BIN` et que le binaire soit présent. | `THOT_OPA_BIN`, `policies/rego/thotsecure.rego` |
| **TimescaleDB** / **hypertable** | TimescaleDB / Hypertable | Extension PostgreSQL pour séries temporelles ; une *hypertable* partitionne automatiquement les données par le temps. Cible de production pour les événements. | DDL dans `storage/`, `THOT_DB_URL`, [architecture/data-model.md](architecture/data-model.md) |

!!! note
    Le MVP fonctionne sur SQLite. PostgreSQL/TimescaleDB est la cible de production : voyez
    [roadmap.md](roadmap.md) avant de dimensionner un déploiement sur ce socle.

---

## Sigles par ordre alphabétique

* **AIPD** — *Analyse d'Impact relative à la Protection des Données* (EN : DPIA)
* **API** — *Application Programming Interface*
* **CEF** — *Common Event Format*
* **CIDR** — *Classless Inter-Domain Routing*
* **CSPM** — *Cloud Security Posture Management*
* **DPIA** — *Data Protection Impact Assessment*
* **DRY_RUN** — *Dry run* (simulation sans effet de bord)
* **EDR** — *Endpoint Detection and Response*
* **IOC** — *Indicator of Compromise*
* **MTTA** — *Mean Time To Acknowledge*
* **MTTD** — *Mean Time To Detect* (non exposé au MVP)
* **MTTR** — *Mean Time To Respond / Resolve*
* **NATS** — *NATS Messaging System*
* **OPA** — *Open Policy Agent*
* **RBAC** — *Role-Based Access Control*
* **ReDoS** — *Regular Expression Denial of Service*
* **Rego** — langage de politiques d'OPA
* **SARIF** — *Static Analysis Results Interchange Format*
* **SIEM** — *Security Information and Event Management*
* **SOAR** — *Security Orchestration, Automation and Response*
* **SOC** — *Security Operations Center*
* **TLS** — *Transport Layer Security*
* **WAF** — *Web Application Firewall*
* **WS** — *WebSocket*

## Où aller plus loin

| Sujet | Page |
|---|---|
| Invariants, schémas, API, CLI | [architecture/api-contract.md](architecture/api-contract.md) |
| Vue d'ensemble et flux | [architecture/overview.md](architecture/overview.md) |
| Modèle de données | [architecture/data-model.md](architecture/data-model.md) |
| Règles de détection | [detection/rules.md](detection/rules.md) |
| Politiques de décision | [decision/policies.md](decision/policies.md) |
| Playbooks et actions | [actions/playbooks.md](actions/playbooks.md) |
| Conformité RGPD | [compliance/rgpd.md](compliance/rgpd.md) |

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
