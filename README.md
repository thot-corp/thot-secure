<div align="center">

# Thot Secure

**SOAR/CSPM défensif open source — détecter, décider, agir, et pouvoir tout annuler.**

Collecte continue · détection par règles YAML · scoring de risque explicable · décision
*policy-as-code* · contre-mesures **réversibles** · journal d'audit **chaîné par hash**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-informational.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Statut](https://img.shields.io/badge/statut-MVP%20(alpha)-orange.svg)](ROADMAP.md)
[![100% défensif](https://img.shields.io/badge/100%25-d%C3%A9fensif-success.svg)](#-ce-que-thot-secure-ne-fait-jamais)
[![Dry-run par défaut](https://img.shields.io/badge/dry--run-actif%20par%20d%C3%A9faut-success.svg)](#-les-quatre-garanties)

[Documentation](docs/index.md) · [Démarrage rapide](docs/quickstart.md) · [Architecture](docs/architecture/overview.md) · [Contrat d'API](docs/architecture/api-contract.md) · [Soutenir le projet](#-soutenir-le-projet)

</div>

---

## Le problème

Un MSP découvre trois jours trop tard qu'un site client a été sondé puis exploité. Un RSSI ne
peut pas prouver *qui* a bloqué une adresse, *quand*, ni *pourquoi*. Un SOC automatise des
blocages… et bloque un partenaire légitime pendant une réunion client, sans pouvoir revenir en
arrière. Un DevOps reçoit 4 000 alertes par semaine et en ignore 3 990.

Thot Secure est né d'une conviction simple : **un outil qui agit sur l'infrastructure doit être
sûr avant d'être puissant.** La détection automatique n'a de valeur que si l'on peut
(i) comprendre pourquoi elle s'est déclenchée, (ii) décider avec des règles lisibles,
(iii) annuler ce qui a été fait, et (iv) le prouver à un auditeur.

## Ce que fait Thot Secure

```
  Collecteurs            Bus              Détection        Décision         Action          Audit
 ┌───────────┐      ┌──────────┐      ┌────────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐
 │ web_probe │      │ memory   │      │ règles YAML│   │policy-as-  │   │ playbooks│   │ chaîne   │
 │ log_tail  │─────▶│ sqlite   │─────▶│ + Sigma-   │──▶│ code YAML  │──▶│ + rollback│──▶│ par hash │
 │ dependency│      │ nats     │      │   lite     │   │ + garde-   │   │ + simu-  │   │ vérifiable│
 │ tls_cert  │      │          │      │ scoring    │   │   fous     │   │   lation │   │ export   │
 │ config    │      │ rejeu    │      │ explicable │   │            │   │          │   │ SIEM     │
 │ syslog    │      └──────────┘      └────────────┘   └────────────┘   └──────────┘   └──────────┘
 └───────────┘          ▲                   ▲                ▲               ▲              ▲
                        │                   │                │               │              │
                     API REST · CLI · SDK Python/TS/Go · Console web · WebSocket temps réel
```

1. **Collecter** — journaux web (Nginx/Apache/JSON), syslog, certificats TLS, dépendances
   (requirements/package.json/go.mod/pom), configurations (SSH, Nginx, Docker), webhooks.
2. **Détecter** — bibliothèque de règles YAML livrée (21 règles, sources OWASP/MITRE/CIS),
   avec seuils d'agrégation, déduplication et compatibilité partielle Sigma.
3. **Scorer** — score de risque 0–100 **explicable** (chaque facteur est justifié dans le
   rapport : sévérité, confiance, criticité d'actif, répétition).
4. **Décider** — politiques *policy-as-code* lisibles, plus des garde-fous que **aucune
   politique ne peut désactiver** (cible protégée, périmètre déclaré, plafond horaire, cooldown,
   seuil critique, dry-run).
5. **Agir** — playbooks avec **rollback obligatoire**, connecteurs simulés par défaut
   (aucun effet réel tant que vous ne l'avez pas décidé), exécution idempotente et auditée.
6. **Prouver** — journal d'audit *append-only* chaîné par hash, vérifiable
   (`thotsecure audit verify`), exportable en CEF/JSONL vers un SIEM, et rapports
   Markdown/HTML/**SARIF**/JSON par finding.

## 🛡️ Les quatre garanties

| Garantie | Comment c'est garanti | Comment le vérifier |
|---|---|---|
| **Rien d'irréversible** | Chaque playbook réversible déclare ses étapes de rollback (le chargement **refuse** un playbook incohérent). Un playbook intrinsèquement irréversible (`revoke-session`, `rotate-secret`) ne peut **jamais** s'exécuter automatiquement. | `thotsecure playbooks list` puis `thotsecure actions rollback <id>` |
| **Rien sans trace** | Journal d'audit chaîné par hash : modifier ou supprimer une ligne casse la chaîne et est détecté. Chaque décision référence sa politique, chaque action son `audit_seq`. | `thotsecure audit verify` (code de sortie 3 si la chaîne est rompue) |
| **Rien d'implicite** | `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised` par défaut. Les connecteurs non configurés sont en **simulation** et le disent. | `thotsecure doctor`, page `/version`, bandeau permanent dans la console |
| **Rien hors périmètre** | `config/targets.yaml` déclare les actifs, le périmètre d'action et les cibles protégées. Hors périmètre ⇒ approbation humaine obligatoire. | `thotsecure collect list --tenant <id>` |

## 🚫 Ce que Thot Secure ne fait jamais

Le projet est **strictement défensif**. Il n'existe — et n'existera — aucune capacité :

- ❌ de scan agressif, d'énumération offensive ou de test d'intrusion ;
- ❌ d'exploitation de vulnérabilité, de charge utile d'attaque ou de *payload* ;
- ❌ de déni de service, de force brute, de *password spraying* ;
- ❌ de riposte, de *hack back*, d'action sur une infrastructure tierce.

Ces limites sont un **invariant de conception** inscrit dans `GOVERNANCE.md` : les lever
exigerait un vote des mainteneurs à la majorité des deux tiers, et une contribution offensive
sera refusée, quelle qu'en soit la justification.

L'audit de surface (`thotsecure probe`) ne cible **que** vos actifs explicitement déclarés,
avec un opt-in (`allow_probe: true`), une requête par contrôle, aucun rythme agressif et un
`User-Agent` identifiant clairement l'outil.

## 🚀 Démarrage rapide (5 minutes)

```bash
# 1. Installation
git clone https://github.com/thotsecure/thot-secure.git && cd thot-secure
python -m venv .venv && . .venv/bin/activate     # Windows : .venv\Scripts\Activate.ps1
pip install -e .
thotsecure init-db

# 2. Diagnostic : la première commande à lancer
thotsecure doctor

# 3. Tenant + clé API (le secret n'est affiché qu'une fois)
thotsecure tenant create --id acme --name "ACME" --mode supervised
thotsecure key create --tenant acme --role responder

# 4. Démonstration : tout le pipeline, sans aucun effet réel
thotsecure demo --tenant demo

# 5. Console web + API
thotsecure serve            # → http://127.0.0.1:8080/
```

Ou en conteneur :

```bash
docker compose --profile demo up      # console : http://localhost:8080/
```

Puis, dans l'ordre : `docs/quickstart.md` → déclarer vos actifs dans `config/targets.yaml`
(`cp config/targets.example.yaml config/targets.yaml`) → `thotsecure collect run config_audit
--tenant acme` → observer en simulation pendant quelques jours → **puis** décider d'activer le
réel, connecteur par connecteur.

> ⚠️ **N'activez jamais `THOT_DRY_RUN=false` avant d'avoir observé les décisions en
> simulation.** C'est la procédure recommandée, et elle est aussi la plus rentable.

## 🧩 Exemples concrets

### Une règle de détection (`rules/web/injection-sql.yaml`)

```yaml
id: AO-WEB-001
title: Tentative d'injection SQL dans une requête HTTP
severity: high
confidence: 0.8
tags: [web, owasp:a03, mitre:T1190, exploit-attempt]
source_types: [log_tail, webhook, syslog]
match:
  any:
    - field: labels.path
      op: regex
      value: "(?i)(union[\\s/*]+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(\\s*\\d+"
  threshold:
    count: 3                      # 3 occurrences…
    window_seconds: 120           # …en 2 minutes…
    group_by: [labels.src_ip]     # …depuis la même source
dedup:
  key: [labels.src_ip]
remediation: Corriger la requête côté code (requêtes paramétrées), puis bloquer la source 1 h.
false_positives:
  - Champ de recherche libre contenant le mot « union » suivi de « select ».
```

### Une politique de décision (`policies/15-approbation-attaque-web-haute.yaml`)

```yaml
id: approval-high-web-attack
priority: 190
description: Attaque web de gravité haute : blocage proposé, validé par un humain.
when:
  finding.severity: [high, critical]
  finding.risk_score: { gte: 60 }
  finding.tags_any: [exploit-attempt, exposure]
then:
  decision: require_approval        # auto | require_approval | notify_only | ignore
  playbook: block-source-ip
  params:
    target: labels.src_ip
    duration_seconds: 3600
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
```

### Une contre-mesure réversible

```bash
thotsecure findings list --tenant acme --min-risk 60
thotsecure actions plan --tenant acme --playbook block-source-ip \
    --finding fi_1a2b… --target 203.0.113.9 --duration 3600
# → plan affiché, AUCUN effet appliqué
thotsecure actions approve  ac_9f8e… --tenant acme --by "rssi@acme.fr"
thotsecure actions execute  ac_9f8e… --tenant acme
thotsecure actions rollback ac_9f8e… --tenant acme     # rien n'est définitif
thotsecure audit verify      --tenant acme             # la preuve
```

### Un rapport exploitable

```bash
thotsecure report fi_1a2b… --tenant acme --format md    -o incident.md
thotsecure report fi_1a2b… --tenant acme --format sarif -o findings.sarif   # GitHub Code Scanning
thotsecure audit export --tenant acme --format cef -o audit.cef             # SIEM
```

## 🏗️ Architecture et arborescence

```
thot-secure/
├── src/thotsecure/
│   ├── core/            modèles, configuration, utilitaires (stdlib + pydantic uniquement)
│   ├── storage/         SQLite (MVP) + DDL PostgreSQL/TimescaleDB (production)
│   ├── bus/             bus d'événements : memory | sqlite | nats (client stdlib, sans dépendance)
│   ├── audit/           journal chaîné par hash + export CEF
│   ├── scope.py         périmètre déclaré : le garde-fou anti-abus
│   ├── collectors/      web_probe, log_tail, dependency_scan, tls_cert, config_audit, syslog
│   ├── detection/       moteur de règles YAML (opérateurs, seuils, Sigma-lite)
│   ├── scoring/         score de risque explicable et monotone
│   ├── decision/        policy-as-code + garde-fous + adaptateur OPA/Rego
│   ├── actions/         playbooks, connecteurs (simulation, nginx-local, quarantaine, webhook…)
│   ├── tenancy/         tenants, clés API hachées (scrypt), RBAC
│   ├── reports/         Markdown · HTML · JSON · SARIF · CEF
│   ├── api/             FastAPI v1, WebSocket, métriques Prometheus
│   ├── ui/              console embarquée (Jinja2 + JS natif, aucun build Node)
│   ├── observability/   métriques, limitation de débit
│   ├── pipeline.py      ingestion → détection → scoring → décision → action → audit
│   ├── service.py       assemblage unique utilisé par l'API, la CLI et les tests
│   └── cli.py           interface en ligne de commande complète
├── rules/  policies/  playbooks/     la bibliothèque livrée (règles, politiques, playbooks)
├── config/                           exemples de périmètre et de connecteurs
├── tests/                            suite unittest (exécutable sans réseau)
├── docs/                             documentation complète + ADR + modèle de menaces
├── deploy/                           Docker, Compose, Kubernetes, Helm, Terraform, Ansible
├── sdks/                             SDK Python, TypeScript, Go
├── examples/                         intégrations prêtes à adapter
├── web/                              tableau de bord React + TypeScript (optionnel)
└── content/                          kit éditorial (articles, forums, réseaux, vidéo)
```

**Choix techniques assumés** : SQLite par défaut (aucun service externe pour démarrer, sauvegarde
par copie de fichier), bus NATS **implémenté en stdlib** (pas de dépendance dans l'image de
production), console web **sans build Node** (utilisable en réseau cloisonné), cœur sans
dépendance lourde. Les alternatives et leurs conséquences sont documentées dans `docs/adr/`.

## 👥 Multi-tenant et RBAC

| Rôle | Capacités |
|---|---|
| `viewer` | Lire événements, findings, règles, politiques, audit, statistiques |
| `analyst` | + ingérer des événements, acquitter/clôturer/supprimer le bruit |
| `responder` | + planifier, approuver, exécuter et **annuler** des actions |
| `admin` | + gérer tenants, clés API, règles, politiques |

Isolation stricte : toute requête filtre le `tenant_id` ; un finding d'un autre tenant est
**indistinguable** d'un finding inexistant (pas de fuite d'existence). Le `tenant_id` est imposé
par la clé API — un collecteur ne peut pas écrire dans le tenant d'un autre.

Clés API stockées **hachées** (scrypt + poivre serveur), jamais en clair, affichées une seule
fois à la création. Sessions de console signées (HMAC), cookie `HttpOnly` + `SameSite=Strict`,
protection CSRF, et jeton court pour le WebSocket (la clé API ne transite jamais dans une URL).

## 📦 Déploiement

| Cible | Commande / chemin |
|---|---|
| Local | `thotsecure serve` · `scripts/dev-setup.sh` · `scripts/dev-setup.ps1` |
| Conteneurs | `docker compose up -d` · `docker-compose.observability.yml` (Prometheus, Grafana, Loki) |
| Kubernetes | `deploy/k8s/` (durci : non-root, rootfs lecture seule, NetworkPolicy, PDB, HPA) |
| Helm | `helm install thotsecure deploy/helm/thotsecure --set dryRun=true` |
| Terraform | `deploy/terraform/examples/{aws-eks,azure-aks,onprem-k3s}` |
| Ansible | `deploy/ansible/playbook-install.yml` (VM, systemd durci, Nginx + TLS) |
| Binaire signé | `scripts/install.sh` — vérifie **signature Sigstore + SHA-256** avant d'installer |

Toutes les cibles respectent les mêmes défauts : `THOT_DRY_RUN=true`,
`THOT_AUTONOMY=supervised`, utilisateur non-root, aucune capability ajoutée, aucun
`hostNetwork`, aucun montage du socket Docker.

## 🧪 Tests

```bash
python -m unittest discover -s tests -t . -v     # sans dépendance, sans réseau
pytest -q                                        # équivalent (les tests sont compatibles)
thotsecure rules validate && thotsecure policies validate
```

La suite couvre le pipeline de bout en bout, l'API (authentification, RBAC, isolation
inter-tenant, cycle de vie complet des actions), les collecteurs (dont un **vrai serveur HTTP
local** pour l'audit de surface), l'intégrité de l'audit (avec détection de falsification), les
garde-fous de décision, et la **validité de la bibliothèque livrée** (règles, politiques,
playbooks, exemples de configuration).

## 📚 Documentation

| Sujet | Où |
|---|---|
| Démarrage, installation, configuration | `docs/quickstart.md`, `docs/installation.md`, `docs/configuration.md` |
| Architecture, modèle de données, **modèle de menaces STRIDE** | `docs/architecture/` |
| Écrire une règle de détection, compatibilité Sigma | `docs/detection/` |
| Politiques de décision, garde-fous | `docs/decision/policies.md` |
| Playbooks, connecteurs, rollback | `docs/actions/playbooks.md` |
| Exploitation, runbook d'incident, alertes | `docs/operations/` |
| RGPD, correspondance SOC 2 / ISO 27001 | `docs/compliance/` |
| Décisions d'architecture (ADR) | `docs/adr/` |
| Contrat d'interface gelé (API, schémas, formats) | `docs/architecture/api-contract.md` |

## ⚠️ Limites connues (MVP 0.1.0)

Nous préférons les écrire que les laisser découvrir en production :

- **Persistance** : SQLite par défaut. Adapté à un MSP ou à un site, pas encore à plusieurs
  centaines de milliers d'événements par heure — la variante PostgreSQL/TimescaleDB est
  documentée et son DDL est livré, l'adaptateur n'est pas encore écrit.
- **Connecteurs** : seuls `nginx-local`, `local-quarantine` et `local-ticket` produisent un
  effet **réel** ; Cloudflare, AWS WAF et les EDR passent par la passerelle `http-webhook`
  (générique et signée) en attendant des connecteurs natifs.
- **Détection** : règles déterministes uniquement. Pas encore de détection d'anomalie par
  apprentissage (prévue en 0.3).
- **Compatibilité Sigma** : sous-ensemble documenté, avec refus explicite de ce qui ne peut pas
  être traduit fidèlement — un faux négatif silencieux serait pire qu'un refus visible.
- **Bandeau de simulation** : le produit est utilisable en production, mais ses défauts sont
  volontairement conservateurs (rien ne s'exécute sans décision explicite).

## 🗺️ Feuille de route

`ROADMAP.md` détaille les jalons. En résumé : **0.2** — adaptateur TimescaleDB, connecteurs
natifs Cloudflare/AWS WAF, SSO OIDC, API GraphQL. **0.3** — marketplace de plugins, détection
d'anomalie, corrélation multi-étapes, OpenSearch. **1.0** — durcissement audité, dossier SOC 2,
SLA et offre de support.

## 🤝 Contribuer

Les contributions sont bienvenues, en particulier : **règles de détection** (le cœur de la
valeur), connecteurs, traductions, et signalements de faux positifs (la contribution la plus
utile à la qualité). Lisez `CONTRIBUTING.md` — les commits sont signés (DCO), les commits
suivent *Conventional Commits*, et **toute contribution offensive est refusée**.

Gouvernance : `GOVERNANCE.md` · Mainteneurs : `MAINTAINERS.md` · Sécurité et divulgation
responsable : `SECURITY.md` (canal privé, accusé sous 72 h) · Code de conduite :
`CODE_OF_CONDUCT.md`.

## 📄 Licence

**Apache-2.0** — voir `LICENSE`. Vous pouvez l'utiliser, le modifier et le redistribuer, y
compris dans un cadre commercial, à condition de conserver la notice de licence. Le cœur du
produit est complet et fonctionnel : seuls le support, le SLA et les intégrations d'entreprise
relèvent d'une offre payante optionnelle (*open core* honnête, sans fonctionnalité retirée).

## 💰 Soutenir le projet

Thot Secure est développé et maintenu sur du temps bénévole. **Les dons sont volontaires et
sans contrepartie.** Ils financent l'hébergement de la documentation et des miroirs, les
certificats TLS, les audits de sécurité externes, la signature des binaires (Sigstore), les
runners de CI/CD, la rédaction de la documentation et le temps de maintenance.

**Adresses officielles** (recopiées à l'identique depuis ce dépôt) :

| Réseau | Adresse |
|---|---|
| **Bitcoin (BTC)** — réseau Bitcoin mainnet | `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR` |
| **Solana (SOL)** — réseau Solana mainnet | `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi` |

> **Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt
> officiel.**

> ⚠️ **Avertissement anti-arnaque.** Seule la source officielle (ce dépôt Git et le site du
> projet) fait foi. Un message privé, un commentaire, un courriel ou une prétendue équipe de
> maintenance ne sont **jamais** légitimes. Thot Secure ne demandera **jamais** votre clé
> privée, votre phrase de récupération (*seed*) ni un accès à votre portefeuille, et
> n'accorde **aucun** avantage, support prioritaire ou fonctionnalité en échange d'un don.

Autres canaux (déclarés dans `.github/FUNDING.yml`, et eux seuls sont officiels) : GitHub
Sponsors, Open Collective, Liberapay. Détails et transparence : `docs/support.md` et la page
`/ui/support` de la console.

Soutenir sans argent, c'est possible et souvent plus utile : contribuer une règle, signaler un
faux positif, traduire la documentation, ou simplement dire que vous utilisez l'outil dans une
Discussion GitHub.

---

<div align="center">

## In English (short version)

**Thot Secure** is an open-source, **strictly defensive** SOAR/CSPM: it collects security
signals (web logs, syslog, TLS certificates, dependencies, configurations), detects threats
with YAML rules, computes an explainable risk score, decides through readable *policy-as-code*
with non-bypassable guardrails, and applies **reversible, fully audited** countermeasures with
rollback.

- **Safe by default**: `dry_run=true`, `supervised` autonomy, unconfigured connectors run in
  simulation and say so.
- **Reversible**: every playbook declares its rollback; irreversible playbooks can never run
  automatically.
- **Provable**: append-only hash-chained audit log, verifiable offline, exportable to any SIEM
  (CEF/JSONL), SARIF reports for GitHub Code Scanning.
- **No offensive capability, ever**: no aggressive scanning, no exploitation, no DoS, no
  hack-back. This is a project invariant, not a configuration option.

Quickstart: `pip install -e . && thotsecure init-db && thotsecure doctor && thotsecure demo --tenant demo`.
Docs: `docs/` (French, with an English quickstart in `docs/index.md`).

Licensed under **Apache-2.0**. Voluntary donations only: BTC `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`,
SOL `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi` — always verify these addresses from this
official repository.

</div>
