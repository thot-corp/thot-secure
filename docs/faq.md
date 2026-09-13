# Questions fréquentes

*Réponses courtes et factuelles aux questions les plus fréquentes sur Thot Secure, SOAR/CSPM défensif auto-hébergé — sans promesse commerciale et sans capacité offensive.*

Cette page s'appuie sur le [contrat d'interface v0.1.0](architecture/api-contract.md), qui fait foi.
Quand le contrat ne tranche pas, c'est signalé explicitement.

---

## 1. Quelle différence avec Wazuh ?

Wazuh est une plateforme de détection et de conformité centrée sur l'agent et l'hôte (HIDS, FIM,
analyse de logs, SCA), avec son propre indexeur et son propre tableau de bord. Thot Secure ne cherche
pas à le remplacer sur ce terrain : il ne déploie pas d'agent hôte au MVP et n'embarque pas
d'indexeur de recherche.

Thot Secure se situe **après** la détection : il normalise des événements déjà collectés, applique des
règles YAML, calcule un `risk_score`, puis **décide** (`auto`, `require_approval`, `notify_only`,
`ignore`) et **exécute** des contre-mesures réversibles avec journal chaîné. Les deux outils sont
complémentaires : Wazuh (ou un SIEM) peut alimenter Thot Secure en événements via
`POST /api/v1/events`.

!!! note
    Thot Secure livre aussi des collecteurs défensifs (`http_probe`, `log_tail`, `dependency_scan`,
    `config_audit`), mais l'accent du MVP est l'orchestration de la réponse, pas la couverture
    d'endpoints.

## 2. Quelle différence avec Suricata ou Zeek ?

Suricata et Zeek sont des moteurs d'analyse réseau (IDS/NSM) : ils inspectent le trafic et
produisent des alertes ou des journaux. Thot Secure n'analyse pas de trafic en ligne, ne capture pas
de paquets et ne contient aucun décodeur de protocole réseau.

La complémentarité est directe : les alertes Suricata/Zeek sont converties en `Event`
(`kind: syslog`, `log.line` ou `generic`) puis ingérées. Thot Secure apporte la couche manquante côté
NSM — agrégation en `Finding`, scoring, politique de décision, action réversible et audit
inviolable.

## 3. Quelle différence avec TheHive et Cortex ?

TheHive est une plateforme de gestion de cas (case management) orientée analystes, et Cortex
exécute des analyseurs/responders à la demande. Thot Secure est orienté **pipeline** :
événement → finding → décision → action, avec des politiques versionnées dans le dépôt
(policy-as-code).

Il n'y a pas de gestion de cas complète au MVP : les findings ont un cycle de vie simple
(`open`, `acked`, `closed`, `suppressed`), sans timeline collaborative, sans tâches, sans
observables typés. Un déploiement qui a déjà TheHive peut utiliser Thot Secure pour décider et agir,
et notifier TheHive via le playbook `open-ticket`.

## 4. Quelle différence avec Shuffle, n8n ou StackStorm ?

Ces outils sont des moteurs d'automatisation génériques : on y construit des workflows visuels ou
des règles de déclenchement, sans modèle de sécurité imposé. Thot Secure est un automate
**spécifique à la sécurité**, avec des garde-fous non contournables codés dans le moteur de
décision :

| Garde-fou (contrat §6) | Shuffle / n8n / StackStorm |
|---|---|
| `DRY_RUN=true` par défaut | Non applicable par défaut |
| Plafond `max_actions_per_hour` par tenant (défaut 20) | À construire |
| `cooldown` par `(tenant, playbook, cible)` | À construire |
| Cibles protégées jamais modifiées | À construire |
| Rollback obligatoire sur chaque playbook | Non imposé |
| Journal chaîné par hash | Non fourni |

La contrepartie est assumée : Thot Secure est moins généraliste. Il ne remplace pas un orchestrateur
d'ITOps et n'a pas vocation à exécuter des workflows métier.

## 5. Est-ce que ça attaque quelque chose ?

**Non. Jamais.** Le projet est 100 % défensif et n'embarque aucun code offensif : pas de scan
agressif, pas de brute force, pas de « hack-back », pas de déni de service, pas d'exploitation de
tiers (contrat §10, ADR 0006).

La seule fonction qui touche au réseau sortant est `thotsecure probe`, et elle est strictement
encadrée : elle n'audite que des cibles **déclarées et possédées** par le tenant, listées dans
`config/targets.yaml` (`THOT_TARGETS_FILE`), avec opt-in explicite. Toute action visant une
cible hors périmètre déclaré est automatiquement convertie en `require_approval` par le garde-fou
n° 5 du contrat.

!!! danger
    Toute contribution ajoutant une capacité offensive est refusée sans revue
    (voir [contributing.md](contributing.md) et ADR 0006).

## 6. Est-ce que ça remplace un SOC ?

Non. Thot Secure est un **outil d'orchestration et de détection**, pas une équipe. Il ne fournit ni
analystes, ni astreinte 24/7, ni supervision humaine, ni engagement de service.

Ce qu'il apporte : détection reproductible, scoring, application cohérente des politiques,
traçabilité, et réduction du temps passé sur les gestes répétitifs. Ce qu'il n'apporte pas :
jugement contextuel, qualification d'une intrusion, gestion de crise, relation avec les autorités.
Un déploiement en autonomie `auto` sans personne pour lire les findings est un usage déconseillé.

## 7. Pourquoi le dry-run par défaut ?

Parce que l'invariant n° 1 du contrat impose `DRY_RUN=true` par défaut : aucune action réelle n'est
exécutée sans levée explicite. Un produit qui bloque une adresse IP de production dès la première
installation est un produit dangereux ; Thot Secure est donc sûr à brancher avant même d'avoir des
credentials de connecteur (mode simulé, `simulated: true`).

L'invariant n° 2 ajoute que toute action critique passe par `require_approval` **ou** par un mode
`auto` explicitement activé au niveau du tenant, et qu'elle est journalisée (`actor`, `policy_id`,
`before`, `after`). Le choix est documenté dans
l'[ADR 0003 — dry-run par défaut et approbation humaine](adr/0003-dry-run-par-defaut-et-approbation-humaine.md)
(voir aussi [ADR 0001](adr/0001-record-architecture-decisions.md) pour le principe même des ADR).

## 8. Comment éviter un faux positif destructeur ?

Plusieurs barrières se cumulent, et aucune n'est optionnelle :

| Barrière | Effet |
|---|---|
| `DRY_RUN=true` (défaut) | Rien ne s'exécute réellement |
| `THOT_AUTONOMY=supervised` (défaut) | Approbation humaine avant action critique |
| `autonomy_allowlist` du tenant | Les cibles de votre propre infrastructure sont intouchables |
| Mode simulé des connecteurs non configurés | Aucun credential requis pour démarrer |
| `max_actions_per_hour` (défaut 20) | Plafond anti-emballement |
| `cooldown` par `(tenant, playbook, cible)` | Empêche la répétition en boucle |
| `duration_seconds` borné (60 → 604800) | Un blocage expire toujours |
| `POST /actions/{id}/rollback` | Annulation tant que le rollback n'a pas expiré |
| `evidence` + `false_positives` de la règle | Faux positifs documentés et revus |
| `decision: notify_only` | Signal sans contre-mesure pendant la phase d'observation |
| `THOT_RETENTION_DAYS` (défaut 30) | Purge bornée des événements |

!!! tip
    La méthode recommandée : démarrer en `notify_only`, observer une à deux semaines, ajuster les
    règles et les seuils, puis passer en `require_approval`, et seulement ensuite envisager `auto`
    sur un périmètre étroit.

## 9. Puis-je l'utiliser chez un client en tant que MSSP ?

Oui, l'architecture est multi-tenant dès le MVP : le `tenant_id` est la frontière d'isolation,
tout objet le porte, toute requête SQL le filtre, et l'isolation est **testée en CI**
(`tests/test_storage.py`, `tests/test_api.py`, contrat §11).

Côté conformité, l'usage en sous-traitance implique un encadrement contractuel et un registre des
traitements (article 30 RGPD), ainsi qu'une AIPD/DPIA lorsque le traitement est susceptible
d'engendrer un risque élevé — notamment en cas de surveillance systématique. Ces points sont
traités dans [compliance/rgpd.md](compliance/rgpd.md).

!!! warning
    L'isolation technique ne dispense pas de l'isolation **opérationnelle** : une clé API
    `admin` mal rangée, un connecteur partagé entre deux tenants ou un export SIEM commun
    annulent la garantie applicative.

## 10. Ça marche en air-gap ?

Oui, le cœur est conçu pour ne dépendre d'aucune ressource réseau : `thotsecure.core` n'utilise que
la stdlib, `pydantic` et `PyYAML` (invariant n° 5). Le bus par défaut, `THOT_BUS=memory`, est
local ; `sqlite` l'est aussi ; `nats` est réservé aux déploiements distribués et pointe par défaut
sur `nats://127.0.0.1:4222`.

L'installation hors-ligne et le transfert des artefacts se font selon
[installation.md](installation.md). Le mode OPA/Rego est purement optionnel : s'il n'y a pas de
binaire `THOT_OPA_BIN`, les politiques YAML suffisent.

## 11. Quelle charge sur mon serveur ?

Le contrat ne fixe **aucun objectif de performance chiffré** : les valeurs ci-dessous sont des
ordres de grandeur d'exploitation, pas des mesures publiées. Validez-les par vos propres tests.

| Profil | Ressources indicatives | Usage typique |
|---|---|---|
| Évaluation, `memory` ou SQLite, mode simulé | 1 vCPU, 1 Gio RAM, 1 Go disque | Démo, `thotsecure demo`, formation |
| Petite production mono-nœud, SQLite | 2 vCPU, 2–4 Gio RAM, disque dimensionné par la rétention | PME, un tenant, quelques milliers d'événements/jour |
| Production distribuée, bus NATS + PostgreSQL | 4 vCPU et plus, RAM selon l'indexation | Plusieurs tenants, volumes soutenus |

Éléments à intégrer au dimensionnement : `THOT_RETENTION_DAYS` (défaut 30 jours), la taille du
journal d'audit (append-only, jamais purgé par la rétention d'événements), la limite de corps de
`POST /api/v1/events` (500 événements par appel) et `THOT_RATE_LIMIT_PER_MIN` (défaut 600).
Voir [operations/deployment.md](operations/deployment.md).

## 12. Que se passe-t-il si le bus tombe ?

`THOT_BUS` accepte `memory`, `sqlite` ou `nats`. En cas de perte du bus, la sonde
`GET /readyz` vérifie base **et** bus **et** règles, et retourne `503` si l'un des trois est
indisponible : un orchestrateur qui honore `/readyz` retire donc l'instance du trafic au lieu
d'accepter des événements qui seraient perdus.

Différence importante : le bus `memory` n'offre **aucune durabilité** (les événements en vol sont
perdus avec le processus), le bus `sqlite` persiste localement, `nats` apporte la distribution.
Pour une production, choisissez explicitement `sqlite` ou `nats` et traitez le cas de perte.
Le choix d'un bus enfichable est documenté dans
l'[ADR 0005](adr/0005-bus-pluggable-memory-sqlite-nats.md). Procédure de diagnostic et de reprise :
[operations/runbook.md](operations/runbook.md).

## 13. Comment contribuer une règle de détection ?

1. Écrire un fichier YAML dans `rules/`, conforme au format du contrat §5 (`id`, `title`,
   `severity`, `confidence`, `match`, `risk`, `false_positives`, `remediation`).
2. Valider : `thotsecure rules validate --path rules`, ou `POST /api/v1/rules/validate`
   (capacité `admin:rules`).
3. Ajouter le test correspondant dans `tests/test_rules_engine.py` (opérateurs, `all`/`any`/`not`,
   seuils, `dedup`).
4. Documenter les faux positifs connus dans le bloc `false_positives` de la règle.
5. Ouvrir une pull request avec le *pourquoi* de la détection, pas seulement le *quoi*.

Détails : [detection/rules.md](detection/rules.md) et [contributing.md](contributing.md).
Rappel : une règle invalide ne casse pas le chargement — elle est rejetée avec un diagnostic.

## 14. Est-ce vraiment gratuit ?

Le cœur est publié sous **Apache-2.0** et il est **complet** : aucune fonctionnalité de sécurité
n'est retirée de la version open source. Il n'y a ni « édition entreprise » bridant les
garde-fous, ni plafond de tenants, ni fonction de détection réservée.

Une offre de **support professionnel optionnel** peut exister le cas échéant, portée par les
canaux officiels du projet ; elle ne conditionne ni la licence, ni les correctifs de sécurité, ni
l'accès aux règles. Les dons, eux, sont volontaires et sans contrepartie
(voir [support.md](support.md)). Ce point est présenté tel quel : le cas échéant, les modalités
exactes se consultent sur les canaux officiels du dépôt.

## 15. Puis-je le revendre ou l'intégrer dans mon produit ?

Oui. Apache-2.0 autorise l'usage commercial, la modification, la redistribution et l'intégration
dans un produit propriétaire. En contrepartie, vous devez conserver la notice de licence et les
mentions de copyright, indiquer les fichiers modifiés, et inclure une copie de la licence.

La licence fournit le logiciel **sans garantie** : ni qualité marchande, ni aptitude à un usage
particulier. Détail des obligations : [governance.md](governance.md) et le fichier
[LICENSE](../LICENSE) à la racine du dépôt. Cette FAQ n'est pas un avis juridique.

## 16. Où sont mes données ?

Chez vous. Thot Secure est auto-hébergé : le contrat ne décrit **aucune télémétrie**, aucun appel
sortant obligatoire, aucun service tiers requis. Les événements, findings, actions et le journal
d'audit résident dans votre base (`THOT_DB_URL`) et vos fichiers de configuration.

Sont concernés : la base de données, le bus éventuel, les exports SIEM que **vous** déclenchez, et
les journaux applicatifs (`THOT_LOG_FORMAT`, `json` ou `console`). Si vous configurez un
connecteur vers un service externe (WAF, tickets), ce sont vos choix et vos credentials : le
périmètre de responsabilité est décrit dans [compliance/rgpd.md](compliance/rgpd.md).

## 17. Quelle base de données ?

SQLite au MVP : `THOT_DB_URL` vaut par défaut `sqlite:///./data/thotsecure.db`, et
`thotsecure init-db` crée le schéma. C'est suffisant pour un nœud unique, un faible volume et une
évaluation.

La cible de production est PostgreSQL, avec TimescaleDB pour les séries temporelles d'événements :
le dépôt contient les DDL correspondantes (contrat §2, `storage/`), mais l'exploitation outillée
(hypertables, compression, agrégats continus, migrations) relève de la suite du programme.

!!! info "Roadmap"
    Le support PostgreSQL/TimescaleDB **en production** est étudié pour la v0.2, avec migrations
    outillées. Voir [roadmap.md](roadmap.md) et [architecture/data-model.md](architecture/data-model.md).

## 18. Comment savoir si une action a réellement été exécutée ?

Quatre éléments, tous vérifiables :

| Élément | Où | Ce qu'il prouve |
|---|---|---|
| `dry_run: true/false` sur l'`Action` | `GET /api/v1/actions/{id}` | Si l'effet était réel ou simulé |
| `simulated: true` | Journal du connecteur | Connecteur non configuré, aucun credential |
| `audit_seq` sur l'`Action` | `AuditRecord` correspondant | Traçabilité de l'exécution (`actor`, `before`, `after`) |
| Chaîne de hash | `GET /api/v1/audit/verify` | Aucune ligne d'audit n'a été modifiée après coup |

Un `rollback.available: true` avec `performed_at: null` signifie que l'annulation est encore
possible. Pour l'export vers un SIEM : `GET /api/v1/audit/export?format=jsonl|cef`. Le journal
chaîné par hash plutôt qu'une chaîne de blocs est un choix assumé, argumenté dans
l'[ADR 0004](adr/0004-audit-log-chaine-par-hash-plutot-que-blockchain.md). Le cycle de vie complet
est détaillé dans [actions/playbooks.md](actions/playbooks.md).

## 19. Est-ce utilisable sans compétence en sécurité ?

Non, et il vaut mieux le dire clairement : un outil de sécurité demande du jugement. Thot Secure
exécute ce que **vous** écrivez — la valeur vient des règles de détection et des politiques de
décision que vous rédigez, pas du logiciel seul. Une politique mal écrite en mode `auto` peut
bloquer du trafic légitime.

Ce qui limite les dégâts : dry-run par défaut, approbation par défaut en `supervised`, cibles
protégées, plafonds et cooldowns, rollback systématique, et un journal d'audit que vous pouvez
relire. La montée en autonomie doit être progressive et documentée.

## 20. Comment obtenir de l'aide et signaler une vulnérabilité ?

Pour l'aide : les issues et discussions du dépôt, ainsi que [support.md](support.md). Pour
contribuer : [contributing.md](contributing.md) et [governance.md](governance.md).

Pour une vulnérabilité : **jamais d'issue publique**. Suivez la politique de sécurité du dépôt,
`SECURITY.md` à la racine ([lien](../SECURITY.md)), qui décrit les canaux privés, les délais visés
et la politique de crédit. Les rapports publiés mettent en danger tous les déploiements avant
qu'un correctif n'existe.

!!! warning
    Thot Secure ne demandera **jamais** de clé privée, de phrase de récupération, ni de secret
    d'API. Toute demande de ce type est une tentative d'arnaque, y compris si elle prétend venir
    du projet.

---

## Récapitulatif

| # | Question | Réponse en une ligne |
|---|---|---|
| 1 | Différence avec Wazuh ? | Complémentaire : Wazuh détecte sur l'hôte, Thot Secure décide et agit après la détection. |
| 2 | Différence avec Suricata/Zeek ? | Complémentaire : pas d'analyse réseau, il ingère leurs alertes et orchestre la réponse. |
| 3 | Différence avec TheHive/Cortex ? | Orienté pipeline et policy-as-code, pas case management. |
| 4 | Différence avec Shuffle/n8n/StackStorm ? | Automate de sécurité avec garde-fous non contournables et rollback obligatoire. |
| 5 | Est-ce que ça attaque quelque chose ? | Non, jamais : zéro capacité offensive, `probe` limité aux cibles déclarées. |
| 6 | Est-ce que ça remplace un SOC ? | Non : outil d'orchestration et de détection, sans analystes ni 24/7. |
| 7 | Pourquoi le dry-run par défaut ? | Invariant n° 1 : rien de réel sans levée explicite. |
| 8 | Éviter un faux positif destructeur ? | Dry-run, approbation, allowlist, plafonds, cooldown, rollback, `notify_only`. |
| 9 | Usage MSSP chez un client ? | Oui, multi-tenant avec isolation testée en CI, sous réserve du cadre RGPD. |
| 10 | Ça marche en air-gap ? | Oui : cœur sans dépendance réseau, bus local par défaut. |
| 11 | Quelle charge serveur ? | De 1 vCPU/1 Gio en évaluation à 4 vCPU et plus en production distribuée (estimations). |
| 12 | Si le bus tombe ? | `/readyz` retourne `503` ; `memory` ne persiste rien, `sqlite`/`nats` oui. |
| 13 | Contribuer une règle ? | YAML dans `rules/`, `thotsecure rules validate`, test unitaire, PR. |
| 14 | Est-ce vraiment gratuit ? | Cœur Apache-2.0 complet ; support professionnel optionnel le cas échéant. |
| 15 | Revendre ou intégrer ? | Oui, avec notice de licence et mentions, et sans garantie. |
| 16 | Où sont mes données ? | Chez vous : auto-hébergé, aucune télémétrie décrite par le contrat. |
| 17 | Quelle base de données ? | SQLite au MVP, PostgreSQL/TimescaleDB visé en production. |
| 18 | Action réellement exécutée ? | `dry_run`, `simulated`, `audit_seq` et `audit/verify` le prouvent. |
| 19 | Sans compétence en sécurité ? | Non : l'outil demande du jugement ; la montée en autonomie doit être progressive. |
| 20 | Aide et vulnérabilités ? | Issues/discussions du dépôt ; vulnérabilités par les canaux privés de `SECURITY.md`. |

## Voir aussi

* [Architecture et invariants](architecture/api-contract.md)
* [Contribuer](contributing.md) — [Gouvernance](governance.md) — [Soutien](support.md)
* [Glossaire](glossary.md) — [Feuille de route](roadmap.md)

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
