# ADR-0005 — Bus d'événements enfichable : memory, sqlite, nats

*Le transport d'événements est une interface unique avec trois implémentations interchangeables
(`memory`, `sqlite`, `nats`), choisies par configuration, pour aller du poste de développeur au
MSSP multi-sites sans changer une ligne de code métier.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté** pour la version 0.1.0 (MVP). Les trois implémentations sont dans le périmètre du
contrat (§2, `src/thotsecure/bus/`) et la sélection par `THOT_BUS` est normée au §9. La sémantique
de livraison reste, à ce stade, **à préciser dans le code** : ce point est signalé explicitement
dans les conséquences négatives plutôt que passé sous silence.

---

## Contexte

Le flux d'un événement dans Thot Secure traverse plusieurs composants : les collecteurs
(`src/thotsecure/collectors/`) produisent et normalisent, le moteur de détection
(`src/thotsecure/detection/`) consomme et agrège en findings, puis la console et le WebSocket
`WS /api/v1/ws/stream` (§4.8) diffusent en temps réel des frames
`{"type":"event|finding|action|audit|heartbeat","data":{…}}` vers les navigateurs. L'ingestion API
`POST /api/v1/events` (§4.3) alimente le même pipeline.

Ces composants ont des besoins contradictoires selon le contexte de déploiement :

| Contexte | Besoin | Contrainte dominante |
|---|---|---|
| Poste de développement, tests, démonstration | Un seul processus, aucun service externe, démarrage instantané | Zéro dépendance |
| Labo, pilote, petite production mono-site | Événements conservés entre deux redémarrages | Simplicité d'exploitation |
| MSSP multi-sites, plusieurs collecteurs et plusieurs consommateurs | Distribution, découplage, montée en charge | Fiabilité et exploitation |
| Réseau isolé, air-gap, conteneur minimal | Fonctionnement sans sortie réseau | Aucune dépendance externe |

Deux exigences cadrent la solution :

1. **Ne pas imposer d'infrastructure pour installer le produit.** La même contrainte que celle qui
   a motivé le choix de SQLite ([ADR-0002](0002-python-fastapi-et-sqlite-pour-le-mvp.md)) :
   `pip install` puis `thotsecure init-db` doit suffire. Un broker obligatoire rendrait l'évaluation
   impossible et la CI (tests §11 « exécutables sans dépendance externe ») dépendante d'un service.
2. **Rester cohérent avec « sûr à brancher avant d'avoir des credentials ».** Le produit doit
   démarrer et démontrer sa valeur sans configuration réseau. Un bus qui suppose une brique
   d'infrastructure contredit cet engagement.

À l'inverse, un bus purement en mémoire condamnerait le produit à l'usage mono-processus et
interdirait le scénario MSSP, qui est un cas d'usage explicite du projet (multi-tenant, `tenant_id`
partout, §1).

---

## Décision

Nous définissons **une seule interface de bus** (publication, abonnement, fanout, acquittement
selon le backend) et **trois implémentations** sélectionnées par la variable `THOT_BUS` (§9) :

* `memory` — **défaut**. File en mémoire dans le processus, fanout vers les abonnés.
* `sqlite` — persistance des messages dans la base, durabilité entre redémarrages.
* `nats` — bus distribué, `THOT_NATS_URL` avec la valeur par défaut
  `nats://127.0.0.1:4222`, **client stdlib embarqué** (pas de dépendance Python externe
  supplémentaire).

| Critère | `memory` | `sqlite` | `nats` |
|---|---|---|---|
| **Durabilité** | Aucune : tout est perdu au redémarrage | Oui : les messages survivent au redémarrage | Oui, selon la configuration du serveur NATS |
| **Distribution** | Non : un seul processus, fanout local uniquement | Non : un seul processus, partage par la base | Oui : plusieurs collecteurs et consommateurs, multi-sites |
| **Dépendance externe** | Aucune | Aucune (même fichier de base que le reste) | Un serveur NATS à exploiter |
| **Cas d'usage** | Développement, tests, démo, poste isolé | Pilote mono-site, besoin de reprise après redémarrage sans broker | MSSP, plusieurs sources, montée en charge, découplage |
| **Limites** | Perte totale au redémarrage ; aucun découplage réel | Partagé avec la base : contention du verrou d'écriture SQLite | Brique supplémentaire à superviser, sécuriser et maintenir ; source de panne additionnelle |
| **Effet si indisponible** | — (in-process) | Échec d'écriture disque | `/readyz` renvoie `503` (§4.1) |

Le choix est **une configuration, pas un refactoring** : le code métier (collecteurs, détection,
décision, actions) ne connaît que l'interface, jamais le backend. Le passage de `memory` à `nats`
en production ne doit impliquer aucune modification du cœur.

!!! tip "Le bon chemin de montée en charge"
    `memory` en développement → `sqlite` si l'on veut survivre à un redémarrage sans introduire de
    serveur → `nats` quand plusieurs collecteurs ou plusieurs sites doivent coopérer. Chaque étape
    est un changement de variable d'environnement, pas une réécriture.

!!! warning "`memory` n'est pas un bus de production"
    Avec `THOT_BUS=memory` (le défaut), **aucun événement ne survit à un redémarrage** et
    **aucune distribution entre processus n'a lieu**. Deux instances d'Thot Secure ne se voient pas.
    C'est un défaut volontaire pour l'installation et les tests — et le piège le plus probable pour
    un exploitant qui passe en production sans relire le §9. À signaler clairement dans la
    console, dans la documentation d'exploitation et dans
    [`../operations/deployment.md`](../operations/deployment.md).

---

## Conséquences

### Positives

* **Zéro dépendance par défaut.** Une installation `pip` suffit : pas de broker, pas de service à
  démarrer, pas de port à ouvrir. Le produit démarre sur un poste isolé comme dans un conteneur
  minimal.
* **Tests unitaires simples et hermétiques.** `tests/test_bus.py` (§11) couvre le **fanout du bus
  mémoire** et la **durabilité du bus SQLite** sans aucun service externe — ce qui est la condition
  pour que la suite de tests reste exécutable en CI et en air-gap.
* **Montée en charge progressive sans toucher au code métier.** Le même collecteur, le même moteur
  de détection et le même exécuteur d'actions fonctionnent sur les trois backends : le backend est
  un détail de déploiement.
* **Découplage producteur / consommateur.** Les collecteurs publient, la détection consomme, la
  console et le WebSocket s'abonnent — sans que les uns connaissent les autres. C'est ce qui permet
  de brancher proprement un nouveau consommateur (flux temps réel, export, futur connecteur).
* **Air-gap possible.** `memory` et `sqlite` ne nécessitent aucun réseau ; `nats` peut être hébergé
  à l'intérieur du périmètre.
* **Un seul modèle mental.** Les contributeurs apprennent une interface, pas trois intégrations
  différentes.

### Négatives

* **`memory` perd tout au redémarrage et ne distribue rien.** Un redémarrage du service efface les
  événements en vol ; deux processus ne communiquent pas. Le danger est que ce comportement soit
  découvert en production, au pire moment. Ce n'est pas un défaut d'implémentation, c'est le
  compromis du défaut « zéro dépendance » — mais il doit être **affiché**, pas seulement documenté.
* **`sqlite` partage la base et donc le verrou d'écriture.** Le bus SQLite écrit dans le même
  fichier que l'ingestion, le journal d'audit et les actions : les performances sont **couplées**
  entre des composants qui n'ont aucune raison de l'être. Une ingestion soutenue ralentit
  l'écriture d'audit, et inversement. C'est le coût direct de l'absence de broker, et il s'ajoute à
  la limite « un seul écrivain » déjà assumée dans
  [ADR-0002](0002-python-fastapi-et-sqlite-pour-le-mvp.md).
* **NATS ajoute une brique à exploiter.** Un serveur à installer, configurer, superviser, mettre à
  jour et sauvegarder — plus une **brique à sécuriser** : authentification, TLS, contrôle des
  sujets auxquels un client peut s'abonner ou publier. Un bus ouvert permet à un client compromis
  d'écouter des événements multi-tenant, ce qui contredit la frontière d'isolation du §1 et §10. Le
  durcissement NATS n'est pas optionnel, et il n'est pas gratuit en compétences.
* **NATS devient une source de panne supplémentaire.** Bus indisponible → `/readyz` renvoie `503`
  (§4.1), donc l'instance est retirée du service, et la procédure de diagnostic et de reprise doit
  figurer dans [`../operations/runbook.md`](../operations/runbook.md). Un composant de plus, c'est
  un mode de défaillance de plus.
* **Sémantique de livraison à préciser.** Le contrat ne fige pas le comportement en cas de
  redémarrage d'un consommateur : les trois backends ne garantissent pas spontanément la même chose
  (au-moins-une-fois vs au-plus-une-fois), et le mode de NATS dépend de sa configuration. **Ce point
  doit être explicité et testé dans le code** — il conditionne l'idempotence de la détection : si un
  événement est livré deux fois, une règle à seuil (§5, `threshold.count`) peut produire un finding
  en double ou franchir un seuil artificiellement. À ce stade, le comportement est **à confirmer par
  le code**, pas à supposer ; c'est une dette identifiée.
* **Risque de divergence de comportement entre les trois bus.** Une même séquence d'événements peut
  se comporter différemment selon le backend (ordre, doublons, perte en cas d'arrêt), ce qui produit
  des bugs uniquement reproductibles en production — le pire cas pour le diagnostic. L'interface
  commune réduit le risque mais ne le supprime pas.
* **Effort de maintenance triplé.** Trois implémentations à maintenir, à tester et à faire évoluer
  ensemble : tout changement d'interface doit être appliqué trois fois, et les tests ne couvrent
  aujourd'hui que `memory` et `sqlite` (§11).

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : **tests de conformité communs** exécutés contre les trois backends (même
    scénario, mêmes assertions sur l'ordre, les doublons et la perte), **spécification écrite de la
    sémantique de livraison** et garanties d'idempotence de la détection qui en découlent,
    **durcissement NATS documenté** (authentification, TLS, contrôle des sujets), et métriques
    d'observabilité par bus (profondeur de file, messages abandonnés) exposées avec le reste des
    métriques Prometheus (`GET /metrics`, §4.1).

---

## Alternatives envisagées

| Alternative | Ce qu'elle apportait | Raison du rejet |
|---|---|---|
| **Kafka ou Redpanda** | Journal distribué éprouvé, rétention longue, rejeu d'historique, débit très élevé, écosystème d'outils. | Rejeté : **disproportionné pour un MVP**. Kafka suppose une grappe, un coordinateur, du stockage dimensionné, une supervision dédiée et des compétences d'exploitation que l'utilisateur type n'a pas. Cela contredit frontalement « installable sans chaîne de build complexe » et « sûr à brancher avant d'avoir des credentials ». Le rejeu d'historique est intéressant, mais les événements sont déjà persistés en base — le bus n'a pas à être aussi le journal. |
| **Redis Streams** | Bus léger, très rapide, groupes de consommateurs, déploiement simple, déjà présent dans beaucoup d'infrastructures. | Rejeté : **dépendance supplémentaire** à installer et à exploiter, et **durabilité à configurer** (persistance AOF/RDB, perte possible selon le réglage). On remplace « zéro dépendance par défaut » par « une dépendance légère mais réelle », avec un modèle de durabilité qu'il faut comprendre et durcir — pour un bénéfice qui n'apparaît qu'au-delà de l'échelle visée par le MVP. |
| **RabbitMQ** | Courtier mature, routage souple (AMQP), acquittements et files durables, largement répandu. | Rejeté pour la même raison principale que Redis — une brique de plus à exploiter — et parce que **le modèle AMQP (échanges, files, routage, bindings) est moins adapté à un simple fanout** d'événements vers quelques consommateurs. La souplesse du routage AMQP n'est pas exploitée ici, alors que son coût conceptuel et opérationnel est bien réel. |
| **Bus uniquement en mémoire, avec persistance des événements en base** | Un seul mode de fonctionnement, plus simple : les événements sont écrits en base (durables) et diffusés en direct par un bus mémoire. | Rejeté : **ne distribue pas** et n'offre aucun découplage entre processus. Un collecteur distant ne peut pas publier, la console d'un autre processus ne reçoit rien, et le scénario MSSP multi-sites devient impossible. Le bus mémoire reste le défaut, mais il ne peut pas être la seule option. |
| **Appel direct collecteur → moteur de détection, sans bus** | Le chemin le plus court : moins de code, moins d'indirection, aucune abstraction à maintenir. | Rejeté : **couplage fort**. Diffuser simultanément vers la détection, la console et le WebSocket `WS /api/v1/ws/stream` deviendrait un enchevêtrement d'appels, les collecteurs connaîtraient leurs consommateurs, et l'ajout d'un consommateur (export, corrélation, notification) exigerait de modifier les producteurs. Les tests de bus (§11, `tests/test_bus.py`) n'auraient plus d'objet, et la montée en charge vers NATS serait une réécriture. |
| **SQLite uniquement** | Une seule implémentation à maintenir, durable, sans broker, cohérente avec le choix de persistance du MVP. | Rejeté **comme unique option**, mais **conservé comme option intermédiaire** (c'est exactement le backend `sqlite`). Le motif du rejet partiel : couplage disque et contention du verrou d'écriture avec l'ingestion, l'audit et les actions, et absence de distribution réelle. Une base partagée n'est pas un bus : elle ne fournit ni fanout entre processus, ni découplage, ni montée en charge horizontale. |
| **MQTT** | Protocole léger, adapté aux réseaux contraints et aux flottes de capteurs, largement déployé dans l'Internet des objets. | Rejeté : **orienté IoT**, donc peu aligné avec des collecteurs serveur qui parlent HTTP, TLS et syslog. Sa sémantique de livraison (QoS 0/1/2) et son modèle de sécurité (authentification, ACL par sujet, TLS) devraient être **entièrement redocumentés** pour un public SOC, et le gain par rapport à NATS n'apparaît que sur des liens très contraints, qui ne sont pas le cas d'usage du MVP. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
