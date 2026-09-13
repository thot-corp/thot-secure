# ADR-0001 — Journaliser les décisions d'architecture

*Nous consignons chaque décision d'architecture structurante dans un fichier ADR versionné avec le
code, au format Nygard, plutôt que dans un wiki externe, des commentaires de code ou une mémoire
collective non écrite.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté.** Cette ADR est elle-même le premier exemplaire de la pratique qu'elle instaure : elle
est rédigée selon le format qu'elle impose aux décisions suivantes, et elle est livrée avec la
version 0.1.0 (MVP) du contrat d'interface [`../architecture/api-contract.md`](../architecture/api-contract.md).

Le processus décrit ici n'a pas de mécanisme d'application automatique : il repose sur la revue de
pull request. Cette faiblesse est assumée et détaillée dans les conséquences négatives.

---

## Contexte

Thot Secure est un produit de sécurité **défensif** : SOAR/CSPM multi-tenant dont le contrat
d'interface est gelé par sprint et dont les invariants (§1 du contrat) sont non négociables. Trois
pressions rendent la traçabilité des décisions structurantes nécessaire :

1. **La justification externe.** Un RSSI, un auditeur ou un acheteur public ne demande pas
   seulement *ce que fait* le produit, mais *pourquoi* il a été conçu ainsi. Répondre « c'est le
   choix de l'équipe » n'est pas une réponse acceptable dans un appel d'offres. Les questions
   récurrentes sont prévisibles : pourquoi une chaîne de hash et pas une blockchain, pourquoi
   SQLite par défaut, pourquoi l'exécution réelle est-elle désactivée à l'installation, pourquoi
   aucun scanner actif n'est fourni.
2. **Le coût de la rediscussion.** Un projet open source reçoit des contributions et des issues
   d'auteurs qui n'ont pas assisté aux discussions initiales. Sans trace écrite, chaque nouveau
   contributeur rouvre les mêmes débats, et les mainteneurs répondent *ex nihilo* à des questions
   déjà tranchées — ou, pire, retranchent différemment selon l'interlocuteur, ce qui produit une
   dérive silencieuse.
3. **La cohérence avec ce que le produit vend.** Thot Secure journalise de façon append-only chaînée
   par hash chaque décision d'action, chaque approbation, chaque rollback (§3.5, §4.7 et §10 du
   contrat). Il serait incohérent — et attaquable en revue — qu'un produit qui impose la
   traçabilité à ses utilisateurs ne trace pas ses propres choix structurants. Un projet défensif
   doit s'appliquer à lui-même l'exigence qu'il vend.

Le contexte technique aggrave ces pressions : le dépôt est organisé pour être installable et
auditable par un tiers ([`../architecture/overview.md`](../architecture/overview.md)), le code, les
règles YAML, les politiques et les playbooks vivent dans le même arbre Git, et la version 0.1.0 est
un MVP à équipe réduite. Toute forme de documentation qui vit ailleurs que dans le dépôt se
désynchronise en quelques semaines.

---

## Décision

Nous adoptons les **Architecture Decision Records (ADR) au format Nygard** comme unique mécanisme de
journalisation des décisions d'architecture.

### Format et emplacement

* Un fichier Markdown par décision, dans `docs/adr/`.
* Nom de fichier : `NNNN-titre-en-kebab-case.md`, numéro à quatre chiffres, jamais réutilisé.
* Sections imposées, dans cet ordre : `## Statut`, `## Contexte`, `## Décision`,
  `## Conséquences`, `## Alternatives envisagées`.
* En-tête de statut en tête de fichier, puis phrase de résumé en italique, puis les sections.
* Les ADR sont publiées dans la navigation MkDocs, entre `architecture/` et `detection/`.

### Règles de gestion

| Règle | Contenu |
|---|---|
| **Immuabilité** | Une ADR acceptée n'est **jamais** réécrite sur le fond. Un changement d'avis produit une nouvelle ADR qui la remplace ; l'ancienne reçoit `Remplacé par : ADR-NNNN` et son statut passe à `Remplacée`. L'historique du raisonnement est la valeur du document. |
| **Qui propose** | Tout contributeur, via une pull request ajoutant le fichier. Une ADR proposée par un contributeur externe suit le même chemin de revue qu'une modification de code. |
| **Qui accepte** | Les mainteneurs d'Thot Secure, selon les règles de revue et de consensus décrites dans [`../governance.md`](../governance.md) et le fichier `CONTRIBUTING.md` à la racine du dépôt. Une ADR non acceptée reste `Proposée` et ne fait pas autorité. |
| **Versionnement** | Les ADR sont versionnées avec le code, dans le même dépôt et la même branche : une ADR et l'implémentation qu'elle décrit doivent pouvoir être lues au même commit. |
| **Traçabilité croisée** | Le code concerné référence l'ADR dans un commentaire ou dans le message de commit ; l'ADR référence les sections du contrat d'interface qu'elle interprète. |
| **Fin de vie** | Une ADR ne se supprime pas. Une décision devenue sans objet reçoit le statut `Dépréciée` et un motif. |

### Quand créer une ADR

Une ADR est requise dès qu'au moins un des critères suivants est satisfait :

* la décision est **structurante** : elle contraint l'architecture au-delà d'un module ou d'un
  sprint ;
* elle est **coûteuse ou difficile à inverser** (choix de persistance, de protocole, de format de
  hash, de modèle de distribution) ;
* elle est **transverse** : elle concerne plusieurs paquets, la CLI, l'API et la documentation ;
* elle porte une **contrainte de sécurité** ou de conformité, y compris un refus explicite de
  fonctionnalité ;
* elle tranche un **compromis** que la communauté rouvrira sinon périodiquement.

### Quand ne pas créer d'ADR

* Correction de bug, refactoring interne sans effet sur les interfaces, renommage.
* Choix local et réversible à l'intérieur d'un module (nom d'une fonction, structure d'une
  dataclass privée).
* Détail d'implémentation déjà entièrement déterminé par le contrat d'interface gelé : le contrat
  fait autorité, l'ADR serait redondante.
* Décision opérationnelle ponctuelle (fenêtre de maintenance, incident) : sa place est dans
  [`../operations/runbook.md`](../operations/runbook.md), pas dans une ADR.

!!! tip "Règle de pouce"
    Si un nouveau contributeur peut lire le code et se demander « pourquoi diable ont-ils fait
    ça ? » sans pouvoir le déduire du contrat d'interface, c'est un candidat ADR.

!!! note "Ce que cette ADR ne couvre pas"
    Le format des règles, des politiques et des playbooks est normé par le contrat d'interface
    (§5, §6, §7) et non par une ADR : ce sont des contrats d'interface publics, pas des décisions
    internes. Les ADR expliquent les *arbitrages* ; le contrat décrit les *formats*.

---

## Conséquences

### Positives

* **Mémoire du projet.** Le raisonnement, et surtout les options écartées, survivent au départ des
  personnes qui les ont portées. Le coût d'onboarding baisse : un nouvel arrivant lit six ADR et
  comprend pourquoi le produit se comporte comme il se comporte.
* **Justification auditable.** Les réponses à un RSSI ou à un auditeur sont des documents datés,
  versionnés et citables, pas des affirmations orales. Les décisions de sécurité — dry-run par
  défaut, zéro capacité offensive, audit chaîné — deviennent des engagements écrits dont on peut
  mesurer l'écart avec le code.
* **Dialogue avec les utilisateurs.** Une ADR qui expose franchement ses conséquences négatives
  permet à un utilisateur d'évaluer le produit pour *son* contexte, et de contester le compromis
  avec des arguments plutôt que par une demande de fonctionnalité.
* **Frein aux décisions par accident.** Rédiger une ADR force à énoncer les alternatives et leur
  raison de rejet ; plusieurs choix mal préparés s'arrêtent à cette étape, ce qui est le résultat
  recherché.
* **Cohérence doctrinale.** Le produit exige la traçabilité de ses utilisateurs ; le projet
  s'applique la même exigence. C'est un argument de crédibilité vérifiable.

### Négatives

* **Charge de maintenance réelle.** Chaque décision structurante coûte une à deux heures de
  rédaction, en plus de l'implémentation, pour une équipe réduite. Le coût est payé immédiatement
  et le bénéfice est différé — la pire combinaison pour un MVP.
* **Risque d'ADR « de façade ».** Une ADR peut décrire une intention que le code ne respecte pas.
  Le document devient alors un alibi : il donne l'impression d'une décision réfléchie là où le code
  fait autre chose. C'est le risque le plus sérieux, et il n'est neutralisé par aucun outil.
* **Dérive entre ADR et code.** Le contrat d'interface est gelé et testé ; une ADR ne l'est pas.
  Rien n'empêche mécaniquement une évolution de code de contredire une ADR acceptée. *Mitigation :*
  la revue en pull request — toute PR qui contredit une ADR doit soit la modifier (nouvelle ADR),
  soit être refusée ; le lien ADR → code est vérifié comme le reste.
* **Faux sentiment de sécurité documentaire.** Une ADR n'est pas un contrôle technique. Écrire
  « zéro capacité offensive » ne l'empêche pas ; seuls les tests et l'absence d'API le font.
* **Risque de rigidité.** L'immuabilité et la cérémonie peuvent décourager une correction utile,
  surtout si le processus est appliqué à des choix réversibles. La liste « quand ne pas créer
  d'ADR » existe précisément pour contenir ce risque.
* **Bruit de navigation.** Sans discipline, `docs/adr/` devient une liste de documents hétérogènes.
  L'index ci-dessous est la contre-mesure, et il doit être mis à jour à chaque ajout.

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : un test de cohérence en CI vérifiant que chaque ADR citée depuis le code
    existe et que l'index est complet (numéroté sans trou, liens résolus), et un modèle de fichier
    (`docs/adr/template.md`) une fois que le format aura été éprouvé sur plusieurs décisions.

---

## Index des ADR

| N° | Titre | Statut | Résumé | Lien |
|---|---|---|---|---|
| 0001 | Journaliser les décisions d'architecture | Accepté | Toute décision structurante devient une ADR Nygard versionnée avec le code. | [ADR-0001](0001-record-architecture-decisions.md) |
| 0002 | Python + FastAPI et SQLite pour le MVP | Accepté | Cœur stdlib + pydantic/PyYAML, API FastAPI, persistance SQLite par défaut, PostgreSQL documenté comme cible. | [ADR-0002](0002-python-fastapi-et-sqlite-pour-le-mvp.md) |
| 0003 | Dry-run par défaut et approbation humaine | Accepté | Aucune action réelle à l'installation : `DRY_RUN=true` et `AUTONOMY=supervised` par défaut. | [ADR-0003](0003-dry-run-par-defaut-et-approbation-humaine.md) |
| 0004 | Journal d'audit chaîné par hash plutôt que blockchain | Accepté | Immuabilité par chaîne SHA-256 locale, vérifiable et exportable, sans infrastructure externe. | [ADR-0004](0004-audit-log-chaine-par-hash-plutot-que-blockchain.md) |
| 0005 | Bus d'événements enfichable : memory, sqlite, nats | Accepté | Une interface, trois implémentations ; `memory` par défaut, NATS pour la distribution. | [ADR-0005](0005-bus-pluggable-memory-sqlite-nats.md) |
| 0006 | Zéro capacité offensive comme invariant | Accepté | Aucun scan agressif, brute force, hack-back ou DoS : l'invariant est structurel, pas déclaratif. | [ADR-0006](0006-zero-capacite-offensive-comme-invariant.md) |

### Lectures associées

* Le contrat d'interface, source de vérité des invariants et des formats :
  [`../architecture/api-contract.md`](../architecture/api-contract.md).
* La vue d'ensemble de l'architecture : [`../architecture/overview.md`](../architecture/overview.md).
* Le modèle de menaces, qui référence plusieurs de ces décisions :
  [`../architecture/threat-model.md`](../architecture/threat-model.md).
* La gouvernance du projet, qui fixe qui peut accepter une ADR : [`../governance.md`](../governance.md).
* Le processus de contribution, qui impose la revue en PR : `CONTRIBUTING.md` à la racine du dépôt.

---

## Alternatives envisagées

| Alternative | Description | Raison du rejet |
|---|---|---|
| **Wiki externe** (GitHub Wiki, Notion, Confluence) | Documenter les décisions hors du dépôt, dans un outil collaboratif. | Hors dépôt : non versionné avec le code, non clonable en air-gap, non revu en pull request, non citable par un commit. La désynchronisation est garantie dès la première divergence de branche, et la suppression accidentelle d'une page ne laisse aucune trace. Un audit qui exige « la décision au commit X » est impossible à satisfaire. |
| **Commentaires et docstrings dans le code** | Expliquer les choix directement là où ils s'appliquent. | Trop locaux : un commentaire explique une ligne, pas un arbitrage transversal entre persistance, API, tests et documentation. Ils ne sont pas découvrables (personne ne lit un module qu'il ne modifie pas), ils se périment silencieusement lors des refactorings, et ils ne permettent pas d'exposer les alternatives écartées. Ils restent utiles — et complémentaires : l'ADR porte la décision, le commentaire porte le détail. |
| **RFC lourdes** (document de spécification, période de commentaires, votes) | Processus formel de proposition, type IETF ou PEP, avec numéros et états. | Trop de cérémonie pour un MVP à équipe réduite : délais de commentaires, format étendu, gestion d'états multiples. Le coût de rédaction dépasse le bénéfice pour des décisions réversibles, et la lourdeur décourage précisément l'écriture régulière qu'on veut obtenir. Les ADR conservent le numéro et l'immuabilité, sans la procédure. |
| **Décisions non documentées** (statu quo) | S'appuyer sur la mémoire de l'équipe, les fils de discussion et les messages de commit. | Rejeté : c'est l'état qui produit les trois problèmes du contexte. Les discussions se perdent, les nouveaux contributeurs rouvrent les débats, et le projet ne peut pas justifier ses choix de sécurité auprès d'un auditeur. Le coût de la documentation est faible devant le coût de la rediscussion et de l'incohérence. |
| **Un fichier unique de décisions** | Un seul document `DECISIONS.md` listant toutes les décisions. | Les décisions ont des durées de vie différentes : un fichier unique grossit sans limite, mélange les statuts, provoque des conflits de fusion permanents et rend impossible le remplacement d'une décision sans réécrire l'historique. Un fichier par décision garde des diffs propres et un statut local. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
