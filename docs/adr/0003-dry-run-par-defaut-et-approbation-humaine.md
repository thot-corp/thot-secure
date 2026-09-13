# ADR-0003 — Dry-run par défaut et approbation humaine

*À l'installation, Thot Secure n'exécute aucune contre-mesure réelle : le dry-run est actif par défaut
et l'autonomie est supervisée, l'exécution réelle n'étant activée qu'explicitement, tenant par
tenant.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté** et considéré comme non négociable pour la version 0.1.0 : c'est l'invariant 1 du
contrat (« `DRY_RUN=true` par défaut ; aucune action réelle n'est exécutée sans levée explicite »,
[`../architecture/api-contract.md`](../architecture/api-contract.md) §1). Une évolution de cette
décision exigerait une nouvelle ADR remplaçant celle-ci.

---

## Contexte

Thot Secure est un SOAR : il ne se contente pas d'observer, il **agit** sur l'infrastructure de
production. Les playbooks livrés (§7) bloquent des IP au niveau d'un WAF ou d'un pare-feu,
appliquent un rate limiting, mettent en quarantaine un artefact, révoquent une session, rotationnent
un secret, isolent un hôte, ouvrent une PR de correctif ou appliquent un profil de durcissement.
Autrement dit, le produit dispose des mêmes primitives qu'un attaquant obtiendrait en compromettant
la console.

Une erreur d'automatisation en sécurité n'est pas une erreur d'affichage : elle coupe un service.
Trois causes réalistes de faux pas :

1. **Faux positif de détection.** Une règle trop large (§5) — par exemple un motif d'injection SQL
   qui matche un champ de recherche libre contenant « union » — désigne un client légitime comme
   attaquant.
2. **Politique mal écrite.** Une politique (§6) dont le `when` est plus permissif que prévu
   (`finding.risk_score: { gte: 70 }` sur un tenant `auto` avec des tags trop génériques) déclenche
   une vague d'actions.
3. **Effet de bord interne.** Bloquer un CIDR, durcir un endpoint ou isoler un hôte peut bloquer
   ses propres utilisateurs, ses propres sondes ou une dépendance interne — un déni de service
   auto-infligé, exactement le type de dommage collatéral que le produit refuse de provoquer chez
   un tiers (voir [ADR-0006](0006-zero-capacite-offensive-comme-invariant.md)).

À l'inverse, la confiance dans une automatisation de sécurité ne se décrète pas : elle se construit
par paliers. Une équipe doit d'abord observer ce que le produit *aurait fait*, constater ses faux
positifs, corriger ses règles et ses politiques, puis seulement déléguer l'exécution. Un produit
qui demande une confiance immédiate n'est pas adopté — il est installé en démonstration, puis
désinstallé.

Le contexte d'usage ajoute une contrainte : chez un MSSP, plusieurs tenants coexistent et n'ont ni
le même niveau de maturité ni la même tolérance au risque. Le réglage de sûreté doit donc être
**par tenant**, pas seulement global.

---

## Décision

### Défauts sûrs

| Réglage | Valeur par défaut | Portée | Source |
|---|---|---|---|
| `THOT_DRY_RUN` | `true` | globale, surchargeable par tenant | §9 |
| `THOT_AUTONOMY` | `supervised` | globale, surchargeable par tenant | §9 |
| `Tenant.mode` | `supervised` | tenant | §4.2 |
| `Tenant.dry_run` | `true` | tenant | §4.2 |
| `autonomy_allowlist` | vide (aucune cible protégée déclarée) | tenant | §4.2 |

Conséquence directe : **aucune action réelle n'a lieu sur une installation neuve**, quel que soit
le contenu d'une politique. Le `dry_run` global est **prioritaire sur toute politique** — une
politique ne peut pas le désactiver (garde-fou 4, §6, « non contournable par une politique »).

### Cycle de vie d'une action

Le statut initial d'une action est **`planned`** (via `POST /api/v1/actions/plan`, qui n'a « aucun
effet de bord », §4.6), puis **`pending_approval`** selon le mode et la politique. Le cycle complet
défini au §3.4 est : `planned | pending_approval | approved | rejected | executing | succeeded |
failed | expired | rolled_back`.

| Mode tenant | Décision attendue | Approbation humaine |
|---|---|---|
| `manual` | `require_approval` ou `notify_only` | systématique avant toute exécution |
| `supervised` | `require_approval` pour les actions significatives | oui, sauf politique explicite en périmètre déclaré |
| `auto` | `auto` possible via politique | non, mais journalisation complète (`actor`, `policy_id`, `before`, `after`, §1.2) |

`require_approval` est **obligatoire** dans deux cas, indépendamment du mode : toute action sur une
**cible hors périmètre déclaré du tenant** (garde-fou 5, §6) et toute **action critique** (§1.2).
L'approbation passe par `POST /api/v1/actions/{id}/approve` avec la capacité `approve:actions`
(rôle `responder` ou `admin`, §4), et l'exécution est refusée tant que l'action n'est pas approuvée
(`409`, §4.6).

### Propagation du drapeau

`dry_run` est un champ de premier ordre, présent dans l'objet `Decision` (§3.3) **et** dans l'objet
`Action` (§3.4). Il n'est pas un paramètre implicite de l'exécuteur : il est visible dans chaque
objet que l'API expose, donc dans les rapports, l'audit et la console.

### Mode simulé des connecteurs

Un connecteur non configuré fonctionne en **mode simulé** (`null` / `simulation`, §7) : il retourne
un `rollback_token` et journalise `simulated: true`. C'est le comportement par défaut du MVP :
**Thot Secure est sûr à brancher avant d'avoir des credentials**. On peut donc installer le produit,
brancher les collecteurs, observer les findings, planifier des actions et vérifier les rollbacks
avant qu'une seule clé d'API Cloudflare ou AWS n'existe.

### Levée explicite

Le mode `auto` s'active **uniquement de façon explicite, au niveau du tenant**, par
`PATCH /api/v1/tenants/{id}` avec `{"mode":"auto","dry_run":false}` (capacité `admin:tenants`, §4.2).
Il n'existe pas de chemin plus discret : ni fichier de politique, ni variable globale ne peut
activer l'exécution réelle pour un tenant qui ne l'a pas demandé.

### Visibilité permanente du mode

Le mode d'autonomie et l'état du dry-run doivent être affichés dans `GET /version`, dans
`GET /api/v1/auth/whoami` et dans `GET /api/v1/stats/overview` (§4.1, §4.8). Un opérateur doit
pouvoir répondre à « suis-je protégé ou seulement en simulation ? » sans interpréter des logs.

!!! warning "Le mode simulé n'est pas une protection"
    Un déploiement en dry-run produit des findings, des décisions et des actions planifiées — mais
    **aucune protection effective**. C'est une phase d'observation, pas une phase de défense.

---

## Conséquences

### Positives

* **Zéro effet de bord à l'installation.** Un nouvel utilisateur peut installer Thot Secure sur une
  infrastructure de production sans risque de couper un service. C'est la condition pour que le
  produit soit essayé là où il compte.
* **Démonstration et évaluation sans risque.** `thotsecure demo --tenant demo` (§8) et le mode simulé
  des connecteurs permettent une démonstration complète — findings, actions, rollback, audit — sans
  credentials et sans effet réel.
* **Adoption progressive et réversible.** Le parcours `manual` → `supervised` → `auto` est
  explicite et documenté : chaque palier s'appuie sur l'observation du précédent.
* **Apprentissage des faux positifs avant d'accorder l'autonomie.** La phase supervisée sert
  exactement à mesurer le taux de faux positifs et à corriger les règles avant de laisser le
  produit agir seul. C'est la seule façon honnête d'acquérir cette donnée.
* **Valeur probante en audit.** Le journal (§4.7, §3.5) montre qui a approuvé quoi, quand, avec
  quelle politique, quel `before`/`after` et quel `dry_run`. Un auditeur peut reconstituer la
  chaîne de responsabilité d'une contre-mesure.
* **Refus explicite opposable.** « Le produit ne fait rien sans vous » est un argument de vente
  vérifiable — et un argument de conformité pour un RSSI qui doit justifier chaque automatisation
  devant sa direction.

### Négatives

* **Latence de réponse.** Une approbation humaine peut arriver après l'attaque. Sur une attaque
  automatisée de quelques secondes, une contre-mesure appliquée dix minutes plus tard n'a plus
  d'effet défensif : elle documente l'incident au lieu de le contenir. Le dry-run par défaut, lui,
  ne protège pas du tout tant qu'il est actif.
* **Charge d'astreinte et fatigue d'approbation.** Un flux d'actions `pending_approval` doit être
  traité par un humain, y compris la nuit. La conséquence documentée de la fatigue d'approbation
  est connue : on approuve sans lire. Un garde-fou « approuver tout » est le pire résultat
  possible, et il est atteignable par simple lassitude.
* **« Auto par paresse ».** La tentation de passer en `mode: auto` pour faire disparaître la file
  d'approbations, sans revue des règles ni mesure du taux de faux positifs. Le produit ne peut pas
  l'empêcher : il peut seulement rendre le changement explicite, journalisé et attribuable à un
  `actor`.
* **Confusion entre « simulé » et « réel » dans les tableaux de bord.** Un compteur d'« actions
  réussies » qui mélange exécutions réelles et simulations est trompeur, et un opérateur peut
  croire son périmètre protégé. *Mitigation :* l'exigence d'afficher le mode dans `GET /version`,
  `whoami` et `stats/overview`, et la présence de `dry_run` dans `Decision` et `Action`.
* **Risque de fausse assurance.** Un exploitant qui laisse `THOT_DRY_RUN=true` en croyant avoir
  une protection active se trouve dans la situation la plus dangereuse : il dispose d'une
  télémétrie de qualité, mais d'aucune défense. C'est un risque de communication, pas seulement
  technique.
* **Complexité de la matrice mode × politique × périmètre.** Trois niveaux (global, tenant,
  politique) interagissent ; le comportement attendu n'est pas toujours évident, et une explication
  claire dans [`../decision/policies.md`](../decision/policies.md) est nécessaire pour éviter les
  malentendus.

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : garde-fous supplémentaires — **approbation à deux personnes** pour les
    actions critiques, **revue périodique automatique des politiques** (signalement des politiques
    qui déclenchent le plus d'actions, ou dont le taux de faux positifs est élevé), et éventuellement
    un délai de sécurité avant exécution en mode `auto` (voir l'alternative *soak time* ci-dessous).

---

## Alternatives envisagées

| Alternative | Ce qu'elle apportait | Raison du rejet |
|---|---|---|
| **Exécution réelle par défaut** | Protection immédiate dès l'installation, aucune action manuelle, valeur perçue plus forte. | Rejeté : irresponsable. Un faux positif peut couper la production d'un client ; un produit qui agit avant d'avoir été observé transforme un défaut de règle en incident de production. Le gain de rapidité ne compense jamais le risque de déni de service interne sur l'infrastructure de l'utilisateur. |
| **Approbation systématique de toutes les actions** | Sécurité maximale, aucun risque d'action non voulue, responsabilité humaine sur chaque effet de bord. | Rejeté : la fatigue d'approbation annule le bénéfice. Une file d'approbations où 95 % des éléments sont des faux positifs évidents conduit à approuver sans lire — c'est-à-dire à une automatisation non supervisée avec une illusion de contrôle, plus dangereuse que l'automatisation assumée. L'automatisation perd aussi tout intérêt : le SOAR devient une file de travail manuelle. |
| **Délai de sécurité avant exécution (*soak time*)** | Laisser une fenêtre (par exemple quelques minutes) pendant laquelle une action `auto` reste annulable avant exécution, ce qui rattrape la plupart des faux positifs sans exiger d'approbation. | Rejeté **au MVP**, mais l'idée est intéressante et honnêtement conservée : elle réduit le risque d'action erronée sans ajouter de latence humaine, et se combine bien avec le mode `auto`. Elle est écartée pour l'instant parce qu'elle ajoute un état supplémentaire au cycle de vie d'une `Action` (§3.4, où `expires_at` existe déjà) et des cas limites à tester (`tests/test_actions_rollback.py`, §11) dans un MVP dont la priorité est ailleurs. À reconsidérer dès que le mode `auto` sera réellement utilisé. |
| **Simulation par « mode test » du connecteur uniquement** | Ne pas toucher aux défauts de sûreté : laisser `dry_run=false` et obtenir la simulation en configurant le connecteur `null`. | Rejeté : ne couvre pas le cas **sans credentials**. C'est précisément la situation d'un premier déploiement : si le dry-run dépendait de la configuration d'un connecteur, un utilisateur disposant d'un vrai connecteur WAF se retrouverait avec une exécution réelle dès le premier lancement, sans l'avoir demandé. Le dry-run doit être un défaut du produit, indépendant de l'état des connecteurs. |
| **Activation de l'autonomie par variable d'environnement globale seulement** | Un seul réglage (`THOT_AUTONOMY=auto`) pour toute l'instance : plus simple à comprendre et à exploiter. | Rejeté : le grain tenant est nécessaire pour les MSSP. Un prestataire gère des clients avec des maturités et des tolérances au risque différentes ; imposer un mode global obligerait à faire tourner une instance par client (ou à imposer `auto` à tout le monde). `THOT_AUTONOMY` reste le défaut global (§9), mais la surcharge par tenant via `PATCH /api/v1/tenants/{id}` est indispensable. |
| **Dry-run par tenant uniquement, sans défaut global** | Moins de niveaux de configuration, un comportement par tenant plus lisible. | Rejeté : sans défaut global sûr, un tenant mal créé pourrait hériter d'une exécution réelle. Le défaut global `THOT_DRY_RUN=true` est ce qui garantit qu'une installation neuve, même mal configurée, ne produit aucun effet de bord. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
