# Journal des modifications

*Où consulter l'historique des changements d'Thot Secure, comment lire une entrée, et ce qu'un changement implique pour l'exploitant.*

Cette page **n'est pas** le journal des modifications du projet. Elle explique comment le lire et
comment s'en servir.

## 1. La source unique de vérité

Le journal officiel est le fichier **[`CHANGELOG.md`](https://github.com/thot-corp/thot-secure/blob/main/CHANGELOG.md) à la racine du dépôt**. Il
est tenu à jour par les contributions qui modifient le comportement visible du produit, et il fait
foi : en cas de divergence avec cette page, ou avec toute autre page de documentation, c'est
`CHANGELOG.md` qui a raison.

La convention visée est celle de *Keep a Changelog* : sections par version, entrées classées par
nature de changement, section `Unreleased` pour ce qui est déjà fusionné sans être publié. Le
versionnement visé est le versionnement sémantique (`MAJEUR.MINEUR.CORRECTIF`). Il s'agit du
**principe annoncé** : la conformité exacte du fichier réel se vérifie en le lisant, pas en se
fiant à cette page.

## 2. Comment lire une entrée

| Élément | Ce qu'il indique |
|---|---|
| Numéro de version (`0.1.0`) | Version publiée. `0.1.0` est la version du MVP décrite par le contrat |
| `Unreleased` | Changements fusionnés, non encore publiés : ne pas les supposer disponibles |
| **Ajouté** | Nouvelle capacité (règle, playbook, connecteur, endpoint) |
| **Modifié** | Changement de comportement d'une capacité existante |
| **Corrigé** | Correction de bug, y compris de sécurité lorsque la divulgation est coordonnée |
| **Supprimé** / **Déprécié** | Retrait effectif, ou annonce d'un retrait futur |
| **Sécurité** | Correctif de vulnérabilité, éventuellement accompagné d'un identifiant CVE |

!!! tip
    Pour un déploiement en production, lisez `Unreleased` **avant** de mettre à jour votre copie :
    c'est là que se trouvent les changements de schéma ou de politique qui demandent une action de
    votre part.

## 3. Cette page et `CHANGELOG.md`

| | `CHANGELOG.md` (racine) | `changelog.md` (cette page) |
|---|---|---|
| Nature | Historique factuel, version par version | Guide de lecture et d'exploitation |
| Public | Contributeurs, exploitants, auditeurs | Exploitants, nouveaux arrivants |
| Mise à jour | À chaque changement visible, dans la même pull request | Rarement, quand la politique évolue |
| Autorité | **Fait foi** | Explicative |

## 4. Politique de version

* Le projet est en `0.y.z` : chaque version mineure peut introduire des changements de
  comportement, et les correctifs restent rétrocompatibles par principe.
* Une **rupture de l'API `/api/v1` reste possible avant `1.0.0`**. Elle doit être annoncée dans
  `CHANGELOG.md` et accompagnée d'une note de migration.
* Le **contrat d'interface est gelé** pour le sprint 1 : toute divergence entre le code et
  [architecture/api-contract.md](architecture/api-contract.md) est un défaut, pas une évolution.
  Faire évoluer le contrat demande une discussion préalable, puis une mise à jour du document.
* Aucune date de publication n'est promise. Aucune version n'est annoncée à l'avance.

## 5. Monter de version

La procédure opérationnelle — sauvegarde, arrêt propre, application du schéma, vérification des
sondes, contrôle de l'audit — est décrite dans
[operations/deployment.md](operations/deployment.md). Deux contrôles minimum après toute montée
de version :

1. `GET /readyz` retourne `200` (base + bus + règles).
2. `GET /api/v1/audit/verify` retourne `{"valid": true}` — la chaîne d'audit n'a pas été altérée.

!!! warning
    L'outillage de migration est encore minimal au MVP (`thotsecure init-db`). Sauvegardez la base
    **avant** toute mise à jour, et lisez les notes de version correspondantes avant d'appliquer
    quoi que ce soit.

## 6. Impact d'un changement, par type

| Type de changement | Impact | Action requise par l'exploitant |
|---|---|---|
| Ajout d'une règle de détection | Nouveaux findings possibles, y compris des faux positifs | Revoir la règle, la passer en `notify_only` si besoin, ajuster les seuils |
| Modification d'une règle existante | Le volume et la sévérité des findings peuvent varier | Comparer les findings avant/après sur une fenêtre d'observation |
| Changement de schéma de base | Migration nécessaire | Sauvegarder, appliquer le schéma, vérifier `/readyz`, contrôler l'audit |
| Changement de politique de décision | Une décision peut passer de `notify_only` à `require_approval` ou `auto` | Relire les politiques livrées, réconcilier avec vos politiques locales |
| Changement d'API `/api/v1` | Rupture possible avant `1.0.0` | Mettre à jour les clients, les scripts et les intégrations SIEM |
| Changement de configuration | Nouvelles variables, ou valeurs par défaut modifiées | Relire la configuration, vérifier les défauts sûrs (`DRY_RUN`, `AUTONOMY`) |
| Correctif de sécurité | Le comportement peut changer volontairement | Appliquer sans attendre, puis vérifier les journaux d'audit |

## 7. Voir aussi

* [Architecture et contrat d'interface](architecture/api-contract.md) — référence de compatibilité
* [Déploiement et exploitation](operations/deployment.md) — procédure de montée de version
* [Feuille de route](roadmap.md) — ce qui est livré, à l'étude, ou hors périmètre
* [Contribuer](contributing.md) — mise à jour de `CHANGELOG.md` dans la pull request

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
