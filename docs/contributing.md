# Contribuer

*Guide de première contribution à Thot Secure : par où commencer, comment proposer une règle, une politique, un playbook ou de la documentation, et ce que le projet refuse.*

!!! note
    Le **guide de référence** est [`CONTRIBUTING.md`](https://github.com/thot-corp/thot-secure/blob/main/CONTRIBUTING.md), **à la racine du
    dépôt** : il décrit l'environnement de développement, la convention de commits, le
    *Developer Certificate of Origin* et la checklist de pull request. Cette page-ci est le
    **guide de première contribution** : elle vous met le pied à l'étrier. En cas de divergence,
    c'est `CONTRIBUTING.md` qui fait foi.

---

## 1. Code de conduite

Toute participation — issue, discussion, revue, pull request — est encadrée par
[`CODE_OF_CONDUCT.md`](https://github.com/thot-corp/thot-secure/blob/main/CODE_OF_CONDUCT.md), à la racine du dépôt. En contribuant, vous vous
engagez à le respecter. Les signalements se font par les canaux indiqués dans ce fichier, jamais en
public.

## 2. Par où commencer

Suivez cet ordre, il vous fera gagner du temps :

1. **Installer l'environnement** — voir [installation.md](installation.md) (déploiement local,
   sans dépendance externe obligatoire).
2. **Vérifier votre poste** — `thotsecure doctor` doit signaler une configuration exploitable avant
   tout autre travail.
3. **Lancer les tests** :
   ```bash
   python -m unittest discover -s tests -t . -v
   ```
   La suite est exécutable sans dépendance externe (contrat §11). `pytest` est utilisé en CI et
   fonctionne également.
4. **Lire le contrat avant de coder** — [architecture/api-contract.md](architecture/api-contract.md).
   Ce document est **gelé pour le sprint 1** : la conformité au contrat est **obligatoire**, pour
   le code comme pour la documentation. Une divergence est un défaut, pas une initiative.
5. **Récupérer les hooks** — `CONTRIBUTING.md` décrit l'installation des vérifications locales
   (*pre-commit*) à exécuter avant de pousser.

!!! warning
    Si vous découvrez un écart entre le contrat et le code, **ne corrigez pas silencieusement l'un
    pour faire coller l'autre** : ouvrez une discussion. C'est le contrat qui tranche, ou il est
    amendé explicitement.

## 3. Parcours « première contribution »

1. **Forker** le dépôt et travailler sur votre fork, jamais directement sur le dépôt amont.
2. **Créer une branche** au nom explicite, avec une portée unique : un correctif, une règle, une
   page. Pas de branche fourre-tout.
3. **Faire le changement minimal** qui résout le problème. Une pull request courte se relit, une
   pull request tentaculaire s'oublie.
4. **Ajouter ou adapter un test**. Une contribution sans test, ou avec une suite rouge, ne sera pas
   fusionnée.
5. **Écrire un message de commit clair**, au format conventionnel utilisé par le projet :
   `type(portée): description`. Exemples : `feat(detection): add rule for encoded path traversal`,
   `fix(decision): honour cooldown on repeated approvals`, `docs(contributing): clarify rollback
   requirement`. Les commits doivent être signés selon la procédure du *Developer Certificate of
   Origin* décrite dans `CONTRIBUTING.md`.
6. **Ouvrir la pull request** en expliquant le **pourquoi** (le problème, le contexte, les
   alternatives écartées), puis **répondre aux commentaires de revue** par de nouveaux commits —
   pas de réécriture d'historique en cours de revue.

| Type de contribution | Difficulté | Où regarder |
|---|---|---|
| Règle de détection | Facile à moyen | `rules/` + [detection/rules.md](detection/rules.md) |
| Politique de décision | Moyen | `policies/` + [decision/policies.md](decision/policies.md) |
| Playbook ou connecteur | Avancé | `playbooks/` + [actions/playbooks.md](actions/playbooks.md) |
| Documentation | Facile | `docs/` (MkDocs Material) |
| Test, jeu de données, faux positif documenté | Facile à moyen | `tests/` (contrat §11) |
| Correctif | Variable | Le paquet concerné dans `src/thotsecure/` |
| Traduction | Moyen | `docs/` — discutez d'abord de la structure, le français est la langue de référence |
| Conformité, durcissement, packaging | Moyen à avancé | `deploy/`, [operations/deployment.md](operations/deployment.md) |

## 4. Contribuer une règle de détection

1. **Écrire la règle** en YAML dans la bibliothèque `rules/`, au format du contrat §5 : `id`,
   `title`, `severity`, `confidence`, `enabled`, `tags`, `source_types`, `kinds`, `match`
   (`all`/`any`/`not`, seuil optionnel), `dedup`, `risk`, `false_positives`, `remediation`.
2. **La valider** :
   ```bash
   thotsecure rules validate --path rules
   ```
   ou, côté API, `POST /api/v1/rules/validate` (capacité `admin:rules`). Une règle invalide ne
   casse pas le chargement : elle est rejetée avec un diagnostic — lisez-le.
3. **Tester** le comportement dans `tests/test_rules_engine.py` : opérateurs utilisés, logique
   `all`/`any`/`not`, seuils, déduplication, et le cas d'une règle invalide.
4. **Documenter les faux positifs** connus dans le bloc `false_positives`, et rédiger une
   `remediation` actionnable (qui, quoi, dans quel ordre).
5. **Penser bruit avant sensibilité** : une règle qui déclenche 200 fois par jour ne sera pas
   exploitée. Préférez une condition plus étroite à un seuil élevé qui masque l'essentiel.

Rappels utiles : les expressions régulières sont compilées avec un **timeout d'exécution** (anti
ReDoS), et le score de risque est modulé par la sévérité, la confiance et la criticité de l'actif.
Détails : [detection/rules.md](detection/rules.md).

## 5. Contribuer une politique

1. **Écrire la politique** en YAML dans `policies/` (ou en Rego dans `policies/rego/` lorsque le
   mode OPA est disponible) : `id`, `priority`, `description`, `when`, `then`, `rollback`.
2. **La valider** :
   ```bash
   thotsecure policies validate
   ```
   puis vérifier l'ordre de priorité obtenu (`GET /api/v1/policies`).
3. **L'essayer en `notify_only` ou en dry-run d'abord.** Une politique de blocage automatique ne
   doit jamais être la première version mise en service : observez, puis durcissez.
4. **Vérifier les garde-fous** : une politique ne peut pas contourner le plafond horaire, le
   cooldown, la protection des cibles de l'allowlist, ni la priorité du dry-run global. Si votre
   politique en a besoin pour « fonctionner », elle est mal conçue.
5. **Tester** les cas limites dans `tests/test_decision.py` : première correspondance gagnante,
   priorité, cas sans correspondance (→ `notify_only`).

Détails : [decision/policies.md](decision/policies.md).

## 6. Contribuer un playbook ou un connecteur

Exigences **non négociables** pour toute contribution d'action :

| Exigence | Pourquoi |
|---|---|
| **Rollback obligatoire** | L'invariant n° 3 : toute action doit être annulable tant que le rollback n'a pas expiré |
| `dry_run_capable: true` | Le dry-run est le défaut du produit ; un playbook qui l'ignore est refusé |
| **Mode simulé par défaut** | Un connecteur non configuré doit retourner un `rollback_token` et journaliser `simulated: true` |
| **Idempotence** | Rejouer une exécution avec la même `idempotency_key` ne doit pas produire un second effet |
| **Aucun secret dans le dépôt** | Ni identifiants, ni jetons, ni URL privées : la configuration se fait par variables d'environnement |
| **Moindre privilège du jeton** | Le connecteur ne doit demander que la permission stricte nécessaire à l'action |
| **Bornes et expiration** | Toute action temporaire a une durée bornée (`duration_seconds`) et une cible validée |
| **Notification et audit** | Renseigner le bloc `audit` (`severity`, `notify`) pour que l'action soit traçable |

Un playbook sans rollback réellement testé n'est pas un playbook réversible : ajoutez le test dans
`tests/test_actions_rollback.py`. Détails : [actions/playbooks.md](actions/playbooks.md).

## 7. Contribuer de la documentation

La documentation est bâtie avec **MkDocs Material** (`mkdocs.yml`, pages dans `docs/`). Conventions
attendues :

* **Français** comme langue de référence, ton factuel, pas de superlatif commercial.
* **Admonitions** Material (`!!! note`, `!!! tip`, `!!! warning`, `!!! danger`, `!!! info`,
  `!!! example`) pour les points saillants, et **tableaux** pour les comparaisons.
* **Pas d'affirmation non vérifiée**, pas de fonctionnalité présentée comme disponible si elle
  relève de la feuille de route : utilisez `!!! info "Roadmap"`.
* **Pas de stub** : une page incomplète se termine par une suppression, pas par un « à compléter ».
* **Liens relatifs** entre pages, sans URL absolue vers une forge.

!!! warning
    La documentation doit rester **alignée sur
    [architecture/api-contract.md](architecture/api-contract.md)** : variables, endpoints, options
    CLI, noms de playbooks et codes d'erreur s'y conforment. Documenter une fonctionnalité
    inexistante est un défaut de sécurité, pas une coquille.

## 8. Ce que le projet refuse

Les contributions suivantes sont refusées, sans revue de fond :

* toute **capacité offensive** : exploit, charge utile, scan agressif, brute force, pulvérisation
  de mots de passe, fuzzing de systèmes tiers, déni de service, « hack-back », exfiltration ;
* toute **action non réversible**, ou dont le rollback n'est pas réellement implémenté ;
* tout **contournement des garde-fous** du §6 du contrat (plafond horaire, cooldown, cibles
  protégées, priorité du dry-run, périmètre déclaré) ;
* tout affaiblissement des **défauts sûrs** (`DRY_RUN=true`, `AUTONOMY=supervised`) ;
* toute **dépendance non justifiée dans le cœur** : `thotsecure.core` se limite à la stdlib +
  `pydantic`/`PyYAML` (invariant n° 5) ;
* tout **secret committé** (clé, jeton, mot de passe, certificat privé, `.env`) ;
* toute **télémétrie non consentie** ou appel sortant imposé par défaut ;
* toute collecte de télémétrie **hors du périmètre déclaré** d'un tenant.

## 9. Revue et attentes

Critères d'acceptation d'une pull request :

| Critère | Vérification |
|---|---|
| Conformité au contrat | Noms d'API, schémas, variables et CLI identiques au contrat §4/§5/§9 |
| Tests | Suite verte, cas limite ajouté |
| Documentation | Page concernée mise à jour, aucun comportement non documenté |
| Isolation multi-tenant | Aucune régression : filtrage `tenant_id` partout, test dédié |
| Dry-run respecté | Aucun effet de bord réel lorsque le dry-run est actif |
| Rollback | Présent et testé pour toute nouvelle action |
| Sécurité | Revue renforcée si la PR touche `audit/`, `tenancy/`, `decision/`, `actions/` |

Les délais de revue sont **« au mieux »** : le projet est maintenu par des bénévoles, sans
engagement de délai. Une pull request sans réponse n'est pas un refus ; relancez poliment dans le
fil concerné. Pour obtenir de l'aide : ouvrez une issue ou une discussion, en décrivant ce que vous
avez essayé. Voir [support.md](support.md).

## 10. Signaler une vulnérabilité

!!! warning
    **N'ouvrez jamais d'issue publique pour une vulnérabilité.** Un rapport public expose tous les
    déploiements avant qu'un correctif n'existe. Suivez
    [`SECURITY.md`](https://github.com/thot-corp/thot-secure/blob/main/SECURITY.md), à la racine du dépôt : il décrit les canaux privés, le
    périmètre, les délais visés (accusé de réception, triage, correctif) et la politique de crédit.
    Les rapports publiés dans un canal public sont retirés et vous serez invité à les re-soumettre
    en privé.

## 11. Reconnaissance

Les contributions sont créditées dans [`CHANGELOG.md`](https://github.com/thot-corp/thot-secure/blob/main/CHANGELOG.md) et dans les notes de
version, ainsi que dans l'historique Git qui reste la trace la plus fiable. Le crédit est donné par
défaut, sous le nom ou le pseudonyme que vous indiquez, et vous pouvez demander l'anonymat.

Aucune contribution n'ouvre de droit à rémunération, à priorité de revue ou à influence sur les
décisions de sécurité. La procédure exacte de crédit et la granularité retenue restent **à
confirmer** avec les mainteneurs : en cas de doute, demandez dans la pull request.

---

Pour la suite : [governance.md](governance.md) décrit qui décide quoi, et [support.md](support.md)
les canaux d'aide et de soutien au projet.

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
