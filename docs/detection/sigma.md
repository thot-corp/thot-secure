# Compatibilité Sigma-lite

*Ce qu'Thot Secure reprend de Sigma, ce qu'il n'en reprend pas, et comment convertir une règle proprement (MVP v0.1.0).*

!!! note "Source de vérité"
    Cette page applique le [contrat d'interface §5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml) :
    « un sous-ensemble de clés Sigma (`title, id, level, logsource, detection.selection|condition|filter`)
    est traduit automatiquement, avec avertissement ». Tout ce qui sort de ce sous-ensemble n'est
    **pas** garanti : voir la section « Limites explicites ».

## 1. Sigma, et pourquoi un sous-ensemble seulement

**Sigma** est un format de règles de détection générique et portable, largement utilisé par la
communauté *blue team* pour décrire des détections indépendamment du SIEM. Un corpus Sigma complet
s'appuie sur des mécanismes riches : **pipelines** de conversion par backend (Splunk, Elastic,
Sentinel…), **modificateurs de champ** (`|contains`, `|base64offset`, `|cidr`, `|windash`…),
**agrégations** (`near`, `timeframe`, `|count`), et toute une bibliothèque de **logsources** par
produit.

Thot Secure fait un choix différent, assumé :

| Choix Thot Secure | Raison |
|---|---|
| **Moteur YAML natif** (format du §5) | Le cycle détection → finding → décision → action a besoin d'un objet natif porteur de `risk`, `dedup` et `threshold`, que Sigma ne décrit pas. |
| **Pas de backend de conversion complet** | Maintenir une traduction fidèle de tout Sigma (pipelines inclus) est un projet en soi ; le MVP préfère 17 opérateurs bien testés à une compatibilité approximative. |
| **Sigma-lite = porte d'entrée, pas cible** | Une règle Sigma simple se convertit automatiquement, avec avertissement ; une règle complexe se réécrit en natif. |

!!! warning "Honnêteté sur le périmètre"
    « Sigma-lite » désigne un **sous-ensemble**. Thot Secure n'est **pas** un backend Sigma et ne
    prétend pas exécuter un corpus Sigma tel quel. Une règle Sigma qui utilise `aggregation`,
    `near`, `timeframe`, des pipelines ou des modificateurs avancés doit être **réécrite** en règle
    native — voir [Écrire une règle de détection](rules.md).

## 2. Sous-ensemble supporté

| Clé Sigma | Supportée ? | Comportement Thot Secure | Avertissement émis |
|---|---|---|---|
| `title` | ✅ | Repris tel quel comme `title` de la règle (et donc `Finding.rule_name`). | non |
| `id` | ✅ | Conservé pour la traçabilité ; l'identifiant natif de la règle est le `id` Thot Secure. Gardez le `id` Sigma **stable** et citez-le dans `references`. | non |
| `level` | ✅ | Traduit en `severity` (table de correspondance en §3.1). | oui si la valeur est hors des cinq niveaux connus |
| `logsource` | ⚠️ partielle | Traduit **heuristiquement** vers `source_types` et `kinds` (voir §3.4). | **oui, systématiquement** : la traduction est approximative |
| `detection.selection` | ✅ | Mapping `champ: valeur` → items de `match.all` avec `op: eq` ; une **liste** de valeurs → `op: in`. | oui |
| `detection.condition` | ✅ (formes simples) | `and` / `or` / `1 of …` / `all of …` → `all` / `any` (voir §3.3). | oui si la condition sort des formes simples |
| `detection.filter` | ✅ | Traduit en `match.not`. | oui |
| `status`, `description`, `author`, `date`, `tags`, `falsepositives`, `references`, `fields` | ❌ non traduites | Clés conservées dans le fichier mais **sans effet de traduction** ; reportez manuellement l'information dans les champs natifs (`status`, `description`, `tags`, `false_positives`, `references`). | oui (clé ignorée) |

!!! note "Formulation exacte des avertissements"
    Le §5 garantit qu'une traduction Sigma-lite est faite **« avec avertissement »**, sans publier la
    liste ni le texte des messages. La colonne « Avertissement émis » décrit donc la **nature**
    attendue de l'avertissement ; le libellé exact est **à confirmer par le code**
    (`src/thotsecure/detection/`).

## 3. Tableau de traduction Sigma → Thot Secure

### 3.1 `level` → `severity`

| `level` (Sigma) | `severity` (Thot Secure) |
|---|---|
| `informational` | `info` |
| `low` | `low` |
| `medium` | `medium` |
| `high` | `high` |
| `critical` | `critical` |

L'échelle Sigma compte cinq niveaux nommés différemment du premier (`informational` → `info`) ; les
quatre autres sont identiques. Le contrat ne publie pas cette table : elle est **à confirmer par le
code**.

### 3.2 `detection.selection` → `match.all`

| Sigma | Thot Secure | Remarque |
|---|---|---|
| `champ: valeur` | `- field: … # op: eq` | Égalité stricte. Le type du littéral compte (`403` ≠ `"403"`). |
| `champ: [v1, v2, v3]` | `- field: … # op: in` + `value: [v1, v2, v3]` | Une liste Sigma est une **disjonction** de valeurs sur un même champ : `in` est la traduction exacte. |
| `champ: null` | `- field: … # op: exists` | L'absence se teste avec `exists`, pas avec `eq`. |
| `champ|modificateur: valeur` | **non traduit automatiquement** | Utilisez l'opérateur natif équivalent en réécriture manuelle (§4). |

### 3.3 `detection.condition` → `all` / `any` / `not`

| Condition Sigma | Traduction Thot Secure | Perte |
|---|---|---|
| `selection` | Les items de `selection` dans `match.all` | aucune |
| `selection and selection2` | Les items des deux sélections, réunis dans `match.all` | **perte** : la structure « deux blocs » disparaît, tout devient une seule conjonction |
| `selection or selection2` | Les items réunis dans `match.any` | **perte** de structure, sémantique globalement préservée |
| `selection and not filter` | Items de `selection` dans `match.all`, items de `filter` dans `match.not` | aucune pour cette forme canonique |
| `1 of selection*` | `match.any` sur l'union des items | **perte** : la notion de « bloc nommé » n'existe plus |
| `all of selection*` | `match.all` sur l'union des items | idem |
| `near`, `timeframe`, `|count(...)` | **non traduit** | Utilisez le bloc `threshold` natif (`count`, `window_seconds`, `group_by`) |

!!! warning "Les blocs nommés au-delà de `selection` et `filter`"
    Le sous-ensemble du §5 cite littéralement `detection.selection`, `detection.condition` et
    `detection.filter`. Une règle Sigma qui nomme d'autres blocs (par ex. `filter_maintenance`) et
    les référence dans `condition` sort du sous-ensemble documenté : son comportement est
    **à confirmer par le code**. En cas de doute, réécrivez la règle en natif.

### 3.4 `logsource` → `source_types` / `kinds`

| Clé `logsource` | Approche de traduction | Fiabilité |
|---|---|---|
| `product` (ex. `linux`, `windows`, `aws`) | Rapprochement heuristique avec les `source.type` / `Event.kind` connus du moteur | **faible** : avertissement émis |
| `service` (ex. `sshd`, `auditd`) | Rapprochement heuristique, souvent vers `kinds: [log.line]` | **faible** |
| `category` (ex. `process_creation`, `webserver`) | Rapprochement heuristique vers `kinds` (`http.request`, `config.audit`, `log.line`…) | **faible** |

La traduction `logsource` est **approximative et signalée**. Après conversion, **relisez toujours**
`source_types` et `kinds` : ce sont eux qui décident si la règle voit réellement les événements.

## 4. Exemple de conversion complet

### 4.1 La règle Sigma d'origine

```yaml
title: SSH authentication failures from a single source
id: 4d2c9b1e-7a55-4f0a-9c3e-2b6f8d1a0c47
status: experimental
description: Détecte les échecs d'authentification SSH répétés depuis une même source.
references:
  - https://www.sigmahq.io/docs/basics/rules.html
author: Thot Secure Documentation
date: 2026/02/14
level: medium
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.outcome: failure
    event.category: authentication
  filter:
    source.ip: 10.0.0.0/8
  condition: selection and not filter
falsepositives:
  - Comptes de service mal configurés qui retentent en boucle.
tags:
  - attack.credential_access
  - attack.t1110
```

### 4.2 Sa traduction Thot Secure

```yaml
id: AO-SSH-101
title: SSH authentication failures from a single source
description: Détecte les échecs d'authentification SSH répétés depuis une même source.
status: test                # `status: experimental` de Sigma n'est pas traduit : à vous de choisir
                            # le statut natif (draft | test | stable | deprecated)
severity: medium            # level: medium -> severity: medium
confidence: 0.7             # Sigma ne fournit aucune notion de confiance : valeur à calibrer
enabled: true
tags: [sigma-lite, credential-access, mitre:T1110]  # attack.t1110 -> mitre:T1110 : convention Thot Secure
source_types: [log_tail]    # logsource (product: linux / service: sshd) -> heuristique : À RELIRE
kinds: [log.line]           # heuristique également : À RELIRE
match:
  all:
    # Sigma `event.outcome: failure` -> `op: eq` (traduction directe du contrat §5)
    - field: labels.outcome          # nom de label volontairement PLAT (voir l'avertissement ci-dessous)
      op: eq
      value: failure
    # Sigma `event.category: authentication` -> `op: eq`
    - field: labels.category
      op: eq
      value: authentication
  any: []
  not:
    # Sigma `detection.filter` -> `match.not`
    - field: labels.src_ip
      op: cidr
      value: "10.0.0.0/8"
  threshold:                # Sigma n'a pas d'agrégation équivalente ici : ajouté en natif
    count: 10
    window_seconds: 300
    group_by: [labels.src_ip, labels.username]
dedup:
  key: [rule_id, labels.src_ip, labels.username]
  ttl_seconds: 1800
risk:
  base: 45
  asset_criticality: 1.0
false_positives:
  # Sigma `falsepositives` n'est pas traduit automatiquement : reporté à la main
  - Comptes de service mal configurés qui retentent en boucle.
references:
  - https://www.sigmahq.io/docs/basics/rules.html
  - https://attack.mitre.org/techniques/T1110/
  # Provenance conservée : id Sigma original
  - sigma:4d2c9b1e-7a55-4f0a-9c3e-2b6f8d1a0c47
```

**Pertes et décisions à assumer dans cette conversion :**

| Élément Sigma | Sort dans la traduction |
|---|---|
| `status: experimental` | Non traduit → `status: test` choisi manuellement |
| `author`, `date`, `fields` | Non traduits → information perdue (à reporter dans `description` si utile) |
| `tags: attack.t1110` | Reformulé en `mitre:T1110` (convention de tags Thot Secure) |
| `logsource` | Traduit **heuristiquement** en `source_types` / `kinds` : avertissement émis |
| `condition: selection and not filter` | Forme canonique supportée → `all` + `not` |
| `event.outcome` / `event.category` | Champs **pointés** côté Sigma : voir l'avertissement ci-dessous |
| `falsepositives` | Non traduit → reporté à la main dans `false_positives` |
| Absence d'agrégation | Complétée en natif par `threshold` (regroupement par IP et par compte) |

!!! danger "Champs Sigma pointés et invariant `labels` plat"
    Le §3.1 impose que `labels` soit **plat**, avec des valeurs **scalaires**. Un champ Sigma pointé
    tel que `event.outcome` ne peut donc pas être transcrit littéralement en `labels.event.outcome`
    (cela produirait un chemin imbriqué). La forme réellement produite par la traduction
    automatique — préservation du point, aplatissement, ou normalisation par le collecteur — est
    **à confirmer par le code**. Dans la traduction ci-dessus, les noms sont volontairement plats
    (`labels.outcome`, `labels.category`) : **alignez-les sur la normalisation réelle de votre
    collecteur** avant de mettre la règle en production.

### 4.3 Valider la règle convertie

```bash
thotsecure rules validate --path rules
```

Sortie attendue en cas de succès :

```text
OK    rules/AO-SSH-101.yaml
```

Et, pour une règle Sigma-lite, un **avertissement** est émis pour signaler la traduction
approximative — typiquement :

```text
WARN  rules/sigma/ssh-auth-failures.yaml: Sigma-lite: `logsource` traduit de façon heuristique
      vers source_types=[log_tail], kinds=[log.line] — à relire
WARN  rules/sigma/ssh-auth-failures.yaml: Sigma-lite: clés ignorées (status, author, date, fields)
```

!!! note "Texte exact des messages"
    Le format `OK` / `WARN` ci-dessus illustre le **type** de sortie attendu ; le texte exact des
    diagnostics est **à confirmer par le code** (`src/thotsecure/detection/`,
    `tests/test_rules_engine.py`). Le contrat garantit seulement deux choses : la traduction se fait
    **avec avertissement**, et une règle invalide est **rejetée avec un diagnostic sans casser le
    chargement** ([§5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml)).

Contrôlez ensuite le chargement effectif et le comportement sur des événements réels, exactement
comme pour une règle native : voir [Écrire une règle de détection §12](rules.md#12-tester-une-regle-avant-pr).

## 5. Limites explicites

| Limite | Détail | Solution de repli en Thot Secure natif |
|---|---|---|
| Pas d'`aggregation` Sigma (`|count`, `|sum`) | Les agrégations Sigma ne sont pas traduites | Bloc `threshold` natif : `count`, `window_seconds`, `group_by` |
| Pas de `near` | La corrélation « proche dans le temps » n'existe pas | Deux règles + `dedup.key` commun, ou `threshold` avec `group_by` sur l'entité commune |
| Pas de `timeframe` | La fenêtre Sigma n'est pas honorée | `threshold.window_seconds` (voir la note du §6 de `rules.md` sur fenêtre glissante/fixe) |
| Pas de pipelines / pySigma | Aucun pipeline de conversion par backend | Écrire la règle en natif ; seuls les 17 opérateurs du §5 sont disponibles |
| Pas de `|base64offset` | Modificateur non supporté | Opérateur `contains` sur la forme encodée observée, ou `regex` bornée |
| Pas de `|cidr` avancé au-delà des opérateurs du §5 | Seul `cidr` existe, avec la sémantique du §5 | Opérateur `cidr` natif (support IPv4/IPv6 **à confirmer par le code**) |
| Autres modificateurs (`|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|windash`) | Non traduits automatiquement au titre du sous-ensemble | Opérateurs natifs correspondants : `contains` / `icontains`, `startswith`, `endswith`, `regex` |
| `logsource` mappé heuristiquement | Product/service/category ne sont pas des `Event.kind` natifs | Fixer explicitement `source_types` et `kinds`, puis vérifier par rejeu d'événements |
| Pas de backend de conversion depuis un corpus Sigma complet | Aucun outil de conversion en masse n'est fourni | Conversion règle par règle, en commençant par les détections les plus utiles |
| Blocs nommés hors `selection` / `filter` | Sous-ensemble documenté uniquement | Réécriture native avec `all` / `any` / `not` explicites |
| Clés Sigma non traduites (`status`, `author`, `date`, `fields`, `falsepositives`, `tags`) | Ignorées par la traduction | Report manuel dans `status`, `description`, `false_positives`, `references`, `tags` |

!!! info "Roadmap"
    Les éléments suivants ne sont **pas livrés** dans le MVP v0.1.0 :

    * conversion automatique d'un **corpus** Sigma complet (dépôt entier, en masse) ;
    * support des **pipelines** de conversion (pySigma ou équivalent) ;
    * **tests de conformité** Sigma vérifiant la fidélité de la traduction ;
    * traduction des agrégations (`near`, `timeframe`, `|count`) et des modificateurs avancés
      (`|base64offset`, `|windash`).

    Le périmètre livré se limite au sous-ensemble du
    [§5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml) : `title`, `id`,
    `level`, `logsource`, `detection.selection|condition|filter`.

## 6. Bonnes pratiques

!!! tip "Règles de conduite pour vivre avec Sigma-lite"
    1. **Natif d'abord pour les cas complexes.** Dès qu'une règle a besoin d'agrégation, de
       corrélation temporelle, de plusieurs blocs nommés ou de plusieurs modificateurs, écrivez-la
       en Thot Secure natif plutôt que de tordre une règle Sigma.
    2. **Gardez le `id` Sigma stable.** Ne le réécrivez pas, ne le réutilisez pas : c'est votre clé
       de rapprochement avec le corpus amont et avec les futures mises à jour.
    3. **Documentez la provenance dans `references`.** Citez l'`id` Sigma, l'URL de la règle
       d'origine et la technique MITRE associée.
    4. **Relisez `source_types` et `kinds` après chaque conversion** : c'est la partie la plus
       approximative de la traduction.
    5. **Ancrez vos regex et bornez vos répétitions** : les modificateurs Sigma masquent souvent des
       motifs fragiles. Voir les pièges de regex dans
       [Écrire une règle de détection](rules.md#10-pieges-de-regex).
    6. **Testez le négatif** autant que le positif : une conversion fidèle qui matche tout n'est pas
       une conversion réussie.

## 7. Voir aussi

* [Écrire une règle de détection](rules.md) — format natif, 17 opérateurs, seuils, déduplication, tests.
* [Contrat d'interface §5 — format des règles](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml).
* [Politiques de décision](../decision/policies.md) — ce qui se passe **après** le finding.
* [Modèle de données](../architecture/data-model.md) — `Event`, `Finding`, `Decision`.

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
