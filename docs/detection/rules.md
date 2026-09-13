# Écrire une règle de détection

*Guide d'ingénierie pour écrire, tester et maintenir les règles YAML du moteur de détection Thot Secure (MVP v0.1.0).*

!!! note "Source de vérité"
    Cette page applique le [contrat d'interface §5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml).
    En cas de divergence entre cette page et le contrat, **le contrat gagne**. Les points que le
    contrat ne tranche pas sont explicitement signalés « à confirmer par le code ».

## 1. Le cycle de détection

Une règle ne fait qu'**une seule chose** : transformer un flux d'événements normalisés en findings.
Le reste (score, décision, action) appartient aux étages suivants.

```text
collecteur ─▶ ÉVÉNEMENT ─▶ RÈGLE ─▶ FINDING ─▶ SCORING ─▶ DÉCISION ─▶ (action + rollback)
              (§3.1)        (§5)      (§3.2)     (§3.2)      (§6)
```

| Étage | Rôle | Où c'est défini |
|---|---|---|
| Événement | Fait brut normalisé, immuable, porteur de `labels` / `payload` | [contrat §3.1](../architecture/api-contract.md#31-event) |
| Règle | Prédicat YAML + agrégation + déduplication → produit un finding | cette page, [contrat §5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml) |
| Finding | Agrégat d'événements, `risk_score`, `status`, `count` | [contrat §3.2](../architecture/api-contract.md#32-finding) |
| Scoring | `severity` + `confidence` + `risk.base` + `asset_criticality` → `risk_score` 0-100 | [contrat §11](../architecture/api-contract.md#11-tests-attendus-unittest-executables-sans-dependance-externe) |
| Décision | `auto \| require_approval \| notify_only \| ignore` par politique | [politiques](../decision/policies.md), [contrat §6](../architecture/api-contract.md#6-format-des-politiques-policy-as-code) |

Vue d'ensemble de la chaîne et des collecteurs : [architecture](../architecture/overview.md).

!!! warning "Une règle n'exécute rien"
    Une règle produit un **finding**. Elle ne bloque pas une IP, ne coupe pas une session, ne
    modifie aucun système. Toute action est décidée par une [politique](../decision/policies.md)
    et exécutée par un [playbook](../actions/playbooks.md) sous le garde-fou `dry_run`.

## 2. Anatomie d'une règle

### 2.1 Tous les champs du §5

| Champ | Type | Obligatoire | Rôle |
|---|---|---|---|
| `id` | `string` | **oui** (usage) | Identifiant stable et unique de la règle (ex. `AO-WEB-001`). Il devient `Finding.rule_id` et sert de clé de déduplication et de corrélation. |
| `title` | `string` | **oui** (usage) | Nom court et factuel. Il devient `Finding.rule_name`. |
| `description` | `string` | non | Ce que la règle détecte, en une ou deux phrases, sans jargon inutile. Devient `Finding.description`. |
| `status` | `enum` | non | Cycle de vie : `draft` (écrite, non fiable) · `test` (validée sur données) · `stable` (production) · `deprecated` (à remplacer). |
| `severity` | `enum` | non | `info` · `low` · `medium` · `high` · `critical`. Alimente `Finding.severity` et le scoring. |
| `confidence` | `float` | non | `0.0` → `1.0`. Qualité de la détection (faux positifs attendus). Devient `Finding.confidence` et module le score. |
| `enabled` | `bool` | non | `false` = règle chargée mais inactive (permet de désactiver sans supprimer l'historique). |
| `tags` | `list[string]` | non | Étiquettes de classification : domaine (`web`), référentiels (`owasp:a03`), MITRE (`mitre:T1190`). Deviennent `Finding.tags`. |
| `source_types` | `list[string]` | non | Filtre d'entrée sur `Event.source.type` (ex. `web_probe`, `log_tail`). |
| `kinds` | `list[enum]` | non | Filtre d'entrée sur `Event.kind` : `http.request`, `http.response`, `log.line`, `tls.cert`, `dependency`, `config.audit`, `syslog`, `generic`. |
| `match` | `object` | **oui** (usage) | Cœur de la détection : `all` / `any` / `not` / `threshold` (voir §4 et §6). |
| `dedup` | `object` | non | `key` + `ttl_seconds` : regroupement des occurrences dans un même finding (voir §7). |
| `risk` | `object` | non | `base` (score de départ) et `asset_criticality` (multiplicateur) (voir §8). |
| `false_positives` | `list[string]` | non (recommandé) | Faux positifs connus, documentés. C'est la documentation opérationnelle de l'analyste. |
| `remediation` | `string` | non | Première action recommandée à l'analyste. Devient `Finding.remediation`. |
| `references` | `list[url]` | non (recommandé) | Sources : OWASP, MITRE ATT&CK, avis éditeur, CVE, règle Sigma d'origine. |

!!! note "Obligatoire : ce que le contrat dit vraiment"
    Le §5 ne publie pas de table « requis / optionnel » : il montre un exemple complet et ne
    qualifie d'« optionnel » que le bloc `threshold`. La colonne « Obligatoire » ci-dessus exprime
    donc une **nécessité fonctionnelle** (`id`, `title` et un `match` exploitable sont
    indispensables pour produire un finding). Les valeurs par défaut réelles des autres champs
    (`status`, `enabled`, `confidence`, `risk.base`) restent **à confirmer par le code**
    (`src/thotsecure/detection/`).

### 2.2 Les énumérations

| Énumération | Valeurs | Effet |
|---|---|---|
| `status` | `draft`, `test`, `stable`, `deprecated` | Gouvernance seule : une règle `draft` ou `deprecated` n'est pas censée être activée en production. |
| `severity` | `info`, `low`, `medium`, `high`, `critical` | Alimente `Finding.severity` puis le score et les politiques (`finding.severity`). |
| `Event.kind` | 8 valeurs (§3.1) | Filtre d'entrée : évite d'évaluer une règle web sur des événements `tls.cert`. |

## 3. Référence des opérateurs

Le §5 énumère les opérateurs supportés par le moteur. Chaque item d'une liste `all` / `any` / `not`
est un triplet `field` / `op` / `value`.

!!! note "Décompte des opérateurs"
    Un décompte de **18** opérateurs circule parfois dans les échanges du projet ; le §5 en
    **énumère 17** : `eq, ne, gt, gte, lt, lte, in, not_in, contains, icontains, startswith,
    endswith, regex, exists, cidr, len_gt, len_lt`. Cette page documente exactement ces 17
    opérateurs : un opérateur non listé ici doit être considéré comme **non supporté** jusqu'à
    confirmation par le code.

| Opérateur | Sémantique | `value` attendu | Exemple `field` + `value` |
|---|---|---|---|
| `eq` | Égalité stricte | scalaire (`string`, `int`, `float`, `bool`) | `payload.status` = `403` |
| `ne` | Inégalité | scalaire | `labels.method` ≠ `GET` |
| `gt` | Strictement supérieur | nombre | `payload.bytes` > `1000000` |
| `gte` | Supérieur ou égal | nombre | `payload.risk_score` ≥ `70` |
| `lt` | Strictement inférieur | nombre | `payload.days_to_expiry` < `14` |
| `lte` | Inférieur ou égal | nombre | `payload.protocol` ≤ `2` |
| `in` | Appartenance à une liste | liste de scalaires | `labels.method` ∈ `[PUT, DELETE, PATCH]` |
| `not_in` | Non-appartenance à une liste | liste de scalaires | `labels.src_ip` ∉ `[10.0.0.1, 10.0.0.2]` |
| `contains` | Sous-chaîne, sensible à la casse | chaîne | `payload.user_agent` contient `sqlmap` |
| `icontains` | Sous-chaîne, insensible à la casse | chaîne | `labels.path` contient `%2e%2e` |
| `startswith` | Préfixe | chaîne | `labels.path` commence par `/admin` |
| `endswith` | Suffixe | chaîne | `labels.path` finit par `/.env` |
| `regex` | Expression régulière, compilée avec **timeout d'exécution** (§10) | chaîne de motif | `labels.path` ~ `(?i)union[\s/*]+select` |
| `exists` | Présence (ou absence) du champ | booléen | `labels.username` existe |
| `cidr` | Appartenance d'une IP à un réseau | CIDR | `labels.src_ip` ∈ `203.0.113.0/24` |
| `len_gt` | Longueur strictement supérieure | entier | `labels.path` longueur > `512` |
| `len_lt` | Longueur strictement inférieure | entier | `payload.body_len` longueur < `10` |

### 3.1 Un mini-exemple YAML par opérateur

Chaque bloc ci-dessous est un item **valide** à placer dans `match.all`, `match.any` ou `match.not`.

**`eq`** — égalité stricte.
```yaml
- field: payload.status
  op: eq
  value: 403              # le type du littéral compte : 403 (int) n'est pas "403" (str)
```

**`ne`** — l'événement n'a pas cette valeur.
```yaml
- field: labels.method
  op: ne
  value: GET
```

**`gt`** — strictement supérieur (utile pour un volume ou une taille anormale).
```yaml
- field: payload.bytes
  op: gt
  value: 10485760         # réponse > 10 Mio : exfiltration potentielle en sortie
```

**`gte`** — supérieur ou égal (seuils de sévérité/score amont).
```yaml
- field: payload.cvss
  op: gte
  value: 7.0
```

**`lt`** — strictement inférieur (expirations, compteurs).
```yaml
- field: payload.days_to_expiry
  op: lt
  value: 14
```

**`lte`** — inférieur ou égal.
```yaml
- field: payload.protocol
  op: lte
  value: 2                # SSHv1 (1) ou SSHv2 (2)
```

**`in`** — appartenance à une liste : plus lisible et plus rapide que plusieurs `eq`.
```yaml
- field: labels.method
  op: in
  value: [PUT, DELETE, PATCH, TRACE]
```

**`not_in`** — exclusion, typiquement d'une liste blanche d'infrastructure connue.
```yaml
- field: labels.src_ip
  op: not_in
  value: [203.0.113.10, 203.0.113.11]
```

**`contains`** — sous-chaîne sensible à la casse (signatures d'outils, mots-clés).
```yaml
- field: payload.user_agent
  op: contains
  value: sqlmap
```

**`icontains`** — sous-chaîne insensible à la casse (encodages et variantes).
```yaml
- field: labels.path
  op: icontains
  value: "%2e%2e%2f"
```

**`startswith`** — préfixe (zones sensibles d'une application).
```yaml
- field: labels.path
  op: startswith
  value: /admin
```

**`endswith`** — suffixe (fichiers de secrets, extensions de sauvegarde).
```yaml
- field: labels.path
  op: endswith
  value: .bak
```

**`regex`** — le seul opérateur qui permet d'exprimer une famille de motifs (voir les pièges en §10).
```yaml
- field: labels.path
  op: regex
  value: "(?i)^/api/v[0-9]+/(users|orders)/[0-9]+$"
```

**`exists`** — présence du champ, sans se soucier de sa valeur. Indispensable pour distinguer
« champ absent » de « champ vide », que `eq` ne sait pas exprimer.
```yaml
- field: labels.username
  op: exists
  value: true            # true = présent ; false = absent (forme exacte à confirmer par le code)
```

**`cidr`** — appartenance à un réseau : la valeur de `value` est le réseau, le `field` porte l'IP.
```yaml
- field: labels.src_ip
  op: cidr
  value: "203.0.113.0/24"   # à confirmer par le code : support IPv4/IPv6 et forme du refus
```

**`len_gt`** — longueur strictement supérieure : détecte les entrées absurdement longues
(déni de service applicatif, tentative de contournement de filtre).
```yaml
- field: labels.path
  op: len_gt
  value: 2048
```

**`len_lt`** — longueur strictement inférieure : détecte les charges anormalement courtes.
```yaml
- field: payload.body
  op: len_lt
  value: 10
```

!!! tip "Choisir le bon opérateur"
    Du moins coûteux au plus coûteux : `eq` / `in` / `exists` d'abord, puis
    `contains` / `startswith` / `endswith`, puis `regex` en dernier recours. Un `in` de trois
    valeurs est plus lisible, plus rapide et plus sûr qu'une alternance `regex`.

## 4. Sémantique de `match`

`match` contient trois listes et un bloc d'agrégation optionnel :

| Clé | Sens | Résultat |
|---|---|---|
| `all` | **ET** logique : tous les items doivent matcher | `true` si la liste est vraie item par item |
| `any` | **OU** logique : au moins un item doit matcher | `true` dès qu'un item matche |
| `not` | **NI** : aucun item ne doit matcher | `true` si aucun item ne matche |
| `threshold` | Agrégation optionnelle `count` / `window_seconds` / `group_by` | voir §6 |

### 4.1 Combinaison des trois listes

Lecture garantie par les commentaires du §5 (`ET logique`, `OU logique (au moins un)`, `NI (aucun)`) :
les trois listes sont combinées en **ET** entre elles.

```text
règle = (tous les items de `all`)  ET  (au moins un item de `any`)  ET  (aucun item de `not`)
```

* une liste **vide** n'impose aucune contrainte (elle est vraie) — c'est le cas de l'exemple du §5 ;
* l'ordre d'évaluation et le court-circuit ne sont **pas** spécifiés par le contrat : ne concevez pas
  de règle dont le résultat dépendrait de l'ordre (à confirmer par le code).

### 4.2 Le cas du `match` vide

Un `match` sans aucun item (ou avec `all: []`, `any: []`, `not: []`) n'exprime **aucun** prédicat.

!!! danger "Ne jamais livrer un `match` vide"
    Le contrat ne garantit pas qu'une règle à `match` vide soit **rejetée** à la validation : la
    seule garantie du §5 est qu'« une règle invalide ne casse pas le chargement : elle est rejetée
    avec un diagnostic ». Le traitement exact du `match` vide est **à confirmer par le code**.
    Une règle sans prédicat produirait un finding sur **chaque** événement : c'est un incident de
    détection, pas une règle. Vérifiez ce point en revue avant PR.

### 4.3 Champ absent de l'événement

Le contrat **ne définit pas** le comportement d'un opérateur lorsque `field` n'existe pas dans
l'événement (échec silencieux, `false` explicite, ou erreur de validation) : **à confirmer par le
code**. En pratique, écrivez des règles qui ne dépendent pas de cette inconnue :

* utilisez `exists` pour rendre l'absence explicite ;
* pour tester une absence, utilisez `not` avec un `exists` :

```yaml
match:
  not:
    - field: labels.username
      op: exists
      value: true          # aucun item ne doit matcher => le champ est absent
```

## 5. Chemins de champs

`field` est un **chemin pointé** sur l'événement.

| Chemin | Structure | Remarques de conception |
|---|---|---|
| `labels.*` | **plat**, valeurs **scalaires** uniquement | Espace de nommage principal des règles. Une imbrication est interdite : `labels.user.role` n'est pas valide ; utilisez un nom plat, par ex. `labels.user_role`. |
| `payload.*` | objet libre | `payload` est **limité à 32 Kio sérialisés** : au-delà, il est **tronqué** et `raw_ref` est renseigné (§3.1). Une règle qui cherche un motif loin dans un gros payload peut donc ne plus le voir — préférez `labels` pour les champs de détection critiques. |
| `source.*` | `type`, `name`, `host` | Filtre de provenance : `source.type` correspond aux valeurs de `source_types`, `source.host` identifie l'actif. |
| `kind` | scalaire | Type d'événement (8 valeurs). À doubler avec `kinds:` pour éviter d'évaluer la règle inutilement. |
| `ts` | horodatage ISO 8601 | Utile avec `gt` / `lt` pour des fenêtres ou des bornes de campagne. |
| `severity_hint` | `info\|low\|medium\|high\|critical\|null` | Indice fourni par le collecteur : peut **contredire** votre `severity`. Ne l'utilisez pas comme sévérité de règle. |

Exemples d'items représentatifs :

```yaml
- field: labels.src_ip
  op: cidr
  value: "198.51.100.0/24"
- field: source.host
  op: endswith
  value: .acme.fr
- field: payload.status
  op: in
  value: [500, 502, 503]
- field: severity_hint
  op: eq
  value: critical
```

!!! warning "Filtres d'entrée : `source_types` et `kinds`"
    Ces deux listes ne sont pas décoratives : elles évitent d'appliquer un motif web à des
    événements `tls.cert` ou `dependency`. Les valeurs de `source_types` sont **libres** et doivent
    correspondre au `source.type` réellement émis par le collecteur (le §5 cite `web_probe` et
    `log_tail` ; le §11 cite les collecteurs `http_probe`, `dependency_scan`, `config_audit`).
    La nomenclature exacte de `source.type` est **à confirmer par le code**.

## 6. Seuils et agrégation

Le bloc `threshold` transforme un prédicat unitaire en **règle de fréquence** :

```yaml
  threshold:              # optionnel : agrégation
    count: 3              # nombre minimal d'événements correspondants
    window_seconds: 60    # fenêtre d'observation
    group_by: [labels.src_ip, labels.path]
```

* `count` : nombre d'événements nécessaires pour déclencher ;
* `window_seconds` : durée sur laquelle ce compte est observé ;
* `group_by` : **tuple de valeurs** ; chaque combinaison distincte (ici « une IP **et** un chemin »)
  est comptée **séparément**. C'est ce qui distingue « une IP qui balaie 200 chemins » de
  « 200 IP qui frappent le même chemin ».

!!! note "Fenêtre glissante ou fenêtre fixe ?"
    Le §5 définit `threshold` comme une « agrégation » avec `count`, `window_seconds` et `group_by`,
    sans préciser si la fenêtre est **glissante** (réévaluée à chaque événement) ou **fixe**
    (tumbling). Conséquence pratique : concevez vos seuils avec une marge, ou confirmez le
    comportement dans `src/thotsecure/detection/` avant de calibrer finement un seuil de production.

### 6.1 Exemple — énumération d'authentification

Motif : beaucoup d'échecs, **même IP**, **même compte**, en peu de temps.

```yaml
  threshold:
    count: 10
    window_seconds: 300
    group_by: [labels.src_ip, labels.username]
```

Sans le `group_by`, cinq utilisateurs légitimes qui se trompent une fois chacun déclencheraient la
règle : le regroupement par couple (IP, compte) est ce qui rend le signal exploitable.

### 6.2 Exemple — scans répétés

Motif : une même source qui génère un grand nombre de requêtes en erreur en quelques secondes.

```yaml
  threshold:
    count: 20
    window_seconds: 60
    group_by: [labels.src_ip]
```

Ici `group_by` ne contient que l'IP : la règle compte **toutes** les erreurs de la source, quels que
soient les chemins — c'est le comportement attendu pour un balayage.

## 7. Déduplication

`dedup` empêche qu'une même détection produise des dizaines de findings redondants.

```yaml
dedup:
  key: [rule_id, labels.src_ip]
  ttl_seconds: 900        # fenêtre de regroupement dans un même finding
```

* `key` : liste de champs formant l'identité de regroupement. `rule_id` est utilisable et apparaît
  dans l'exemple du §5 ; une clé typique est `[rule_id, labels.src_ip]` ou
  `[rule_id, labels.src_ip, labels.username]`.
* `ttl_seconds` : durée pendant laquelle des occurrences identiques (même `key`) sont **regroupées
  dans le même finding**.

Effet sur le [schéma Finding §3.2](../architecture/api-contract.md#32-finding) :

| Champ du finding | Comportement |
|---|---|
| `count` | Nombre d'occurrences regroupées. |
| `first_seen` / `last_seen` | Première et dernière occurrence du groupe. |
| `event_ids` | Événements rattachés au finding. |
| `evidence.samples` | Échantillons d'événements conservés pour l'analyste. |
| `updated_at` | Réécrit à chaque nouvelle occurrence regroupée. |
| `status` | `open` à la création ; `acked` / `closed` / `suppressed` relèvent de l'analyste (routes `POST /findings/{id}/ack|close|suppress`). |

!!! tip "Choisir `ttl_seconds`"
    Un `ttl` court crée beaucoup de findings (bruit pour l'analyste, coût d'actions) ; un `ttl` trop
    long masque une reprise d'attaque. Alignez `ttl_seconds` sur le temps de réaction réel de votre
    équipe, et gardez `dedup.key` **au même grain** que `threshold.group_by` pour que le comptage et
    le regroupement racontent la même histoire.

## 8. Scoring

Le score d'un finding (`Finding.risk_score`) est construit à partir de quatre entrées :

```yaml
risk:
  base: 60                # base du score, modulée par severity/confidence/asset_criticality
  asset_criticality: 1.0  # multiplicateur
```

| Entrée | Origine | Effet garanti |
|---|---|---|
| `risk.base` | La règle | Point de départ du score. |
| `severity` | La règle | Plus la sévérité est haute, plus le score est haut. |
| `confidence` | La règle | Plus la confiance est haute, plus le score est haut. |
| `risk.asset_criticality` | La règle | Multiplicateur d'importance de l'actif. |
| Bornes | Moteur | `0 ≤ risk_score ≤ 100` (testé en CI — [§11](../architecture/api-contract.md#11-tests-attendus-unittest-executables-sans-dependance-externe)). |

!!! warning "La formule exacte n'est pas publiée par le contrat"
    Le §5 indique seulement que `base` est « modulée par severity/confidence/asset_criticality », et
    le §11 exige un test de **monotonie** (sévérité, confiance, criticité) et de **bornes 0-100**.
    Le contrat ne donne ni coefficients ni formule : ils sont **à confirmer par le code**
    (`src/thotsecure/scoring/`). Le tableau ci-dessous exprime donc des **effets qualitatifs garantis**
    par la monotonie, plus la seule valeur publiée par le contrat.

| `risk.base` | `severity` | `confidence` | `asset_criticality` | Effet attendu |
|---|---|---|---|---|
| 60 | `high` | 0.85 | 1.0 | **78.5** — valeur de référence publiée au §3.2 |
| 60 | `critical` | 0.85 | 1.0 | supérieur (sévérité plus haute) |
| 60 | `medium` | 0.85 | 1.0 | inférieur |
| 20 | `high` | 0.85 | 1.0 | inférieur (base plus faible) |
| 80 | `high` | 0.85 | 1.0 | supérieur |
| 60 | `high` | 0.50 | 1.0 | inférieur (confiance plus faible) |
| 60 | `high` | 0.85 | 1.5 | supérieur (actif plus critique) |
| 100 | `critical` | 1.0 | 1.5 | plafonné à **100** (borne haute) |
| 0 | `info` | 0.0 | 1.0 | plancher à **0** (borne basse) |

!!! note "Le score pilote la décision, pas l'inverse"
    `risk_score` est une clé de politique (`finding.risk_score: { gte: 70 }` au §6). Un `base` trop
    haut fait basculer des findings légitimes en `auto` ; un `base` trop bas les maintient en
    `notify_only`. Calibrez `base` dans la règle, laissez les politiques fixer le seuil d'action :
    voir [politiques](../decision/policies.md). Les bornes de `asset_criticality` ne sont pas
    fixées par le contrat — **à confirmer par le code**.

## 9. Six règles complètes commentées

Les six règles suivantes sont **défensives** : elles détectent, elles n'exécutent rien.

### 9.1 `AO-WEB-001` — tentative d'injection SQL dans la chaîne de requête

C'est la règle de référence du [§5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml).

```yaml
id: AO-WEB-001
title: SQL injection attempt in query string
description: Détecte les motifs d'injection SQL dans les paramètres de requête.
status: stable            # draft | test | stable | deprecated
severity: high            # info | low | medium | high | critical
confidence: 0.85          # 0.0 → 1.0
enabled: true
tags: [web, owasp:a03, mitre:T1190]
source_types: [web_probe, log_tail]
kinds: [http.request]
match:
  all:                    # ET logique
    - field: labels.path
      op: regex
      value: "(?i)(union[\\s/*]+select|or\\s+1=1|sleep\\(\\d+\\)|benchmark\\()"
  any: []                 # OU logique (au moins un)
  not: []                 # NI (aucun)
  threshold:              # optionnel : agrégation
    count: 3
    window_seconds: 60
    group_by: [labels.src_ip, labels.path]
dedup:
  key: [rule_id, labels.src_ip]
  ttl_seconds: 900        # fenêtre de regroupement dans un même finding
risk:
  base: 60                # base du score, modulée par severity/confidence/asset_criticality
  asset_criticality: 1.0  # multiplicateur
false_positives:
  - Requêtes contenant le mot "union" dans un champ de recherche libre.
remediation: Bloquer l'IP source au WAF 1 h, vérifier les logs applicatifs, patcher l'entrée.
references:
  - https://owasp.org/Top10/A03_2021-Injection/
```

* **Ce que détecte la règle** : les familles classiques d'injection dans l'URL (`UNION SELECT`,
  tautologie `or 1=1`, injection temporelle `sleep()` / `benchmark()`).
* **Faux positifs connus** : champs de recherche libre où l'utilisateur écrit « union » (déjà
  documenté) ; exports/recherches internes contenant `or 1=1` dans un texte.
* **Action recommandée** : bloquer la source au WAF via le playbook `block-source-ip`, puis vérifier
  côté application que la requête n'a pas atteint la base.
* **Choix des opérateurs** : `regex` est ici nécessaire (famille de motifs) ; le seuil `count: 3`
  évite de créer un finding pour une requête isolée, et `group_by` garde la trace de l'IP et du
  chemin. Le motif est ancré par `(?i)` pour la casse — voir §10 pour l'ancrage.

### 9.2 `AO-PATH-002` — traversée de chemin

```yaml
id: AO-PATH-002
title: Path traversal attempt in request path
description: Détecte les tentatives de remontée de répertoire, encodées ou non.
status: stable
severity: high
confidence: 0.8
enabled: true
tags: [web, owasp:a01, mitre:T1190]
source_types: [web_probe, log_tail]   # source.type émis par le collecteur HTTP — à confirmer par le code
kinds: [http.request]
match:
  all:
    - field: labels.method
      op: ne
      value: OPTIONS                   # les requêtes préliminaires CORS ne portent pas de charge
  any:                                 # OU : une seule des variantes suffit
    - field: labels.path
      op: regex
      value: "(^|/)\\.{2}(/|%2f|$)"    # ../../, ..%2f
    - field: labels.path
      op: icontains
      value: "%2e%2e%2f"               # ../ encodé, insensible à la casse
    - field: labels.path
      op: icontains
      value: "..%5c"                   # ..\ encodé (cibles Windows/IIS)
    - field: labels.path
      op: endswith
      value: "/etc/passwd"             # cible la plus banale des tests de traversée
  not:
    - field: labels.path
      op: startswith
      value: /static/                  # chemin statique connu : pas de remontée légitime
dedup:
  key: [rule_id, labels.src_ip]
  ttl_seconds: 600
risk:
  base: 55
  asset_criticality: 1.0
false_positives:
  - Clients légitimes qui synchronisent des chemins contenant ".." (exceptions à documenter ici).
  - Certains CDN percent-encodent les chemins avant transmission.
remediation: Rejeter la requête au reverse-proxy, vérifier qu'aucun fichier hors racine n'a été lu, corriger la normalisation côté application.
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cwe.mitre.org/data/definitions/22.html
```

* **Ce que détecte la règle** : remontée de répertoire en clair et sous ses formes encodées.
* **Faux positifs connus** : proxys/CDN qui ré-encodent les chemins, clients internes utilisant
  `..` dans un nom de ressource ; la liste `not` sur `/static/` réduit le bruit.
* **Action recommandée** : blocage de la source, contrôle des journaux d'accès fichiers, revue de la
  normalisation des chemins.
* **Choix des opérateurs** : `any` combine des formes hétérogènes — `regex` pour la forme structurelle
  ancrée sur un séparateur, `icontains` pour les encodages (la casse de `%2E` varie), `endswith`
  pour la cible exacte. Une seule `regex` géante serait moins lisible et plus risquée (ReDoS).

### 9.3 `AO-AUTH-003` — énumération d'authentification

```yaml
id: AO-AUTH-003
title: Authentication enumeration from a single source
description: Détecte les échecs d'authentification répétés sur un même compte depuis une même source.
status: test                          # à promouvoir en stable après calibration du seuil
severity: medium
confidence: 0.7
enabled: true
tags: [auth, owasp:a07, mitre:T1110]
source_types: [log_tail]
kinds: [log.line]
match:
  all:
    - field: labels.event
      op: in
      value: [auth_failure, invalid_user, bad_password]   # normalisation du collecteur : à confirmer par le code
  any: []
  not:
    - field: labels.src_ip
      op: cidr
      value: "10.0.0.0/8"             # infrastructure interne connue : à adapter au tenant
  threshold:
    count: 10                         # 10 échecs…
    window_seconds: 300               # …en 5 minutes
    group_by: [labels.src_ip, labels.username]
dedup:
  key: [rule_id, labels.src_ip, labels.username]
  ttl_seconds: 1800                   # une campagne d'énumération = un finding
risk:
  base: 45
  asset_criticality: 1.0
false_positives:
  - Comptes de service mal configurés qui retentent en boucle.
  - Utilisateur ayant changé de mot de passe sur plusieurs postes.
remediation: Vérifier si le compte visé a été compromis, imposer une réinitialisation, activer le verrouillage progressif côté IdP.
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
```

* **Ce que détecte la règle** : une source qui accumule les échecs d'authentification sur un même
  compte — le préambule d'une attaque par force brute ou par bourrage d'identifiants.
* **Faux positifs connus** : comptes de service en échec permanent (à exclure via `not` ou par une
  politique de suppression), postes partagés.
* **Action recommandée** : vérifier la compromission du compte, forcer une réinitialisation, durcir
  le verrouillage côté fournisseur d'identité. Le playbook `revoke-session` est réversible.
* **Choix des opérateurs** : `in` pour les libellés d'échec (lisible et rapide), `cidr` dans `not`
  pour soustraire l'infrastructure interne, puis `threshold` avec `group_by` au couple
  (IP, compte) — c'est lui qui rend le signal exploitable (§6.1).

### 9.4 `AO-TLS-004` — certificat arrivant à expiration

```yaml
id: AO-TLS-004
title: TLS certificate expiring soon
description: Détecte les certificats TLS dont l'expiration est proche, avant toute coupure de service.
status: stable
severity: medium
confidence: 0.95                      # l'observation est factuelle, pas heuristique
enabled: true
tags: [tls, hygiene, availability]
source_types: [tls_probe]             # source.type du collecteur de certificats — à confirmer par le code
kinds: [tls.cert]
match:
  all:
    - field: payload.days_to_expiry   # clé de payload émise par le collecteur — à confirmer par le code
      op: lt
      value: 14
  any:
    - field: labels.host
      op: endswith
      value: .acme.fr                 # périmètre du tenant
    - field: labels.host
      op: endswith
      value: .acme.com
  not:
    - field: labels.host
      op: in
      value: [lab.acme.fr, demo.acme.fr]   # laboratoires : expiration tolérée
dedup:
  key: [rule_id, labels.host, labels.port]
  ttl_seconds: 86400                  # un rappel par jour et par point de terminaison
risk:
  base: 40                            # pas d'attaque : problème d'hygiène et de disponibilité
  asset_criticality: 1.0
false_positives:
  - Certificats de test volontairement courts sur des environnements éphémères.
remediation: Faire renouveler le certificat, vérifier la chaîne ACME et les alertes de renouvellement, planifier l'application avant l'expiration.
references:
  - https://www.rfc-editor.org/rfc/rfc5280
```

* **Ce que détecte la règle** : un certificat qui expire sous 14 jours sur un point de terminaison du
  périmètre — donc une indisponibilité annoncée.
* **Faux positifs connus** : environnements de recette, certificats éphémères de test.
* **Action recommandée** : renouvellement (procédure de routine, réversible), contrôle de
  l'automatisation ACME.
* **Choix des opérateurs** : `lt` sur un nombre de jours (jamais sur une date textuelle : les
  comparaisons de chaînes sont fragiles), `any` avec `endswith` pour délimiter le périmètre,
  `not` avec `in` pour les exceptions. `dedup.ttl_seconds` à 24 h évite le rappel quotidien
  répété pendant 14 jours.

### 9.5 `AO-DEP-005` — dépendance vulnérable connue

```yaml
id: AO-DEP-005
title: Vulnerable dependency detected in inventory
description: Détecte une dépendance dont la sévérité ou le score CVSS dépasse le seuil de traitement.
status: stable
severity: high
confidence: 0.8
enabled: true
tags: [supply-chain, owasp:a06, mitre:T1195]
source_types: [dependency_scan]       # collecteur cité au §11 — nom exact de source.type à confirmer
kinds: [dependency]
match:
  all:
    - field: labels.ecosystem         # pypi | npm | maven | … (normalisation à confirmer par le code)
      op: exists
      value: true
  any:                               # une seule condition suffit à qualifier la vulnérabilité
    - field: payload.cvss
      op: gte
      value: 7.0                      # 7.0 = haut selon CVSS v3
    - field: labels.advisory_severity
      op: in
      value: [high, critical]
    - field: labels.kev
      op: eq
      value: true                     # présente dans les catalogues d'exploitation connue
  not:
    - field: labels.scope
      op: eq
      value: dev_only                 # dépendance de développement : hors périmètre de production
  threshold:
    count: 1                          # un seul inventaire suffit : pas d'agrégation nécessaire
    window_seconds: 3600
    group_by: [labels.package, labels.version]
dedup:
  key: [rule_id, labels.package, labels.version]
  ttl_seconds: 604800                 # une semaine : une vulnérabilité n'est pas un événement de flux
risk:
  base: 65
  asset_criticality: 1.0
false_positives:
  - Installations de développement ou images non déployées incluses dans l'inventaire.
  - Versions corrigées par un correctif rétroporté (backport) non reflété par le scanner.
remediation: Ouvrir une mise à jour de dépendance via le playbook patch-dependency (PR proposée, jamais de merge automatique), vérifier la version corrigée et relancer le scan.
references:
  - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
  - https://nvd.nist.gov/
```

* **Ce que détecte la règle** : une dépendance à score CVSS élevé, à sévérité d'avis haute, ou
  référencée comme activement exploitée.
* **Faux positifs connus** : inventaires de développement, correctifs rétroportés non reconnus par le
  scanner.
* **Action recommandée** : mise à jour via le playbook `patch-dependency`, qui **ouvre une PR et ne
  fusionne jamais automatiquement**.
* **Choix des opérateurs** : `any` combine trois signaux de nature différente (numérique, énuméré,
  booléen) ; `not` sur `labels.scope` écarte le hors-périmètre ; `dedup.ttl_seconds` long parce que
  l'inventaire est répété à chaque scan.

### 9.6 `AO-SSH-006` — configuration SSH faible

```yaml
id: AO-SSH-006
title: Weak SSH server configuration
description: Détecte les paramètres SSH durcissables relevés par l'audit de configuration.
status: stable
severity: medium
confidence: 0.9                       # constat de configuration, pas de heuristique de trafic
enabled: true
tags: [config, harden, cis, mitre:T1021]
source_types: [config_audit]          # collecteur cité au §11 — nom exact de source.type à confirmer
kinds: [config.audit]
match:
  all:
    - field: labels.service
      op: eq
      value: sshd
  any:                                # chaque item est une faiblesse indépendante
    - field: labels.permit_root_login
      op: icontains
      value: "yes"                    # connexion directe de root
    - field: labels.password_authentication
      op: icontains
      value: "yes"                    # mot de passe au lieu de clé
    - field: labels.permit_empty_passwords
      op: icontains
      value: "yes"                    # doit toujours être "no"
    - field: labels.protocol
      op: lt
      value: 2                        # protocole SSHv1 obsolète
    - field: labels.x11_forwarding
      op: icontains
      value: "yes"                    # surface inutile sur un serveur
  not:
    - field: labels.environment
      op: in
      value: [lab, sandbox]           # exceptions de laboratoire explicites
dedup:
  key: [rule_id, labels.host]
  ttl_seconds: 86400                  # un finding par hôte et par jour
risk:
  base: 50
  asset_criticality: 1.0
false_positives:
  - Serveurs de rebond volontairement configurés avec X11 ou mot de passe.
  - Profils de durcissement d'un référentiel interne qui divergent du CIS.
remediation: Appliquer le profil de durcissement via le playbook harden-endpoint (clés seules, PermitRootLogin no, protocole 2, désactivation du transfert X11).
references:
  - https://www.cisecurity.org/controls
  - https://www.ssh.com/academy/ssh/sshd_config
```

* **Ce que détecte la règle** : une configuration SSH qui s'écarte des pratiques de durcissement.
* **Faux positifs connus** : hôtes de rebond métier, profils maison divergents du CIS.
* **Action recommandée** : application du profil de durcissement par le playbook `harden-endpoint`,
  réversible, après validation du changement.
* **Choix des opérateurs** : `icontains` parce que les valeurs relevées varient en casse et en
  espaces (`yes`, `YES`) ; `lt` pour le prototype de protocole ; `not` avec `in` pour les exceptions
  de laboratoire ; `dedup` quotidien pour éviter de rejouer le même constat à chaque audit.

## 10. Pièges de regex

`regex` est le seul opérateur capable d'exprimer une famille de motifs — c'est aussi le seul capable
de mettre le moteur à genoux.

!!! danger "ReDoS : un motif peut coûter un déni de service"
    Les quantificateurs imbriqués (`(a+)+`, `(.*)*`, `(.+)+`) provoquent un **backtracking
    catastrophique** : un motif naïf peut transformer une entrée de 30 caractères en plusieurs
    secondes de calcul. C'est un déni de service **subi par votre propre moteur de détection**, pas
    une capacité offensive. À éviter absolument :

    ```text
    (?i)^(.*\+.*)+select        # backtracking exponentiel
    (?i)(\w+\s*)+=              # quantificateur imbriqué
    ```

    À préférer : classes de caractères explicites et répétitions **bornées**.

    ```yaml
    - field: labels.path
      op: regex
      value: "(?i)^/api/v1/items/[0-9]{1,64}$"
    ```

Le contrat impose que les regex de règle soient **compilées avec un timeout d'exécution**
([§10](../architecture/api-contract.md#10-securite-produit-exigences-a-implementer)). Conséquence
pratique : un motif coûteux n'est pas seulement lent, il est **abandonné** — vous perdez la détection
au moment précis où l'attaquant la déclenche. Ne comptez pas sur le timeout comme filet : il protège
le moteur, pas votre couverture de détection.

| Piège | Symptôme | Bonne pratique |
|---|---|---|
| Backtracking catastrophique | Détections manquées / latence en rafale | Pas de quantificateur imbriqué, répétitions bornées `{1,64}`, `[0-9]` plutôt que `\d+` quand la longueur est connue |
| Absence d'ancrage | Le motif matche au milieu d'une valeur `labels` | **Ancrez explicitement** : `^…$` |
| `re.search` vs `re.match` | Comportement de bord inattendu | Le contrat ne précise pas la fonction utilisée : **ancrez donc toujours** (`^…$`) pour que le résultat soit identique dans les deux cas |
| Casse | Motif efficace en test, inefficace en prod | `(?i)` explicite en tête de motif |
| Échappement YAML | `\s` transformé en erreur de parsing | En scalaire **entre guillemets doubles**, écrivez `\\s` : YAML le décode en `\s` pour le moteur. En scalaire brut (sans guillemets), utilisez `'\s'` |
| Longueur du motif | Motif illisible, non relu en PR | Un motif = une intention ; découpez en plusieurs items `any` plutôt qu'une alternance géante |
| Ancrage implicite | Le motif matche `labels.path` en entier alors que vous visiez un fragment | Utilisez `icontains` pour un fragment, `regex` **ancré** pour une forme complète |

```yaml
# Échappement correct : "\\s" en YAML double-quote => \s pour le moteur
- field: labels.path
  op: regex
  value: "(?i)^/search\\?q=(union|select|insert)\\b"
```

## 11. Qualité et cycle de vie d'une règle

### 11.1 Cycle de vie de `status`

```text
draft ──▶ test ──▶ stable ──▶ deprecated
```

| Statut | Signification | Attendu en revue |
|---|---|---|
| `draft` | Écrite, non confrontée aux données réelles | Ne pas activer en production ; les faux positifs sont inconnus. |
| `test` | Validée sur des événements réels ou rejoués | Le seuil et la confiance sont calibrés et justifiés dans la PR. |
| `stable` | En production, bruit connu et accepté | `false_positives` et `references` documentés ; revue de la règle au moins annuelle. |
| `deprecated` | Remplacée, conservée pour l'historique | Indiquer la règle de remplacement dans `description` ou `references`. |

### 11.2 Nommage des `tags`

| Famille | Forme | Exemple |
|---|---|---|
| Domaine | mot simple | `web`, `auth`, `tls`, `supply-chain`, `config` |
| Référentiel OWASP | `owasp:<id>` en minuscules | `owasp:a03`, `owasp:a01` |
| MITRE ATT&CK | `mitre:T####` | `mitre:T1190`, `mitre:T1110` |

Le schéma [Finding §3.2](../architecture/api-contract.md#32-finding) porte à la fois `tags` et un
champ `mitre` (exemple : `tags: ["web", "owasp:a03", "mitre:T1190"]` et `mitre: ["T1190"]`). La
dérivation du champ `mitre` à partir des tags `mitre:T####` est cohérente avec cet exemple, mais
elle est **à confirmer par le code**.

### 11.3 Liste de contrôle avant PR

* [ ] `id` unique et stable, `title` factuel, `description` compréhensible par un analyste non auteur.
* [ ] `status` honnête (pas de `stable` pour une règle jamais confrontée à des données).
* [ ] `severity` et `confidence` justifiés, `risk.base` calibré (§8).
* [ ] `source_types` / `kinds` réduits au strict nécessaire (§5).
* [ ] `false_positives` documentés avec au moins un cas réel, `references` renseignées.
* [ ] Aucun opérateur hors des 17 du §5, aucune regex non ancrée ou à backtracking risqué (§10).
* [ ] `dedup` cohérent avec `threshold.group_by` (§6, §7).
* [ ] Testée sur `events.jsonl` (§12) : elle matche le positif et **ne matche pas** le négatif.
* [ ] Aucune capacité offensive : la règle détecte, elle n'attaque rien et n'exécute rien.

## 12. Tester une règle avant PR

### 12.1 Boucle locale (CLI)

```bash
# 1. Valider la syntaxe et la sémantique de toutes les règles du dépôt
thotsecure rules validate --path rules

# 2. Vérifier que la règle est bien chargée et listée
thotsecure rules list

# 3. Rejouer les tests du moteur : tous les opérateurs, all/any/not, seuils,
#    Sigma-lite et le cas « règle invalide »
python -m unittest discover -s tests -t . -v
```

`tests/test_rules_engine.py` est le test de référence du moteur : il couvre **tous les opérateurs**,
la sémantique `all/any/not`, les **seuils**, la **compatibilité Sigma-lite** et le cas de la
**règle invalide** ([§11](../architecture/api-contract.md#11-tests-attendus-unittest-executables-sans-dependance-externe)).

### 12.2 Rejeu de bout en bout avec un fichier d'événements

Créez `events.jsonl` : un événement **JSON par ligne**, conforme au schéma
[Event §3.1](../architecture/api-contract.md#31-event).

```json
{"event_id":"11111111-1111-4111-8111-111111111111","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:00.123Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"info","labels":{"src_ip":"203.0.113.9","path":"/search?user=admin' or 1=1--","method":"POST"},"payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"22222222-2222-4222-8222-222222222222","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:05.000Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"info","labels":{"src_ip":"198.51.100.7","path":"/download?file=/..%2f..%2fetc%2fpasswd","method":"GET"},"payload":{"status":400,"bytes":218,"user_agent":"python-requests/2.31"},"raw_ref":null}
{"event_id":"33333333-3333-4333-8333-333333333333","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:01:00.000Z","kind":"log.line","source":{"type":"log_tail","name":"ssh-edge","host":"bastion.acme.fr"},"severity_hint":"low","labels":{"src_ip":"198.51.100.7","username":"root","event":"auth_failure"},"payload":{"line":"Failed password for root from 198.51.100.7 port 51022 ssh2"},"raw_ref":null}
{"event_id":"44444444-4444-4444-8444-444444444444","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:02:00.000Z","kind":"tls.cert","source":{"type":"tls_probe","name":"edge-cert","host":"shop.acme.fr"},"severity_hint":"info","labels":{"host":"shop.acme.fr","port":"443"},"payload":{"days_to_expiry":9,"issuer":"Example CA"},"raw_ref":null}
```

```bash
# Ingestion : le tenant est celui de la commande
thotsecure ingest --tenant acme --file events.jsonl

# Quels findings remontent ?
thotsecure findings list --tenant acme
thotsecure findings list --tenant acme --severity high --min-risk 70
```

!!! note "Les seuils ne se franchissent pas avec un seul événement"
    Ce fichier déclenche immédiatement `AO-PATH-002` (aucun seuil) et `AO-TLS-004` (aucun seuil).
    En revanche `AO-WEB-001` exige `count: 3` et `AO-AUTH-003` exige `count: 10` : dupliquez la
    ligne concernée (en changeant `event_id` et `ts`) pour franchir le seuil et vérifier que
    l'agrégation par `group_by` fonctionne — c'est précisément le comportement à tester (§6).

!!! tip "Test négatif obligatoire"
    Un jeu d'essai qui ne contient que des positifs ne teste rien. Ajoutez au moins un événement
    **bénin** proche du motif (`path: /search?q=union de syndicats`, `days_to_expiry: 90`) et
    vérifiez qu'**aucun** finding n'est produit pour lui.

### 12.3 Via l'API

`POST /api/v1/rules/validate` attend le YAML/JSON de la règle et exige la capacité `admin:rules`
([§4.5](../architecture/api-contract.md#45-regles-politiques-playbooks)).

```bash
# Validation d'un fichier de règle (remplacez la clé)
curl -sS -X POST http://127.0.0.1:8080/api/v1/rules/validate \
  -H "X-API-Key: ao_REMPLACER_PAR_VOTRE_CLE" \
  -H "Content-Type: application/yaml" \
  --data-binary @rules/AO-WEB-001.yaml
# → {"valid":true,"errors":[]}

# Rechargement depuis THOT_RULES_DIR (défaut ./rules)
curl -sS -X POST http://127.0.0.1:8080/api/v1/rules/reload \
  -H "X-API-Key: ao_REMPLACER_PAR_VOTRE_CLE"
# → {"loaded":12,"errors":[]}

# Lecture d'une règle complète + son YAML source
curl -sS http://127.0.0.1:8080/api/v1/rules/AO-WEB-001 \
  -H "X-API-Key: ao_REMPLACER_PAR_VOTRE_CLE"
```

Sous PowerShell :

```powershell
$key  = 'ao_REMPLACER_PAR_VOTRE_CLE'
$body = Get-Content -Raw .\rules\AO-WEB-001.yaml

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/rules/validate `
  -Headers @{ 'X-API-Key' = $key } -ContentType 'application/yaml' -Body $body

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/rules/reload `
  -Headers @{ 'X-API-Key' = $key }
```

Le rechargement lit le répertoire `THOT_RULES_DIR` (défaut `./rules`,
[§9](../architecture/api-contract.md#9-variables-denvironnement-thotsecure)).

### 12.4 Règle invalide : rejetée, jamais fatale

Garantie du [§5](../architecture/api-contract.md#5-format-des-regles-de-detection-yaml) : « une
règle invalide **ne casse pas** le chargement : elle est rejetée avec un diagnostic ».

| Cas | Comportement garanti | Où l'observer |
|---|---|---|
| YAML non parsable (indentation, tabulation) | Règle rejetée avec diagnostic ; les autres règles restent chargées | `thotsecure rules validate --path rules`, `POST /rules/reload` → `errors[]` |
| Champ indispensable manquant (`id`, `title`, `match`) | Rejet avec diagnostic | idem |
| Opérateur hors des 17 du §5 | Rejet avec diagnostic | idem |
| `value` incompatible avec l'opérateur (ex. `in` sans liste) | Rejet avec diagnostic | idem (forme exacte du message à confirmer par le code) |
| `regex` non compilable | Rejet à la compilation ; à l'exécution, timeout imposé par le §10 | idem |
| `id` dupliqué entre deux fichiers | Comportement non spécifié par le contrat → **à confirmer par le code** | `thotsecure rules list` (doublon visible) |
| `threshold` incohérent (`count` sans `window_seconds`) | Comportement non spécifié par le contrat → **à confirmer par le code** | `thotsecure rules validate` |
| `match` vide | Comportement non spécifié → **à confirmer par le code** (voir §4.2) | rejeu sur `events.jsonl` |

En intégration continue, `thotsecure rules validate --path rules` renvoie le code de sortie `1` en cas
d'erreur et `0` en cas de succès ([§8](../architecture/api-contract.md#8-cli-thotsecure)) : c'est le
point d'ancrage naturel d'un job de validation des règles.

## 13. Ce qu'une règle ne fait jamais

!!! warning "Une règle est un prédicat, pas une capacité d'action"
    * Une règle **n'exécute rien** : elle lit des événements et produit un **finding**. Elle n'a
      accès à aucun connecteur, à aucun playbook, à aucun système cible.
    * Une règle ne déclenche **aucune** action : c'est le rôle d'une
      [politique de décision](../decision/policies.md) (`then.playbook`), sous le garde-fou
      `dry_run` ([§6](../architecture/api-contract.md#6-format-des-politiques-policy-as-code)).
    * Thot Secure est **100 % défensif** : une règle ne doit jamais décrire ni déclencher de scan
      agressif, de force brute, de hack-back, de déni de service ou d'exploitation de tiers
      ([§10](../architecture/api-contract.md#10-securite-produit-exigences-a-implementer)).
    * Une règle ne doit pas non plus **subir** un déni de service : les regex sont compilées avec
      timeout et doivent rester simples (§10).

Pour la suite du parcours : [politiques de décision](../decision/policies.md) ·
[playbooks](../actions/playbooks.md) · [compatibilité Sigma-lite](sigma.md) ·
[modèle de données](../architecture/data-model.md).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
