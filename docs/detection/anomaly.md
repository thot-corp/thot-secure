# Détection d'anomalie statistique

> Une règle répond à « ce motif est-il présent ? ». Elle ne peut pas répondre à « ce volume
> est-il *anormal pour cet actif* ». C'est une question de **contexte**, et c'est précisément
> le terrain des attaques lentes et distribuées.

Ce document décrit le détecteur d'anomalie livré avec Thot Secure : ce qu'il mesure, comment il
décide, comment le régler, et **pourquoi il est désactivé par défaut**.

!!! info "Activation"
    `THOT_ANOMALY_ENABLED=false` par défaut. Voir la [procédure de mise en service](#5-mise-en-service-recommandee)
    plus bas : ce détecteur s'active après observation, pas à l'installation.

---

## 1. Le problème traité

Trois familles de comportements échappent structurellement à une règle déterministe :

| Situation | Pourquoi une règle échoue | Ce que mesure le détecteur |
|---|---|---|
| **Bourrage d'identifiants lent** | 5 tentatives par heure et par adresse ne franchissent aucun seuil raisonnable | Écart entre le rythme observé et le rythme habituel de cette source |
| **Attaque répartie** | Chaque adresse reste sous tous les seuils ; c'est leur *nombre* qui compte | Nombre de sources distinctes par intervalle |
| **Premier contact** | Aucune règle ne peut savoir ce qui est « habituel » pour ce tenant | Première apparition d'une adresse source |

## 2. La méthode : EWMA + z-score

Pour chaque entité suivie (par défaut l'adresse source), le détecteur maintient une **moyenne
mobile exponentielle** du nombre d'événements par intervalle, et une variance EWMA. À la fin de
chaque intervalle, il compare le volume observé à cette base :

```text
z = (observé − moyenne) / √(variance + plancher)
```

Quatre propriétés ont dicté ce choix :

1. **Explicable** — le signal contient toujours les trois nombres : observé, attendu, écart.
   Un analyste peut contester le seuil, un RSSI peut l'expliquer en réunion.
2. **Sans dépendance** — aucune bibliothèque d'apprentissage à auditer. Un SOC doit pouvoir
   lire le code de son propre outil de détection.
3. **En ligne et à coût constant** — une mise à jour arithmétique par événement, état borné.
   La détection ne devient jamais le goulot d'étranglement du pipeline.
4. **Déterministe dans les tests** — l'horloge est injectable, donc un franchissement
   d'intervalle se teste sans attendre la durée réelle. Une détection qu'on ne peut pas tester
   vite finit par ne plus être testée du tout.

!!! note "Pourquoi pas un modèle d'apprentissage (encore) ?"
    Le [ROADMAP](../roadmap.md) prévoit un modèle d'anomalie plus riche en 0.3. La version
    actuelle privilégie une base **dont on peut expliquer chaque décision** — ce qui est la
    condition pour qu'un analyste lui fasse confiance, et donc pour qu'il l'utilise.

### Trois signaux produits

| Signal (`labels.check`) | Ce qu'il détecte | Sévérité graduée |
|---|---|---|
| `rate_anomaly` | Écart de volume d'une entité | `low` (4σ) → `critical` (20σ) |
| `source_cardinality_anomaly` | Pic du nombre de sources distinctes | `high` (8σ), `critical` (20σ) |
| `new_source` | Première observation d'une entité pour ce tenant | `low` |

## 3. Intégration au pipeline

Un signal d'anomalie est émis comme un **événement ordinaire** (`kind: anomaly`,
`source.type: baseline`) et traverse exactement le même chemin qu'un événement de journal :

```text
collecteur → event → détecteur d'anomalie → event « anomaly »
                                                     ↓
                        moteur de règles → scoring → décision → garde-fous → action → audit
```

Conséquences volontaires de cette conception :

* **aucune voie parallèle** : une anomalie ne peut pas contourner les garde-fous (cible
  protégée, périmètre déclaré, plafond horaire, cooldown, dry-run) ;
* **les règles décident** : le détecteur *signale*, les règles `AO-ANO-*` livrées décident de
  ce qui mérite un finding — et vous pouvez écrire les vôtres ;
* **les événements sont persistés** : un signal qui n'existerait que dans la mémoire du
  processus ne serait pas une preuve ;
* **la détection est auditée** (`anomaly.detected`), avec la source à l'origine du signal ;
* **pas de récursion** : un événement d'anomalie n'est jamais réanalysé par le détecteur.

!!! warning "Pourquoi les règles `AO-ANO-*` n'ont pas de `threshold`"
    Un signal d'anomalie **résume déjà un intervalle complet**. Exiger plusieurs signaux
    reviendrait à attendre un second intervalle avant d'alerter : une minute de retard pour un
    gain de précision nul.

## 4. Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `THOT_ANOMALY_ENABLED` | `false` | Active le détecteur |
| `THOT_ANOMALY_BUCKET_SECONDS` | `60` | Durée d'un intervalle d'observation |
| `THOT_ANOMALY_WARMUP_SAMPLES` | `30` | Intervalles observés avant tout verdict |
| `THOT_ANOMALY_ZSCORE_THRESHOLD` | `4.0` | Seuil de déclenchement, en écarts-types |
| `THOT_ANOMALY_MIN_OBSERVED` | `20` | Volume minimal dans l'intervalle |
| `THOT_ANOMALY_ENTITY_FIELDS` | `["labels.src_ip"]` | Champs d'identité suivis |
| `THOT_ANOMALY_MAX_ENTITIES` | `20000` | Borne mémoire (éviction des plus anciennes) |
| `THOT_ANOMALY_ENTITY_TTL_SECONDS` | `86400` | Conservation d'une entité silencieuse |
| `THOT_ANOMALY_DETECT_NEW_SOURCES` | `true` | Signaler la première apparition |

### Choisir la durée d'intervalle

L'intervalle est le réglage qui compte le plus, et il doit correspondre à **votre rythme
métier**, pas à une valeur par défaut :

* site à faible trafic (intranet, portail interne) → `THOT_ANOMALY_BUCKET_SECONDS=300` ;
* site public à trafic soutenu → `60` (défaut) ;
* API à très fort volume → `10` à `30`, avec `THOT_ANOMALY_MIN_OBSERVED` relevé.

### Deux garde-fous intégrés

* **Volume minimal** (`min_observed`) : un écart de 3 → 12 événements est statistiquement fort
  et opérationnellement insignifiant. Le détecteur ne signale pas.
* **Période de chauffe** (`warmup_samples`) : sans elle, la première minute d'un déploiement
  serait entièrement « anormale » et le produit serait jugé inutilisable avant d'avoir servi.

## 5. Mise en service recommandée

!!! danger "Ne l'activez pas en même temps que la production"
    1. **Activer en observation** sur un environnement de recette ou en production avec
       `THOT_AUTONOMY=manual` : les signaux apparaissent en findings, aucune action n'est
       déclenchée.
    2. **Relever pendant 3 à 7 jours** : combien de signaux par jour ? Lesquels correspondent à
       des événements métier connus (campagnes, sauvegardes, tests de charge) ?
    3. **Ajuster** : relever `THOT_ANOMALY_ZSCORE_THRESHOLD` (5, 6…) ou `THOT_ANOMALY_MIN_OBSERVED`
       si le bruit est trop élevé ; élargir l'intervalle si le trafic est irrégulier.
    4. **Créer des exceptions datées** pour les événements légitimes récurrents
       (`POST /api/v1/findings/{id}/suppress`) plutôt que de relever le seuil global : cela
       préserve la sensibilité là où elle compte.
    5. **Puis** laisser les politiques agir — et vérifier que la politique livrée
       `approval-volume-anomaly` reste en `require_approval`.

```bash
# Observation : détecteur actif, aucune action automatique
THOT_ANOMALY_ENABLED=true THOT_AUTONOMY=manual thotsecure serve
```

## 6. Analyser un signal

Un finding d'anomalie se lit comme les autres, avec trois informations supplémentaires :

```bash
thotsecure findings list --tenant acme --min-risk 40
thotsecure findings show <finding_id> --tenant acme
```

```text
[high] 62.4/100  AO-ANO-002
  Écart de volume majeur pour une source (anomalie statistique) depuis 203.0.113.9
  décision    : require_approval (politique approval-volume-anomaly)
  garde-fous  : dry_run
```

La preuve contient l'explication chiffrée (`payload.baseline`) :

```json
{
  "observed": 299.0,
  "mean": 9.1,
  "zscore": 289.9,
  "model": "EWMA + z-score (variance plancher appliquée)"
}
```

!!! tip "Interpréter correctement"
    « 299 événements contre 9 attendus » est une phrase qu'un responsable comprend en trois
    secondes et peut contester s'il sait qu'un test de charge était planifié. C'est tout
    l'intérêt d'un détecteur explicable : il rend la décision **discutable**, donc vérifiable.

## 7. Réglages fins par règle

Les règles livrées graduent la sévérité par bandes d'écart, ce qui permet d'ajuster le
traitement sans toucher au détecteur :

| Règle | Bande | Sévérité | Politique |
|---|---|---|---|
| `AO-ANO-001` | 4σ ≤ z < 12σ | `medium` | Aucune correspondance → notification seule |
| `AO-ANO-002` | z ≥ 12σ | `high` | `approval-volume-anomaly` → limitation de débit proposée |
| `AO-ANO-003` | source nouvelle | `low` | Notification seule (signal de contexte) |
| `AO-ANO-004` | 8σ ≤ z < 20σ (cardinalité) | `high` | `notify-distributed-anomaly` → ticket |
| `AO-ANO-005` | z ≥ 20σ (cardinalité) | `critical` | Ticket + traitement manuel |

!!! note "Pourquoi aucune action automatique sur les anomalies distribuées"
    Face à une attaque répartie, bloquer **une** adresse ne sert à rien, et bloquer une plage
    entière risque de couper des clients légitimes — les attaques distribuées utilisent
    souvent des adresses compromises. La bonne réponse est globale et humaine : Thot Secure
    ouvre un ticket avec les éléments de décision, et n'agit pas.

## 8. Limites connues

* **Trafic saisonnier** : un pic récurrent (lundi matin, campagne mensuelle) est signalé la
  première fois, puis intégré à la moyenne. Utilisez des exceptions datées pour les événements
  prévus.
* **Changement d'infrastructure** : nouveau CDN, mise en cache, bascule DNS invalident
  temporairement la base. Après un changement majeur, laissez une journée de réapprentissage.
* **Entités à très faible volume** : une source qui émet 1 événement par heure ne produit pas
  de base statistique exploitable ; c'est le rôle des règles déterministes.
* **Pas de corrélation multi-signaux** : le détecteur ne croise pas encore plusieurs entités
  (une source *et* un compte, par exemple). C'est prévu en 0.3.
