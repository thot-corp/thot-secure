```yaml
canal: Blog du projet (Thot Secure) — article technique de fond
langue: fr
format: article technique markdown, code Python exécutable (stdlib), schémas
objectif: >
  Expliquer pourquoi l'audit d'Thot Secure est chaîné par hash plutôt que « blockchainisé »,
  montrer une implémentation simple, démontrer la détection de falsification, puis exposer
  sans complaisance les limites réelles (accès root, troncature de queue, RGPD, horloge).
mot_cle_principal: audit log chaîné par hash
mots_cles_secondaires: [intégrité de journal, détection de falsification, RGPD, SIEM, ancrage horodaté, append-only]
longueur: 1500–2000 mots (hors blocs de code)
public_cible: RSSI, ingénieurs sécurité, auditeurs, architectes, équipes conformité
date_de_publication_cible: S2 — mardi, 10:00 CET
appel_a_action: contribuer aux tests d'audit (chaîne valide, falsification, export CEF) et au mécanisme d'ancrage
mention_de_dons: uniquement en toute fin d'article
```

# Audit log chaîné par hash : pourquoi, comment, et où ça casse vraiment

**Chapô.** Un journal d'audit sert à répondre à une question désagréable : *« prouvez-moi que cette trace n'a pas été modifiée. »* Thot Secure répond avec une chaîne de hash — pas avec une blockchain. Voici le mécanisme exact, la détection de falsification en quelques lignes de Python, puis les cas où ça ne protège pas : accès root, troncature de la queue du journal, horloge non fiable, et le conflit entre immuabilité et droit à l'effacement.

---

## 1. Ce qu'un journal d'audit doit prouver

Répondre « oui, on a des logs » ne prouve rien. Cinq propriétés sont réellement demandées.

**Append-only.** On ajoute, on ne réécrit pas : toute API capable de modifier un enregistrement passé est un défaut de conception, pas une fonctionnalité.

**Intégrité détectable.** Si un enregistrement change, ne serait-ce qu'un champ d'état, la falsification doit être détectable et l'endroit de la rupture identifiable.

**Ordre vérifiable.** « L'action a été approuvée avant d'être exécutée » doit être prouvable par le journal, pas par la mémoire des opérateurs.

**Vérifiabilité hors ligne.** Un auditeur doit pouvoir conclure avec le journal, un script et une somme de contrôle — sans service tiers, sans réseau, sans fournisseur.

**Continuité.** Un attaquant ne doit pas pouvoir *retirer* des enregistrements sans laisser de trace. C'est la propriété la plus difficile, et celle qui échoue le plus souvent (§5).

## 2. Pourquoi pas une blockchain

Une blockchain résout ceci : établir un consensus sur un état partagé **entre plusieurs parties qui ne se font pas mutuellement confiance et qui n'ont pas d'autorité commune**. C'est un problème de coordination sans tiers de confiance. Ce n'est pas le nôtre, pour trois raisons.

**Le modèle de confiance diffère.** Sur votre journal, il y a une autorité : vous. Vous n'avez pas à convaincre un réseau de mineurs que l'enregistrement 42 est authentique ; vous devez le prouver à un auditeur ou à votre équipe dans six mois. Un hash suffit.

**Le coût va dans le mauvais sens.** Un registre distribué ajoute latence, nœuds, synchronisation et surface d'attaque, pour un bénéfice nul sur la propriété visée.

**Le code doit rester auditable.** `thotsecure.core` ne dépend que de la **stdlib** plus `pydantic` et `PyYAML` ; un journal chaîné tient en quelques dizaines de lignes relisibles. En sécurité, la vérifiabilité dépend de la simplicité du code qui la produit.

Ce qu'une blockchain apporte d'utile ici, c'est **l'ancrage externe** — une empreinte hors de portée de l'attaquant. Horodatage signé, export SIEM ou empreinte publiée dans un dépôt distinct suffisent (§5.1).

## 3. Le mécanisme exact

Chaque enregistrement contient `seq`, `ts`, `tenant_id`, `actor`, `actor_role`, `action`, `target`, `before`, `after`, `prev_hash` et `hash`. Le hash est calculé ainsi :

```
hash = sha256( f"{seq}|{ts}|{tenant_id}|{actor}|{actor_role}|{action}|{canonical(target)}|"
        f"{canonical(before)}|{canonical(after)}|{prev_hash}" )
```

`canonical()` est une sérialisation JSON déterministe : clés triées, séparateurs compacts, UTF-8. Le premier enregistrement a `prev_hash = "sha256:genesis"`. Trois détails décident de la solidité, et sont souvent bâclés.

**La canonicalisation.** Hasher un JSON « tel quel » donne des empreintes différentes selon l'ordre des clés ou les espaces. D'où la spécification de `canonical()` dans le contrat : sans elle, la vérification dépend du langage ou de la bibliothèque.

**Le préfixe d'algorithme.** Les empreintes sont stockées en `sha256:`. Le préfixe fait partie de la valeur *stockée* — donc de `prev_hash` tel qu'il entre dans le calcul — et non de la matière hachée. Une ambiguïté d'un caractère suffit à rendre un journal invérifiable.

**Les champs `before` / `after`.** Journaliser la transition (`{"status": "pending_approval"}` → `{"status": "approved"}`) permet de reconstruire une chronologie probante sans interpréter des messages libres.

## 4. Démonstration : détecter une falsification

L'implémentation tient en stdlib. `append()` lit l'empreinte précédente dans la base plutôt que de la garder en mémoire : l'enchaînement survit au redémarrage. `verify()` contrôle deux choses indépendamment — la correspondance empreinte/contenu, et la continuité de `seq`.

```python
import hashlib
import json
import sqlite3
from typing import Any

GENESIS = "sha256:genesis"


def canonical(obj: Any) -> str:
    """JSON déterministe : clés triées, séparateurs compacts, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(
    seq: int,
    ts: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    action: str,
    target: Any,
    before: Any,
    after: Any,
    prev_hash: str,
) -> str:
    material = "|".join(
        [
            str(seq),
            ts,
            tenant_id,
            actor,
            actor_role,
            action,
            canonical(target),
            canonical(before),
            canonical(after),
            prev_hash,
        ]
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def append(
    conn: sqlite3.Connection,
    *,
    ts: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    action: str,
    target: Any,
    before: Any,
    after: Any,
) -> tuple[int, str]:
    row = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    seq = 1 if row is None else row[0] + 1
    prev_hash = GENESIS if row is None else row[1]
    h = record_hash(seq, ts, tenant_id, actor, actor_role, action, target, before, after, prev_hash)
    conn.execute(
        "INSERT INTO audit (seq, ts, tenant_id, actor, actor_role, action,"
        " target, before, after, prev_hash, hash)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            seq,
            ts,
            tenant_id,
            actor,
            actor_role,
            action,
            canonical(target),
            canonical(before),
            canonical(after),
            prev_hash,
            h,
        ),
    )
    conn.commit()
    return seq, h


def verify(conn: sqlite3.Connection) -> dict:
    """Renvoie l'équivalent de GET /api/v1/audit/verify."""
    prev_hash = GENESIS
    records = 0
    for (
        seq,
        ts,
        tenant_id,
        actor,
        actor_role,
        action,
        target,
        before,
        after,
        stored,
    ) in conn.execute(
        "SELECT seq, ts, tenant_id, actor, actor_role, action,"
        " target, before, after, hash FROM audit ORDER BY seq"
    ):
        records += 1
        if seq != records:  # trou de séquence : suppression
            return {"valid": False, "records": records, "broken_at": seq}
        expected = record_hash(
            seq,
            ts,
            tenant_id,
            actor,
            actor_role,
            action,
            json.loads(target),
            json.loads(before),
            json.loads(after),
            prev_hash,
        )
        if expected != stored:  # contenu modifié
            return {"valid": False, "records": records, "broken_at": seq}
        prev_hash = stored
    return {"valid": True, "records": records, "broken_at": None}
```

Le contrôle de continuité est ce qui détecte une suppression — beaucoup d'implémentations l'oublient. Voici ce que l'API et la CLI exposent :

```console
$ thotsecure audit verify
audit: 1284 enregistrements, chaîne valide (valid=true, broken_at=null)

$ curl -s -H "X-API-Key: thot_…" https://thotsecure.local/api/v1/audit/verify
{"valid":true,"records":1284,"broken_at":null}
```

Le code de sortie CLI `3` est réservé aux vérifications négatives : une supervision peut alerter sans analyser de texte.

**Cas 1 — modification brutale.** Un opérateur veut effacer la trace d'un rejet et modifie directement la base :

```python
conn.execute("UPDATE audit SET after = ? WHERE seq = 3", (canonical({"status": "approved"}),))
conn.commit()
print(verify(conn))
# {'valid': False, 'records': 3, 'broken_at': 3}
```

**Cas 2 — l'attaquant soigneux.** Il recalcule l'empreinte de l'enregistrement modifié ; la chaîne casse alors au suivant, car le `prev_hash` de l'enregistrement 4 ne correspond plus :

```python
h3 = record_hash(
    3,
    ts3,
    "acme",
    "api-key:ops",
    "responder",
    "action.reject",
    target3,
    before3,
    {"status": "approved"},
    prev_hash3,
)
conn.execute(
    "UPDATE audit SET after=?, hash=? WHERE seq=3", (canonical({"status": "approved"}), h3)
)
conn.commit()
print(verify(conn))
# {'valid': False, 'records': 4, 'broken_at': 4}
```

Pour passer inaperçu, il faut recalculer **toute la queue** du journal, en cascade. C'est cette propriété — un coût de falsification qui croît avec la profondeur de l'historique — qui fait la valeur d'une chaîne de hash. Ce n'est pas de la magie cryptographique : c'est une accumulation de travail.

## 5. Là où ça casse

Une chaîne de hash **détecte** la modification ; elle n'empêche rien. Quatre limites comptent.

### 5.1 Un accès root réécrit la chaîne entière

Qui peut écrire dans la base et exécuter du code sur la machine peut recalculer toute la chaîne depuis le genesis et obtenir un journal **valide** au sens de `verify()`. Un journal chaîné n'est pas inviolable : sa falsification est coûteuse et détectable **si et seulement si** une copie de référence existe ailleurs.

Contre-mesures, par ordre d'efficacité :

1. **Exporter vers un système que l'administrateur d'Thot Secure ne contrôle pas.** `GET /api/v1/audit/export?format=jsonl|cef` produit un flux destiné à un SIEM. La mesure décisive est de l'exécuter en **push planifié**, et non en pull à la demande : une suppression locale suivie d'un export à la demande donnerait un résultat silencieusement propre.
2. **Ancrer l'empreinte de tête.** Publier périodiquement `(seq_max, hash_max, horodatage)` hors de portée de l'attaquant — autorité d'horodatage, dépôt Git distinct, stockage WORM. *L'ancrage automatique n'est pas fourni en v0.1.0 : chantier identifié.*
3. **Sauvegardes hors ligne** et stockage non réinscriptible pour les exports.4. **Séparer les privilèges.** Qui exploite la base ne devrait pas pouvoir la purger : `read:audit` est une capacité distincte dans le RBAC (quatre rôles : `viewer | analyst | responder | admin`), et les clés API sont stockées hachées (`scrypt`), au format `thot_<identifiant>_<secret>`, révocables, jamais en clair. L'authentification se fait **par clés API uniquement** : pas de SSO/OIDC ni de comptes nominatifs.

### 5.2 La troncature de la queue ne casse pas la chaîne

La limite la plus sous-estimée. Supprimer les 50 **derniers** enregistrements laisse une chaîne parfaitement valide : plus de `prev_hash` orphelin, séquence continue. La vérification intégrée ne détecte pas cette attaque — comme dans la plupart des journaux chaînés existants. Ce qui la détecte, c'est la comparaison avec une référence externe : le dernier `seq` connu du SIEM, ou l'ancrage de tête. **La détection de troncature est un problème d'exploitation, pas d'algorithme.**

### 5.3 L'horloge n'est pas de confiance

`ts` entre dans le hash, mais rien ne garantit l'horloge système : une dérive NTP ou une manipulation de l'heure peut antidater un enregistrement dans une chaîne réécrite. L'ordre logique reste prouvé par `seq` — raison supplémentaire de contrôler la continuité de la séquence. Un horodatage externe apporte ici une garantie que le journal seul ne peut pas fournir.

### 5.4 Le journal prouve ce qui a été enregistré, pas l'action elle-même

La chaîne garantit l'intégrité *du journal*, pas la vérité de son contenu. Elle ne prouve pas que l'action a modifié le système cible (cela dépend du connecteur et de ses journaux), ni que l'acteur était bien la personne annoncée (une clé API volée produit des enregistrements parfaitement valides), ni que **tous** les événements pertinents ont été collectés — l'absence de trace n'est pas une preuve d'absence. Condition nécessaire à une enquête crédible, jamais suffisante.

*Limite d'échelle, pour être complet :* une chaîne impose un écrivain séquentiel. Cohérent avec SQLite en MVP ; à plus grande échelle, la parade usuelle est le lot avec racine de Merkle par lot. **Non implémenté en v0.1.0 : roadmap.**

## 6. Immuabilité contre RGPD

Le conflit est réel : un journal immuable conserve des identifiants d'acteurs — donc potentiellement des données personnelles — alors que le RGPD prévoit un droit à l'effacement (art. 17) et une limitation de conservation (art. 5.1.e). Ces exigences ne sont pas absolues : la conservation peut se justifier par une obligation légale ou la défense de droits en justice. Mais elles doivent être **arbitrées et documentées**, pas ignorées. *Analyse technique, pas avis juridique : la qualification relève de votre DPO.*

**Minimiser à la source.** Journaliser `api-key:ci` plutôt qu'un nom de personne, un `tenant_id` plutôt qu'une raison sociale, et ne pas recopier de données métier dans `target` ou `before`/`after` au-delà de ce qui prouve la transition d'état. La donnée qu'on n'écrit pas n'a pas à être effacée. Le contrat va dans ce sens : `actor` est un identifiant de clé, les charges utiles d'événement sont limitées à 32 Kio (`raw_ref` au-delà), et leur rétention est réglable par `THOT_RETENTION_DAYS` (30 jours par défaut).

**Supprimer par segments, après ancrage.** On ne peut pas retirer un enregistrement au milieu d'une chaîne sans la casser — c'est voulu. On peut en revanche définir une fenêtre de conservation puis supprimer des **segments entiers en partant du plus ancien**, après avoir ancré l'empreinte de tête du segment supprimé et celle du segment conservé : la preuve qu'une histoire a existé et n'a pas été réécrite subsiste, sans conserver le détail au-delà de la durée justifiée. *Thot Secure v0.1.0 ne fournit pas de purge consciente de la chaîne : procédure à concevoir par l'organisation, chantier ouvert.*

**Chiffrer les champs sensibles et détruire la clé (crypto-shredding).** Le journal et sa chaîne restent intacts ; la clé par sujet disparaît et rend les champs concernés illisibles. La chaîne reste vérifiable, le hash portant sur le texte chiffré.

Deux points opérationnels : la politique de rétention de l'audit **doit être écrite** (le contrat spécifie la purge des événements, pas la durée de conservation de l'audit — décision de l'organisation) ; et la **révocation d'accès doit être auditée** (`admin:keys`, avec acteur et horodatage). C'est ce qu'un auditeur demandera.

## 7. Checklist d'évaluation

Dix questions à poser à tout outil qui promet un « audit immuable » :

1. La fonction de hash est-elle spécifiée au caractère près (canonicalisation, préfixe, genesis, premier enregistrement) ?
2. La vérification détecte-t-elle une suppression **au milieu** de la chaîne (continuité de `seq`) ?
3. Est-elle exécutable **hors ligne**, sur une copie du journal ?
4. Les enregistrements sont-ils seulement ajoutables, sans API de modification ?
5. Existe-t-il un **ancrage externe** de l'empreinte de tête, et l'export vers un tiers est-il **poussé** régulièrement plutôt que disponible à la demande ?
6. Qui peut lire la base, qui peut la purger, et sont-ce deux personnes différentes ?
7. La rétention est-elle écrite, et la suppression préserve-t-elle la vérifiabilité du reste ?
8. La vérification tourne-t-elle en continu, avec alerte sur un résultat négatif ?

État actuel côté Thot Secure : oui pour 1, 2, 3, 4, 6 et 8 (`thotsecure audit verify`, code de sortie `3`, `/api/v1/audit/verify`, métriques sur `/metrics`) ; **partiellement, ou par procédure d'exploitation** pour 5 et 7 — chantiers ouverts.

## 8. Contribuer

**Tests d'audit.** `tests/test_storage_conformance.py` doit couvrir chaîne valide, falsification (contenu modifié, hash recalculé, suppression au milieu) et export CEF, cas limites compris : journal vide, séquence trouée — complété par `tests/test_api.py` (métriques, `/api/v1/audit/verify`, export CEF) et `tests/test_smoke_e2e.py` (le cycle complet inscrit dans la chaîne). Un test qui échoue volontairement pour documenter la troncature de queue vaut autant qu'un correctif.

**Ancrage horodaté.** Identifié, non implémenté : c'est l'apport qui transforme une chaîne « détecte la modification » en chaîne « détecte aussi l'effacement ».

**Purge consciente de la chaîne.** Concevoir la suppression par segments ancrés, avec tests et documentation de conformité.

`python -m unittest discover -s tests -t . -v` exécute **396 tests** sans dépendance externe (70 ignorés sans serveur PostgreSQL) ; le contrat d'interface fait foi. Et si vous avez déjà dû défendre un journal contesté en audit, votre retour sur les sections 5 et 6 vaut plus que n'importe quelle étoile GitHub : ouvrez une issue, décrivez le cas, dites ce qui a manqué.

---

## Soutenir le projet

Thot Secure est un projet bénévole sous licence Apache-2.0. Les dons sont volontaires :

- **Bitcoin (BTC, réseau Bitcoin mainnet)** : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- **Solana (SOL, réseau Solana mainnet)** : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

Dons volontaires, **aucune contrepartie** : un don ne donne droit à rien — ni support, ni fonctionnalité, ni priorité. Vérifiez toujours l'adresse depuis le dépôt officiel : ce sont les seules adresses officielles.

⚠️ **Anti-arnaque** : seule la source officielle — dépôt Git + site du projet — fait foi. Le projet ne demande **jamais** de clé privée ni de phrase de récupération, et n'offre aucun support prioritaire ni avantage contre un paiement. Toute sollicitation de ce type est frauduleuse.
