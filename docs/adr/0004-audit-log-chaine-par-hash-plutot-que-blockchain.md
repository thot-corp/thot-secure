# ADR-0004 — Journal d'audit chaîné par hash plutôt que blockchain

*Nous garantissons l'intégrité du journal d'audit par une chaîne de hachage SHA-256 locale,
append-only, vérifiable et exportable, plutôt que par une blockchain ou un service d'horodatage
externe.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté** pour la version 0.1.0 (MVP). Le format de hachage décrit ci-dessous est **gelé** : il
fait partie du contrat d'interface (§3.5 du
[`../architecture/api-contract.md`](../architecture/api-contract.md)) et toute évolution
invalidant l'historique exigera une nouvelle ADR et un versionnement de format.

---

## Contexte

Le journal d'audit est la pièce probante d'Thot Secure. Il enregistre ce que le produit a décidé et
fait : approbations, rejets, exécutions, rollbacks, changements de mode d'autonomie, créations et
révocations de clés. C'est ce journal qu'un RSSI ou un auditeur consultera pour répondre à « qui a
bloqué cette IP, sur quelle base, à quelle heure ? ».

Le §10 du contrat impose un « **audit immuable** : chaîne de hash + `GET /audit/verify` + export
SIEM ». Les exigences concrètes dérivées de cet objectif :

1. **Append-only et inviolable en pratique.** Personne — y compris un administrateur d'Thot Secure —
   ne doit pouvoir modifier ou supprimer discrètement une entrée passée sans que cela se voie. Ce
   n'est pas une exigence d'impossibilité absolue mais de **détection fiable** de toute
   falsification *a posteriori*.
2. **Auditable par un tiers non expert.** Un auditeur doit pouvoir comprendre le mécanisme en
   quelques minutes et le vérifier lui-même, sans faire confiance aux mainteneurs du projet. Une
   garantie que personne ne peut contrôler n'est pas une garantie.
3. **Exportable vers un SIEM.** `GET /api/v1/audit/export?format=jsonl|cef` (§4.7) : le journal doit
   alimenter un SIEM ou un SOAR existant, donc être sérialisable dans des formats standards, sans
   traitement propriétaire.
4. **Aucune dépendance externe.** Thot Secure doit fonctionner en **air-gap**, sur un poste isolé, dans
   un réseau classifié ou chez un client qui refuse toute sortie réseau. Un journal dont
   l'intégrité dépend d'un service tiers est inutilisable dans ces contextes — et c'est exactement
   là que la traçabilité compte le plus.
5. **Aucune fuite de données vers un tiers.** Les enregistrements contiennent des `tenant_id`, des
   `actor`, des `target` (adresses IP, identifiants d'hôtes, noms de playbooks). Les publier hors du
   périmètre du client, même hachés, même « seulement les métadonnées », est un problème de
   confidentialité et de conformité.

Le §3.5 définit déjà la structure de l'enregistrement (`seq`, `ts`, `tenant_id`, `actor`,
`actor_role`, `action`, `target`, `before`, `after`, `prev_hash`, `hash`) et la formule de hash ;
le §4.7 définit les trois points d'entrée `audit`, `audit/verify` et `audit/export` ; le §11 impose
`tests/test_audit_chain.py` (chaîne valide, détection de falsification, export CEF).

---

## Décision

### Structure et chaînage

La table `audit_log` est **append-only** : les opérations autorisées sont l'insertion et la lecture.
Aucune mise à jour ni suppression d'un enregistrement existant n'est prévue par le code applicatif
(hors purge de rétention, qui est elle-même un sujet traité plus bas).

Chaque enregistrement est chaîné au précédent par un SHA-256 calculé sur les champs **canoniques**,
dans l'ordre exact défini au §3.5 :

```
hash = sha256( f"{seq}|{ts}|{tenant_id}|{actor}|{actor_role}|{action}|{canonical(target)}|" \
        f"{canonical(before)}|{canonical(after)}|{prev_hash}" )
```

où `canonical()` = **JSON trié, séparateurs compacts, UTF-8**. Le premier enregistrement (genesis) a
`prev_hash = "sha256:genesis"`.

| Élément | Rôle |
|---|---|
| `seq` | Numéro de séquence strictement croissant, non réutilisé ; lie l'enregistrement à sa position. |
| `prev_hash` | Chaîne l'enregistrement au précédent ; `sha256:genesis` pour le premier. |
| `hash` | Empreinte de l'enregistrement courant, recalculable par tout tiers. |
| `canonical()` | Normalisation en JSON trié / séparateurs compacts / UTF-8 : rend le hash indépendant de la mise en forme, des espaces et de l'ordre des clés. |
| `before` / `after` | États avant/après de l'objet visé (par exemple `{"status":"pending_approval"}` → `{"status":"approved"}`). |
| `actor`, `actor_role` | Qui a agi et sous quel rôle — la traçabilité de responsabilité. |

### Vérification

* `GET /api/v1/audit/verify` (capacité `read:audit`) relit les enregistrements **dans l'ordre de
  `seq`**, recalcule chaque hash et renvoie `{"valid":…,"records":n,"broken_at":…}` (§4.7).
* La CLI expose `thotsecure audit verify` et `thotsecure audit tail` (§8).
* Une vérification négative produit le **code de sortie `3`** (« vérification négative, ex. audit
  corrompu », §8), distinct du `1` (erreur) et du `2` (usage) : un script d'exploitation peut donc
  alerter sur une corruption d'audit sans confondre ce cas avec une panne de l'outil.
* `tests/test_audit_chain.py` (§11) couvre la chaîne valide, la **détection de falsification** et
  l'export CEF.

### Export et ancrage externe

`GET /api/v1/audit/export?format=jsonl|cef` produit un flux téléchargeable vers un SIEM/SOAR. Cet
export est aussi — et c'est essentiel — le **mécanisme d'ancrage externe** : la copie sortie du
périmètre d'Thot Secure devient une preuve indépendante du produit (voir les conséquences négatives,
qui expliquent pourquoi l'export n'est pas un détail mais une nécessité).

### Traçabilité croisée

Chaque action référence son enregistrement d'audit via `audit_seq` (§3.4), chaque décision
référence `policy_id` : la relecture d'un incident relie décision, exécution et journal sans
ambiguïté.

!!! note "Vérifiable par un tiers en trente lignes"
    Un auditeur peut réimplémenter la vérification à partir du seul §3.5 du contrat : lire les
    enregistrements triés par `seq`, recalculer `sha256` sur la concaténation canonique, comparer
    `prev_hash` au `hash` précédent, et signaler le premier `seq` divergent. C'est un critère de
    conception explicite : **aucune bibliothèque propriétaire, aucune autorité de confiance, aucun
    accès réseau** n'est nécessaire.

---

## Conséquences

### Positives

* **Aucune infrastructure supplémentaire.** Pas de nœud, pas de réseau, pas de service : la chaîne
  vit dans la même base que le reste (SQLite au MVP, PostgreSQL en cible). Le coût d'exploitation
  est nul.
* **Vérifiable par un script court.** La formule est publique, déterministe et reproductible en une
  trentaine de lignes dans n'importe quel langage disposant de SHA-256 et d'un sérialiseur JSON.
* **Aucune fuite de données vers un tiers.** Les enregistrements — donc les `tenant_id`, les
  adresses IP et les noms d'hôtes — ne quittent jamais le périmètre de l'utilisateur. La
  confidentialité n'est pas négociée contre l'intégrité.
* **Compatible air-gap.** Fonctionne sur un poste isolé, dans un réseau fermé, chez un client qui
  interdit toute sortie réseau. C'est une contrainte dure pour un outil de sécurité OT/industriel ou
  gouvernemental.
* **Détection de toute falsification *a posteriori*.** Modifier un `before`, supprimer un
  enregistrement intermédiaire ou réordonner la chaîne casse la vérification et désigne le premier
  `seq` divergent (`broken_at`).
* **Coût nul.** Quelques dizaines de microsecondes de SHA-256 par enregistrement, aucune latence
  réseau, aucun coût de transaction.
* **Indépendant de toute crypto-monnaie.** Aucun token, aucune volatilité, aucun discours
  spéculatif : le mécanisme est un usage classique de fonction de hachage, compréhensible par
  n'importe quel ingénieur sécurité.

### Négatives

* **La chaîne n'empêche pas la falsification par un attaquant disposant d'un accès en écriture au
  fichier.** C'est la limite fondamentale, et il faut être précis : un adversaire qui peut réécrire
  la base **et recalculer toute la chaîne depuis le genesis** produit un journal parfaitement
  cohérent. Le chaînage ne fait que rendre la falsification *détectable* si une copie antérieure
  authentique existe ailleurs. **La seule parade est l'ancrage externe** : export périodique vers un
  SIEM, horodatage, ou copie hors ligne sur un support non accessible depuis le serveur. Sans cette
  discipline opérationnelle, la garantie est faible — et c'est à l'exploitant de la mettre en place.
* **Vérification en O(n).** Recalculer toute la chaîne coûte proportionnellement à l'historique. Un
  journal de plusieurs millions d'enregistrements rend la vérification complète longue, ce qui
  décourage la vérification fréquente — précisément ce qu'on veut éviter. *Prévoir une vérification
  incrémentale ou par plage (`since`/`until`, §4.7) ; la disponibilité de ce mode doit être
  **confirmée par le code** et n'est pas garantie par le contrat.*
* **Tension avec le droit à l'effacement (RGPD).** Un journal immuable s'oppose frontalement à
  l'obligation d'effacer des données personnelles : supprimer un enregistrement casse la chaîne,
  le réécrire est une falsification. La position d'Thot Secure est de **pseudonymiser, jamais
  supprimer** — voir [`../compliance/rgpd.md`](../compliance/rgpd.md). C'est un compromis assumé,
  pas une solution neutre : il faut le documenter et l'assumer face à une autorité de contrôle.
* **Restauration de sauvegarde = divergence de chaîne.** Restaurer une base plus ancienne puis
  continuer à écrire crée deux historiques divergents (ou une rupture de `prev_hash`). Ce scénario
  n'est pas un incident de confort : il doit être traité comme un **incident de sécurité** dans
  [`../operations/runbook.md`](../operations/runbook.md), avec constat, explication de la rupture et
  conservation des deux historiques. La purge par `THOT_RETENTION_DAYS` (§9) et la rétention du
  journal doivent être cohérentes entre elles, sans quoi une purge d'événements peut surprendre
  l'exploitant.
* **Pas de consensus distribué.** Une seule base = un seul point de confiance. Il n'y a pas de
  majorité de nœuds pour contester une réécriture, contrairement à une blockchain. Le modèle suppose
  que l'exploitant contrôle son serveur, ce qui est vrai dans un déploiement mono-instance mais
  devient un point faible si le serveur est compromis avec un accès en écriture durable.
* **Format de hash figé.** Toute évolution de la formule (champ ajouté, normalisation modifiée)
  invaliderait l'intégralité de l'historique existant. Le format du §3.5 est donc gelé, ce qui
  contraint les évolutions futures de l'objet `AuditRecord` : ajouter un champ obligerait à
  versionner le format et à traiter la vérification de plusieurs générations de chaînes.

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : **versionnement explicite du format de hash** (pour permettre des
    évolutions sans invalider l'historique), **vérification incrémentale / par plage** pour rendre
    la vérification praticable sur de gros volumes, **signature de la chaîne entière ou d'un point
    d'ancrage périodique** (clé de l'instance, `THOT_SECRET_KEY`), **arbre de Merkle avec
    ancrage périodique** pour une vérification en O(log n) et une preuve d'antériorité compacte, et
    **export automatique planifié** vers un SIEM ou un stockage WORM pour matérialiser l'ancrage
    externe.

---

## Alternatives envisagées

| Alternative | Ce qu'elle apportait | Raison du rejet |
|---|---|---|
| **Blockchain (publique ou permissionnée)** | Immuabilité « par construction », consensus distribué, horodatage indépendant, récit commercial fort (« notre audit est sur une blockchain »). | Rejetée. **Complexité opérationnelle disproportionnée** : nœuds à déployer, gouvernance du réseau à définir, mise à jour et supervision d'une brique supplémentaire, pour un journal **mono-écrivain** qui ne bénéficie d'aucun consensus. **Latence et coût** : l'écriture d'un enregistrement dépend de la production d'un bloc, ce qui est incompatible avec des approbations interactives (`POST /api/v1/actions/{id}/approve`) et avec un produit qui doit fonctionner hors ligne. **Dépendance réseau** : incompatible avec l'air-gap, alors que c'est un besoin explicite. **Fuite potentielle de métadonnées** : publier des empreintes de `tenant_id`, d'IP et d'horodatages dans un registre public est un risque de confidentialité et de corrélation, même sans contenu en clair. **Gouvernance** : qui détient les clés, qui valide, que se passe-t-il en cas de fork ? Enfin, une blockchain **ne résout pas** le problème réel — un attaquant qui contrôle l'écrivain peut de toute façon proposer une chaîne alternative — et le coût de vérification et de gouvernance du réseau est sans commune mesure avec le bénéfice pour un MVP. |
| **Stockage immuable type WORM / append-only** (objet S3 avec verrouillage, volume WORM, coffre-fort de journalisation) | Immuabilité réellement garantie par l'infrastructure, y compris contre un administrateur ; rétention légale opposable. | Intéressant mais **dépendant du fournisseur** : cela introduit une dépendance cloud, un coût récurrent, une configuration de rétention à gérer et une rupture de l'air-gap. La solution contredit le principe « aucune infrastructure supplémentaire » et le coût d'entrée d'un pilote. Considéré comme **cible à moyen terme** (`!!! info "Roadmap"` ci-dessus) plutôt que comme fondation du MVP. |
| **Journalisation externe uniquement** (syslog distant, SIEM, journalisation en streaming) | Déport immédiat de la preuve hors du serveur, exploitation par les outils existants du client, corrélation avec le reste du SI. | Rejeté : **pas de garantie locale**. Si le SIEM est indisponible, surchargé, mal filtré ou si le réseau tombe, l'enregistrement est perdu — et un journal qui perd des entrées au moment de l'incident n'a aucune valeur probante. La disponibilité du SIEM devient une dépendance de la sécurité du produit. L'export reste **un complément essentiel** (ancrage externe), pas le mécanisme primaire. |
| **Signature électronique par enregistrement** (clé privée de l'instance, une signature par entrée) | Non-répudiation forte par entrée, preuve d'origine indépendante de la chaîne. | Rejetée **au MVP** : coût CPU significatif par enregistrement (asymétrique sur chaque insertion), **gestion des clés** entière (génération, stockage, rotation, révocation, sauvegarde, procédure de compromission), et **complexité de vérification** pour un tiers — l'auditeur doit disposer de la clé publique, comprendre le schéma de signature, gérer la rotation. Cela contredit l'objectif « vérifiable par un script de 30 lignes ». Piste conservée : la signature de la **chaîne entière** ou d'un **point d'ancrage périodique** (un seul calcul par période, une seule clé à gérer) — voir Roadmap. |
| **Arbre de Merkle avec ancrage périodique** | Vérification en **O(log n)** au lieu de O(n), preuve d'inclusion compacte pour un enregistrement donné, ancrage externe d'une seule racine plutôt que de tout le journal. | Non rejetée : c'est une **piste crédible et retenue pour la suite**, mais elle exige une structure de stockage supplémentaire (nœuds internes, recalcul des racines à chaque insertion), une définition des périodes d'ancrage (`epochs`) et une procédure de vérification distincte à spécifier et à tester. Elle est disproportionnée pour un MVP dont l'objectif est la vérification complète d'un journal de taille modérée. Reportée en Roadmap, en complément — non en remplacement — du chaînage linéaire. |
| **Aucune garantie d'intégrité** (journal simple, horodaté) | Simplicité maximale, aucun coût. | Rejeté sans hésitation : un journal modifiable sans détection ne vaut rien en audit et contredirait l'exigence d'« audit immuable » du §10. Un produit défensif qui vend de la traçabilité ne peut pas livrer un journal non protégé. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
