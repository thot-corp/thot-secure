# RGPD et protection des données

*Aide opérationnelle pour traiter les données personnelles présentes dans une plateforme de détection et de réponse : rôles, bases légales, minimisation, pseudonymisation des IP, durées de conservation, droits des personnes et registre des traitements.*

!!! warning "Cette page n'est pas un avis juridique"
    Ce document est une **aide opérationnelle** destinée aux équipes techniques et sécurité. Il ne
    constitue **ni un avis juridique**, ni une interprétation opposable du RGPD, ni une garantie de
    conformité. La qualification des traitements, le choix des bases légales, la rédaction des
    contrats et la réponse aux autorités relèvent de la **responsabilité de l'exploitant**, avec
    l'appui de son **DPO** et de son **juriste**. Thot Secure ne délivre aucune certification et
    n'engage aucune obligation de résultat en matière de conformité.

Référence technique de tout ce qui suit : [`../architecture/api-contract.md`](../architecture/api-contract.md)
(contrat gelé de l'interface v0.1.0). Les schémas cités (`Event`, `Finding`, `AuditRecord`) y sont
définis au §3 ; les routes au §4 ; les variables `THOT_*` au §9.

## 1. Rôles : qui est responsable de quoi

Thot Secure est un **logiciel auto-hébergé et distribué en open source** (Apache-2.0). L'éditeur du
logiciel **n'héberge aucune donnée** et ne traite, pour le compte de personne, les événements
collectés par une instance. Le contrat d'interface **ne décrit aucune télémétrie sortante**, aucun
appel vers un service de l'éditeur, aucun identifiant d'instance transmis à un tiers : le produit
n'émet pas de données vers l'extérieur par conception, et aucune fonction de ce type n'est prévue.

!!! note "Conséquence pratique"
    Puisque l'éditeur n'héberge rien, il n'est **ni responsable de traitement ni sous-traitant** au
    titre de l'instance que vous exploitez. Les rôles se répartissent entre l'exploitant, son
    hébergeur et, le cas échéant, le MSSP qui opère la plateforme pour ses clients. Ce point reste à
    confirmer au regard du **modèle de distribution retenu** (dépôt public, paquet, image, offre
    supportée) : faites-le valider par votre juriste.

| Mode de déploiement | Responsable de traitement | Sous-traitant(s) | Personnes concernées |
|---|---|---|---|
| Client final s'auto-hébergeant (une seule organisation) | L'organisation elle-même | Hébergeur d'infrastructure, prestataire d'exploitation éventuel | Utilisateurs internes, visiteurs et clients exposés sur Internet, **tiers attaquants** identifiés par leur IP |
| MSSP opérant Thot Secure pour le compte de ses clients | Chaque **client** du MSSP, pour ses propres données | Le **MSSP** (art. 28), plus l'hébergeur du MSSP | Idem, côté client |
| Laboratoire / environnement de test | L'entité qui exploite le labo | Hébergeur | Personnes présentes dans les jeux de données (souvent synthétiques, à vérifier) |
| Éditeur du logiciel (distribution, support) | Sans objet : pas de données hébergées | Sans objet | Sans objet |

!!! tip "Le réflexe à avoir"
    Écrivez noir sur blanc, dans votre registre, **qui** est responsable et **pour quel périmètre de
    tenants**. Dans un déploiement MSSP, un même serveur Thot Secure peut contenir les données de
    plusieurs responsables de traitement distincts : l'isolation technique se fait par `tenant_id`
    (invariant 4 du §1), mais l'isolation **juridique** se fait par contrat.

## 2. Bases légales

Une plateforme de sécurité traite des données personnelles sans consentement préalable : les
personnes concernées (visiteurs, salariés, attaquants) ne « s'inscrivent » pas. La base légale
mobilisée est donc presque toujours l'**intérêt légitime** (art. 6.1.f), parfois complétée par une
**obligation légale** (art. 6.1.c) propre au secteur.

| Finalité | Base légale usuelle | Remarques |
|---|---|---|
| Détecter les intrusions, abus et erreurs de configuration sur son propre SI | Intérêt légitime (art. 6.1.f) | Finalité première ; nécessite un test de mise en balance documenté |
| Qualifier et prioriser les incidents (règles, scoring, dedup) | Intérêt légitime | Le scoring ne doit pas servir à un profilage des personnes |
| Déclencher une contre-mesure **réversible** (blocage, limitation, isolation) | Intérêt légitime | Le caractère réversible (§1 invariant 3) et le `dry_run` par défaut sont des garanties de proportionnalité |
| Tracer les accès et les actions dans un journal d'audit | Intérêt légitime ; obligation légale pour certains secteurs | Le journal sert aussi à répondre aux demandes des personnes |
| Conserver des éléments en vue d'une plainte ou d'une procédure | Intérêt légitime ; obligation légale | Conservation ciblée, pas de conservation « au cas où » |
| Répondre à une obligation réglementaire de journalisation (secteur régulé, OIV, santé, finance) | Obligation légale (art. 6.1.c) | Vérifier la durée imposée par le texte applicable |
| Notifier un CERT, une autorité ou un client impacté | Intérêt légitime ; obligation légale | Cadrer le contenu minimal nécessaire |
| Gérer les comptes d'accès à la console (clés API nominatives) | Intérêt légitime ; exécution du contrat pour un client MSSP | Préférer des clés fonctionnelles ; voir §4 |
| Communications non transactionnelles (marketing, newsletter) | Consentement (art. 6.1.a) | **Hors périmètre du produit** : aucune fonction d'envoi de ce type n'existe dans Thot Secure |

### 2.1 Analyse d'intérêt légitime (test de mise en balance)

L'intérêt légitime n'est pas une base « libre » : elle doit être **documentée** avant la mise en
production. Quatre étapes, à consigner dans le registre (§9) :

1. **L'intérêt** : protéger la disponibilité, l'intégrité et la confidentialité du SI ; détecter les
   intrusions ; protéger les utilisateurs et les tiers contre des usages abusifs.
2. **La nécessité** : montrer que des moyens moins intrusifs (journaux agrégés, compteurs, alertes
   sans identifiant) ne permettent pas d'atteindre la finalité — d'où la pseudonymisation des IP
   (§5) et la rétention courte (§6).
3. **La mise en balance** : les personnes concernées ont-elles des attentes légitimes de non-surveillance
   ? Les données sont-elles limitées au strict nécessaire ? Une surveillance des **salariés** doit
   respecter les règles internes et, selon les pays, les obligations d'information préalable des
   représentants du personnel.
4. **Les garanties** : minimisation, pseudonymisation, cloisonnement par tenant, RBAC de moindre
   privilège, journal d'audit chaîné, durée de conservation bornée, revue périodique des accès.

!!! warning "Point d'attention : surveillance des personnes"
    Une IP identifie une personne ; un `user_agent`, un chemin d'URL avec jeton de session ou un nom
    d'utilisateur dans un `payload` aussi. Un outil de détection n'est **pas** un outil de contrôle
    des salariés : ne détournez pas les findings à des fins d'évaluation individuelle, d'où
    l'insistance sur la pseudonymisation et la restriction des `payload` collectés.

## 3. Quelles données personnelles circulent réellement

Les journaux de sécurité **contiennent des données personnelles** : c'est le constat central de
cette page. Le §3.1 du contrat définit les `labels` comme un espace plat de valeurs scalaires
(« `labels.src_ip`, `payload.status` ») explicitement destiné aux règles de détection : les
adresses IP y sont donc **par construction** un champ de première classe.

| Champ (contrat §3) | Nature | Risque | Mesure |
|---|---|---|---|
| `labels.src_ip` | Donnée personnelle (identifiant indirect fort) | Identifier un visiteur, un salarié, un attaquant ; réidentification croisée avec d'autres sources | **Pseudonymiser** (§5) ou n'ingérer que le préfixe réseau |
| `labels.path` | Non personnel en soi | Peut contenir un **jeton de session**, un identifiant de compte, un e-mail en paramètre | Filtrer/normaliser à l'ingestion ; interdire les secrets en URL par ailleurs |
| `labels.method` | Non personnel | Faible | Aucune |
| `payload.user_agent` | Identifiant indirect (empreinte) | Réidentification d'un poste ou d'un utilisateur | Tronquer, agréger, ou considérer comme un quasi-identifiant |
| `payload` (libre) | Variable : peut contenir identifiants, cookies, corps de requête, adresses e-mail | Élevé : risque d'ingestion de mots de passe ou de jetons | **Masquage** des secrets ; préférer un extrait ; la taille est déjà bornée (≤ 32 Kio, au-delà tronqué + `raw_ref`) |
| `raw_ref` | Référence vers le brut d'origine | Contourne la minimisation : pointe vers une donnée plus riche | Restreindre l'accès au stockage brut ; appliquer la même rétention |
| `source.host` / `source.name` | Peut être un nom de machine nominatif (`pc-marie`) | Faible à moyen | Nommer les hôtes de façon fonctionnelle |
| `Evidence` du `Finding` (§3.2) | **Copie** d'échantillons d'événements | Redouble la donnée personnelle dans une seconde table | Même minimisation à la source ; c'est le point qui rend la pseudonymisation amont indispensable |
| `Finding.title` (§3.2) | Texte libre, peut contenir une IP (l'exemple du contrat contient `203.0.113.9`) | Propagation de la donnée dans les rapports, notifications et tickets | Éviter d'interpoler l'IP dans les titres ; utiliser le pseudonyme |
| `AuditRecord.actor` / `actor_role` (§3.5) | `actor` est une **clé API** (ex. `api-key:ci`), `actor_role` un rôle | Faible : pas de donnée personnelle directe, **sauf** si vous nommez les clés par personne | Utiliser des libellés fonctionnels ; voir §4 |
| `AuditRecord.target.id` / `before` / `after` | Identifiants techniques et états | Faible, mais peut contenir une cible IP dans `params` | Préférer l'identifiant de ressource au contenu |
| `Tenant.name` | Nom d'entité (souvent personne morale) | Faible | Aucune |

!!! danger "Deux fuites classiques par le haut de la pile"
    **1.** Le libellé d'une clé API (`label`, §4.2) est stocké et renvoyé par
    `GET /api/v1/tenants/{id}/keys` : un libellé du type `marie-dsi` transforme un identifiant
    technique en donnée personnelle. **2.** Le paramètre `q` de `GET /api/v1/events` (§4.3) permet
    de rechercher du texte libre : il permet donc de **retrouver une personne** par son IP ou son
    nom d'utilisateur. Ces deux routes relèvent du moindre privilège (`read:events`,
    `admin:keys`) et doivent être tracées.

## 4. Minimisation par conception

| Principe | Mise en œuvre avec Thot Secure |
|---|---|
| Ne collecter que le nécessaire | Restreindre les collecteurs et les `kind` ingérés (`http.request`, `log.line`…) aux sources justifiées ; ne pas ingérer un flux « pour voir » |
| Pseudonymiser les identifiants | HMAC-SHA-256 sur `labels.src_ip`, préfixe réseau conservé (§5) |
| Masquer les secrets | Filtrer jetons, cookies, en-têtes d'authentification et corps de requête **dans le collecteur**, avant l'ingestion |
| Borner les charges utiles | Le contrat plafonne déjà `payload` à 32 Kio (troncature + `raw_ref` du §3.1) ; viser **beaucoup moins** qu'un `payload` complet quand un extrait suffit |
| Restreindre les accès | Rôles `viewer` / `analyst` / `responder` / `admin` (§4) ; une clé par usage et par rôle ; jamais de clé `admin` dans un collecteur |
| Cloisonner | Un `tenant_id` par client (§1 invariant 4) ; ne jamais mélanger les jeux de données de deux clients dans un même tenant |
| Limiter la durée | `THOT_RETENTION_DAYS` (§6) |
| Limiter la diffusion | L'export SIEM (§4.7) est une **copie** : chaque export crée un nouveau destinataire à encadrer |

```yaml
# config/targets.yaml — extrait illustratif : le périmètre autorisé est un choix,
# pas un défaut implicite (§9, THOT_TARGETS_FILE ; §10, cibles déclarées).
tenants:
  acme:
    autonomy_allowlist:
      - 10.0.0.0/8          # infra propre : jamais ciblée par une action (§6 garde-fou 3)
    targets:
      - https://shop.acme.fr # surface auditée par le collecteur / probe, opt-in explicite
```

!!! tip "Le test de la question gênante"
    Pour chaque champ que vous ajoutez à `labels` ou à `payload`, posez la question : « si ce champ
    était publié demain, que révélerait-il sur une personne ? ». Si la réponse n'est pas
    « rien d'utile », pseudonymisez-le ou ne le collectez pas.

## 5. Pseudonymisation de `labels.src_ip`

### 5.1 Objectif

Pseudonymiser une IP, c'est **conserver la capacité de corrélation** (« est-ce la même source ? »)
tout en **supprimant la capacité d'identification directe** (« qui est-ce ? »). Corréler est le cœur
du métier de la détection : seuils, `group_by`, `dedup.key` du §5 s'appuient tous sur
`labels.src_ip`. Un hachage appliqué naïvement **casse** ces mécanismes ou les rend inutiles s'il est
non déterministe (avec sel aléatoire par événement, deux événements de la même source ne se
regroupent plus).

| Exigence | Conséquence de conception |
|---|---|
| Déterministe | Même IP ⇒ même pseudonyme (indispensable au `group_by` et au `dedup`) |
| Non inversible sans secret | HMAC avec clé, jamais un simple hachage |
| Exploitable pour les règles | Le pseudonyme reste une valeur scalaire plate, compatible `labels` (§3.1) |
| Utile à la géolocalisation grossière | Conserver un préfixe réseau séparé, jamais l'IP entière |

### 5.2 Méthode recommandée

**HMAC-SHA-256** de l'adresse normalisée, avec une **clé de pseudonymisation** dédiée, plus
conservation du **préfixe réseau** (par exemple `/24` en IPv4, `/48` en IPv6) dans un champ
distinct.

Deux raisons de préfixer le pseudonyme par un **identifiant de clé** (`k1:…`) : la rotation devient
possible sans perdre la lisibilité des données passées, et la **destruction ciblée** d'une clé
(« crypto-effacement ») devient une opération d'effacement partiel traçable (voir §5.6).

### 5.3 Où l'implémenter

| Emplacement | Avantages | Limites |
|---|---|---|
| **Collecteur** (avant émission de l'événement) | La donnée brute n'atteint jamais la base ni les sauvegardes ; c'est la seule option qui protège aussi `raw_ref` | À écrire et maintenir par l'exploitant ; dépend du collecteur |
| **Proxy d'ingestion** devant `POST /api/v1/events` (§4.3) | Indépendant du langage des collecteurs ; un seul point de contrôle | Le brut transite par le proxy : il faut le configurer pour ne pas journaliser le corps |
| **Règle / pipeline de normalisation** | Se fait dans l'écosystème Thot Secure (règles YAML, §5 du contrat) | Le brut est **déjà stocké** : la pseudonymisation devient curative, pas préventive |

!!! danger "Ce que le contrat ne fournit pas"
    Le contrat d'interface **ne décrit aucune fonction de pseudonymisation intégrée**, aucun
    paramètre `THOT_*` dédié et aucune option CLI pour cela. La pseudonymisation est donc
    **une pratique à mettre en œuvre par l'exploitant**, dans le collecteur, dans un proxy
    d'ingestion ou dans un traitement en aval. Ne cherchez pas une case à cocher dans
    `THOT_*` (§9) : elle n'existe pas.

!!! info "Roadmap"
    Une aide native (fonction de pseudonymisation des `labels`, rotation de clé associée) relève de
    la feuille de route produit, pas du MVP. Voir [`../roadmap.md`](../roadmap.md). En l'état,
    l'implémentation est de votre côté.

### 5.4 Exemple d'implémentation (illustratif)

!!! note "Statut du code ci-dessous"
    Cet exemple est **illustratif** : il n'est pas livré par le dépôt et la clé `THOT_PSEUDO_KEY`
    n'est **pas** une variable du contrat §9. Adaptez-le, testez-le, versionnez-le. La convention de
    nommage `src_ip_hash` / `src_ip_prefix` est proposée par cette page : le contrat ne définit que
    `labels.src_ip`. Ajouter des clés plates supplémentaires reste compatible avec le §3.1 (espace
    plat, valeurs scalaires uniquement) — à confirmer contre
    [`../architecture/data-model.md`](../architecture/data-model.md).

```python
"""Pseudonymisation d'IP — exemple illustratif (stdlib uniquement)."""

import hashlib
import hmac
import ipaddress
import os

# La clé vit HORS de la base : coffre de secrets, injectée par l'environnement.
PSEUDO_KEY = os.environ["THOT_PSEUDO_KEY"].encode("utf-8")
KEY_ID = os.environ.get("THOT_PSEUDO_KEY_ID", "k1")


def pseudonymize_ip(raw_ip: str) -> dict[str, str]:
    """Retourne le pseudonyme déterministe et le préfixe réseau d'une IP.

    - déterministe  : indispensable au group_by / dedup des règles (§5 du contrat) ;
    - non réversible: HMAC avec clé secrète, jamais un hachage nu ;
    - préfixe gardé : géolocalisation grossière sans exposer l'adresse complète.
    """
    addr = ipaddress.ip_address(raw_ip.strip())
    prefix_len = 24 if addr.version == 4 else 48
    network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)

    digest = hmac.new(PSEUDO_KEY, str(addr).encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "src_ip_hash": f"{KEY_ID}:{digest[:32]}",  # tronqué : 128 bits, largement suffisant
        "src_ip_prefix": str(network),
    }


if __name__ == "__main__":
    print(pseudonymize_ip("203.0.113.9"))
    # {'src_ip_hash': 'k1:9f2c…', 'src_ip_prefix': '203.0.113.0/24'}
```

Le collecteur écrit ensuite `src_ip_hash` et `src_ip_prefix` dans `labels` **au lieu de** `src_ip`.
Si des règles existantes s'appuient sur `labels.src_ip` (§5, opérateur `cidr`), il faut les adapter :
la correspondance CIDR n'a plus de sens sur un pseudonyme, d'où l'intérêt de conserver le préfixe
dans un champ séparé.

### 5.5 HMAC avec clé ou hachage nu : le point de sécurité décisif

| Approche | Rejouable par un attaquant | Corrélable | Verdict |
|---|---|---|---|
| **HMAC-SHA-256 avec clé secrète** | Non, tant que la clé reste secrète et robuste | Oui | **Recommandé** : pseudonymisation |
| SHA-256 sans clé | **Oui, par énumération** : l'espace IPv4 publique compte ≈ 4,3 milliards d'adresses, soit quelques minutes de calcul sur GPU pour construire une table exhaustive | Oui | À proscrire : ce n'est pas de la pseudonymisation, c'est une **anonymisation illusoire** |
| SHA-256 avec sel **global fixe** stocké en base | Oui, dès que la base fuite (le sel fuite avec elle) | Oui | Insuffisant : le secret doit être hors base |
| Sel aléatoire par événement | Non | **Non** : casse `group_by`, `dedup` et le seuillage | Inutilisable pour la détection |

!!! danger "Le message à retenir"
    Une IP est un identifiant à très faible entropie : masquer une IP par un hachage non salé revient
    à ne rien masquer. **La sécurité de la mesure tient entièrement au secret de la clé HMAC.** Une
    clé fuitée transforme instantanément toute votre base pseudonymisée en base d'adresses IP en
    clair.

Rappel de vocabulaire, car la nuance est juridiquement structurante : la pseudonymisation **reste
une donnée personnelle** (le responsable, qui détient la clé, peut réidentifier) ; seule
l'anonymisation irréversible sort du champ du RGPD — et un HMAC sur une IP n'est pas une
anonymisation.

### 5.6 Stockage de la clé et procédure de destruction

| Règle | Détail |
|---|---|
| **Hors base** | La clé ne doit jamais être stockée dans la base Thot Secure, ni dans un fichier de règles, ni dans un dépôt Git |
| **Distincte de `THOT_SECRET_KEY`** | Cette variable (§9) est le *pepper* des clés API et sert à la signature : elle a un autre cycle de vie et une autre portée. Utiliser la même valeur pour les deux usages est une erreur de conception |
| **Coffre de secrets** | Gestionnaire de secrets ou coffre (Vault, KMS, secret managé), avec accès restreint et journalisé |
| **Portée** | Une clé par tenant lorsque plusieurs responsables de traitement coexistent (mode MSSP) : la destruction devient alors sélective |
| **Rotation** | Nouvel identifiant de clé (`k2:…`), application aux données futures ; documenter la date de bascule, car la corrélation historique s'arrête à la rotation |
| **Sauvegardes** | Une clé sauvegardée « en clair » dans un export annule la mesure : chiffrer les sauvegardes et exclure la clé matérielle de la base |

**Procédure de destruction d'une clé de pseudonymisation** (crypto-effacement) :

1. **Décider et documenter** : motif, périmètre exact (quel `KEY_ID`, quels tenants concernés),
   validateurs (DPO/juriste pour un effacement au titre des droits), date.
2. **Mesurer l'impact** : après destruction, plus personne — y compris vous — ne peut réidentifier
   les enregistrements correspondants, ni répondre à une demande d'accès les concernant. La
   corrélation entre données antérieures et postérieures à la rotation est perdue.
3. **Retirer la clé** du coffre, puis de l'environnement d'exécution des collecteurs et des
   pipelines ; redémarrer les services concernés.
4. **Traquer les copies** : fichiers `.env`, scripts, historiques de shell, sauvegardes, exports
   SIEM, journaux de CI, tickets. Une copie oubliée suffit à rouvrir la faille.
5. **Consigner** : date, périmètre, opérateur ; inscrire la mesure au registre des traitements (§9).
6. **Basculer** sur une nouvelle clé (`KEY_ID` incrémenté) pour les données futures.

!!! warning "Ce que la destruction de clé ne fait pas"
    Les enregistrements pseudonymisés **restent en base**. Le crypto-effacement supprime
    l'attribuabilité, pas les lignes : la purge de rétention (§6) reste nécessaire.

### 5.7 Exploiter des données pseudonymisées

Exemple de requête d'analyse : repérer les sources les plus insistantes **sans jamais manipuler
d'IP en clair**.

```sql
-- Illustratif : les noms physiques de tables et de colonnes dépendent du schéma de stockage
-- (SQLite au MVP ; DDL PostgreSQL documenté). À vérifier contre ../architecture/data-model.md.
SELECT
  json_extract(labels, '$.src_ip_hash')   AS source_pseudonyme,
  json_extract(labels, '$.src_ip_prefix') AS reseau,
  COUNT(*)                                AS nb_evenements,
  MIN(ts)                                 AS premier_vu,
  MAX(ts)                                 AS dernier_vu
FROM events
WHERE tenant_id = :tenant_id          -- cloisonnement obligatoire (§1 invariant 4, §10)
  AND ts >= :depuis
GROUP BY source_pseudonyme, reseau
HAVING COUNT(*) >= :seuil             -- équivalent d'un threshold de règle (§5)
ORDER BY nb_evenements DESC
LIMIT 50;
```

Le résultat alimente une règle ou une politique sans jamais exposer d'adresse : la décision peut
cibler le pseudonyme ou le préfixe réseau. En revanche, un playbook de blocage
(`block-source-ip`, §7) a besoin d'une **vraie** IP côté connecteur : ce cas précis doit être
documenté comme un accès légitime au brut, restreint et journalisé — c'est le principal point de
tension entre détection pseudonymisée et contre-mesure.

## 6. Durée de conservation

`THOT_RETENTION_DAYS` (§9) vaut **30 jours** par défaut et son rôle est explicitement la
**purge des événements**. C'est le seul mécanisme de rétention décrit par le contrat ; toute autre
durée doit être organisée, justifiée et documentée par l'exploitant.

| Type de donnée | Durée recommandée | Mécanisme | Justification |
|---|---|---|---|
| Événements (`Event`) | 30 jours (défaut), ajustable de 7 à 90 jours | `THOT_RETENTION_DAYS` ; couvert par `tests/test_storage.py` (§11 : « purge rétention ») | Fenêtre utile à la détection et à l'investigation ; au-delà, le rapport valeur/risque se dégrade |
| Findings (`Finding`) et leurs `evidence` | Aligner sur la fenêtre d'investigation, puis archiver de façon minimisée | **Aucune purge automatique n'est décrite par le contrat** : à organiser par procédure | Conserver la trace d'un incident ne justifie pas de conserver indéfiniment des échantillons d'événements |
| Journal d'audit (`AuditRecord`) | Plus long que les événements — plusieurs mois à plusieurs années selon l'obligation applicable | Append-only, chaîné par hash (§3.5) ; **aucune purge décrite** | Traçabilité des accès et des actions, valeur probante, réponse aux demandes de droits |
| Sauvegardes | Durée identique ou légèrement supérieure aux données qu'elles contiennent | Politique de sauvegarde du client ; chiffrement | Une sauvegarde est une copie : elle hérite du risque et de l'obligation d'effacement |
| Exports SIEM (`format=jsonl\|cef`) | Fixée par le destinataire, contractualisée | Contrat de sous-traitance avec l'éditeur du SIEM | Un export sort du périmètre technique d'Thot Secure : c'est un nouveau traitement |
| Journaux applicatifs (`THOT_LOG_FORMAT=json`) | Court (jours) | `THOT_LOG_LEVEL`, rotation applicative | Peuvent contenir des URL, des acteurs ou des IP : à minimiser et à borner |

!!! danger "La durée doit être écrite, pas subie"
    Une durée de conservation non documentée est une non-conformité en soi : le principe de
    limitation de la conservation (art. 5.1.e) exige une durée **déterminée et justifiée**. La
    question « pourquoi 30 jours ? » doit avoir une réponse écrite dans le registre (§9), pas
    « c'est le défaut ».

!!! warning "Deux angles morts à traiter explicitement"
    **1. Le contrat ne prévoit aucune route de suppression d'événements ni d'entrées d'audit.** Il
    n'existe donc pas de « supprimer cet événement » dans l'API : la seule voie est la purge par
    rétention (pour les événements) ou une intervention directe sur le stockage, **hors contrat**,
    qui doit être documentée, justifiée, testée sur une copie et tracée par ailleurs.
    **2. Le nettoyage manuel des sauvegardes** ne se déduit pas de `THOT_RETENTION_DAYS` :
    vérifiez que vos sauvegardes n'immortalisent pas des données que la purge applicative a
    supprimées.

## 7. Droits des personnes

### 7.1 Le compromis honnête avec l'immutabilité de l'audit

Le §3.5 du contrat définit `AuditRecord` avec `prev_hash` et `hash`, où
`hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`.
Le journal est **append-only**, et `GET /api/v1/audit/verify` (§4.7) renvoie
`{"valid":…, "records":…, "broken_at":…}` : toute suppression ou modification d'une entrée **casse
la chaîne** et devient **détectable**.

| Position | Faisabilité | Ce qu'il faut dire |
|---|---|---|
| Supprimer une entrée d'audit pour honorer un droit à l'effacement | **Techniquement contradictoire** avec la finalité d'intégrité : la chaîne casse, `broken_at` désigne l'entrée manquante, et la suppression est **elle-même l'événement le plus visible** du journal | Position **défendable** : on ne supprime pas la chaîne |
| Ne pas écrire de données personnelles dans l'audit | **Faisable dès la conception** | `actor` est une clé API, `actor_role` un rôle, `target.id` un identifiant technique : l'audit contient donc **peu de données personnelles directes** — à condition de ne pas y écrire d'IP ni de nom d'utilisateur |
| Pseudonymiser **à la source** | **Faisable** (§5) | La donnée personnelle n'entre jamais dans le périmètre : c'est la mesure qui rend le compromis acceptable |
| Purger les **événements** | **Faisable** | `THOT_RETENTION_DAYS` (§6) |

!!! tip "L'argument à tenir devant un auditeur ou une autorité"
    La journalisation est **elle-même** une mesure de sécurité et une obligation pour de nombreux
    secteurs. Un journal d'audit chaîné dont on sait démontrer l'intégrité est une **garantie** au
    service des personnes. La stratégie cohérente est donc : **pseudonymiser à la source, minimiser
    ce qui entre dans l'audit, borner la rétention des événements** — et non amputer l'audit.

### 7.2 Droit par droit

| Droit | Faisabilité dans Thot Secure | Moyen | Limites |
|---|---|---|---|
| **Accès** (art. 15) | Partielle, indirecte | `GET /api/v1/events` (§4.3, filtres `q`, `since`, `until`) et `GET /api/v1/audit` (§4.7, filtres `actor`, `action`) ; export `GET /api/v1/audit/export?format=jsonl\|cef` pour l'extraction | **Aucune route ne recherche par personne** : il faut disposer du pseudonyme de la personne (donc de sa correspondance) pour retrouver ses données. Si la clé de pseudonymisation est détruite, l'accès rétroactif devient impossible — et c'est un choix à assumer |
| **Rectification** (art. 16) | Très limitée | `POST /api/v1/findings/{id}/close` avec `comment` (§4.4) permet de **documenter** une correction d'appréciation | Les événements sont **immuables** (§1) : on ne corrige pas un fait journalisé. La rectification porte sur les conclusions, pas sur la trace |
| **Effacement** (art. 17) | Non disponible comme opération produit | Purge par rétention pour les événements ; crypto-effacement (§5.6) pour l'attribuabilité | **Aucune route de suppression d'événements ni d'audit n'existe dans le contrat.** L'effacement d'une entrée d'audit casse la chaîne (§7.1). Toute suppression directe en base est hors contrat, à documenter et à justifier |
| **Limitation** (art. 18) | Partielle, procédurale | Restreindre la collecte (configurer le collecteur), restreindre les accès (`read:*`), documenter l'exclusion | Aucune fonction produit de « mise en quarantaine » d'une personne. Attention à ne pas confondre avec `POST /findings/{id}/suppress` (§8) |
| **Opposition** (art. 21) | À instruire au cas par cas | Analyse écrite : la sécurité du SI peut constituer un motif légitime impérieux | Un refus doit être motivé par écrit et communiqué au demandeur |
| **Portabilité** (art. 20) | Peu pertinente ici | Export `jsonl` | Base légale fondée sur l'intérêt légitime : la portabilité ne s'applique en principe pas |

!!! warning "Export SIEM : un export est une copie"
    `GET /api/v1/audit/export?format=jsonl|cef` (§4.7) produit un flux téléchargeable destiné à un
    SIEM/SOAR. Chaque export crée une **nouvelle copie de données personnelles** chez un nouveau
    destinataire : celui-ci devient un acteur à encadrer (contrat de sous-traitance ou de
    communication, durée de conservation, sécurité, localisation). Un export non tracé est une fuite
    en puissance — et l'export lui-même suppose la capacité `read:audit`.

## 8. Suppression et limitation côté métier : ne pas confondre

Deux routes §4.4 sont souvent prises l'une pour l'autre. Elles n'ont **rien à voir** avec l'effacement
des données personnelles.

| Route | Ce que fait réellement le produit | Ce que ce n'est **pas** |
|---|---|---|
| `POST /api/v1/findings/{id}/suppress` avec `{"duration_seconds":86400,"reason":"…"}` | Crée une **exception sur la règle** : la détection est mise au silence pour cette règle pendant la durée demandée | **Ce n'est pas un effacement RGPD**, ni une limitation au sens de l'art. 18, ni une anonymisation. Les événements déjà collectés restent en base ; ils seront simplement moins sollicités par les alertes |
| `POST /api/v1/findings/{id}/close` avec `{"resolution":"true_positive\|false_positive\|mitigated","comment":"…"}` | Clôt un finding et **documente le traitement** retenu | Ce n'est pas une suppression : c'est au contraire une **preuve de traitement**, souvent précieuse (diligence, proportionnalité, qualité de détection) |

!!! danger "Le piège à éviter absolument"
    Utiliser `suppress` en réponse à une demande de droit aboutit à **deux échecs** : le demandeur
    n'obtient pas l'effet recherché (les données restent), et vous ajoutez une **zone d'aveuglement
    de détection** — un attaquant qui obtient une suppression de règle se protège gratuitement.
    Toute suppression doit être **motivée**, **limitée dans le temps** et **revue** ; elle est
    visible dans l'audit et doit être traitée comme un changement de sécurité, pas comme une
    formalité de conformité.

En pratique, écrivez dans votre procédure : « une demande d'effacement n'est **jamais** traitée par
`/findings/{id}/suppress` », et documentez la voie réellement retenue (purge de rétention,
crypto-effacement, ou refus motivé).

## 9. Registre des traitements : fiche pré-remplie

Modèle à recopier dans votre registre (art. 30). **À adapter** : les éléments entre crochets sont des
choix qui vous appartiennent.

| Rubrique | Contenu pour un déploiement Thot Secure |
|---|---|
| Nom du traitement | Détection et réponse aux incidents de sécurité — plateforme Thot Secure v0.1.0 |
| Responsable de traitement | [Entité], [adresse], représentant : [nom], DPO : [contact] |
| Finalités | Collecte et normalisation d'événements de sécurité ; détection par règles ; scoring de risque ; décision *policy-as-code* ; contre-mesure réversible ; journalisation d'audit ; production de rapports |
| Base légale | Intérêt légitime (art. 6.1.f) — analyse documentée (§2.1). [Compléter : obligation légale sectorielle le cas échéant.] [MSSP : traitement pour le compte du client sur instructions documentées.] |
| Catégories de personnes | Utilisateurs internes, visiteurs et clients exposés sur Internet, administrateurs, **tiers identifiés par leur IP** (dont attaquants) |
| Catégories de données | Adresse IP source (pseudonymisée), préfixe réseau, horodatage, chemin d'URL, méthode HTTP, `user_agent`, extraits de `payload` (≤ 32 Kio, tronqués au-delà), identifiants d'hôte, clés API et rôles dans l'audit, libellés de clés |
| Destinataires internes | Rôles `viewer`, `analyst`, `responder`, `admin` (§4), strictement nécessaires |
| Destinataires externes | [SIEM/SOAR via export `jsonl`/`cef`], [hébergeur], [MSSP], [CERT/CSIRT], [ticketing] |
| Transferts hors UE | [À documenter : hébergeur, SIEM, support.] Le logiciel n'en effectue aucun par lui-même (§11) |
| Durées de conservation | Événements : `THOT_RETENTION_DAYS` = [valeur] jours. Findings : [durée] ([procédure]). Audit : [durée]. Sauvegardes : [durée]. Exports : [durée fixée par le destinataire] |
| Mesures de sécurité | RBAC de moindre privilège, isolation multi-tenant (`tenant_id`, testée en CI), clés API hachées (scrypt), TLS en transit et disque chiffré au repos, audit append-only chaîné par hash + vérification, `dry_run` activé par défaut, allowlist de cibles, plafond d'actions horaire et cooldown, pseudonymisation des IP (HMAC-SHA-256), rétention bornée, cloisonnement des environnements |
| Source des données | Collecteurs défensifs (surface déclarée par le tenant), journaux applicatifs et système exposés par l'exploitant, collecte de dépendances et d'audit de configuration |
| Mesures de minimisation | [Pseudonymisation activée : oui/non], [masquage des secrets au collecteur], [restriction des `payload`], [libellés de clés fonctionnels] |
| Analyse d'impact | [DPIA réalisée : oui/non/date — voir §12] |
| Registre des violations | [Référence du registre — voir §13] |

## 10. Sous-traitance et chaîne contractuelle

Dès qu'un **MSSP** héberge Thot Secure pour ses clients, la répartition est la suivante : le client
reste **responsable de traitement**, le MSSP devient **sous-traitant** (art. 28), et l'éditeur du
logiciel n'est **ni l'un ni l'autre** puisqu'il n'héberge rien (à confirmer selon le modèle de
distribution).

| Obligation du sous-traitant (art. 28) | Ce que cela implique concrètement pour un MSSP |
|---|---|
| Agir sur **instructions documentées** | Contrat + annexe : finalités autorisées, périmètre de tenants, interdiction d'usage pour un autre client |
| **Confidentialité** | Engagement des personnels, moindre privilège sur les clés (`admin` restreint), pas de consultation hors incident |
| **Sécurité** | Mesures de l'art. 32 : contrôle d'accès, chiffrement, journalisation, résilience, tests |
| **Assistance** | Aider le client à répondre aux droits et aux analyses d'impact ; lui fournir les exports nécessaires |
| **Notification** | Notifier le client « sans délai » après avoir pris connaissance d'une violation (§13) |
| **Sort des données** | Restitution et/ou suppression en fin de contrat, y compris sauvegardes et exports SIEM |
| **Audit** | Droit d'audit du client (ou du mandataire) et obligation de coopération |
| **Sous-traitants ultérieurs** | Autorisation, information préalable, mêmes obligations imposées par écrit |

| Sous-traitant ultérieur possible | Ce qu'il faut contractualiser |
|---|---|
| Hébergeur (IaaS) | Localisation, chiffrement, isolation, sécurité physique, notification d'incident, sous-traitants ultérieurs |
| CDN / réverse-proxy / WAF en amont | Journaux d'accès contenant des IP : durée, minimisation, suppression à la fin du contrat |
| Fournisseur de messagerie / webhook | Contenu des notifications : minimiser (pas d'IP en clair, pas de `payload`) |
| Éditeur du SIEM/SOAR destinataire | Copie des données exportées : durée, sécurité, localisation, sort des données |
| Éditeur de la distribution logicielle / support | Absence d'accès aux données par défaut ; si un accès est ouvert pour le support, l'encadrer, le tracer et le borner dans le temps |

!!! note "Un point de vigilance propre à la console embarquée"
    La console (`GET /`, §4.9) et la page `/ui/support` affichent des données de sécurité dans un
    navigateur. Ce poste de travail est un **destinataire de fait** : session de navigateur, cache,
    captures d'écran, extensions. Intégrez-le à votre analyse de risque.

## 11. Transferts hors UE

**Le logiciel n'effectue par lui-même aucun transfert** : auto-hébergé, il écrit dans votre base, et
aucune télémétrie n'est décrite par le contrat. Les transferts éventuels proviennent
**exclusivement** de l'exploitant et de ses choix d'infrastructure ou de sous-traitance.

| Scénario de transfert | Risque | Garantie à prévoir |
|---|---|---|
| Hébergement de l'instance hors UE | Accès gouvernemental étranger, droit local contraire | Choisir une région UE ; décision d'adéquation, clauses contractuelles types (CCT), analyse du transfert |
| Région UE, mais **support** de l'hébergeur hors UE | Accès à distance depuis un pays tiers | Accès juste-à-temps tracé, CCT, chiffrement des volumes, aucune donnée en clair |
| SIEM/SOAR destinataire des exports hors UE | Copie hors UE de données de sécurité | Réduire le contenu exporté, pseudonymiser avant export, CCT + analyse |
| Support éditeur hors UE avec accès à l'instance | Accès direct à des données personnelles | Éviter l'accès par défaut ; si nécessaire, accès temporaire encadré et journalisé, CCT |
| Sauvegarde répliquée hors UE | Copie oubliée dans les analyses et les demandes d'effacement | Inventorier les emplacements de sauvegarde ; chiffrement ; documenter la localisation |
| Outil de ticketing ou de notification hors UE | Contenu des alertes (IP, chemins, extraits) exporté | Minimiser le contenu des notifications, CCT, information des personnes |

!!! tip "Bonne pratique de conception"
    Pseudonymiser **avant** l'export est la garantie la plus simple et la plus robuste contre les
    transferts non maîtrisés : un SIEM qui ne reçoit que des pseudonymes et des préfixes réseau
    devient un risque nettement plus faible.

## 12. Analyse d'impact (AIPD / DPIA)

Une analyse d'impact est **recommandée** — et souvent requise — pour un déploiement à grande échelle
ou pour un MSSP, dès lors que plusieurs critères de déclenchement sont réunis.

| Critère de déclenchement | Application à Thot Secure |
|---|---|
| Surveillance systématique | Oui : collecte continue, y compris de flux réseau ou applicatifs |
| Traitement à grande échelle | À évaluer : nombre de personnes concernées (visiteurs et utilisateurs exposés), volume d'événements, nombre de tenants |
| Croisement de données | Oui : corrélation événements ↔ findings ↔ audit, et croisement possible avec d'autres journaux de l'organisation |
| Personnes vulnérables | À évaluer selon l'activité (mineurs, patients, usagers de services essentiels) |
| Données sensibles | Variable : un `payload` peut contenir des données de santé ou de connexion |
| Décision automatisée / contre-mesure | Oui, partiellement : une politique `auto` peut déclencher un blocage — atténué par la réversibilité (§1 invariant 3) et le `dry_run` par défaut |
| Usage innovant / nouvelle technologie | À évaluer — l'exigence d'un avis préalable n'est pas automatique |

### 12.1 Trame de DPIA spécifique Thot Secure

**1. Description du traitement** — finalités (§2), flux de données (collecteurs → `POST /api/v1/events`
§4.3 → base → règles → findings → politiques → actions), périmètre de tenants, catégories de données
(§3), destinataires, durées (§6), infrastructure d'hébergement.

**2. Nécessité et proportionnalité** — la pseudonymisation des IP est-elle activée (§5) ? Les
`payload` sont-ils bornés au strict nécessaire ? Les règles ont-elles une clause de faux positifs
documentée (§5, `false_positives`) ? Existe-t-il un moyen moins intrusif d'atteindre la finalité ?
La durée de rétention est-elle justifiée (§6) ?

**3. Risques pour les personnes**

| Risque | Manifestation concrète | Mesure d'atténuation |
|---|---|---|
| Surveillance indue | Suivi de navigation d'un salarié ou d'un usager via ses IP et chemins d'URL | Pseudonymisation, finalité écrite, interdiction d'usage disciplinaire, rétention courte |
| Réidentification | Croisement d'une IP pseudonymisée avec un annuaire ou un journal d'accès | HMAC avec clé hors base, pas d'IP en clair dans l'audit ni les exports, préfixe réseau seul quand c'est suffisant |
| Excès de collecte | Ingestion de `payload` complets, de corps de requêtes, de `raw_ref` vers des données riches | Filtrage au collecteur, masquage des secrets, revue périodique des flux collectés |
| Accès interne abusif | Clé `admin` partagée, consultation de données d'un autre tenant, export non tracé | RBAC de moindre privilège (§4), une clé par usage, isolation `tenant_id` testée en CI, audit chaîné de chaque appel |
| Non-pertinence | Alertes sur des personnes sans lien avec une menace | Revue des règles, `false_positives`, clôture documentée (`resolution`) |
| Conservation excessive | Sauvegardes et exports éternels | Purge `THOT_RETENTION_DAYS`, inventaire des sauvegardes, contrat sur les exports |
| Effet du blocage légitime | Une contre-mesure automatique bloque un utilisateur ou un client | `dry_run=true` par défaut, `require_approval`, allowlist de cibles protégées, plafond d'actions horaire, rollback obligatoire |

**4. Mesures et suivi** — pseudonymisation (§5), RBAC et isolation (§4), audit chaîné et
`GET /api/v1/audit/verify` (§4.7), rétention bornée (§6), minimisation (§4), journalisation des accès
et **revue périodique des accès** (liste des clés d'un tenant avec `last_used_at` et `revoked_at`,
§4.2), procédure de violation (§13), test de restauration, revue annuelle de la DPIA et de l'analyse
d'intérêt légitime.

## 13. Violation de données

| Étape | Contenu | Délai |
|---|---|---|
| Détecter | Signalement interne, alerte de sécurité, anomalie d'audit (voir ci-dessous), notification d'un sous-traitant | Immédiat |
| Contenir | Révoquer les clés compromises (`DELETE /api/v1/keys/{key_id}` → `204`, §4.2), couper un accès, isoler l'instance | Immédiat |
| Qualifier | Nature (confidentialité, intégrité, disponibilité), catégories et volume de personnes, gravité, probabilité de risque | < 24 h |
| Notifier l'autorité | Registre de traitement + notification à l'autorité de contrôle | **72 h** après la connaissance de la violation (art. 33) |
| Informer les personnes | Si risque élevé : communication claire et compréhensible | « Sans délai raisonnable » (art. 34) |
| Notifier les clients | En mode MSSP : chaque client est responsable de traitement et doit pouvoir notifier **ses** autorités et **ses** personnes | Selon le contrat |
| Consigner | Nature, effets, mesures prises, décisions et justifications — **même pour une violation non notifiée** | Immédiat et permanent |

!!! danger "Cas particulier : corruption ou falsification de l'audit"
    Une chaîne d'audit cassée est un incident **grave et spécifique** : `GET /api/v1/audit/verify`
    renvoie `"valid": false` avec l'entrée fautive dans `broken_at`, et la CLI `thotsecure audit verify`
    sort avec le code `3` (§8 : « vérification négative (ex. audit corrompu) »). Cela peut signaler
    une suppression, une altération, une perte de données ou un conflit de séquence : la confiance
    dans la traçabilité est atteinte, ce qui dégrade aussi la capacité à démontrer la conformité.
    Déclenchez la procédure d'incident et suivez
    [`../operations/runbook.md`](../operations/runbook.md). Vérifiez également `GET /api/v1/audit/verify`
    de manière **planifiée**, car une chaîne cassée non détectée ne se répare pas toute seule.

!!! tip "Réflexe de preuve"
    Avant toute correction, **préservez** l'état : export `jsonl` de l'audit, copies des journaux
    applicatifs, horodatage, sortie exacte de `verify`. C'est ce qui permet ensuite d'expliquer
    l'incident — et c'est aussi ce que produira un auditeur.

## 14. Checklist RGPD de déploiement

- [ ] Durée de conservation **définie et justifiée** par écrit, `THOT_RETENTION_DAYS` positionné en conséquence (défaut 30 jours).
- [ ] **Pseudonymisation** de `labels.src_ip` implémentée au collecteur ou au proxy d'ingestion (§5), avec clé HMAC stockée **hors base** et distincte de `THOT_SECRET_KEY`.
- [ ] Minimisation amont : masquage des secrets, restriction des `payload`, refus des `raw_ref` inutiles.
- [ ] **RBAC minimal** : aucun collecteur avec une clé `admin` ; une clé par usage et par rôle (§4).
- [ ] `THOT_BOOTSTRAP_API_KEY` changée, `THOT_ENV=prod`, `THOT_DRY_RUN` laissé à `true` tant que les politiques ne sont pas validées.
- [ ] Accès **revus** : inventaire des clés par tenant (`last_used_at`, `revoked_at`), révocation des clés dormantes, revue périodique planifiée.
- [ ] Isolation vérifiée : un test de non-fuite entre deux tenants au moins une fois par version.
- [ ] **Registre des traitements** complété (§9) et analyse d'intérêt légitime documentée (§2.1).
- [ ] **DPIA** réalisée si MSSP ou déploiement à grande échelle (§12).
- [ ] Mention d'information des personnes concernées (note interne, charte, information des représentants du personnel le cas échéant).
- [ ] Procédure de **violation** écrite, avec registre des violations et canal de signalement interne (§13).
- [ ] Encadrement des **exports SIEM** : destinataires listés, contrats, durées, contenu minimisé.
- [ ] Contrats de sous-traitance en place (hébergeur, MSSP, SIEM, messagerie) et inventaire des transferts hors UE (§10, §11).
- [ ] **Test de restauration** effectué et daté (une sauvegarde jamais restaurée n'est pas une sauvegarde).
- [ ] Vérification planifiée de l'audit : `GET /api/v1/audit/verify` (ou `thotsecure audit verify`).
- [ ] Procédure écrite interdisant d'utiliser `POST /findings/{id}/suppress` en réponse à une demande de droits (§8).

## 15. Ce qu'Thot Secure ne fait pas

| Attendu parfois prêté au produit | Réalité du MVP |
|---|---|
| Anonymisation automatique des données personnelles | **Non.** Aucune fonction d'anonymisation n'est décrite ; la pseudonymisation est à implémenter par l'exploitant (§5) |
| Module de gestion des consentements | **Non.** Aucune fonction de recueil, de preuve ou de retrait de consentement n'existe dans le contrat |
| Portail ou API de droits des personnes | **Non.** Il n'existe **aucune route de recherche par personne**, ni d'effacement, ni de rectification d'événement (§7) |
| Suppression d'événements ou d'entrées d'audit | **Non, et c'est un choix assumé.** Le contrat ne prévoit **aucune** route de suppression d'événements ni d'audit ; l'audit est append-only et chaîné (§3.5, §7.1). Toute suppression relève d'une intervention hors contrat, documentée et justifiée |
| Classification ou étiquetage RGPD des champs | **Non.** Aucun champ `pseudonymized_at`, aucune étiquette de sensibilité n'existe : le §3 ne définit que la structure des événements, findings et enregistrements d'audit |
| Rapport de conformité RGPD prêt à signer | **Non.** Les rapports du produit (`md`, `html`, `json`, `sarif`, §4.8) sont des artefacts **techniques** sur un finding, pas des attestations de conformité |
| Journalisation d'audit avec IP ou nom d'utilisateur | **Non.** `AuditRecord` (§3.5) porte `actor` (clé API) et `actor_role` : c'est une minimisation native, à préserver en n'y ajoutant pas de données personnelles |

!!! info "Roadmap"
    Les fonctions qui combleraient ces manques — aide native à la pseudonymisation, inventaire
    d'exposition des données personnelles dans les flux collectés, purge assistée des findings —
    relèvent de la feuille de route produit. Voir [`../roadmap.md`](../roadmap.md). En l'état, elles
    sont **à la charge de l'exploitant**.

## Pour aller plus loin

- Contrat d'interface (source de vérité) : [`../architecture/api-contract.md`](../architecture/api-contract.md)
- Modèle de données et cycle de vie : [`../architecture/data-model.md`](../architecture/data-model.md)
- Modèle de menace : [`../architecture/threat-model.md`](../architecture/threat-model.md)
- Configuration et variables `THOT_*` : [`../configuration.md`](../configuration.md)
- Déploiement et exploitation : [`../operations/deployment.md`](../operations/deployment.md), [`../operations/runbook.md`](../operations/runbook.md)
- Correspondance SOC 2 / ISO 27001 : [`soc2-iso27001.md`](soc2-iso27001.md)
- Feuille de route : [`../roadmap.md`](../roadmap.md) — Glossaire : [`../glossary.md`](../glossary.md)

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
