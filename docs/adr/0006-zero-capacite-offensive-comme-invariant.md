# ADR-0006 — Zéro capacité offensive comme invariant

*Thot Secure ne comporte et ne comportera aucune capacité offensive : pas de scan agressif, pas de
brute force, pas de hack-back, pas de déni de service, pas d'exploitation de tiers — et cet
invariant est structurel, garanti par l'absence d'API, pas seulement par une déclaration
d'intention.*

**Statut :** Accepté
**Date :** 2026-09-13
**Version du contrat :** 0.1.0 (MVP)
**Décideurs :** mainteneurs Thot Secure
**Remplace :** —
**Remplacé par :** —

---

## Statut

**Accepté comme invariant non négociable.** Le §10 du contrat d'interface
([`../architecture/api-contract.md`](../architecture/api-contract.md)) énonce déjà « **Zéro capacité
offensive** : aucun code de scan agressif/exploitation ; `probe` n'audite que des cibles déclarées
possédées par le tenant ». Cette ADR documente le raisonnement, les conséquences assumées et le
mécanisme de préservation. Sa révocation exigerait une nouvelle ADR remplaçant celle-ci et une
modification du contrat — c'est-à-dire un changement de nature du projet, pas une évolution de
fonctionnalité.

---

## Contexte

La frontière entre défense et attaque ne se franchit presque jamais d'un coup : elle se franchit par
**accumulation de fonctionnalités raisonnables prises une à une**. Les demandes arrivent
habituellement sous cette forme :

* « L'IP nous attaque : et si on la **scannait** pour savoir à qui on a affaire ? »
* « Elle est hébergée chez un fournisseur connu : et si on **bloquait tout le range** de
  l'hébergeur ? »
* « Elle tente des connexions : et si on **testait ses identifiants** pour voir si c'est un
  serveur compromis ? »
* « Le site attaquant est en ligne : et si on le **neutralisait** le temps de l'incident ? »

Chacune prise isolément semble défendable — et c'est précisément le danger. Thot Secure dispose par
construction de capacités d'action puissantes : il bloque des sources au niveau de WAF et de
pare-feu (`block-source-ip`), met en quarantaine des artefacts, révoque des sessions, rotationne des
secrets, isole des hôtes, ouvre des PR et applique des profils de durcissement (§7). Ces primitives
sont **exactement** celles qu'un attaquant chercherait à détourner : un Thot Secure compromis est un
outil d'action à distance sur l'infrastructure de ses utilisateurs.

Trois contraintes rendent la réponse claire :

1. **Le cadre légal.** L'accès ou le maintien frauduleux dans un système de traitement automatisé de
   données d'autrui, l'atteinte à un tel système, l'extraction ou la modification de données sans
   autorisation sont pénalement sanctionnés dans la plupart des juridictions. Un scan agressif, une
   tentative d'authentification ou un blocage visant un tiers sont des actes d'attaque, quelle que
   soit l'intention défensive de celui qui les déclenche. Y ajouter l'usage de données personnelles
   issues de ces actions aggrave le problème au regard du RGPD.
2. **L'usage chez un client.** Thot Secure est conçu pour être exploité par un tiers — un MSSP qui
   opère pour le compte de plusieurs clients. Le fournisseur de sécurité n'a évidemment pas
   l'autorisation du système qui attaque son client. Toute capacité offensive rendrait le produit
   inutilisable par un prestataire sérieux, et engagerait **sa** responsabilité, pas seulement
   celle de l'éditeur.
3. **La crédibilité.** Un RSSI qui installe un SOAR doit savoir exactement ce que l'outil peut faire
   et ne peut pas faire. « Nous n'avons pas de fonction offensive » est un engagement vérifiable —
   il se contrôle en lisant le code et la surface d'API. Un engagement vérifiable vaut infiniment
   plus qu'une promesse de modération.

---

## Décision

**Aucune capacité offensive**, sans exception ni option d'activation : pas de scan agressif, pas de
brute force, pas de hack-back, pas de déni de service, pas d'exploitation de tiers (§10).

### Périmètre des actions autorisées

| Autorisé | Interdit |
|---|---|
| Auditer **sa propre** surface exposée : `thotsecure probe --tenant acme --target https://shop.acme.fr` (§8) | Scanner, sonder ou énumérer un système tiers |
| Lire des logs, des configurations, des certificats, des dépendances | Tester des identifiants, des mots de passe ou des sessions |
| Bloquer, limiter, isoler, révoquer, quarantainer **dans son propre périmètre** | Bloquer, dégrader ou saturer une ressource d'un tiers (hack-back, DoS, tarpit) |
| Ouvrir un ticket, notifier, ouvrir une PR de correctif (`patch-dependency`, sans merge auto) | Exploiter une vulnérabilité, même « pour vérifier » |
| Refuser, journaliser, escalader vers un humain | Toute action dont la cible n'est pas déclarée comme possédée par le tenant |

### Cibles : opt-in explicite et périmètre déclaré

* Le collecteur `probe` **n'audite que des cibles déclarées possédées par le tenant**. La
  déclaration est un **opt-in explicite** dans `config/targets.yaml`, dont l'emplacement est
  configurable par `THOT_TARGETS_FILE` (§9). Aucune cible n'est auditée par défaut.
* Trigger d'un run manuel : `POST /api/v1/collectors/{name}/run` — « Déclenche un run manuel **sur
  les cibles déclarées du tenant** » (§4.8). Le périmètre est donc une propriété de la requête, du
  tenant et du fichier de cibles, pas une saisie libre.
* **Toute cible hors périmètre déclaré du tenant → `require_approval`** (garde-fou 5, §6) : jamais
  d'action silencieuse hors périmètre.
* **Jamais d'action sur une cible de l'`autonomy_allowlist` protégée** (garde-fou 3, §6), qui
  désigne l'infrastructure propre : le produit ne doit pas se couper lui-même ni couper
  l'infrastructure de son utilisateur. Testé par `tests/test_decision.py` (§11, « cibles
  protégées »).
* Un mode `auto` explicitement activé au niveau du tenant ne lève **aucune** de ces limites : le
  périmètre déclaré et la liste des cibles protégées restent des bornes dures, non contournables par
  une politique.

### Aucune exécution de code arbitraire

Le moteur de décision et le moteur de règles n'exécutent pas de code fourni par l'utilisateur :

* **pas d'`eval` de template utilisateur** (§10) — les playbooks utilisent une substitution de
  variables bornée (`${params.target}`, `${params.duration_seconds}`, §7), pas un langage de
  programmation ;
* **regex de règle compilées avec timeout d'exécution** (§10), pour qu'une expression
  pathologique ne bloque pas le pipeline de détection (et ne devienne pas un déni de service
  interne) ;
* **pas de plugin exécutable arbitraire** dans le format de règle : les opérateurs supportés sont
  énumérés (§5 : `eq, ne, gt, gte, lt, lte, in, not_in, contains, icontains, startswith, endswith,
  regex, exists, cidr, len_gt, len_lt`).

### L'invariant est structurel, pas déclaratif

La distinction est essentielle : il n'existe **pas d'API pour attaquer**. Ni endpoint, ni commande
CLI, ni option de playbook ne prend en paramètre une cible hostile avec une intention offensive. Il
n'y a donc rien à désactiver, aucun drapeau à mal configureer, aucune politique à rédiger
soigneusement pour éviter le pire. La capacité offensive n'est pas désactivée par défaut : elle
**n'est pas implémentée**. C'est une garantie qu'aucun utilisateur, aucune erreur de configuration
et aucune compromission de la console ne peut transformer en capacité d'attaque.

!!! note "Ce que garantit l'absence d'API, et ce qu'elle ne garantit pas"
    L'absence d'API garantit qu'Thot Secure ne peut pas être **configuré** pour attaquer un tiers. Elle
    ne garantit pas l'absence de dommage : une compromission d'Thot Secure donne à l'attaquant un
    pouvoir d'action sur **ses propres cibles déclarées** (blocage, isolation, révocation de
    sessions). Ce n'est pas un botnet, mais l'impact reste réel et doit être traité par le modèle de
    menaces : voir [`../architecture/threat-model.md`](../architecture/threat-model.md).

---

## Conséquences

### Positives

* **Utilisable sans risque juridique.** Aucune autorisation préalable n'est nécessaire auprès du
  fournisseur de la cible ou de l'hébergeur du système attaquant, puisqu'aucune action n'est menée
  contre un tiers. C'est la condition pour qu'un RSSI, un juriste ou un acheteur public valide le
  déploiement sans réserve.
* **Jamais un vecteur d'attaque en cas de compromission.** Un Thot Secure compromis ne devient pas un
  botnet ni un outil de riposte : il agit, au pire, sur les cibles que son propre utilisateur a
  déclarées. L'impact reste réel — blocage de ses propres services, isolation de ses propres hôtes —
  mais il reste borné au périmètre du tenant et ne fait de victime tierce.
* **Discours clair et vérifiable.** « Thot Secure n'attaque personne » se vérifie dans le code, dans la
  surface d'API et dans les tests. C'est un argument de confiance qui ne repose pas sur la bonne
  volonté des mainteneurs.
* **Compatible avec l'audit et l'appel d'offres public.** Les clauses d'exclusion de responsabilité
  pénale, les exigences de conformité et les cahiers des charges publics se satisfont d'un produit
  dont le périmètre d'action est borné par construction, et non d'un produit dont on promet qu'il
  sera utilisé correctement.
* **Adoption facilitée chez un MSSP.** Un prestataire peut déployer Thot Secure chez plusieurs clients
  sans craindre qu'une action déclenchée chez l'un atteigne un système de l'autre, ou un tiers
  commun. Le périmètre déclaré par tenant matérialise cette frontière.
* **Périmètre testable.** La combinaison cibles déclarées + `autonomy_allowlist` + garde-fou 5 est
  vérifiable automatiquement (`tests/test_decision.py`, §11) : l'invariant n'est pas seulement
  affiché, il est testé sur le comportement le plus sensible.

### Négatives

* **Capacités de vérification limitées.** C'est la conséquence la plus lourde : Thot Secure **ne peut
  pas valider lui-même une exposition par test actif**. Il ne dira pas « cette injection est
  effectivement exploitable » ni « ce port est réellement ouvert depuis Internet ». Il faut un
  scanner tiers légitime ou une validation manuelle. C'est une **limite fonctionnelle réelle**, pas
  un détail de positionnement : sur ce terrain, le produit est moins utile qu'un scanner
  authentifié.
* **Couverture plus faible qu'un scanner de vulnérabilités authentifié.** Le volet CSPM d'Thot Secure
  s'appuie sur les collecteurs `config.audit` et `dependency` (§5, `kinds`, `source_types`) :
  analyse de configuration et de dépendances, pas exploitation. Un scanner authentifié corrèle
  versions, configurations et exploits connus, et détecte des failles qu'une lecture de
  configuration ne voit pas. La couverture est donc structurellement partielle.
* **Dépendance à la qualité des collecteurs.** Puisqu'il n'y a pas de validation active, tout repose
  sur ce qui est collecté : `config.audit`, `dependency`, journaux (`log.line`, `syslog`), sondes
  HTTP. Un collecteur mal configuré, un flux de logs incomplet ou une source absente produit un
  angle mort **silencieux** — l'absence de finding n'est pas une preuve d'absence de problème.
* **Pression de la communauté.** Les demandes de fonctionnalités offensives reviendront : elles
  paraissent utiles, elles sont techniquement intéressantes, et d'autres projets les proposent. Y
  résister durablement demande un effort de pédagogie à chaque fois, et une position écrite (cette
  ADR) pour ne pas ré-arbitrer de mémoire.
* **Tentation de « ceinture et bretelles ».** Des utilisateurs brancheront de toute façon un scanner
  agressif à côté d'Thot Secure. Notre refus est un **choix assumé, pas une garantie sur
  l'écosystème** : nous ne contrôlons pas ce qui est exécuté autour du produit, et nous ne
  prétendons pas que l'utilisateur est protégé de ses propres outils.
* **Attentes déçues à l'évaluation.** Un évaluateur qui cherche un outil « tout-en-un » conclura que
  le produit est incomplet : la limite est réelle, et le positionnement doit être explicite dès la
  documentation d'entrée plutôt que découvert en cours de pilote.

### Mécanisme de préservation de l'invariant

Un invariant qui n'est pas défendu activement disparaît par petites touches. Les mesures suivantes
sont donc **partie intégrante de la décision** :

| Mesure | Contenu |
|---|---|
| **Revue obligatoire** | Toute pull request touchant `src/thotsecure/collectors/` ou `src/thotsecure/actions/` exige une revue renforcée par les mainteneurs : ce sont les deux points par lesquels une capacité offensive entrerait dans le produit. |
| **Refus par défaut** | Toute contribution offensive est refusée par défaut. La charge de la preuve pèse sur la contribution, jamais sur le mainteneur qui refuse. |
| **Documentation explicite** | L'invariant est énoncé dans [`../governance.md`](../governance.md), dans `CONTRIBUTING.md` à la racine du dépôt et dans le `README.md`. Un contributeur ne peut pas l'ignorer de bonne foi. |
| **Tests de non-régression** | `tests/test_decision.py` (§11) vérifie le comportement sur les cibles protégées : jamais d'action automatique sur une cible de l'`autonomy_allowlist`, et `require_approval` pour toute cible hors périmètre déclaré (garde-fous 3 et 5, §6). |
| **Absence d'API** | L'invariant est **structurel** : il n'existe pas d'interface permettant d'attaquer, seulement des interfaces d'audit, de décision et de contre-mesure réversible dans le périmètre déclaré. |
| **Cohérence du discours public** | Aucune publication, aucun article, aucune page marketing ne doit suggérer une capacité offensive, y compris par formulation ambiguë (« testez vos adversaires »). |

!!! warning "Ne pas confondre avec une garantie de sécurité"
    Cette ADR traite de ce que **Thot Secure** ne fait pas. Elle ne dit rien de la sécurité du
    déploiement, des clés API, de la journalisation ou de la compromission de l'instance. Ces sujets
    sont couverts par le §10 du contrat, par [`../architecture/threat-model.md`](../architecture/threat-model.md)
    et par les autres ADR.

!!! info "Roadmap"
    Au-delà du MVP v0.1.0 : publication d'une page dédiée « périmètre d'action » dans la
    documentation (ce que le produit fait, ce qu'il ne fera jamais, comment le vérifier),
    test automatisé refusant toute nouvelle route ou commande dont la sémantique est offensive, et
    renvois documentés vers des outils légitimes pour les besoins de validation active — le projet
    oriente vers des outils spécialisés plutôt que d'en intégrer.

---

## Alternatives envisagées

| Alternative | Ce qu'elle apportait | Raison du rejet |
|---|---|---|
| **Scanner actif intégré, en opt-in explicite** | Validation réelle des expositions : ports ouverts, services vulnérables, injections exploitables. Comble la principale faiblesse fonctionnelle du produit. | Rejeté, **même en opt-in**. Un scanner agressif peut provoquer un **déni de service** chez la cible (bannières mal formées, charge excessive, services fragiles) ; l'opt-in ne protège que celui qui coche la case, pas le système scanné. Il engage la responsabilité de l'utilisateur — et, en pratique, celle de l'éditeur qui a fourni l'outil et l'a présenté comme légitime. Un utilisateur qui déclare à tort une cible comme sienne transforme Thot Secure en instrument d'attaque, et la déclaration sur l'honneur n'est pas un contrôle. Le projet **renvoie vers des outils spécialisés et légitimes** plutôt que d'intégrer la capacité. |
| **Hack-back automatisé** (riposte automatique contre la source) | Dissuasion immédiate, récit séduisant, sentiment de réciprocité. | Rejeté sans réserve : **illégal dans de nombreux cadres** (accès et atteinte à un STAD d'autrui), **escalade du conflit** (riposter à une source usurpée revient à attaquer une victime), **risque d'attaquer un intermédiaire** — l'adresse source est souvent un proxy, un relais de messagerie, un résolveur DNS ouvert ou un équipement compromis qui n'est pas l'attaquant. Enfin, c'est **contraire à l'éthique** d'un projet défensif et incompatible avec l'usage chez un MSSP opérant pour des clients qui n'ont rien demandé. |
| **Tests d'intrusion intégrés** (module de pentest assisté) | Valeur métier réelle et reconnue, validation de l'efficacité des défenses, offre élargie. | Rejeté : c'est une **activité métier distincte**, avec son propre **cadre contractuel et légal** (lettre de mission, périmètre signé, fenêtre d'intervention, assurance responsabilité professionnelle) et des **compétences spécifiques** qui ne sont pas celles d'un moteur de règles. La confondre avec un SOAR brouille les responsabilités : si Thot Secure « fait du pentest », qui est responsable d'un test qui casse une production ? Thot Secure se limite à l'**audit de configuration de sa propre surface** (`probe` sur cibles déclarées, `config.audit`, `dependency`). |
| **Blocage d'hébergeurs ou de plages entières** (réponse « large » à une attaque) | Réponse rapide et radicale, facile à automatiser, efficace contre les attaques distribuées depuis un même fournisseur. | Rejeté : **dommages collatéraux** massifs (des milliers de clients légitimes hébergés chez le même fournisseur, dont l'utilisateur lui-même) et **déni de service interne** — exactement l'abus case documenté dans [`../architecture/threat-model.md`](../architecture/threat-model.md). La contre-mesure d'un SOAR doit rester proportionnée, ciblée et réversible (§1, invariant 3) ; bloquer un `/8` ou un fournisseur n'est ni l'un ni l'autre. |
| **Tarpit / empoisonnement** (ralentir ou tromper l'attaquant) | Occupe l'attaquant, gaspille son temps, peut révéler ses techniques, effet dissuasif léger. | Rejeté : c'est une **contre-offensive active** qui agit sur un système qui ne nous appartient pas et sur une connexion dont on ne contrôle pas l'origine. Les **effets sont imprévisibles** (amplification, blocage d'un intermédiaire légitime, interaction avec un système industriel fragile), l'efficacité réelle est faible contre un attaquant outillé, et le coût en responsabilité est élevé. Un produit défensif observe et se protège ; il ne manipule pas son adversaire. |
| **Ne rien écrire et laisser la question ouverte** | Souplesse : on garde la possibilité d'ajouter des fonctions offensives plus tard, sans se lier publiquement. | Rejeté : **perte de crédibilité**. Un produit de sécurité qui refuse de préciser son périmètre d'action laisse planer le doute chez les RSSI, les juristes et les acheteurs publics, et s'expose à ce qu'une contribution offensive arrive « par surprise » faute de doctrine écrite. L'ambiguïté n'apporte aucune option stratégique réelle : elle coûte de la confiance immédiatement, pour un bénéfice hypothétique. L'écrire noir sur blanc est aussi ce qui rend le refus **opposable** lors des revues de contribution. |

<!-- Métadonnées: statut=accepté, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
