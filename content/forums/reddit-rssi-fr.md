```yaml
canal: "Reddit — communauté RSSI/sécurité francophone (sous-reddit exact à vérifier le jour J)"
langue: "Français intégral (public francophone)"
format: "Post texte (self post), sections courtes, un seul lien (le dépôt) placé en fin de post et non en accroche"
objectif: "Parler aux RSSI, DPO et responsables conformité sur des critères qu'ils vérifient eux-mêmes : auditabilité, revue d'accès, preuve exploitable, rétention, et les limites honnêtes du produit — notamment la tension entre journal immuable et droit à l'effacement"
mot_cle_principal: "auditabilité"
longueur: "Fichier de travail ≈ 2 800 mots ; post ≈ 700 à 850 mots (sections courtes ; un post plus long n'est pas lu par ce public)"
meilleur_creneau_publication: "Hypothèse de travail non mesurée : mardi→jeudi, 08:00–10:00 ou 12:30–14:00 heure de Paris. À confirmer sur place ; ne pas présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : nom et existence du sous-reddit francophone visé (plusieurs communautés coexistent, certaines sont fermées ou peu actives), règles sur l'auto-promotion et sur la publication d'un projet par son auteur, flairs disponibles, seuils de réputation éventuels, tolérance vis-à-vis des sujets de conformité et de la terminologie juridique. Ces règles évoluent et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — la communauté visée est professionnelle et particulièrement allergique au contenu perçu comme commercial, d'autant plus sur un sujet de conformité où l'argument de vente habituel est la peur. Conséquences : (1) déclarer la qualité d'auteur dès la première ligne ; (2) UN SEUL lien, celui du dépôt, en fin de post ; (3) AUCUNE mention de dons, de financement ou de prestation — sur ce canal, une sollicitation décrédibiliserait instantanément l'ensemble du propos ; (4) aucun vocabulaire de conformité clé en main (« conforme RGPD », « prêt pour l'audit », « certifié ») : ce serait faux et immédiatement relevé ; (5) ne pas chercher à recruter des utilisateurs, mais à exposer des limites et à recueillir des objections ; (6) ne jamais répondre à une question juridique par un avis juridique."
```

---

# 1. Stratégie (FR)

**Positionnement.** Sur un canal RSSI, deux postures existent : vendre de la conformité, ou exposer ce qui est démontrable et ce qui ne l'est pas. La première produit de la méfiance immédiate, d'autant qu'Thot Secure est un logiciel libre en alpha sans éditeur. La seconde est la seule tenable ici : décrire précisément ce qu'un auditeur peut vérifier dans l'outil, et nommer les endroits où le produit ne répond pas au problème.

**Le fil conducteur du post** : distinguer trois choses que le vocabulaire courant mélange.

1. Ce qui est **techniquement démontrable** (une chaîne de hachages vérifiable, une revue de clés API, des rapports exportables).
2. Ce qui est une **décision d'organisation** et ne peut pas venir du logiciel (durées de conservation, base légale des traitements, qualification des rôles, procédure de réponse aux demandes d'exercice de droits).
3. Ce qui **n'est pas traité** par la v0.1.0 et qu'il faut savoir avant de s'engager (absence de mécanisme d'effacement ou de rédaction dans la chaîne d'audit, absence de correspondance avec un référentiel de contrôles, aucune fonction de type GRC).

**La phrase qui doit figurer dans le post, sous une forme ou une autre** : Thot Secure n'est ni un outil de certification, ni un avis juridique, ni une conformité clé en main. Sans elle, le post sera lu comme une promesse de conformité et démonté, à raison.

**Ce qu'il faut éviter absolument** : « conforme RGPD », « audit-ready », « prêt pour NIS2 / ISO 27001 / SOC 2 », « facilite votre mise en conformité », « preuve irréfutable », « immuable » employé sans nuance. Les mots « immuable » et « preuve » doivent être systématiquement accompagnés de leur périmètre exact.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Mardi→jeudi, 08:00–10:00 ou 12:30–14:00 heure de Paris (hypothèse non mesurée, à confirmer). |
| Longueur | 700–850 mots. Sections de 3 à 5 lignes, titres explicites. Ce public lit en diagonale et s'arrête sur les listes et les formulations conditionnelles. |
| Participation préalable | Compte avec un historique de commentaires dans la communauté visée. Un compte créé pour l'occasion et publiant sur la conformité sera lu comme du démarchage. Si l'historique manque, commenter d'abord sur des sujets voisins pendant quelques semaines. |
| Disponibilité | Répondre pendant 24 à 48 h. Les questions viendront probablement d'un DPO ou d'un auditeur : ce sont les plus utiles et les plus dures. |
| Posture | Répondre « je ne sais pas » quand c'est le cas, puis revenir avec la réponse vérifiée. Sur ce canal, une approximation juridique coûte plus cher que six « je vérifie ». |
| Anti-patterns | Citer le RGPD comme un bloc monolithique ; confondre sécurité et conformité ; promettre une évolutivité de feuille de route ; parler dons ; publier un tableau comparatif avec des concurrents. |

---

# 3. Faits vérifiés (FR) — base du post et des réponses

| Affirmation | Source |
|---|---|
| Le journal d'audit est append-only et chaîné par hash : détection de falsification | §1 du contrat (vocabulaire) |
| Formule : `hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`, `canonical()` = JSON trié, séparateurs compacts, UTF-8 ; le genesis a `prev_hash = "sha256:genesis"` | §3.5 du contrat |
| Vérification : `GET /api/v1/audit/verify` → `{"valid":true,"records":n,"broken_at":null}` | §4.7 du contrat |
| Export vers SIEM/SOAR : `GET /api/v1/audit/export?format=jsonl\|cef` (flux téléchargeable) | §4.7 du contrat |
| Chaque enregistrement porte `seq`, `ts`, `tenant_id`, `actor`, `actor_role`, `action`, `target`, `before`, `after`, `prev_hash`, `hash` | §3.5 du contrat |
| Chaque décision référence un `policy_id` et chaque action un `audit_seq` | §10 du contrat |
| Le cycle de vie d'une action est explicitement énuméré : `planned, pending_approval, approved, rejected, executing, succeeded, failed, expired, rolled_back`, avec `requested_by`, `approved_by`, `approved_at`, `executed_at`, `expires_at`, `result` et l'état du rollback (`available`, `token`, `performed_at`, `result`) | §3.4 du contrat |
| Le hash couvre les transitions d'état d'une action (`before`/`after`) et sa cible, pas le contenu brut des événements | §3.4 et §3.5 du contrat |
| Rôles et capacités : `viewer` = `read:events read:findings read:rules read:policies read:audit read:stats` ; `analyst` = viewer + `write:events write:findings` ; `responder` = analyst + `execute:actions approve:actions` ; `admin` = responder + `admin:tenants admin:rules admin:keys admin:policies` | §4 du contrat |
| Clés API : créées via `POST /api/v1/tenants/{id}/keys` avec `{"role","label"}`, la valeur `ao_…` n'est **affichée qu'une seule fois** ; listables avec `created_at`, `last_used_at`, `revoked_at` ; révocables immédiatement par `DELETE /api/v1/keys/{key_id}` → `204` | §4.2 du contrat |
| Clés API stockées **hachées** (`scrypt`), jamais en clair | §10 du contrat |
| `GET /api/v1/auth/whoami` renvoie tenant, rôle, capacités et mode d'autonomie | §4.1 du contrat |
| Rapports par finding : `GET /api/v1/findings/{id}/report?format=md\|html\|json\|sarif`, SARIF 2.1.0 pour GitHub Code Scanning | §4.8 du contrat ; §2 du contrat (`reports/` : markdown, html, json, sarif, cef) |
| Statistiques : `GET /api/v1/stats/overview` — compteurs 24 h/7 j, findings par sévérité, MTTA/MTTR, top règles, actions réussies/rollback, mode d'autonomie | §4.8 du contrat |
| Rétention : `THOT_RETENTION_DAYS=30` — « Purge événements » ; la purge de rétention est couverte par un test dédié | §9 et §11 du contrat |
| Isolation multi-tenant : tout objet porte `tenant_id`, toute requête SQL filtre `tenant_id`, test dédié en CI ; sur `POST /api/v1/events`, `tenant_id` est forcé depuis la clé API | §1, §4.3 et §10 du contrat |
| Chiffrement : TLS en transit (reverse-proxy ou direct via `THOT_TLS_ENABLED`), au repos `THOT_SECRET_KEY` + disque chiffré documenté | §9 et §10 du contrat |
| Anti-abus : limitation de débit sur l'ingestion (`THOT_RATE_LIMIT_PER_MIN=600`), taille de corps limitée, aucune évaluation de template utilisateur, expressions régulières de règle compilées avec délai d'exécution maximal | §9 et §10 du contrat |
| Traçabilité : `policy_id` sur chaque décision, `audit_seq` sur chaque action ; l'action critique passe par `require_approval` ou par un mode `auto` explicitement activé au niveau du tenant, avec journalisation de `actor`, `policy_id`, `before`, `after` | §1 et §10 du contrat |
| Endpoints publics : `GET /healthz`, `GET /readyz`, `GET /version` ; `GET /metrics` est public et explicitement destiné à un réseau interne | §4.1 du contrat |
| Horizon d'exploitation : MTTA/MTTR calculés par le produit, donc la mesure des délais de traitement ne dépend pas d'un tableur externe | §4.8 du contrat |
| Le contrat ne décrit **aucun** mécanisme de rédaction, d'effacement ou de caviardage d'un enregistrement d'audit, ni aucune correspondance avec un référentiel de contrôles (ISO 27001, NIS2, SOC 2), ni aucune fonction de type GRC | **absence constatée dans le contrat** — à présenter comme telle, et non comme une garantie de non-existence dans le code |

---

# 4. POST — à copier tel quel (FR)

> **Titre :** `Thot Secure 0.1.0 (alpha, Apache-2.0) : audit chaîné, RBAC, rétention — ce qu'un audit peut vraiment vérifier, et la tension RGPD que je ne balaie pas`
>
> **Flair :** à vérifier le jour J (chercher un flair de discussion, éviter tout flair de type « promotion »)

Je suis l'auteur d'Thot Secure, un SOAR/CSPM défensif en Python/FastAPI, publié en v0.1.0 sous Apache-2.0. Le projet est en alpha. Je ne vends rien et ce post n'est pas une offre : je travaille en ce moment la partie auditabilité et je préfère exposer les limites avant que quelqu'un d'autre ne les trouve.

**D'abord, ce que ce n'est pas.** Thot Secure n'est pas un outil de certification, ne produit pas de conformité clé en main, ne contient aucune correspondance avec un référentiel de contrôles (ISO 27001, NIS2, SOC 2), et rien de ce qui suit n'est un avis juridique. Ce qui suit décrit des propriétés techniques et les questions qu'elles laissent ouvertes.

## Auditabilité : ce qui est démontrable

Le journal d'audit est append-only et chaîné par hachage. Chaque enregistrement s'engage sur le précédent :

```
hash = sha256(seq|ts|tenant_id|actor|actor_role|action|
              canonical(target)|canonical(before)|canonical(after)|prev_hash)
```

`canonical()` est du JSON trié, à séparateurs compacts, en UTF-8 ; le premier enregistrement a `prev_hash = "sha256:genesis"`. La vérification est locale : `GET /api/v1/audit/verify` renvoie `{"valid":true,"records":n,"broken_at":null}`, et `broken_at` désigne l'index de rupture. L'export se fait en `jsonl` ou `cef` vers votre SIEM (`GET /api/v1/audit/export?format=jsonl|cef`).

Ce qu'un enregistrement contient : `seq`, `ts`, `tenant_id`, `actor`, `actor_role`, `action`, `target`, `before`, `after` et les deux hachages. Une action porte en plus `policy_id` et un `audit_seq`, ce qui relie la décision de politique à sa trace, et son cycle de vie est énuméré (`planned`, `pending_approval`, `approved`, `rejected`, `executing`, `succeeded`, `failed`, `expired`, `rolled_back`) avec `requested_by`, `approved_by`, `approved_at`, `executed_at`, `expires_at`.

**La nuance qui compte** : une chaîne de hachages démontre la **cohérence interne** du journal que vous détenez, et détecte modification, suppression ou réordonnancement. Elle ne démontre pas la **complétude** : qui contrôle l'hôte peut tronquer le journal et recommencer une chaîne, et qui peut réécrire la base peut recalculer la chaîne. L'ancrage de la tête de chaîne (export régulier vers un SIEM, notarisation périodique) est ce qui rend la propriété opposable — c'est un choix d'exploitation, pas une fonctionnalité du logiciel.

## Revue d'accès : ce que l'outil donne

Quatre rôles : `viewer` (lecture des événements, findings, règles, politiques, audit, statistiques), `analyst` (ajoute l'écriture d'événements et de findings), `responder` (ajoute l'exécution et l'approbation d'actions), `admin` (ajoute la gestion des tenants, règles, clés et politiques). `GET /api/v1/auth/whoami` renvoie le tenant, le rôle, les capacités effectives et le mode d'autonomie.

Les clés API sont créées avec un rôle et un libellé et leur valeur n'est affichée **qu'une seule fois** ; elles sont stockées hachées (`scrypt`), jamais en clair. La liste (`GET /api/v1/tenants/{id}/keys`) expose `created_at`, `last_used_at` et `revoked_at` — de quoi alimenter une revue d'accès périodique — et la révocation est immédiate (`DELETE /api/v1/keys/{key_id}` → `204`). Ce que l'outil ne fait pas : pas de revue automatisée, pas de rapport de revue, pas d'expiration obligatoire des clés, pas de MFA, pas de SSO. Le logiciel fournit des données, pas une procédure.

## Preuve exploitable : ce que vous pouvez sortir

Par finding : `md`, `html`, `json` ou `sarif` (`SARIF 2.1.0`, utilisable avec GitHub Code Scanning). Nuance : SARIF sert à remonter des résultats d'analyse dans une chaîne CI, ce n'est pas un format de restitution d'audit ; `cef` concerne l'export d'audit vers un SIEM. Côté pilotage, `GET /api/v1/stats/overview` expose les compteurs 24 h/7 j, les findings par sévérité, les MTTA/MTTR, les règles les plus déclenchées et le mode d'autonomie — utile pour un comité, insuffisant pour un audit de contrôle. Et un artefact produit par l'outil n'est pas un élément de preuve qualifié : la qualification reste votre travail.

## Rétention et purge

`THOT_RETENTION_DAYS` vaut 30 par défaut et pilote la purge des événements. Insistons : **30 jours est un défaut technique, pas une recommandation de conformité.** Arbitrez-le contre votre propre référentiel de conservation, qui peut exiger plus ou moins selon la catégorie de journal et la base légale.

Point à vérifier avant de vous engager : le contrat décrit la purge des **événements**. Ce qu'il advient des objets dérivés — findings, résultats d'actions, rapports déjà générés, enregistrements d'audit — n'est pas décrit avec la même précision. Ne supposez pas que purger les événements purge tout ce qui en découle.

## La tension que je ne balaie pas : journal immuable et droit à l'effacement

Un journal conçu pour détecter toute suppression s'oppose frontalement à une demande d'effacement. Trois éléments factuels, sans conclusion juridique.

1. **Ce qui entre dans la chaîne.** Le hachage couvre `actor`, `actor_role`, `target`, `before`, `after`. Un `actor` de type `api-key:ci` est un identifiant pseudonyme, mais reste une donnée personnelle dès lors qu'il est rattachable à une personne ; et `target` peut contenir une adresse IP (`{"type":"ip","value":"203.0.113.9"}`), qui est une donnée personnelle. Des données personnelles peuvent donc se retrouver **dans** la chaîne, pas seulement à côté.
2. **Ce qui en sort.** Les données personnelles les plus volumineuses sont dans les événements (`labels`, `payload` : IP source, user agent, chemin). Elles relèvent de la purge liée à `THOT_RETENTION_DAYS`, donc d'une durée finie — c'est le principal levier de minimisation dont vous disposez.
3. **Ce qui manque.** Le contrat ne décrit **aucun** mécanisme de rédaction, de caviardage ou d'effacement d'un enregistrement d'audit. Supprimer un enregistrement rompt la chaîne et détruit la propriété de détection de falsification — exactement ce pour quoi la chaîne existe. En v0.1.0, il n'y a donc aucune réponse technique satisfaisante à une demande d'effacement visant une donnée présente dans la chaîne.

Conséquence, que je ne peux pas trancher à votre place : soit vous vous appuyez sur une exception au droit à l'effacement (obligation légale, constatation, exercice ou défense de droits en justice — l'appréciation est celle de votre DPO et, le cas échéant, de votre conseil), soit vous réduisez la présence de données personnelles en amont, en veillant à ce que ce qui entre dans la chaîne soit déjà pseudonymisé. La seconde voie est la plus solide, et elle est aujourd'hui **de votre responsabilité** : le produit ne fournit pas de pseudonymisation à l'ingestion, et un mécanisme de rédaction préservant la vérifiabilité est une piste de conception, pas une fonctionnalité livrée.

Je préfère l'écrire noir sur blanc : un journal chaîné est un bon outil de détection de falsification et un mauvais outil de gestion des droits des personnes, tant que la question n'a pas été traitée en amont.

## Ce qu'il ne faut pas attendre du logiciel

Thot Secure traite des données personnelles (adresses IP, agents utilisateurs, chemins) : cela fait de vous un responsable de traitement et, si vous êtes prestataire, un sous-traitant — avec les documents que cela suppose, que le projet ne fournit pas. Ni registre des traitements, ni modèle d'AIPD, ni contrat de sous-traitance, ni gestion des demandes d'exercice de droits. Ce n'est pas un logiciel de GRC.

## Ce que je vous demanderais de vérifier vous-même

La purge effective de tous les objets dérivés, et pas seulement des événements ; le comportement réel de `GET /api/v1/audit/verify` après une coupure, une restauration de sauvegarde ou une migration ; l'ancrage de la tête de chaîne hors de l'hôte qui la produit ; l'adéquation de l'exposition réseau par défaut (`0.0.0.0`, `GET /metrics` et `GET /readyz` publics) à votre zone de confiance ; la justification et la minimisation de chaque donnée personnelle qui entre dans la chaîne ; et la qualification exacte de vos traitements avec votre DPO.

Dépôt (le seul lien de ce post) : `https://github.com/thot-corp/thot-secure`

Je réponds volontiers aux questions techniques sur la chaîne, la vérification et les rôles. Sur les questions juridiques, je vous dirai franchement que ce n'est pas mon métier.

---

# 5. Ce que le RSSI doit vérifier lui-même (FR) — section de travail, à ne pas publier telle quelle

À utiliser comme grille d'évaluation ; chaque ligne doit rester vraie après vérification.

**Auditabilité**
- [ ] `GET /api/v1/audit/verify` renvoie bien `broken_at` non nul après une altération provoquée d'un enregistrement (test de falsification reproduit, pas seulement lu).
- [ ] Le comportement de la vérification après restauration d'une sauvegarde antérieure, après migration de base et après changement de `tenant_id` : constaté, pas supposé.
- [ ] La tête de chaîne est ancrée hors de l'hôte : export périodique vers un SIEM, notarisation, ou les deux. Fréquence définie et documentée.
- [ ] `GET /api/v1/audit/export?format=cef` est réellement ingéré par votre SIEM (test de bout en bout avec `jsonl` également).
- [ ] La disponibilité et l'intégrité du journal ne dépendent pas d'un composant unique non sauvegardé.

**Revue d'accès**
- [ ] Inventaire des clés API : `GET /api/v1/tenants/{id}/keys`, contrôle de `last_used_at` (clés dormantes) et de `revoked_at`.
- [ ] Chaque clé a un libellé rattachable à un service ou une personne — sinon la revue est impossible.
- [ ] Les rôles attribués respectent le moindre privilège : combien de clés `admin` existent réellement, et pourquoi.
- [ ] Procédure de révocation testée (`DELETE /api/v1/keys/{key_id}` → `204`), y compris en urgence.
- [ ] Absence de MFA, d'expiration automatique des clés et de SSO prise en compte dans le contrôle compensatoire.
- [ ] `THOT_BOOTSTRAP_API_KEY` a été changé, et `THOT_SECRET_KEY` défini explicitement.

**Preuve et pilotage**
- [ ] Les rapports `md`, `html`, `json`, `sarif` produits sont rattachables à une procédure interne (qui les produit, qui les conserve, combien de temps).
- [ ] Usage du SARIF clarifié : intégration CI/Code Scanning, et non restitution d'audit.
- [ ] `GET /api/v1/stats/overview` : MTTA/MTTR et mode d'autonomie exploités dans un tableau de bord, avec la définition retenue pour ces indicateurs.
- [ ] Le périmètre de ce qu'un artefact prouve et ne prouve pas est écrit dans la procédure, pas seulement compris.

**Rétention, purge et RGPD**
- [ ] `THOT_RETENTION_DAYS` arbitré contre les durées de conservation applicables à chaque catégorie de données.
- [ ] Périmètre réel de la purge mesuré : événements, mais aussi findings, actions, résultats, rapports déjà générés et enregistrements d'audit. Ce qui n'est pas purgé est identifié.
- [ ] Analyse du point de tension : quelles données personnelles entrent effectivement dans la chaîne (`actor`, `target`) et comment elles sont justifiées.
- [ ] Réponse préparée à une demande d'effacement touchant une donnée présente dans la chaîne : exception invoquée ou mesure de pseudonymisation en amont, validée par le DPO.
- [ ] Base légale de chaque traitement, mention d'information, et — si vous êtes prestataire — contrat de sous-traitance : hors périmètre du logiciel, donc à produire.
- [ ] Analyse d'impact (AIPD) évaluée si le traitement est susceptible d'engendrer un risque élevé.
- [ ] Procédure de notification d'une violation de données (délais internes, autorité, personnes concernées) définie indépendamment de l'outil.

**Sécurité du déploiement**
- [ ] Exposition réseau arbitrée : `GET /metrics`, `GET /readyz` et `GET /healthz` sont publics par conception et doivent rester sur un réseau interne.
- [ ] TLS en transit assuré (reverse-proxy ou direct), chiffrement au repos effectif (disque chiffré, `THOT_SECRET_KEY` géré comme un secret).
- [ ] `THOT_ENV=prod` en production.
- [ ] Isolation multi-tenant reproduite par vos soins avec au moins deux tenants, y compris sur l'API, le bus et les rapports.
- [ ] Sauvegarde et restauration de la base testées, avec le comportement de la chaîne d'audit après restauration documenté.

---

# 6. Notes d'objection (FR) — réponses préparées

| Objection | Réponse |
|---|---|
| « Un journal chaîné n'est pas immuable, c'est un abus de langage. » | Accord, et le post le dit déjà : la chaîne démontre la cohérence interne et détecte les altérations, pas la complétude. L'immuabilité réelle suppose un ancrage hors de l'hôte. Toute réponse qui défend le mot « immuable » sans cette nuance est perdue d'avance. |
| « Comment gérez-vous l'article 17 ? » | Réponse honnête : en v0.1.0, aucun mécanisme de rédaction ou d'effacement dans la chaîne ; supprimer rompt la chaîne et détruit la propriété recherchée. Les leviers sont la minimisation à l'ingestion (de la responsabilité de l'exploitant, pas fournie) et l'appréciation d'une exception par le DPO. Ne jamais donner d'avis juridique. |
| « Où est votre mapping ISO 27001 / NIS2 ? » | Il n'y en a pas, et le post l'annonce. Ne pas improviser de correspondance de contrôles en commentaire. |
| « Êtes-vous conforme RGPD ? » | Reformuler : un logiciel n'est pas conforme, un traitement peut l'être. Thot Secure fournit des propriétés techniques (traçabilité, rôles, export, rétention configurable) ; la conformité dépend de votre qualification, de vos bases légales et de vos procédures. Et rappeler qu'Thot Secure traite des données personnelles. |
| « Le défaut de rétention à 30 jours est-il conforme ? » | Non par construction : c'est un défaut technique. C'est à l'exploitant de l'arbitrer. Ne jamais présenter 30 jours comme une recommandation. |
| « Pourquoi pas de MFA, pas d'expiration de clés ? » | Parce que ce n'est pas implémenté : quatre rôles, clés hachées, révocation immédiate, valeurs affichées une seule fois. Il faut le dire comme une limite, et indiquer le contrôle compensatoire attendu côté exploitant. |
| « Un auditeur acceptera-t-il vos rapports ? » | Ni moi ni le logiciel ne pouvons répondre : c'est l'auditeur qui qualifie l'élément de preuve. Fournir le format, la méthode de vérification et le périmètre exact, et laisser l'auditeur trancher. |
| « Et l'IA / la remédiation automatique sur des données de production ? » | Rappeler les garde-fous utiles ici : `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised` par défaut, dry-run global prioritaire sur toute politique, plafond horaire, cooldown par (tenant, playbook, cible), refus sur les cibles protégées, approbation obligatoire hors périmètre déclaré. Puis rappeler que ces garde-fous sont techniques, pas une validation de conformité. |
| « Qui est responsable si une action automatique casse la production ? » | Question d'organisation, pas de produit. Le produit documente qui a approuvé quoi (`approved_by`, `approved_at`) et ce qui a été fait (`before`/`after`, `audit_seq`) — la répartition des responsabilités doit être écrite ailleurs. |

---

# 7. Checklist avant publication (FR)

- [ ] Le sous-reddit visé existe, est actif, et ses règles ont été relues le jour J (elles n'ont pas pu être vérifiées hors ligne).
- [ ] La qualité d'auteur est déclarée dans la première phrase.
- [ ] Le post contient explicitement qu'Thot Secure n'est ni un outil de certification, ni un avis juridique, ni une conformité clé en main.
- [ ] Le mot « immuable » n'apparaît jamais sans le périmètre exact de ce que la chaîne démontre, et la limite de complétude est écrite.
- [ ] La tension effacement/journal est traitée frontalement, sans la balayer, et sans conclure à la place du DPO.
- [ ] Aucune correspondance avec ISO 27001, NIS2, SOC 2 ou un texte réglementaire n'est suggérée : il n'y en a pas.
- [ ] Un seul lien (le dépôt), placé en fin de post.
- [ ] Aucune mention de dons, de prestation ou de financement.
- [ ] Aucun chiffre non mesuré ; aucun chiffre d'exemple sans la mention « ordre de grandeur à remplacer ».
- [ ] Le périmètre de la purge (événements oui, objets dérivés à vérifier) est écrit tel quel, sans affirmation non étayée.
- [ ] La liste « ce que je vous demanderais de vérifier vous-même » figure bien dans le post publié — c'est ce qui distingue ce post d'une plaquette.
- [ ] Les réponses préparées du §6 sont à portée de main, en particulier sur l'article 17.
- [ ] L'auteur est disponible 24 à 48 h et s'engage à répondre « je vérifie » plutôt qu'à improviser une réponse juridique.
