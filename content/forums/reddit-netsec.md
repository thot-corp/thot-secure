```yaml
canal: "Reddit — r/netsec"
langue: "Post en anglais (le sous-reddit est anglophone) ; analyse, positionnement, notes d'objection et notes de canal en français dans des sections séparées"
format: "Post texte (self post) — flair [Tool] ; le lien vers le dépôt figure dans le corps, jamais en URL de soumission externe"
objectif: "Annoncer la v0.1.0 à une audience de praticiens exigeants, obtenir des critiques de conception sur la décision policy-as-code, la réversibilité et l'audit chaîné ; ne pas chercher du trafic mais des objections techniques"
mot_cle_principal: "defensive SOAR"
longueur: "Cible ≈ 1 500 mots pour le fichier de travail ; texte du post ≈ 600 à 700 mots (au-delà, couper plutôt que compléter)"
meilleur_creneau_publication: "Hypothèse de travail non mesurée : mardi→jeudi, 14:00–17:00 UTC (matinée côte Est US). À confirmer par les statistiques du sous-reddit le jour J ; ne jamais présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : liste des flairs disponibles, contenu des règles du sous-reddit sur l'auto-promotion et les publications d'outils, éventuelle obligation de poster un self post plutôt qu'un lien, seuils de karma/ancienneté éventuels, interdiction ou non de solliciter des contributions. Ces règles évoluent et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — r/netsec encadre strictement l'auto-promotion et attend un historique de participation réel avant toute publication d'outil. Conséquences opérationnelles : (1) ne pas publier ce post sans avoir commenté le sous-reddit de façon substantielle et non promotionnelle sur plusieurs semaines ; (2) disclosure de la qualité d'auteur dès la première ligne ; (3) UN SEUL lien dans tout le post (le dépôt) ; aucun lien vers un site commercial, une newsletter, une page de dons ou un article de blog ; (4) répondre aux commentaires pendant les premières heures, sans jamais replacer de lien ; (5) si l'historique de participation est insuffisant, ne pas publier — utiliser r/selfhosted ou Lobsters à la place. Ne mentionner AUCUN don sur ce canal (voir §5)."
```

---

# 1. Décision de canal et de flair (FR)

**Pourquoi r/netsec.** C'est l'un des rares espaces où une critique sur la *conception* d'un outil défensif arrive en quelques minutes, souvent par des gens qui ont exploité ou détruit le genre d'outil qu'on propose. L'objectif n'est pas l'acquisition d'utilisateurs : c'est de faire émerger les objections que nous n'avons pas anticipées sur le moteur de décision et la réversibilité.

**Choix du flair : `[Tool]`.**

- `[Tool]` — retenu. Le post annonce une version publiée (`v0.1.0`) d'un outil utilisable, avec un dépôt et une licence. C'est la catégorie honnête. Le flair `[Tool]` expose aussi le post à la règle anti-spam du sous-reddit, ce qui est assumé : nous préférons un post étiqueté comme outil et modéré comme tel plutôt qu'un post `[Discussion]` déguisant une annonce.
- `[Discussion]` — non retenu, mais c'est le bon flair dans un cas précis : si l'historique de participation est trop mince pour publier une annonce d'outil, alors il faut publier une **vraie** question de conception, sans annonce de version et sans lien de dépôt en tête de post (par exemple : « comment décidez-vous entre auto-remédiation et approbation pour un blocage d'IP ? »). Un post `[Discussion]` qui contient un lien de dépôt et une version est un abus de flair et sera traité comme tel.

**Attention** : la liste des flairs effectivement disponibles et leur orthographe exacte doivent être vérifiées dans l'interface de soumission le jour J. Aucune vérification n'a pu être faite hors ligne.

**Stratégie de titre** : le titre retenu énonce le fait vérifiable le plus différenciant (réversibilité + audit chaîné + dry-run par défaut) et rien d'autre. Les variantes ci-dessous sont classées par ordre de préférence, du plus factuel au plus discutable.

1. Retenu : `Thot Secure v0.1.0 – defensive SOAR with reversible actions, hash-chained audit, dry-run by default (Apache-2.0)`
2. Repli si le premier paraît trop long : `Thot Secure v0.1.0 – a defensive SOAR where every playbook ships with a rollback (Apache-2.0, dry-run by default)`
3. À éviter : toute formulation en « introducing », « finally », « the SOAR that… ». Aucune de ces formes n'apporte d'information vérifiable.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Mardi→jeudi 14:00–17:00 UTC (hypothèse non mesurée). Éviter le week-end et les jours de publication majeure d'un avis de sécurité : le post serait noyé. |
| Longueur | Post 600–700 mots. Un post r/netsec plus long que ~800 mots est lu en diagonale : si une section dépasse, la déplacer dans un commentaire préparé et y renvoyer. |
| Participation préalable | **Exigée.** Le compte utilisé doit avoir un historique de commentaires techniques dans r/netsec ou des sous-reddits proches. Recommandation interne : au minimum plusieurs semaines de participation et une dizaine de commentaires substantiels. Un compte qui n'a jamais commenté et publie un outil sera lu comme du spam, quel que soit le contenu. |
| Fenêtre de réponse | Rester disponible 3 à 4 heures après publication. C'est là que se joue la perception : une objection sans réponse est lue comme un aveu. |
| Ton | Humble et factuel. Reconnaître une limite avant qu'on nous la reproche. Ne jamais répondre à une critique par une fonctionnalité non publiée sans l'étiqueter « roadmap ». |
| Ce qu'on ne fait pas | Pas de cross-post immédiat sur plusieurs sous-reddits le même jour. Pas de demande d'upvote. Pas de MP aux commentateurs. Pas de relance du post s'il ne prend pas. |

---

# 3. Résumé technique en anglais (pour le fichier, pas pour le post)

Short, verifiable facts for the author to keep in mind while replying in comments:

- Pipeline: `Event` → YAML rule match → `Finding` (with `risk_score`, `confidence`) → policy-as-code `Decision` → `Action` (playbook instance) → `AuditRecord`. Intermediate states are separate, persisted objects; a decision is not implicit in a finding.
- `Decision.decision` ∈ `auto | require_approval | notify_only | ignore`. Policy semantics: `when` is an AND across keys; a list is an OR of equalities; a mapping is a comparator set (`gt, gte, lt, lte, in, not_in, matches`). `priority` is evaluated highest-first. No policy match ⇒ `notify_only`. Silence requires an explicit `ignore` policy.
- Engine guardrails that a policy **cannot** override: per-tenant `max_actions_per_hour` (default 20); cooldown per `(tenant, playbook, target)`; never act on a target in the protected `autonomy_allowlist`; global `dry_run` wins over any policy; an action on a target outside the tenant's declared scope becomes `require_approval`.
- Audit chain: `hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`, `canonical()` = sorted JSON, compact separators, UTF-8, genesis `prev_hash = "sha256:genesis"`. Verified by `GET /api/v1/audit/verify` → `{"valid":true,"records":n,"broken_at":null}`. Export via `GET /api/v1/audit/export?format=jsonl|cef`.
- Action lifecycle: `planned | pending_approval | approved | rejected | executing | succeeded | failed | expired | rolled_back`. `POST /api/v1/actions/{id}/execute` returns `409` if a `pending_approval` action was not approved; execute is idempotent via `idempotency_key`; `POST /api/v1/actions/{id}/rollback` returns `409` if already `rolled_back`.
- Roles: `viewer | analyst | responder | admin`. `viewer` = `read:events read:findings read:rules read:policies read:audit read:stats`; `analyst` adds `write:events write:findings`; `responder` adds `execute:actions approve:actions`; `admin` adds `admin:tenants admin:rules admin:keys admin:policies`.
- Multi-tenancy: every object carries `tenant_id`; on `POST /api/v1/events` the `tenant_id` is forced from the API key, never taken from the body. Isolation has a dedicated CI test.
- Core isolation: `thotsecure.core` depends only on the stdlib plus `pydantic`/`PyYAML`. FastAPI, Jinja2 and uvicorn belong to the API layer.
- Honest MVP limits to state before anyone asks: SQLite is the default store; connectors are unconfigured by default and therefore run in **simulated** mode (a playbook returns a `rollback_token` and logs `simulated: true`); the event bus defaults to `memory`; detection is YAML rules plus a Sigma-lite translation subset, not a Sigma engine; `web/` (React+TS) is optional and the console that ships is the Jinja2 + JS one with no Node build.

---

# 4. TEXTE DU POST — à copier tel quel (EN)

> **Titre :** Thot Secure v0.1.0 – defensive SOAR with reversible actions, hash-chained audit, dry-run by default (Apache-2.0)
>
> **Flair :** `[Tool]`
>
> **Corps :**

I'm the author — disclosure first, since that's the rule here.

Thot Secure is a defensive SOAR/CSPM in Python/FastAPI. The pipeline is: normalize events → match YAML rules → score → decide from policy-as-code → run a playbook that always has a rollback path. Repo: https://github.com/thot-corp/thot-secure — that is the only link in this post.

The four design bets, in the order they mattered to me:

1. **Reversibility is an interface contract, not a best effort.** Every playbook carries `reversible: true` and a `rollback:` block, and `POST /api/v1/actions/{id}/rollback` must succeed as long as the rollback window hasn't expired. If an action can't be undone, it doesn't belong in a playbook.

2. **A policy decides, not whoever clicks first.** Decisions are YAML policies evaluated by `priority`, with an explicit `when`/`then` and a `decision` of `auto`, `require_approval`, `notify_only` or `ignore`. If no policy matches, the outcome is `notify_only` — never `auto`. Total silence requires an explicit `ignore` policy, so "we forgot to write a rule" can't look like "we decided nothing was worth doing".

3. **Audit you can verify locally.** Records are hash-chained: `sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`, with `canonical()` = sorted compact UTF-8 JSON. `GET /api/v1/audit/verify` returns `{"valid":true,"records":n,"broken_at":null}`, and `GET /api/v1/audit/export?format=jsonl|cef` feeds a SIEM.

4. **Defaults you have to actively fight.** `THOT_DRY_RUN=true` and `THOT_AUTONOMY=supervised` out of the box. Global dry-run outranks any policy, and the decision engine enforces guardrails no policy can override: `max_actions_per_hour` per tenant (default 20), a cooldown per `(tenant, playbook, target)`, a hard refusal to act on targets in the tenant's protected `autonomy_allowlist`, and `require_approval` for any target outside the declared scope.

That last point is the one I care about most: the thing that stops a runaway automation isn't a setting, it's a code path a policy can't argue with.

**What v0.1.0 actually is, and isn't.** I'd rather list the limits than have them discovered later:

- Storage is SQLite (`THOT_DB_URL=sqlite:///./data/thotsecure.db`). PostgreSQL/TimescaleDB DDL is documented, not the default path.
- Connectors are unconfigured on a fresh install, so they run in **simulated** mode: the playbook returns a `rollback_token` and logs `simulated: true`. Nothing touches your WAF until you wire it up. It's deliberate — install-before-credentials — but it also means "it blocked an IP for me" is not what a fresh v0.1.0 does.
- The event bus defaults to in-process memory (`THOT_BUS=memory`); `sqlite` and `nats` are the alternatives.
- Detection is YAML rules with a fixed operator set (`eq, ne, gt, gte, lt, lte, in, not_in, contains, icontains, startswith, endswith, regex, exists, cidr, len_gt, len_lt`) plus a Sigma-lite translation subset. It is not a Sigma engine and won't pretend to be.
- `thotsecure.core` depends only on the stdlib plus pydantic/PyYAML. FastAPI/uvicorn/Jinja2 are API-layer, which is why the whole thing can be read as a library.

**Where I'd like to be told I'm wrong.** The two questions I haven't resolved to my own satisfaction: does a policy layer with guardrails actually earn its complexity over `if severity == "high": block(...)` in a 40-line script, and is a chained hash log materially more useful in a post-incident review than well-structured logs plus the SIEM you already pay for? I have opinions and I'd rather have counterexamples.

I'm expecting "yet another SOAR?" and "why not Wazuh + Shuffle?" — short version in the comments, and I'll answer properly there. The honest one-line answers: no connector-count competition, and Wazuh + Shuffle is a reasonable thing to run; I'll explain where the axes differ and where Thot Secure is simply the wrong pick.

---

# 5. Réponses préparées aux objections (FR — notes internes, à reformuler en anglais dans les commentaires)

## 5.1 « Encore un SOAR ? »

Réponse à donner, en trois temps : ce que le marché fait déjà, ce que nous faisons différemment, ce que nous n'avons pas.

- **Ce qui existe déjà et est légitime.** L'espace SOAR est encombré et majoritairement commercial. Les critères habituels sont le nombre d'intégrations, la richesse du designer de workflows, la console, le support. Sur ces critères, la v0.1.0 perd, et le dire d'emblée évite un débat stérile.
- **L'axe différent.** Ici, l'objet central n'est pas le workflow mais la **décision**, et elle est un artefact versionné et relisible : des politiques YAML ordonnées par `priority`, évaluées du plus grand au plus petit, dont l'effet est un `decision` explicite parmi quatre valeurs. Autour de cette décision, trois propriétés tenues comme contractuelles :
  - **Réversibilité** : le playbook contient un bloc `rollback:` et l'API expose `POST /api/v1/actions/{id}/rollback` ; l'échec du rollback tant que la fenêtre est ouverte est un défaut, pas une limite.
  - **Audit chaîné** : la chaîne de hash est une donnée du produit, vérifiable par `GET /api/v1/audit/verify`, et exportable (`jsonl|cef`), donc opposable hors du produit.
  - **Garde-fous non contournables par une politique** : `max_actions_per_hour`, cooldown par `(tenant, playbook, cible)`, refus absolu sur les cibles de l'`autonomy_allowlist`, priorité du `dry_run` global, `require_approval` hors périmètre déclaré. Un auteur de politique ne peut pas les désactiver en écrivant du YAML.
- **Ce que nous n'avons pas, à dire sans détour** : pas des centaines d'intégrations, pas de place de marché, pas de SSO d'entreprise, quatre rôles RBAC seulement (`viewer|analyst|responder|admin`), pas de retour d'expérience à grande échelle, une seule base (SQLite) par défaut, des connecteurs en mode simulé tant qu'ils ne sont pas configurés. Si l'exigence du jour est la couverture d'intégrations, un SOAR commercial est le bon choix et nous ne sommes pas une alternative crédible.

À ne pas faire : répondre que nous sommes « différents » sans nommer la différence, ou lister des capacités non encore livrées sans les étiqueter « roadmap ».

## 5.2 « Pourquoi pas Wazuh + Shuffle ? »

C'est la meilleure objection du lot et elle mérite une réponse longue, factuelle, et qui commence par reconnaître ce que ces outils font bien.

- **Ce que Wazuh fait bien.** Télémétrie hôte, agents à l'échelle, intégrité de fichiers, évaluation de configuration, corrélation côté endpoint, un écosystème mûr. Thot Secure ne remplace pas une couche agent/HIDS et n'a pas d'agent : c'est un consommateur d'événements normalisés (`POST /api/v1/events`), pas un collecteur d'endpoint.
- **Ce que Shuffle fait bien.** Automatisation par graphes de workflow, catalogue d'applications large, designer visuel : pour brancher quarante outils hétérogènes, un moteur de workflow est plus adapté qu'un moteur de politiques.
- **La différence d'axe, en trois points** :
  1. **Où vit la décision.** Shuffle orchestre un graphe que vous dessinez ; Thot Secure évalue des politiques déclaratives avec une priorité et un ensemble de garde-fous hors d'atteinte de la politique. Compromis assumé : beaucoup moins de puissance arbitraire qu'un graphe de workflow.
  2. **La réversibilité comme exigence du modèle de données**, pas comme convention de dessin. Le playbook déclare `reversible` et un bloc `rollback:` (avec `auto_after_seconds` côté politique) ; dans un moteur générique, l'annulation est ce que vous avez pris la peine de câbler.
  3. **L'audit comme artefact chaîné et vérifiable**, avec `audit_seq` sur chaque action, plutôt qu'un historique d'exécutions. C'est la différence entre « voici le journal d'exécution » et « voici une chaîne dont je peux prouver qu'elle n'a pas été réécrite ».
  4. **Isolation multi-tenant** traitée comme invariant du cœur avec un test dédié en CI — un point qui compte si vous êtes MSP et que le même déploiement sert plusieurs clients.
- **Quand Thot Secure n'est PAS le bon choix** (à énoncer explicitement, c'est ce qui rend la réponse crédible) :
  - vous avez besoin de plusieurs centaines d'intégrations dès demain ;
  - votre processus de validation exige un designer de workflow visuel plutôt que du YAML en revue de code ;
  - vous ne voulez pas de Python ni de YAML dans votre chaîne de réponse ;
  - vous cherchez un produit avec support éditeur et SLA contractuel ;
  - vous avez besoin d'agents endpoint (prenez Wazuh ou équivalent et alimentez Thot Secure en événements) ;
  - vous n'avez pas de besoin d'audit opposable ni d'exigence multi-tenant : dans ce cas un script et un SIEM suffisent, et le surcoût d'un moteur de politiques n'est pas justifié.
- **Composition réaliste à proposer plutôt qu'une opposition** : Wazuh (ou un autre collecteur) → `POST /api/v1/events` → Thot Secure (détection, décision, action réversible) → Shuffle pour les intégrations exotiques que nous n'avons pas. Thot Secure n'est pas un sur-ensemble de ces outils ; c'est un axe différent, et les deux peuvent coexister dans la même chaîne.

Formulation à éviter absolument : toute comparaison dénigrant Wazuh ou Shuffle, et tout chiffre de performance non mesuré. Nous n'avons pas de benchmark public : dire « plus rapide » serait une invention.

---

# 6. Règles d'auto-promotion appliquées à ce post (FR)

1. **Participation d'abord.** Ne pas publier sans historique de commentaires dans r/netsec. Un compte dédié à la publication d'un outil est traité comme du spam, à raison.
2. **Un seul lien.** `https://github.com/thot-corp/thot-secure`, une seule occurrence, dans le corps du post. Aucun lien vers un site de projet, une page de soutien, un article de blog ou une boutique.
3. **Disclosure en première ligne** : « I'm the author ». Non négociable, y compris dans les commentaires où l'on répond à une objection de conception.
4. **Pas de dons sur ce canal.** Décision volontaire : r/netsec n'est pas un lieu de sollicitation, et une section dons dans un post d'outil décrédibilise l'ensemble de l'argumentaire technique. Si quelqu'un demande comment soutenir le projet, répondre en une phrase qu'il existe une page de soutien dans le produit (`GET /ui/support`) et s'arrêter là — sans adresse, sans insistance, sans relance.
5. **Pas de relance.** Si le post ne prend pas, ne pas le republier ni le faire remonter.
6. **Réciprocité.** Répondre techniquement aux posts d'autres auteurs dans les jours qui suivent, indépendamment du sort de celui-ci.

---

# 7. Checklist avant publication (FR)

- [ ] Le compte dispose d'un historique de commentaires substantiel et non promotionnel dans r/netsec.
- [ ] Les règles du sous-reddit sur les publications d'outils et l'auto-promotion ont été relues **le jour J** (elles n'ont pas pu être vérifiées hors ligne).
- [ ] La liste des flairs et leur libellé exact ont été vérifiés dans l'interface de soumission ; `[Tool]` est disponible.
- [ ] Le dépôt public répond réellement, la licence affichée est Apache-2.0, la version publiée est bien `0.1.0`.
- [ ] Chaque limite annoncée dans le post a été vérifiée contre l'état réel du dépôt au moment de publier : SQLite par défaut, mode simulé des connecteurs non configurés, absence d'agent endpoint, bus `memory` par défaut, opérateurs de règles, rôles RBAC, dry-run et autonomie par défaut.
- [ ] Aucun chiffre mesuré n'apparaît dans le post. Tout exemple chiffré qui serait ajouté doit porter la mention « ordre de grandeur à remplacer ».
- [ ] Aucun superlatif marketing (« révolutionnaire », « game-changer », « next-gen », « leader ») ne figure dans le texte.
- [ ] Une seule occurrence du lien de dépôt dans tout le post (vérification par recherche textuelle).
- [ ] Les réponses préparées des §5.1 et §5.2 sont ouvertes dans un onglet à côté, pour répondre dans les minutes suivant l'objection.
- [ ] Une personne de l'équipe est disponible pendant 3 à 4 heures après publication.
- [ ] Tout élément relevant de la feuille de route est étiqueté « roadmap » dans les commentaires, jamais présenté comme livré.
