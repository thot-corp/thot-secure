```yaml
canal: "Hacker News — Show HN"
langue: "Tout en anglais (titre, texte et réponses aux commentaires) ; stratégie, notes de canal et aide au répondant en français dans des sections séparées"
format: "Show HN. Deux variantes fournies : (A) soumission d'URL vers le dépôt + commentaire d'auteur en premier, (B) self post texte. Variante A recommandée."
objectif: "Annoncer la v0.1.0 à une audience d'ingénieurs qui teste immédiatement ce qui est affirmé, et faire remonter les objections de conception. Aucun objectif de trafic."
mot_cle_principal: "SOAR"
longueur: "Fichier de travail ≈ 2 000 mots ; soumission : titre ≤ 80 caractères, texte du commentaire d'auteur ≈ 250 à 350 mots (concis, aucune liste de fonctionnalités)"
meilleur_creneau_publication: "Hypothèse de travail non mesurée : jour de semaine, 13:00–15:00 UTC (matinée côte Est US). À confirmer sur place ; ne pas présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : formulation attendue du préfixe « Show HN », règles HN sur les titres (pas de majuscules intempestives, pas de listes, pas d'accroche), politique sur les créations de compte neuves, règles d'auto-promotion et de vote, éventuelle limite sur la fréquence de soumission d'un même domaine. Ces règles évoluent et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — HN autorise le Show HN d'un projet dont on est l'auteur, mais sanctionne durement la promotion déguisée : pas de vote sollicité, pas de relais par des proches, pas de réécriture du titre en accroche, pas de réponse évasive à une critique technique. Conséquences : (1) l'auteur doit être présent dans les commentaires ; (2) aucun lien de don, de financement ou de boutique — le sujet n'est pas abordé, même si on pose la question, au-delà d'une phrase neutre ; (3) si une affirmation du post est fausse, la corriger publiquement dans le fil, sans la supprimer ; (4) ne pas reposter le même projet avant plusieurs mois."
```

---

# 1. Décision de format (FR)

**Pourquoi Show HN et pas un simple lien.** Le canal attend qu'un auteur réponde. Un Show HN sans auteur présent pendant la première heure est lu comme une publicité. Nous partons donc du principe que l'auteur bloque deux heures.

**Variante A — retenue : soumission d'URL vers le dépôt + commentaire d'auteur immédiat.**
La soumission pointe vers `https://github.com/thot-corp/thot-secure` ; le commentaire d'auteur (§4) apporte le contexte, les limites et les chiffres vérifiables. C'est la forme la plus courante et la plus honnête pour un outil : le lecteur peut vérifier lui-même, immédiatement, ce qui est affirmé.

**Variante B — repli : self post texte.**
À utiliser seulement s'il n'y a rien de réellement exécutable à cliquer (dépôt privé, absence de README). Ce n'est pas notre cas, mais la variante est fournie par sécurité.

**Ce que le titre ne doit pas contenir** : aucun adjectif. Pas de « finally », « simple », « powerful », « modern », « next-gen », « production-ready », « enterprise-grade », « blazing ». Le titre énonce ce que l'outil fait, avec le fait différenciant, et s'arrête.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Jour de semaine 13:00–15:00 UTC (hypothèse non mesurée). Éviter les jours de forte actualité sécurité : le fil ne survivra pas à la concurrence de la page d'accueil. |
| Longueur | Titre ≤ 80 caractères. Commentaire d'auteur 250–350 mots. Aucune section « features ». |
| Présence | L'auteur répond pendant 2 à 3 heures. Les 20 premières minutes décident de la trajectoire du fil. |
| Participation préalable | Fortement recommandée : un compte avec un historique de commentaires techniques et un karma non nul. Un compte créé le jour de la soumission sera filtré ou ignoré. |
| Anti-patterns | Demander un upvote (bannissement), faire commenter des collègues (détecté), reformuler le titre après soumission pour l'embellir, supprimer un commentaire gênant. |
| Suivi | Un post-mortem interne privé après 48 h : quelles objections sont revenues, quelles limites ont été découvertes, ce qui doit changer avant une nouvelle annonce. |

---

# 3. Faits à ne dire qu'après vérification (FR)

Le texte ci-dessous n'affirme que des éléments du contrat d'interface ou du dépôt. Deux points exigent une vérification **avant** de soumettre, sinon la phrase doit être retirée :

1. **Fichier compose** — `docker-compose.yml` et `docker-compose.observability.yml` sont à la racine du dépôt, et `deploy/` contient k8s, helm, terraform, ansible, grafana, prometheus. Le `Makefile` expose une cible `compose-up` qui appelle `docker compose up -d --build`. Citer le fichier comme source ; ne pas présenter la pile comme testée si elle ne l'a pas été depuis un clone propre.
2. **Télémétrie / réseau** — le contrat ne mentionne aucun mécanisme de télémétrie. Formulation autorisée : « aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface ; à confirmer par audit du code ». Interdit : « zéro télémétrie » ou « fonctionne en air-gap » présentés comme des garanties vérifiées.

Le troisième point du contrat — gouvernance — est vérifié : `CONTRIBUTING.md` renvoie bien à `GOVERNANCE.md`, qui existe dans le dépôt, cite une règle constitutionnelle (« pas de capacité offensive »), un DCO sans CLA, et l'exigence d'au moins une approbation de mainteneur avant fusion.

---

# 4. TEXTE À PUBLIER (EN)

## Variante A — soumission d'URL (recommandée)

> **Titre :** `Show HN: Thot Secure – defensive SOAR with reversible actions and dry-run by default`
>
> **URL :** `https://github.com/thot-corp/thot-secure`

Puis, immédiatement, en premier commentaire :

Author here. Thot Secure is a defensive SOAR/CSPM: normalized events in, YAML detection rules, risk score, policy-based decision, then a playbook that always carries a rollback. Python/FastAPI, Apache-2.0, v0.1.0, alpha.

The four decisions that shaped the code, in the order I'd defend them:

1. **Every action is reversible.** A playbook declares `reversible: true` and a `rollback:` block; `POST /api/v1/actions/{id}/rollback` must succeed while the rollback window is open. An action you can't undo doesn't go in a playbook — or it goes in marked `reversible: false`, which forces a human approval every time, whatever the autonomy mode.
2. **Decisions come from versioned policy, not from clicks.** YAML policies ordered by `priority`, each producing one of `auto`, `require_approval`, `notify_only`, `ignore`. No matching policy means `notify_only`, never `auto`; going fully silent takes an explicit `ignore` policy.
3. **The audit log is hash-chained and verifiable locally.** `hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`, compact sorted JSON. `GET /api/v1/audit/verify` returns `{"valid":true,"records":n,"broken_at":null}`; export is `jsonl` or `cef`.
4. **Guardrails a policy cannot override.** `THOT_DRY_RUN=true` and `THOT_AUTONOMY=supervised` by default; global dry-run beats any policy; `max_actions_per_hour` per tenant (default 20); cooldown per `(tenant, playbook, target)`; never act on a target in the tenant's protected `autonomy_allowlist`; anything outside the tenant's declared scope becomes `require_approval`.

Limits, before anyone has to dig for them. Storage is SQLite by default. Connectors ship unconfigured, so they run in **simulated** mode — a playbook returns a rollback token and logs `simulated: true`, which means a fresh install simulates rather than blocks. The event bus defaults to in-process memory (`sqlite` and `nats` otherwise). Detection is YAML rules with a fixed operator set plus a Sigma-lite translation subset — it is not a Sigma engine. There are no endpoint agents: it consumes normalized events at `POST /api/v1/events`. And `GET /metrics` and `GET /readyz` are unauthenticated by design, so they belong on an internal network.

`thotsecure.core` depends only on the stdlib plus pydantic/PyYAML; FastAPI, uvicorn and Jinja2 are API-layer. The console is server-rendered Jinja2 with no Node build step.

What I'd genuinely like to be argued out of: whether a policy engine with guardrails earns its complexity over a short `if severity == "high"` script, and whether a hash-chained log buys you anything a well-structured log plus your existing SIEM doesn't. Happy to answer anything about the decision engine or the rollback semantics.

## Variante B — self post (repli)

> **Titre :** `Show HN: Thot Secure – defensive SOAR with reversible actions and dry-run by default`

Body: same text as the first comment above, minus the "Author here" line, with the repo URL as the final line: `https://github.com/thot-corp/thot-secure`. Nothing else is added — no badge, no screenshot, no roadmap list.

---

# 5. Questions probables en commentaires — réponses courtes et honnêtes (EN, prêtes à coller)

> Ces réponses sont écrites pour être collées telles quelles. Elles sont volontairement courtes : un pavé en réponse à une question précise est lu comme une esquive.

**1. "An automated tool that blocks things — how do you keep it from taking down production?"**
Four layers, in the order they apply. (a) `THOT_DRY_RUN=true` is the default and global dry-run outranks every policy — a policy cannot turn it off. (b) An action on a target outside the tenant's declared scope becomes `require_approval` instead of executing. (c) Targets in the tenant's protected `autonomy_allowlist` — your own infrastructure — can never be acted on by any policy; the decision engine refuses in code. (d) Even in `auto` mode, the engine caps `max_actions_per_hour` (default 20 per tenant) and applies a cooldown per `(tenant, playbook, target)`, so a burst of findings can't snowball. And the first version you install has unconfigured connectors, so nothing is reachable until you deliberately point a playbook at a real WAF.

**2. "What about false positives?"**
A false positive at `notify_only` costs an analyst's attention; a false positive at `auto` costs you an outage, which is why the default is the former. Concretely: no policy match yields `notify_only`; an out-of-scope target yields `require_approval`; findings carry `confidence` alongside `risk_score` so a policy can require both; rules have a `false_positives:` block for documenting known-benign patterns; and `POST /api/v1/findings/{id}/suppress` creates a time-boxed exception on the rule (`duration_seconds`, `reason`) instead of letting people disable the rule. I won't claim the rules ship tuned for your environment — they don't, and shipping untuned rules to `auto` is exactly the mistake the defaults are designed to prevent.

**3. "Why not just use Sigma (and Shuffle)?"**
Sigma is a detection format, and Thot Secure doesn't replace it: the rule engine supports a Sigma-lite translation subset (`title, id, level, logsource, detection.selection|condition|filter`) with a warning on translation. But detection was never the hard part here. The parts I cared about are what happens after a finding: who owns the decision, whether the action can be undone, and whether the record of it is verifiable. A detection format doesn't answer any of those. On Shuffle: it's a workflow engine with a large app catalog and a visual designer, and for wiring forty heterogeneous tools together it's a better tool than a policy engine. Where the axes differ: Shuffle orchestrates a graph you draw, Thot Secure evaluates declarative policies with guardrails the policy can't override; and rollback/`audit_seq` are in the data model rather than being whatever you drew. If you need breadth of integrations today, use Shuffle. If you have a Sigma corpus you like, keep it.

**4. "Why SQLite?"**
Because the MVP is single-node and the alternative was shipping with no working default. `THOT_DB_URL` defaults to `sqlite:///./data/thotsecure.db`. There's a written PostgreSQL/TimescaleDB adapter that runs in CI against a real server with the same conformance suite as SQLite, but it isn't the default path and hasn't been exercised at production scale. SQLite also makes the "install and look at it before you trust it" flow trivial — one file, no service to bring up. It is a real constraint: don't run multiple writers against it and expect Postgres behavior. If your deployment is multi-node, this is a migration you do, not something the code handles for you today.

**5. "Why not put the audit log on a blockchain?"**
Because the requirement is tamper-evidence, and a hash chain gives you that without a consensus layer. Each record commits to its predecessor: `prev_hash` in, `hash` out, with a genesis record at `prev_hash = "sha256:genesis"`. That gives you local, offline verification of a contiguous log — `GET /api/v1/audit/verify` returns `{"valid":true,"records":n,"broken_at":null}` — and it's exported as `jsonl` or `cef` so an external system can keep its own copy. A chain proves *internal* consistency, and I'd rather say that plainly than oversell it: whoever controls the host can truncate the whole log and start a new chain, and an attacker able to rewrite the database can rewrite the chain unless the hashes are anchored somewhere you don't control. Anchoring is a deployment decision (ship records to your SIEM, notarize the head hash, or both), not something the product does for you. A blockchain would add operational weight without changing that trust question.

**6. "What state is this actually in?"**
v0.1.0, alpha (`Development Status :: 3 - Alpha`). What's real: the schema and API surface are frozen for sprint 1 in a written interface contract, the decision semantics and guardrails are specified, the audit hash formula is specified, and there's a unittest suite defined around config, storage and tenant isolation, the audit chain, the bus, the rule engine, scoring, decision, actions and rollback, collectors, the API, reports and the CLI. What's not: integration breadth, a tuned rule corpus, an endpoint agent, and the kind of field mileage that reveals the ugly edge cases. If you're looking for something to run in production this week, this isn't it.

**7. "License and governance?"**
Apache-2.0, with a `NOTICE` file. Development is under the DCO, not a CLA — there's no copyright assignment, and contributions carry a sign-off. Merges need at least one maintainer approval, and there's a written governance document referenced from `CONTRIBUTING.md` covering who decides what and how disagreement gets resolved. One thing is treated as a constitutional invariant rather than a preference: **no offensive capability**. No exploit code, no payloads, no aggressive or high-rate scanning, no brute-forcing, no hack-back. A PR that adds any of it is closed without review. That's the one rule I'd rather over-document than leave implicit.

**8. "How do I contribute, or just try it?"**
Clone the repo, install it, run the demo tenant, and run the tests: `python -m unittest discover -s tests -t . -v` (the suite is stdlib unittest; pytest also works and runs in CI for compatibility). The most useful reports right now are things I can't reproduce alone: install failures on a specific distro, the retention purge behaving unexpectedly, and any case where a connector you configured doesn't match what the playbook documents. There's a `good first issue` label with an explicit rule attached — if it's labeled that way, a maintainer has committed to keeping it under roughly a day of work with no open design questions. If something in the interface contract is wrong, say so; it's a written document and it's meant to be argued with.

**9. "Is there any telemetry?"**
No telemetry mechanism appears in Thot Secure's interface contract. That's a statement about the contract, not a warranty, and the honest answer is that it should be confirmed by reading the code — the defaults point inward (SQLite, in-memory bus, server-rendered UI with no CDN), and outbound traffic is opt-in: a configured connector, a notification webhook, or NATS if you set `THOT_BUS=nats`. If you want to verify it independently, that's a welcome contribution, and I'd rather be corrected than have someone take my word for it.

---

# 6. Aide au répondant (FR)

- **Ordre de priorité des réponses** : question technique sur le comportement par défaut > question de conception > question de licence > remarque de ton. Une critique de ton correctement argumentée se traite par un remerciement et un fait, jamais par une justification.
- **Quand on ne sait pas** : répondre « je ne sais pas, je vérifie et je reviens » puis revenir effectivement dans le fil. Une réponse inventée sera démontée publiquement, et c'est mérité.
- **Quand une affirmation du post est fausse** : l'écrire dans le fil (« you're right, the post says X; the code does Y ») et corriger la source. Ne pas éditer discrètement.
- **Ne jamais** : comparer Thot Secure à un concurrent de façon dénigrants, citer un chiffre non mesuré, annoncer une fonctionnalité non livrée sans l'étiqueter « roadmap », parler dons, ou répondre à une critique par une liste de fonctionnalités.
- **Un chiffre d'exemple ?** Tout chiffre illustratif doit porter la mention « ordre de grandeur à remplacer ». Dans un fil HN, la seule option raisonnable est de ne pas en donner.

---

# 7. Checklist avant soumission (FR)

- [ ] Le dépôt public est accessible, la licence affichée est Apache-2.0, le `NOTICE` existe, la version est `0.1.0`.
- [ ] Le fichier compose et la commande de démarrage ont été testés depuis un clone propre.
- [ ] `GOVERNANCE.md` existe bien dans le dépôt public (il est référencé par `CONTRIBUTING.md`).
- [ ] La suite de tests a été exécutée et son résultat réel est connu, y compris ses échecs éventuels.
- [ ] La formulation sur la télémétrie est un constat de lecture du contrat, pas une garantie.
- [ ] Le titre ne contient aucun adjectif marketing et fait moins de 80 caractères.
- [ ] Le texte ne contient aucune liste de fonctionnalités gonflée : limites d'abord, faits vérifiables ensuite.
- [ ] Aucun chiffre non mesuré ; aucun chiffre d'exemple sans étiquette « ordre de grandeur à remplacer ».
- [ ] Le préfixe `Show HN` et les règles de titres ont été revérifiés le jour J.
- [ ] L'auteur a deux heures de disponibilité bloquées dans son agenda.
- [ ] Aucun lien de don, de financement ou de boutique nulle part dans le fil.
