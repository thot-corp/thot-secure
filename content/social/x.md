```yaml
canal: X (Twitter)
langue: en
format: thread de 6 posts, texte seul (pas de média requis)
objectif: "faire comprendre la différence de conception (dry-run par défaut, réversibilité, audit chaîné) et convertir vers le dépôt GitHub"
mot_cle_principal: "defensive SOAR"
longueur: "280 caractères maximum par post (compte brut, espaces et ponctuation inclus) ; 6 posts ; un seul lien dans tout le thread, en post 6"
heure_optimale_publication: "mardi, mercredi ou jeudi, 14 h 00 - 16 h 00 UTC (matin US Eastern / après-midi Europe) ; éviter 00 h - 06 h UTC et le vendredi soir"
regles_specifiques_du_canal:
  - "aucun clickbait, aucune fausse rareté, aucun « 🚨 », pas d'emoji-martelage (zéro emoji sur ce thread)"
  - "un seul lien dans tout le thread, en post 6 : X réduit la portée des posts contenant un lien externe"
  - "post 1 = hook factuel : une affirmation vraie et vérifiable, pas une promesse"
  - "thread auto-répondu (chaque post répond au précédent) pour que le fil se lise d'un bloc"
  - "pas de demande de like/repost, pas de sondage d'engagement, pas de tag de comptes non concernés"
  - "si une capture d'écran est ajoutée, texte alternatif obligatoire et aucune donnée client ni clé API visible"
  - "répondre aux réponses techniques dans l'heure ; corriger publiquement toute imprécision signalée"
dons: "AUCUNE adresse de don dans ce fichier. Les threads X ne s'y prêtent pas ; les adresses officielles vivent uniquement dans la newsletter, README.md, .github/FUNDING.yml, GET /ui/support et docs/support.md."
autopromotion: "1 lien au total, en fin de thread uniquement ; disclosure d'auteur possible en réponse au post 6 (« maintainer here ») ; pas de DM, pas de relance automatique, pas de cross-post du même texte d'un réseau à l'autre."
```

# X — thread de lancement Thot Secure v0.1.0 (EN)

6 posts. Chaque post est **une seule ligne** dans son bloc : le compte de caractères ci-dessous est donc directement vérifiable (aucun retour à la ligne caché).

---

## Thread principal

### Post 1 — hook factuel

Longueur : **268/280 caractères**

<!--post:1-->
```text
Thot Secure v0.1.0 — a defensive SOAR/CSPM built the other way round: dry-run is the default (THOT_DRY_RUN=true), every playbook ships with a rollback unless it is explicitly irreversible, every decision lands in a hash-chained audit log. Apache-2.0, Python/FastAPI.
```

### Post 2 — le problème

Longueur : **216/280 caractères**

<!--post:2-->
```text
The problem is not detection volume. It is automation you cannot audit and cannot undo. If a tool can block an IP, the real questions are: which policy decided, who approved it, and how do I reverse it in 30 seconds?
```

### Post 3 — la décision

Longueur : **216/280 caractères**

<!--post:3-->
```text
Decisions are policy-as-code in YAML, with four outcomes: auto, require_approval, notify_only, ignore. No matching policy means notify_only. Going silent requires an explicit ignore rule — it is never the fallback.
```

### Post 4 — les garde-fous

Longueur : **227/280 caractères**

<!--post:4-->
```text
Guard-rails sit outside the policy and cannot be overridden by it: hourly action cap per tenant, cooldown per (tenant, playbook, target), autonomy-allowlist targets never touched, and a global dry_run that wins over everything.
```

### Post 5 — l'audit chaîné

Longueur : **204/280 caractères**

<!--post:5-->
```text
Audit records are chained by hash: sha256(seq|ts|tenant|actor|role|action|target|before|after|prev_hash). GET /api/v1/audit/verify returns {valid, records, broken_at}. Export as jsonl or cef to your SIEM.
```

### Post 6 — essayer + appel à contribution (seul lien du thread)

Longueur : **243/280 caractères**

<!--post:6-->
```text
Try it with no credentials: thotsecure init-db, thotsecure demo --tenant demo, thotsecure audit verify. Unconfigured connectors run simulated and return a rollback token. Code, rules, good first issues: https://github.com/thot-corp/thot-secure
```

---

## Variante A/B — hook uniquement (post 1)

Angle différent : on attaque par la confiance accordée à l'automatisation, pas par l'ordre des garanties. À tester en remplacement du post 1, thread identique à partir du post 2.

Longueur : **226/280 caractères**

<!--post:7-->
```text
Most SOAR asks you to trust the automation first and prove it later. Thot Secure v0.1.0 flips that default: nothing executes until you lift dry-run, every action is reversible, every decision is hashed into an append-only log.
```

**Hashtags du thread (à placer en fin de post 6 seulement) :** `#infosec #blueteam #opensource #SOAR`

---

## Variante du post de clôture (post 6 alternatif)

Angle différent : contribution et gouvernance plutôt qu'essai en 5 minutes. Conserve **l'unique lien** du thread — ne jamais publier cette variante en plus du post 6, seulement à sa place.

Longueur : **210/280 caractères**

<!--post:8-->
```text
v0.1.0 is pre-1.0 on purpose and Apache-2.0. Good first issues are scoped to about a day of work, DCO sign-off, no CLA. The one hard rule: no offensive capability. Repo: https://github.com/thot-corp/thot-secure
```

---

## Notes de publication

- **Heure optimale :** mardi/mercredi/jeudi 14 h - 16 h UTC. Un thread technique posté entre 20 h et 23 h UTC atteint surtout l'Europe du soir et rate la matinée US du lendemain.
- **Un seul lien :** `https://github.com/thot-corp/thot-secure` apparaît une fois, en post 6 (ou dans sa variante). Ne pas le répéter en réponse.
- **Comptage :** les comptes annoncés sont des comptes **bruts** de caractères, mesurés sur la ligne du bloc `text`. X applique par ailleurs sa propre règle de comptage (une URL est comptée 23 caractères quelle que soit sa longueur), donc les posts contenant le lien sont encore plus confortables en pratique que le compte affiché.
- **Longueur du lien :** l'URL du dépôt fait 34 caractères bruts. Si le compte d'un post approche 280, raccourcir le texte plutôt que l'URL — un lien raccourci par un tiers (bit.ly & co) est un signal négatif pour un projet de sécurité.
- **Fil :** publier les 6 posts en une seule fois, en auto-réponse, pour que le thread soit lisible immédiatement. Ne pas étaler sur plusieurs jours.
- **Correction :** si un chiffre ou un sigle est contesté en réponse, corriger dans le fil avec un post de correction visible plutôt que par message privé.
- **Pas de chiffre d'impact :** ce thread n'affirme aucun gain mesuré. Ne pas ajouter de pourcentage (« -70 % de MTTR ») : le contrat d'interface n'expose que les compteurs et moyennes, pas de benchmark.
- **Sigles :** le contrat expose MTTA/MTTR (`GET /api/v1/stats/overview`). MTTD n'existe pas dans le contrat — ne pas l'employer, même en réponse.
