```yaml
canal: Mastodon (instance infosec / communauté blueteam)
langue: en
format: thread de 7 posts, texte seul, un extrait YAML et des commandes CLI
objectif: "obtenir un examen critique par des pairs blueteam (approche, limites assumées) et des contributions de règles de détection"
mot_cle_principal: "policy-as-code"
longueur: "500 caractères maximum par post (défaut Mastodon, compte brut, retours à la ligne inclus) ; 7 posts"
heure_optimale_publication: "mardi ou mercredi, 13 h 00 - 15 h 00 UTC ; un fil technique long se publie en début de semaine pour rester visible dans les timelines chronologiques"
regles_specifiques_du_canal:
  - "500 caractères par post par défaut : au-delà, le post est refusé ou tronqué selon l'instance — vérifier la limite de son instance avant publication"
  - "les instances infosec tolèrent très mal l'auto-promotion : apporter la matière technique avant le lien, et le lien en toute fin de fil"
  - "hashtags uniquement dans le dernier post du fil (usage Mastodon : ils servent à la découverte, pas à la décoration) — 4 ou 5 maximum"
  - "CW (content warning) non nécessaire : aucun contenu choquant ; ne pas mettre de CW « auto-promo » qui masquerait le fil"
  - "texte alternatif obligatoire sur toute image ; une capture de terminal doit être recopiée en texte"
  - "pas de repost en boucle, pas de relance des personnes qui n'ont pas répondu, pas de message privé non sollicité"
  - "répondre aux critiques techniques publiquement et dans le fil ; ne pas supprimer une réponse critique"
dons: "AUCUNE adresse de don dans ce fichier (choix éditorial : les fils Mastodon n'en portent pas). Adresses officielles : newsletter, README.md, .github/FUNDING.yml, GET /ui/support, docs/support.md."
autopromotion: "1 lien au total, dans le dernier post ; matière technique d'abord ; disclosure d'auteur en réponse au dernier post si on est mainteneur ; pas de campagne de republication."
```

# Mastodon (infosec) — thread de lancement Thot Secure v0.1.0 (EN)

Angle : infosec / blueteam. Le problème, l'approche, un extrait de code, les limites assumées, l'appel à contribution. Les posts contenant du code sont multi-lignes : le compte inclut les retours à la ligne (comme le fait Mastodon).

---

### Post 1 — le problème

Longueur : **255/500 caractères**

<!--post:1-->
```text
Alert volume is rarely the hard part of blue-team work. The hard part is automation you cannot audit, cannot undo, and cannot explain at 03:00. Two questions decide whether a response tool is usable at all: who was allowed to act, and how do I reverse it?
```

### Post 2 — l'approche

Longueur : **283/500 caractères**

<!--post:2-->
```text
Thot Secure v0.1.0 is a defensive SOAR/CSPM built on three ideas: policy-as-code for decisions, reversibility for actions, and a hash-chained audit log for evidence. Apache-2.0, Python/FastAPI, SQLite for the MVP, embedded console with no Node build. No offensive capability, by design.
```

### Post 3 — une politique, en YAML

Longueur : **290/500 caractères**

<!--post:3-->
```text
A decision policy is a versioned YAML file. This one auto-blocks web findings only when the tenant itself is in auto mode:

when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  tenant.mode: [auto]
then:
  decision: auto
  playbook: block-source-ip
  dry_run: false
```

### Post 4 — les garde-fous, appliqués après la politique

Longueur : **323/500 caractères**

<!--post:4-->
```text
Guard-rails run after the policy and cannot be overridden by it: hourly action cap per tenant, cooldown per (tenant, playbook, target), autonomy-allowlist targets never touched, global dry_run wins over everything. Plan a response without side effects first:

thotsecure actions plan --finding <id> --playbook block-source-ip
```

### Post 5 — la réversibilité et le mode simulé

Longueur : **320/500 caractères**

<!--post:5-->
```text
Every shipped playbook carries a rollback block; a playbook without one is rejected at load time. POST /actions/{id}/rollback undoes it while the rollback window is open. An unconfigured connector runs in simulated mode, returns a rollback token and logs simulated: true — safe to wire up before you own any credentials.
```

### Post 6 — les limites assumées

Longueur : **304/500 caractères**

<!--post:6-->
```text
Limits we are not hiding in v0.1.0: SQLite is the storage backend (PostgreSQL/TimescaleDB is roadmap), connectors stay simulated until configured, Rego needs an OPA binary present, patch-dependency opens a PR and never merges it, probe only audits targets you declared. Pre-1.0: schemas can still change.
```

### Post 7 — appel à contribution + lien + hashtags

Longueur : **340/500 caractères**

<!--post:7-->
```text
Highest-value contribution is a detection rule: one YAML file, one test that must match, one look-alike that must not, and the false positives you expect written down. Tests run on the standard library alone:

python -m unittest discover -s tests -t . -v

https://github.com/thotsecure/thot-secure
#infosec #blueteam #opensource #SOAR #detection
```

---

## Variante A/B — post 3 (extrait de code alternatif : la règle de détection)

Angle différent : on montre la détection plutôt que la décision. Même longueur cible, à substituer au post 3, thread inchangé ailleurs.

Longueur : **371/500 caractères**

<!--post:8-->
```text
Detection rules are YAML too. A rule declares its evidence, its expected false positives and its remediation — so the person on call knows what to do with the finding:

id: AO-WEB-001
severity: high
match:
  all:
    - field: labels.path
      op: regex
      value: "(?i)(union[\\s/*]+select|or\\s+1=1)"
false_positives:
  - The word "union" in a free-text search field.
```

---

## Variante A/B — post 1 (hook alternatif)

Angle différent : entrer par l'audit et la preuve, pas par la charge d'alertes.

Longueur : **253/500 caractères**

<!--post:9-->
```text
An audit log you can edit is not evidence. Thot Secure v0.1.0 chains every record by hash: modify one row and the chain breaks at that exact point, and GET /api/v1/audit/verify tells you where. Export it as jsonl or cef to your SIEM, no proprietary format.
```

---

## Notes de publication

- **Heure optimale :** mardi ou mercredi, 13 h - 15 h UTC. Les timelines Mastodon sont chronologiques : un fil posté le matin en Europe reste visible l'après-midi en Amérique du Nord.
- **Hashtags :** uniquement dans le dernier post, comme indiqué — `#infosec #blueteam #opensource #SOAR #detection`. Cinq, pas trente : ce sont ceux qui servent réellement la découverte sur les instances infosec.
- **Un seul lien :** `https://github.com/thotsecure/thot-secure` dans le post 7. Ne pas le répéter en réponse au fil.
- **Découpage :** poster les 7 posts à la suite en auto-réponse. Chaque post doit rester compréhensible seul, mais le fil doit se lire d'un bloc — d'où les phrases de liaison dans les posts 4, 5 et 6.
- **Comptage :** compte brut, retours à la ligne inclus, avec une marge volontaire sous 500 pour absorber les différences d'instances (certaines acceptent 1000, d'autres restent à 500). En cas de dépassement sur une instance stricte, couper le post 6 en deux plutôt que de supprimer une limite assumée.
- **Pas de chiffre d'impact :** ce fil n'annonce aucun gain mesuré. Les seuls chiffres cités sont des faits du produit (codes de sortie 0/1/2/3, seuil `gte: 70`, 500 événements par lot d'ingestion). Aucun benchmark, aucune moyenne inventée.
- **Sigles :** `MTTA` et `MTTR` sont les deux moyennes exposées par `GET /api/v1/stats/overview`. MTTD n'est pas exposé par le contrat : ne pas l'employer, même en réponse à une question.
- **Vocabulaire :** « finding » et non « alert » ; « counter-measure », pas « remediation automatique » ni « réponse autonome ».
