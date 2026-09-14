```yaml
canal: Bluesky (AT Protocol)
langue: en
format: thread court de 5 posts, texte seul
objectif: "faire passer une seule idée vérifiable — réversibilité + dry-run par défaut + audit chaîné — avec une commande CLI concrète"
mot_cle_principal: "reversible automation"
longueur: "300 caractères maximum par post (compte brut) ; 5 posts"
heure_optimale_publication: "mardi ou jeudi, 15 h 00 - 17 h 00 UTC ; Bluesky récompense les fils courts postés quand l'audience technique US est réveillée"
regles_specifiques_du_canal:
  - "300 caractères par post : compter avant de publier, un post trop long casse le fil"
  - "ton sec et factuel, un fait par post, pas d'emoji, pas de slogan"
  - "auto-réponse pour former le fil ; ne pas publier les 5 posts en posts racines séparés"
  - "pas de hashtag dans le corps du fil : Bluesky n'utilise pas les hashtags comme découverte principale, ils s'affichent comme du bruit"
  - "un seul lien dans tout le fil, en post 5 ; Bluesky n'a pas de raccourcisseur imposé"
  - "ajouter un texte alternatif si une capture est jointe ; ne jamais montrer de clé API ni de donnée client"
  - "pas de demande de repost, pas de follow-for-follow"
dons: "AUCUNE adresse de don dans ce fichier (choix éditorial : les fils Bluesky n'en portent pas). Adresses officielles : newsletter, README.md, .github/FUNDING.yml, GET /ui/support, docs/support.md."
autopromotion: "1 lien au total, en dernier post ; pas de vente, pas de DM, pas de relance ; le contenu doit rester utile sans clic."
```

# Bluesky — thread Thot Secure v0.1.0 (EN)

Angle imposé : **la garantie de réversibilité + le dry-run par défaut + l'audit chaîné**, avec une commande CLI concrète. Chaque post tient sur une seule ligne : le compte annoncé est donc exactement vérifiable.

---

## Thread principal (5 posts)

### Post 1 — le point de départ

Longueur : **172/300 caractères**

<!--post:1-->
```text
Thot Secure v0.1.0: a defensive SOAR/CSPM, Apache-2.0. Dry-run is the default — THOT_DRY_RUN=true. Nothing real is executed until you lift it, globally or for one tenant.
```

### Post 2 — la réversibilité

Longueur : **270/300 caractères**

<!--post:2-->
```text
Reversibility is not optional here. Every shipped playbook carries a rollback block unless it is explicitly marked irreversible — and then it needs human approval every time. thotsecure actions rollback <id> undoes an executed action while its rollback window is open.
```

### Post 3 — la décision

Longueur : **200/300 caractères**

<!--post:3-->
```text
Decisions are policy-as-code: auto, require_approval, notify_only, ignore. No matching policy means notify_only. Going silent requires an explicit ignore rule — it is never what you get by omission.
```

### Post 4 — la preuve

Longueur : **217/300 caractères**

<!--post:4-->
```text
Audit records are chained: seq, ts, actor, role, action, target, before, after, prev_hash. thotsecure audit verify exits 0 when the chain is intact and 3 when it is broken — not 1, so scripts can tell the two apart.
```

### Post 5 — essayer + lien unique

Longueur : **199/300 caractères**

<!--post:5-->
```text
Five minutes, no credentials: thotsecure init-db, thotsecure demo --tenant demo, thotsecure doctor. Unconfigured connectors run simulated and return a rollback token. github.com/thot-corp/thot-secure
```

---

## Variante A/B — hook uniquement (post 1)

Angle différent : on part de la question « comment annuler », pas de la liste des garanties. Thread identique à partir du post 2.

Longueur : **200/300 caractères**

<!--post:6-->
```text
Most response automation answers one question: what will it do? Thot Secure v0.1.0 answers the other one first: how do I undo it? Dry-run on by default, rollback on every playbook, hash-chained audit.
```

**A/B sur le post 4 (variante possible, même longueur cible)** — utile si le public est plus « SOC » que « dev » :

Longueur : **218/300 caractères**

<!--post:7-->
```text
Every state change is appended to a hash-chained log: actor, role, action, before, after, prev_hash. Tamper with one row and the chain breaks at that point: GET /api/v1/audit/verify returns {valid, records, broken_at}.
```

---

## Variante du post de clôture (post 5 alternatif)

Angle différent : contribution plutôt qu'essai immédiat. Conserve **l'unique lien** — remplacer le post 5, ne jamais l'ajouter.

Longueur : **214/300 caractères**

<!--post:8-->
```text
Highest-value contribution right now: a detection rule. One YAML file, one test that must match, one look-alike test that must not, documented false positives. DCO sign-off, no CLA: github.com/thot-corp/thot-secure
```

---

## Notes de publication

- **Heure optimale :** mardi ou jeudi, 15 h - 17 h UTC. Éviter de publier un fil technique le week-end : la portée retombe avant les réponses.
- **Comptage :** compte brut de la ligne, espaces compris. Bluesky mesure les graphèmes : les accents et les apostrophes typographiques peuvent valoir plus d'un octet mais restent un seul caractère — ce fil est intégralement en ASCII pour supprimer le risque.
- **Pas de hashtags :** ce choix est volontaire. Sur Bluesky, la découverte passe par les feeds et les reposts, pas par les hashtags ; quatre hashtags en fin de fil y ressemblent à du démarchage. Les hashtags demandés (`#infosec #blueteam #opensource #SOAR`) sont portés par le thread Mastodon, canal où ils servent réellement.
- **Un seul lien :** `github.com/thot-corp/thot-secure` en post 5 uniquement. Si le fil est reposté, conserver la même forme.
- **Longueur de l'URL :** version courte sans schéma (32 caractères) pour rester sous les 300 sur le dernier post. Ne pas utiliser de raccourcisseur tiers.
- **Pas de chiffre d'impact :** aucune métrique de gain n'est affirmée. Le contrat d'interface expose des compteurs et des moyennes (MTTA/MTTR dans `GET /api/v1/stats/overview`), pas de benchmark ; MTTD n'y figure pas et ne doit pas être cité.
