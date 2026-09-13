```yaml
canal: "Reddit — r/selfhosted"
langue: "Post en anglais (sous-reddit anglophone) ; stratégie, notes de canal, checklist de vérification réseau et notes d'objection en français, dans des sections séparées et étiquetées"
format: "Post texte (self post) — un seul lien, celui du dépôt, dans le corps. Pas de lien de soumission externe (les liens directs sont mal reçus et souvent filtrés)."
objectif: "Toucher l'audience auto-hébergement sur des critères qu'elle vérifie elle-même : démarrage sans compte ni clé tierce, SQLite par défaut, console embarquée sans chaîne de build Node, rien à configurer avant d'avoir des identifiants. Obtenir des retours d'installation réelle, pas des votes."
mot_cle_principal: "self-hosted SOAR"
longueur: "Fichier de travail ≈ 1 800 mots ; post ≈ 550 à 700 mots (cette audience coupe au-delà de ~800 mots)"
meilleur_creneau_publication: "Hypothèse de travail non mesurée : samedi ou dimanche matin en Europe (≈ 08:00–11:00 UTC), ou mardi→jeudi 15:00–18:00 UTC. r/selfhosted a un trafic de week-end marqué ; à confirmer sur place. Ne pas présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : règles du sous-reddit sur l'auto-promotion d'un projet personnel, obligation éventuelle d'un flair, interdiction ou limitation des sollicitations (dons, financement, crypto), politique sur les liens de dépôt et les comptes neufs, seuils de karma éventuels. Ces règles changent régulièrement et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — r/selfhosted tolère l'annonce d'un projet open source mais encadre la promotion et interdit en général toute sollicitation financière, en particulier les adresses de cryptomonnaie. Conséquences : (1) disclosure de la qualité d'auteur en première ligne ; (2) UN SEUL lien dans le post (le dépôt) ; (3) AUCUNE mention de don, de financement, de sponsor ou de page de soutien, même en réponse à une question — répondre une fois que le sujet n'est pas abordé ici et s'arrêter ; (4) répondre aux questions d'installation en priorité sur toute autre considération ; (5) ne pas demander d'étoiles, de votes ou de partage."
```

---

# 1. Positionnement sur r/selfhosted (FR)

**L'audience.** r/selfhosted ne juge pas un projet sur son architecture : elle juge sur *est-ce que je peux le lancer ce soir, chez moi, sans compte chez personne*. Trois questions reviennent toujours : combien de conteneurs, quelle base de données, et est-ce que je dois créer un compte quelque part. Ce post y répond dans cet ordre, avant toute considération de sécurité.

**L'angle, et pourquoi il est honnête.** Thot Secure ne prétend pas être un outil « simple » : c'est un SOAR/CSPM, avec des règles YAML, des politiques YAML et des playbooks YAML. Ce serait mentir que de le vendre comme un `docker run` d'une ligne. L'angle retenu est différent et vérifiable : **la v0.1.0 est sûre à installer avant d'avoir le moindre identifiant**, parce qu'un connecteur non configuré tourne en mode simulé. On peut donc découvrir l'outil, voir la chaîne de décision, vérifier que le dry-run est bien actif, et ne brancher un vrai pare-feu que plus tard — ou jamais.

**Ce qu'il ne faut surtout pas faire sur ce canal** : promettre une intégration qui n'existe pas, prétendre que « tout est branché », ou passer sous silence le fait que c'est de l'alpha (`Development Status :: 3 - Alpha`). Le public de r/selfhosted pardonne l'inachevé ; il ne pardonne pas le flou.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Week-end matin Europe ou mardi→jeudi 15:00–18:00 UTC (hypothèse non mesurée, à confirmer). |
| Longueur | 550–700 mots. Fournir les commandes exactes plutôt que des paragraphes : c'est ce que cette audience lit réellement. |
| Participation préalable | Recommandée et non négociable en pratique : plusieurs commentaires utiles dans r/selfhosted avant de publier, en particulier des réponses à des questions d'installation. Un compte sans historique sera suspecté de spam. |
| Flair | Le flair exact dépend du sous-reddit ; si un flair « Release » ou équivalent existe, il faut le vérifier et l'utiliser le jour J. |
| Disponibilité | Rester 4 heures minimum. Les questions portent presque toujours sur le port, le volume, les droits du conteneur et la sauvegarde du fichier SQLite. |
| Suite | Un post de suivi n'a de sens qu'après avoir corrigé ce que les commentaires auront révélé. Ne pas publier de suivi à moins de 3–4 semaines d'écart. |

---

# 3. Faits vérifiés dans le contrat (FR) — base du post

Ne rien affirmer qui ne figure pas ici, et ne pas citer cette section dans le post (c'est un aide-mémoire interne).

| Affirmation | Source contractuelle |
|---|---|
| Base de données : SQLite par défaut, `THOT_DB_URL=sqlite:///./data/thotsecure.db` ; PostgreSQL/TimescaleDB seulement documenté | §9 ; §9 (colonne défaut et rôle) |
| Bus d'événements : `THOT_BUS=memory` par défaut, alternatives `memory \| sqlite \| nats`, `THOT_NATS_URL=nats://127.0.0.1:4222` | §9 ; §2 (`bus/`) |
| Le cœur `thotsecure.core` ne dépend que de la stdlib + `pydantic`/`PyYAML` ; FastAPI, Jinja2 et uvicorn sont des dépendances de la couche API | §1 invariants (5) ; §2 |
| Console embarquée en Jinja2 + JS, **aucun build Node requis** ; le dashboard React+TS (`web/`) est optionnel | §4.9 ; §2 |
| Écoute : `THOT_HOST=0.0.0.0`, `THOT_PORT=8080` | §9 |
| TLS : `THOT_TLS_ENABLED=false` par défaut, HTTPS direct sinon reverse-proxy ; le chiffrement au repos repose sur `THOT_SECRET_KEY` + disque chiffré documenté | §9 ; §10 |
| Rétention : `THOT_RETENTION_DAYS=30` (purge des événements) | §9 |
| Connecteur non configuré ⇒ mode simulé (`null` / `simulation`) : retourne un `rollback_token`, journalise `simulated: true` ; **c'est le comportement par défaut du MVP** | §7 |
| Clé API d'amorçage `THOT_BOOTSTRAP_API_KEY=ao_dev_local_change_me`, à changer (⚠️) ; `THOT_SECRET_KEY` est généré par défaut avec un avertissement | §9 |
| Clés API stockées hachées (`scrypt`), jamais en clair | §10 |
| Garde-fou anti-abus sur l'ingestion : `THOT_RATE_LIMIT_PER_MIN=600`, taille de corps limitée, pas d'`eval` de template utilisateur, regex de règle compilées avec un délai d'exécution maximal | §9 ; §10 |
| Observabilité locale : `GET /metrics` (exposition Prometheus, réseau interne), `GET /healthz`, `GET /readyz` (vérifie DB + bus + règles → `200` ou `503`), `GET /version` | §4.1 |
| Cibles déclarées : `THOT_TARGETS_FILE=./config/targets.yaml` — le périmètre autorisé par tenant ; `probe` n'audite **que** des cibles déclarées possédées par le tenant, opt-in explicite | §9 ; §10 |
| Défauts de sûreté : `THOT_DRY_RUN=true`, `THOT_AUTONOMY=supervised` | §9 ; §1 invariants (1) |
| Déploiement : `deploy/` contient Dockerfile, compose, k8s, helm, terraform, ansible | §2 |

**Point de vigilance à ne pas transformer en slogan — l'air-gap et la télémétrie.** Le contrat ne décrit **aucun** mécanisme de télémétrie, de remontée d'usage, de compte en ligne ou d'appel à un service tiers. C'est un constat de lecture du contrat, pas une garantie produit : le post doit être formulé comme « aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface ; à confirmer par audit du code avant publication ». Deux formulations à bannir : « zéro télémétrie » présenté comme un engagement contractuel, et « fonctionne en air-gap » présenté comme testé. Un air-gap réel suppose des dépendances installables hors ligne et l'absence de point de sortie réseau : c'est à **prouver** par la checklist du §4 avant de l'écrire.

---

# 4. Checklist de vérification réseau — à exécuter par l'auteur AVANT de poster (FR)

But : pouvoir écrire une phrase du post sans la surinterpréter. Chaque case doit être cochée sur une machine de test, pas déduite de la documentation.

**A. Sans réseau sortant**
- [ ] Installation depuis les seules dépendances déjà présentes (cible `install-offline` du `Makefile` du dépôt) sur une machine sans accès sortant : succès noté ou échec noté.
- [ ] `pip install` du paquet + des dépendances (`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `PyYAML`, `Jinja2`) depuis un miroir local ou un cache, sans accès Internet.
- [ ] `thotsecure doctor` exécuté hors ligne : comportement observé noté tel quel.
- [ ] `thotsecure init-db` puis `thotsecure serve` hors ligne : le serveur répond-il sur `THOT_HOST:THOT_PORT` ?
- [ ] `thotsecure demo --tenant demo` hors ligne : le jeu de données et les actions de démonstration se produisent-ils sans réseau ?
- [ ] La console embarquée (`GET /`) s'affiche-t-elle sans requête vers un CDN (vérifier les sources CSS/JS dans l'onglet réseau du navigateur) ?
- [ ] `GET /ui/static/*` sert bien les ressources localement.

**B. Preuve d'absence de sortie réseau**
- [ ] Capture du trafic sortant de l'hôte pendant un cycle complet (démarrage, ingestion, détection, action en mode simulé, vérification d'audit) : aucune connexion sortante inattendue. Méthode à choisir selon l'environnement (pare-feu local en refus par défaut, journalisation des connexions, ou machine sans passerelle) — l'important est de documenter **la méthode** employée, pas seulement le résultat.
- [ ] Recherche dans le code de tout mécanisme de remontée : occurrences de télémétrie, d'analytics, d'envoi automatique de rapports d'erreur, d'appel à un service d'identité. Noter les occurrences trouvées, y compris bénignes.
- [ ] Vérifier que les seuls appels sortants possibles sont ceux explicitement configurés : connecteurs (`cloudflare`, `aws-waf`, `modsecurity`, `nginx-local`, `null`), webhooks de notification, et `THOT_NATS_URL` si `THOT_BUS=nats`.
- [ ] Vérifier que le mode simulé n'émet aucune requête vers le service tiers simulé (c'est le point qui rend la promesse « installable avant credentials » vraie ou fausse).

**C. Reproduction du parcours d'installation**
- [ ] `docker compose up` (ou la cible `compose-up` du `Makefile`) depuis un clone propre : **vérifier d'abord qu'un fichier compose existe bien dans `deploy/` le jour de la publication** — le contrat prévoit cette arborescence, il faut la constater sur disque.
- [ ] Note du temps de démarrage observé et de la consommation mémoire — sans en faire un chiffre public, seulement pour répondre aux questions.
- [ ] Persistance : le fichier `./data/thotsecure.db` survit-il à un redémarrage du conteneur ? Le volume est-il correctement monté ?
- [ ] Rétention : `THOT_RETENTION_DAYS=30` purge-t-il effectivement les événements anciens lors d'un test accéléré ?
- [ ] Sauvegarde du SQLite : arrêt propre du service et copie du fichier — procédure à décrire dans une réponse, pas dans le post.
- [ ] `THOT_SECRET_KEY` défini explicitement dans le déploiement de test, et `THOT_BOOTSTRAP_API_KEY` changé : confirmer que le service le signale correctement.

**D. Sécurité du déploiement exposé**
- [ ] L'exposition d'origine (`0.0.0.0:8080`) est bien comprise : derrière un reverse-proxy, faut-il lier à `127.0.0.1` via `THOT_HOST` ?
- [ ] `THOT_ENV=prod` : erreurs masquées, défauts durcis — comportement constaté.
- [ ] `GET /metrics` et `GET /readyz` : confirmer qu'ils sont publics et qu'ils doivent donc rester sur un réseau interne, comme l'indique le contrat.
- [ ] Vérifier qu'aucune donnée d'un autre tenant n'est visible après création de deux tenants de test (le contrat annonce un test d'isolation en CI : le reproduire soi-même).

**Règle d'écriture qui découle de cette checklist** : si une case n'a pas pu être vérifiée, la phrase correspondante est retirée du post. Aucune case cochée par déduction.

---

# 5. TEXTE DU POST — à copier tel quel (EN)

> **Flair :** à vérifier le jour J (chercher un flair de type « Release » / « Showcase »).
>
> **Titre :** `Thot Secure v0.1.0 – self-hosted defensive SOAR/CSPM: SQLite, no cloud account, unconfigured connectors run simulated`
>
> **Corps :**

I'm the author. Thot Secure is a defensive SOAR/CSPM (event collection → YAML detection rules → risk score → policy-based decision → reversible playbook). It's Apache-2.0 and alpha. Repo: https://github.com/thotsecure/thot-secure — the only link here.

**What you can actually run today.** Defaults are boring on purpose:

- SQLite, no external DB: `THOT_DB_URL=sqlite:///./data/thotsecure.db`
- In-process event bus by default: `THOT_BUS=memory` (`sqlite` and `nats` are the alternatives)
- `THOT_HOST=0.0.0.0`, `THOT_PORT=8080`; `THOT_TLS_ENABLED=false` by default, i.e. either a reverse proxy or direct TLS — your call
- Retention: `THOT_RETENTION_DAYS=30`
- `thotsecure.core` depends only on the stdlib plus pydantic/PyYAML. FastAPI, uvicorn and Jinja2 sit in the API layer. So the core is usable as a library in a script, without running a server.
- The console is server-rendered Jinja2 + plain JS with **no Node build step**. There's an optional React+TS dashboard in `web/`, but you don't need a Node toolchain to see anything.

**The part that matters for self-hosting: it's safe to install before you have any credentials.** A connector that isn't configured runs in **simulated** mode — the playbook returns a rollback token and the audit record is flagged `simulated: true`. That's the default behaviour of the MVP, not a degraded fallback. You can install it, ingest your own logs, watch findings appear, watch the decision engine pick a playbook, and *not* let it touch a firewall until you deliberately configure a connector. And it ships with `THOT_DRY_RUN=true` and `THOT_AUTONOMY=supervised` as the defaults.

**On network egress — stated precisely, because it's the claim people care about here.** No telemetry mechanism appears in Thot Secure's interface contract. That is a statement about the contract, not a warranty: it needs confirming by reading the code before you rely on it, and the honest way to present it is "I need to confirm this by audit before publication". What I can say concretely is that the defaults point inward — SQLite, in-memory bus, server-rendered UI with no CDN — and that outbound traffic is something you opt into: a connector (Cloudflare, AWS WAF, ModSecurity, nginx-local, or `null`), a notification webhook, or NATS if you set `THOT_BUS=nats`. Before posting this I'm going through a network-verification pass: install with no outbound access, capture egress during a full cycle, and check that simulated mode makes zero calls to the simulated third party. I'd rather understate this than have someone find an unexpected connection.

**Two things to change before you expose it**, straight from the docs and worth repeating: `THOT_BOOTSTRAP_API_KEY` defaults to `ao_dev_local_change_me` and must be replaced, and `THOT_SECRET_KEY` is auto-generated with a warning — set it yourself. Note that the API surface is also public by design in places: `GET /metrics` and `GET /readyz` are unauthenticated, so keep them on an internal network.

**Where it isn't a good fit:** it's alpha, not a polished appliance. No endpoint agents — it consumes normalized events (`POST /api/v1/events`), so if you want host telemetry you feed it from something else. Detection is YAML rules with a fixed operator set plus a Sigma-lite subset, not a Sigma engine. Connectors are unconfigured by default, so a fresh install simulating every action is the expected first experience, not a bug. And it does have real moving parts (rules, policies, playbooks are all YAML you'll want to read).

Install steps, the compose file and the config reference are in the repo. If you try it, I'm most interested in where the install breaks on your distro and whether the retention purge behaves the way you expect — those are the things I can't test on my own machine.

---

# 6. Notes d'objection probables (FR — aide au répondant)

| Question probable | Réponse courte et vérifiée |
|---|---|
| « Pourquoi pas Postgres ? » | SQLite est le défaut de la v0.1.0 (`THOT_DB_URL=sqlite:///./data/thotsecure.db`) ; le DDL PostgreSQL/TimescaleDB est documenté, pas le chemin par défaut. Pour un usage mono-nœud, SQLite tient ; pour du multi-écrivain, ce sera Postgres, et c'est annoncé comme tel. |
| « Ça sort sur Internet ou pas ? » | Réponse honnête : aucun mécanisme de télémétrie n'apparaît dans le contrat ; la vérification par audit du code est en cours et le résultat sera publié. Les seules sorties prévues sont les connecteurs configurés, les webhooks de notification et NATS si `THOT_BUS=nats`. Ne pas dépasser cette formulation. |
| « Combien de RAM / CPU ? » | Ne pas inventer de chiffre. Répondre avec la mesure faite sur la machine de test, en la présentant comme une mesure ponctuelle non représentative, ou dire qu'on ne l'a pas mesuré. |
| « Ça marche dans un conteneur non-root ? » | À vérifier dans l'image le jour J. Si ce n'est pas vérifié, le dire. |
| « Est-ce que je peux l'utiliser sans Docker ? » | Oui pour le cœur (stdlib + pydantic/PyYAML, utilisable en bibliothèque) et pour le serveur (couche API), mais l'installation hors Docker doit être testée par l'auteur sur au moins une distribution avant d'être affirmée. |
| « C'est un vrai alpha ? » | Oui : `Development Status :: 3 - Alpha`, version `0.1.0`. Le dire avant qu'on le découvre. |
| « Comment je sauvegarde ? » | Procédure à décrire seulement après l'avoir exécutée : arrêt propre du service, copie du fichier `./data/thotsecure.db` (ou de la base Postgres si migré), redémarrage. Ne pas improviser de procédure. |
| « Ça remplace Wazuh / CrowdSec / fail2ban ? » | Non. Thot Secure ne collecte pas de télémétrie endpoint et n'écrit pas de règles de pare-feu lui-même : il décide et il exécute via des connecteurs, avec annulation. La composition est le cas d'usage attendu. |
| « Vous demandez des dons ? » | Réponse unique, sobre, sans adresse : le sujet n'est pas abordé ici ; il existe une page de soutien dans le produit. Ne jamais coller d'adresse de cryptomonnaie dans un fil r/selfhosted. |
| « Quelle licence ? » | Apache-2.0, avec un `NOTICE`. Contributions sous DCO (pas de CLA) d'après le `CONTRIBUTING.md` du dépôt. |

---

# 7. Checklist avant publication (FR)

- [ ] La checklist réseau du §4 a été exécutée ; toute case non cochée a entraîné la suppression de la phrase correspondante dans le post.
- [ ] La formulation sur la télémétrie est bien un constat de lecture, suivie de l'engagement d'audit — jamais un slogan.
- [ ] Aucune mention de don, de financement ou de page de soutien dans le post.
- [ ] Un seul lien (le dépôt) dans tout le post.
- [ ] Un fichier compose existe effectivement dans `deploy/` et la commande de démarrage a été testée telle qu'elle sera écrite.
- [ ] Les règles du sous-reddit sur l'auto-promotion et les sollicitations ont été relues le jour J.
- [ ] `THOT_BOOTSTRAP_API_KEY` et `THOT_SECRET_KEY` sont bien présentés comme des points à changer avant exposition.
- [ ] Le caractère alpha est écrit noir sur blanc.
- [ ] Aucun chiffre non mesuré, aucun superlatif marketing.
- [ ] L'auteur est disponible 4 heures après publication et n'y touche plus ensuite.
