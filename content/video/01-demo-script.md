```yaml
canal: "YouTube (vidéo longue) + déclinaison réseaux sociaux (version 60 s)"
langue: "fr (voix off), sous-titres fr"
format: "démo écran + voix off, storyboard plan par plan, script SRT, version courte 60 s"
objectif: "Prouver en 6 min 50 que la boucle détection → décision → approbation humaine → action → rollback → audit est réelle et vérifiable, puis convertir en contributions (règles, connecteurs, tests)"
mot_cle_principal: "SOAR défensif open source"
longueur: "6 min 50 (cible 5–7 min) + version courte 60 s"
public_cible: "ingénieurs sécurité, SRE/DevOps, RSSI de PME/ETSI, mainteneurs open source, recruteurs techniques"
produit: "Thot Secure MVP v0.1.0 — SOAR/CSPM défensif, Python/FastAPI, multi-tenant, Apache-2.0"
source_de_verite: "docs/architecture/api-contract.md (contrat gelé, 492 lignes)"
garanties_a_demontrer: ["réversibilité totale", "audit chaîné par hash", "isolation multi-tenant", "dry-run par défaut"]
statut: "prêt à tourner (script complet, aucune section à rédiger)"
date_redaction: "2026-02-14"
```

# Thot Secure — script + storyboard de démo (v0.1.0)

## 0. Règles de vérité de ce document

1. **Toute commande, tout statut, tout playbook et toute variable cités ici existent exactement
   dans `docs/architecture/api-contract.md`** : CLI (§8), variables `THOT_*` (§9), schémas
   `Event`/`Finding`/`Decision`/`Action`/`AuditRecord` (§3), règles YAML (§5), politiques (§6),
   playbooks (§7), API `/api/v1` (§4).
2. **Ce qui n'est pas dans le contrat est marqué « roadmap »** et n'est jamais présenté à l'écran
   comme disponible.
3. **Aucun chiffre de ce document n'est une mesure.** Le score de risque, le nombre d'événements,
   les sorties de commandes : ce sont des valeurs d'illustration ou des valeurs produites par
   votre propre exécution. Le libellé « ordre de grandeur à remplacer par vos mesures » s'applique
   partout où un nombre est écrit.
4. **La voix off est écrite pour être indépendante du formatage des sorties CLI.** Le contrat
   spécifie les *commandes* et les *schémas JSON* (§3, §4), pas le rendu texte de la CLI. Si votre
   sortie diffère, la voix off reste juste : elle ne lit aucun caractère à l'écran.
5. **Ni le script, ni la description, ni le carton d'ouverture ne mentionnent les dons.** Les
   adresses n'apparaissent qu'au dernier plan (§ 12 de ce document).
6. Ce script est soumis à **`content/CHARTE-EDITORIALE.md`**, qui prime : pas de superlatif, aucune
   affirmation non vérifiable, aucune donnée réelle, aucun lien raccourci, une disclosure d'auteur si
   la vidéo est partagée sur un canal tiers. La publication attend que la relecture technique (étape 1
   de la charte) ait confirmé **chaque commande exécutée à l'écran**.

Point d'honnêteté à ne pas rater en montage : un **connecteur non configuré fonctionne en mode
simulé** (`null` / `simulation`) et journalise `simulated: true` — c'est le comportement par défaut
du MVP (contrat §7). Donc même avec `dry_run: false`, une exécution sans connecteur reste simulée.
La vidéo doit le dire à voix haute. La démo prouve le **plan de contrôle** (plan → approbation →
exécution → rollback → audit) ; elle ne prouve pas la modification d'un pare-feu réel, sauf si
vous configurez un connecteur.

---

## 1. Matériel et environnement d'enregistrement

| Poste | Spécification | Pourquoi |
|---|---|---|
| Capture écran | OBS Studio 30+ ou équivalent, **1920×1080**, 30 fps (60 fps inutile pour du terminal), CQP 18–20, format MKV puis remux MP4 | Le terminal ne bouge pas assez vite pour justifier 60 fps |
| Audio | Micro cardioïde USB ou XLR + interface, filtre anti-pop, pièce traitée (rideaux, tapis), **48 kHz / 24 bits**, crête cible **−12 dBFS**, bruit de fond < −50 dBFS | La crédibilité d'une démo technique se joue sur l'audio plus que sur l'image |
| Terminal | **Police à chasse fixe lisible : JetBrains Mono, Cascadia Mono ou IBM Plex Mono, corps 16–18 px**, interligne 1.2 à 1.4, thème sombre à fort contraste (pas de thème « hacker » vert sur noir : illisible après compression) | Lisibilité à 1080p et sur mobile en 720p |
| Fenêtre terminal | **100 à 110 colonnes maximum**, taille de police telle que la ligne la plus longue ne soit jamais coupée | Une commande coupée = un spectateur perdu |
| Zone d'écran | Barre de titre masquée si possible, fond neutre, **aucun onglet de navigateur visible**, aucune notification système activée (mode concentration) | Aucune fuite d'information, aucun élément parasite |
| Bandeau | Lower-third sobre 1920×180 px, texte ≥ 32 px, contraste AA, pas d'animation clignotante | Le « Texte incrusté » du storyboard |
| Logiciel | OBS (scène « terminal », scène « console web », scène « diagramme », scène « talking head ») + un enregistreur audio de secours (audacity ou équivalent) | Le plan de secours audio évite de rejouer toute la prise |
| Voix | Débit cible **~150 mots/minute**. Le minutage du storyboard est calibré sur ce débit | Sinon les plans dépassent |
| Machine | **VM jetable ou conteneur dédié**, jamais une machine de production | La démo écrit dans une base locale |

---

## 2. Prérequis d'enregistrement (à faire avant d'appuyer sur REC)

| # | Prérequis | Détail | Fait |
|---|---|---|---|
| 1 | Environnement vierge | VM/ répertoire de travail neuf, dépôt cloné localement, environnement Python dédié. **Les commandes d'installation dépendent de votre packaging et ne sont pas couvertes par le contrat : ne les improvisez pas à l'écran.** La vidéo ne montre que les commandes du contrat §8 | ☐ |
| 2 | Base initialisée | `thotsecure init-db` **exécuté avant le tournage** sur une base vide → la base à l'écran ne contient que ce que la démo produit | ☐ |
| 3 | Santé vérifiée | `thotsecure doctor` exécuté deux fois avant le tournage, sortie notée. Si `doctor` signale un problème, on corrige **avant** REC | ☐ |
| 4 | Jeu de démo pré-testé | `thotsecure demo --tenant demo` exécuté **une fois hors caméra** pour valider l'environnement. Le tenant filmé est **`acme`**, pas `demo` : on veut des identifiants de finding prévisibles | ☐ |
| 5 | Données de démo | `events.jsonl` (7 lignes, voir §4) écrit et relu. **Aucune donnée client réelle.** Aucun nom d'hôte réel | ☐ |
| 6 | Adresses IP | **Uniquement les plages de documentation** : `203.0.113.0/24` (IPv4) et `2001:db8::/32` (IPv6). Aucune IP réelle, aucune IP publique d'un tiers | ☐ |
| 7 | Dry-run armé | `THOT_DRY_RUN=true` (défaut, contrat §9) **vérifié** avant REC. C'est l'état de départ de la démo | ☐ |
| 8 | Tenant filmé | `acme` créé en mode `supervised` (le gate d'approbation doit être actif à l'écran) | ☐ |
| 9 | Clé API | Clé `responder` créée hors caméra ; **la clé n'est affichée qu'une seule fois** (contrat §4.2) : soit on la montre à l'écran en assumant qu'elle sera révoquée juste après, soit on ne la montre pas. Recommandé : **ne pas la montrer**, masquer la sortie. Si montrée : `thotsecure key revoke --key-id <id>` juste après le tournage | ☐ |
| 10 | Politique de démo | `policies/demo-require-approval-web.yaml` présente (voir §5) avec `dry_run: true` au départ | ☐ |
| 11 | Console web | Optionnelle. Si vous montrez `thotsecure serve` et `GET /`, elle ne doit exposer que les données du tenant `acme` | ☐ |
| 12 | Notifications coupées | Mode concentration OS, son système coupé, messagerie fermée | ☐ |
| 13 | Minuteur visible hors cadre | Pour tenir les 6 min 50 sans dépasser | ☐ |

### 2.1 Ce qui ne doit jamais apparaître à l'écran

- Une adresse IP réelle, un nom de domaine réel d'un tiers, un vrai `src_ip`.
- Un jeton, une clé privée, une phrase de récupération, un secret d'API tiers.
- Un identifiant de client, un nom de société réelle, un ticket interne.
- Une sortie de commande fabriquée à la main. Si ça n'a pas tourné, ça ne s'affiche pas.

---

## 3. Diagramme d'architecture (plan 00:20–01:20)

À dessiner en un seul flux, de gauche à droite, **huit blocs**, sans 3D ni ombres portées.
Couleur unique par étage, deux étages en surbrillance pendant la voix off (le moteur de décision
puis le gate d'approbation).

```
 ┌──────────────┐   ┌────────────────┐   ┌─────────────────┐   ┌───────────────┐
 │ 1 COLLECTEUR │   │ 2 NORMALISATION│   │ 3 MOTEUR DE     │   │ 4 SCORING     │
 │ web_probe    │──▶│ Event immuable │──▶│    RÈGLES (YAML)│──▶│ risk_score    │
 │ log_tail     │   │ tenant_id, ts, │   │ conditions      │   │ sévérité      │
 │ dependency   │   │ kind, labels,  │   │ seuils          │   │ confiance     │
 │ config_audit │   │ payload        │   │ déduplication   │   │ criticité     │
 └──────────────┘   └────────────────┘   └─────────────────┘   └───────┬───────┘
        ▲                                                              │
        │ cibles déclarées du tenant (§9 THOT_TARGETS_FILE)        ▼
        │                                                     ┌─────────────────┐
        │                                                     │ 5 MOTEUR DE     │
        │                                                     │   DÉCISION      │
        │                                                     │ policy-as-code  │
        │                                                     │ auto |          │
        │                                                     │ require_approval│
        │                                                     │ notify_only |   │
        │                                                     │ ignore          │
        │                                                     └────────┬────────┘
        │                                                              │
        │                        ┌─────────────────────────────────────┘
        │                        ▼
        │              ┌──────────────────────┐        ┌────────────────────────┐
        │              │ 6 GATE D'APPROBATION │        │ garde-fous (§6)        │
        │              │ humain si            │◀──────▶│ plafond horaire        │
        │              │ require_approval     │        │ cooldown               │
        │              │ (mode supervised)    │        │ cibles protégées       │
        │              └──────────┬───────────┘        │ dry_run global         │
        │                         │                    └────────────────────────┘
        │                         ▼
        │              ┌──────────────────────┐        ┌────────────────────────┐
        └──────────────│ 7 PLAYBOOK + ROLLBACK│───────▶│ 8 AUDIT CHAÎNÉ PAR HASH│
                       │ block-source-ip      │        │ seq, prev_hash, hash   │
                       │ unblock-source-ip    │        │ append-only            │
                       │ simulateur si pas de │        │ audit verify → 0 ou 3  │
                       │ connecteur (null)    │        └────────────────────────┘
                       └──────────────────────┘
```

Annotations à afficher en petit sous le diagramme :

- `Event` immuable, `payload` ≤ 32 Kio sérialisé, au-delà tronqué avec `raw_ref` (contrat §3.1).
- `hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`, genesis `prev_hash = "sha256:genesis"` (contrat §3.5).
- Le core ne dépend que de la stdlib + `pydantic`/`PyYAML` ; FastAPI, Jinja2 et uvicorn sont des dépendances de la couche API (contrat §1, invariant 5).

---

## 4. Jeu de données de démo — `events.jsonl`

7 événements, `kind: http.request`, tous depuis `203.0.113.9` (plage de documentation),
fenêtre de 12 secondes, source `web_probe` sur `prod-edge` / `shop.acme.fr`.
Conçu pour franchir le `threshold: {count: 3, window_seconds: 60}` de la règle `AO-WEB-001`
(contrat §5) et tomber dans une seule déduplication `key: [rule_id, labels.src_ip]`.

```jsonl
{"event_id":"e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:00.123Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"info","labels":{"src_ip":"203.0.113.9","path":"/login?user=admin' OR 1=1--","method":"POST"},"payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556601","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:01.410Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"low","labels":{"src_ip":"203.0.113.9","path":"/login?user=admin' UNION SELECT 1,2,3--","method":"POST"},"payload":{"status":403,"bytes":498,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556602","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:03.002Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"medium","labels":{"src_ip":"203.0.113.9","path":"/login?user=admin' AND SLEEP(5)--","method":"POST"},"payload":{"status":403,"bytes":505,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556603","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:05.500Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"medium","labels":{"src_ip":"203.0.113.9","path":"/search?q=1' OR 1=1--","method":"GET"},"payload":{"status":200,"bytes":18422,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556604","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:07.180Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"high","labels":{"src_ip":"203.0.113.9","path":"/login?user=x'; SELECT BENCHMARK(1000000,MD5(1))--","method":"POST"},"payload":{"status":500,"bytes":731,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556605","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:09.640Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"high","labels":{"src_ip":"203.0.113.9","path":"/login?user=admin' OR 1=1--","method":"POST"},"payload":{"status":403,"bytes":512,"user_agent":"curl/8.5"},"raw_ref":null}
{"event_id":"7a1b2c3d-1111-4222-8333-444455556606","schema_version":"1","tenant_id":"acme","ts":"2026-02-14T10:00:11.900Z","kind":"http.request","source":{"type":"web_probe","name":"prod-edge","host":"shop.acme.fr"},"severity_hint":"high","labels":{"src_ip":"203.0.113.9","path":"/api/v1/user?id=1 UNION/**/SELECT password FROM users--","method":"GET"},"payload":{"status":403,"bytes":468,"user_agent":"curl/8.5"},"raw_ref":null}
```

Variante IPv6 (facultative, si vous voulez montrer que le modèle est agnostique) : dupliquer deux
lignes avec `"src_ip":"2001:db8::9"` — plage de documentation IPv6, `2001:db8::/32`.

Aucun nombre ci-dessus n'est une mesure de performance : c'est un jeu de test choisi pour déclencher
la règle. Le `risk_score` affiché ensuite est **calculé par le moteur** à partir de `risk.base`,
de la sévérité, de la confiance et de `asset_criticality` de la règle (contrat §5) ; le contrat
montre `78.5` en exemple illustratif (§3.2) — **ordre de grandeur à remplacer par vos mesures**.

---

## 5. Politique de démo — `policies/demo-require-approval-web.yaml`

Le tenant filmé est en `supervised` : la politique livrée d'exemple `auto-block-critical-web-attack`
(contrat §6) exige `tenant.mode: [auto, supervised]` et reste en `decision: auto` — le moteur retomberait donc sur
`notify_only` si le dry-run global est actif. Pour démontrer le **gate d'approbation humaine**, on écrit une politique dédiée,
conforme au schéma §6.

```yaml
version: 1
id: demo-require-approval-web
priority: 90
description: Toute attaque web à fort score part en approbation humaine (tenant supervisé).
when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  finding.tags_any: [web]
  tenant.mode: [supervised]
then:
  decision: require_approval
  playbook: block-source-ip
  params:
    target: labels.src_ip
    duration_seconds: 3600
  dry_run: true
  cooldown_seconds: 300
  max_actions_per_hour: 10
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
```

À l'écran, la levée du dry-run se fait **en deux endroits visibles** :

1. `THOT_DRY_RUN` passe de `true` à `false` (variable globale, contrat §9) ;
2. `dry_run: true` → `dry_run: false` dans `then:` de la politique.

Tant que le global vaut `true`, **aucune politique ne peut forcer une action réelle**
(contrat §6, garde-fou 4 : le `dry_run` global est prioritaire sur toute politique).

Garde-fous qui restent actifs même après la levée (contrat §6, non contournables par une politique) :
plafond `max_actions_per_hour` par tenant (défaut 20), `cooldown` par `(tenant, playbook, cible)`,
interdiction absolue d'agir sur une cible de l'`autonomy_allowlist` protégée, et
`require_approval` obligatoire pour toute cible hors périmètre déclaré du tenant.

---

## 6. Storyboard complet (6 min 50)

| Temps | Plan | Voix off (à lire mot pour mot) | Action à l'écran | Texte incrusté |
|---|---|---|---|---|
| 00:00–00:20 | **Talking head**, cadrage poitrine, fond neutre. Aucune image d'illustration, aucun écran factice, aucune reconstitution : on reste sur le visage | « Trois heures du matin. Une alerte tombe. La vraie question, ce n'est pas ce qui se passe. C'est : qui a décidé quoi, sur quelle base, et comment on annule. Thot Secure est un SOAR défensif open source, Apache-2.0. Quatre garanties : réversibilité totale, audit chaîné par hash, isolation multi-tenant, dry-run par défaut. Aucune capacité offensive. » | Aucune commande. Fixe. Aucun mot « dons » à l'écran | `01 · LE PROBLÈME` puis `SOAR défensif · Apache-2.0` |
| 00:20–01:20 | **Diagramme** (plan §3), surbrillance progressive bloc par bloc | « Le flux est linéaire, et c'est volontaire. En entrée, des collecteurs défensifs — sonde HTTP sur vos propres cibles déclarées, lecture de logs, inventaire de dépendances, audit de configuration. Chaque fait est normalisé en un événement immuable : un identifiant, un tenant, un horodatage, des étiquettes plates. Le moteur de règles YAML évalue ces événements : conditions, seuils, déduplication. Un finding naît — règle, sévérité, confiance, score de risque. Le moteur de décision applique vos politiques policy-as-code : auto, require_approval, notify_only, ignore. Si la politique exige une approbation, on passe par un gate humain — une politique ne peut pas contourner ça. Le playbook s'exécute, avec son rollback. Et chaque étape écrit dans le journal d'audit chaîné par hash : si une ligne est modifiée après coup, la vérification casse. » | Animation du diagramme, 8 blocs, ~7 s par bloc. Aucune souris qui tremble : transitions nettes | `collecteur → normalisation → règles → scoring → décision → approbation → playbook → audit` |
| 01:20–01:50 | **Terminal**, plein écran | « On part d'une base vide. `thotsecure init-db` crée le schéma local — SQLite dans ce MVP. `thotsecure doctor` vérifie l'environnement : base, répertoires de règles, de politiques et de playbooks, bus d'événements. Ensuite, un tenant : `acme`, en mode supervisé. Le mode supervisé, c'est la garantie que rien de critique ne partira sans une approbation humaine. Et une clé API de rôle responder — la clé n'est affichée qu'une seule fois. » | `thotsecure init-db`<br>`thotsecure doctor`<br>`thotsecure tenant create --id acme --name "ACME SAS" --mode supervised`<br>`thotsecure key create --tenant acme --role responder --label ci` (sortie masquée au montage) | `02 · MISE EN PLACE` · `mode supervised = approbation humaine obligatoire` |
| 01:50–02:30 | **Terminal** + incrustation des 7 lignes de `events.jsonl` (3 s) | « Voici sept requêtes HTTP, émises en douze secondes depuis 203.0.113.9 — une plage de documentation, jamais une adresse réelle. Elles visent `/login`. `thotsecure ingest --tenant acme --file events.jsonl`. Chaque ligne devient un événement immuable, normalisé, rattaché au tenant. Le moteur de règles YAML les évalue en flux. La règle AO-WEB-001 cherche des motifs d'injection SQL dans les paramètres de requête. Trois occurrences en soixante secondes suffisent, la déduplication regroupe, et un finding est créé. » | `thotsecure ingest --tenant acme --file events.jsonl` | `03 · INGESTION ET DÉTECTION` · `AO-WEB-001 · threshold 3 / 60 s` |
| 02:30–03:00 | **Terminal** | « On liste : `thotsecure findings list --tenant acme --severity high --min-risk 70`. Le finding est là. `thotsecure findings show` donne l'évidence : les échantillons, les identifiants d'événements, la remédiation proposée. Mais ce qui décide, ce n'est pas le score. C'est la politique. Quand la sévérité est haute ou critique, le score au-dessus de soixante-dix, le tag web, et le tenant en mode supervisé, la politique répond : require_approval. Approbation humaine obligatoire. » | `thotsecure findings list --tenant acme --severity high --min-risk 70`<br>`thotsecure findings show <finding_id>` | `04 · FINDING ET POLITIQUE` · `decision: require_approval` |
| 03:00–03:35 | **Terminal**, puis zoom sur le champ `dry_run` de la sortie | « Premier réflexe : ne rien faire. `thotsecure actions plan --finding <id> --playbook block-source-ip` construit un plan et rien d'autre — le contrat précise qu'un plan n'a aucun effet de bord. Regardez le champ dry_run : il vaut vrai, et le dry-run global est actif. `thotsecure actions execute <id>`. L'action est journalisée, marquée simulée, et le pare-feu n'a pas bougé. C'est le comportement par défaut du MVP : brancher un SOAR avant d'avoir les credentials ne doit rien casser. » | `thotsecure actions plan --finding <id> --playbook block-source-ip`<br>`thotsecure actions execute <id>`<br>Zoom 2× sur `dry_run` et sur la mention de simulation | `05 · DRY-RUN PAR DÉFAUT` · `THOT_DRY_RUN=true · aucun effet réel` |
| 03:35–04:15 | **Terminal** : affichage de la variable, édition de la politique, redémarrage | « Maintenant, on veut agir pour de vrai — consciemment. Deux changements explicites : la variable globale THOT_DRY_RUN passe à faux, et la politique passe dry_run à faux. Redémarrage du service. On approuve : `thotsecure actions approve <id>`. Puis `thotsecure actions execute <id>`. Cette fois dry_run vaut faux. Et notez l'honnêteté du résultat : sans connecteur configuré, l'exécution reste simulée — c'est le connecteur qui le dit, pas nous. Configurez Cloudflare, AWS WAF, Slack, GitHub Issues ou un nginx local, et le même playbook écrit une vraie règle. » | `$env:THOT_DRY_RUN` (affiche `true`)<br>`$env:THOT_DRY_RUN = "false"`<br>édition visible de `dry_run: true` → `false` dans la politique<br>redémarrage de `thotsecure serve` si vous l'utilisez<br>`thotsecure actions approve <id>`<br>`thotsecure actions execute <id>` | `06 · LEVÉE EXPLICITE DU DRY-RUN` · `2 changements visibles · tracés dans l'audit`<br>puis `connecteur non configuré → simulated: true` |
| 04:15–04:45 | **Terminal** | « Toute action est réversible. Le playbook déclare son rollback : unblock-source-ip. `thotsecure actions rollback <id>`. L'action passe en rolled_back, le jeton de rollback est consommé, et le déblocage est journalisé avec la même rigueur que le blocage. C'est ça, la réversibilité : une contre-mesure qu'on peut défaire, avec une trace dans les deux sens. Si le rollback a expiré, la commande échoue — elle ne prétend pas avoir réussi. » | `thotsecure actions rollback <id>` | `07 · ROLLBACK` · `status: rolled_back` |
| 04:45–05:10 | **Terminal** + extrait du schéma `AuditRecord` incrusté 4 s | « Chaque décision et chaque action ont écrit une ligne dans le journal d'audit. Ce journal est append-only, et chaque enregistrement contient le hash du précédent. `thotsecure audit verify`. Code de sortie zéro : la chaîne est intègre. Modifiez une seule ligne à la main, et la vérification renvoie le code trois — vérification négative — en indiquant où la chaîne casse. `thotsecure audit tail` pour suivre en direct. » | `thotsecure audit verify`<br>`thotsecure audit tail`<br>Optionnel : montrer `echo $LASTEXITCODE` après la commande | `08 · AUDIT CHAÎNÉ` · `exit 0 = intègre · exit 3 = chaîne rompue`<br>incrust : `hash = sha256(seq\|ts\|tenant_id\|actor\|…\|prev_hash)` |
| 05:10–05:40 | **Terminal** puis aperçu du fichier SARIF dans l'éditeur | « Un finding doit sortir de l'outil. `thotsecure report <id> --format sarif` produit un SARIF 2.1.0 — le format que GitHub Code Scanning consomme. Les autres formats : markdown, HTML, JSON, et CEF pour un SIEM. Le rapport est un artefact : il cite la règle, l'évidence, l'action, l'acteur et la séquence d'audit. Il est régénérable depuis la base à tout moment. » | `thotsecure report <finding_id> --format sarif`<br>ouverture du fichier produit dans l'éditeur, 5 s de défilement | `09 · RAPPORT` · `SARIF 2.1.0 · md · html · json · cef` |
| 05:40–06:10 | **Talking head** (retour visage, fin de la démo) | « Ce que ce MVP n'est pas. L'interface principale, c'est une console Jinja2 servie par l'API, sans build Node — pas un SPA ; un tableau de bord React optionnel est livré à côté. La persistance, c'est SQLite par défaut ; l'adaptateur PostgreSQL et TimescaleDB est écrit et tourne en CI, mais il n'a pas été éprouvé à l'échelle de production. Le bus supporte memory, sqlite et nats. L'authentification repose sur des clés API hachées en scrypt, avec quatre rôles : viewer, analyst, responder, admin — pas de SSO, pas de comptes nominatifs. Les collecteurs sont volontairement limités à votre propre surface déclarée. Et il n'y a aucune télémétrie : le projet ne renvoie rien nulle part. Les tests sont en unittest, exécutables sans dépendance externe : 396 tests. » | Aucune. Fixe. Possibilité d'incruster 4 lignes de « limites » | `10 · LIMITES ASSUMÉES` · `SQLite par défaut · pas de télémétrie · zéro capacité offensive` |
| 06:10–06:40 | **Terminal** sur `rules validate`, puis `ls rules/` | « Si ce fonctionnement vous parle, le plus utile n'est pas une étoile. C'est une règle de détection, un connecteur, un test, une traduction. Une règle, c'est un fichier YAML d'une vingtaine de lignes, et `thotsecure rules validate` vous dit tout de suite si elle est valide — une règle invalide ne casse jamais le chargement, elle est rejetée avec un diagnostic. Il y a aussi les playbooks à écrire et les politiques à durcir. Les playbooks livrés couvrent le blocage d'IP, le rate-limit, la quarantaine d'artefact, la révocation de session, la rotation de secret, l'isolation d'hôte, le patch de dépendance — qui ouvre une pull request et ne merge jamais tout seul — le durcissement d'endpoint, la notification et l'ouverture de ticket. » | `thotsecure rules list`<br>`thotsecure rules validate --path rules`<br>`Get-ChildItem playbooks` | `11 · CONTRIBUER` · `Apache-2.0 · règles YAML · playbooks · tests` |
| 06:40–06:50 | **Carton final** statique, fond sombre, texte centré. **Dernier plan de la vidéo** (voir §12 pour le contenu exact) | « Thot Secure. Dépôt GitHub, licence Apache-2.0. Le lien du dépôt et les informations de soutien sont en description. » | Aucune commande. Carton statique 10 s | `github.com/thot-corp/thot-secure` · `Apache-2.0` · `dépôt, licence et soutien : voir la description` |

**Durée cumulée : 6 min 50**, dans la cible 5–7 min.
Si vous devez couper 40 s pour tenir 6 min : fusionner 05:10–05:40 (rapport) dans le plan audit en
gardant seulement la commande `report --format sarif` à l'écran sans voix off dédiée, et réduire le
plan 00:20–01:20 à 45 s.

---

## 7. Séquence de commandes exacte (copier-coller pour le tournage)

Bloc 1 — mise en place (hors caméra si vous voulez gagner du temps ; montré à l'écran en 01:20–01:50) :

```powershell
thotsecure init-db
thotsecure doctor
thotsecure tenant create --id acme --name "ACME SAS" --mode supervised
thotsecure key create --tenant acme --role responder --label ci
```

Bloc 2 — détection :

```powershell
thotsecure ingest --tenant acme --file events.jsonl
thotsecure findings list --tenant acme --severity high --min-risk 70
thotsecure findings show <finding_id>
```

Bloc 3 — dry-run par défaut :

```powershell
$env:THOT_DRY_RUN            # doit afficher : true
thotsecure actions plan --finding <finding_id> --playbook block-source-ip
thotsecure actions execute <action_id>
```

Bloc 4 — levée explicite du dry-run, approbation, exécution :

```powershell
$env:THOT_DRY_RUN = "false"
# éditer policies/demo-require-approval-web.yaml : dry_run: true  ->  dry_run: false
thotsecure serve                   # uniquement si vous montrez la console web ; sinon passer au bloc suivant
thotsecure actions approve <action_id>
thotsecure actions execute <action_id>
```

Bloc 5 — rollback, audit, rapport :

```powershell
thotsecure actions rollback <action_id>
thotsecure audit verify
thotsecure audit tail
thotsecure report <finding_id> --format sarif
```

Bloc 6 — contribution :

```powershell
thotsecure rules list
thotsecure rules validate --path rules
Get-ChildItem playbooks
```

Commandes disponibles mais **non utilisées** dans le montage final (utiles en B-roll ou en
plan de secours) : `thotsecure tenant list`, `thotsecure key revoke --key-id <id>`,
`thotsecure policies validate`, `thotsecure actions list`, `thotsecure probe --tenant acme --target https://shop.acme.fr`,
`thotsecure demo --tenant demo`, `thotsecure serve` avec la console `GET /`.

Précision de contrat à ne pas se tromper en voix off : la CLI du contrat expose
`actions plan | approve | execute | rollback`. Le **rejet** existe côté API
(`POST /api/v1/actions/{id}/reject`), pas dans la liste CLI du §8. Ne dites pas « `thotsecure actions reject` ».

---

## 8. Le plan « dry-run » en détail (00:03:00 → 00:04:15)

C'est le plan qui porte la promesse. Il se joue en trois temps, sans coupe, pour que le spectateur
voie qu'il n'y a pas de montage truqué.

**Temps 1 — preuve de l'état sûr (30 s).**
1. Afficher `$env:THOT_DRY_RUN` → `true`. C'est le défaut documenté (contrat §9).
2. `thotsecure actions plan --finding <finding_id> --playbook block-source-ip`.
   Le plan est créé en statut `planned`. Le contrat §4.6 précise « aucun effet de bord ».
3. `thotsecure actions execute <action_id>`.
   L'action est journalisée et **simulée**. Deux causes possibles, cumulables, et il faut dire
   laquelle s'applique chez vous :
   - le dry-run global est actif (contrat §9, §6 garde-fou 4) ;
   - le connecteur WAF n'est pas configuré → mode simulé avec `rollback_token` et
     `simulated: true` (contrat §7).
4. Texte incrusté : `aucun effet réel · action journalisée · rollback_token émis`.

**Temps 2 — levée explicite (40 s).**
5. Montrer les deux changements à l'écran : `$env:THOT_DRY_RUN = "false"` **et**
   `dry_run: false` dans la politique. Insister : « deux gestes, pas un glissement de terrain ».
6. `thotsecure actions approve <action_id>` → statut `approved`.
7. `thotsecure actions execute <action_id>` → `dry_run: false` dans l'objet `Action`.
   Si le connecteur est `null`, le journal porte encore `simulated: true` : **le dire**.

**Temps 3 — la frontière (le dire explicitement à voix haute).**
8. Phrase de cadrage à ne pas couper : « La levée du dry-run change ce qu'Thot Secure *a le droit*
   de faire. Elle ne change pas ce que le connecteur *peut* faire. Sans credentials, on reste en
   simulation. C'est exactement ce qu'on veut d'un outil qu'on branche avant de lui donner les clés. »
9. Rappeler les garde-fous qui restent actifs : `max_actions_per_hour` (défaut 20 par tenant),
   `cooldown` par `(tenant, playbook, cible)`, cibles protégées de l'`autonomy_allowlist`
   intouchables, `require_approval` imposé hors périmètre déclaré.

Si vous voulez montrer un effet réel (optionnel, et **uniquement sur une infra jetable à vous**) :
configurez un connecteur listé au contrat §7 parmi `cloudflare`, `aws-waf`, `slack`,
`github-issues`, `nginx-local`, sur une cible déclarée dans le périmètre du tenant. Ne le faites pas en direct sans
répétition : c'est le plan qui fait rater une prise.

---

## 9. Plans de secours (si une commande échoue en direct)

| Panne | Ce qu'on ne fait **jamais** | Plan B |
|---|---|---|
| `thotsecure doctor` signale un problème | Tourner quand même | On arrête, on corrige, on refait la prise. Ce plan est un prérequis, pas un plan de secours |
| `ingest` ne déclenche aucun finding | Inventer un finding | Vérifier `rules list` (AO-WEB-001 présente et `enabled`), puis rejouer sur une base fraîche. En dernier recours, utiliser `thotsecure demo --tenant demo` pour obtenir des données, **et le dire à l'écran** (« on bascule sur le jeu de démo livré ») |
| Le finding n'apparaît pas dans `findings list` | Baisser le seuil sans le dire | Refaire la commande avec `--min-risk` plus bas **en annonçant le changement** : c'est une information utile, pas une triche |
| `actions plan` refuse la cible | Forcer via l'API | C'est probablement une cible protégée ou hors périmètre : c'est le comportement attendu (contrat §6). En faire un **plan bonus** : « regardez, le garde-fou refuse » — c'est plus fort que la démo nominale |
| `actions execute` renvoie un conflit (409) | Relancer en boucle | L'action est en `pending_approval` non approuvée ; c'est le gate qui fonctionne (contrat §4.6). Refaire le plan d'approbation |
| Le passage à `dry_run: false` ne prend pas effet | Mentir sur l'état | Vérifier que le service a bien été relancé avec la variable d'environnement, et réafficher `$env:THOT_DRY_RUN` à l'écran. Si le doute persiste : couper le plan, expliquer, refaire |
| `audit verify` renvoie 3 en direct | Couper au montage en espérant que personne ne voie | **Le montrer et l'expliquer** : « la chaîne est rompue, voici pourquoi et comment on le détecte ». C'est la meilleure démonstration possible de la garantie. Sinon, refaire sur une base propre |
| `serve` plante ou la console ne s'ouvre pas | Redémarrer pendant 5 min à l'écran | **Toute la démo fonctionne sans serveur** : les commandes du §8 sont toutes des commandes CLI. La console est un confort de capture, pas une dépendance |
| Problème audio | Publier quand même | Le plan est rejouable intégralement sur base vierge en ~15 min : `thotsecure init-db` puis les blocs du §7 |
| Le temps déborde | Accélérer la voix off | Couper dans cet ordre : le plan rapport (05:10–05:40), puis 10 s sur l'architecture, puis 5 s sur `rules list` |

Règle générale : **si ça n'a pas tourné proprement, ça ne s'affiche pas**. Un plan manquant est
moins coûteux qu'une sortie fabriquée.

---

## 10. Version courte 60 secondes (réseaux sociaux)

Format : vertical 1080×1920 ou carré 1080×1080 selon la plateforme, sous-titres brûlés obligatoires
(le son est coupé chez la majorité des spectateurs), texte incrusté de grande taille,
**aucune** mention de dons dans les 60 secondes.

| Temps | Plan | Voix off / texte à l'écran | Action à l'écran | Texte incrusté |
|---|---|---|---|---|
| 00:00–00:08 | **Plan clé 1** — le problème, en surimpression sur un terminal vide | « Une alerte à trois heures du matin. La question n'est pas ce qui se passe. C'est : qui a décidé quoi, et comment on annule. » | Terminal vide, curseur qui clignote | `qui a décidé quoi ?` |
| 00:08–00:20 | **Plan clé 2** — la boucle en 5 commandes, accélérées 4× | « Thot Secure : détecter, décider, approuver, agir, annuler. Avec la preuve. » | `thotsecure ingest --tenant acme --file events.jsonl`<br>`thotsecure findings list --tenant acme --severity high --min-risk 70`<br>`thotsecure actions plan --finding <id> --playbook block-source-ip`<br>`thotsecure actions approve <id>`<br>`thotsecure actions rollback <id>` (accéléré, pauses de 0,5 s sur les résultats) | `détecter → décider → approuver → agir → annuler` |
| 00:20–00:34 | **Plan clé 3** — le dry-run, en temps réel, non accéléré | « Par défaut, Thot Secure ne touche à rien. Dry-run actif : l'action est journalisée, marquée simulée, le pare-feu n'a pas bougé. La levée du dry-run est un geste explicite, visible, et tracé. » | `$env:THOT_DRY_RUN` → `true`<br>`thotsecure actions execute <id>`<br>puis `$env:THOT_DRY_RUN = "false"` et nouvelle exécution | `dry-run par défaut` puis `levée explicite` |
| 00:34–00:46 | **Plan incrusté** — extrait du storyboard long : `audit verify` | « Chaque décision est dans un journal chaîné par hash. Vérifiable en une commande : code zéro, chaîne intègre. Code trois, chaîne rompue. » | `thotsecure audit verify` (plan repris du montage long) | `exit 0 = intègre`<br>`exit 3 = chaîne rompue` |
| 00:46–00:54 | **Plan incrusté** — diagramme, 8 blocs, une seconde chacun | « Collecteurs, normalisation, règles, scoring, décision, approbation humaine, playbook, audit. Linéaire, et volontairement. Zéro capacité offensive. » | Animation du diagramme du §3 | `SOAR défensif · Apache-2.0` |
| 00:54–01:00 | **Carton de fin** (voir §12 pour le texte exact, dons inclus) | « Thot Secure, open source, Apache-2.0. Règles YAML, playbooks, tests : les contributions les plus utiles sont là. Dépôt et soutien en description. » | Carton statique | `github.com/thot-corp/thot-secure`<br>`Apache-2.0 · dépôt et soutien : voir la description` |

**Les 3 plans clés à ne pas rater** : (1) le dry-run par défaut qui ne touche à rien,
(2) la levée explicite du dry-run avec approbation humaine, (3) `audit verify` avec les codes de
sortie 0 et 3. Ces trois plans suffisent à raconter la promesse ; le reste est du contexte.

Découpe de production : tourner d'abord les 3 plans clés (ils sont critiques), puis les plans de
contexte. Si vous devez livrer 30 s au lieu de 60 s, gardez 00:20–00:34 et 00:34–00:46.

---

## 11. Métadonnées de publication

### 11.1 Titre de la vidéo longue

**Titre principal :**

> Thot Secure — SOAR défensif open source : détection, approbation humaine, dry-run, rollback et audit chaîné (démo)

**Variante A/B (à tester après publication, jamais avant) :**

> Détecter, approuver, annuler : démo d'un SOAR qui prouve ce qu'il a fait (Thot Secure, Apache-2.0)

Les deux titres sont honnêtes et descriptifs : ni « incroyable », ni « révolutionnaire », ni
« le meilleur ». Pas de majuscules criardes, pas d'emoji dans le titre principal.

### 11.2 Description (vidéo longue)

```
Thot Secure est un SOAR/CSPM défensif open source (Apache-2.0), écrit en Python/FastAPI.
Cette démo montre la boucle complète sur le MVP v0.1.0 :
ingestion de logs → détection par règles YAML → finding scoré → politique de décision
policy-as-code → approbation humaine → action (dry-run d'abord) → rollback → vérification
de la chaîne d'audit → rapport SARIF.

Quatre garanties, démontrées dans la vidéo :
- réversibilité totale : chaque playbook déclare son rollback ;
- audit chaîné par hash : chaque enregistrement contient le hash du précédent ;
- isolation multi-tenant : tout objet porte un tenant_id, testé en CI ;
- dry-run par défaut : THOT_DRY_RUN=true, aucune action réelle sans levée explicite.

Zéro capacité offensive : pas de hack-back, pas de scan agressif, pas de brute force.
Le scan `probe` n'audite que des cibles déclarées et détenues par le tenant.

Chapitres :
00:00 Le problème
00:20 Architecture : collecteur → normalisation → règles → scoring → décision → approbation → playbook → audit
01:20 Mise en place : init-db, doctor, tenant supervisé, clé responder
01:50 Ingestion de logs et détection (règle AO-WEB-001)
02:30 Finding, score de risque et politique de décision
03:00 Premier plan en dry-run : la preuve qu'il ne se passe rien
03:35 Levée explicite du dry-run, approbation humaine, exécution
04:15 Rollback : défaire proprement, et le journaliser
04:45 Audit chaîné par hash et vérification (codes de sortie 0 et 3)
05:10 Rapport SARIF pour GitHub Code Scanning
05:40 Limites assumées du MVP
06:10 Contribuer : règles, connecteurs, playbooks, tests
06:40 Dépôt, licence et soutien

Dépôt : github.com/thot-corp/thot-secure
Licence : Apache-2.0
Documentation : docs/architecture/api-contract.md — documentation publiée : https://thot-corp.github.io/thot-secure/

Les valeurs affichées dans la vidéo proviennent de notre propre exécution sur un jeu de données
de démonstration, avec des adresses de la plage de documentation 203.0.113.0/24. Aucune donnée
client réelle n'apparaît. Les chiffres de performance ne sont pas mesurés dans cette vidéo.

Adresses de soutien (voir la section dédiée en fin de description) :
Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
Solana (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.
Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais
de clé privée ni de phrase de récupération.
```

Les deux lignes d'adresses ci-dessus figurent **en fin de description**, jamais dans les cinq
premières lignes, jamais dans le titre, jamais dans les tags.

### 11.3 Tags / sujets

`soar` · `sécurité défensive` · `open source` · `python` · `fastapi` · `policy as code` ·
`audit log` · `réversibilité` · `dry run` · `cspm` · `multi-tenant` · `apache-2.0`

Pas de tag trompeur (« pentest », « hacking », « exploit ») : ce projet n'a aucune capacité
offensive et le référencement ne doit pas attirer le mauvais public.

### 11.4 Sous-titres — `.srt` des 60 premières secondes

Fichier `01-demo-script.srt` esquissé ci-dessous. Les durées sont calées sur les estimations de
débit du §6 et **doivent être recalées sur l'audio final** (le texte est figé, pas les timecodes).
Deux lignes maximum par sous-titre, 42 caractères maximum par ligne.

```srt
1
00:00:00,000 --> 00:00:03,200
Trois heures du matin.
Une alerte tombe.

2
00:00:03,200 --> 00:00:07,600
La vraie question,
ce n'est pas ce qui se passe.

3
00:00:07,600 --> 00:00:12,800
C'est : qui a décidé quoi, sur quelle base,
et comment on annule.

4
00:00:12,800 --> 00:00:16,400
Thot Secure est un SOAR défensif
open source, Apache-2.0.

5
00:00:16,400 --> 00:00:20,000
Quatre garanties : réversibilité totale,
audit chaîné, isolation, dry-run par défaut.

6
00:00:20,000 --> 00:00:24,500
Le flux est linéaire,
et c'est volontaire.

7
00:00:24,500 --> 00:00:29,500
En entrée, des collecteurs défensifs :
vos cibles déclarées, vos logs.

8
00:00:29,500 --> 00:00:34,500
Chaque fait devient un événement
immuable, normalisé, rattaché au tenant.

9
00:00:34,500 --> 00:00:39,500
Le moteur de règles YAML l'évalue :
conditions, seuils, déduplication.

10
00:00:39,500 --> 00:00:45,000
Un finding naît : règle, sévérité,
confiance, score de risque.

11
00:00:45,000 --> 00:00:50,500
Le moteur de décision applique
vos politiques policy-as-code.

12
00:00:50,500 --> 00:00:56,000
auto, require_approval,
notify_only, ignore.

13
00:00:56,000 --> 00:01:00,000
Le playbook s'exécute avec son rollback.
Chaque étape écrit dans l'audit chaîné.
```

Note de production : « Thot Secure » et les statuts d'action (`require_approval`, `notify_only`,
`planned`, `rolled_back`) sont à écrire exactement comme dans le contrat — pas de traduction,
pas de reformulation. Un sous-titre est un artefact technique, pas une paraphrase.

---

## 12. Carton final et adresses de dons (dernier plan uniquement)

Ce bloc est le **contenu exact du carton 06:40–06:50**, et le même bloc va **en fin de description**.
Il n'apparaît nulle part ailleurs : ni en accroche, ni dans les dix premières secondes, ni dans la
version courte autrement qu'à la dernière seconde.

**Carton final (texte à l'écran) :**

```
Thot Secure — SOAR défensif, open source, Apache-2.0
Dépôt : github.com/thot-corp/thot-secure
Le projet ne demande JAMAIS de clé privée ni de phrase de récupération.

Soutien volontaire, sans contrepartie : un don ne donne droit à rien
Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
Solana (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
Dons volontaires : ni support, ni fonctionnalité, ni priorité. Vérifiez toujours l'adresse depuis le dépôt officiel.
Seule la source officielle — dépôt Git + site du projet — fait foi.
```

**Texte copiable (description, fin de description, ou page de soutien) :**

- Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

> Dons volontaires : ni support, ni fonctionnalité, ni priorité. Vérifiez toujours l'adresse depuis le dépôt officiel.

Avertissement à afficher avec les adresses : seule la source officielle — dépôt Git + site du
projet — fait foi ; le projet ne demande jamais de clé privée ni de phrase de récupération.

Ces adresses sont la source unique de vérité du contrat §12 et figurent également dans `README.md`,
`.github/FUNDING.yml`, `GET /ui/support` et `docs/support.md`. **Toute adresse qui ne se trouve pas
dans ces emplacements est une arnaque** : ne la relayez pas, ne la corrigez pas « de bonne foi »
dans les commentaires, renvoyez au dépôt. Aucune contrepartie n'est promise ni sous-entendue :
pas de mention de sponsor, pas de remerciement personnalisé, pas d'accès privilégié, pas de support
prioritaire.
