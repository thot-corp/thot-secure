```yaml
canal: "LinuxFr.org — journal (avec variante dépêche)"
langue: "Français intégral (analyse et texte publié)"
format: "Journal LinuxFr : accroche courte, puis corps structuré avec sections ; liens regroupés en fin. Variante dépêche (titre + accroche + corps condensé) fournie pour une soumission à la modération."
objectif: "Présenter Thot Secure à la communauté du logiciel libre francophone sur ses critères propres : licence Apache-2.0, gouvernance ouverte, auto-hébergement, absence de verrouillage, reproductibilité des tests — et énoncer clairement ce qui manque encore"
mot_cle_principal: "SOAR libre"
longueur: "Fichier de travail ≈ 2 400 mots ; journal ≈ 900 à 1 100 mots ; accroche ≤ 60 mots ; variante dépêche ≈ 500 à 600 mots"
meilleur_creneau_publication: "Hypothèse de travail non mesurée : jour de semaine, 08:00–11:00 heure de Paris (le lectorat est majoritairement européen). À confirmer sur place ; ne pas présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : conditions de création de compte et délai de modération éventuel, différences de traitement entre journal et dépêche (la dépêche passe par la modération et peut être refusée ou réécrite), conventions de titre, règles sur les liens commerciaux et l'auto-promotion, éventuelle obligation de déclarer un contenu sponsorisé. Ces règles évoluent et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — LinuxFr tolère la présentation d'un projet libre par son auteur, mais attend une déclaration explicite de la qualité d'auteur et refuse les contenus perçus comme promotionnels ou commerciaux. Conséquences : (1) écrire dès l'accroche ou la première ligne que l'on est l'auteur du projet ; (2) aucun vocabulaire commercial, aucune sollicitation d'utilisateurs ou de contributions par obligation morale ; (3) les dons ne sont mentionnés qu'en toute fin, sobrement, une seule fois, et jamais en accroche — le bloc du §6 est obligatoire si et seulement si les dons sont mentionnés ; (4) répondre sur le fond technique et reconnaître les limites ; (5) ne pas relancer un journal qui n'a pas pris."
```

---

# 1. Stratégie (FR)

**Pourquoi LinuxFr, et ce que ce n'est pas.** LinuxFr n'est pas un canal d'acquisition : c'est un canal de *crédibilité*. La communauté y juge trois choses, dans cet ordre : la licence, la gouvernance (qui décide, comment on conteste), et la capacité à faire tourner le logiciel soi-même sans dépendre de quelqu'un. Le trafic généré est faible ; l'effet est durable, parce que le fil reste indexé et cité.

**Ce qui fonctionne sur ce site et ce qui ne fonctionne pas.**

- Fonctionne : annoncer explicitement que le projet est en alpha, lister ce qui manque, expliquer pourquoi une décision de conception a été prise contre l'évidence, donner la commande exacte qui reproduit les tests.
- Ne fonctionne pas : le vocabulaire produit (« solution », « plateforme », « écosystème »), les listes de fonctionnalités, l'absence de déclaration d'auteur, l'usage du mot « communauté » pour désigner des utilisateurs.

**Journal ou dépêche ?** Les deux textes sont fournis.

- Le **journal** (§5) est le format retenu en priorité : publié immédiatement, il ne dépend pas d'un modérateur, et il autorise une longueur suffisante pour expliquer les compromis.
- La **dépêche** (§7) n'est à soumettre que si le journal a produit une discussion de qualité : la dépêche passe par la modération, peut être refusée, et n'a de sens que si le contenu est stabilisé. Ne pas soumettre les deux le même jour.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Jour de semaine 08:00–11:00 heure de Paris (hypothèse non mesurée, à confirmer). Éviter le vendredi après-midi et le week-end : la discussion retombe trop vite sur LinuxFr. |
| Longueur | Journal 900–1 100 mots, accroche ≤ 60 mots. Les journaux trop longs sont survolés ; les journaux trop courts ne montrent pas le raisonnement. |
| Participation préalable | Compte avec un historique de commentaires appréciés, idéalement. Un compte créé le jour même attirera la suspicion ; annoncer sa qualité d'auteur et répondre sur le fond désarme l'essentiel. |
| Présence | Répondre pendant 24 à 48 heures : le rythme de LinuxFr est plus lent que celui d'un forum anglophone, la discussion peut démarrer plusieurs heures après publication. |
| Ton | Communauté du logiciel libre : factuel, précis, sans marketing, avec une préférence marquée pour le « voilà ce qui n'est pas fait ». Ne pas traduire les messages anglophones du projet mot à mot : écrire directement en français. |
| Suivi | Si des limites sont pointées dans les commentaires, les corriger avant de publier quoi que ce soit d'autre, et le dire dans le fil. |

---

# 3. Faits vérifiés (FR) — base des textes

Tout ce qui suit provient du contrat d'interface (`docs/architecture/api-contract.md`) ou d'un fichier du dépôt explicitement nommé. Rien d'autre ne doit être affirmé.

| Affirmation | Source |
|---|---|
| Licence Apache-2.0, version `0.1.0`, statut « Development Status :: 3 - Alpha », Python ≥ 3.11 | `pyproject.toml` du dépôt |
| Dépôt public : `https://github.com/thotsecure/thot-secure` | `pyproject.toml`, `Dockerfile`, `CONTRIBUTING.md` |
| Développement sous DCO, sans CLA ; au moins une approbation de mainteneur avant fusion ; document de gouvernance référencé depuis `CONTRIBUTING.md` | `CONTRIBUTING.md` du dépôt |
| Interdiction des capacités offensives traitée comme invariant constitutionnel du projet | `CONTRIBUTING.md` du dépôt ; §1 et §10 du contrat |
| Tests en `unittest` exécutables sans dépendance externe ; commande `python -m unittest discover -s tests -t . -v` ; `pytest` fonctionne aussi et tourne en CI | §11 du contrat |
| Couverture de tests prévue : config, stockage et isolation tenant, chaîne d'audit, bus, moteur de règles, scoring, décision, actions/rollback, collecteurs, API, rapports, CLI | §11 du contrat |
| Base SQLite par défaut : `THOT_DB_URL=sqlite:///./data/thotsecure.db` ; PostgreSQL/TimescaleDB documenté seulement | §9 du contrat |
| Bus d'événements `memory` (défaut) `|` `sqlite` `|` `nats` | §9 et §2 du contrat |
| Le cœur `thotsecure.core` ne dépend que de la stdlib + `pydantic`/`PyYAML` ; FastAPI, Jinja2, uvicorn sont dans la couche API | §1 invariants du contrat |
| Console embarquée en Jinja2 + JS, **aucun build Node requis** ; dashboard React+TS optionnel dans `web/` | §4.9 et §2 du contrat |
| API REST `/api/v1`, OpenAPI 3.1 généré par FastAPI (`GET /openapi.json`) | §3 et §4.9 du contrat |
| CLI `thotsecure` avec `--json` sur toutes les commandes ; codes de sortie `0` succès, `1` erreur, `2` usage, `3` vérification négative | §8 du contrat |
| Audit : journal append-only chaîné par hash ; vérification `GET /api/v1/audit/verify` ; export `GET /api/v1/audit/export?format=jsonl|cef` | §3.5, §4.7, §10 du contrat |
| Format des règles, des politiques et des playbooks : YAML, dans `rules/`, `policies/`, `playbooks/` | §5, §6, §7, §2 du contrat |
| Arborescence cible : `sdks/{python,typescript,go}/`, `deploy/` (Dockerfile, compose, k8s, helm, terraform, ansible), `docs/` MkDocs Material | §2 du contrat — **arborescence cible : à traiter comme telle** |
| Défauts de sûreté : `THOT_DRY_RUN=true`, `THOT_AUTONOMY=supervised` ; dry-run global prioritaire sur toute politique | §9, §1, §6 du contrat |
| Connecteur non configuré ⇒ mode simulé, retourne un `rollback_token`, journalise `simulated: true` ; comportement par défaut du MVP | §7 du contrat |
| Rétention : `THOT_RETENTION_DAYS=30` | §9 du contrat |
| `probe` n'audite que des cibles déclarées possédées par le tenant, opt-in explicite dans `targets.yaml` (`THOT_TARGETS_FILE`) | §10 et §9 du contrat |

**Deux points de prudence à ne pas transformer en argument de vente**

1. **Air-gap et télémétrie.** Aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface. C'est un constat de lecture du contrat, à confirmer par un audit du code avant de l'écrire publiquement. Le journal doit donc dire « aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface ; à confirmer par lecture du code », et non « sans télémétrie » comme s'il s'agissait d'un engagement vérifié. De même, ne pas écrire « fonctionne en air-gap » sans l'avoir testé hors ligne.
2. **Arborescence cible.** `sdks/`, `deploy/`, `docs/` sont décrits dans le contrat comme l'arborescence cible. Le journal ne doit pas laisser croire que tout est livré : si le contenu n'est pas constaté sur disque le jour de la publication, la phrase correspondante est retirée ou explicitement marquée « prévu ».

---

# 4. Accroche proposée (FR)

> **Titre :** `Thot Secure : un SOAR défensif où chaque action est annulable et le journal d'audit est une chaîne de hachages`
>
> **Accroche (à copier telle quelle) :**

Thot Secure est un SOAR/CSPM défensif en Python/FastAPI, sous Apache-2.0, publié en v0.1.0 (alpha). Je suis l'auteur du projet. Il collecte des événements, détecte avec des règles YAML, score, décide à partir de politiques *policy-as-code* et exécute des playbooks — chacun accompagné d'un rollback. Le journal d'audit est chaîné par hachage et vérifiable hors ligne. Le dry-run est actif par défaut. Ce journal décrit les compromis assumés et, surtout, ce qui n'est pas encore fait.

---

# 5. TEXTE DU JOURNAL — à copier tel quel (FR)

Je suis l'auteur d'Thot Secure, un projet que je publie en v0.1.0 sous licence Apache-2.0. Le dépôt est ici : `https://github.com/thotsecure/thot-secure`.

## Le problème visé

Il existe beaucoup d'outils qui détectent, et beaucoup d'outils qui automatisent une réponse. Le point qui m'intéresse est ailleurs : quand une machine applique une contre-mesure toute seule, comment sait-on *pourquoi* elle l'a fait, comment l'annule-t-on proprement, et comment prouve-t-on plus tard ce qui s'est réellement passé ? Ces trois questions sont traitées séparément par la plupart des chaînes existantes, avec des journaux applicatifs et de la discipline humaine. Thot Secure les traite comme des propriétés du produit.

## Ce que fait la v0.1.0

La chaîne est : un **événement** normalisé entre par une API (`POST /api/v1/events`), une **règle YAML** le fait correspondre à un **finding** porteur d'un score de risque et d'une confiance, une **politique** décide, un **playbook** agit. Chaque étape est un objet persisté : une décision n'est pas implicite dans un finding.

Quatre choix structurent le reste :

1. **Toute action est réversible.** Un playbook déclare `reversible: true` et un bloc `rollback:` ; `POST /api/v1/actions/{id}/rollback` doit réussir tant que la fenêtre de rollback n'a pas expiré. Une action qu'on ne peut pas annuler n'a pas sa place dans un playbook.
2. **La décision est un artefact versionné.** Des politiques YAML ordonnées par `priority` produisent l'une de quatre décisions : `auto`, `require_approval`, `notify_only`, `ignore`. Si aucune politique ne correspond, le résultat est `notify_only` — jamais `auto`. Le silence total exige une politique `ignore` explicite : on ne peut donc pas confondre « règle oubliée » et « décision de ne rien faire ».
3. **Le journal d'audit est chaîné et vérifiable sur place.** Chaque enregistrement s'engage sur le précédent par un hachage, et `GET /api/v1/audit/verify` répond `{"valid":true,"records":n,"broken_at":null}`. L'export se fait en `jsonl` ou `cef` vers un SIEM.
4. **Des garde-fous qu'une politique ne peut pas désactiver.** `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised` par défaut ; le dry-run global l'emporte sur toute politique ; plafond d'actions horaires par tenant ; délai de refroidissement par couple (tenant, playbook, cible) ; refus absolu d'agir sur une cible de la liste de protection du tenant. Une cible hors périmètre déclaré devient une demande d'approbation, pas une exécution.

## Où sont les compromis

Sur l'audit : une chaîne de hachages prouve la cohérence interne et détecte toute modification, suppression ou réordonnancement qui la rompt. Elle ne prouve pas la *complétude*. Qui contrôle la machine peut tronquer le journal et recommencer une chaîne ; qui peut réécrire la base peut recalculer la chaîne. La vraie parade est d'ancrer la tête de chaîne ailleurs — export vers un SIEM, notarisation périodique — et c'est une décision de déploiement, pas une fonctionnalité du logiciel. Une blockchain serait une réponse à un autre problème, plus lourde à opérer.

Sur les dépendances : le cœur (`thotsecure.core`) ne dépend que de la bibliothèque standard plus `pydantic` et `PyYAML`. FastAPI, uvicorn et Jinja2 sont dans la couche API. La conséquence pratique est qu'on peut lire et tester le cœur comme une bibliothèque, et faire tourner quelque chose sans chaîne de build Node : la console embarquée est du Jinja2 avec du JavaScript ordinaire.

Sur la base de données : SQLite est le défaut (`sqlite:///./data/thotsecure.db`) et c'est délibéré — l'outil doit pouvoir être évalué sur un portable sans service à démarrer. Le DDL PostgreSQL/TimescaleDB est documenté mais n'est pas le chemin par défaut. Pour du multi-nœuds, c'est une migration à faire, pas quelque chose que le code gère pour vous.

Sur les connecteurs : non configurés, ils fonctionnent en **mode simulé** — le playbook renvoie un jeton de rollback et l'enregistrement d'audit porte `simulated: true`. C'est le comportement par défaut du MVP, et il est volontaire : on peut installer l'outil et observer la chaîne de décision avant de lui donner le moindre identifiant de pare-feu. La contrepartie, qu'il faut dire, est qu'une installation neuve simule au lieu de bloquer.

Sur la détection : les règles YAML couvrent un ensemble fixé d'opérateurs, avec un sous-ensemble de traduction Sigma — ce n'est pas un moteur Sigma, et la traduction signale ses pertes plutôt que de les masquer.

Sur le réseau : aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface du projet, et les défauts pointent vers l'intérieur (SQLite, bus en mémoire, interface servie localement sans CDN). C'est un constat de lecture du contrat, à confirmer par un audit du code ; je préfère l'écrire ainsi plutôt que d'en faire un slogan. Le trafic sortant est censé être un choix explicite : un connecteur configuré, un webhook de notification, ou NATS si l'on choisit ce bus.

## Ce qui manque, et qui manque franchement

- **C'est un alpha.** Le statut déclaré est « Development Status :: 3 - Alpha », la version est 0.1.0. Il ne faut pas le mettre en production cette semaine.
- **Pas d'agent endpoint.** Thot Secure consomme des événements normalisés ; la télémétrie hôte doit venir d'ailleurs. C'est un choix de périmètre, pas une feuille de route cachée.
- **Pas de corpus de règles éprouvé.** Les règles livrées ne sont pas ajustées à votre environnement, et les envoyer directement en mode `auto` est précisément l'erreur que les défauts cherchent à empêcher.
- **RBAC grossier** : quatre rôles (`viewer`, `analyst`, `responder`, `admin`). Un vrai déploiement multi-tenant voudra plus fin.
- **PostgreSQL non testé par défaut**, connecteurs en simulation, pas de place de marché d'intégrations, pas de support éditeur.
- **Gouvernance à écrire publiquement.** Le développement se fait sous DCO, sans CLA, avec au moins une approbation de mainteneur avant fusion, et une règle tenue comme constitutionnelle : aucune capacité offensive (pas d'exploit, pas de scan agressif, pas de brute force, pas de hack-back). Si vous constatez que le document de gouvernance n'est pas encore dans le dépôt public, dites-le : c'est une lacune, pas un détail.

## Reproductibilité

La suite de tests est en `unittest`, sans dépendance externe :

```
python -m unittest discover -s tests -t . -v
```

`pytest` fonctionne également et tourne en CI. La couverture prévue inclut la configuration et les défauts de sûreté, le stockage et l'isolation entre tenants, la chaîne d'audit et la détection de falsification, le bus mémoire et le bus SQLite, tous les opérateurs du moteur de règles, le scoring, la décision (mode automatique contre approbation, cooldown, plafond horaire, cibles protégées), les actions et le rollback, les collecteurs, l'API (401/403, RBAC, parcours ingestion → finding → action → rollback, WebSocket, isolation), les rapports (dont SARIF 2.1.0) et la CLI.

## Absence de verrouillage

Les règles, les politiques et les playbooks sont des fichiers YAML dans le dépôt ; l'API est décrite par un schéma OpenAPI 3.1 généré, et l'interface REST est versionnée sous `/api/v1` ; la CLI accepte `--json` sur toutes les commandes, avec des codes de sortie documentés (`0` succès, `1` erreur, `2` usage, `3` vérification négative — par exemple une chaîne d'audit corrompue) ; le journal d'audit s'exporte en deux formats standards. Le contrat prévoit par ailleurs des clients Python, TypeScript et Go ainsi qu'un déploiement Docker, Compose, Kubernetes, Helm, Terraform et Ansible : c'est l'arborescence cible du contrat, à ne pas confondre avec ce qui est déjà livré.

## Comment participer

Le plus utile aujourd'hui n'est pas du code : c'est de signaler ce qui casse à l'installation, ce qui se comporte autrement que la documentation, et les cas où une politique fait autre chose que ce qu'un lecteur attentif attendait. Les contributions se font sous DCO (pas d'assignation de copyright), la règle sur les capacités offensives est non négociable, et les désaccords sur le contrat d'interface sont bienvenus : c'est un document écrit, fait pour être contesté.

---

# 6. Bloc soutien (FR) — à n'utiliser que si les dons sont mentionnés

**Décision éditoriale** : LinuxFr n'est pas un lieu de collecte, et ce journal se tient sans appel aux dons. Si — et seulement si — le sujet est soulevé dans les commentaires, la réponse à publier est le bloc ci-dessous, une seule fois, en fin de fil, jamais en accroche et jamais dans le corps du journal. Les quatre éléments sont obligatoires et doivent être recopiés caractère par caractère.

> **Soutien (facultatif).** Le projet n'a pas de modèle économique et ne vend rien. Si vous souhaitez soutenir le travail :
>
> ```
> Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
> Solana  (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
> ```
>
> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.
>
> Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais de clé privée ni de phrase de récupération. Aucun don ne donne droit à un support prioritaire, à une fonctionnalité ou à une influence sur les décisions techniques.

**Interdits absolus** : ne jamais recopier ces adresses de mémoire ou depuis un autre fichier que le contrat (§12) ou le dépôt officiel ; ne jamais les placer en accroche ; ne jamais suggérer une contrepartie ; ne jamais proposer d'envoyer une clé privée ou une phrase de récupération (le projet ne le demande jamais, et toute demande de ce type est une tentative d'arnaque à signaler).

---

# 7. Variante dépêche (FR) — pour soumission à la modération, après le journal

> **Titre :** `Thot Secure 0.1.0, SOAR défensif sous Apache-2.0 : actions réversibles et journal d'audit chaîné`
>
> **Accroche :** Thot Secure est un SOAR/CSPM défensif en Python/FastAPI, publié en v0.1.0 sous Apache-2.0. Règles de détection YAML, décision *policy-as-code*, playbooks toujours accompagnés d'un rollback, journal d'audit chaîné par hachage et vérifiable localement. Dry-run actif par défaut. Alpha, avec des limites explicites.
>
> **Corps :** reprendre le §5 en retirant les titres de section et en condensant les paragraphes « Où sont les compromis » et « Ce qui manque », pour viser 500 à 600 mots. Points à conserver impérativement : statut alpha, SQLite par défaut, connecteurs en mode simulé, absence (ou présence, selon vérification) d'agents endpoint, commande exacte des tests, et la déclaration de qualité d'auteur.
>
> **Liens :** dépôt `https://github.com/thotsecure/thot-secure`. Aucun autre lien.

---

# 8. Aide au répondant (FR) — objections typiques sur LinuxFr

| Objection | Réponse |
|---|---|
| « Pourquoi Apache-2.0 et pas GPL ? » | Réponse factuelle : le choix est Apache-2.0 avec un fichier `NOTICE`. Ne pas entrer dans un débat juridique improvisé ni affirmer des compatibilités de licence sans vérification ; si la question est poussée, dire que le choix est documenté dans le dépôt et que la discussion est ouverte. |
| « Est-ce que ça téléphone à la maison ? » | Reprendre la formulation du journal : aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface, à confirmer par lecture du code ; les défauts pointent vers l'intérieur ; les sorties réseau sont censées être explicites (connecteur configuré, webhook, NATS). Inviter à vérifier plutôt que demander de croire. |
| « Encore un outil qui n'existe qu'à moitié. » | Reconnaître : oui, c'est un alpha, la liste de ce qui manque est dans le journal et elle est franche. Ne pas défendre l'inachevé, ne pas promettre de dates. |
| « Pourquoi pas du Rego par défaut ? » | Rego/OPA est pris en charge si `THOT_OPA_BIN` pointe vers un binaire présent. Le YAML est le défaut parce qu'une politique de sécurité doit rester relisible par un analyste en revue de code. Compromis assumé : moins expressif. |
| « SQLite, ce n'est pas sérieux. » | Assumé et documenté : c'est le défaut pour qu'on puisse évaluer l'outil sans démarrer un service ; PostgreSQL/TimescaleDB est documenté comme migration, pas comme défaut. Pour du multi-nœuds, c'est un travail à faire. |
| « Y a-t-il des binaires, ou faut-il tout compiler ? » | Réponse à vérifier dans le dépôt le jour J (image conteneur, distribution Python, présence de dépendances hors ligne). Si ce n'est pas vérifié, le dire. |
| « Qui décide du projet ? » | DCO sans CLA, une approbation de mainteneur avant fusion, document de gouvernance référencé depuis `CONTRIBUTING.md`, et un invariant non négociable sur l'absence de capacité offensive. Si le document n'est pas encore publié, le dire franchement — c'est une lacune, et la reconnaître est meilleur que de la contourner. |
| « Pourquoi pas Wazuh / Shuffle / Sigma ? » | Même réponse qu'ailleurs, et en français : ces outils font bien ce qu'ils font ; Thot Secure ne collecte pas de télémétrie endpoint, traduit un sous-ensemble Sigma sans prétendre le remplacer, et porte un axe différent — décision déclarative, réversibilité dans le modèle de données, audit vérifiable. La composition est le cas d'usage attendu, pas la substitution. |

---

# 9. Checklist avant publication (FR)

- [ ] La qualité d'auteur est déclarée dès l'accroche et dans le corps du journal.
- [ ] Chaque affirmation du journal est vérifiée contre le contrat ou le dépôt ; les éléments relevant de l'arborescence cible sont marqués comme prévus, pas comme livrés.
- [ ] La formulation sur la télémétrie et le réseau est un constat de lecture suivi d'un appel à vérification, jamais un slogan.
- [ ] La commande de tests a été exécutée par l'auteur, et le résultat réel est connu.
- [ ] Le document de gouvernance est présent dans le dépôt public, ou son absence est assumée dans le texte.
- [ ] Aucun chiffre non mesuré ; tout chiffre d'exemple porte la mention « ordre de grandeur à remplacer » ou est supprimé.
- [ ] Aucun vocabulaire commercial ni superlatif marketing.
- [ ] Les dons ne figurent **pas** dans le journal ni dans la dépêche ; le bloc du §6 est prêt à être collé en réponse, une seule fois, si le sujet est soulevé.
- [ ] Les adresses de don, si elles sont utilisées, ont été recopiées caractère par caractère depuis le §12 du contrat, et les quatre éléments obligatoires sont présents.
- [ ] Un seul lien (le dépôt) dans le texte publié.
- [ ] Les règles de compte, de modération et de format ont été relues le jour J.
- [ ] L'auteur est disponible sur 24 à 48 heures pour répondre.
