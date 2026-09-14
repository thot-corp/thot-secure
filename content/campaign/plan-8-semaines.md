```yaml
canal: "Hacker News (Show HN) · Reddit · LinkedIn FR · blog du projet · forums FR · GitHub Discussions · newsletter · vidéo (YouTube + réseaux)"
langue: "fr pour la rédaction FR, en pour HN/Reddit (les artefacts sont écrits dans la langue du canal)"
format: "plan de campagne 8 semaines, tableau hebdomadaire canal par canal, règle de recyclage, dépendances critiques, points de non-retour"
objectif: "Produire une traction mesurable et honnête autour d'Thot Secure v0.1.0 (puis 0.2) : premières contributions externes réelles, premiers utilisateurs qui essaient, et une décision documentée en S8 sur ce qu'on garde et ce qu'on arrête"
mot_cle_principal: "SOAR défensif open source"
longueur: "8 semaines (S1 à S8)"
public_cible: "ingénieurs sécurité et SRE, mainteneurs open source, RSSI de PME/ETSI, devs Python, communautés FR de cybersécurité"
produit: "Thot Secure MVP v0.1.0 — SOAR/CSPM défensif, Python/FastAPI, multi-tenant, Apache-2.0, GitHub"
source_de_verite: "docs/architecture/api-contract.md du dépôt (contrat gelé, v0.1.0)"
jalons: ["S1 release 0.1.0 + Show HN", "S4 ouverture aux règles communautaires", "S7 release 0.2 (si réellement publiée)", "S8 bilan et décision"]
kpi_principal: "contributions externes mergées (PR) et essais réussis déclarés — voir content/campaign/metriques.md"
statut: "prêt à exécuter (aucune section à rédiger)"
date_redaction: "2026-02-14"
```

# Thot Secure — plan de campagne 8 semaines

## 0. Cadre de vérité

- **Toutes les commandes, tous les playbooks, tous les statuts et toutes les variables cités dans ce
  plan existent exactement dans `docs/architecture/api-contract.md`** (§3 à §9). Rien n'est promis
  qui ne soit pas dans le contrat.
- Tout ce qui n'est pas dans le contrat est marqué **« roadmap »** et ne doit jamais être annoncé
  comme disponible.
- **Aucun chiffre de ce document n'est une mesure.** Les cibles (« ≥ 1 PR externe ») sont des
  **hypothèses à calibrer** après le relevé de la semaine 1 : un projet qui démarre n'a pas de
  référence historique. Les efforts en heures sont des **ordres de grandeur à remplacer par vos
  mesures**.
- **Les prix, les étoiles, les vues ne sont pas des objectifs.** Le KPI principal est
  « contributions externes mergées », complété par « essais réussis déclarés ». Le détail de la
  mesure vit dans `content/campaign/metriques.md` — c'est le document qui décide, pas ce plan.
- Aucune mention de dons dans un titre, une accroche, un premier paragraphe ou un post de
  lancement. Les adresses n'apparaissent qu'en fin de contenu, comme au §9.
- **`content/CHARTE-EDITORIALE.md` prime sur ce plan.** Elle fixe les règles non négociables
  (pas de spam, un seul lien par post de canal, valeur technique autonome, format adapté au canal),
  la procédure de validation en cinq étapes, et le contrôle caractère par caractère des adresses de
  don. En cas de conflit entre ce plan et la charte, **la charte gagne**, et le plan se corrige.
- **Disclosure obligatoire** : tout post sur un canal tiers porte la mention explicite
  « je suis l'auteur / mainteneur d'Thot Secure » (`I'm the author, maintainer of Thot Secure` sur les
  canaux anglophones). Pas de drive-by, pas de lien nu.
- **Un seul lien par post de canal**, pas de raccourcisseur opaque, pas de paramètre de suivi ajouté
  aux URL, pas de lien affilié.
- **Les règles de chaque canal sont relues le jour même de la publication** : elles changent, et
  « je ne savais pas » n'est pas une défense.
- Le projet est **défensif** : `DRY_RUN=true` par défaut, `THOT_AUTONOMY=supervised` par défaut,
  **zéro capacité offensive**. Les posts ne doivent jamais employer le vocabulaire de l'attaque
  (« hack », « exploit », « offensive ») : ce serait faux et ça attirerait le mauvais public.

### 0.1 Rythme hebdomadaire type (5 h à 12 h par semaine hors semaine de sortie)

| Jour | Activité | Durée type |
|---|---|---|
| Lundi | Relevé des métriques (quotidien en S1–S2, hebdomadaire ensuite) + une ligne dans le journal des décisions | 30 min |
| Mardi | Publication principale de la semaine (article, release, discussion) | 2–4 h |
| Mercredi | Présence en commentaires : répondre à **tout**, y compris les critiques | 1–2 h |
| Jeudi | Publication secondaire (déclinaison : post, thread, vidéo) | 1–2 h |
| Vendredi | Triage des issues/PR externes : première réponse sous 48 h, toujours | 1 h |

Règle de présence : **une publication sans présence en commentaires pendant 48 h est une
publication ratée**, même si elle a généré du trafic. Le trafic sans réponse humaine n'est pas de
l'adoption.

---

## 1. Tableau semaine par semaine

Colonnes : `Semaine` · `Canal` · `Format` · `Objectif` · `Indicateur (KPI mesurable)` ·
`Effort estimé (h — ordre de grandeur à remplacer par vos mesures)` · `Dépendances / livrables`.

Les cibles chiffrées sont des **hypothèses de départ**, pas des mesures. Elles se recalibrent après
le premier relevé de S1.

### Semaine 1 — lancement (Show HN + Reddit + LinkedIn)

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S1 | GitHub | Release `v0.1.0` taguée + README + topics + `LICENSE`/`NOTICE` en place | Rendre le dépôt présentable en 60 s de lecture | Le dépôt s'installe et `thotsecure demo --tenant demo` fonctionne sur une machine vierge | 3 | Dépend du contrat gelé (`docs/architecture/api-contract.md`) et du MVP réellement exécutable. **Ne pas taguer une release qui ne tourne pas** |
| S1 | Hacker News | Post **Show HN** (texte, pas de lien brut) + lien vers le dépôt | Obtenir les premiers retours techniques exigeants | ≥ 5 commentaires substantiels ; 100 % des commentaires ont une réponse < 24 h | 8 (2 rédaction + 6 présence étalée) | Dépend de la release 0.1.0 publiée et de la vidéo démo disponible. Livrable : `content/forums/*.md` (un fichier par canal) |
| S1 | Reddit (r/opensource ou r/selfhosted selon les règles du sub) | Post orienté « essayez-le, voici quoi faire en 5 minutes » | Convertir des curieux en essayeurs | ≥ 1 personne déclarant avoir exécuté `thotsecure init-db` + `thotsecure demo --tenant demo` | 4 | Dépend de l'historique de participation du compte sur le sub — **voir §3** |
| S1 | LinkedIn (FR) | Post texte + 1 image (diagramme d'architecture) | Toucher le public FR sécurité/RSSI et les recruteurs techniques | ≥ 5 commentaires qualifiés (pas des « Bravo 👏 ») ; ≥ 1 prise de contact entrante | 2 | Dépend du diagramme décrit dans `content/video/01-demo-script.md` (§3) |
| S1 | Blog du projet | Article de lancement : problème, garanties, ce que le projet n'est pas | Poser la référence longue vers laquelle tout le reste renvoie | Article publié, liens sortants vers le dépôt fonctionnels, 0 promesse hors contrat | 4 | Livrable existant : `content/blog/01-lancement-thotsecure.md` |
| S1 | YouTube + réseaux sociaux | Vidéo démo complète (6 min 50) + déclinaison 60 s | Montrer la boucle complète plutôt que la décrire | Vidéo publiée, chapitres fonctionnels, SRT en français disponible | 8 (tournage + montage + sous-titres) | Livrable existant : `content/video/01-demo-script.md` (storyboard, SRT, version 60 s) |
| S1 | Newsletter | Envoi n° 01 : lancement, 3 liens, 1 appel à contribution précis | Créer le lien direct avec les gens intéressés | Envoyée, taux d'ouverture et de clic relevés, ≥ 1 réponse humaine | 2 | Livrable existant : `content/newsletter/01-lancement.md`. Si la liste est vide : **ne pas envoyer**, voir §3 |
| S1 | Réseaux sociaux | 3 posts courts (déclinaison) : dry-run, réversibilité, zéro capacité offensive | Tester 3 angles différents en 1 semaine | Sur les 3 angles : celui qui génère le plus de clics **et** de temps de lecture | 2 | Livrable : `content/social/*.md` |

**Total S1 (ordre de grandeur) : ~33 h.** C'est la semaine la plus lourde du plan : elle concentre
la release, la vidéo et le lancement. Ne pas la doubler avec autre chose.

### Semaine 2 — article technique : audit log chaîné par hash

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S2 | Blog du projet | Article long technique : la chaîne de hash, la formule, ce qu'elle empêche | Prouver la compétence technique, pas le marketing | Article ≥ 1 200 mots, formule de hachage reproduite à l'identique du contrat §3.5, 0 approximation | 8 | Livrable existant : `content/blog/03-audit-log-chaine-hash.md`. Dépend du schéma `AuditRecord` (§3.5) |
| S2 | Hacker News | **Commentaire** (pas un nouveau post) sur le fil S1 + lien vers l'article | Réactiver un fil qui vit encore plutôt que spammer un nouveau post | Au moins 1 réponse technique d'un tiers | 1 | Dépend de la survie du fil S1 ; si le fil est mort, sauter et reporter à S4 |
| S2 | Reddit | Cross-post de l'article dans un sub technique approprié | Tester si l'angle « audit » intéresse un autre public que le lancement | ≥ 3 commentaires techniques, ratio commentaires/votes > 0,05 | 3 | Dépend de l'historique de participation. **Pas de r/netsec à ce stade** (§3) |
| S2 | GitHub | Discussion dans le dépôt : « cassez la chaîne » (exercice guidé, code de sortie 3) | Transformer un lecteur passif en contributeur qui touche le code | ≥ 1 personne postant la sortie de `thotsecure audit verify` | 2 | Dépend de Discussions activées et d'un dépôt qui a déjà un peu de visites |
| S2 | LinkedIn (FR) | Post court : « ce que 40 lignes de YAML ne peuvent pas casser » | Ramener l'audience FR vers l'article | ≥ 20 clics sortants mesurés côté serveur | 1 | Dépend de l'article publié |
| S2 | Réseaux sociaux | 3 posts déclinaisons de l'article (voir §2) | Tester 3 accroches sur le même contenu | Identifier l'accroche au meilleur taux de clic | 2 | Livrable : `content/social/*.md`, même sujet = déclinaisons |

**Total S2 (ordre de grandeur) : ~17 h.**

### Semaine 3 — devlog + forums FR

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S3 | Blog du projet | Devlog : ce qu'on a construit, ce qui a cassé, ce qu'on n'a pas fait | Créer la régularité et la confiance par la transparence | Devlog publié avec ≥ 2 échecs assumés explicitement | 5 | Livrable existant : `content/blog/02-devlog-sprint1.md` |
| S3 | Forums FR (communautés cybersécurité / dev Python) | Fil de présentation + réponse aux questions, ton non commercial | Trouver les premiers utilisateurs francophones | ≥ 3 réponses de membres, ≥ 1 essai déclaré | 4 | Livrable : `content/forums/*.md` (un fichier par forum). Dépend des règles de chaque forum : lire la charte avant de poster |
| S3 | GitHub Discussions | Ouvrir un fil « roadmap 0.2 : que prioriser ? » avec 3 options fermées | Faire décider la communauté plutôt que de deviner | ≥ 5 participants distincts votant ou argumentant | 2 | Dépend d'une audience minimale : sans trafic, le fil reste muet — ce n'est pas un échec du fil |
| S3 | LinkedIn (FR) | Post devlog : un échec concret + comment il a été détecté | Crédibiliser par l'aveu plutôt que par la démo | ≥ 1 commentaire d'un pair sur le fond | 1 | Dépend du devlog publié |
| S3 | Newsletter | **Pas d'envoi** cette semaine | Éviter la fatigue de liste | 0 envoi — c'est volontaire | 0 | — |

**Total S3 (ordre de grandeur) : ~12 h.**

### Semaine 4 — règles de détection communautaires

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S4 | GitHub | Modèle d'issue « proposer une règle » + gabarit YAML + doc de contribution au format §5 | Rendre la contribution la plus utile **facile** | Modèle mergé, `thotsecure rules validate --path rules` documenté, 0 règle acceptée sans validation | 3 | Dépend du format de règle (contrat §5) et de `thotsecure rules validate` (§8). **Une règle invalide ne casse pas le chargement : elle est rejetée avec un diagnostic** — le dire dans le modèle |
| S4 | Blog du projet | Article court : écrire une règle de détection en 20 lignes de YAML | Recruter des contributeurs de règles, pas des utilisateurs | Article publié, ≥ 1 règle proposée par un externe à la fin de S4 | 4 | Livrable : nouveau fichier dans `content/blog/` (poursuivre la numérotation, n° 04) |
| S4 | GitHub Discussions | Fil « quelle règle vous manque ? » avec exemples de règles livrées | Obtenir des besoins réels plutôt que des compliments | ≥ 5 propositions distinctes, classées par faisabilité | 2 | Dépend du catalogue `rules/` livré |
| S4 | Hacker News / Reddit | Second passage : angle « voici comment écrire une règle en YAML » | Retester HN avec un artefact nouveau, pas un repost | Nouveau post seulement si l'artefact est nouveau ; sinon **ne rien poster** | 3 | **§3 : jamais deux fois la même URL ; jamais de resoumission à l'identique** |
| S4 | LinkedIn (FR) | Post + capture d'une règle YAML commentée | Montrer la simplicité du modèle | ≥ 10 clics vers le dépôt | 1 | Dépend de l'article S4 |
| S4 | Réseaux sociaux | 3 posts déclinaisons du sujet « règles » | Tester l'angle contributeur | ≥ 1 conversation entamée en commentaire | 2 | Livrable : `content/social/*.md` |

**Total S4 (ordre de grandeur) : ~15 h.**

### Semaine 5 — connecteurs

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S5 | GitHub | 2 issues « bonne première contribution » sur des connecteurs, avec périmètre fermé | Transformer l'intérêt en PR réelle | ≥ 1 PR externe ouverte sur un connecteur | 3 | Dépend du mécanisme de connecteurs (contrat §7) et du **mode simulé par défaut** : c'est l'argument massue — on peut développer un connecteur sans credentials |
| S5 | Blog du projet | Article : anatomie d'un connecteur, du mode simulé au mode réel | Prouver qu'on peut contribuer sans risque | Article publié, ≥ 1 connecteur externe en cours | 6 | Livrable : nouveau fichier dans `content/blog/` (n° 05). Dépend des connecteurs listés au contrat §7 : `cloudflare`, `aws-waf`, `modsecurity`, `nginx-local`, `null` |
| S5 | Newsletter | Envoi n° 02 : mi-parcours, ce qui a changé, appel à connecteurs | Réactiver la liste avec du concret | ≥ 1 réponse de lecteur, ≥ 1 clic sur l'issue « bonne première contribution » | 3 | Livrable : nouveau fichier dans `content/newsletter/` (n° 02). Si la liste est < 50 abonnés : **suspendre le format**, voir §4 |
| S5 | Vidéo | Vidéo courte (60 s) : « un connecteur en mode simulé, sans credentials » | Démontrer la sécurité du branchement | Vidéo publiée, ≥ 10 vues qualifiées (durée moyenne > 50 %) | 2 | Dépend de `content/video/01-demo-script.md` (§10, version 60 s) : réutiliser les plans dry-run |
| S5 | Reddit | Post : « comment on teste un SOAR sans lui donner les clés » | Trouver l'audience SRE/ops, pas seulement sécurité | ≥ 5 commentaires, ≥ 1 essai déclaré | 3 | Dépend de l'historique de participation sur le sub visé |
| S5 | LinkedIn (FR) | Post : le dry-run comme argument de déploiement | Toucher les décideurs prudents | ≥ 1 échange entrant (MP ou commentaire) | 1 | Dépend de la vidéo 60 s |

**Total S5 (ordre de grandeur) : ~18 h.**

### Semaine 6 — retours d'expérience pilote

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S6 | Blog du projet | Étude de cas : un pilote réel, ce qui a marché, ce qui a coincé | Fournir la seule preuve qui compte : quelqu'un d'autre s'en est servi | Étude de cas publiée **avec l'accord écrit** du pilote, et avec des limites assumées | 6 | **Condition absolue : un pilote réel existe.** Sinon, remplacer par « ce que nos propres tests ont cassé » et le dire explicitement. Aucun pilote inventé, aucun témoignage retouché |
| S6 | GitHub Discussions | Fil : « votre retour d'usage, y compris négatif » | Collecter les frictions réelles | ≥ 3 retours distincts, dont ≥ 1 négatif exploitable | 2 | Dépend d'utilisateurs réels : sans eux, le fil reste vide et c'est une information en soi |
| S6 | LinkedIn (FR) | Post étude de cas, chiffres uniquement s'ils sont mesurés chez le pilote | Parler aux organisations qui hésitent | ≥ 1 demande de mise en relation ou de démo | 2 | Dépend de l'accord du pilote |
| S6 | Newsletter | **Pas d'envoi** (l'étude de cas part en S7) | — | 0 envoi | 0 | — |
| S6 | Réseaux sociaux | 2 posts : une friction réelle, une correction apportée | Montrer qu'on corrige | ≥ 1 issue ouverte par un lecteur | 2 | Livrable : `content/social/*.md` |

**Total S6 (ordre de grandeur) : ~12 h.**

### Semaine 7 — release 0.2

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S7 | GitHub | Release **0.2** taguée + notes de version honnêtes (ajouts, correctifs, ce qui reste cassé) | Donner une raison de revenir à ceux qui ont essayé la 0.1.0 | Release publiée **uniquement si le code est réellement mergé et que la suite de tests passe** (`python -m unittest discover -s tests -t . -v`) | 3 | **Dépendance critique : ne jamais annoncer 0.2 avant publication réelle.** Voir §5 |
| S7 | Blog du projet | Article « ce qui change en 0.2 » avec les commandes exactes et les changements de schéma | Éviter la surprise aux utilisateurs existants | Article publié le jour de la release, pas avant | 4 | Livrable : nouveau fichier dans `content/blog/` (n° 06) |
| S7 | Hacker News / Reddit | Post « 0.2 : ce qui change » avec un artefact nouveau (release + article) | Retester les canaux qui ont marché en S1, avec du neuf | Nouveau post autorisé : contenu réellement nouveau. ≥ 1 PR externe dans les 7 jours | 5 | Dépend de la release 0.2 publiée **et** d'un artefact nouveau |
| S7 | Newsletter | Envoi n° 03 : release 0.2, étude de cas, appel à contribution ciblé | Relancer une dernière fois avant le bilan | ≥ 1 réponse, ≥ 1 clic vers les issues « bonne première contribution » | 3 | Livrable : nouveau fichier dans `content/newsletter/` (n° 03) |
| S7 | Vidéo | Vidéo courte « quoi de neuf en 0.2 » (réutiliser le storyboard existant) | Recycler sans retomber | Vidéo publiée, chapitres cohérents avec la release | 6 | Dépend de `content/video/01-demo-script.md` (structure et chapitres réutilisables) |
| S7 | LinkedIn (FR) | Post release + un chiffre réel de la campagne (mesuré, pas estimé) | Crédibiliser par la transparence | ≥ 1 partage organique par un tiers | 1 | Dépend des relevés de `content/campaign/metriques.md` |

**Total S7 (ordre de grandeur) : ~22 h.**

### Semaine 8 — rétrospective + bilan

| Semaine | Canal | Format | Objectif | Indicateur | Effort (h) | Dépendances / livrables |
|---|---|---|---|---|---|---|
| S8 | Blog du projet | Rétrospective : ce qui a marché, ce qui a échoué, avec les chiffres **réels** et la fenêtre de mesure | Rendre la campagne vérifiable, y compris ses échecs | Article publié avec ≥ 3 chiffres mesurés, chacun daté et sourcé | 5 | Livrable : nouveau fichier dans `content/blog/` (n° 07). Dépend de `content/campaign/metriques.md` dûment rempli |
| S8 | `content/campaign/metriques.md` | Consolidation du tableau de bord + journal des décisions daté | Fermer la boucle mesure → décision | Journal des décisions complet sur 8 semaines, chaque ligne avec une décision **et** une action | 3 | Dépend des relevés quotidiens S1–S2 et hebdomadaires S3–S8. Le tableau de bord n'est valide que s'il a été tenu **pendant**, pas reconstitué après |
| S8 | GitHub Discussions | Fil « ce qu'on garde, ce qu'on arrête » | Décider avec la communauté, pas contre elle | Fil publié avec la liste explicite des canaux abandonnés | 2 | Dépend du §4 (points de non-retour) |
| S8 | Décision interne | Note de décision : go / pivot / pause, avec critères écrits | Éviter de continuer par inertie | Décision écrite, datée, avec les seuils qui l'ont déclenchée | 2 | Dépend du bilan. **Si aucun critère de succès n'est atteint, la décision par défaut est « réduire le périmètre », pas « continuer comme avant »** |
| S8 | Réseaux sociaux | 1 post bilan honnête (ce qui n'a pas marché inclus) | Crédibiliser la suite | ≥ 1 retour de pair | 1 | Dépend de l'article de rétrospective |

**Total S8 (ordre de grandeur) : ~13 h.**

**Total campagne (ordre de grandeur) : ~142 h sur 8 semaines**, soit une moyenne de ~18 h/semaine
tirée vers le haut par S1, S5 et S7. Ces valeurs sont un **plafond de planification à remplacer par
vos mesures réelles** : chronométrez la première semaine et recalibrez tout le tableau avec vos
propres durées.

---

## 2. Règle de recyclage : « 1 sujet = 1 article long + 3 posts + 1 thread + 1 vidéo »

### 2.1 Le mécanisme

Un **sujet** (un problème, pas un produit) est décliné en 6 artefacts, dans cet ordre strict :

| Rang | Artefact | Rôle | Longueur | Délai par rapport à l'article |
|---|---|---|---|---|
| 1 | **Article long** (blog du projet) | L'ancre. C'est le seul artefact qui contient tout : la preuve, les commandes exactes, les limites | 1 200–2 000 mots | J0 |
| 2 | **Thread** (GitHub Discussions) | L'endroit où l'on cherche la contradiction. On y pose une question ouverte et on y répond | 150–300 mots + questions | J+2 |
| 3 | **Post 1** (LinkedIn FR) | Angle « conséquence pour une organisation » : ce que ça change concrètement | 120–180 mots | J+3 |
| 4 | **Post 2** (Reddit ou HN) | Angle « détail technique contestable » : la partie où des gens compétents peuvent nous reprendre | 150–250 mots | J+5 |
| 5 | **Post 3** (réseau social court) | Angle « une image, une phrase » : le diagramme ou la sortie de commande qui se partage seule | 1 visuel + 1 phrase | J+7 |
| 6 | **Vidéo** (60 s) | Angle « regardez-le se faire » : la démonstration, sans commentaire superflu | 60 s, sous-titres brûlés | J+10 |

Pourquoi cet ordre : l'article donne la profondeur, le thread fait remonter les objections pendant
qu'on est encore disponible, les posts testent des accroches différentes sur le même fond, la vidéo
arrive quand le sujet est déjà connu et qu'elle peut convertir plutôt que découvrir.

Pourquoi **pas** tous le même jour : cinq liens vers la même page le même jour sur les mêmes
plateformes, c'est du spam et ça dilue l'attention. Étaler sur 10 jours, c'est aussi ce qui permet de
mesurer **quelle accroche** fonctionne, au lieu de tout mélanger.

### 2.2 Exemple concret, de bout en bout — sujet « audit log chaîné par hash » (S2)

**Sujet** : *un journal d'audit que l'on peut vérifier, pas un journal qu'on nous demande de croire.*

1. **Article long** — `content/blog/03-audit-log-chaine-hash.md` (déjà planifié en S2).
   Contenu : pourquoi un journal append-only ne suffit pas ; le schéma `AuditRecord` (contrat §3.5) ;
   la formule exacte
   `hash = sha256(seq|ts|tenant_id|actor|actor_role|action|canonical(target)|canonical(before)|canonical(after)|prev_hash)`
   avec `canonical()` = JSON trié, séparateurs compacts, UTF-8 ; le genesis `prev_hash = "sha256:genesis"` ;
   les deux commandes de vérification (`thotsecure audit verify`, `thotsecure audit tail`) ; les codes de
   sortie 0 (intègre) et 3 (vérification négative) ; puis une section **« ce que ça ne protège pas »**
   (une base entièrement réécrite, un attaquant qui contrôle le générateur, la perte de la clé de
   signature hors du périmètre du MVP).
2. **Thread GitHub Discussions (J+2)** — titre : « Cassez la chaîne : modifiez une ligne, obtenez le
   code 3 ». Corps : l'exercice en 4 étapes (`thotsecure init-db`, `thotsecure demo --tenant demo`,
   `thotsecure audit verify`, puis modification manuelle d'une ligne et nouvelle vérification), plus
   une question ouverte : « quel scénario de menace manque à notre modèle ? ». Objectif : obtenir
   des objections techniques réelles, pas des félicitations.
3. **Post LinkedIn FR (J+3)** — angle organisation : « En audit, la question n'est pas *avez-vous un
   journal ?* mais *pouvez-vous prouver qu'il n'a pas été modifié ?* Voici les 6 lignes de code qui
   répondent. » + le diagramme de la chaîne de hash. 150 mots, 1 lien vers l'article.
4. **Post Reddit / HN (J+5)** — angle contestable : « Nous hachons `prev_hash` dans chaque
   enregistrement. Voici pourquoi nous incluons `actor_role` dans le pré-image — et pourquoi ça
   pourrait être une erreur. » 200 mots, lien vers l'article, et surtout : présence en commentaires
   pendant 24 h.
5. **Post court (J+7)** — un visuel : la sortie de `thotsecure audit verify` avant/après falsification
   d'une ligne, avec les codes de sortie `0` et `3` en gros. Une phrase : « 0 = intègre. 3 = chaîne
   rompue. » Lien vers l'article.
6. **Vidéo 60 s (J+10)** — réutilisation directe du plan 04:45–05:10 du storyboard
   (`content/video/01-demo-script.md`) : `audit verify`, `audit tail`, les deux codes de sortie.
   Sous-titres brûlés, SRT issu du même fichier.

**Coût du recyclage (ordre de grandeur à remplacer par vos mesures)** : ~2 h par dérivé, soit ~10 h
en plus de l'article (8 h), pour **5 portes d'entrée** au lieu d'une. Le recyclage n'est rentable que
si l'article est bon : décliner un contenu faible multiplie la faiblesse.

**Règles de recyclage à ne pas violer :**

- Chaque dérivé a **sa propre accroche et sa propre destination** ; jamais le même texte copié sur
  cinq plateformes.
- Chaque dérivé renvoie **vers l'article du projet ou vers le dépôt** — jamais vers une page de
  capture d'e-mails, jamais vers un lien raccourci inconnu.
- Chaque dérivé **cite le contrat** (`docs/architecture/api-contract.md`) dès qu'il parle de
  comportement produit.
- Si l'article contient un chiffre non mesuré, il est étiqueté comme tel — et les dérivés qui
  reprennent ce chiffre doivent le réétiqueter. Un chiffre qui perd son étiquette en se déclinant
  devient un mensonge.

---

## 3. Dépendances critiques

| # | Dépendance | Ce qui casse si on l'ignore | Ce qu'on fait |
|---|---|---|---|
| 1 | **r/netsec** exige un historique de participation et un ratio d'auto-promotion sain | Post supprimé, compte signalé, voire banni : le canal est perdu pour toute la campagne | **Ne pas poster sur r/netsec sans historique de participation réel sur le sub.** Accumuler d'abord des réponses utiles à d'autres fils pendant S1–S3. En cas de doute : ne pas poster |
| 2 | Règles de Hacker News (Show HN) | Suppression, marquage, réputation abîmée | Show HN réservé à un projet **essayable** : dépôt public, fonctionnel, avec un mode sûr par défaut. Aucune demande de vote, jamais. Aucune resoumission de la même URL. Présence obligatoire dans le fil |
| 3 | Charte de chaque forum FR | Message supprimé, compte bloqué | Lire la charte **le jour de la publication**, respecter la section « présentations » quand elle existe, ne jamais coller le même texte partout. Le fichier de référence est `content/CHARTE-EDITORIALE.md` (§3, étape 4 : conformité au canal) |
| 3 bis | Disclosure d'auteur et limitation du nombre de liens | Un post sans disclosure est traité en drive-by ; deux liens ou plus dans un post de canal passent pour du spam | Mention « je suis l'auteur / mainteneur d'Thot Secure » en clair, **un seul lien** par post, aucun raccourcisseur |
| 4 | Le dépôt doit réellement fonctionner | Le premier commentaire technique détruit la crédibilité de la campagne entière | `thotsecure demo --tenant demo` doit tourner sur une machine vierge avant la release 0.1.0. Tests : `python -m unittest discover -s tests -t . -v` verts |
| 5 | La vidéo démo | Un lancement sans démo oblige à décrire au lieu de montrer | `content/video/01-demo-script.md` tourné **avant** le Show HN ; prévoir le plan de secours (§9 du script) |
| 6 | Liste de diffusion réelle | Une newsletter envoyée à 4 personnes est un placebo qui consomme 3 h | Sous ~50 abonnés (ordre de grandeur), **ne pas envoyer de newsletter** : reporter le format et garder le fil GitHub Discussions comme canal direct |
| 7 | GitHub Discussions activées et un minimum de trafic | Les fils restent muets, ce qui est démoralisant et non informatif | Ne pas compter sur Discussions avant S3. Un fil vide en S2 n'est pas un signal d'échec du sujet |
| 8 | Release 0.2 réellement publiée | Annoncer une version non publiée détruit la confiance définitivement | Voir §5. Si le code n'est pas pret, la S7 devient une semaine de développement et l'annonce glisse |
| 9 | Un pilote réel et son accord écrit pour S6 | Publier une étude de cas sans accord, ou enjolivée, est une faute grave | Sans pilote : remplacer par un retour d'usage interne, **étiqueté comme tel** |
| 10 | Adresses de dons conformes au contrat §12 | Une adresse inventée détourne de l'argent et détruit la confiance | Toujours copier depuis `README.md` / `docs/support.md` / `GET /ui/support`. Ne jamais retaper de mémoire |
| 11 | Contrat gelé (`docs/architecture/api-contract.md`) | Chaque post qui cite une commande inexistante devient une dette de crédibilité | Toute affirmation produit se vérifie dans le contrat avant publication. Ce qui n'y est pas est marqué **roadmap** |
| 12 | Présence en commentaires | Un post sans réponses est un post mort ; le trafic sans humain ne convertit pas | 48 h de présence après chaque publication, bloquées dans l'agenda avant de publier |

---

## 4. Points de non-retour (ce qu'on arrête si ça ne marche pas)

Ces règles sont écrites **avant** de connaître les résultats, pour éviter de les réécrire après coup.
Les seuils sont des **hypothèses à calibrer sur le relevé S1** (voir `content/campaign/metriques.md`),
pas des mesures.

| # | Condition observable | Ce qu'on arrête | Ce qu'on fait à la place |
|---|---|---|---|
| 1 | Après 2 semaines, très peu d'étoiles et **surtout aucune contribution externe** (ordre de grandeur : < 50 étoiles et 0 PR externe) | L'angle **produit** (« voici notre SOAR ») | Passer à l'angle **technique/problème** : publier sur des problèmes datés et vérifiables (« comment nous détectons X en Y lignes de YAML »), et non sur l'outil |
| 2 | Après S4–S5, toujours 0 PR externe malgré les issues « bonne première contribution » | La campagne « contribuez » | Passer à l'angle **utilisateur** : tutoriels d'installation, recettes de déploiement, guides d'intégration — on abaisse le coût d'entrée avant de demander un effort |
| 3 | Un canal publie 2 fois et génère moins de 5 visites qualifiées au total | Ce canal, pour le reste de la campagne | Concentrer l'effort sur les 2 canaux qui ont réellement produit des visiteurs **et** des essais |
| 4 | Un post HN/Reddit reçoit moins de 5 commentaires et aucun trafic mesurable | Les tentatives répétées sur ce canal | Ne pas y revenir avant d'avoir un artefact réellement nouveau (release, étude de cas) |
| 5 | La newsletter reste sous ~50 abonnés après S5 (ordre de grandeur) | Le format newsletter | Fusionner le contenu dans le dépôt (Discussions + release notes) jusqu'à ce qu'il existe une audience |
| 6 | Les essais déclarés restent à 0 après S5, malgré du trafic | L'hypothèse « il suffit de montrer » | Enquêter sur le **frottement** : demander à 3 personnes pourquoi elles n'ont pas essayé, corriger l'installation, refaire une vidéo de 3 minutes « de zéro à un finding » |
| 7 | Le pilote de S6 ne peut pas être documenté honnêtement (pas d'accord, résultats non vérifiables) | Le contenu de S6 | Publier un retour d'usage interne étiqueté comme tel. **Ne jamais fabriquer ni embellir un témoignage** |
| 8 | Le rythme impose de publier du contenu vide pour tenir le calendrier | La cadence | Réduire à **une publication par semaine**, voire une par quinzaine. Mieux vaut 8 bons contenus que 30 mauvais : la cadence n'est pas un objectif, la crédibilité en est un |
| 9 | Critères de succès non atteints en S8 | La poursuite « comme avant » | La décision par défaut est **réduire le périmètre** (un canal, un format, un objectif), pas prolonger la même campagne |

**Règle d'arrêt absolue** : si la seule façon de continuer est d'acheter de l'attention, de créer de
faux comptes, de solliciter des votes ou de publier du contenu qu'on ne peut pas prouver — **on
arrête la campagne**. Un projet open source qui s'arrête proprement garde sa crédibilité et peut
reprendre ; une campagne qui triche ne la récupère pas.

---

## 5. Annonce de la release 0.2 — condition stricte

La release **0.2** ne s'annonce **que si elle est réellement publiée**. Concrètement :

1. Le code est mergé sur la branche principale.
2. La suite de tests passe : `python -m unittest discover -s tests -t . -v` (le contrat §11 précise
   que les tests sont en `unittest`, compatibles `pytest` en CI).
3. Le tag est posé et la page de release existe, avec des notes de version qui disent **aussi** ce
   qui reste cassé.
4. Les notes de version ne mentionnent que ce qui est dans le contrat, ou explicitement marqué
   **roadmap**.

Si ces quatre points ne sont pas tous vrais : **la S7 devient une semaine de développement**, et
l'annonce glisse d'autant. Aucun post ne dit « bientôt disponible », « en cours de finalisation » ou
« prévu pour ». Le calendrier de campagne est un plan, pas un engagement public : personne à
l'extérieur ne saura qu'une date a glissé, et c'est très bien ainsi.

Corollaire : les jalons de S4 (règles communautaires) et S5 (connecteurs) sont annoncés comme des
**appels à contribution**, pas comme des fonctionnalités livrées. On ouvre un chantier, on ne promet
pas un résultat.

---

## 6. Ce qu'on ne fait pas

| Interdit | Pourquoi |
|---|---|
| **Acheter des étoiles, des followers, des vues ou des upvotes** | C'est une falsification de la mesure : on ne sait plus ce qui marche, et la découverte est humiliante |
| **Créer de faux comptes** (pour commenter, voter, relayer, poser des questions complaisantes) | Détectable, disqualifiant, et ça transforme la communauté en décor |
| **Spammer des messages privés** (LinkedIn, Reddit, Discord, e-mail) pour demander une étoile ou un partage | Une demande non sollicitée n'est pas une contribution, c'est une nuisance. Zéro MP de prospection |
| **Sondages de complaisance** (« vous trouvez notre projet utile ? ») | Un sondage complaisant produit un chiffre flatteur et aucune décision. Si on pose une question, elle doit pouvoir recevoir « non » |
| **Demander explicitement un vote sur HN ou Reddit** | Violation directe des règles de ces plateformes, et perte du canal |
| **Copier-coller le même texte sur 5 plateformes** | Signal de spam, et impossible de savoir quelle accroche a fonctionné |
| **Publier une sortie de commande fabriquée, une capture retouchée, une démo truquée** | La démo est la preuve : une preuve falsifiée annule tout le reste |
| **Annoncer une fonctionnalité « roadmap » comme disponible** | Le premier utilisateur qui essaie le découvre et le dit publiquement |
| **Cacher les échecs du devlog ou de la rétrospective** | La transparence est le seul avantage d'un projet jeune face à un éditeur installé |
| **Employer le vocabulaire offensif** (« hack », « exploit », « attaque », « offensif ») pour le référencement | Faux (le projet n'a **aucune** capacité offensive) et attire un public qui n'a rien à faire là |
| **Faire du « AI-powered » vide** | Aucune promesse de ce genre n'est adossée au contrat. Si ce n'est pas dans le contrat, ça ne se dit pas |
| **Modérer ou supprimer les critiques négatives** dans les espaces qu'on contrôle | Une critique supprimée revient toujours, ailleurs et plus fort |
| **Promettre une contrepartie contre un don** ou suggérer un avantage | Contraire au contrat §12 : dons volontaires, aucune contrepartie attendue |
| **Mettre une adresse de don en accroche, en présentation ou en signature de post** | Règle du projet : les adresses n'apparaissent qu'en fin de contenu, avec l'avertissement anti-arnaque |

---

## 7. Déclinaisons et fichiers de travail

| Artefact | Fichier | Semaines d'utilisation |
|---|---|---|
| Article de lancement | `content/blog/01-lancement-thotsecure.md` | S1, recyclé en S3 et S8 |
| Article technique audit chaîné | `content/blog/03-audit-log-chaine-hash.md` | S2, exemple de recyclage du §2.2 |
| Devlog sprint 1 | `content/blog/02-devlog-sprint1.md` | S3 |
| Articles S4, S5, S6, S7, S8 | `content/blog/` (nouveaux fichiers, numérotation à poursuivre : 04 à 07) | S4–S8 |
| Posts par canal — forums et agrégateurs | `content/forums/hacker-news.md`, `content/forums/reddit-netsec.md`, `content/forums/reddit-selfhosted.md`, `content/forums/lobsters.md`, `content/forums/journal-du-hacker.md`, `content/forums/linuxfr.md` (un fichier par canal ; tout nouveau canal crée son fichier dans `content/forums/`) | S1–S8 |
| Posts courts et déclinaisons | `content/social/linkedin.md`, `content/social/x.md`, `content/social/bluesky.md`, `content/social/mastodon-infosec.md`, `content/social/reddit-cross-post-plan.md` | S1–S8 |
| Newsletter | `content/newsletter/01-lancement.md` (S1) puis n° 02 (S5) et n° 03 (S7) | S1, S5, S7 |
| Vidéo et déclinaisons 60 s | `content/video/01-demo-script.md` | S1, S5, S7, et toute vidéo dérivée |
| Tableau de bord de mesure | `content/campaign/metriques.md` | S1 → S8, relevé continu |
| Charte éditoriale (règle supérieure) | `content/CHARTE-EDITORIALE.md` | Permanente — relue avant chaque publication |
| Blocs de soutien | `content/funding/blocs-soutien.md` | Fin de contenu uniquement |

---

## 8. Récapitulatif de la campagne en 10 lignes

- S1 lancement : release 0.1.0, Show HN, Reddit, LinkedIn, vidéo, newsletter n° 01.
- S2 profondeur technique : article audit log chaîné + thread « cassez la chaîne ».
- S3 régularité : devlog honnête + forums FR.
- S4 ouverture : contribution de règles de détection.
- S5 ouverture : contribution de connecteurs, sur l'argument du mode simulé.
- S6 preuve : étude de cas d'un pilote réel — ou rien.
- S7 release 0.2 : **seulement si publiée**.
- S8 bilan : chiffres réels, décisions datées, canaux abandonnés explicitement.
- Fil rouge : 1 sujet = 1 article + 3 posts + 1 thread + 1 vidéo, étalés sur 10 jours.
- Fil rouge : on mesure les contributions et les essais, pas les étoiles.

---

## 9. Adresses de dons officielles (fin de contenu uniquement)

Elles ne figurent **jamais** en accroche, ni dans un titre, ni dans les premiers paragraphes d'un
post, ni dans un message privé de prospection. Elles apparaissent en **fin** d'article, en fin de
description de vidéo, et sur la page de soutien du dépôt.

- Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais de
clé privée ni de phrase de récupération.

Ces adresses sont la source unique de vérité du contrat §12 et sont également publiées dans
`README.md`, `.github/FUNDING.yml`, `GET /ui/support` et `docs/support.md`. Toute adresse trouvée
ailleurs est une arnaque : ne la relayez pas, ne la corrigez pas dans les commentaires, renvoyez au
dépôt officiel. Aucune contrepartie n'est promise ni sous-entendue : pas de remerciement commercial,
pas d'accès privilégié, pas de support prioritaire, aucune mention de sponsor.
