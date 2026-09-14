```yaml
canal: "GitHub (Insights/Traffic, Releases, Issues/PR/Discussions) · analytics du site du projet · journaux du serveur · liste de diffusion"
langue: "fr"
format: "tableau de bord de mesure : définitions, sources exactes, cadence, seuils de décision, modèle de relevé, lecture des résultats, biais, journal des décisions"
objectif: "Mesurer ce qui décide — contributions externes, essais réussis, canaux qui convertissent — et non ce qui flatte ; produire une décision datée à chaque relevé"
mot_cle_principal: "mesure de traction open source"
longueur: "document de référence permanent, relevé quotidien (S1–S2) puis hebdomadaire (S3–S8)"
public_cible: "mainteneur du projet, responsable campagne, contributeurs qui veulent savoir si le projet avance vraiment"
produit: "Thot Secure MVP v0.1.0 — SOAR/CSPM défensif, Python/FastAPI, multi-tenant, Apache-2.0, GitHub"
source_de_verite: "docs/architecture/api-contract.md du dépôt (contrat gelé, v0.1.0)"
plan_associe: "content/campaign/plan-8-semaines.md"
kpi_principal: "PR externes mergées (indicateur de santé n° 1)"
statut: "prêt à remplir (aucune section à rédiger ; les exemples sont marqués comme fictifs)"
date_redaction: "2026-02-14"
```

# Thot Secure — tableau de bord de mesure (8 semaines)

## 0. Principes

**Règle anti-auto-illusion : on ne mesure pas ce qui flatte, on mesure ce qui décide.**

Ce document applique l'**étape 5 de `content/CHARTE-EDITORIALE.md`** (« Journalisation et mesure ») :
aucune publication sans indicateur associé, sans seuil de décision, sans date de relevé fixée, et
sans regroupement des objections reçues — celles-ci deviennent la matière du contenu suivant.
Là où la charte et ce document diffèrent, la charte prime.

Test à appliquer à chaque indicateur avant de l'ajouter au tableau : *« si ce chiffre doublait demain
matin, quelle décision changerait ? »* S'il n'y a pas de réponse concrète, l'indicateur reste dans la
colonne « vanité » et **ne déclenche aucune action**.

### 0.1 Aucun chiffre de ce document n'est une mesure

Toutes les valeurs écrites ici (seuils, exemples, taux) sont :

- soit des **hypothèses de départ à calibrer** après le premier relevé réel — elles sont marquées
  « hypothèse » ;
- soit des **exemples explicitement fictifs** — ils sont marqués « EXEMPLE FICTIF » ;
- soit des **ordres de grandeur à remplacer par vos mesures**.

Aucun de ces chiffres ne doit être cité dans un article, un post ou une vidéo comme s'il avait été
observé.

### 0.2 Limite structurelle du MVP : il n'y a pas de télémétrie

Le contrat ne définit **aucune télémétrie produit** : Thot Secure n'appelle rien chez l'éditeur du
projet, ne « phone home » pas, et `GET /metrics` (contrat §4.1) expose des métriques **Prometheus du
service que vous hébergez**, pas des statistiques d'usage agrégées au niveau du projet. Conséquence
directe et honnête :

> **Le numérateur de tout « taux d'essai » ne peut venir que d'un signal volontaire** :
> une issue ouverte, une discussion, une réponse à la newsletter, un formulaire explicite.
> Le taux calculé est donc un **plancher**, systématiquement sous-estimé. On ne doit jamais
> présenter ce taux comme une mesure exacte d'adoption.

Ne jamais « corriger » ce biais en ajoutant une télémétrie silencieuse : ce serait contraire à
l'esprit du projet (sûreté par défaut, transparence). On assume la sous-estimation et on la note.

---

## 1. Cadence de relevé

| Période | Cadence | Durée du relevé | Pourquoi |
|---|---|---|---|
| S1–S2 (J0 → J+14) | **Quotidien**, à heure fixe (par ex. 09:00) | 5 min | C'est la fenêtre où tout bouge très vite et où une erreur de canal se paie cher. Un relevé quotidien permet de distinguer un pic d'un décollage |
| S3–S8 | **Hebdomadaire**, même jour, même heure (par ex. lundi 09:00) | 20 min | Les variations quotidiennes sont du bruit ; la semaine est l'unité de décision |
| Déclenché | **J+1, J+3, J+7 et J+30 après chaque publication** | 5 min | Pour mesurer la queue de vie d'un contenu : un pic à J+1 suivi de zéro à J+7 signifie que le canal ne retient personne. `content/CHARTE-EDITORIALE.md` (§3, étape 5) impose au minimum J+2, J+7 et J+30 : ce document fait J+1 **en plus** de ce minimum, et ne remplace jamais le relevé à J+30 |
| Fin de semaine 8 | Relevé de clôture + gel du tableau | 1 h | Le bilan doit être calculé sur des relevés faits **pendant**, jamais reconstitués après |

**Règle d'honnêteté du relevé** : on note la valeur **et** la fenêtre (« cumulé depuis J0 »,
« 7 derniers jours », « 24 h »). Un chiffre sans fenêtre n'est pas un chiffre, c'est une impression.
Chaque ligne du journal des décisions (§7) doit citer la fenêtre.

Où regarder, précisément (aucun de ces relevés ne nécessite d'outil payant) :

| Source | Chemin exact | Ce qu'on y lit |
|---|---|---|
| GitHub → Trafic | Dépôt → **Insights → Traffic** | Vues, visiteurs uniques, clonages, cloneurs uniques, sites référents, contenus populaires |
| GitHub → Releases | Dépôt → **Releases**, compteur de téléchargements par fichier joint | Téléchargements d'artefacts |
| GitHub → Issues / PR | Listes + recherche qualifiée (voir §2) | Ouvertes, fermées, externes, mergées, délais |
| GitHub → Contributors | Dépôt → **Insights → Contributors** (et l'historique de commits) | Contributeurs uniques et récurrence |
| GitHub → Discussions | Onglet **Discussions** : abonnés, participants, fils actifs | Communauté « engagée » (≠ étoiles) |
| GitHub → Community | Dépôt → **Insights → Community Standards** | Présence de CONTRIBUTING, CODE_OF_CONDUCT, modèles d'issues/PR |
| Site du projet | Analytics du site **ou** journaux du reverse-proxy / du serveur (comptage des requêtes et des référents) | Trafic par canal, parcours visiteur |
| Liste de diffusion | Console de l'outil d'envoi auto-hébergé (abonnés, ouvertures, clics) | Abonnés et engagement de liste |
| Journal des décisions | `content/campaign/metriques.md` (§7) | La mémoire de la campagne |

---

## 2. Tableau de bord principal

`Type` : **santé** = un indicateur qui déclenche une décision structurelle ·
**vanité** = un indicateur qui informe mais ne décide pas seul.

Les `Seuil de décision` sont des **hypothèses à calibrer** sur le relevé S1. Ils ne sont pas des
mesures et ne doivent pas être présentés comme tels.

| # | Indicateur | Type | Définition opérationnelle | Source exacte | Cadence | Seuil de décision (hypothèse à calibrer) |
|---|---|---|---|---|---|---|
| 1 | **Étoiles GitHub** | vanité | Nombre d'étoiles du dépôt, cumulé | Page du dépôt, compteur d'étoiles | Quotidien S1–S2, hebdo ensuite | **Si < 50 étoiles après 2 semaines → changer d'angle : passer de l'angle produit (« voici notre SOAR ») à l'angle technique/problème (« voici comment nous détectons X en Y lignes »).** Ne jamais acheter ni solliciter d'étoiles |
| 2 | **Forks** | vanité | Nombre de forks, cumulé | Page du dépôt → onglet Forks / Insights → Forks | Hebdomadaire | Si forks > étoiles/5 **et** 0 PR externe → des gens modifient le code sans proposer : aller leur parler, ouvrir une issue « qu'est-ce qui vous a bloqué ? ». Un fork sans PR est un signal, pas un succès |
| 3 | **Issues ouvertes / fermées** | santé | Nombre d'issues ouvertes, nombre fermées sur la période, et **ratio** fermées/ouvertes | Listes Issues, recherche qualifiée `is:issue repo:<org>/<repo>` | Quotidien S1–S2, hebdo ensuite | **Si > 10 issues ouvertes et < 30 % fermées après 2 semaines → le triage est cassé : arrêter de publier et traiter la file.** Une file qui pourrit est le premier motif d'abandon des contributeurs |
| 4 | **PR externes mergées** | santé (KPI principal) | PR ouvertes par une personne hors de l'organisation et **mergées** | Recherche : `repo:<org>/<repo> is:pr is:merged -author:<votre-org>` | Hebdomadaire | **0 PR externe mergée après S5 → arrêter l'angle « contribuez »** et passer à l'angle utilisateur (tutoriels, recettes de déploiement). C'est le seul indicateur dont le seuil déclenche un changement de stratégie |
| 5 | **Contributeurs uniques** | santé | Personnes distinctes ayant au moins 1 commit mergé, hors organisation | Insights → Contributors + `git`/liste des auteurs de commits | Hebdomadaire | Si contributeurs uniques > 0 mais **aucun revenu** (aucune 2ᵉ contribution d'une même personne) après S6 → l'onboarding contributeur est cassé : réduire le périmètre des « bonnes premières contributions », améliorer `CONTRIBUTING.md` |
| 6 | **Récurrence des contributeurs** | santé | Nombre de personnes ayant **≥ 2 contributions** mergées, sur le total de contributeurs externes | Insights → Contributors, recoupé avec l'historique de PR | Hebdomadaire | Récurrence = 0 après S6 → priorité absolue à la rétention : répondre en < 24 h, proposer une 2ᵉ tâche à chaque contributeur qui vient d'être mergé |
| 7 | **Délai de première réponse** | santé | Temps médian entre l'ouverture d'une issue/PR externe et la **première réponse humaine** | Listes Issues/PR (horodatages) | Hebdomadaire | **> 48 h en médiane → la campagne de contribution est en train d'échouer silencieusement.** Suspendre toute publication du canal « contributions » jusqu'au retour sous 48 h |
| 8 | **Ratio PR / issues** | santé | Nombre d'issues ouvertes par des externes vs PR ouvertes par des externes, sur la période | Recherche `is:issue` et `is:pr` avec `-author:<votre-org>` | Hebdomadaire | Ratio > 10 (beaucoup d'issues, quasi aucune PR) → transformer 3 issues « faciles » en « bonnes premières contributions » avec périmètre fermé. **Voir §5, lecture du « pic d'issues sans PR »** |
| 9 | **Téléchargements de release** | vanité utile | Somme des téléchargements d'artefacts d'une release (par fichier) | Page **Releases** → compteur sous chaque fichier joint | Hebdomadaire | Téléchargements en hausse **et** issues/PR plates → utilisateurs silencieux : ajouter un signal de retour volontaire (modèle d'issue « racontez votre installation », fil Discussion dédié). Ne pas conclure à l'adoption |
| 10 | **Clonages** | vanité | Clonages **uniques** (et cloneurs uniques) du dépôt | **Insights → Traffic → Clones** | Hebdomadaire | Clonages élevés **et** téléchargements de release faibles → suspicion de frottement d'installation : mesurer le temps « clone → premier finding » et simplifier. **Voir §5** |
| 11 | **Abonnés newsletter** | santé indirecte | Nombre d'abonnés confirmés, et delta sur la période | Console de l'outil d'envoi auto-hébergé | Hebdomadaire | **< 50 abonnés après S5 (ordre de grandeur) → suspendre le format newsletter** et basculer le contenu dans GitHub Discussions jusqu'à ce qu'une audience existe |
| 12 | **Abonnés / participants Discussions** | santé indirecte | Abonnés à l'onglet Discussions, participants distincts, fils actifs | Onglet **Discussions** | Hebdomadaire | 0 participant externe après S4 → les Discussions ne sont pas le bon canal : ne pas y investir plus d'une heure par semaine |
| 13 | **Trafic par canal** | santé | Visiteurs distincts attribués à chaque canal (référent), par publication | Insights → Traffic → **Referring sites** + analytics du site / journaux du serveur | Quotidien S1–S2, hebdo ensuite | **2 publications sur un canal et < 5 visiteurs qualifiés cumulés → abandonner ce canal pour le reste de la campagne.** Un canal se juge sur les visiteurs **et** sur les essais, pas sur les impressions |
| 14 | **Taux de conversion visiteur → essai** | santé (KPI secondaire) | `essais réussis déclarés ÷ visiteurs distincts` sur la période. **Pourquoi « déclarés » : sans télémétrie, c'est le seul numérateur disponible (voir §0.2)** — le taux réel est plus élevé | Numérateur : issues/Discussions/newsletter/formulaire. Dénominateur : Insights → Traffic → visiteurs uniques + analytics du site | Hebdomadaire | **< 1 % (ordre de grandeur, à recalibrer) → le problème est l'entrée, pas la promotion : réécrire le premier écran du dépôt (README) et la vidéo 60 s autour de « de zéro à un finding en 5 minutes », puis remesurer avant de publier quoi que ce soit d'autre** |
| 15 | **Temps « clone → premier finding »** | santé | Temps déclaré ou observé entre le clone et le premier résultat obtenu par un nouvel utilisateur | Signal volontaire : issue « racontez votre installation » ; vos propres mesures sur machine vierge | Hebdomadaire | > 15 min sur une machine vierge → la documentation d'entrée est le chantier prioritaire, avant tout nouveau contenu |

### 2.1 Définition de l'« essai réussi »

Un essai est considéré **réussi** si la personne rapporte avoir exécuté, sans aide extérieure, la
séquence minimale du contrat (§8) :

```powershell
thotsecure init-db
thotsecure demo --tenant demo
thotsecure findings list --tenant demo
```

Un essai **tenté mais échoué** doit être compté séparément, et l'échec doit être qualifié : trou de
documentation, dépendance manquante, erreur compréhensible, message d'erreur absent. Un échec
documenté vaut mieux que dix étoiles : c'est une correction à faire, pas un chiffre à afficher.

---

## 3. Vanité vs santé : ce qu'on fait de chaque catégorie

| | Indicateurs de vanité | Indicateurs de santé |
|---|---|---|
| **Exemples** | étoiles, forks, vues, clonages, téléchargements, abonnés | PR externes mergées, récurrence des contributeurs, issues résolues, délai de première réponse, taux d'essai réussi |
| **Ce qu'ils mesurent** | l'attention portée au projet, à un instant donné, souvent par effet de relais | la capacité du projet à faire revenir des gens et à être utilisé |
| **Durée de vie du signal** | quelques jours après une publication | quelques semaines, et seulement s'il y a une queue |
| **Ce qu'ils ne disent jamais** | si quelqu'un a essayé, si quelqu'un est resté, si c'est utilisable | — |
| **Comment les utiliser** | comme **contexte** d'un relevé, jamais comme objectif, jamais comme critère de décision seul | comme **déclencheurs de décision** |
| **Piège classique** | optimiser l'indicateur (acheter, solliciter, relayer en boucle) et détruire la mesure | négliger la vanité et ne pas savoir si le message porte |

Règle pratique : dans chaque relevé hebdomadaire, **au moins une ligne de décision doit concerner un
indicateur de santé**. Un compte rendu qui ne parle que d'étoiles et de vues n'est pas un compte
rendu, c'est un communiqué.

---

## 4. Modèle de tableau à remplir

Colonnes : `Semaine` · `Indicateur` · `Valeur` · `Delta` · `Seuil` · `Décision` · `Action`.

Une ligne = un indicateur, une semaine, une décision. Si une ligne n'a pas d'action, elle n'a pas sa
place ici : elle va dans les notes.

| Semaine | Indicateur | Valeur | Delta | Seuil | Décision | Action |
|---|---|---|---|---|---|---|
| S1 | PR externes mergées | **3 (EXEMPLE FICTIF)** | +3 vs S0 | 0 après S5 | Continuer | — |
| S2 | Délai de première réponse (médiane) | **61 h (EXEMPLE FICTIF)** | +61 h | > 48 h → alerte | **Suspendre les publications « contributions »** | Bloquer 1 h/jour de triage jusqu'au retour sous 48 h ; écrire un modèle de réponse |
| S2 | Trafic canal Reddit | **4 visiteurs pour 2 publications (EXEMPLE FICTIF)** | +4 | < 5 visiteurs / 2 publications → abandon | **Abandonner ce canal** | Retirer Reddit du plan des semaines 3 à 8 dans `content/campaign/plan-8-semaines.md` |
| | | | | | | |

Les trois lignes ci-dessus sont des **exemples explicitement fictifs**, destinés à montrer la forme
attendue (une observation → une décision → une action datable). **Elles ne doivent jamais être
recopiées comme des valeurs réelles, ni citées dans un article ou une vidéo.**

Modèle de relevé hebdomadaire vierge, à dupliquer :

| Semaine | Indicateur | Valeur | Delta | Seuil | Décision | Action |
|---|---|---|---|---|---|---|
| S1 | | | | | | |
| S1 | | | | | | |
| S1 | | | | | | |

---

## 5. Lecture des résultats

Un chiffre qui monte n'est pas un résultat. Voici les trois configurations pièges les plus fréquentes,
et ce qu'elles signifient réellement.

### 5.1 Pic de trafic sans conversion

**Ce qu'on voit** : visiteurs en forte hausse sur 24–48 h, étoiles qui grimpent, puis retour au
niveau antérieur en une semaine ; aucun essai déclaré, aucune issue.

**Ce que ça veut dire** : le message de surface (« un SOAR open source ») a fonctionné comme curiosité,
mais la promesse d'entrée n'a pas été comprise ou pas crue. Le visiteur a regardé, n'a pas vu en 30 s
*ce qu'il pouvait faire dans les 5 minutes*, et est parti. Ce n'est **pas** un problème de promotion,
c'est un problème de **porte d'entrée**.

**Ce qu'on fait** : ne pas publier davantage. Réécrire le premier écran du dépôt et la vidéo 60 s
autour d'une seule promesse vérifiable (« de zéro à un finding en 5 minutes, en dry-run, sans
credentials »), puis remesurer la conversion **sur le même canal** pour comparer ce qui est comparable.
Vérifier aussi la répartition des référents : si 80 % du trafic vient d'un seul relais, le pic est un
effet de relais, pas un intérêt pour le projet (voir §6).

### 5.2 Pic d'issues sans PR

**Ce qu'on voit** : beaucoup d'issues ouvertes par des externes, quasi aucune PR ; éventuellement des
issues de qualité (« ça ne s'installe pas », « le message d'erreur est illisible »).

**Ce que ça veut dire** : deux hypothèses à départager, et on les départage en **lisant** les issues :
soit les gens sont des utilisateurs qui butent et rapportent (bon signe de traction, mauvais signe de
finitions), soit ce sont des demandeurs de fonctionnalités sans intention de contribuer (ni traction
ni contribution). Le ratio PR/issues (§2, ligne 8) tranche : au-delà de 10, on a une file de
consommateurs, pas une communauté de contributeurs.

**Ce qu'on fait** : traiter la file avant tout le reste, répondre en < 48 h, puis transformer
**3 issues réelles** en « bonnes premières contributions » au périmètre fermé (un fichier, un test,
un message d'erreur). Si certaines demandes sont hors contrat, le dire clairement et les marquer
**roadmap** — jamais « bientôt » sans engagement de version.

### 5.3 Fort taux de clonage sans adoption

**Ce qu'on voit** : clonages uniques élevés (Insights → Traffic → Clones), téléchargements de release
faibles, aucun essai déclaré, aucune issue.

**Ce que ça veut dire** : deux lectures opposées, à trancher par un test : soit **frottement
d'installation** (les gens clonent, butent, abandonnent en silence), soit usage **en lecture**
(ils consultent le code, s'en inspirent, n'installent jamais). Ce n'est pas la même chose et ça ne se
corrige pas pareil.

**Ce qu'on fait** : chronométrer soi-même « clone → premier finding » sur une machine vierge, en
notant chaque hésitation. Puis ajouter un signal volontaire minimal (modèle d'issue « racontez votre
installation, même si ça a échoué »). Si le frottement est réel, le chantier prioritaire est la
séquence d'entrée, pas un post de plus.

### 5.4 Autres configurations à savoir lire

| Configuration | Lecture | Action |
|---|---|---|
| Étoiles en forte hausse venant d'un seul relais | Effet de relais, pas traction | Mesurer la **rétention** à J+7 : si tout retombe, ne pas considérer le canal comme acquis |
| Beaucoup de vues du README, peu de clics vers la documentation | Le README ne donne pas envie d'aller plus loin | Réécrire le README ; une seule promesse, une seule commande, un seul résultat |
| Croissance des étoiles **et** zéro issue **et** zéro fork | Attention sans engagement : profil « collectionneurs d'étoiles » | Chercher un signal d'usage plus fort (essai déclaré), ne pas s'en satisfaire |
| Issues fermées rapidement mais sans PR acceptée | Triage **poli** mais pas de contribution : on répond, on n'intègre pas | Convertir 3 issues en tâches fermées et assignables |
| Téléchargements de release en hausse continue | Signal le plus proche de l'usage réel disponible sans télémétrie | Compléter par un canal de retour volontaire ; ne pas confondre avec de l'adoption |
| Newsletter : bons taux d'ouverture, zéro réponse | Liste passive | Poser **une** question ouverte dans l'envoi suivant (« quel est votre blocage n° 1 ? ») et compter les réponses |
| Relevés qui n'ont pas été tenus pendant 2 semaines | Trou de mesure | Ne pas reconstituer : écrire « non mesuré » dans le journal des décisions. Un chiffre inventé après coup contamine tout le bilan de S8 |

---

## 6. Biais de mesure

| Biais | Comment il se manifeste | Comment on le neutralise |
|---|---|---|
| **Fenêtre de temps trop courte** | On juge un contenu à J+1 : pic artificiel, conclusion fausse dans les deux sens | Toujours relever à **J+1, J+3, J+7 et J+30** (le minimum imposé par la charte est J+2, J+7, J+30). Une décision ne se prend jamais sur J+1 seul |
| **Effet Show HN / effet de relais** | Pic fort à J0–J1 puis effondrement ; on confond popularité instantanée et intérêt durable | Comparer le pic à J+7 et au niveau de base de la semaine précédente. Si tout est retombé, le canal n'a pas créé d'audience : il a créé une visite |
| **Étoiles venant d'un seul relais** | Toutes les étoiles d'une journée viennent du même référent (un agrégateur, un influenceur, un cross-post) | Vérifier **Insights → Traffic → Referring sites**. Si un relais dépasse ~60 % du trafic d'un pic, l'étoile mesure la popularité du relais, pas la valeur du projet |
| **Biais de survie** | On ne voit que les gens qui ont réussi à installer ; les autres partent en silence | Créer un canal explicite d'échec (« racontez votre installation, **même si ça a échoué** ») et compter les échecs |
| **Biais d'auto-déclaration** | Le taux d'essai ne compte que ceux qui le déclarent, donc les plus motivés | L'annoncer comme **plancher**, jamais comme taux réel (voir §0.2) |
| **Effet d'observation** | Plus on surveille les étoiles, plus on écrit des posts à étoiles : l'indicateur pilote le comportement | Le KPI principal est une **PR externe mergée**, pas une étoile. Les étoiles ne déclenchent aucune action directe |
| **Effet de nouveauté** | Les premiers chiffres d'un projet jeune sont gonflés par la curiosité de l'entourage et des pairs | Ne pas prendre S1 comme référence de performance : c'est la **ligne de base** (baseline), pas un objectif |
| **Champ de vision étroit** | On ne compte que GitHub et on ignore le site, la newsletter, les Discussions | Relever les 4 sources chaque semaine, même quand 3 sont plates. Une source plate est une information |
| **Reconstitution après coup** | Le tableau de bord est rempli en S8 de mémoire | Relevé **pendant**. Ce qui n'a pas été relevé est noté « non mesuré », jamais estimé |
| **Comparaison avec les autres** | On compare ses chiffres à ceux d'un projet à 10 000 étoiles | Comparer un projet à **sa propre semaine précédente**, jamais à un autre projet : la distribution est trop inégale pour être informative |

---

## 7. Journal des décisions (daté)

**Règle : aucune décision sans date, aucune décision sans chiffre, aucun chiffre sans source et sans
fenêtre.**

Chaque relevé qui déclenche un changement produit une ligne. Les lignes ne sont jamais supprimées ni
réécrites : une décision qui s'avère mauvaise reste au journal, avec la correction en ligne suivante.
C'est la même logique que l'audit chaîné du produit : on ne réécrit pas l'histoire, on ajoute.

| Date | Observation (chiffre + source + fenêtre) | Décision | Action | Réévaluation |
|---|---|---|---|---|
| 2026-02-17 | **4 visiteurs Reddit pour 2 publications — Insights → Traffic → Referring sites, cumulé depuis J0 (EXEMPLE FICTIF)** | **Abandonner le canal Reddit** | Retirer Reddit du plan des semaines 3 à 8 ; reporter les 3 h sur le blog du projet | 2026-03-17 |
| 2026-02-24 | **Délai médian de première réponse 61 h sur 5 issues externes — listes Issues, fenêtre 7 jours (EXEMPLE FICTIF)** | **Suspendre les publications « contribuez »** | 1 h/jour de triage ; modèle de réponse ; retour sous 48 h avant toute publication | 2026-03-03 |
| | | | | |
| | | | | |

Les deux lignes ci-dessus sont des **exemples explicitement fictifs** illustrant la forme attendue.
Elles ne doivent jamais être présentées comme des observations réelles.

### 7.1 Comment remplir une ligne

1. **Observation** : le chiffre, la **source exacte** (pas « GitHub » mais « Insights → Traffic →
   Referring sites ») et la **fenêtre** (« cumulé depuis J0 », « 7 derniers jours »).
2. **Décision** : un verbe d'action sur la campagne (« abandonner ce canal », « suspendre ce format »,
   « changer d'angle », « continuer »). « Continuer » est une décision valide **et doit être écrite** :
   l'absence de décision est le vrai risque.
3. **Action** : ce qui change concrètement, dans quel fichier ou quel canal.
4. **Réévaluation** : une date. Sans date, la décision n'est pas vérifiable.

### 7.2 Décisions attendues (à confirmer par les chiffres, jamais décidées d'avance)

| Moment | Décision à prendre | Seuil associé |
|---|---|---|
| Fin S1 | Garder ou abandonner chaque canal testé | §2, ligne 13 : < 5 visiteurs qualifiés pour 2 publications |
| Fin S2 | Rester sur l'angle produit ou passer à l'angle technique/problème | §2, ligne 1 : < 50 étoiles après 2 semaines (hypothèse) **et** 0 contribution externe |
| Fin S4 | Poursuivre ou arrêter l'appel aux règles communautaires | §2, ligne 4 : 0 PR externe |
| Fin S5 | Maintenir ou suspendre la newsletter | §2, ligne 11 : < 50 abonnés (ordre de grandeur) |
| Fin S6 | Publier ou annuler l'étude de cas pilote | §3 du plan : accord écrit indispensable ; sinon remplacer par un retour interne **étiqueté comme tel** |
| Fin S7 | Annoncer 0.2 maintenant ou décaler | §5 du plan : release réellement publiée, tests verts — sans exception |
| Fin S8 | Continuer / réduire le périmètre / mettre en pause | §4 du plan : décision par défaut = réduire le périmètre, jamais « continuer comme avant » sans critère atteint |

---

## 8. Rapport hebdomadaire type (5 lignes, à poster dans Discussions si utile)

> **Semaine N** — visiteurs uniques : X (source, fenêtre) · PR externes mergées : X ·
> contributeurs récurvents : X · délai médian de première réponse : X h · essais réussis déclarés : X
> · **décision prise** : … · **action engagée** : … · **non mesuré** : …

Une publication qui annonce une décision, une action et ce qui n'a pas pu être mesuré est plus utile
à la communauté que n'importe quel graphique. Elle rend aussi le projet difficile à « embellir » :
on ne peut pas inventer une trajectoire qu'on publie chaque semaine.

---

## 9. Adresses de dons officielles (fin de contenu uniquement)

Ces adresses ne figurent **jamais** en tête d'un article, d'un post, d'un rapport hebdomadaire ou
d'une description de vidéo. Elles apparaissent en **fin** de contenu, avec l'avertissement.

- Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais de
clé privée ni de phrase de récupération.

Ces adresses sont la source unique de vérité du contrat §12 et figurent aussi dans `README.md`,
`.github/FUNDING.yml`, `GET /ui/support` et `docs/support.md`. Toute adresse trouvée ailleurs est une
arnaque : renvoyez au dépôt officiel, ne la relayez pas. Aucune contrepartie n'est promise ni
sous-entendue.
