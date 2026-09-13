```yaml
canal: Reddit (plan de cross-post multi-subreddits)
langue: en
format: plan opérationnel + checklists de publication + règles d'espacement
objectif: "obtenir un examen critique par des communautés techniques distinctes, sans spammer : un angle par subreddit, un lien par post, participation préalable obligatoire"
mot_cle_principal: "defensive SOAR"
longueur: "plan interne (pas de limite plateforme) ; les posts publiés restent sous 1 200 mots et sous 40 000 caractères (limite Reddit)"
heure_optimale_publication: "lundi-jeudi, 13 h 00 - 16 h 00 UTC (matin US Eastern : les subreddits techniques sont les plus actifs) ; jamais le week-end pour un post de projet"
regles_specifiques_du_canal:
  - "participer d'abord : avoir un historique de commentaires utiles dans le subreddit avant d'y publier quoi que ce soit (viser plusieurs semaines)"
  - "un seul lien par post ; pas de lien en commentaire de contournement, pas de lien raccourci, pas d'URL avec paramètres de campagne (UTM) : Reddit comme les modérateurs y voient un signal de spam"
  - "disclosure d'auteur explicite : « I'm a maintainer of Thot Secure » dans le post ou en premier commentaire épinglé par l'auteur"
  - "le même texte partout = spam : chaque subreddit reçoit un angle et un texte différents (voir tableau)"
  - "lire les règles du subreddit ET sa politique d'auto-promotion avant publication ; certains exigent un message préalable aux modérateurs ou un thread dédié"
  - "choisir le flair correct ; ne pas éditer un post après publication pour y ajouter un lien qui n'y était pas"
  - "ne jamais demander de votes, ne jamais voter avec plusieurs comptes, ne jamais utiliser de comptes secondaires pour amorcer les commentaires"
  - "répondre à tous les commentaires techniques pendant les 4 premières heures ; accepter la critique sans argumenter sur le ton"
  - "si un post est retiré par un modérateur : ne pas le republier ailleurs le jour même, ne pas relancer le modérateur en message privé, demander la raison une fois puis attendre"
dons: "AUCUNE adresse de don dans un post Reddit ni dans ce plan. Reddit interdit ou restreint la sollicitation financière dans la plupart des subreddits techniques, et un post de projet qui demande de l'argent est retiré. Les adresses officielles vivent uniquement dans la newsletter, README.md, .github/FUNDING.yml, GET /ui/support et docs/support.md."
autopromotion: "ratio de participation très défavorable à la promotion (viser au minimum 10 commentaires utiles pour 1 publication de projet) ; 1 seul lien par post ; pas de campagne de republication d'un même contenu ; pas de DM aux modérateurs ni aux membres."
```

# Thot Secure v0.1.0 — plan de cross-post Reddit

Objectif : faire relire le projet par cinq ou six communautés **différentes**, avec un angle adapté à chacune. Le même texte collé partout est du spam : il sera retiré, et le compte perdra le droit de publier dans les subreddits qui comptent.

## 1. Règles non négociables avant toute publication

1. **Participer d'abord.** Aucune publication de projet avant d'avoir un historique réel de commentaires utiles dans le subreddit visé. Viser plusieurs semaines de participation, pas trois commentaires la veille.
2. **Un seul lien par post.** `https://github.com/thot-corp/thot-secure`. Ce lien apparaît **une fois**, dans le corps du post.
3. **Disclosure d'auteur.** Le post commence ou se termine par : *« I'm one of the maintainers of Thot Secure. »* Pas de compte neutre qui « découvre » le projet.
4. **Un angle par subreddit.** Le tableau §3 donne l'angle et le point d'entrée de chaque texte. Ne jamais réutiliser le même texte d'un sub à l'autre.
5. **Lire les règles avant d'écrire.** Politique d'auto-promotion, format de titre imposé, flair obligatoire, thread hebdomadaire dédié. En cas de doute, demander aux modérateurs **avant** de publier.
6. **Pas de vote manipulation.** Jamais de demande de votes, jamais de comptes multiples, jamais de compte secondaire pour commenter son propre post, jamais de groupe qui vote en bloc.
7. **Pas de repost du même contenu.** Ni dans le même subreddit à quelques jours d'intervalle, ni dans plusieurs subreddits le même jour.
8. **Assumer la critique.** Un post de projet reçoit « encore un SOAR », « pourquoi pas X », « votre audit chaîné ne prouve rien ». Répondre factuellement, reconnaître les limites, ne jamais répondre à l'attaque personnelle.

## 2. Interdits explicites

| Interdit | Pourquoi |
|---|---|
| Vote manipulation, brigading, comptes multiples | Bannissement de compte et du domaine, sans recours |
| Repost du même texte dans plusieurs subreddits | Détecté comme spam ; les modérateurs partagent leurs listes de spammeurs |
| Lien en commentaire après un post sans lien | Contournement de règle = retrait + ban |
| Sollicitation de don ou lien de financement | Hors règles de la plupart des subreddits techniques ; jamais dans un post de lancement |
| DM non sollicités à des membres intéressés | Harcèlement ; la réponse se fait en commentaire public |
| Demander « upvote si vous aimez » | Vote manipulation |
| Republier un post retiré ailleurs le jour même | Escalade immédiate |
| Publier depuis un compte neuf sans historique | Filtre anti-spam automatique ; le post n'est jamais vu |
| Ajouter un lien a posteriori en éditant le post | Contournement de règle |
| Cross-poster pendant le lancement d'un autre projet concurrent | Concurrence déloyale, mauvaise réputation immédiate |

## 3. Subreddits retenus, angle et fichier de texte

Les textes de chaque subreddit sont préparés dans `content/forums/`. **Vérifier que le fichier existe et correspond bien au subreddit avant de publier** : un angle écrit pour `r/devops` publié sur `r/netsec` sera retiré.

> **À vérifier au moment de publier :** le répertoire `content/forums/` est produit par le lot éditorial « forums ». Au moment de la rédaction de ce plan, ce répertoire n'existe pas encore dans l'arbre de travail. Si le fichier correspondant est absent, **ne pas publier** : écrire le texte pour ce subreddit d'abord, à partir du contrat d'interface gelé.

| # | Subreddit | Pourquoi ce sub | Angle (différent des autres) | Fichier de texte | Priorité |
|---|---|---|---|---|---|
| 1 | `r/blueteamsec` | Cœur de cible : détection, réponse à incident, blueteam. Public qui lit le YAML et juge la conception. | Les décisions de conception : policy-as-code, réversibilité obligatoire, audit chaîné. Demander un avis critique sur les garde-fous. | `content/forums/blueteamsec.md` | **1** |
| 2 | `r/selfhosted` | Public qui installe pour de vrai, hors cloud, et déteste les dépendances lourdes. | Auto-hébergement : SQLite, console embarquée sans build Node, `docker compose`, aucune credential requise pour démarrer (connecteurs simulés). | `content/forums/selfhosted.md` | **2** |
| 3 | `r/netsec` | Le sub le plus exigeant en sécurité. Y figurer crédibilise — ou coule — le projet. | Post de type outil : le modèle de menace, ce qui est prouvé (chaîne de hash, isolation tenant testée en CI), ce qui ne l'est pas. | `content/forums/netsec.md` | **3** |
| 4 | `r/devops` | Public policy-as-code / CI : YAML versionné, automatisation vérifiable. | Politiques YAML en revue de code, CLI scriptable (`--json` partout), codes de sortie `0/1/2/3` exploitables dans un pipeline. | `content/forums/devops.md` | **4** |
| 5 | `r/MSP` | Le cas d'usage multi-tenant est directement le leur. | Isolation par tenant : une clé API par client, RBAC `viewer/analyst/responder/admin`, plafond d'actions par tenant. | `content/forums/msp.md` | **5** |
| 6 | `r/opensource` | Public gouvernance / contribution, pas sécurité. | Apache-2.0, DCO sans CLA, gouvernance écrite, `good first issue` calibrés à environ un jour de travail. | `content/forums/opensource.md` | **6** |
| 7 | `r/Python` | Public qui juge le code, pas la sécurité. | Le core (`thotsecure.core`) ne dépend que de la stdlib + pydantic/PyYAML ; suite `unittest` exécutable sans réseau. | `content/forums/python.md` | **7** |
| 8 | `r/cybersecurity` | Volume élevé, mais scepticisme élevé : public large. | Bilan honnête : ce qui marche en v0.1.0, ce qui ne marche pas, la roadmap assumée. | `content/forums/cybersecurity.md` | **8** |
| 9 | `r/homelab` | Optionnel, audience plus large et moins spécialisée. | Démo locale sur un serveur personnel : `thotsecure demo --tenant demo`, une seule base SQLite. | `content/forums/homelab.md` | 9 (optionnel) |

**Subreddits écartés volontairement :**

- `r/sysadmin` — très hostile à l'auto-promotion, règles strictes sur les posts de fournisseur. À traiter par participation aux fils de discussion, jamais par un post de lancement.
- `r/AskNetsec` — réservé aux questions, pas aux annonces.
- `r/hacking` et équivalents — incompatibles avec l'invariant « zéro capacité offensive » du projet.
- `r/programming`, `r/technology` — audience non technique, aucune conversion utile, risque de spam élevé.

**Cible réaliste :** 5 ou 6 subreddits, pas 9. Les rangs 7 à 9 ne se publient que si les cinq premiers ont reçu un accueil correct.

## 4. Espacement temporel conseillé

Un même contenu publié deux fois le même jour dans deux subreddits se fait repérer immédiatement. Espacement minimal : **72 heures** entre deux publications, et **jamais deux subreddits le même jour**.

| Jour | Action | Subreddit |
|---|---|---|
| J-0 | Vérifier l'historique de participation, lire les règles, écrire les modérateurs si le sub l'exige | — |
| J+0 (mardi, 14 h UTC) | Publication 1 + présence active 4 h en commentaires | `r/blueteamsec` |
| J+3 (vendredi, 13 h UTC) | Publication 2, texte réécrit pour l'angle auto-hébergement | `r/selfhosted` |
| J+7 (mardi, 14 h UTC) | Publication 3, format outil, message préalable aux modérateurs si requis | `r/netsec` |
| J+11 (samedi — **décaler à J+12**, lundi) | Publication 4 | `r/devops` |
| J+17 | Publication 5 | `r/MSP` |
| J+24 | Publication 6 | `r/opensource` |
| J+31 et au-delà | Publications 7 à 9, uniquement si les retours sont bons | `r/Python`, `r/cybersecurity`, `r/homelab` |

Règles d'espacement complémentaires :

- **Une publication par semaine maximum** pendant le premier mois, par compte.
- **Jamais deux publications le même jour**, même dans des subreddits sans lien entre eux.
- **Jamais de republication** d'un contenu retiré, dans le même sub ou ailleurs, avant d'avoir compris la règle enfreinte.
- **Entre deux publications**, continuer à commenter utilement dans les subreddits déjà visités : c'est ce qui rend la publication suivante acceptable.
- **Un fil de feedback vit plusieurs jours** : répondre aux commentaires des publications précédentes avant d'en lancer une nouvelle.

## 5. Checklist avant chaque publication

À valider intégralement avant d'appuyer sur « Post ». Un seul « non » = ne pas publier.

- [ ] J'ai lu les règles du subreddit et sa politique d'auto-promotion **aujourd'hui** (elles changent).
- [ ] J'ai un historique de commentaires utiles dans ce subreddit, pas seulement des posts de projet.
- [ ] Le fichier `content/forums/<sub>.md` existe et son angle correspond **à ce** subreddit.
- [ ] Le texte est réécrit pour cet angle : ce n'est pas le texte d'un autre sub.
- [ ] Le titre décrit le projet factuellement, sans clickbait, sans majuscules criardes, sans « 🚀 ».
- [ ] Le flair demandé par le subreddit est sélectionné.
- [ ] Le lien du dépôt apparaît **une seule fois**, en clair, sans UTM ni raccourcisseur.
- [ ] La disclosure d'auteur est présente : « I'm one of the maintainers of Thot Secure. »
- [ ] Aucune adresse de don, aucun lien de financement, aucune demande de vote ou d'étoile.
- [ ] Aucun chiffre d'impact non mesuré : pas de « -70 % de MTTR », pas de benchmark inventé.
- [ ] Les limites de v0.1.0 sont écrites noir sur blanc dans le post (SQLite, connecteurs simulés, Rego si binaire OPA, `patch-dependency` n'auto-merge jamais, `probe` limité aux cibles déclarées).
- [ ] Ce qui est **roadmap** est étiqueté « roadmap » explicitement (PostgreSQL/TimescaleDB, connecteurs réels, collecteurs supplémentaires, dashboard React, SDK TypeScript/Go).
- [ ] Je suis disponible pendant les 4 heures qui suivent pour répondre aux commentaires.
- [ ] Aucune publication n'a eu lieu dans un autre subreddit depuis moins de 72 heures.
- [ ] Si le subreddit exige un message préalable aux modérateurs, il est envoyé et j'attends leur accord.

## 6. Après publication

- Répondre à **tous** les commentaires techniques la première journée, y compris les plus durs. « Vous avez raison, ce n'est pas couvert en v0.1.0, c'est en roadmap » est une bonne réponse.
- Si un bug est signalé, ouvrir une issue publique et la lier dans le fil : cela se voit, et cela vaut mieux qu'une réponse polie sans suite.
- Ne jamais éditer le post pour atténuer une critique : ajouter une réponse publique.
- Noter dans le suivi éditorial : date, subreddit, angle, réactions, issues ouvertes. Ces notes alimentent les publications suivantes.
- Si un modérateur signale une règle enfreinte, s'excuser une fois, corriger, ne pas argumenter.

## 7. Rappel des faits autorisés dans les posts Reddit

Ces éléments sont vérifiables dans `docs/architecture/api-contract.md` et peuvent être cités :

- `THOT_DRY_RUN=true` par défaut ; autonomie par défaut `supervised` ; modes tenant `manual|supervised|auto`.
- Décisions `auto|require_approval|notify_only|ignore` ; aucune politique qui matche ⇒ `notify_only`.
- Garde-fous non contournables : plafond horaire par tenant (défaut 20), cooldown par `(tenant, playbook, cible)`, cibles protégées de l'`autonomy_allowlist` jamais touchées, `dry_run` global prioritaire, cible hors périmètre ⇒ `require_approval`.
- Audit chaîné par hash, `GET /api/v1/audit/verify` ⇒ `{"valid","records","broken_at"}`, export `jsonl|cef`.
- CLI : codes de sortie `0`/`1`/`2`/`3` (3 = vérification négative), `--json` sur toutes les commandes, `thotsecure demo --tenant demo`, `thotsecure doctor`.
- Tests : `python -m unittest discover -s tests -t . -v`, sans réseau ni service externe.
- Licence Apache-2.0 ; DCO sans CLA.

Rien d'autre. Pas de chiffre de performance, pas de comparaison nominative avec un concurrent, pas de promesse de date de livraison.
