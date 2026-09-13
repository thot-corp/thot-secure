```yaml
canal: "Journal du Hacker (journalduhacker.net)"
langue: "Français intégral"
format: "Soumission de lien : titre + URL du dépôt + texte de présentation court (150–300 mots) publié en description/premier commentaire, selon ce que la plateforme permet"
objectif: "Faire connaître en une lecture courte l'angle défensif et souverain du projet (auto-hébergement, défauts fermés, absence de mécanisme de télémétrie dans le contrat d'interface), sans slogan, et orienter vers le dépôt pour vérification"
mot_cle_principal: "SOAR défensif"
longueur: "Fichier de travail ≈ 1 000 mots ; texte publié strictement 150–300 mots (cible ≈ 250 mots). Tout dépassement doit être coupé, pas reformaté."
meilleur_creneau_publication: "Hypothèse de travail non mesurée : jour de semaine, 09:00–12:00 heure de Paris. À confirmer sur place ; ne pas présenter ce créneau comme une donnée du projet."
regles_specifiques_du_canal: "À re-vérifier le jour de la publication : format exact de soumission (lien seul, lien + description, ou commentaire d'auteur), existence et libellé des étiquettes/tags, règles sur l'auto-promotion et sur les liens vers un dépôt de code, éventuel seuil de réputation du compte, durée de présence en page d'accueil. Ces règles évoluent et n'ont pas pu être consultées hors ligne."
autopromotion: "AVERTISSEMENT — le Journal du Hacker est une plateforme de partage de liens où l'auto-promotion est surveillée et où les soumissions purement promotionnelles sont mal reçues. Conséquences : (1) déclarer la qualité d'auteur dans la première phrase ; (2) UN SEUL lien, celui du dépôt ; (3) aucun lien de don, de financement ou de boutique dans la soumission ni dans le texte — le Journal du Hacker n'est pas un lieu de collecte, et une adresse de cryptomonnaie y serait contre-productive ; (4) ne pas demander de votes ni de partage ; (5) ne pas soumettre plusieurs textes du projet le même jour ; (6) si une critique technique arrive, y répondre par un fait vérifiable, jamais par une promesse."
```

---

# 1. Stratégie (FR)

**Contrainte principale : la longueur.** Le texte publié ne doit pas dépasser 300 mots. C'est une contrainte utile : elle force à choisir trois idées et à abandonner le reste. Les trois idées retenues sont la réversibilité des actions, le caractère vérifiable du journal d'audit, et des défauts fermés qu'une politique ne peut pas contourner. Tout le reste — l'architecture, les politiques YAML, les playbooks, les collecteurs — est renvoyé au dépôt.

**Le piège à éviter sur l'angle « souveraineté ».** Il est facile de glisser vers le slogan : « souverain », « sans télémétrie », « air-gap », « 100 % local ». Aucun de ces termes ne doit apparaître comme une propriété garantie. La formulation autorisée est descriptive et vérifiable : les défauts d'installation pointent vers l'intérieur, et **aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface** — ce qui est un constat de lecture, explicitement suivi d'un appel à vérification par audit du code. Si le code n'a pas été audité à ce sujet le jour de la publication, la phrase reste au conditionnel du constat et ne devient jamais une affirmation de garantie.

**Pourquoi ce canal quand même.** L'angle souveraineté intéresse une partie du lectorat du Journal du Hacker, mais ce lectorat sanctionne l'enthousiasme non étayé. Un texte court, vérifiable, qui dit aussi ce qui manque, est mieux reçu qu'un texte long et flatteur.

---

# 2. Notes de canal (FR) — créneau, longueur, participation préalable

| Point | Consigne |
|---|---|
| Créneau | Jour de semaine 09:00–12:00 heure de Paris (hypothèse non mesurée, à confirmer). |
| Longueur | **150–300 mots**, cible 250. Le texte du §4 en fait environ 260 : c'est la version à publier, sans ajout. |
| Participation préalable | Compte avec un historique de soumissions ou de commentaires, si la plateforme l'exige. Sans historique, la soumission risque d'être ignorée ; dans ce cas, commencer par commenter d'autres soumissions pendant quelques jours. |
| Étiquettes | À vérifier le jour J. Candidats plausibles : développement, sécurité, réseau, logiciel libre. Ne pas inventer d'étiquette. |
| Présence | Répondre dans les 24 heures. Le volume de commentaires est faible ; une objection sans réponse reste visible longtemps. |
| Anti-patterns | Titre en accroche commerciale ; texte de plus de 300 mots ; deuxième lien ; mention de dons ; demande de votes ; republication rapprochée. |

---

# 3. Rappel de prudence (FR)

Les seuls éléments autorisés dans le texte publié :

- Licence Apache-2.0, version `0.1.0`, alpha, Python/FastAPI (source : `pyproject.toml` du dépôt).
- `POST /api/v1/actions/{id}/rollback` doit réussir tant que la fenêtre de rollback n'est pas expirée ; tout playbook porte `reversible: true` et un bloc `rollback:` (§1, §3.4, §7 du contrat).
- Journal d'audit append-only chaîné par hachage, vérification `GET /api/v1/audit/verify`, export `jsonl|cef` (§3.5, §4.7 du contrat).
- `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised` par défaut ; le dry-run global l'emporte sur toute politique ; les garde-fous du moteur de décision ne sont pas contournables par une politique (§9, §1, §6 du contrat).
- Connecteur non configuré ⇒ mode simulé, jeton de rollback renvoyé, `simulated: true` journalisé : comportement par défaut du MVP (§7 du contrat).
- Défauts orientés vers l'intérieur : SQLite par défaut (`THOT_DB_URL=sqlite:///./data/thotsecure.db`), bus `memory` par défaut, console Jinja2 + JS sans build Node (§9, §4.9 du contrat).
- Aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface → **constat de lecture, à confirmer par audit du code**, formulé comme tel.
- Manques à citer : pas d'agent endpoint, connecteurs en simulation, PostgreSQL seulement documenté, quatre rôles RBAC, pas de corpus de règles éprouvé (§7, §9, §4 du contrat ; §10 pour les rôles).

Ce qui est interdit dans ce texte : tout chiffre non mesuré ; tout superlatif ; la formule « zéro télémétrie » présentée comme un engagement ; « fonctionne en air-gap » sans test hors ligne ; « souverain » sans définition ; toute fonctionnalité non livrée présentée au présent.

---

# 4. TEXTE PUBLIÉ — à copier tel quel (FR), ≈ 260 mots

> **Titre :** `Thot Secure 0.1.0 — SOAR défensif auto-hébergeable : actions réversibles, audit chaîné, dry-run par défaut`
>
> **URL :** `https://github.com/thotsecure/thot-secure`
>
> **Étiquettes :** à vérifier le jour J (candidats : développement, sécurité, réseau, logiciel libre)
>
> **Texte :**

Je suis l'auteur d'Thot Secure, publié en v0.1.0 sous Apache-2.0. C'est un SOAR/CSPM défensif en Python/FastAPI : des événements normalisés entrent, des règles YAML détectent, un score est calculé, une politique *policy-as-code* décide, un playbook agit — et chaque playbook porte un rollback.

Trois points m'ont occupé plus que le reste.

La réversibilité est dans le modèle de données : `POST /api/v1/actions/{id}/rollback` doit réussir tant que la fenêtre de rollback est ouverte. Une action qu'on ne peut pas annuler n'entre pas dans un playbook.

Le journal d'audit est chaîné par hachage, vérifiable sur place (`GET /api/v1/audit/verify`) et exportable en `jsonl` ou `cef`. Une chaîne prouve la cohérence interne, pas la complétude : l'ancrage de la tête de chaîne reste une décision de déploiement. Je préfère l'écrire que le laisser croire.

Les défauts sont fermés : `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised`, qu'aucune politique ne peut contourner, et un connecteur non configuré qui tourne en mode simulé — on peut donc installer l'outil avant de lui confier le moindre identifiant.

Sur l'auto-hébergement : les défauts pointent vers l'intérieur (SQLite, bus en mémoire, console Jinja2 sans chaîne de build Node, aucun CDN). Aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface ; c'est un constat de lecture, à confirmer par audit du code, pas une garantie que je demande de croire sur parole.

C'est un alpha et il manque des choses : pas d'agent endpoint, pas de corpus de règles éprouvé, PostgreSQL seulement documenté, quatre rôles RBAC. Dépôt : `https://github.com/thotsecure/thot-secure`

---

# 5. Bloc dons (FR) — non inclus dans le texte publié

**Décision** : le texte publié ne mentionne pas les dons. Motif : le Journal du Hacker n'est pas un lieu de collecte, une sollicitation affaiblirait un texte qui repose entièrement sur des faits vérifiables, et un texte de 260 mots n'a pas la place d'accueillir un bloc de soutien sans que celui-ci devienne le sujet.

Si — et seulement si — la question est posée explicitement dans les commentaires, répondre **une fois**, sobrement, avec le bloc ci-dessous, sans le remettre dans la soumission. Les quatre éléments sont obligatoires.

> **Soutien (facultatif).** Le projet ne vend rien et ne propose aucun service payant.
>
> ```
> Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
> Solana  (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
> ```
>
> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.
>
> Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais de clé privée ni de phrase de récupération. Aucun don ne donne droit à un support prioritaire ni à une influence sur les décisions techniques.

Interdits : recopier ces adresses de mémoire (elles doivent être relues dans le §12 du contrat ou dans le dépôt officiel au moment de l'envoi) ; les placer en accroche ; suggérer une contrepartie ; demander une clé privée ou une phrase de récupération — le projet ne le fait jamais, et une telle demande est une tentative d'arnaque à signaler.

---

# 6. Réponses aux objections probables (FR)

| Objection | Réponse courte |
|---|---|
| « Encore un projet qui n'est qu'un dépôt vide. » | Reconnaître l'état alpha, citer la commande de tests (`python -m unittest discover -s tests -t . -v`) et le périmètre couvert par le contrat, sans prétendre que tout est terminé. Si des couches ne sont pas encore publiées, le dire. |
| « "Sans télémétrie", c'est une affirmation ou une promesse ? » | C'est un constat de lecture du contrat d'interface : aucun mécanisme de télémétrie n'y apparaît. À confirmer par audit du code, et la vérification est bienvenue comme contribution. Ne pas transformer cela en garantie. |
| « Pourquoi SQLite ? » | Défaut choisi pour qu'on puisse évaluer l'outil sans démarrer de service (une seule base fichier). PostgreSQL/TimescaleDB est documenté comme migration, pas testé par défaut. |
| « Sans agent, à quoi ça sert ? » | Thot Secure consomme des événements normalisés via `POST /api/v1/events` ; la télémétrie hôte vient d'ailleurs. C'est un choix de périmètre, affiché comme tel. |
| « Qui décide du projet ? » | Développement sous DCO, sans CLA, au moins une approbation de mainteneur avant fusion ; la règle d'absence totale de capacité offensive est tenue comme non négociable. Si le document de gouvernance n'est pas encore publié, l'admettre. |
| « Pourquoi pas du Rego ? » | Rego/OPA est pris en charge si `THOT_OPA_BIN` pointe vers un binaire présent ; le YAML est le défaut pour rester relisible en revue par un analyste. |
| « Combien ça consomme ? » | Ne pas inventer. Donner une mesure réelle si elle a été faite, en la présentant comme ponctuelle, ou dire qu'elle n'a pas été mesurée. |

---

# 7. Checklist avant publication (FR)

- [ ] Le texte publié fait entre 150 et 300 mots (cible 250) — comptage effectué, pas estimé.
- [ ] La qualité d'auteur est déclarée en première phrase.
- [ ] La phrase sur la télémétrie est bien un constat de lecture suivi d'un appel à vérification ; les mots « zéro », « garanti », « air-gap » n'y figurent pas.
- [ ] Un seul lien : le dépôt.
- [ ] Aucun bloc de dons dans la soumission ; le bloc du §5 est prêt en réserve pour une question explicite.
- [ ] Aucune fonctionnalité non livrée présentée au présent ; les éléments d'arborescence cible sont absents du texte publié.
- [ ] Aucun chiffre non mesuré ; aucun superlatif marketing.
- [ ] Les règles et le format exact de soumission ont été relus le jour J ; les étiquettes utilisées existent réellement.
- [ ] Le compte a un historique de participation suffisant, ou la soumission est reportée.
- [ ] L'auteur est disponible sur 24 heures et ne demandera aucun vote.
