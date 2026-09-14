```yaml
canal: LinkedIn (post organique, compte projet)
langue: fr
format: post texte sans image + variante A/B + variante courte pour le feed
objectif: "positionner Thot Secure v0.1.0 sur l'impact professionnel (temps humain, contrôle, réversibilité) et générer des visites du dépôt GitHub"
mot_cle_principal: "SOAR défensif open source"
longueur: "post principal <= 1300 caractères (auto-imposé ; la limite plateforme est 3000) ; variante A/B <= 1300 ; variante courte 400-600"
heure_optimale_publication: "mardi ou mercredi, 08 h 15 - 09 h 00 heure de Paris (pic de consultation avant les réunions du matin) ; éviter vendredi après 15 h et le week-end"
regles_specifiques_du_canal:
  - "les 2 premières lignes sont visibles avant le « voir plus » : le hook doit tenir sans le reste"
  - "pas de lien externe placé en fin de la 1re ligne ; le lien va en fin de post (ou en premier commentaire, voir notes)"
  - "3 à 5 hashtags maximum, en fin de post, en français, sans bloc de 15 mots-clés"
  - "pas de demande d'engagement (« likez si… », « partagez »), pas de fausse rareté, pas d'emoji décoratif en série"
  - "ton professionnel posé, pas de storytelling émotionnel ; LinkedIn punit le clickbait par la baisse de portée"
  - "aucun chiffre d'impact présenté comme mesuré : les ordres de grandeur doivent être remplacés par les chiffres de l'auteur du post"
  - "répondre aux commentaires dans les 2 h suivant la publication"
sigles_a_ne_pas_confondre: "le contrat d'interface n'expose que MTTA et MTTR (GET /api/v1/stats/overview). MTTD n'est pas exposé : ne pas l'écrire dans le post."
dons: "aucune adresse de don dans ce fichier (choix éditorial : X, Bluesky, Mastodon et LinkedIn n'en portent pas ; les adresses vivent dans la newsletter, dans README.md, .github/FUNDING.yml, GET /ui/support et docs/support.md)."
autopromotion: "disclosure en clair dans le post (« je maintiens… » dans le premier commentaire) ; un seul lien ; pas de sollicitation ; pas de DM automatique ; contenu utile même sans clic (chaque garantie est décrite sur place)."
```

# LinkedIn — post de lancement Thot Secure v0.1.0 (FR)

Angle : impact professionnel (temps humain, MTTA/MTTR, contrôle et réversibilité plutôt qu'automatisation aveugle).
Faits techniques : tous vérifiables dans `docs/architecture/api-contract.md` (§1 invariants, §4.6 actions, §4.7 audit, §4.8 stats, §6 garde-fous, §8 CLI).

---

## Post principal (A)

Longueur mesurée : **1258/1300 caractères** (compte brut, espaces, ponctuation, retours à la ligne et URL inclus).

<!--post:1-->
```text
Un finding « high » tombe à 3 h du matin. Trois questions décident de la suite : qui peut agir, sur quelle base, et comment annuler.

Thot Secure v0.1.0 (Apache-2.0, Python/FastAPI) y répond dans le produit, pas dans une procédure interne.

1. Dry-run par défaut. THOT_DRY_RUN=true. Aucune action réelle sans levée explicite, globale ou par tenant.

2. Réversibilité obligatoire. Chaque playbook livré embarque son rollback ; un playbook irréversible exige une approbation humaine.

3. Décision traçable. Politiques en YAML versionné : auto, require_approval, notify_only, ignore. Aucune politique ne matche → notify_only. Chaque action porte un policy_id et un audit_seq dans un journal chaîné par hash.

Les garde-fous ne sont pas des options : plafond horaire par tenant, cooldown par (tenant, playbook, cible), cibles protégées jamais touchées, dry-run prioritaire.

Mesurable : /api/v1/stats/overview expose compteurs 24 h/7 j, moyennes MTTA/MTTR, top règles, actions et rollbacks.

Ordre de grandeur à remplacer par vos chiffres : sur quelques milliers d'alertes par semaine, l'essentiel du temps humain part dans la qualification. C'est le poste que la policy-as-code attaque d'abord.

https://github.com/thot-corp/thot-secure
```

**Hashtags (à coller en fin de post, après le lien) :** `#Cybersécurité #SOC #OpenSource #SOAR`

**Premier commentaire à publier soi-même dans les 2 minutes (disclosure + précision) :**
> Je maintiens le projet. Le contrat d'interface v0.1.0 est gelé et public : `docs/architecture/api-contract.md`. Les adresses de don officielles ne sont pas dans ce post ; elles vivent dans le dépôt, la page de soutien du produit et `docs/support.md` — vérifiez-les toujours à la source.

---

## Variante A/B du post principal (angle « preuve » : conformité, audit, SIEM)

Angle volontairement différent du post A : on ne parle plus de temps gagné, mais de capacité à **prouver** ce qui s'est passé. À tester en second, à 7 jours d'intervalle minimum.

Longueur mesurée : **1127/1300 caractères**.

<!--post:2-->
```text
Le sujet n'est pas d'aller plus vite. C'est de pouvoir prouver ce qui s'est passé.

Un journal d'audit classique se modifie. Thot Secure chaîne ses enregistrements par hash : hash = sha256(seq|ts|tenant_id|actor|actor_role|action|target|before|after|prev_hash). Modifier une ligne casse la chaîne à partir de ce point, et l'endroit exact est identifié.

Concrètement : GET /api/v1/audit/verify renvoie {valid, records, broken_at}. En CLI, thotsecure audit verify sort en code 0 si la chaîne est valide, et 3 si elle est corrompue. Pas 1 : 3. Un script d'audit peut donc distinguer « tout va bien » d'« une vérification a échoué », au lieu de traiter les deux comme une erreur générique.

L'export se fait en jsonl ou cef vers votre SIEM, sans format propriétaire ni agent à installer.

Le reste tient en deux garanties par défaut : dry_run actif (THOT_DRY_RUN=true) et rollback sur chaque playbook livré (sauf marquage irréversible explicite, qui impose une approbation humaine).

Apache-2.0, Python/FastAPI, SQLite pour le MVP, console embarquée sans build Node.

https://github.com/thot-corp/thot-secure
```

**Hashtags :** `#Cybersécurité #Audit #SIEM #OpenSource`

---

## Variante courte pour le feed

Pour un repost, une story LinkedIn « lien », ou une version mobile-first. Un seul bloc, pas de liste longue.

Longueur mesurée : **595/600 caractères** (cible 400-600).

<!--post:3-->
```text
Le réflexe SOAR habituel : automatiser d'abord, espérer ensuite.

Thot Secure v0.1.0 prend le chemin inverse : dry-run par défaut (THOT_DRY_RUN=true), rollback sur chaque playbook livré (sauf irréversibles, qui exigent une approbation), audit chaîné par hash, isolation stricte par tenant.

Les décisions sont du YAML versionné (auto, require_approval, notify_only, ignore) ; plafond horaire et cooldown ne se contournent pas.

Pour mesurer avant d'automatiser : thotsecure demo --tenant demo déroule findings et actions en local.

Apache-2.0 : https://github.com/thot-corp/thot-secure
```

**Hashtags :** `#Cybersécurité #SOC #OpenSource`

---

## Notes de publication

- **Heure optimale :** mardi ou mercredi entre 08 h 15 et 09 h 00 (Paris). Deuxième créneau acceptable : mardi 12 h 30 - 13 h 00. Éviter vendredi après-midi.
- **Lien :** le lien est en fin de post. Si la portée du post A est faible après 60 minutes, republier la variante A/B avec le lien en **premier commentaire** et un appel du type « dépôt en commentaire » : c'est le seul cas où déplacer le lien est justifié.
- **Un seul lien par post.** Ne pas ajouter le lien de la page de soutien.
- **Ordre de test recommandé :** A (semaine 1), A/B (semaine 2) — à heure et jour identiques pour que la comparaison ait un sens. La variante courte sert de rappel, pas de test A/B.
- **Pas d'image obligatoire.** Si une capture est ajoutée, elle doit montrer une sortie CLI réelle (`thotsecure demo --tenant demo`, `thotsecure audit verify`) et être décrite en texte alternatif ; ne jamais inclure de donnée client, de clé API ou de nom d'hôte réel.
- **Chiffres :** toute mention de volume d'alertes, de temps gagné ou de réduction de délai doit être remplacée par la mesure de l'auteur du post avant publication. Le contrat n'expose que des compteurs et des moyennes (24 h/7 j, MTTA/MTTR) : il ne fournit aucun chiffre d'impact, et ce fichier n'en invente aucun.
- **Vocabulaire :** employer « finding » (pas « alerte ») pour rester aligné sur le produit, et « contre-mesure réversible ». Ne jamais écrire « détection automatique des attaques » : le produit collecte, détecte, score, décide — puis applique une contre-mesure réversible.
