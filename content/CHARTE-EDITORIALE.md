```yaml
canal: Documentation interne du projet — s'applique à tous les canaux
langue: fr (le document de travail ; les contenus publiés suivent la langue de leur canal)
format: charte éditoriale, règles non négociables + tableaux + procédure de validation
objectif: >
  Fixer les règles de publication du projet Thot Secure : honnêteté technique, respect strict
  des règles de chaque canal, valeur autonome pour le lecteur, mesure systématique,
  recyclage des sujets, et encadrement strict de toute mention de dons.
mot_cle_principal: charte éditoriale
longueur: ~1400 mots
public_cible: toute personne publiant au nom d'Thot Secure (mainteneurs, contributeurs, relais)
date_de_publication_cible: référence interne, mise à jour à chaque release
avertissement: ce document prime sur toute envie de « faire du bruit » — en cas de doute, ne pas publier
```

# Charte éditoriale Thot Secure

> **Principe directeur.** Thot Secure est un outil de sécurité défensif. Sa crédibilité repose entièrement sur une chose : ce que le projet affirme doit être vérifiable dans le code, dans le contrat d'interface (`docs/architecture/api-contract.md`) ou dans une démonstration reproductible. Une communication qui exagère détruit la confiance plus vite qu'un bug.

Cette charte s'applique à **tout** contenu publié au nom du projet : articles, devlogs, posts de forum, réseaux sociaux, newsletter, vidéos, réponses en commentaire, documentation publique.

---

## 1. Règles non négociables

1. **Jamais de spam.** Pas d'envoi massif, pas de message privé non sollicité, pas de repost du même contenu en rafale sur plusieurs canaux le même jour, pas de commentaire promotionnel glissé sous un post tiers sans rapport.
2. **Respect strict des règles de chaque canal.** Flair obligatoire quand il existe, limite d'autopromotion respectée, format du canal suivi, un seul lien, disclosure d'auteur explicite. Les règles de canal sont **re-vérifiées le jour de la publication** : elles changent, et « je ne savais pas » n'est pas une défense.
3. **Toujours lier le dépôt**, et une démo reproductible quand elle existe (`thotsecure demo --tenant demo`). Un lecteur doit pouvoir passer de la promesse à la preuve sans nous croire sur parole.
4. **Toujours fournir une valeur technique autonome.** Le contenu doit être utile même si personne ne clique sur le lien. Un post qui n'apprend rien à un ingénieur sécurité est un post publicitaire, et sera traité comme tel.
5. **Toujours adapter le format au canal.** Reddit n'est pas Hacker News, LinkedIn n'est pas un journal LinuxFr. Le même texte partout est du spam, même avec de bonnes intentions.
6. **Toujours mesurer.** Aucune publication sans indicateur associé et sans relevé dans `content/campaign/metriques.md`.
7. **Toujours recycler.** Un sujet produit un article long, des posts déclinés, un thread et une vidéo. On ne rédige pas deux fois le même fond, on le décline.
8. **Jamais de mention de don en accroche.** Les dons n'apparaissent qu'en **toute fin** de contenu, sobrement, jamais en tête, jamais en premier post d'un thread, jamais dans un titre, jamais dans une bio tronquée qui les mettrait en avant.
9. **Jamais de contrepartie promise.** Aucun don ne donne droit à un support prioritaire, une fonctionnalité, un accès, un badge ou une influence sur la roadmap. Le projet ne promet rien en échange d'un paiement, et ne doit jamais laisser entendre le contraire.
10. **Jamais de demande de clé privée ni de phrase de récupération.** Sous aucun prétexte, sur aucun canal, par aucun intermédiaire. Le projet ne demandera jamais non plus d'envoyer des fonds vers une adresse communiquée en commentaire ou en message privé.
11. **Jamais d'affirmation non vérifiable.** Toute fonctionnalité citée existe dans le contrat d'interface ou est explicitement étiquetée **roadmap**. Aucun chiffre inventé présenté comme une mesure : les exemples sont marqués « ordre de grandeur à remplacer ». Les fonctions absentes du contrat ne sont pas décrites comme présentes, même « à peu près ».
12. **Jamais de dénigrement de concurrent.** Critique factuelle et équilibrée uniquement. On dit ce que les autres outils font bien, et dans quels cas Thot Secure n'est pas le bon choix.
13. **Aucune capacité offensive présentée, suggérée ou sous-entendue.** Pas de hack-back, pas de scan agressif, pas de « on pourrait ajouter… ». Si une idée de contenu flirte avec l'offensif, elle est abandonnée.
14. **Aucune donnée réelle de client, d'employeur ou de tiers.** Captures, logs, noms d'hôtes, adresses IP : on utilise les plages de documentation (`203.0.113.0/24`, `2001:db8::/32`) et des noms fictifs. Aucune donnée personnelle, aucun identifiant, aucune clé, même expirée, même tronquée.

---

## 2. Ce qu'on fait / ce qu'on ne fait pas

| Ce qu'on fait | Ce qu'on ne fait pas |
|---|---|
| Écrire un article long, puis le décliner en posts adaptés par canal | Copier-coller le même texte sur 6 canaux le même jour |
| Publier des commandes et du YAML copiables, testés | Décrire des fonctionnalités « prévues » au présent |
| Dire « ça n'est pas encore branché » quand c'est le cas | Laisser croire que tout fonctionne en production |
| Mentionner les dons en fin d'article, une fois, sobrement | Mettre une adresse de don en accroche, en titre ou en bio mise en avant |
| Indiquer la licence Apache-2.0 et la gouvernance ouverte | Parler de « communauté » quand il n'y a pas encore de contributeurs |
| Répondre aux objections techniques, y compris quand elles sont fondées | Argumenter en boucle pour défendre le projet |
| Publier un devlog qui documente aussi les bugs et les erreurs | Ne montrer que les réussites et les captures propres |
| Mesurer les étoiles **et** les PR externes mergées | Ne regarder que les étoiles |
| Ancrer les affirmations dans `api-contract.md` | Inventer un chiffre, un benchmark ou un retour utilisateur |
| Dire « Thot Secure n'est pas le bon outil si… » | Prétendre être la solution universelle |
| Signaler soi-même une limite découverte après publication | Corriger discrètement un post déjà publié sans le dire |
| Répondre en commentaire avec du contenu technique | Poster un lien puis disparaître |
| Assumer qu'un lancement peut faire peu de bruit | Acheter des étoiles, des votes, des abonnés ou des vues |
| Utiliser un seul lien, une seule fois, avec disclosure | Multiplier les liens, utiliser des raccourcisseurs, poster en messages privés |

---

## 3. Procédure de validation avant publication

Aucun contenu ne part sans passer ces cinq contrôles, dans cet ordre. Le responsable du lot éditorial tient le rôle de dernier filtre et peut **refuser** une publication.

### Étape 1 — Relecture technique (bloquante)

- [ ] Chaque nom d'endpoint, de commande CLI, de variable `THOT_*`, de clé YAML, de statut d'action et de valeur de décision **existe exactement** dans `docs/architecture/api-contract.md`.
- [ ] Les extraits de code s'exécutent : au minimum, `thotsecure init-db`, `thotsecure demo --tenant demo`, `thotsecure doctor`, les commandes de la démo. Les blocs YAML de règle, de politique et de playbook valident via `thotsecure rules validate` / `thotsecure policies validate`.
- [ ] Toute fonctionnalité non implémentée est étiquetée **roadmap**, visiblement.
- [ ] Aucun chiffre n'est présenté comme mesuré ; les exemples sont marqués comme tels.
- [ ] Aucune donnée client, aucun identifiant, aucune adresse IP réelle, aucun nom d'hôte de production.

### Étape 2 — Vérification des liens

- [ ] Un seul lien par post de canal (sauf article long où les références techniques sont légitimes).
- [ ] L'URL du dépôt est exacte et pointe vers la bonne branche/tag de release.
- [ ] Les liens de documentation existent réellement dans le dépôt au moment de la publication.
- [ ] Aucun lien raccourci opaque ; aucun lien affilié ; aucun tracker ajouté aux URL.
- [ ] Toute URL citée en référence externe a été ouverte et correspond bien au contenu annoncé (si l'accès réseau est indisponible, la publication est reportée — on ne publie pas un lien qu'on n'a pas ouvert).

### Étape 3 — Vérification des adresses de don (bloquante, caractère par caractère)

- [ ] Les adresses sont recopiées **depuis la source officielle** : `docs/architecture/api-contract.md` §12, `README.md`, `.github/FUNDING.yml` ou `GET /ui/support` — **jamais** depuis un souvenir, un brouillon, un message ou une capture d'écran.
- [ ] Comparaison caractère par caractère, deux fois, par deux relectures distinctes si possible.
- [ ] Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- [ ] Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
- [ ] Le mot « mainnet » et le nom de la devise sont présents à côté de chaque adresse.
- [ ] La phrase exacte figure : « Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel. »
- [ ] L'avertissement anti-arnaque figure : seule la source officielle (dépôt Git + site du projet) fait foi ; le projet ne demande jamais de clé privée ni de phrase de récupération.
- [ ] La mention est **en fin de contenu**, sobre, sans urgence, sans montant suggéré, sans palier de don.
- [ ] Aucune promesse de contrepartie, de support prioritaire ou d'influence sur la roadmap.
- [ ] **Une adresse de don fausse est le seul risque de cette charte qui peut faire perdre de l'argent à quelqu'un.** En cas de doute : on retire la mention et on publie sans elle.

### Étape 4 — Conformité au canal

- [ ] Les règles du canal ont été relues **le jour même** (flair, limite d'autopromotion, format, ratio participation/promotion).
- [ ] L'historique de participation de la personne qui publie est suffisant pour que le post ne soit pas perçu comme du drive-by.
- [ ] La disclosure « je suis l'auteur / I'm the author, maintainer of Thot Secure » est présente en clair.
- [ ] Le texte est dans la langue du canal.
- [ ] La longueur respecte la limite du canal (comptée, pas estimée).

### Étape 5 — Journalisation et mesure

- [ ] Le contenu est enregistré dans `content/` (version publiée = version du dépôt).
- [ ] L'indicateur associé et le seuil de décision sont notés dans `content/campaign/metriques.md`.
- [ ] Une date de relevé est fixée (J+2, J+7, J+30).
- [ ] Les commentaires et objections reçus sont relevés et regroupés : ils deviennent la matière du contenu suivant.

---

## 4. Répartition des rôles

| Rôle | Responsabilité |
|---|---|
| Rédacteur | Produit le contenu complet, sourcé sur le contrat, dans le format du canal. |
| Relecteur technique | Vérifie chaque affirmation, exécute les commandes, refuse tout ce qui n'est pas vérifiable. |
| Responsable éditorial | Arbitre le calendrier, contrôle les liens et les adresses de don, tient le journal de mesure. |
| Publication | Publie depuis le compte du projet, répond aux commentaires dans les 24 h (une non-réponse est un signal négatif). |

En l'absence de relecteur technique disponible : **on décale la publication**. Un lancement retardé de deux jours ne coûte rien ; une affirmation fausse sur un endpoint ou une adresse de don erronée coûte cher.

---

## 5. Ton et style

**Ce que le ton est :** technique, direct, factuel, orienté preuve. On nomme les limites avant qu'on nous les demande. On assume les bugs. On écrit « je ne sais pas » ou « pas encore mesuré » quand c'est le cas.

**Ce que le ton n'est pas :** enthousiaste sur le vide, alarmiste, grandiloquent.

| À éviter | À écrire |
|---|---|
| « révolutionnaire », « game-changer », « next-gen », « leader du marché » | « voici ce que ça fait, voici ce que ça ne fait pas » |
| « 10x plus rapide » (sans protocole de mesure publié) | « les chiffres à votre échelle sont à mesurer ; voici notre méthode » |
| « sécurisé par design » (auto-décerné) | « quatre garanties vérifiables : réversibilité, audit chaîné, isolation, dry-run » |
| « il suffit de » | « il faut, dans l'ordre : … » |
| « les utilisateurs adorent » (sans source) | « deux retours reçus à ce jour, dont un négatif, décrit ci-dessous » |
| « notre communauté grandit » | le nombre réel de contributeurs, daté |

Structure attendue de tout contenu long : **problème → solution → preuve → code → appel à contribution**.

---

## 6. Gestion des erreurs après publication

Une affirmation technique publiée qui s'avère fausse est corrigée **publiquement** : mention de correction en tête ou en fin du contenu, description de l'erreur, date. On ne supprime pas un post pour effacer une erreur, sauf si celui-ci contient une donnée sensible, une adresse de don erronée ou une capacité offensive — auquel cas on retire, et on explique pourquoi.

Une adresse de don publiée par erreur doit être corrigée **immédiatement et visiblement**, avec un message explicite invitant les lecteurs à ne pas envoyer de fonds vers l'adresse erronée.
