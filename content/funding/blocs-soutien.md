```yaml
canal: Bibliothèque de contenus réutilisables (articles, README, bio, FAQ, /ui/support)
langue: fr (variante anglaise fournie pour la bio et les blocs courts)
format: blocs de texte prêts à insérer, de trois longueurs + FAQ de financement
objectif: >
  Fournir des mentions de soutien sobres, honnêtes et juridiquement propres, à insérer
  exclusivement en fin de contenu, avec les avertissements anti-arnaque exigés.
mot_cle_principal: soutenir Thot Secure
longueur: ~900 mots
public_cible: rédacteurs du projet (blog, README, bio, réponses en commentaire)
regle_absolue: jamais en accroche, jamais en titre, jamais en premier post d'un thread
```

# Blocs de soutien réutilisables

> **Règle d'usage.** Ces blocs se placent **uniquement en toute fin** de contenu. Jamais en introduction, jamais en titre, jamais dans un premier post de thread, jamais dans un message privé non sollicité. Un seul bloc par contenu : on ne cumule pas la version courte et la version longue.

**Adresses officielles — à recopier depuis `docs/architecture/api-contract.md` §12, jamais de mémoire :**

- Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

---

## 1. Version une ligne (signature de fin d'article, bas de README)

> Thot Secure est un projet bénévole sous Apache-2.0. Si ce travail vous est utile : [soutenir le projet](https://github.com/thot-corp/thot-secure#soutenir) — dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

**Variante anglaise :**

> Thot Secure is a volunteer-run Apache-2.0 project. If it's useful to you: [support the project](https://github.com/thot-corp/thot-secure#support) — voluntary donations, no strings attached. Always verify the address from the official repository.

*Note de publication : remplacer l'URL par le chemin réel de la section de soutien du dépôt. Ne jamais coller une adresse crypto directement dans une signature de forum ou de réseau social.*

---

## 2. Version un paragraphe (fin d'article long, fin de newsletter)

> **Soutenir Thot Secure.** Le projet est développé sur du temps bénévole et publié sous licence Apache-2.0. Il accepte des dons volontaires, qui financent du temps de maintenance, de la relecture de règles de détection et l'infrastructure de CI :
>
> - **Bitcoin (BTC, réseau Bitcoin mainnet)** : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
> - **Solana (SOL, réseau Solana mainnet)** : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
>
> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.
>
> ⚠️ **Anti-arnaque** : seule la source officielle — le dépôt Git et le site du projet — fait foi. Thot Secure ne demandera **jamais** de clé privée ni de phrase de récupération, et ne proposera jamais d'investissement, de jeton ou de support prioritaire en échange d'un paiement. Toute demande de ce type est une fraude. Les alternatives gratuites et souvent plus utiles : ouvrir une issue reproductible, proposer une règle de détection avec ses faux positifs, relire le contrat d'interface, tester le projet dans votre labo et raconter ce qui casse.

---

## 3. Version section complète (page de soutien du site, `/ui/support`, `docs/support.md`)

### Soutenir Thot Secure

Thot Secure est un SOAR/CSPM défensif open source, publié sous licence **Apache-2.0**. Le projet n'a ni société commerciale, ni investisseur, ni budget publicitaire : il vit du temps de ses mainteneurs et de ses contributeurs.

**Ce que finance un don**, concrètement : du temps de maintenance et de revue de code, la relecture technique des règles de détection communautaires, l'infrastructure d'intégration continue, et le temps passé à répondre aux retours d'exploitation. Un don ne finance pas de la communication, et n'achète aucune influence sur la roadmap.

#### Adresses officielles

| Réseau | Adresse |
|---|---|
| Bitcoin (BTC, réseau Bitcoin mainnet) | `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR` |
| Solana (SOL, réseau Solana mainnet) | `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi` |

Envoyez uniquement sur le réseau indiqué. Un envoi sur un autre réseau (autre chaîne, autre testnet) entraîne une perte définitive des fonds, sans recours possible.

> Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

#### ⚠️ Avertissement anti-arnaque

- **Seule la source officielle fait foi** : le dépôt Git du projet et le site du projet. Toute adresse publiée ailleurs (commentaire, message privé, vidéo, capture d'écran, forum) doit être considérée comme non fiable jusqu'à vérification dans le dépôt.
- Thot Secure **ne demande jamais** de clé privée, de phrase de récupération (seed), de fichier de portefeuille, ni de signature de transaction.
- Thot Secure ne propose **aucun** investissement, jeton, prévente, NFT, programme de parrainage ou rendement.
- Thot Secure ne contacte personne en message privé pour solliciter un don ou promettre un accès.
- Thot Secure ne promet **aucun** avantage en échange d'un don : ni support prioritaire, ni fonctionnalité, ni place dans la roadmap, ni badge de « sponsor officiel ».
- Si vous constatez une usurpation, ouvrez une issue publique pour la signaler.

#### Autres façons d'aider (gratuites, et souvent plus utiles)

1. **Une règle de détection** avec ses faux positifs documentés et un événement d'exemple.
2. **Un connecteur de playbook** avec son rollback — c'est-à-dire la commande exacte qui défait l'action.
3. **Un test** sur un cas limite : chaîne d'audit rompue, rollback expiré, idempotence, isolation multi-tenant.
4. **Une traduction** de la documentation, de la console ou des diagnostics de règle invalide.
5. **Un retour d'exploitation** : « je l'ai testé dans mon labo, voilà ce qui casse » vaut plus qu'une étoile.
6. **Une relecture critique du contrat d'interface** (`docs/architecture/api-contract.md`).

#### Transparence

Aucun don n'est requis pour utiliser Thot Secure, ni pour obtenir une réponse sur le dépôt, ni pour faire accepter une contribution. Le code publié sous Apache-2.0 est le même pour tout le monde. Les dons reçus, s'il y en a, ne créent aucun droit particulier — et le projet s'engage à ne jamais conditionner une fonctionnalité à un financement.

---

## 4. Texte de bio / README (et variante courte)

**Bio longue (profil GitHub, page « à propos », signature de blog) :**

> Thot Secure — SOAR/CSPM défensif open source (Python/FastAPI, multi-tenant, Apache-2.0). Quatre garanties : actions réversibles, audit chaîné par hash, isolation multi-tenant, **dry-run par défaut**. Aucune capacité offensive. Code, contrat d'interface et issues : [dépôt]. Soutien volontaire possible, jamais requis — adresses officielles uniquement dans le dépôt : [lien vers la section de soutien].

**Variante anglaise :**

> Thot Secure — open-source defensive SOAR/CSPM (Python/FastAPI, multi-tenant, Apache-2.0). Four guarantees: reversible actions, hash-chained audit log, strict tenant isolation, **dry-run by default**. No offensive capability. Code, interface contract and issues: [repo]. Voluntary support only, never required — official addresses in the repo: [link].

**Bio courte (≤ 200 caractères, réseaux sociaux) :**

> SOAR/CSPM défensif open source (Apache-2.0). Actions réversibles, audit chaîné, dry-run par défaut. Zéro capacité offensive. [dépôt]

---

## 5. Réponses types aux questions de financement

### « Comment financer le projet ? »

> Trois voies, par ordre d'utilité réelle. 1) Contribuer : une règle de détection avec ses faux positifs, un connecteur avec son rollback, un test sur un cas limite — c'est ce qui fait avancer le logiciel. 2) Relayer utilement : un retour d'expérience d'exploitation, un article technique écrit par vous, une critique du contrat d'interface. 3) Don volontaire, si vous le souhaitez : les adresses officielles (Bitcoin mainnet, Solana mainnet) sont dans le dépôt et sur la page de soutien. Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel. Le projet ne demande jamais de clé privée ni de phrase de récupération.

### « Y a-t-il une version payante ? Une version entreprise ? »

> **Aujourd'hui : non.** Il n'existe aucune offre payante, aucune édition « entreprise », aucun service commercial derrière Thot Secure. Le dépôt public sous Apache-2.0 est tout ce qui existe, et il est complet pour ce qu'il fait : détection, scoring, décision policy-as-code, actions réversibles, audit chaîné, isolation multi-tenant, CLI, API et console embarquée. Utiliser Thot Secure en production ne coûte rien et ne nécessite aucun compte, aucune clé tierce, aucun abonnement.
>
> **Si une offre payante voit le jour**, elle suivra un modèle *open core honnête*, dont la règle est simple : **le cœur reste complet et fonctionnel sous Apache-2.0**. Ce qui pourrait être payant relève uniquement de ce qui ne peut pas être donné gratuitement sans créer de charge permanente :
>
> - du **support** avec engagement de délai ;
> - un **SLA** contractuel et une assistance à la mise en production ;
> - des **intégrations d'entreprise** (connecteurs spécifiques à un éditeur, déploiements particuliers, accompagnement à l'intégration SIEM/SOAR existant) ;
> - éventuellement de la **formation** et de l'audit de configuration.
>
> Ce qui ne sera **jamais** réservé à une version payante : les garanties de sécurité (dry-run par défaut, réversibilité, chaîne d'audit, isolation multi-tenant), le format des règles et des politiques, l'API et la CLI, et les correctifs de sécurité. Il n'y a pas de « fonctionnalité de sécurité derrière un paywall ».
>
> Cette seconde partie est une **intention publiée, pas un produit existant** : à ce jour, aucune de ces offres n'est disponible, et aucune date n'est annoncée. Si cela change, l'annonce se fera publiquement dans le dépôt, avec la répartition exacte open core / payant.

### « Puis-je financer une fonctionnalité précise ? »

> Non, et c'est un choix. La roadmap est publique et discutée dans les issues ; un financement peut accélérer du temps de développement, mais ne garantit ni l'acceptation d'une fonctionnalité, ni un délai, ni une priorité. Aucun don ne crée de droit sur la roadmap, et aucun contributeur bénévole ne doit voir son travail arbitré par un montant reçu. Si vous avez un besoin précis et un budget, la voie normale est : ouvrir une issue, décrire le cas d'usage, et proposer une contribution (la vôtre ou celle d'un tiers).

### « Le projet vend-il des données, de la télémétrie ou des identifiants ? »

> Non. Thot Secure ne fonctionne pas sur un modèle de revente de données et n'exige aucun compte hébergé par un tiers : la base par défaut est un fichier SQLite local, et le core ne dépend que de la bibliothèque standard Python plus `pydantic` et `PyYAML`. Aucun mécanisme de télémétrie n'apparaît dans le contrat d'interface ni dans les variables d'environnement du projet — et cette affirmation est vérifiable par lecture du code, ce qui est la seule forme d'affirmation acceptable sur ce sujet. Si vous constatez un appel sortant non documenté, c'est un bug de sécurité : ouvrez une issue.

### « Comment savoir si une adresse de don est la bonne ? »

> Trois vérifications, dans cet ordre. 1) Ouvrez le dépôt officiel et lisez l'adresse dans `docs/architecture/api-contract.md` §12 (source unique de vérité), dans `README.md`, dans `.github/FUNDING.yml` ou sur la page `GET /ui/support` de votre instance. 2) Comparez **caractère par caractère** avec celle qu'on vous a communiquée. 3) Si l'adresse vient d'un commentaire, d'un message privé, d'une vidéo ou d'un autre site : considérez-la comme frauduleuse jusqu'à preuve du contraire. Le projet ne vous demandera jamais de clé privée, de phrase de récupération, ni de « valider » un portefeuille. En cas de doute, ne payez pas : aucune contribution financière n'est nécessaire pour utiliser ou soutenir Thot Secure.
