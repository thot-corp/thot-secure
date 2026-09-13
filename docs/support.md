# Soutenir le projet

*Thot Secure est un logiciel libre sous licence Apache-2.0. Les dons financent ce qui ne se code pas tout seul : l'infrastructure, les certificats, les audits de sécurité et la maintenance dans la durée.*

## À quoi servent les dons

| Poste | Pourquoi c'est nécessaire |
|---|---|
| **Hébergement** | Site de documentation, miroir des releases, intégration continue, registre d'images de conteneurs |
| **Certificats et nom de domaine** | Publication de la documentation et des binaires en HTTPS |
| **Audits de sécurité** | Relecture externe du code d'audit chaîné, du RBAC et de l'isolation multi-tenant — un outil de sécurité qui n'est pas audité n'est pas crédible |
| **Binaires signés** | Chaîne de publication reproductible et signée (cosign) : un binaire non signé ne devrait jamais être installé |
| **Documentation** | Rédaction, relecture technique, traductions |
| **Maintenance** | Temps de tri des issues, revue des contributions, veille sur les dépendances |

!!! note "Ce que les dons ne financent pas — et ne changent pas"

    Un don **n'achète rien** : ni priorité de support, ni fonctionnalité, ni influence sur
    les décisions de sécurité, ni exception aux invariants du projet (dry-run par défaut,
    réversibilité, zéro capacité offensive). Les canaux de décision sont décrits dans la
    [Gouvernance](governance.md).

## Adresses officielles

Ce sont les **adresses de référence** du projet, telles que publiées par le dépôt officiel.

| Réseau | Devise | Adresse |
|---|---|---|
| **Bitcoin mainnet** | BTC | `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR` |
| **Solana mainnet** | SOL | `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi` |

=== "Bitcoin (BTC, réseau Bitcoin mainnet)"

    ```text
    33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
    ```

=== "Solana (SOL, réseau Solana mainnet)"

    ```text
    95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
    ```

!!! warning "Anti-arnaque"

    **Dons volontaires, aucune contrepartie attendue.** Vérifiez toujours ces adresses depuis
    ce dépôt officiel — seule la source officielle (repo Git + site du projet) fait foi.
    Thot Secure ne demandera **jamais** votre clé privée, votre phrase de récupération ni un
    accès à votre wallet, et n'accorde **aucun** avantage, support prioritaire ou
    fonctionnalité en échange d'un don.

    Trois réflexes simples :

    * **Recopiez l'adresse depuis cette page**, jamais depuis un message privé, un courriel,
      une vidéo ou un commentaire de forum — même s'il semble venir d'un mainteneur.
    * **Vérifiez le réseau.** Envoyer un actif sur le mauvais réseau (par exemple du SOL vers
      une adresse Bitcoin, ou un jeton sur une autre chaîne) entraîne une perte définitive.
    * **Personne n'a besoin d'un accès à votre wallet.** Une demande de connexion de wallet,
      de signature ou de « validation » est une tentative de vol, sans exception.

## Autres façons de soutenir

| Canal | Remarque |
|---|---|
| **GitHub Sponsors** | Si un programme de sponsoring est ouvert, il est référencé dans `.github/FUNDING.yml` du dépôt officiel |
| **Open Collective** | Canal adapté à une transparence comptable publique (si actif, référencé dans le dépôt) |
| **Liberapay** | Dons récurrents, sans commission prélevée au bénéficiaire (si actif, référencé dans le dépôt) |

!!! note "Source unique de vérité pour les canaux"

    Le dépôt officiel est la référence : les canaux actifs sont listés dans
    `.github/FUNDING.yml`, et les adresses ci-dessus sont reprises à l'identique dans
    `README.md`, dans la console embarquée (`GET /ui/support`) et dans cette page. Si une
    adresse diverge quelque part, **c'est cette page et le dépôt qui font foi** — et
    [signalez la divergence](contributing.md).

## Contribuer sans argent

Le temps de contribution vaut souvent plus qu'un don :

| Contribution | Où commencer |
|---|---|
| Écrire ou corriger une règle de détection | [Écrire une règle](detection/rules.md) |
| Proposer une politique de décision | [Politiques](decision/policies.md) |
| Développer un playbook ou un connecteur (avec rollback !) | [Playbooks et connecteurs](actions/playbooks.md) |
| Améliorer la documentation | [Contribuer](contributing.md) |
| Ajouter un test ou reproduire un bogue | `python -m unittest discover -s tests -t . -v` |
| Signaler une vulnérabilité **en privé** | `SECURITY.md` à la racine du dépôt — **jamais** en issue publique |
| Témoigner d'un déploiement réel | Utile pour la [feuille de route](roadmap.md) et la robustesse du produit |

## Transparence

* **Registre public et agrégé.** L'usage des fonds est publié de façon **agrégée** (par poste :
  hébergement, audits, certificats…). Les dons ne sont **jamais** rendus nominatifs sans
  consentement explicite du donateur.
* **Aucune conservation de données de don.** Thot Secure ne collecte pas l'identité des
  donateurs et n'a aucun moyen de relier une adresse de portefeuille à une personne. Voir
  [RGPD](compliance/rgpd.md).
* **Aucune sollicitation agressive.** Pas de bandeau pressant, pas de compte à rebours, pas
  de relance par courriel. Les dons apparaissent en fin de page, jamais en accroche.
* **Aucun avantage en échange.** C'est le principe inscrit dans la [Gouvernance](governance.md) :
  un don ne crée pas de relation client, ni de droit de regard sur la sécurité du produit.

Merci de lire, de tester, de critiquer et de corrigera ce qui doit l'être : c'est déjà
beaucoup.

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
