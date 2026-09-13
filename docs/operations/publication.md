# Publier une version (release) — procédure d'exploitation

Ce document décrit **exactement** ce qu'il reste à faire pour qu'une version de Thot Secure
soit publique. Il est écrit pour être suivi par une personne, pas par une machine : la
publication engage le nom du projet, la licence et la confiance des utilisateurs.

> **État au moment de la rédaction (v0.1.0)** : le dépôt est *prêt à publier*, mais **rien
> n'est publié**. Dépôt Git initialisé localement (branche `main`, un commit), aucun remote,
> aucun tag, aucune release, aucun paquet publié, aucun article posté.

---

## 1. Ce que la publication implique (et qui peut le faire)

| Étape | Qui | Automatisable ? |
|---|---|---|
| 1.1 Créer le dépôt distant | mainteneur (compte GitHub) | non |
| 1.2 Pousser `main` | mainteneur (clé SSH ou jeton) | oui, en local |
| 1.3 Protéger `main`, activer Discussions | administrateur GitHub | non (interface) |
| 1.4 Créer les labels, activer Dependabot/CodeQL | administrateur GitHub | oui (workflows fournis) |
| 1.5 Tagger `v0.1.0` → release + SBOM + signatures + image GHCR | workflow `release.yml` | oui |
| 1.6 Publier sur PyPI (facultatif) | mainteneur | oui (à activer) |
| 1.7 Activer GitHub Pages (documentation) | workflow `docs.yml` | oui |
| 1.8 Poster articles, forums, réseaux | mainteneur (comptes personnels) | **non** |

**Aucune de ces étapes ne peut être réalisée par un agent sans compte, sans réseau et sans
autorisation explicite du mainteneur.** C'est volontaire : publier au nom d'un projet est une
décision humaine.

---

## 2. Préparation du dépôt distant (à exécuter par le mainteneur)

```bash
# 2.1 Créer le dépôt vide sur GitHub (interface web ou gh CLI), SANS README ni licence :
#     le dépôt local contient déjà tout. Nom recommandé : thot-secure (org : thotsecure)

# 2.2 Déclarer le remote et pousser la branche principale
git remote add origin git@github.com:thotsecure/thot-secure.git
git push -u origin main

# 2.3 Vérifier qu'aucun fichier sensible n'est parti
git ls-files | grep -E '(^|/)(\.env|targets\.yaml|connectors\.yaml|secret\.key|.*\.db)$' \
  && echo "STOP : fichier sensible suivi par Git" || echo "OK : aucun fichier sensible suivi"
```

Après le premier push, dans les réglages GitHub :

1. **Protection de `main`** : interdire le push direct, exiger une Pull Request, exiger la
   réussite de `ci.yml`, exiger la signature des commits (DCO via `git commit -s`).
2. **Discussions** : activer (canal de support communautaire, référencé par `docs/support.md`).
3. **Security** : activer *Private vulnerability reporting* (utilisé par `SECURITY.md`) et
   *Dependabot alerts*.
4. **Environnements** : créer `release` (utilisé par `release.yml` pour GHCR) avec les
   approbations souhaitées.
5. **Secrets** : aucun n'est requis pour la CI de base. `GITHUB_TOKEN` suffit à GHCR ; pour
   PyPI, ajouter `PYPI_API_TOKEN` (Trusted Publishing recommandé).
6. **Labels** : lancer le workflow `sync-labels` (fichier `.github/labels.yml`).

---

## 3. Créer la release v0.1.0

Le workflow `.github/workflows/release.yml` se déclenche sur un tag `v*` et produit :

* l'exécution complète des tests (`unittest` + `pytest`) ;
* un **SBOM** (Syft, SPDX + CycloneDX) ;
* la **signature** des artefacts (Sigstore/cosign, keyless via OIDC) ;
* l'image de conteneur poussée vers **GHCR** avec provenance et SBOM attachés ;
* la **GitHub Release** avec les notes extraites de `CHANGELOG.md`.

```bash
# 3.1 Fixer la date dans le CHANGELOG (remplacer la date provisoire si nécessaire)
#     puis committer la mise à jour
git add CHANGELOG.md && git commit -m "docs(changelog): date de la version 0.1.0"

# 3.2 Créer le tag signé (recommandé : tag GPG/SSH signé)
git tag -s v0.1.0 -m "Thot Secure 0.1.0 — MVP défensif"
git push origin v0.1.0

# 3.3 Vérifier la release publiée
gh release view v0.1.0
```

**Après publication, vérifier côté utilisateur** (c'est le point qui compte : l'installateur
refuse une archive non vérifiée) :

```bash
cosign verify-blob --bundle thotsecure-0.1.0.tar.gz.sigstore \
  --certificate-identity-regexp 'https://github.com/thotsecure/thot-secure/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  thotsecure-0.1.0.tar.gz
sha256sum -c thotsecure-0.1.0.tar.gz.sha256
```

---

## 4. Documentation publique (GitHub Pages)

```bash
# Déclencher le workflow docs (mkdocs build --strict + déploiement Pages)
git push origin main           # ou : gh workflow run docs.yml
```

Puis dans *Settings → Pages* : source = **GitHub Actions**. Vérifier ensuite que la page
`/support` en ligne affiche bien les **adresses de dons officielles** et l'avertissement
anti-arnaque (toute divergence entre le site et le dépôt doit être traitée comme un incident :
c'est exactement le scénario d'arnaque que la documentation cherche à éviter).

---

## 5. Publication éditoriale (multi-canaux)

Le kit est livré dans `content/` : article de fond (3 600 mots), article technique, devlog,
posts forums (Reddit, Hacker News, Lobsters, LinuxFr, Journal du Hacker), réseaux (LinkedIn,
Mastodon, Bluesky, X), newsletter, script vidéo, plan de campagne 8 semaines et tableau de
mesure.

**Règles non négociables avant chaque envoi** (détaillées dans `content/CHARTE-EDITORIALE.md`) :

1. Relire le contenu **après** publication du dépôt : tous les liens doivent fonctionner.
2. Vérifier chaque adresse de don **depuis le dépôt officiel** avant publication (jamais de
   copier-coller depuis un brouillon).
3. Respecter les règles du canal : flair obligatoire sur Reddit, autopromotion limitée,
   divulgation « je suis l'auteur », pas de repost multiple le même jour.
4. Adapter le format : Hacker News factuel et concis, Reddit orienté discussion, LinuxFr en
   journal, LinkedIn orienté impact professionnel.
5. **Jamais** de mention de don en accroche : uniquement en fin de contenu, en section sobre.
6. Ne jamais promettre d'avantage, de support prioritaire ou de fonctionnalité en échange d'un
   don.
7. Relever les indicateurs une fois par semaine (`content/campaign/metriques.md`) et ajuster
   l'angle plutôt que d'augmenter la fréquence.

**Ordre recommandé** : dépôt public + release **avant** le premier article. Pousser un article
vers un dépôt vide est le meilleur moyen de perdre la confiance d'un forum technique.

---

## 6. Vérifications de fin de publication

- [ ] `main` protégée, CI verte sur le commit de release.
- [ ] Release `v0.1.0` publiée avec SBOM, signatures et image GHCR.
- [ ] `cosign verify-blob` et `sha256sum -c` réussissent sur un poste vierge.
- [ ] Documentation en ligne : démarrage rapide suivi **de bout en bout** sur une machine
      vierge (pas seulement relu).
- [ ] `LICENSE`, `NOTICE`, `SECURITY.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md` présents et
      à jour ; canal de sécurité privé testé.
- [ ] Adresses de dons identiques **partout** (dépôt, `.github/FUNDING.yml`, site, articles) —
      comparer automatiquement :

  ```bash
  grep -rIo '33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR\|95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi' \
    --include='*.md' --include='*.yml' --include='*.yaml' . | sort | uniq -c
  ```

- [ ] Aucun répertoire `data/`, aucune clé API, aucun secret dans l'historique Git.
- [ ] `scripts/install.sh` testé depuis la release publique (et non depuis le dépôt local).

---

## 7. En cas d'erreur après publication

| Situation | Action |
|---|---|
| Un secret a été poussé | **Révoquer le secret d'abord**, puis purger l'historique (`git filter-repo`), forcer le push, publier un avis dans `SECURITY.md`. Ne jamais se contenter d'un `git rm`. |
| Un tag erroné est publié | Ne pas le supprimer si des utilisateurs ont pu l'installer : publier une version corrective (`v0.1.1`) et documenter l'incident dans le `CHANGELOG`. |
| Une adresse de don erronée a été publiée | Corriger **immédiatement** partout, publier un avertissement dans le README et sur le site, et vérifier l'historique des transactions publiées. |
| Un article contient une affirmation fausse | Correction publique assumée en tête d'article (et non en note de bas de page) : c'est ce qui préserve la crédibilité technique. |

---

**Rappel** : les dons sont **volontaires et sans contrepartie**, et seule la source officielle
(dépôt Git + site du projet) fait foi pour les adresses. Toute page de publication doit le
rappeler sans ambiguïté.
