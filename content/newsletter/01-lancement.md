```yaml
canal: "Newsletter projet + annonce GitHub Discussions"
langue: fr
format: "email d'annonce, également publiable comme post GitHub Discussions (même corps)"
objectif: "annoncer Thot Secure v0.1.0, faire essayer localement en 5 minutes, recruter des contributeurs sur trois chantiers précis"
mot_cle_principal: "SOAR défensif open source"
longueur: "corps de 682 mots (cible 400-700, hors bloc de métadonnées, commandes incluses)"
heure_optimale_publication: "mardi 09 h 00 heure de Paris pour l'email ; le post GitHub Discussions peut partir 30 minutes avant, pour que le lien soit déjà en ligne quand l'email arrive"
regles_specifiques_du_canal:
  - "objet court, factuel, sans emoji et sans majuscules : « Thot Secure v0.1.0 — SOAR défensif, dry-run par défaut »"
  - "préheader qui complète l'objet, il ne le répète pas"
  - "un seul appel à l'action principal (essayer localement) ; la contribution vient après"
  - "commandes réelles uniquement, copiables telles quelles ; ne jamais inventer un drapeau CLI"
  - "tout ce qui n'est pas livré est étiqueté « roadmap » dans le texte"
  - "aucun chiffre d'impact présenté comme mesuré : le projet n'a pas de benchmark à publier"
  - "section soutien en toute fin, jamais en accroche, jamais répétée dans le corps"
dons: "ce fichier est le SEUL des six à porter les adresses de don (choix éditorial : X, Bluesky, Mastodon, LinkedIn et Reddit n'en portent aucune). Elles sont en toute fin de contenu, avec l'avertissement complet, et elles sont recopiées caractère par caractère depuis §12 du contrat d'interface."
autopromotion: "contenu technique d'abord ; un seul lien vers le dépôt dans le corps ; la section soutien est sobre, sans urgence artificielle et sans contrepartie promise."
```

# Objet de l'email

**Objet principal :** Thot Secure v0.1.0 — SOAR défensif, dry-run par défaut

**Variante A (angle réversibilité) :** Thot Secure v0.1.0 : automatiser la réponse sans perdre la possibilité d'annuler

**Variante B (angle contribution) :** Thot Secure v0.1.0 est publié — et trois chantiers cherchent des mains

**Préheader :** Contre-mesures réversibles, décisions en YAML et audit chaîné par hash. Apache-2.0, à essayer en local en 5 minutes.

---

<!--body:start-->
## Le problème

Un finding de sévérité haute tombe à 3 h du matin. La question n'est pas « quelle alerte ? » mais : qui peut agir, sur quelle base, et comment annuler.

La plupart des outils de réponse automatisée répondent à la première et laissent les deux autres à une procédure interne non versionnée. Thot Secure v0.1.0 inverse l'ordre : action réversible, décision en code versionné, preuve dans un journal chaîné par hash.

## Ce qui est livré dans v0.1.0

- **API REST** `/api/v1` (FastAPI), WebSocket `/api/v1/ws/stream`, métriques Prometheus, OpenAPI 3.1.
- **Console embarquée** (Jinja2 + JS, aucun build Node) : flux live, findings, actions, audit, règles — et un **tableau de bord React optionnel** (`web/`), dont le job CI est bloquant.
- **CLI `thotsecure`**, `--json` partout, codes de sortie `0` succès, `1` erreur, `2` usage, `3` vérification négative.
- **Quatre garanties** : dry-run par défaut (`THOT_DRY_RUN=true`), rollback obligatoire sur chaque playbook, audit append-only chaîné par hash, isolation multi-tenant testée en CI.
- **Détection** : **26 règles** YAML livrées (dont 5 pour les anomalies), seuils d'agrégation, compatibilité Sigma sur un sous-ensemble documenté ; une règle invalide est rejetée sans casser le moteur. Un détecteur statistique (EWMA + z-score) analyse une entité à la fois et reste **désactivé par défaut** (`THOT_ANOMALY_ENABLED=false`).
- **Décision** : **9 politiques** YAML versionnées, garde-fous non contournables (plafond horaire, cooldown par cible, cibles protégées, `dry_run` global prioritaire), `notify_only` par défaut.
- **Playbooks livrés** : **15 playbooks**, dont `block-source-ip` et `unblock-source-ip`, `rate-limit-source` et `remove-rate-limit`, `quarantine-artifact` et `restore-artifact`, `revoke-session`, `rotate-secret`, `isolate-host` et `unisolate-host`, `patch-dependency` (ouvre une PR, jamais de merge auto), `harden-endpoint`, `notify`, `open-ticket`, `close-ticket`.
- **Rapports** `md|html|json|sarif` (SARIF 2.1.0) et export d'audit `jsonl|cef` vers votre SIEM.
- **Connecteurs non configurés** ⇒ mode simulé : `rollback_token` retourné, `simulated: true` journalisé — branchable avant d'avoir la moindre credential.

## Essayer en 5 minutes, sans credential

```console
python -m venv .venv
python -m pip install -e ".[dev]"
thotsecure init-db
thotsecure tenant create --id acme --name "ACME SAS" --mode supervised
thotsecure demo --tenant demo
thotsecure doctor
thotsecure findings list --tenant acme --severity high --min-risk 70
thotsecure audit verify
```

`thotsecure demo --tenant demo` remplit un jeu de données local et produit findings et actions. `thotsecure audit verify` renvoie `{"valid": true, "records": …, "broken_at": null}` et sort en code `0` ; chaîne corrompue, il sort en `3`. Le tenant `acme` reste vide jusqu'à :

```console
thotsecure ingest --tenant acme --file events.jsonl
```

Console : `thotsecure serve`, puis `http://127.0.0.1:8080`. Tests, sans réseau ni service externe : `python -m unittest discover -s tests -t . -v` (**396 tests**, 70 ignorés sans serveur PostgreSQL).

## Comment contribuer

DCO, sans CLA : vous gardez le copyright, un `Signed-off-by` par commit (`git commit -s`) suffit. Commits en Conventional Commits, branches `feat/*`, `fix/*`, `rule/*`, `docs/*`. Aucune capacité offensive. Les `good first issue` sont calibrées à une journée de travail, avec critères d'acceptation, fichiers à toucher et relecteur nommé. Trois chantiers :

1. **Ajouter une règle de détection YAML avec ses faux positifs documentés.** Un test qui doit matcher, un cas ressemblant qui ne doit pas matcher, la liste `false_positives:` remplie. Validation : `thotsecure rules validate --path rules`.
2. **Écrire un connecteur de playbook avec son rollback.** Sans rollback, le playbook est refusé ; non configuré, il doit fonctionner en mode simulé et journaliser `simulated: true`.
3. **Traduire la documentation ou la console.** Sources dans `docs/` et `src/thotsecure/ui/templates/` ; la console fonctionne sans build Node et doit le rester.

## Livré mais non éprouvé, et roadmap

Ce qui suit est soit **livré mais explicitement non validé**, soit **roadmap** (non livré en v0.1.0, aucune date promise). La distinction est faite ligne par ligne.

- **Livré, non éprouvé — PostgreSQL / TimescaleDB** : l'adaptateur est écrit et exécuté en CI contre un vrai serveur TimescaleDB, avec la même suite de conformité que SQLite ; SQLite reste le défaut. Il n'a pas été éprouvé à l'échelle de production.
- **Livré, non validé contre un compte réel — connecteurs natifs** : Cloudflare, AWS WAF v2, Slack et GitHub Issues sont écrits, et **aucun n'a été validé contre un compte réel** — c'est l'étape obligatoire avant de les activer. ModSecurity et le reste passent par la passerelle `http-webhook` signée.
- **Roadmap — davantage de collecteurs**, limités aux cibles déclarées.
- **Roadmap — mode Rego / OPA** durci (`THOT_OPA_BIN`).
- **Roadmap — SDK TypeScript et Go** : le SDK Python est livré.

## Soutien

Thot Secure est maintenu par des bénévoles. Les dons sont volontaires et sans contrepartie : ils n'achètent ni merge, ni fonctionnalité, ni priorité, ni support garanti.

- **Bitcoin (BTC, réseau Bitcoin mainnet)** : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
- **Solana (SOL, réseau Solana mainnet)** : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`

Dons volontaires, **aucune contrepartie** : un don ne donne droit à rien — ni support, ni fonctionnalité, ni priorité. Vérifiez toujours l'adresse depuis le dépôt officiel : ce sont les seules adresses officielles, et toute autre adresse est une arnaque.

Seule la source officielle — dépôt Git + site du projet — fait foi ; le projet ne demande jamais de clé privée ni de phrase de récupération.

La contribution la plus utile reste une règle de détection avec son test négatif.

Le dépôt : https://github.com/thot-corp/thot-secure
<!--body:end-->
