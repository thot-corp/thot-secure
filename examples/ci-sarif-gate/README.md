# Exemple — Portail CI SARIF (findings → SARIF 2.1.0 → échec du pipeline)

Transforme l'état de sécurité du tenant en **artefact exploitable** (SARIF 2.1.0, format natif de
GitHub Code Scanning) et en **code de sortie** que l'intégration continue sait interpréter :

```text
GET /api/v1/findings?status=open        →  findings ouverts (pagination par cursor)
GET /api/v1/findings/{id}/report?format=sarif  →  SARIF serveur (facultatif, repli local)
                    ↓
        thotsecure.sarif  (SARIF 2.1.0 agrégé : 1 run, règles dédupliquées)
                    ↓
   exit 0  portail franchi        exit 3  finding bloquant non acquitté
```

Le portail échoue si un finding **critique non acquitté** existe. Un finding `acked`, `closed` ou
`suppressed` **ne bloque jamais** : quelqu'un l'a examiné et en a assumé la suite — il apparaît en
`suppressions` dans le SARIF.

---

## 1. Fichiers de cet exemple

| Fichier | Rôle |
|---|---|
| `sarif_gate.py` | Le portail : lecture des findings, agrégation SARIF, verdict, annotations. |
| `.github-workflow-example.yml` | Workflow GitHub Actions complet (à renommer `.github/workflows/thotsecure-sarif.yml`). |
| `sample/findings.jsonl` | Jeu de findings de démonstration (dont un critique acquitté) pour tester **hors ligne**. |

---

## 2. Mode hors ligne (aucune instance requise)

```powershell
python sarif_gate.py --from-file sample/findings.jsonl --sarif-source local `
    --out demo.sarif --warn-only --github-annotations
```

Sortie :

```text
==============================================================================
PORTAIL CI — FINDINGS THOT SECURE
==============================================================================
  Findings examinés : 3
    critical : 2
    high     : 1
  SARIF agrégé      : demo.sarif
  Sévérités bloquantes : critical

  ✖ 1 finding(s) bloquant(s) non acquitté(s) :
    - [critical] risque 92.4 · AO-WEB-001 · Injection SQL active depuis 203.0.113.77 sur /product
      finding_id : f1c2aabb-1111-4000-8000-000000000001
      régularisation : thotsecure findings show f1c2aabb-1111-4000-8000-000000000001  (puis ack/close, ou correction)
::warning title=Thot Secure critical (risque 92.4)::Injection SQL active … — règle AO-WEB-001 — finding_id f1c2aabb-…
```

Sans `--warn-only`, la même commande sort en **3** (portail échoué). Le finding critique *acquitté*
du jeu de test n'apparaît pas dans la liste bloquante : c'est le comportement voulu.

---

## 3. Utilisation en production

```powershell
$env:THOT_SECURE_URL     = "https://thotsecure.interne"
$env:THOT_SECURE_API_KEY = "ao_..."     # capacité read:findings (rôle viewer suffit)

python sarif_gate.py `
    --out thotsecure.sarif `
    --fail-on critical `
    --github-annotations --step-summary -v
```

| Option | Défaut | Rôle |
|---|---|---|
| `--url` / `--api-key` | `$env:THOT_SECURE_*` puis `$env:THOT_*` | Instance et clé (`read:findings` suffit). |
| `--from-file` | — | Findings depuis un JSON/JSONL (mode hors ligne). |
| `--status` | `open` | Statut interrogé. |
| `--include-acked` | `false` | Ajoute les acquittés (en `suppressions` du SARIF, jamais bloquants). |
| `--min-risk` | — | Seuil de risque transmis à l'API (§4.4). |
| `--fail-on` | `critical` | Sévérités bloquantes : `critical`, `critical,high`, `any`… |
| `--warn-only` | `false` | N'échoue jamais (mode recommandé la première semaine). |
| `--sarif-source` | `auto` | `auto` (serveur puis repli local), `server`, `local`. |
| `--out` / `--no-sarif` | `thotsecure.sarif` | Fichier SARIF agrégé. |
| `--artifact-uri-template` | `thotsecure://finding/{finding_id}` | Gabarit d'URI des localisations. |
| `--github-annotations` | `false` | Annotations `::error::`/`::warning::` sur la page du workflow. |
| `--step-summary` | `false` | Résumé Markdown dans `$GITHUB_STEP_SUMMARY`. |

---

## 4. Adopter le portail sans casser l'équipe

Un portail bloquant activé du jour au lendemain sur un dépôt déjà rouge **finit désactivé** — et un
portail désactivé ne protège rien. La séquence qui fonctionne :

| Étape | `sarif_gate.py` | `continue-on-error` | Effet |
|---|---|---|---|
| **Semaine 1** | `--warn-only` | `true` | Le SARIF est publié, l'équipe voit les alertes dans *Security*. Rien n'est bloqué. |
| **Semaine 2-3** | _(retiré)_ | `true` | Le job devient rouge, visible, mais la fusion reste possible : l'équipe se met au travail. |
| **Ensuite** | _(retiré)_ | `false` | Un finding critique non acquitté bloque la fusion. C'est le but. |

Pendant ce temps, l'équipe **régularise** : correction à la source, `thotsecure findings ack` (constat
assumé, surveillé) ou `close` (traité). Un `ack` n'est pas un effacement : il reste dans l'audit.

---

## 5. La question du « SARIF serveur » ou « local »

* `GET /api/v1/findings/{id}/report?format=sarif` (§4.8) renvoie un SARIF **par finding**. Un
  pipeline préfère **un seul** fichier : ce script agrège donc les `runs` renvoyés en un `run`
  unique, avec des règles dédupliquées par `rule_id`.
* Si l'instance ne produit pas de SARIF (`404`/`405`/`501`), le script **bascule automatiquement**
  sur la conversion locale (à partir des seuls champs de `Finding`, §3.2) : le portail reste
  fiable, aucun finding n'est perdu. `--sarif-source local` force ce mode (aucun appel de rapport).
* Les identifiants de règle du SARIF agrégé sont **toujours** ceux du contrat (`rule_id`) : un
  serveur qui annoncerait un identifiant différent produirait sinon des règles homonymes — ce que
  la spécification SARIF interdit et que GitHub rejette à l'import.

### Localisation des résultats

Un finding n'est pas un fichier du dépôt : la localisation vaut par défaut
`thotsecure://finding/<finding_id>`, ce que GitHub classe en *« other location »*. Pour rattacher
les constats à de vrais fichiers (Terraform, Kubernetes, code applicatif), utilisez le gabarit :

```powershell
python sarif_gate.py --artifact-uri-template "infra/{rule_id}.tf"
```

Variables disponibles : `{finding_id}`, `{rule_id}`, `{severity}`, `{tenant_id}`.

---

## 6. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Portail franchi — ou findings bloquants signalés sous `--warn-only`. |
| `1` | Erreur d'exécution : réseau, `5xx`, SARIF non productible en mode `server`. |
| `2` | Usage ou configuration : argument invalide, clé API absente, `401`/`403`. |
| `3` | **Portail échoué** : au moins un finding de sévérité bloquante non acquitté. |

`3` est le code « vérification négative » du contrat (§8), celui que la CI doit interpréter comme un
échec de contrôle — distinct d'une erreur technique (`1`), qui doit alerter la plateforme et non
l'équipe applicative.

---

## 7. Intégration GitHub Actions

Voir `.github-workflow-example.yml`, à copier en `.github/workflows/thotsecure-sarif.yml`. Points
importants :

* `permissions: security-events: write` est **obligatoire** pour `upload-sarif` (sinon l'envoi
  échoue avec « Resource not accessible by integration ») ;
* `continue-on-error: true` la première semaine, avec `--warn-only` ;
* `if: always()` sur l'upload : on veut le SARIF **même** si le portail échoue ;
* `github/codeql-action/upload-sarif@v3` avec `category: thotsecure` pour cohabiter avec d'autres
  analyseurs ;
* le jeton d'API Thot Secure est un **secret de dépôt** (`secrets.THOT_SECURE_API_KEY`), jamais une
  variable en clair.

---

## 8. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `exit 3` inattendu | Finding critique non acquitté | `thotsecure findings show <id>`, puis correction, `ack` ou `close`. |
| Aucun SARIF dans l'onglet *Security* | `permissions` manquantes ou `upload-sarif` sans `if: always()` | Corriger le workflow, relancer. |
| `::error::` affiché mais job vert | `--warn-only` encore actif | Retirer l'option quand les findings sont traités. |
| `HTTP 401/403` | Clé absente/révoquée, ou rôle sans `read:findings` | `thotsecure key create --tenant acme --role viewer --label ci`. |
| Règles homonymes dans le SARIF | Serveur renvoyant des `rule_id` incohérents | Mettre à jour l'instance : l'agrégation impose désormais le `rule_id` du finding. |
| Import SARIF refusé par GitHub | Schéma invalide | Vérifier `version: 2.1.0`, `$schema`, et l'unicité des `rules[].id`. |

---

## 9. Sûreté

Le script est **en lecture seule** : il lit des findings et des rapports, écrit un fichier SARIF
local, et n'effectue aucune action de remédiation. Il n'introduit aucune capacité offensive et
n'appelle que l'URL configurée. La clé API n'est jamais journalisée ni incluse dans un artefact.

Soutien
-------

Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

* Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
* Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
