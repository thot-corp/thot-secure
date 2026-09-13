# Exemple — Contre-mesure assistée (findings → plan → approbation → exécution → rollback)

Déroule **le chemin d'action complet** du SOAR Thot Secure, en gardant l'humain dans la boucle :

```text
GET /version            →  état de sûreté affiché (dry_run, mode d'autonomie, rôle)
GET /api/v1/findings    →  findings ouverts à risk_score ≥ 70
POST /actions/plan      →  plan complet affiché (aucun effet de bord)
        ⏸               →  CONFIRMATION HUMAINE EXPLICITE (mot « OUI », ou --yes)
POST /actions/{id}/approve
POST /actions/{id}/execute
POST /actions/{id}/rollback   →  proposé systématiquement
```

Ce n'est pas un script de « remédiation automatique » : c'est un **script d'approbation
instrumenté**, destiné à être lu et compris avant d'être lancé — y compris à 3 h du matin pendant
un incident.

---

## 1. Prérequis

* Python 3.9+ (testé 3.11).
* Une clé API portant `read:findings` + `execute:actions` + `approve:actions` → rôle `responder`
  minimum (contrat §4) :

  ```powershell
  thotsecure key create --tenant acme --role responder --label mitigation
  ```

* Le SDK Python officiel est utilisé **s'il est importable** (`sdks/python/thotsecure_sdk`) ; sinon
  le script bascule automatiquement sur un client embarqué (`urllib`, bibliothèque standard). Le
  client effectivement employé est affiché en tête d'exécution. `--no-sdk` force le client
  embarqué.

---

## 2. Configuration

| Variable | Option | Défaut | Rôle |
|---|---|---|---|
| `THOT_SECURE_URL` / `THOT_URL` | `--url` | `http://127.0.0.1:8080` | Base de l'API. |
| `THOT_SECURE_API_KEY` / `THOT_API_KEY` | `--api-key` | *(vide)* | Clé `ao_…`. Obligatoire. Jamais journalisée. |
| `THOT_SECURE_TENANT_ID` / `THOT_TENANT_ID` | `--tenant-id` | *(dérivé de la clé)* | Tenant ciblé. |
| `THOT_SECURE_SDK_PATH` / `THOT_SDK_PATH` | — | *(auto-détecté)* | Chemin de `sdks/python` si le SDK est ailleurs. |
| `THOT_SECURE_TIMEOUT` / `THOT_TIMEOUT` | `--timeout` | `15` | Délai par requête (s). |

Options principales : `--min-risk`, `--status`, `--limit`, `--finding-id`, `--index`, `--playbook`,
`--target`, `--duration-seconds`, `--reason`, `--comment`, `--live`, `--yes`, `--rollback`,
`--no-rollback`, `--rollback-reason`, `--rollback-action`, `--force-irreversible`, `--no-sdk`, `-v`.

---

## 3. Utilisation

### 3.1 Répétition à blanc (recommandée en premier)

```powershell
$env:THOT_SECURE_URL     = "http://127.0.0.1:8080"
$env:THOT_SECURE_API_KEY = "ao_..."

# Plan en simulation : rien ne peut être appliqué, quoi qu'il arrive
python auto_mitigation.py --min-risk 70
```

Sans `--live`, le script demande un plan `dry_run: true` : tout l'enchaînement (approbation,
exécution, rollback) est parcouru, mais **aucun connecteur n'est appelé**. C'est la façon de
vérifier une politique, un playbook et un runbook sans risque.

### 3.2 Contre-mesure réelle, avec confirmation interactive

```powershell
python auto_mitigation.py --min-risk 70 --live
```

Le script affiche le **plan JSON intégral**, puis demande de taper exactement `OUI`. Toute autre
réponse annule (`exit 3`). En fin d'exécution, il propose le rollback `[o/N]`.

### 3.3 Pipeline non interactif (CI, cron, runbook automatisé)

```powershell
python auto_mitigation.py --finding-id f1c2aabb --playbook block-source-ip --live --yes --rollback
```

`--yes` **est obligatoire** dès que l'entrée standard n'est pas un terminal : sans lui, le script
**refuse** (`exit 3`). Aucune contre-mesure ne peut être approuvée par accident parce que personne
ne regardait l'écran.

### 3.4 Annuler une action existante (runbook d'incident)

```powershell
python auto_mitigation.py --rollback-action a91b0000 --yes
```

Affiche l'action, vérifie que le rollback est disponible, et l'annule. Utile pour « annuler
d'abord, analyser ensuite ».

---

## 4. Le mode `auto` : une décision consciente, journalisée et réversible

Le mode `auto` (`mode: auto` sur le tenant, §4.2) autorise le moteur de décision à exécuter un
playbook **sans approbation humaine**. Ce script ne l'active jamais, ne le contourne jamais : il
l'**affiche**. Si l'état de sûreté annonce `auto`, l'opérateur voit :

```text
  Mode d'autonomie    : auto
    ⚠ mode « auto » : le moteur de décision peut exécuter des contre-mesures SANS
      approbation humaine. Ce script n'en déclenche aucune de lui-même — vérifiez que
      ce mode est bien une décision consciente, limitée, journalisée et réversible.
```

Activer `auto` n'est pas un réglage technique anodin. Quatre conditions, non négociables :

1. **Conscient** — décision d'une personne nommée, tracée (changement, ADR, ticket), avec une date
   de revue. Personne ne doit découvrir après coup que son infrastructure bloque des adresses
   toute seule, ni se retrouver à bloquer un partenaire ou un client.
2. **Limité** — un périmètre étroit : quelques playbooks, une sévérité haute, un environnement.
   Les garde-fous §6 restent appliqués par le moteur et **ne sont pas contournables** par une
   politique : plafond `max_actions_per_hour`, `cooldown` par `(tenant, playbook, cible)`, cibles
   de l'`autonomy_allowlist` (votre propre infrastructure) jamais modifiables, `dry_run` global
   prioritaire.
3. **Journalisé** — chaque décision porte `policy_id`, chaque action un `audit_seq`, et
   `GET /api/v1/audit/verify` doit rester `valid: true`. Une chaîne d'audit rompue est un incident
   majeur, pas un détail.
4. **Réversible** — le playbook doit être `reversible: true` et le rollback exécutable dans la
   fenêtre annoncée (`expires_at`). Un playbook non réversible exige `--force-irreversible` : le
   script s'arrête sinon.

Le mode `supervised` reste le défaut recommandé — c'est celui que ce script implémente.

---

## 5. `dry_run` : ne jamais laisser croire qu'une action a eu lieu

Si `DRY_RUN=true` (défaut du projet), l'API **simule** : elle renvoie une `Action` avec
`dry_run: true` et `result.simulated: true`. Rien n'est appliqué, aucun connecteur n'est appelé.

Le script le dit **trois fois** : à l'affichage de l'état de sûreté, au moment du plan, puis à la
place du message de succès :

```text
==============================================================================
⚠ SIMULATION — AUCUNE ACTION RÉELLE N'A ÉTÉ EXÉCUTÉE
==============================================================================
  L'instance est en dry_run (garde-fou §6, prioritaire sur toute politique) :
  le playbook a été parcouru sans effet de bord et aucun connecteur n'a été appelé.
  Ne considérez donc PAS la cible comme bloquée. Pour une contre-mesure réelle :
    - lever DRY_RUN au niveau du tenant (THOT_DRY_RUN=false, décision tracée),
    - puis relancer ce script avec --live.
```

Corollaire : un opérateur en astreinte qui lit « succeeded » sans lire le bandeau croira à un
blocage effectif. C'est pour cette raison que le message de succès est **remplacé**, pas complété.

---

## 6. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Déroulé terminé : plan seul, exécution, ou exécution + rollback. |
| `1` | Erreur d'exécution : réseau, `5xx`, réponse inexploitable. |
| `2` | Usage ou configuration : argument invalide, clé absente, `401`/`403`, aucun finding à traiter. |
| `3` | Refus de l'opérateur (confirmation déclinée) — l'action reste `planned`/`pending_approval` et expire d'elle-même. |
| `130` | `Ctrl-C` : interruption propre, aucune action supplémentaire déclenchée. |

---

## 7. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `HTTP 403 · forbidden` | Capacité manquante | Clé `responder`+ (`approve:actions`, `execute:actions`). |
| `HTTP 409` sur `plan` | `cooldown`, plafond horaire, ou cible protégée | Vérifier les garde-fous §6 ; une cible de l'`autonomy_allowlist` ne sera **jamais** modifiée. |
| `HTTP 409` sur `execute` | Action non approuvée, déjà exécutée, ou rollback déjà fait | Relire le statut via `GET /api/v1/actions/{id}`. |
| Aucun finding listé | Seuil trop haut ou détection silencieuse | Baisser `--min-risk`, ou vérifier `GET /api/v1/events` (§4.3). |
| « statut inattendu avant exécution » | Le plan n'est ni `planned`, ni `pending_approval`, ni `approved` | Inspecter `GET /api/v1/actions/{id}` ; ne pas insister. |
| Le rollback proposé n'apparaît pas | `rollback.available: false` | Action définitive : à noter au compte rendu d'incident. |

---

## 8. Pseudonymisation des IP et cible d'action : une tension à connaître

Si les événements sont ingérés avec pseudonymisation (`examples/python-ingest-nginx-logs`), alors
`labels.src_ip` vaut `ip-<32 hex>` : **le finding ne contient plus l'adresse en clair**, et bloquer
ce pseudonyme n'a aucun sens pour un pare-feu.

Deux approches, à choisir **explicitement** :

* le connecteur d'action résout le pseudonyme (table de correspondance conservée côté tenant,
  sous contrôle d'accès) avant d'appeler le WAF — c'est la seule voie conforme au RGPD qui
  préserve la capacité de blocage ;
* ou l'ingestion conserve les IP nécessaires à la mitigation, avec base légale et durée de
  conservation documentées.

Dans tous les cas, cible affichée = cible bloquée : le script montre la cible **telle qu'elle sera
transmise au connecteur**, et `--target` permet de la forcer en connaissance de cause.

---

## 9. Sûreté

* Aucune capacité offensive : le script ne fait que lire des findings et demander des actions
  **défensives et réversibles** sur des cibles du périmètre déclaré du tenant. Aucun scan, aucune
  force brute, aucune exploitation.
* La clé API n'est jamais journalisée, jamais affichée, jamais passée en paramètre d'URL.
* Toute interruption (`Ctrl-C`) laisse une action `planned` qui expire d'elle-même : jamais de
  contre-mesure orpheline.

Soutien
-------

Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

* Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
* Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
