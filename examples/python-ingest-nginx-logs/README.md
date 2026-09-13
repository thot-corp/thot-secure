# Exemple — Ingestion de journaux Nginx vers Thot Secure

Collecteur Python **autonome** (bibliothèque standard uniquement) qui suit un ou plusieurs
journaux Nginx en continu, normalise chaque ligne en `Event` conforme au contrat d'interface
v0.1.0 (`docs/architecture/api-contract.md` §3.1), masque les secrets, pseudonymise les adresses
IP (obligation RGPD) et ingère le tout par lots vers `POST /api/v1/events` (§4.3).

C'est le collecteur à utiliser lorsque vous ne voulez **rien installer** sur le serveur web :
un seul fichier à copier, aucune dépendance, aucune bibliothèque tierce.

---

## 1. Ce que fait le script

| Étape | Détail |
|---|---|
| **Suivi incrémental** | Lecture depuis l'offset mémorisé dans `--state-file` ; reprise exacte après redémarrage (aucun rejeu, aucune perte). |
| **Rotations** | Détection du changement d'inode (`logrotate`) et de la troncature → relecture depuis le début du nouveau fichier. |
| **Normalisation** | `access.log` → `kind: http.request` (méthode, chemin, requête, statut, octets, agent, référent, hôte virtuel, IP) ; `error.log` → `kind: log.line` avec le niveau mappé (`[error]` → `high`, `[crit]` → `critical`…). |
| **Redaction** | `redact_secrets()` : JWT, `Authorization: Bearer …`, `?token=…`, `api_key=…`, cookies, mots de passe (`[REDACTED]`). |
| **Pseudonymisation** | `pseudonymize_ip()` : chaque IP devient `ip-<32 hex>` (HMAC-SHA256 avec sel). Appliqué **aux champs** (`labels.src_ip`, `remote_addr`…) **et au texte libre** (`payload.message`) : sinon l'IP resterait en clair dans la ligne brute conservée. |
| **Lots de 100** | `--batch-size` (défaut 100, plafond 500 du §4.3). |
| **Contre-pression** | File interne **bornée** (`--queue-size`) entre les lecteurs et l'émetteur ; `429` honoré via `Retry-After` ; repli exponentiel borné sur `5xx` et erreurs réseau. |
| **Récapitulatif** | Lignes lues, lignes non reconnues, événements construits/acceptés/rejetés, lots envoyés, reprises, lots en échec, débit. |
| **Sortie propre** | `Ctrl-C` / `SIGTERM` : arrêt des lecteurs, **vidage des lots en attente**, sauvegarde de l'état, code de sortie `130`. |

### Ligne de journal → événement

```text
shop.acme.fr:443 203.0.113.9 - - [14/Feb/2026:10:00:00 +0100] "GET /catalog?page=2 HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
```

```json
{
  "event_id": "81d59630-2fcc-4046-a359-ee4c27ad9acc",
  "schema_version": "1",
  "tenant_id": "acme",
  "ts": "2026-02-14T09:00:00.000Z",
  "kind": "http.request",
  "source": { "type": "log_tail", "name": "access.log", "host": "shop.acme.fr:443" },
  "severity_hint": "info",
  "labels": {
    "method": "GET", "path": "/catalog", "protocol": "HTTP/1.1",
    "query": "page=2", "host": "shop.acme.fr:443",
    "src_ip": "ip-9298199ec02569dfe27442c5ee2b06e7"
  },
  "payload": { "status": 200, "bytes": 5120, "user_agent": "Mozilla/5.0", "message": "…", "ingest": "python-ingest-nginx-logs/0.1.0" },
  "raw_ref": null
}
```

L'horodatage est converti en UTC (`+0100` → `09:00:00Z`), `labels` reste **plat** et scalaire, et
`payload` est tronqué au-delà de 32 Kio avec `raw_ref` renseigné (§3.1).

---

## 2. Prérequis

* Python 3.9+ (testé sur 3.11). **Aucune dépendance** : ni `httpx`, ni `requests`, ni le SDK.
* Un accès réseau vers l'instance Thot Secure (`THOT_URL`), et une clé API portant la
  capacité `write:events` (rôle `analyst` minimum, contrat §4).

---

## 3. Configuration

Toutes les valeurs se règlent par variable d'environnement (les noms `THOT_SECURE_*` sont
prioritaires, les noms `THOT_*` du contrat §9 restent acceptés) ou par option de ligne de
commande. **Aucun secret n'est écrit dans le script.**

| Variable | Option équivalente | Défaut | Rôle |
|---|---|---|---|
| `THOT_SECURE_URL` / `THOT_URL` | `--url` | `http://127.0.0.1:8080` | Base de l'API. |
| `THOT_SECURE_API_KEY` / `THOT_API_KEY` | `--api-key` | *(vide)* | Clé `ao_…` (en-tête `X-API-Key`). Jamais journalisée. |
| `THOT_SECURE_TENANT_ID` / `THOT_TENANT_ID` | `--tenant-id` | `default` | `tenant_id` porté par les événements (le serveur le force depuis la clé, §4.3). |
| `THOT_SECURE_IP_SALT` / `THOT_IP_SALT` | `--ip-salt` | *(vide)* | Sel de pseudonymisation. **Sans sel, les IP partent en clair** : le script avertit. |

Options principales : `--file` (répétable), `--batch-size`, `--queue-size`, `--flush-interval`,
`--poll-interval`, `--timeout`, `--max-attempts`, `--retry-after-max`, `--state-file`,
`--from-start`, `--once`, `--max-events`, `--dry-run`, `--pretty`, `-v`.

---

## 4. Utilisation (PowerShell)

### 4.1 Vérifier hors ligne, sans serveur ni réseau

```powershell
$env:THOT_SECURE_IP_SALT = "sel-secret-d-organisation"
python ingest_nginx_logs.py --file sample/access.log --file sample/error.log --dry-run --once --pretty
```

`--dry-run` n'émet **aucune requête** et n'écrit **aucun fichier d'état** : les événements
construits sont imprimés sur stdout (JSON indenté par lot avec `--pretty`, un JSON compact par
ligne sinon). Les messages de progression vont sur stderr, ce qui permet de rediriger la sortie :

```powershell
python ingest_nginx_logs.py --file sample/access.log --dry-run --once > evenements.jsonl
```

### 4.2 Collecte réelle en continu

```powershell
$env:THOT_SECURE_URL     = "http://127.0.0.1:8080"
$env:THOT_SECURE_API_KEY = "ao_..."          # jamais dans un fichier du dépôt
$env:THOT_SECURE_IP_SALT = "sel-secret-d-organisation"

python ingest_nginx_logs.py `
    --file C:\nginx\logs\access.log `
    --file C:\nginx\logs\error.log `
    --tenant-id acme `
    -v
```

### 4.3 Tâche planifiée / cron (traiter le contenu existant puis sortir)

```powershell
python ingest_nginx_logs.py --file C:\nginx\logs\access.log --once
```

Les identifiants sont lus par le script dans son environnement : on source donc un fichier
d'environnement en 0600 (`/etc/thotsecure/collector.env` contenant `THOT_SECURE_URL`,
`THOT_SECURE_API_KEY`, `THOT_SECURE_IP_SALT`).

```cron
# /etc/cron.d/thotsecure-nginx — la commande tient sur UNE ligne
*/5 * * * * thotcollector . /etc/thotsecure/collector.env; /usr/bin/python3 /opt/thotsecure/examples/python-ingest-nginx-logs/ingest_nginx_logs.py --file /var/log/nginx/access.log --once
```

### 4.4 Service systemd (Linux)

```ini
[Unit]
Description=Collecteur Nginx vers Thot Secure
After=network-online.target nginx.service

[Service]
EnvironmentFile=/etc/thotsecure/collector.env
ExecStart=/usr/bin/python3 /opt/thotsecure/examples/python-ingest-nginx-logs/ingest_nginx_logs.py \
    --file /var/log/nginx/access.log --file /var/log/nginx/error.log -v
Restart=always
RestartSec=5
User=thotcollector
ReadOnlyPaths=/var/log/nginx

[Install]
WantedBy=multi-user.target
```

---

## 5. RGPD : pourquoi pseudonymiser les IP

Une adresse IP est une **donnée à caractère personnel** (RGPD art. 4.1, CJUE *Breyer*). Ingérer un
`access.log` brut dans un SIEM revient à constituer un fichier de connexions nominatif, soumis à
obligations (durée de conservation, information, droits d'accès).

* `pseudonymize_ip()` produit `ip-<32 hex>` = `HMAC-SHA256(sel, forme canonique de l'IP)`.
* Le pseudonyme est **déterministe** : la corrélation « même source, plusieurs requêtes » reste
  possible, les règles de détection portant sur `labels.src_ip` continuent de fonctionner.
* Le **sel** est un secret d'organisation : sans lui, un attaquant disposant du pseudonyme peut
  tester par dictionnaire l'espace IPv4 (2³² essais, trivial) pour retrouver l'adresse d'origine.
  Conservez-le hors du dépôt (variable d'environnement, coffre-fort, `EnvironmentFile` en 0600).
* L'algorithme est **identique** à celui du SDK Python (`sdks/python/thotsecure_sdk/helpers.py`)
  et du pont n8n : une même IP donne le même pseudonyme quel que soit le chemin d'ingestion.
* La pseudonymisation couvre aussi le **texte libre** : sans cela, l'IP resterait en clair dans
  `payload.message` (ligne brute conservée) et la mesure serait purement cosmétique.

Si vous devez conserver les IP en clair pour une raison légitime, faites-le **explicitement** :
ne définissez pas le sel, et le script vous le signale à chaque démarrage. Documentez la base
légale et la durée de conservation dans votre registre de traitements.

---

## 6. Contre-pression : comment le collecteur ralentit au lieu de casser

```text
access.log ──┐
             ├─► fils lecteurs ──► file BORNÉE (--queue-size) ──► lots de 100 ──► POST /api/v1/events
error.log ───┘                       │                                              │
                                     │  pleine → les lecteurs bloquent              │
                                     └──────────────────────────────────────────────┘
                                           429 → attente Retry-After, puis reprise
```

* La file est **bornée** : la mémoire du collecteur ne dépend pas du retard du serveur.
* Un `429` est **respecté** : le script attend le délai de `Retry-After` (secondes ou date HTTP),
  plafonné par `--retry-after-max`, et réessaie.
* Un lot n'est jamais abandonné en silence : l'échec est journalisé et compte dans le récapitulatif.
* L'offset n'est avancé **qu'après** mise en file de l'événement : au pire un doublon au
  redémarrage, jamais une perte (sémantique « au moins une fois »).

---

## 7. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Collecte terminée sans incident. |
| `1` | Échec réseau ou `5xx` persistant (tentatives épuisées) : lot perdu. |
| `2` | Usage ou configuration : argument invalide, journal introuvable, clé API absente, `401`/`403`. |
| `3` | Le serveur a refusé au moins un événement (`400`/`409`/`422` ou `rejected > 0`). |
| `130` | `Ctrl-C` : arrêt propre après vidage des lots en attente. |

---

## 8. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `HTTP 401/403` | Clé absente, révoquée, ou rôle sans `write:events` | Créer une clé `analyst`+ : `thotsecure key create --tenant acme --role analyst --label nginx`. |
| Les événements repartent du début | `--state-file` non inscriptible (le message le signale) | Corriger les droits, ou fixer `--state-file` sur un chemin persistant. |
| Aucun événement après rotation | Le suivi est en cours et le nouveau fichier est vide | Comportement normal : la reprise se fait dès la première ligne écrite. |
| Les IP n'apparaissent pas pseudonymisées | `THOT_SECURE_IP_SALT` non défini | Définir le sel (avertissement affiché au démarrage). |
| `payload.message` tronqué | Ligne > 32 Kio (§3.1) | Normal : `raw_ref` indique la troncature. |

---

## 9. Portée et sûreté

Le script **ne fait que lire un fichier local et émettre vers Thot Secure**. Il n'ouvre aucune
connexion vers les adresses IP observées : ni scan, ni test d'authentification, ni exploitation.
Aucune capacité offensive n'est introduite — invariant du projet (§10 du contrat).

Soutien
-------

Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

* Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
* Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
