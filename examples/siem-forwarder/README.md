# Exemple — Forward d'audit et de findings vers un SIEM (CEF / JSONL)

Pont **sortant** de Thot Secure : exporte le journal d'audit chaîné et les findings vers un SIEM
(Splunk, QRadar, Elastic, Sentinel…) sous forme de **fichiers tournants** que les agents habituels
savent déjà lire. Aucun connecteur exotique, aucun agent propriétaire à écrire.

```text
GET /api/v1/audit/verify          ← vérification périodique de la chaîne (hash chaîné §3.5)
GET /api/v1/audit/export?format=cef|jsonl&since=…&until=…   ← flux recopié tel quel
GET /api/v1/findings?since=…      ← findings convertis localement en CEF
                    ↓
   audit.cef / audit.jsonl / findings.cef / findings.jsonl   (rotation par taille)
                    ↓
   curseur persisté (state.json) — avancé seulement après écriture réussie
```

---

## 1. Pourquoi ce script existe

Un SIEM qui ingère un audit **non vérifié** ingère une affirmation non prouvée : quiconque a accès à
la base pourrait supprimer la trace d'une action, et le SIEM la relayerait comme un fait. La chaîne
de hachage du contrat (§3.5) rend la falsification détectable ; ce forwarder en fait un **contrôle
opérationnel** :

* vérification **périodique** de `GET /api/v1/audit/verify` ;
* si `valid: false` → **incident majeur** : journalisation `CRITICAL`, écriture d'un marqueur
  `AUDIT_CHAIN_BROKEN.incident.json` (collectable par le SIEM), et **arrêt de la transmission** ;
* redémarrage possible seulement après décision explicite (`--continue-on-chain-break`, déconseillé).

Continuer à transmettre des enregistrements dont la continuité est rompue reviendrait à blanchir
des données non attestables.

---

## 2. Configuration

| Variable | Option | Défaut | Rôle |
|---|---|---|---|
| `THOT_SECURE_URL` / `THOT_URL` | `--url` | `http://127.0.0.1:8080` | Instance source. |
| `THOT_SECURE_API_KEY` / `THOT_API_KEY` | `--api-key` | *(vide)* | Clé `ao_…` portant `read:audit` **et** `read:findings` (rôle `viewer` minimum). |
| `THOT_SECURE_TIMEOUT` / `THOT_TIMEOUT` | `--timeout` | `30` | Délai par requête (s). |

| Option | Défaut | Rôle |
|---|---|---|
| `--out-dir` | `.` | Dossier des fichiers destinés au SIEM. |
| `--format` | `cef` | `cef`, `jsonl` ou `both` (les deux fichiers). |
| `--sources` | `audit,findings` | Sources transférées. |
| `--since` | — | Curseur initial ISO 8601 si aucun état n'existe. |
| `--until` | — | Borne de fin fixe (rattrapage borné, avec `--once`). |
| `--overlap-seconds` | `5` | Recouvrement demandé avant le curseur (dérive d'horloge). |
| `--interval` | `60` | Période entre deux cycles. |
| `--verify-interval` | `300` | Période de vérification de la chaîne d'audit (`0` = à chaque cycle). |
| `--max-bytes` / `--backups` | `67108864` / `5` | Rotation : seuil et nombre de fichiers conservés. |
| `--state-file` / `--no-state` | `siem-forwarder-state.json` | Persistance des curseurs. |
| `--from-start` | `false` | Ignore l'état existant. |
| `--dedupe-size` | `20000` | Taille de la mémoire de déduplication. |
| `--once` | `false` | Un seul cycle puis sortie (cron, test). |
| `--continue-on-chain-break` | `false` | Poursuite malgré une chaîne rompue (**déconseillé**). |

---

## 3. Utilisation

```powershell
$env:THOT_SECURE_URL     = "https://thotsecure.interne"
$env:THOT_SECURE_API_KEY = "ao_..."          # read:audit + read:findings

# Un cycle, les deux formats, dans un dossier dédié au spool du SIEM
python forward_cef.py --once --format both --out-dir C:\siem\spool\thotsecure -v
```

Service continu (PowerShell, tâche planifiée, conteneur) :

```powershell
python forward_cef.py --interval 60 --verify-interval 300 --format cef --out-dir C:\siem\spool
```

Rattrapage historique borné :

```powershell
python forward_cef.py --once --from-start `
    --since 2026-02-01T00:00:00Z --until 2026-02-14T00:00:00Z --out-dir .\rattrapage
```

Unité systemd :

```ini
[Unit]
Description=Thot Secure — forward SIEM (audit + findings)
After=network-online.target

[Service]
EnvironmentFile=/etc/thotsecure/forwarder.env
ExecStart=/usr/bin/python3 /opt/thotsecure/examples/siem-forwarder/forward_cef.py \
    --out-dir /var/spool/thotsecure --format cef --interval 60
Restart=always
RestartSec=10
User=thotforward
# La chaîne rompue provoque une sortie 3 : `Restart=on-failure` redémarrerait en boucle.
# Utilisez `Restart=always` uniquement si vous acceptez cette boucle, ou surveillez le code 3.
ReadWritePaths=/var/spool/thotsecure

[Install]
WantedBy=multi-user.target
```

---

## 4. Reprise sur erreur : le curseur, contrat de non-perte

```text
cycle N   : since = curseur − overlap   until = maintenant
            export → écriture (flush + fsync) → ALORS SEULEMENT curseur = until
cycle N+1 : reprend au curseur confirmé
```

* **Coupure réseau, disque plein, redémarrage, Ctrl-C** : le curseur n'a pas bougé → le cycle
  suivant rejoue la même fenêtre. Le SIEM ne perd rien.
* **Recouvrement** (`--overlap-seconds`) : la fenêtre demandée recule un peu avant le curseur, pour
  absorber une dérive d'horloge entre le serveur (qui horodate) et le forwarder (qui fixe `until`).
  Un SIEM préfère **un doublon à un trou**.
* **Déduplication** : les enregistrements déjà transmis sont écartés en mémoire (clé `seq`+`hash`
  en JSONL, `externalId` en CEF, `finding_id`+`updated_at` pour les findings). La mémoire est
  **locale au processus** : après un redémarrage, la fenêtre de recouvrement peut être réémise —
  c'est borné par `--overlap-seconds`. Côté SIEM, dédupliquez sur `externalId` (ou `cn1`/`seq`).
* **Écriture atomique de l'état** : fichier temporaire + `os.replace`, jamais d'état à moitié écrit.

---

## 5. Le format CEF, et pourquoi il n'est pas réécrit

L'export serveur (`format=cef`) est recopié **octet pour octet** : le réécrire ferait perdre la
garantie de conformité de l'émetteur. Le forwarder se contente de filtrer les lignes déjà
transmises (lecture de `externalId`), sans toucher au reste.

Les **findings**, eux, ne disposent pas d'export CEF dans le contrat (§4.7 n'en fournit que pour
l'audit) : ils sont donc convertis localement, avec :

| Élément CEF | Source (§3.2) |
|---|---|
| `signature_id` | `rule_id` |
| `name` | `rule_name` puis `title` |
| `severity` (0-10) | `critical` 10, `high` 8, `medium` 5, `low` 2, `info` 0 (plafonné à 2 si `acked`/`closed`) |
| `externalId` | `finding_id` |
| `src` / `requestUrl` / `suser` | `labels.src_ip` / `labels.path` / `labels.user` |
| `cn1` | `risk_score` (`cn1Label=riskScore`) |
| `cs4` / `cs5` | `tags` / MITRE |
| `cs6` / `cs7` | `description` / `remediation` |

L'échappement CEF est appliqué correctement : `\` et `|` dans l'en-tête, `\`, `=` et sauts de ligne
dans les extensions. Un `=` non échappé couperait la valeur et ferait dériver l'analyse côté SIEM.

---

## 6. Configuration côté SIEM

### 6.1 Splunk (Universal Forwarder ou HEC)

*Universal Forwarder* surveille le dossier de spool :

```ini
# /opt/splunkforwarder/etc/systemd/system/SplunkForwarder.service.d/… ou props.conf sur l'indexer
[thotsecure:audit]
SHOULD_LINEMERGE = false
LINE_BREAKER    = ([\r\n]+)
TRUNCATE        = 65536
TIME_PREFIX     = \brt=
MAX_TIMESTAMP_LOOKAHEAD = 13
# CEF : le parseur natif cef_decode fonctionne sur les lignes CEF:0|…|
[thotsecure:findings]
SHOULD_LINEMERGE = false
```

`inputs.conf` :

```ini
[monitor:///var/spool/thotsecure]
sourcetype = thotsecure:audit
index = security
disabled = false
crcSalt = <SOURCE>
```

*HEC* (si vous préférez pousser) : les fichiers CEF peuvent être envoyés par un petit `curl`/
`Invoke-RestMethod` depuis le même hôte ; dans ce cas, gardez ce forwarder comme **source de
vérité** et le HEC comme second chemin.

### 6.2 QRadar

* Créer un **Log Source** de type *Custom* avec le DSM générique « CEF »
  (`Universal DSM` → *Log Source Type: CEF*), protocole *Log File* (lecture du spool) ou *Syslog*.
* Vérifier la **parsing** : le DSM CEF mappe automatiquement `name`, `severity`, `src`, `suser`,
  `externalId`. Ajouter un *Custom Property* pour `riskScore` (`cn1`) et `tenantId` (`cs1`).
* Surveiller le champ `externalId` comme clé de corrélation (il porte `finding_id`/`seq`).

### 6.3 Elastic (Filebeat → Logstash/Elasticsearch)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: thotsecure-audit
    paths:
      - /var/spool/thotsecure/audit.cef
    parsers:
      - ndjson: { target: "" }   # seulement pour audit.jsonl / findings.jsonl
    fields: { thotsecure_source: audit, format: cef }
  - type: filestream
    id: thotsecure-findings
    paths:
      - /var/spool/thotsecure/findings.jsonl
    fields: { thotsecure_source: findings, format: jsonl }
    # Les fichiers tournants sont détectés (inode) : la rotation ne duplique pas les lignes.
processors:
  - add_host_metadata: ~
```

Pour du CEF pur, le module *decode_cef* de Logstash ou l'`ingest pipeline` `cef` d'Elastic convertit
les lignes en champs structurés. Indexez `findings.*` et `audit.*` séparément : les politiques de
rétention n'ont rien à voir (l'audit se conserve plus longtemps que les findings).

> Rappel : ce sont les **fichiers** qui sont le point d'intégration. Le SIEM est responsable de la
> rotation de son côté (celle du forwarder est indépendante et bornée par `--backups`).

---

## 7. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Cycles terminés sans incident. |
| `1` | Erreur d'exécution : réseau, I/O disque, réponse inexploitable (curseur non avancé). |
| `2` | Usage ou configuration : argument invalide, clé absente, `401`/`403`. |
| `3` | **Chaîne d'audit rompue** : incident majeur, transmission arrêtée. |
| `130` | `Ctrl-C` : arrêt propre, curseur sauvegardé. |

Le code `3` est le même que celui de `thotsecure audit verify` (§8) : un superviseur qui le voit sait
qu'il s'agit d'une atteinte à l'intégrité, pas d'une panne de réseau.

---

## 8. Que faire quand la chaîne est rompue

1. **Figer** : sauvegarder la base et le journal d'audit, ne rien purger, ne rien relancer.
2. **Localiser** : `broken_at` désigne le premier enregistrement dont le chaînage ne tient plus.
   Tout ce qui suit est postérieur à la rupture et doit être considéré comme non attestable.
3. **Comparer** : sauvegardes, exports SIEM antérieurs, journaux système autour de l'horodatage.
4. **Décider** : restaurer une copie saine, ou documenter l'écart s'il est légitime (migration,
   purge volontaire) — dans ce cas, consignez-le, la « rupture » doit avoir une explication.
5. **Ouvrir un incident de sécurité** : l'intégrité de la traçabilité est en cause, pas seulement la
   disponibilité d'un service.

Le marqueur `AUDIT_CHAIN_BROKEN.incident.json` contient le contexte et ce runbook, et peut être
collecté par le SIEM lui-même (le dossier de spool est déjà surveillé).

---

## 9. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `HTTP 401/403` | Capacité manquante | Clé `viewer`+ : `read:audit` **et** `read:findings`. |
| Fichiers vides en continu | Aucun enregistrement sur la fenêtre | Normal si rien ne s'est produit : vérifier `cursors` dans la sortie JSON. |
| Doublons après redémarrage | Mémoire de déduplication locale au processus | Augmenter `--overlap-seconds` ne les réduit pas : dédupliquer côté SIEM sur `externalId`. |
| Trou dans l'audit | Curseur avancé sans écriture (impossible ici) | Vérifier les journaux : une erreur d'écriture empêche l'avance du curseur. |
| Rotation trop agressive | `--max-bytes` faible | 64 Mio par défaut : à ajuster selon le débit et la politique du SIEM. |
| `valid: null` (indéterminé) | `/audit/verify` en `5xx` | Le forwarder poursuit et retente : un contrôle impossible n'est ni un succès ni une rupture. |

---

## 10. Sûreté

Le script est **en lecture seule** vis-à-vis de Thot Secure : il exporte, écrit des fichiers locaux,
et n'exécute aucune action. Il n'introduit aucune capacité offensive, ne contacte que l'instance
configurée, et ne journalise jamais la clé API. En cas de rupture de la chaîne d'audit, son
comportement par défaut est de **s'arrêter** plutôt que de propager des données douteuses.

Soutien
-------

Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

* Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
* Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
