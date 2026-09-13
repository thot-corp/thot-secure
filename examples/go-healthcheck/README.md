# Exemple — Sonde de disponibilité Go (`thotsecure-healthcheck`)

Sonde **autonome**, en **bibliothèque standard uniquement** (`net/http`, `encoding/json`, `flag`),
destinée aux orchestrateurs et aux superviseurs : Kubernetes, systemd, Nagios/Icinga, ou n'importe
quel script qui a besoin de savoir « le service est-il prêt ? » et « la chaîne d'audit est-elle
intacte ? ».

```text
GET /healthz   → le processus vit-il ?            (200 attendu)
GET /readyz    → peut-il servir ?                 (200 = prêt, 503 = non prêt)
GET /metrics   → est-il sain ? (option -metrics)  (thotsecure_up, thotsecure_audit_chain_valid)
```

Code de sortie : **0 prêt**, **1 non prêt**, **2 usage**. La première ligne de sortie suit la
convention des plugins de supervision (`OK - …` / `CRITICAL - …`), donc elle est lisible telle
quelle par Nagios/Icinga et par le journal systemd.

---

## 1. Compilation

```bash
cd examples/go-healthcheck
go build -trimpath -ldflags "-s -w" -o thotsecure-healthcheck .
# binaire statique pour un conteneur minimal :
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o thotsecure-healthcheck .
```

Aucune dépendance externe : `go.mod` n'est pas nécessaire pour un programme `package main` isolé
(`go build` en mode module demande toutefois un module — voir la note ci-dessous).

> **Note module** : dans un dépôt déjà pourvu d'un `go.mod` sous `sdks/go`, `go build` fonctionne
> directement. Utilisé seul, le fichier se compile avec `go run main.go …` ou, après
> `go mod init example.com/thotsecure-healthcheck && go mod tidy`, avec `go build`.

---

## 2. Options

| Option | Défaut | Rôle |
|---|---|---|
| `-url` | `$env:THOT_SECURE_URL`, sinon `http://127.0.0.1:8080` | Base de l'API à sonder (`THOT_URL`/`THOT_URL` acceptés). |
| `-timeout` | `5s` | Délai d'attente par requête (`-timeout 2s`). |
| `-metrics` | `false` | Récupère `/metrics` et vérifie les métriques clés. |
| `-require-metrics` | `thotsecure_audit_chain_valid,thotsecure_up` | Métriques exigées (séparées par des virgules). |
| `-metrics-lenient` | `false` | Une métrique absente devient un avertissement (utile pendant un déploiement progressif). |
| `-json` | `false` | Rapport JSON complet sur stdout (automatisation). |
| `-verbose` | `false` | Affiche les corps de réponse tronqués. |
| `-insecure` | `false` | Ne vérifie pas le certificat TLS (instance locale autosignée **uniquement**). |
| `-version` | — | Affiche la version de la sonde. |

---

## 3. Utilisation

```powershell
# Sonde simple : le service répond-il et est-il prêt ?
.\thotsecure-healthcheck.exe -url http://127.0.0.1:8080
# OK - http://127.0.0.1:8080 version 0.1.0 | healthz=200 (4.1 ms) readyz=200 (6.7 ms) | prêt

# Sonde complète : disponibilité + préparation + intégrité de la chaîne d'audit
.\thotsecure-healthcheck.exe -url https://thotsecure.interne -metrics
```

Sortie en échec (exemple) :

```text
CRITICAL - https://thotsecure.interne version 0.1.0 | healthz=200 (3.2 ms) readyz=503 (11.4 ms) | NON PRÊT (2 raison(s))
  info : mode d'autonomie « supervised »
  contrôles dégradés (1) :
    - rules : 0 règle chargée depuis THOT_RULES_DIR
  métriques :
    - thotsecure_audit_chain_valid = 1 (ok)
    - thotsecure_up = 0 (ÉCHEC)
  raisons :
    - readyz a répondu 503 (service non prêt : DB, bus ou règles indisponibles)
    - contrôle dégradé rules : 0 règle chargée depuis THOT_RULES_DIR
    - thotsecure_up = 0 (le service s'annonce hors service (voir /readyz))
```

Le détail des contrôles dégradés est extrait de `/readyz` sous plusieurs conventions
(`checks`, `components`, `dependencies`, `subsystems`) et plusieurs formes de valeur (booléen,
chaîne `ok`/`down`, objet `{"ok": false, "error": "…"}`) : la sonde n'impose pas une forme que le
contrat ne fige pas.

---

## 4. Les deux métriques qui comptent

| Métrique | Valeur saine | Sinon |
|---|---|---|
| `thotsecure_up` | `1` | Le service s'estime hors service → non prêt. |
| `thotsecure_audit_chain_valid` | `1` | **CHAÎNE D'AUDIT ROMPUE — incident majeur.** Le journal chaîné (§3.5) a été altéré ou tronqué : la traçabilité des décisions n'est plus garantie. Conservez les sauvegardes, ouvrez un incident, n'effacez rien. |

Une chaîne d'audit rompue est signalée même si `/readyz` répond `200` : la sonde sort en `1` et le
message le dit explicitement. C'est le seul contrôle qui distingue « le service fonctionne » de
« le service est digne de confiance ».

---

## 5. Intégration Kubernetes

### 5.1 Sondes HTTP directes (recommandé pour liveness/readiness)

Les routes étant publiques, les sondes natives suffisent dans la plupart des cas :

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: thotsecure
spec:
  replicas: 2
  selector:
    matchLabels: { app: thotsecure }
  template:
    metadata:
      labels: { app: thotsecure }
    spec:
      containers:
        - name: api
          image: ghcr.io/thot-corp/thot-secure:0.1.0
          ports:
            - { name: http, containerPort: 8080 }
          # /healthz : le processus répond (aucune dépendance externe) → redémarrage si bloqué
          livenessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          # /readyz : DB + bus + règles → retrait du service (endpoints) et non redémarrage
          readinessProbe:
            httpGet: { path: /readyz, port: http }
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 2
          startupProbe:
            httpGet: { path: /healthz, port: http }
            failureThreshold: 30
            periodSeconds: 2
```

**Ne mettez jamais `/readyz` en livenessProbe** : une base momentanément indisponible déclencherait
un redémarrage en boucle, ce qui aggrave l'incident au lieu de le résoudre.

### 5.2 Sondes `exec` avec la sonde (contrôles approfondis)

Utile quand vous voulez du superviseur qu'il vérifie **aussi** la chaîne d'audit, ou lorsque la
sonde sert de `check` dans un sidecar de supervision. Le binaire est alors présent dans l'image
(ou dans un conteneur sidecar, avec `-url http://127.0.0.1:8080`).

```yaml
        - name: api
          image: ghcr.io/thot-corp/thot-secure:0.1.0
          livenessProbe:
            exec:
              command:
                - /usr/local/bin/thotsecure-healthcheck
                - -url
                - http://127.0.0.1:8080
                - -timeout
                - 3s
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            exec:
              command:
                - /usr/local/bin/thotsecure-healthcheck
                - -url
                - http://127.0.0.1:8080
                - -metrics
                - -require-metrics
                - thotsecure_up,thotsecure_audit_chain_valid
            periodSeconds: 15
            timeoutSeconds: 5
```

Le conteneur doit embarquer le binaire :

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY examples/go-healthcheck/main.go ./
RUN go mod init example.com/thotsecure-healthcheck && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/thotsecure-healthcheck .

FROM alpine:3.20
COPY --from=build /out/thotsecure-healthcheck /usr/local/bin/thotsecure-healthcheck
ENTRYPOINT ["/usr/local/bin/thotsecure-healthcheck"]
```

> Attention aux sondes `exec` : elles consomment du CPU du conteneur. Pour un contrôle périodique
> approfondi, préférez un `CronJob` ou le sidecar de supervision ci-dessous.

### 5.3 Contrôle périodique par `CronJob`

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: thotsecure-healthcheck
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: probe
              image: ghcr.io/thot-corp/thotsecure-healthcheck:0.1.0
              args: ["-url", "http://thotsecure:8080", "-metrics", "-json"]
```

---

## 6. Intégration systemd (timer)

`/etc/systemd/system/thotsecure-healthcheck.service` :

```ini
[Unit]
Description=Sonde de disponibilité Thot Secure
After=network-online.target

[Service]
Type=oneshot
# Le code de sortie 1 met l'unité en échec : « systemctl --failed » devient votre tableau de bord.
ExecStart=/usr/local/bin/thotsecure-healthcheck -url http://127.0.0.1:8080 -metrics -require-metrics thotsecure_up,thotsecure_audit_chain_valid
User=thotprobe
# Aucun accès en écriture n'est nécessaire : la sonde est en lecture seule.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
```

`/etc/systemd/system/thotsecure-healthcheck.timer` :

```ini
[Unit]
Description=Sonde Thot Secure toutes les minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=thotsecure-healthcheck.service

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now thotsecure-healthcheck.timer
systemctl list-timers thotsecure-healthcheck.timer
journalctl -u thotsecure-healthcheck.service -n 50 --no-pager
```

Pour alerter sur échec sans supervision externe, ajoutez `OnFailure=alert@%n.service` (unité
générique qui envoie le ticket ou le message).

---

## 7. Intégration Nagios / Icinga

Déposez le binaire dans le répertoire des plugins (`/usr/lib/nagios/plugins/`) et déclarez la
commande :

```text
# /etc/nagios/objects/commands.cfg
define command {
    command_name    check_thotsecure
    command_line    $USER1$/thotsecure-healthcheck -url $ARG1$ -metrics -require-metrics $ARG2$
}

# /etc/nagios/objects/services.cfg
define service {
    use                     generic-service
    host_name               thotsecure-prod
    service_description     Thot Secure (disponibilité + chaîne d'audit)
    check_command           check_thotsecure!http://127.0.0.1:8080!thotsecure_up,thotsecure_audit_chain_valid
    check_interval          1
    retry_interval          3
    max_check_attempts      3
    notes                   La sortie « CHAÎNE D'AUDIT ROMPUE » impose un incident majeur.
}
```

Icinga 2 (objet `CheckCommand`) :

```text
object CheckCommand "thotsecure" {
  command = [ "/usr/lib/nagios/plugins/thotsecure-healthcheck" ]
  arguments = {
    "-url"              = "$thotsecure_url$"
    "-metrics"          = { set_if = "$thotsecure_metrics$" }
    "-require-metrics"  = "$thotsecure_require$"
  }
  vars.thotsecure_url     = "http://127.0.0.1:8080"
  vars.thotsecure_metrics = true
  vars.thotsecure_require = "thotsecure_up,thotsecure_audit_chain_valid"
}
```

Correspondance des codes de sortie : `0` → OK, `1` → CRITICAL (2 en usage : votre configuration de
commande est erronée, corrigez-la avant d'alerter l'astreinte).

Pour un collecteur de métriques (Telegraf `exec`, `node_exporter` textfile), utilisez `-json` et
lisez les champs `ready`, `degraded_checks`, `metrics`.

---

## 8. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `CRITICAL … healthz injoignable` | Service arrêté, port erroné, TLS invalide | Vérifier `-url`, le port et le certificat (`-insecure` **uniquement** en local). |
| `readyz a répondu 503` | DB, bus ou règles indisponibles | Lire les contrôles dégradés affichés, puis les journaux du service. |
| `métrique requise absente` | `/metrics` non exposé ou restreint au réseau interne | Exécuter la sonde depuis le réseau interne, ou `-metrics-lenient` le temps du déploiement. |
| `CHAÎNE D'AUDIT ROMPUE` | Journal d'audit altéré ou tronqué | Incident majeur : figer les sauvegardes, enquêter, ne rien purger. |
| `exit 2` | Argument invalide | `-h` pour l'aide ; l'URL doit commencer par `http://` ou `https://`. |

---

## 9. Sûreté

La sonde est **strictement en lecture seule** : trois `GET` sur des routes publiques, aucune
authentification, aucun secret, aucune écriture. Elle n'introduit aucune capacité offensive —
aucun scan, aucune énumération, aucun test d'authentification — et n'appelle que l'URL fournie.

Soutien
-------

Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.

* Bitcoin (BTC, réseau Bitcoin mainnet) : `33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR`
* Solana (SOL, réseau Solana mainnet) : `95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi`
