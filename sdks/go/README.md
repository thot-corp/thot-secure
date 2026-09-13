# SDK Go — Thot Secure (nom technique `thotsecure`) v0.1.0

SDK officiel pour l'API REST **Thot Secure** (SOAR/CSPM **défensif**), conforme au contrat
d'interface [`docs/architecture/api-contract.md`](../../docs/architecture/api-contract.md) §3 et §4.

* **Bibliothèque standard uniquement** : `net/http`, `net`, `crypto/tls`, `encoding/json`,
  `log/slog`. Aucune dépendance externe, donc aucun `go mod download` et aucune chaîne
  d'approvisionnement tierce.
* **Couverture complète du §4** : santé (§4.1), tenants et clés (§4.2), événements (§4.3),
  findings (§4.4), règles/politiques/playbooks (§4.5), actions SOAR (§4.6), audit (§4.7),
  stats/collecteurs (§4.8), plus un client WebSocket minimal pour le flux temps réel.
* **`context.Context` sur chaque méthode** : annulation et *deadlines* propagées jusqu'au
  transport.
* **Aucune capacité offensive** : le SDK ne fait que parler à l'API (pas de scan, pas de force
  brute, pas d'exploitation). `RunCollector` ne cible que les cibles déclarées du tenant.
* **TLS vérifié par défaut**, **aucun secret journalisé**, **`dry_run` jamais levé
  automatiquement**.

## Installation

```bash
go get github.com/thot-corp/thot-secure/sdks/go
```

```go
import thotsecure "github.com/thot-corp/thot-secure/sdks/go"
```

Go ≥ 1.22 est requis (génériques, `log/slog`, `min`/`max`).

## Configuration

Le client lit son environnement par défaut :

| Variable | Rôle |
|---|---|
| `THOT_SECURE_URL`, `THOT_URL`, `THOT_URL` | racine du service (défaut `http://127.0.0.1:8080`) |
| `THOT_SECURE_API_KEY`, `THOT_API_KEY`, `THOT_API_KEY` | clé API `ao_…` |
| `THOT_SECURE_TENANT_ID`, `THOT_TENANT_ID`, `THOT_TENANT_ID` | tenant par défaut |

Les orthographes héritées `THOT_*` restent acceptées (renommage en cours).

```go
client, err := thotsecure.NewClient(
	thotsecure.WithTenantID("acme"),
	thotsecure.WithTimeout(30*time.Second),
	thotsecure.WithMaxRetries(3),
)
if err != nil {
	log.Fatal(err)
}
defer client.Close()

who, err := client.Whoami(ctx)
```

Options disponibles : `WithBaseURL`, `WithAPIKey`, `WithTenantID`, `WithHTTPClient`,
`WithMaxRetries`, `WithUserAgent`, `WithTimeout`, `WithBackoff`, `WithLogger`, `WithInsecureTLS`.

## Exemples par famille de routes

### §4.1 Santé, méta, observabilité

```go
health, _ := client.Healthz(ctx)          // GET /healthz
ready, _ := client.Readyz(ctx)            // GET /readyz — 503 ⇒ {Status:"unavailable"} SANS erreur
info, _ := client.Version(ctx)            // GET /version
metrics, _ := client.Metrics(ctx)         // GET /metrics (texte Prometheus)
who, _ := client.Whoami(ctx)              // GET /api/v1/auth/whoami
```

### §4.2 Tenants et clés

```go
tenants, err := client.ListTenants(ctx)
created, err := client.CreateTenant(ctx, thotsecure.CreateTenantInput{
	TenantID: "acme", Name: "ACME SAS", Mode: "supervised",
})

// ⚠️ `auto` ou `dry_run: false` change le niveau d'autonomie : décision de sécurité volontaire,
// limitée et journalisée (contrat §6).
dryRun := false
_, err = client.UpdateTenant(ctx, "acme", thotsecure.UpdateTenantInput{Mode: "auto", DryRun: &dryRun})

key, err := client.CreateKey(ctx, "acme", thotsecure.CreateKeyInput{Role: "responder", Label: "ci"})
fmt.Println(key.ApiKey) // affichée UNE SEULE FOIS — ne la journalisez jamais
_, err = client.ListKeys(ctx, "acme")
err = client.RevokeKey(ctx, key.KeyID)
```

### §4.3 Événements

```go
severityLow := "low"
result, err := client.IngestEvent(ctx, thotsecure.EventInput{
	Kind:         "http.request",
	TS:           "2026-02-14T10:00:00.123Z",
	SeverityHint: &severityLow,
	Labels:       map[string]any{"src_ip": "203.0.113.9", "path": "/login", "method": "POST"},
	Payload:      map[string]any{"status": 403, "bytes": 512},
})

// Lot : découpage automatique au-delà de 500 événements (contrat §4.3).
total, err := client.IngestEvents(ctx, events,
	thotsecure.WithBatchSize(500),
	thotsecure.WithBatchCallback(func(batch *thotsecure.IngestResult) error {
		log.Printf("lot accepté : %d", batch.Accepted) // contre-pression : produire le suivant ici
		return nil
	}),
)

page, err := client.ListEvents(ctx, thotsecure.ListEventsOptions{
	Kind: "http.request", Since: "2026-02-14T00:00:00Z", Limit: 100,
})
event, err := client.GetEvent(ctx, "e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11")
```

### §4.4 Findings

```go
page, err := client.ListFindings(ctx, thotsecure.ListFindingsOptions{
	Status: "open", Severity: "high", MinRisk: 70, Sort: "risk_score", Limit: 50,
})
finding, err := client.GetFinding(ctx, page.Items[0].FindingID) // + Actions liées

_, err = client.AckFinding(ctx, finding.FindingID, thotsecure.WithComment("revue en cours"))
_, err = client.CloseFinding(ctx, finding.FindingID, thotsecure.CloseFindingInput{
	Resolution: "true_positive", Comment: "corrigé",
})
_, err = client.SuppressFinding(ctx, finding.FindingID, thotsecure.SuppressFindingInput{
	DurationSeconds: 86400, Reason: "faux positif connu",
})

sarif, err := client.GetReport(ctx, finding.FindingID, "sarif") // md | html | json | sarif
```

### §4.5 Règles, politiques, playbooks

```go
rules, err := client.ListRules(ctx)
rule, err := client.GetRule(ctx, "AO-WEB-001")           // + YAML source
validation, err := client.ValidateRule(ctx, yamlSource)  // YAML ou JSON
reload, err := client.ReloadRules(ctx)                   // admin:rules
policies, err := client.ListPolicies(ctx)
_, err = client.ReloadPolicies(ctx)                      // admin:policies
playbooks, err := client.ListPlaybooks(ctx)
```

### §4.6 Actions SOAR

```go
// Planification : aucun effet de bord, `dry_run` à true par défaut.
action, err := client.PlanAction(ctx, thotsecure.PlanActionInput{
	FindingID: finding.FindingID,
	Playbook:  "block-source-ip",
	Params:    map[string]any{"target": "203.0.113.9", "duration_seconds": 3600},
})

_, err = client.ApproveAction(ctx, action.ActionID, thotsecure.WithComment("validé par astreinte"))
// `execute` refuse (409) une action encore `pending_approval`. Sans clé d'idempotence, un POST
// n'est JAMAIS rejoué automatiquement : la clé rend la reprise sûre (le serveur déduplique).
_, err = client.ExecuteAction(ctx, action.ActionID,
	thotsecure.WithIdempotencyKey(action.TenantID+":"+action.Playbook+":203.0.113.9:1739527200"),
)
_, err = client.RollbackAction(ctx, action.ActionID, thotsecure.WithReason("faux positif"))

_, err = client.ListActions(ctx, thotsecure.ListActionsOptions{Status: "pending_approval"})
```

### §4.7 Audit

```go
records, err := client.ListAudit(ctx, thotsecure.ListAuditOptions{Action: "action.execute", Limit: 50})
verification, err := client.VerifyAudit(ctx)
if !verification.Valid {
	log.Printf("chaîne d'audit cassée à la séquence %v", *verification.BrokenAt)
}
cef, err := client.ExportAudit(ctx, "cef", "2026-02-01T00:00:00Z", "") // jsonl | cef
```

### §4.8 Stats, collecteurs, flux temps réel

```go
stats, err := client.StatsOverview(ctx)
collectors, err := client.ListCollectors(ctx)
_, err = client.RunCollector(ctx, "http_probe") // cibles déclarées du tenant uniquement

// Flux WebSocket (handshake vérifié, `Sec-WebSocket-Accept` contrôlé).
streamURL, err := client.StreamURL("")   // ⚠️ contient la clé API
conn, err := thotsecure.DialWS(ctx, streamURL)
if err != nil {
	log.Fatal(err)
}
defer conn.Close()

for {
	frame, err := conn.ReadFrame(ctx)
	if err != nil {
		break // ErrWSClosed, ErrFragmentedFrame, ErrFrameTooLarge…
	}
	switch frame.Type {
	case thotsecure.FrameTypeFinding:
		var finding thotsecure.Finding
		if err := frame.UnmarshalData(&finding); err == nil {
			log.Printf("finding %s (risk=%.1f)", finding.FindingID, finding.RiskScore)
		}
	case thotsecure.FrameTypeHeartbeat:
		// battement de cœur : la connexion est vivante
	}
}
```

## Aide-mémoire des erreurs

```go
_, err := client.GetFinding(ctx, "inconnu")
var apiErr *thotsecure.APIError
if errors.As(err, &apiErr) {
	switch {
	case apiErr.IsNotFound():
		// 404 — inexistant, ou appartenant à un autre tenant (isolation stricte)
	case apiErr.IsForbidden():
		// 403 — capacité RBAC manquante
	case apiErr.IsConflict():
		// 409 — conflit d'état (action non approuvée, rollback déjà effectué)
	case apiErr.IsRateLimited():
		time.Sleep(apiErr.RetryAfter) // 429 : délai conseillé par le serveur
	}
	log.Printf("%s (status=%d, code=%s, request_id=%s)", apiErr.Message, apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
}
```

`APIError` expose : `StatusCode`, `Code`, `Message`, `Details`, `Method`, `URL`, `RequestID`,
`RetryAfter`, `Retryable`, `Cause` — et satisfait `errors.Is`/`errors.As` (`Unwrap`).

## Sécurité

> **⚠️ N'embarquez jamais une clé API dans un client distribué** (application mobile, binaire
> posté sur un poste, page web). Une clé `ao_…` extraite du binaire donne accès aux findings, à
> l'audit et — selon son rôle — au déclenchement d'actions de remédiation. Faites porter la clé
> par **votre** service et n'exposez au client qu'un jeton à courte durée de vie.

* **TLS vérifié par défaut.** `WithInsecureTLS()` (et `WithWSInsecureTLS()`) existent pour un
  laboratoire isolé, **journalisent un avertissement bruyant** à l'activation et sont à proscrire
  en production : sans vérification du certificat, un homme du milieu peut lire la clé API
  (transmise en paramètre d'URL pour le WebSocket) et injecter de fausses trames.
* **Aucun secret journalisé** : `redactURL` masque `api_key`, `token`, `password`…, `Client.String()`
  n'affiche jamais la clé, et `APIKeyConfigured()` est le seul accesseur exposé.
* **Reprise prudente** : seuls `429/502/503/504` et les erreurs réseau sont réessayés, avec backoff
  exponentiel plafonné (30 s) et jitter ; un `POST`/`PATCH` n'est rejoué que si une clé
  d'idempotence est fournie. `WithoutRetry()` désactive toute reprise pour un appel (sondes).
* **`dry_run` respecté** : `PlanAction` envoie `dry_run: true` par défaut ; rien dans le SDK ne
  lève ce garde-fou implicitement.
* **Annulation** : chaque méthode accepte un `context.Context` ; une annulation interrompt
  l'attente de reprise et remonte `context.Canceled` / `context.DeadlineExceeded`.

## Limites honnêtes

1. **Fragmentation WebSocket non assemblée.** `ReadTextMessage` refuse une trame non finale
   (`FIN=0`), une trame de continuation, ou une trame binaire, avec l'erreur explicite
   `ErrFragmentedFrame` / `ErrUnexpectedOpcode` — **jamais** un message tronqué livré
   silencieusement. Si votre serveur fragmente ses trames, ce client ne convient pas tel quel.
2. **Pas de reconnexion automatique** dans `ws.go` : enveloppez la lecture dans votre propre
   boucle (backoff) ou utilisez le SDK Python, qui embarque une reconnexion avec backoff et
   détection de connexion morte. Le client Go fournit `ReadFrame`, `WritePing`/`WritePong` et
   `WriteClose` pour l'implémenter proprement.
3. **Pas de `permessage-deflate`** ni de négociation d'extension : les bits RSV non nuls sont
   refusés.
4. **Chemins de type** : les pages de liste sont exposées par `Page[T]` (avec `NextCursor`) ; le SDK
   n'implémente pas d'itérateur de pagination automatique — bouclez sur `NextCursor` si vous voulez
   tout parcourir.
5. **Hors périmètre** : console embarquée (§4.9), `GET /ui/*`, `GET /openapi.json` (ce ne sont pas
   des routes d'API métier), et le client NATS du bus (usage interne du serveur).
6. **Pas de validation exhaustive des énumérations côté client** : le SDK valide ce qui évite un
   aller-retour inutile évident (`resolution`, `format`, `limit > 500`, corps vides) et laisse le
   serveur trancher le reste (`422 unprocessable`).

## Développement

```bash
go build ./...     # compilation (bibliothèque standard uniquement)
go vet ./...       # analyse statique
go test ./...      # tests hors ligne : httptest.Server + socket locale pour le WebSocket
gofmt -l .         # formatage
```

Les tests n'ouvrent **aucune** connexion vers l'extérieur : l'API est simulée par
`httptest.Server` et le flux WebSocket par un `net.Listener` local qui reproduit un handshake
RFC 6455 et des trames fabriquées (longueurs 126/127, masque, fragmentation, surdimensionnement).

## Licence

Apache-2.0 — projet Thot Secure (nom technique `thotsecure`).
