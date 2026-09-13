// Package thotsecure est le SDK Go officiel de Thot Secure (nom technique « thotsecure »),
// un SOAR/CSPM **défensif**.
//
// Il couvre l'intégralité de la surface REST décrite par le contrat d'interface
// (docs/architecture/api-contract.md §4) et n'utilise que la bibliothèque standard :
// aucune dépendance externe, aucun `go mod download` nécessaire.
//
// Trois fichiers suffisent à s'orienter :
//
//   - `types.go`   — les structures JSON du contrat §3 ;
//   - `client.go`  — le client REST, ses options fonctionnelles et toutes les méthodes du §4 ;
//   - `ws.go`      — un client WebSocket minimal mais correct pour le flux `/api/v1/ws/stream`.
//
// Règle de sécurité appliquée partout : la clé API n'est jamais journalisée, les erreurs ne
// contiennent jamais de secret, et le SDK n'expose **aucune** capacité offensive (pas de scan,
// pas de force brute, pas d'exploitation) — il ne fait que parler à l'API.
package thotsecure

import (
	"bytes"
	"encoding/json"
)

/* ====================================================================================== */
/* §3.1 Event                                                                              */
/* ====================================================================================== */

// EventSource décrit l'origine d'un événement (contrat §3.1).
type EventSource struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Host string `json:"host"`
}

// Event est un événement normalisé et **immuable** (contrat §3.1).
//
// Les champs d'horodatage restent des chaînes ISO 8601 UTC (`2026-02-14T10:00:00.123Z`) : le
// contrat définit le format, pas un type de date, et une chaîne évite toute perte de précision
// ou de fuseau à l'aller-retour.
type Event struct {
	EventID       string         `json:"event_id"`
	SchemaVersion string         `json:"schema_version"`
	TenantID      string         `json:"tenant_id"`
	TS            string         `json:"ts"`
	Kind          string         `json:"kind"`
	Source        EventSource    `json:"source"`
	SeverityHint  *string        `json:"severity_hint"`
	Labels        map[string]any `json:"labels"`
	Payload       map[string]any `json:"payload"`
	RawRef        *string        `json:"raw_ref"`
}

// EventInput est le corps accepté par `POST /api/v1/events` (contrat §4.3).
//
// `tenant_id` est forcé depuis la clé API côté serveur ; `event_id` et `ts` sont générés si
// l'appelant les omet.
type EventInput struct {
	EventID       string         `json:"event_id,omitempty"`
	SchemaVersion string         `json:"schema_version,omitempty"`
	TenantID      string         `json:"tenant_id,omitempty"`
	TS            string         `json:"ts,omitempty"`
	Kind          string         `json:"kind,omitempty"`
	Source        *EventSource   `json:"source,omitempty"`
	SeverityHint  *string        `json:"severity_hint,omitempty"`
	Labels        map[string]any `json:"labels,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	RawRef        *string        `json:"raw_ref,omitempty"`
}

/* ====================================================================================== */
/* §3.2 Finding                                                                            */
/* ====================================================================================== */

// Finding est un agrégat d'événements déclenché par une règle, porteur d'un `risk_score`
// (contrat §3.2).
type Finding struct {
	FindingID   string         `json:"finding_id"`
	TenantID    string         `json:"tenant_id"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    string         `json:"severity"`
	RiskScore   float64        `json:"risk_score"`
	Confidence  float64        `json:"confidence"`
	Status      string         `json:"status"`
	Title       string         `json:"title"`
	Description *string        `json:"description"`
	Remediation *string        `json:"remediation"`
	Tags        []string       `json:"tags"`
	MITRE       []string       `json:"mitre"`
	Evidence    map[string]any `json:"evidence"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
	Count       int            `json:"count"`
	EventIDs    []string       `json:"event_ids"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
	// Actions liées, ajoutées par `GET /api/v1/findings/{id}` (contrat §4.4).
	Actions []Action `json:"actions,omitempty"`
}

/* ====================================================================================== */
/* §3.3 Decision                                                                           */
/* ====================================================================================== */

// Decision est le verdict du moteur policy-as-code (contrat §3.3).
type Decision struct {
	Decision        string         `json:"decision"`
	PolicyID        *string        `json:"policy_id"`
	Playbook        *string        `json:"playbook"`
	Params          map[string]any `json:"params"`
	Reason          string         `json:"reason"`
	RiskScore       *float64       `json:"risk_score"`
	ExpiresAt       *string        `json:"expires_at"`
	CooldownSeconds *int           `json:"cooldown_seconds"`
	// DryRun à true : aucune action réelle ne sera exécutée (contrat §1, invariant 1).
	DryRun bool `json:"dry_run"`
}

/* ====================================================================================== */
/* §3.4 Action                                                                             */
/* ====================================================================================== */

// ActionTarget est la cible d'une action (`{"type":"ip","value":"203.0.113.9"}`).
type ActionTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ActionRollback décrit l'état du rollback d'une action (contrat §3.4).
type ActionRollback struct {
	Available   bool           `json:"available"`
	Token       *string        `json:"token"`
	PerformedAt *string        `json:"performed_at"`
	Result      map[string]any `json:"result"`
}

// Action est l'instance d'exécution d'un playbook sur un finding (contrat §3.4).
type Action struct {
	ActionID     string         `json:"action_id"`
	TenantID     string         `json:"tenant_id"`
	FindingID    string         `json:"finding_id"`
	PolicyID     *string        `json:"policy_id"`
	Playbook     string         `json:"playbook"`
	Status       string         `json:"status"`
	Mode         string         `json:"mode"`
	DryRun       bool           `json:"dry_run"`
	Params       map[string]any `json:"params"`
	Target       ActionTarget   `json:"target"`
	RequestedBy  string         `json:"requested_by"`
	RequestedAt  string         `json:"requested_at"`
	ApprovedBy   *string        `json:"approved_by"`
	ApprovedAt   *string        `json:"approved_at"`
	ExecutedAt   *string        `json:"executed_at"`
	ExpiresAt    *string        `json:"expires_at"`
	Result       map[string]any `json:"result"`
	Rollback     ActionRollback `json:"rollback"`
	Idempotency  *string        `json:"idempotency_key"`
	AuditSeq     *int64         `json:"audit_seq"`
	ErrorMessage *string        `json:"error,omitempty"`
}

/* ====================================================================================== */
/* §3.5 AuditRecord                                                                        */
/* ====================================================================================== */

// AuditTarget est la cible d'une entrée d'audit (`{"type":"action","id":"a91b…"}`).
type AuditTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuditRecord est une entrée du journal append-only chaîné par hash (contrat §3.5).
type AuditRecord struct {
	Seq      int64          `json:"seq"`
	TS       string         `json:"ts"`
	TenantID string         `json:"tenant_id"`
	Actor    string         `json:"actor"`
	ActorRole string        `json:"actor_role"`
	Action   string         `json:"action"`
	Target   AuditTarget    `json:"target"`
	Before   map[string]any `json:"before"`
	After    map[string]any `json:"after"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// AuditVerification est la réponse de `GET /api/v1/audit/verify` (contrat §4.7).
type AuditVerification struct {
	Valid    bool   `json:"valid"`
	Records  int    `json:"records"`
	BrokenAt *int64 `json:"broken_at"`
}

/* ====================================================================================== */
/* §4.2 Tenant et clés                                                                     */
/* ====================================================================================== */

// Tenant est la frontière d'isolation multi-tenant (contrat §4.2).
type Tenant struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	// DryRun à true : aucune action réelle pour ce tenant.
	DryRun bool `json:"dry_run"`
	// AutonomyAllowlist protège l'infrastructure propre : **aucune** action n'y est possible
	// (contrat §6, garde-fou 3).
	AutonomyAllowlist []string `json:"autonomy_allowlist"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

// CreateTenantInput est le corps de `POST /api/v1/tenants`.
type CreateTenantInput struct {
	TenantID          string   `json:"tenant_id"`
	Name              string   `json:"name"`
	Mode              string   `json:"mode,omitempty"`
	AutonomyAllowlist []string `json:"autonomy_allowlist,omitempty"`
	DryRun            *bool    `json:"dry_run,omitempty"`
}

// UpdateTenantInput est le corps de `PATCH /api/v1/tenants/{id}`.
//
// ⚠️ Activer `Mode: "auto"` ou `DryRun: false` change le niveau d'autonomie d'un tenant : c'est
// une décision de sécurité volontaire, limitée et journalisée (contrat §6).
type UpdateTenantInput struct {
	Mode              string   `json:"mode,omitempty"`
	DryRun            *bool    `json:"dry_run,omitempty"`
	Name              string   `json:"name,omitempty"`
	AutonomyAllowlist []string `json:"autonomy_allowlist,omitempty"`
}

// ApiKeyInfo décrit une clé API. `ApiKey` n'est renseignée **qu'à la création** (contrat §4.2) :
// elle n'est jamais relue ensuite et ne doit jamais être journalisée.
type ApiKeyInfo struct {
	KeyID      string  `json:"key_id"`
	ApiKey     string  `json:"api_key,omitempty"`
	Label      *string `json:"label"`
	Role       string  `json:"role"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	RevokedAt  *string `json:"revoked_at"`
}

// CreateKeyInput est le corps de `POST /api/v1/tenants/{id}/keys`.
type CreateKeyInput struct {
	Role  string `json:"role"`
	Label string `json:"label,omitempty"`
}

/* ====================================================================================== */
/* §4.5 / §5 / §6 / §7 Règles, politiques, playbooks                                       */
/* ====================================================================================== */

// RuleMatch regroupe les conditions d'une règle (contrat §5).
type RuleMatch struct {
	All       []map[string]any `json:"all,omitempty"`
	Any       []map[string]any `json:"any,omitempty"`
	Not       []map[string]any `json:"not,omitempty"`
	Threshold map[string]any   `json:"threshold,omitempty"`
}

// Rule est une règle de détection (contrat §4.5 et §5).
type Rule struct {
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Description *string        `json:"description"`
	Status      string         `json:"status"`
	Severity    string         `json:"severity"`
	Confidence  float64        `json:"confidence"`
	Enabled     bool           `json:"enabled"`
	Tags        []string       `json:"tags"`
	SourceTypes []string       `json:"source_types"`
	Kinds       []string       `json:"kinds"`
	Path        string         `json:"path"`
	Match       RuleMatch      `json:"match"`
	Dedup       map[string]any `json:"dedup"`
	Risk        map[string]any `json:"risk"`
	Remediation *string        `json:"remediation"`
	References  []string       `json:"references"`
	// YAMLSource n'est renseigné que par `GET /api/v1/rules/{rule_id}`.
	YAMLSource string `json:"yaml_source,omitempty"`
}

// RuleValidation est la réponse de `POST /api/v1/rules/validate` (contrat §4.5).
type RuleValidation struct {
	Valid  bool             `json:"valid"`
	Errors []map[string]any `json:"errors"`
}

// ReloadResult est la réponse de `POST /api/v1/rules/reload` et `.../policies/reload`.
type ReloadResult struct {
	Loaded int              `json:"loaded"`
	Errors []map[string]any `json:"errors"`
}

// PolicyThen est le bloc `then` d'une politique (contrat §6).
type PolicyThen struct {
	Decision          string         `json:"decision"`
	Playbook          string         `json:"playbook,omitempty"`
	Params            map[string]any `json:"params,omitempty"`
	DryRun            *bool          `json:"dry_run,omitempty"`
	CooldownSeconds   *int           `json:"cooldown_seconds,omitempty"`
	MaxActionsPerHour *int           `json:"max_actions_per_hour,omitempty"`
}

// PolicyRollback est le bloc `rollback` d'une politique (contrat §6).
type PolicyRollback struct {
	Playbook         string `json:"playbook,omitempty"`
	AutoAfterSeconds *int   `json:"auto_after_seconds,omitempty"`
}

// Policy est une politique de décision *policy-as-code* (contrat §6).
type Policy struct {
	Version     int            `json:"version"`
	ID          string         `json:"id"`
	Priority    int            `json:"priority"`
	Description *string        `json:"description"`
	When        map[string]any `json:"when"`
	Then        PolicyThen     `json:"then"`
	Rollback    PolicyRollback `json:"rollback"`
	Path        string         `json:"path,omitempty"`
}

// PlaybookParam décrit un paramètre de playbook (contrat §7).
type PlaybookParam struct {
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	Default     any    `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
	Min         *int   `json:"min,omitempty"`
	Max         *int   `json:"max,omitempty"`
}

// Playbook est une procédure d'action nommée, **toujours** accompagnée d'un rollback
// (contrat §4.5 et §7).
type Playbook struct {
	Name          string                    `json:"name"`
	Description   string                    `json:"description"`
	ParamsSchema  map[string]PlaybookParam  `json:"params_schema"`
	Reversible    bool                      `json:"reversible"`
	DryRunCapable bool                      `json:"dry_run_capable"`
	Connectors    []string                  `json:"connectors"`
}

/* ====================================================================================== */
/* §4.8 Stats, collecteurs                                                                 */
/* ====================================================================================== */

// CollectorStatus est l'état d'un collecteur (dernier run, items, erreurs, contrat §4.8).
type CollectorStatus struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Enabled       bool    `json:"enabled"`
	Status        string  `json:"status"`
	LastRunAt     *string `json:"last_run_at"`
	LastSuccessAt *string `json:"last_success_at"`
	Items         int     `json:"items"`
	Errors        int     `json:"errors"`
	Error         *string `json:"error"`
}

// StatsOverview regroupe les compteurs agrégés 24 h / 7 j (contrat §4.8).
type StatsOverview struct {
	Window24h          map[string]any  `json:"window_24h"`
	Window7d           map[string]any  `json:"window_7d"`
	Events             map[string]any  `json:"events"`
	FindingsBySeverity map[string]int  `json:"findings_by_severity"`
	MTTASeconds        *float64        `json:"mtta_seconds"`
	MTTRSeconds        *float64        `json:"mttr_seconds"`
	TopRules           []map[string]any `json:"top_rules"`
	ActionsSucceeded   int             `json:"actions_succeeded"`
	ActionsRolledBack  int             `json:"actions_rolled_back"`
	AutonomyMode       string          `json:"autonomy_mode"`
}

/* ====================================================================================== */
/* Réponses composées                                                                      */
/* ====================================================================================== */

// IngestOutcome est un finding issu d'une ingestion (élément de `findings[]`, contrat §4.3).
type IngestOutcome struct {
	FindingID string  `json:"finding_id"`
	RuleID    string  `json:"rule_id"`
	Severity  string  `json:"severity"`
	RiskScore float64 `json:"risk_score"`
	Decision  string  `json:"decision"`
}

// IngestResult est la réponse `202` de `POST /api/v1/events` (contrat §4.3).
type IngestResult struct {
	Accepted int             `json:"accepted"`
	Rejected int             `json:"rejected"`
	EventIDs []string        `json:"event_ids"`
	Findings []IngestOutcome `json:"findings"`
}

// WhoAmI est la réponse de `GET /api/v1/auth/whoami` (contrat §4.1).
type WhoAmI struct {
	TenantID      string   `json:"tenant_id"`
	Role          string   `json:"role"`
	Capabilities  []string `json:"capabilities"`
	AutonomyMode  string   `json:"autonomy_mode"`
	DryRun        bool     `json:"dry_run"`
}

// HealthStatus est la réponse de `GET /healthz` (contrat §4.1).
type HealthStatus struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	UptimeS  int64  `json:"uptime_s"`
}

// ReadyStatus est la réponse de `GET /readyz`. Un `503` alimente `Status: "unavailable"` et
// `HTTPStatus: 503` **sans lever d'erreur** : c'est ce qu'attend une sonde d'orchestrateur.
type ReadyStatus struct {
	Status     string         `json:"status"`
	HTTPStatus int            `json:"http_status"`
	Version    string         `json:"version,omitempty"`
	Error      string         `json:"error,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

// VersionInfo est la réponse de `GET /version` (contrat §4.1).
type VersionInfo struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	License      string `json:"license"`
	AutonomyMode string `json:"autonomy_mode"`
}

// StatusResult est la réponse des routes de cycle de vie d'un finding (ack/close/suppress).
type StatusResult struct {
	Status string `json:"status"`
}

/* ====================================================================================== */
/* Corps de requête des routes d'action                                                    */
/* ====================================================================================== */

// PlanActionInput est le corps de `POST /api/v1/actions/plan` (contrat §4.6) — aucun effet de
// bord. `DryRun` vaut `true` par défaut : la planification reste une simulation tant que ce
// garde-fou n'est pas levé explicitement.
type PlanActionInput struct {
	FindingID string         `json:"finding_id"`
	Playbook  string         `json:"playbook"`
	Params    map[string]any `json:"params,omitempty"`
	DryRun    *bool          `json:"dry_run,omitempty"`
}

// CloseFindingInput est le corps de `POST /api/v1/findings/{id}/close`.
//
// Resolution ∈ `true_positive | false_positive | mitigated`.
type CloseFindingInput struct {
	Resolution string `json:"resolution"`
	Comment    string `json:"comment,omitempty"`
}

// SuppressFindingInput est le corps de `POST /api/v1/findings/{id}/suppress`.
type SuppressFindingInput struct {
	DurationSeconds int    `json:"duration_seconds"`
	Reason          string `json:"reason,omitempty"`
}

/* ====================================================================================== */
/* Erreurs du contrat (§4.6) et pagination                                                 */
/* ====================================================================================== */

// APIErrorBody est le corps d'erreur normalisé du contrat §4.6 :
//
//	{"error":{"code":"forbidden","message":"…","details":{…}}}
type APIErrorBody struct {
	Error APIErrorDetail `json:"error"`
}

// APIErrorDetail est le détail d'une erreur du contrat.
type APIErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Page est une page de résultats d'une route de liste.
//
// Le type accepte aussi bien `{"items":[…]}` (contrat §4.2, §4.5, §4.8) qu'un tableau nu, afin
// de rester robuste à une réponse serveur plus directe.
type Page[T any] struct {
	Items      []T
	NextCursor *string
}

// UnmarshalJSON accepte `{"items":[…]}`, `{"data":[…]}` et `[…]`, avec `next_cursor` ou `cursor`.
func (p *Page[T]) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		p.Items = []T{}
		return nil
	}
	if trimmed[0] == '[' {
		var items []T
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return err
		}
		p.Items = items
		return nil
	}
	var envelope struct {
		Items      []T     `json:"items"`
		Data       []T     `json:"data"`
		NextCursor *string `json:"next_cursor"`
		Cursor     *string `json:"cursor"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return err
	}
	if envelope.Items != nil {
		p.Items = envelope.Items
	} else if envelope.Data != nil {
		p.Items = envelope.Data
	} else {
		p.Items = []T{}
	}
	if envelope.NextCursor != nil {
		p.NextCursor = envelope.NextCursor
	} else {
		p.NextCursor = envelope.Cursor
	}
	return nil
}
