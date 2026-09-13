/**
 * Thot Secure — types miroirs du contrat d'interface gelé v0.1.0.
 * Source : `docs/architecture/api-contract.md` (§3 schémas, §4 API, §4.1 rôles).
 *
 * Règles de ce fichier :
 *  - un type par schéma JSON du contrat, nommé comme le schéma ;
 *  - aucun `any`, aucun `unknown` public non justifié ;
 *  - les énumérations du contrat sont des unions de littéraux exportées
 *    *et* des tableaux de constantes (pour la validation d'entrée runtime) ;
 *  - les champs que le contrat donne comme nullables sont typés `| null`,
 *    jamais `| undefined` : l'absence de clé est un problème d'API, pas une
 *    variation de schéma. Les helpers de rendu traitent `null` comme « — ».
 */

/* -------------------------------------------------------------------------- */
/* Primitives JSON                                                             */
/* -------------------------------------------------------------------------- */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/** `labels` d'un événement : plat, valeurs scalaires uniquement (contrat §3.1). */
export type LabelValue = string | number | boolean | null;
export type LabelMap = Record<string, LabelValue>;

/* -------------------------------------------------------------------------- */
/* Énumérations                                                                */
/* -------------------------------------------------------------------------- */

/** `severity` d'un finding et `severity` d'une règle. */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** `severity_hint` d'un événement ∈ info|low|medium|high|critical|null. */
export type SeverityHint = Severity | null;

/** `kind` d'un événement (contrat §3.1). */
export const EVENT_KINDS = [
  'http.request',
  'http.response',
  'log.line',
  'tls.cert',
  'dependency',
  'config.audit',
  'syslog',
  'generic',
] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

/** `status` d'un finding (contrat §3.2). */
export const FINDING_STATUSES = ['open', 'acked', 'closed', 'suppressed'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** `resolution` d'une clôture de finding (contrat §4.4). */
export const RESOLUTIONS = ['true_positive', 'false_positive', 'mitigated'] as const;
export type Resolution = (typeof RESOLUTIONS)[number];

/** `decision` du moteur de décision (contrat §3.3). */
export const DECISIONS = ['auto', 'require_approval', 'notify_only', 'ignore'] as const;
export type DecisionKind = (typeof DECISIONS)[number];

/** `status` d'une action (contrat §3.4). */
export const ACTION_STATUSES = [
  'planned',
  'pending_approval',
  'approved',
  'rejected',
  'executing',
  'succeeded',
  'failed',
  'expired',
  'rolled_back',
] as const;
export type ActionStatus = (typeof ACTION_STATUSES)[number];

/** Mode d'autonomie : global (`THOT_AUTONOMY`) et par tenant (contrat §9, §4.2). */
export const AUTONOMY_MODES = ['manual', 'supervised', 'auto'] as const;
export type AutonomyMode = (typeof AUTONOMY_MODES)[number];

/** Rôles RBAC (contrat §4). */
export const ROLES = ['viewer', 'analyst', 'responder', 'admin'] as const;
export type Role = (typeof ROLES)[number];

/** Capacités RBAC (contrat §4). */
export const CAPABILITIES = [
  'read:events',
  'read:findings',
  'read:rules',
  'read:policies',
  'read:audit',
  'read:stats',
  'write:events',
  'write:findings',
  'execute:actions',
  'approve:actions',
  'admin:tenants',
  'admin:rules',
  'admin:keys',
  'admin:policies',
] as const;
export type Capability = (typeof CAPABILITIES)[number];

/** Formats de rapport de finding (contrat §4.8) — SARIF 2.1.0 inclus. */
export const REPORT_FORMATS = ['md', 'html', 'json', 'sarif'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** Formats d'export d'audit (contrat §4.7). */
export const AUDIT_EXPORT_FORMATS = ['jsonl', 'cef'] as const;
export type AuditExportFormat = (typeof AUDIT_EXPORT_FORMATS)[number];

/** Tri serveur des findings (contrat §4.4). */
export const FINDING_SORTS = ['risk_score', 'last_seen'] as const;
export type FindingSort = (typeof FINDING_SORTS)[number];

/** Sens de tri appliqué côté client sur la page courante. */
export type SortDirection = 'asc' | 'desc';

/** Types de frame du WebSocket (contrat §4.8). */
export const LIVE_FRAME_TYPES = ['event', 'finding', 'action', 'audit', 'heartbeat'] as const;
export type LiveFrameType = (typeof LIVE_FRAME_TYPES)[number];

/* -------------------------------------------------------------------------- */
/* §4.1 Santé, méta, observabilité                                             */
/* -------------------------------------------------------------------------- */

export interface HealthResponse {
  status: string;
  version: string;
  uptime_s: number;
}

export interface ReadyResponse {
  status: string;
  checks?: Record<string, string>;
}

/** `GET /version` — version, commit, licence, mode d'autonomie global. */
export interface ServerVersion {
  version: string;
  commit: string | null;
  license: string;
  autonomy: AutonomyMode;
  dry_run?: boolean;
  env?: string | null;
}

/** `GET /api/v1/auth/whoami` — tenant, rôle, capacités, mode d'autonomie. */
export interface WhoAmI {
  tenant_id: string;
  tenant_name?: string | null;
  role: Role;
  capabilities: Capability[];
  /** Mode d'autonomie effectif du tenant. */
  autonomy: AutonomyMode;
  /** `true` : aucune action réelle ne peut être exécutée (garde-fou global). */
  dry_run: boolean;
  key_id?: string | null;
  key_label?: string | null;
  auth_method?: string | null;
}

/* -------------------------------------------------------------------------- */
/* §4.2 Tenants & clés                                                         */
/* -------------------------------------------------------------------------- */

export interface Tenant {
  tenant_id: string;
  name: string;
  mode: AutonomyMode;
  dry_run: boolean;
  /** CIDR d'infra propre jamais ciblée par une action (contrat §6, garde-fou 3). */
  autonomy_allowlist: string[];
  created_at: string;
  updated_at: string;
}

export interface TenantCreateRequest {
  tenant_id: string;
  name: string;
  mode: AutonomyMode;
  autonomy_allowlist: string[];
}

export interface TenantPatchRequest {
  name?: string;
  mode?: AutonomyMode;
  dry_run?: boolean;
  autonomy_allowlist?: string[];
}

/** `POST /api/v1/tenants/{id}/keys` → `api_key` affichée une seule fois. */
export interface ApiKeyCreated {
  key_id: string;
  api_key: string;
}

export interface ApiKeyInfo {
  key_id: string;
  label: string | null;
  role: Role;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface CreateApiKeyRequest {
  role: Role;
  label?: string;
}

/* -------------------------------------------------------------------------- */
/* §4.3 Événements                                                             */
/* -------------------------------------------------------------------------- */

export interface EventSource {
  type: string;
  name?: string | null;
  host?: string | null;
}

/** Événement normalisé — immuable (contrat §3.1). */
export interface Event {
  event_id: string;
  schema_version: string;
  tenant_id: string;
  ts: string;
  kind: EventKind;
  source: EventSource;
  severity_hint: SeverityHint;
  labels: LabelMap;
  payload: JsonObject;
  /** Renseigné si `payload` a été tronqué (> 32 Kio sérialisé). */
  raw_ref: string | null;
}

/** Événement en cours d'ingestion : le serveur force `tenant_id` depuis la clé. */
export type EventInput = Omit<Event, 'tenant_id' | 'schema_version' | 'raw_ref'> &
  Partial<Pick<Event, 'tenant_id' | 'schema_version' | 'raw_ref'>>;

export interface IngestFindingRef {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  risk_score: number;
  decision: DecisionKind;
}

/** `POST /api/v1/events` → 202. */
export interface IngestResponse {
  accepted: number;
  rejected: number;
  event_ids: string[];
  findings: IngestFindingRef[];
}

export interface EventQuery {
  kind?: EventKind | '';
  source_type?: string;
  since?: string;
  until?: string;
  q?: string;
  limit?: number;
  cursor?: string | null;
}

/* -------------------------------------------------------------------------- */
/* §3.2 Finding                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Échantillon de preuve. Ces objets contiennent des **payloads d'attaque** :
 * ils ne doivent jamais être interprétés comme du HTML (aucun
 * `dangerouslySetInnerHTML` dans ce projet).
 */
export interface FindingEvidenceSample {
  ts?: string | null;
  labels?: LabelMap;
  payload?: JsonValue;
  [key: string]: JsonValue | undefined;
}

export interface FindingEvidence {
  samples?: FindingEvidenceSample[];
  [key: string]: JsonValue | FindingEvidenceSample[] | undefined;
}

export interface Finding {
  finding_id: string;
  tenant_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  status: FindingStatus;
  title: string;
  description: string;
  remediation: string;
  tags: string[];
  mitre: string[];
  evidence: FindingEvidence;
  first_seen: string;
  last_seen: string;
  count: number;
  event_ids: string[];
  created_at: string;
  updated_at: string;
}

/** `GET /api/v1/findings/{id}` : finding + actions liées. */
export interface FindingDetail extends Finding {
  actions: Action[];
}

export interface FindingQuery {
  status?: FindingStatus | '';
  severity?: Severity | '';
  rule_id?: string;
  since?: string;
  until?: string;
  min_risk?: number;
  sort?: FindingSort;
  limit?: number;
  cursor?: string | null;
}

export interface AckFindingRequest {
  comment?: string;
}

export interface CloseFindingRequest {
  resolution: Resolution;
  comment?: string;
}

export interface SuppressFindingRequest {
  duration_seconds: number;
  reason?: string;
}

export interface FindingStatusResponse {
  status: FindingStatus;
}

/* -------------------------------------------------------------------------- */
/* §3.3 Décision                                                               */
/* -------------------------------------------------------------------------- */

export interface Decision {
  decision: DecisionKind;
  policy_id: string;
  playbook: string | null;
  params: JsonObject;
  reason: string;
  risk_score: number;
  expires_at: string | null;
  cooldown_seconds: number;
  /** `true` : planification sans effet de bord (§6 garde-fou 4). */
  dry_run: boolean;
}

/* -------------------------------------------------------------------------- */
/* §3.4 Action                                                                 */
/* -------------------------------------------------------------------------- */

export interface ActionTarget {
  type: string;
  value: string;
}

export interface ActionRollbackState {
  available: boolean;
  token: string | null;
  performed_at: string | null;
  result: JsonValue;
}

export interface Action {
  action_id: string;
  tenant_id: string;
  finding_id: string;
  policy_id: string;
  playbook: string;
  status: ActionStatus;
  /** Mode d'autonomie du tenant au moment de la planification. */
  mode: AutonomyMode;
  dry_run: boolean;
  params: JsonObject;
  target: ActionTarget;
  requested_by: string;
  requested_at: string;
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  expires_at: string | null;
  result: JsonValue;
  rollback: ActionRollbackState;
  idempotency_key: string;
  audit_seq: number | null;
}

export interface ActionPlanRequest {
  finding_id: string;
  playbook: string;
  params?: JsonObject;
  dry_run?: boolean;
}

export interface ActionQuery {
  status?: ActionStatus | '';
  playbook?: string;
  finding_id?: string;
  limit?: number;
  cursor?: string | null;
}

export interface ApproveActionRequest {
  comment?: string;
}

export interface RejectActionRequest {
  reason: string;
}

/* -------------------------------------------------------------------------- */
/* §3.5 AuditRecord                                                            */
/* -------------------------------------------------------------------------- */

export interface AuditTarget {
  type: string;
  id: string;
}

export interface AuditRecord {
  seq: number;
  ts: string;
  tenant_id: string;
  actor: string;
  actor_role: Role;
  action: string;
  target: AuditTarget;
  before: JsonObject | null;
  after: JsonObject | null;
  prev_hash: string;
  hash: string;
}

/** `GET /api/v1/audit/verify`. */
export interface AuditVerifyResult {
  valid: boolean;
  records: number;
  broken_at: number | null;
}

export interface AuditQuery {
  since?: string;
  until?: string;
  action?: string;
  actor?: string;
  limit?: number;
  cursor?: string | null;
}

/* -------------------------------------------------------------------------- */
/* §4.5 Règles, politiques, playbooks                                          */
/* -------------------------------------------------------------------------- */

export interface RuleSummary {
  rule_id: string;
  title: string;
  severity: Severity;
  enabled: boolean;
  tags: string[];
  source_types: string[];
  kinds: EventKind[];
  path: string | null;
}

/** `GET /api/v1/rules/{rule_id}` : règle complète + YAML source (contrat §5). */
export interface RuleDetail extends RuleSummary {
  description: string | null;
  confidence: number | null;
  status: string | null;
  match: JsonObject | null;
  dedup: JsonObject | null;
  risk: JsonObject | null;
  false_positives: string[];
  remediation: string | null;
  references: string[];
  /** YAML source exact, affiché tel quel (échappé). */
  yaml: string | null;
}

export interface RuleValidationResult {
  valid: boolean;
  errors: string[];
}

export interface RuleReloadResult {
  loaded: number;
  errors: string[];
}

export interface PolicyThen {
  decision: DecisionKind;
  playbook?: string | null;
  params?: JsonObject;
  dry_run?: boolean;
  cooldown_seconds?: number;
  max_actions_per_hour?: number;
}

export interface PolicyRollback {
  playbook?: string | null;
  auto_after_seconds?: number;
}

/** Politique policy-as-code chargée (contrat §6). `when` est laissé générique. */
export interface PolicyRecord {
  id: string;
  version: number | null;
  priority: number;
  description: string | null;
  when: JsonObject | null;
  then: PolicyThen;
  rollback: PolicyRollback | null;
  path: string | null;
}

export interface PoliciesResponse {
  items: PolicyRecord[];
}

export interface PolicyReloadResult {
  loaded: number;
  errors: string[];
}

export interface PlaybookParamSpec {
  type: string;
  required?: boolean;
  default?: JsonValue;
  description?: string | null;
  min?: number | null;
  max?: number | null;
  enum?: JsonValue[];
}

export interface Playbook {
  name: string;
  description: string;
  params_schema: Record<string, PlaybookParamSpec>;
  /** `false` interdit toute exécution (contrat §1 invariant 3). */
  reversible: boolean;
  dry_run_capable: boolean;
  connectors: string[];
}

/* -------------------------------------------------------------------------- */
/* §4.6 Actions : planification                                                */
/* -------------------------------------------------------------------------- */

/* (voir §3.4 ci-dessus : `Action`, `ActionPlanRequest`, `ActionQuery`) */

/* -------------------------------------------------------------------------- */
/* §4.8 Stats, collecteurs                                                     */
/* -------------------------------------------------------------------------- */

export type SeverityCounts = Record<Severity, number>;

export interface TopRuleStat {
  rule_id: string;
  rule_name?: string | null;
  severity?: Severity | null;
  count: number;
}

/** `GET /api/v1/stats/overview` — compteurs 24 h/7 j + mode d'autonomie. */
export interface StatsOverview {
  events_24h: number;
  events_7d: number;
  findings_24h: number;
  findings_7d: number;
  findings_by_severity: SeverityCounts;
  open_findings: number;
  /** MTTA / MTTR en secondes (`null` si aucune donnée). */
  mtta_seconds: number | null;
  mttr_seconds: number | null;
  top_rules: TopRuleStat[];
  actions_succeeded: number;
  actions_failed: number;
  actions_rolled_back: number;
  actions_pending_approval: number;
  autonomy: AutonomyMode;
  dry_run: boolean;
  generated_at: string | null;
}

/** État d'un collecteur défensif (contrat §4.8). */
export interface CollectorState {
  name: string;
  kind: string | null;
  enabled: boolean;
  last_run_at: string | null;
  last_status: string | null;
  items_last_run: number | null;
  errors: string[];
  next_run_at: string | null;
}

export interface CollectorRunResult {
  collector: string;
  status: string;
  /** Nombre d'items collectés lors du run manuel. */
  items?: number | null;
  findings?: number | null;
  errors?: string[];
}

/* -------------------------------------------------------------------------- */
/* Enveloppes de liste et pagination par curseur                               */
/* -------------------------------------------------------------------------- */

/**
 * Enveloppe `{"items":[…]}` utilisée par le contrat (§4.2, §4.5, §4.4…).
 * `next_cursor` est lu avec tolérance (l'API peut exposer `cursor`).
 */
export interface ListEnvelope<T> {
  items: T[];
  cursor: string | null;
  next_cursor: string | null;
  total: number | null;
}

/* -------------------------------------------------------------------------- */
/* Erreurs normalisées (contrat §4.6)                                          */
/* -------------------------------------------------------------------------- */

/** Codes d'erreur du contrat, plus les codes produits côté client. */
export type ApiErrorCode =
  | 'validation_error'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'unprocessable'
  | 'rate_limited'
  | 'internal_error'
  | 'network_error'
  | 'aborted'
  | 'bad_response'
  | 'missing_api_key'
  | 'tenant_mismatch';

/** Corps d'erreur normalisé : `{"error":{"code","message","details"}}`. */
export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;
    details?: JsonObject | null;
  };
}

/* -------------------------------------------------------------------------- */
/* Frame WebSocket (contrat §4.8)                                              */
/* -------------------------------------------------------------------------- */

/**
 * Frame de flux : `data` reste un `JsonObject` brut car le flux est une entrée
 * non fiable. Le rendu passe par `toLiveRow()` (`lib/ws.ts`) qui échantillonne
 * les champs connus de façon défensive, sans cast dangereux.
 */
export interface LiveFrame {
  type: LiveFrameType;
  data: JsonObject;
}
