/**
 * Types du contrat d'interface Thot Secure v0.1.0 (ex-Thot Secure).
 *
 * Référence unique : `docs/architecture/api-contract.md`, **§3** (schémas JSON canoniques) et
 * **§4** (surface REST). Les noms de champs sont **exactement** ceux du contrat, en `snake_case`
 * (`risk_score`, `severity_hint`, `dry_run`, `audit_seq`…), afin que la documentation soit
 * valable telle quelle pour les trois SDK (Python, TypeScript, Go).
 *
 * Conventions de typage
 * ---------------------
 * 1. **Champ requis** = champ présent dans l'exemple du §3 (le serveur le renvoie toujours).
 * 2. **`| null`** = champ nullable d'après le contrat (`raw_ref`, `approved_by`, `rollback.token`…).
 * 3. **`?`** = réservé aux enrichissements explicitement documentés (ex. `actions` jointes à un
 *    `Finding` par `GET /findings/{id}`) — jamais utilisé pour masquer une incertitude.
 * 4. Aucun `any` : les structures ouvertes du contrat (`payload`, `params`, `evidence`, `result`)
 *    sont typées `JsonObject` / `unknown`, jamais `any`.
 *
 * Les types `*Input` décrivent les **corps de requête** acceptés par le serveur : ce sont eux qui
 * sont utilisés par `ThotSecureClient`, ce qui évite d'exiger de l'appelant des champs que le
 * serveur sait dériver (par exemple `tenant_id`, forcé depuis la clé API — contrat §4.3).
 */

/* ------------------------------------------------------------------------------------ */
/* Types scalaires et utilitaires                                                        */
/* ------------------------------------------------------------------------------------ */

/** Valeur JSON scalaire. */
export type Scalar = string | number | boolean | null;

/** Objet JSON quelconque (`payload`, `params`, `evidence`…). */
export type JsonObject = { [key: string]: JsonValue };

/** Valeur JSON quelconque. */
export type JsonValue = Scalar | JsonObject | JsonValue[];

/**
 * Étiquettes d'un événement : **objet plat à valeurs scalaires** (contrat §3.1).
 * C'est l'espace de nommage utilisé par les règles (`labels.src_ip`, `payload.status`).
 */
export type Labels = { [key: string]: Scalar };

/** Sévérité d'un finding (contrat §3.2). */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** `severity_hint` d'un événement : même échelle, ou `null` si inconnue (contrat §3.1). */
export type SeverityHint = Severity | null;

/** Types d'événement énumérés par le contrat §3.1. */
export type EventKind =
  | "http.request"
  | "http.response"
  | "log.line"
  | "tls.cert"
  | "dependency"
  | "config.audit"
  | "syslog"
  | "generic";

/** Cycle de vie d'un finding (contrat §3.2). */
export type FindingStatus = "open" | "acked" | "closed" | "suppressed";

/** Décision rendue par le moteur policy-as-code (contrat §3.3). */
export type DecisionKind = "auto" | "require_approval" | "notify_only" | "ignore";

/** Statuts d'une action SOAR (contrat §3.4). */
export type ActionStatus =
  | "planned"
  | "pending_approval"
  | "approved"
  | "rejected"
  | "executing"
  | "succeeded"
  | "failed"
  | "expired"
  | "rolled_back";

/** Mode d'autonomie d'un tenant (contrat §4.2). */
export type TenantMode = "manual" | "supervised" | "auto";

/** Rôles RBAC (contrat §4). */
export type Role = "viewer" | "analyst" | "responder" | "admin";

/** Capacités RBAC (contrat §4). */
export type Capability =
  | "read:events"
  | "read:findings"
  | "read:rules"
  | "read:policies"
  | "read:audit"
  | "read:stats"
  | "write:events"
  | "write:findings"
  | "execute:actions"
  | "approve:actions"
  | "admin:tenants"
  | "admin:rules"
  | "admin:keys"
  | "admin:policies";

/** Résolution d'un finding à la clôture (contrat §4.4). */
export type Resolution = "true_positive" | "false_positive" | "mitigated";

/** Formats de rapport (contrat §4.8). */
export type ReportFormat = "md" | "html" | "json" | "sarif";

/** Formats d'export d'audit (contrat §4.7). */
export type AuditExportFormat = "jsonl" | "cef";

/** Tri des findings (contrat §4.4). */
export type FindingSort = "risk_score" | "last_seen";

/* ------------------------------------------------------------------------------------ */
/* Constantes d'énumération (miroir des valeurs admises par le serveur)                   */
/* ------------------------------------------------------------------------------------ */

export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
export const EVENT_KINDS: readonly EventKind[] = [
  "http.request",
  "http.response",
  "log.line",
  "tls.cert",
  "dependency",
  "config.audit",
  "syslog",
  "generic",
];
export const FINDING_STATUSES: readonly FindingStatus[] = ["open", "acked", "closed", "suppressed"];
export const DECISIONS: readonly DecisionKind[] = ["auto", "require_approval", "notify_only", "ignore"];
export const ACTION_STATUSES: readonly ActionStatus[] = [
  "planned",
  "pending_approval",
  "approved",
  "rejected",
  "executing",
  "succeeded",
  "failed",
  "expired",
  "rolled_back",
];
export const TENANT_MODES: readonly TenantMode[] = ["manual", "supervised", "auto"];
export const ROLES: readonly Role[] = ["viewer", "analyst", "responder", "admin"];
export const RESOLUTIONS: readonly Resolution[] = ["true_positive", "false_positive", "mitigated"];
export const REPORT_FORMATS: readonly ReportFormat[] = ["md", "html", "json", "sarif"];
export const AUDIT_EXPORT_FORMATS: readonly AuditExportFormat[] = ["jsonl", "cef"];
export const FINDING_SORTS: readonly FindingSort[] = ["risk_score", "last_seen"];

/** Taille maximale d'un lot d'ingestion (contrat §4.3 : ≤ 500 événements). */
export const MAX_BATCH_SIZE = 500;

/** Taille maximale d'un `payload` d'événement sérialisé (contrat §3.1 : 32 Kio). */
export const MAX_PAYLOAD_BYTES = 32 * 1024;

/* ------------------------------------------------------------------------------------ */
/* §3.1 Event                                                                            */
/* ------------------------------------------------------------------------------------ */

/** Origine d'un événement (contrat §3.1). */
export interface EventSource {
  type: string;
  name: string;
  host: string;
}

/** `source` tel qu'accepté en entrée (le serveur complète les champs manquants). */
export interface EventSourceInput {
  type: string;
  name?: string;
  host?: string;
}

/** Événement normalisé, **immuable** (contrat §3.1). */
export interface Event {
  event_id: string;
  schema_version: string;
  tenant_id: string;
  /** Horodatage ISO 8601 UTC (`2026-02-14T10:00:00.123Z`). */
  ts: string;
  kind: EventKind;
  source: EventSource;
  severity_hint: SeverityHint;
  labels: Labels;
  payload: JsonObject;
  raw_ref: string | null;
}

/**
 * Corps accepté par `POST /api/v1/events` pour un événement (contrat §4.3).
 * `tenant_id` est **forcé depuis la clé API** côté serveur ; `event_id` et `ts` sont générés si
 * l'appelant les omet — d'où l'intérêt d'utiliser `normalizeNginxLine()` qui les renseigne.
 */
export interface EventInput {
  event_id?: string;
  schema_version?: string;
  tenant_id?: string;
  ts?: string;
  kind?: EventKind;
  source?: EventSourceInput;
  severity_hint?: SeverityHint;
  labels?: Labels;
  payload?: JsonObject;
  raw_ref?: string | null;
}

/* ------------------------------------------------------------------------------------ */
/* §3.2 Finding                                                                          */
/* ------------------------------------------------------------------------------------ */

/** Échantillon d'évidence attaché à un finding (contrat §3.2). */
export interface EvidenceSample {
  ts: string;
  labels: Labels;
}

/** Bloc `evidence` d'un finding (structure ouverte : le serveur peut l'enrichir). */
export interface Evidence {
  samples?: EvidenceSample[];
  [key: string]: JsonValue | EvidenceSample[] | undefined;
}

/** Agrégat d'événements déclenché par une règle, porteur d'un `risk_score` (contrat §3.2). */
export interface Finding {
  finding_id: string;
  tenant_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  /** Score de risque borné 0-100. */
  risk_score: number;
  /** Confiance de la règle, 0.0 → 1.0. */
  confidence: number;
  status: FindingStatus;
  title: string;
  description: string | null;
  remediation: string | null;
  tags: string[];
  /** Identifiants MITRE ATT&CK (`T1190`…). */
  mitre: string[];
  evidence: Evidence;
  first_seen: string;
  last_seen: string;
  count: number;
  event_ids: string[];
  created_at: string;
  updated_at: string;
  /** Actions liées, ajoutées par `GET /api/v1/findings/{id}` (contrat §4.4). */
  actions?: Action[];
}

/* ------------------------------------------------------------------------------------ */
/* §3.3 Decision                                                                         */
/* ------------------------------------------------------------------------------------ */

/** Décision du moteur policy-as-code (contrat §3.3). */
export interface Decision {
  decision: DecisionKind;
  policy_id: string | null;
  playbook: string | null;
  params: JsonObject;
  reason: string;
  risk_score: number | null;
  expires_at: string | null;
  cooldown_seconds: number | null;
  /** `true` = simulation : aucune action réelle ne sera exécutée. */
  dry_run: boolean;
}

/* ------------------------------------------------------------------------------------ */
/* §3.4 Action                                                                           */
/* ------------------------------------------------------------------------------------ */

/** Cible d'une action (`{"type":"ip","value":"203.0.113.9"}`). */
export interface ActionTarget {
  type: string;
  value: string;
  [key: string]: JsonValue | undefined;
}

/** État du rollback d'une action (contrat §3.4). */
export interface ActionRollback {
  available: boolean;
  /** Jeton opaque à présenter pour annuler l'action (`null` tant qu'elle n'a pas réussi). */
  token: string | null;
  performed_at: string | null;
  result: JsonObject | null;
}

/** Instance d'exécution d'un playbook, avec cycle de vie et audit (contrat §3.4). */
export interface Action {
  action_id: string;
  tenant_id: string;
  finding_id: string;
  policy_id: string | null;
  playbook: string;
  status: ActionStatus;
  /** Mode d'autonomie effectif au moment de la décision (`manual|supervised|auto`). */
  mode: TenantMode | string;
  /** `true` = aucune action réelle (sûreté par défaut, contrat §1 invariant 1). */
  dry_run: boolean;
  params: JsonObject;
  target: ActionTarget;
  requested_by: string;
  requested_at: string;
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  expires_at: string | null;
  result: JsonObject | null;
  rollback: ActionRollback;
  idempotency_key: string | null;
  /** Numéro de séquence dans le journal d'audit chaîné (§3.5). */
  audit_seq: number | null;
}

/** Statuts terminaux d'une action (hors rollback). */
export const TERMINAL_ACTION_STATUSES: readonly ActionStatus[] = [
  "rejected",
  "succeeded",
  "failed",
  "expired",
  "rolled_back",
];

/* ------------------------------------------------------------------------------------ */
/* §3.5 AuditRecord                                                                      */
/* ------------------------------------------------------------------------------------ */

/** Cible d'une entrée d'audit (`{"type":"action","id":"a91b…"}`). */
export interface AuditTarget {
  type: string;
  id: string;
  [key: string]: JsonValue | undefined;
}

/** Entrée du journal append-only chaîné par hash (contrat §3.5). */
export interface AuditRecord {
  seq: number;
  ts: string;
  tenant_id: string;
  actor: string;
  actor_role: Role | string;
  /** Verbe d'audit (`action.approve`, `action.execute`…). */
  action: string;
  target: AuditTarget;
  before: JsonObject;
  after: JsonObject;
  prev_hash: string;
  /** `sha256:…` calculé selon la formule du contrat §3.5. */
  hash: string;
}

/** Réponse de `GET /api/v1/audit/verify` (contrat §4.7). */
export interface AuditVerification {
  valid: boolean;
  records: number;
  /** Séquence de la première entrée cassée, `null` si la chaîne est intègre. */
  broken_at: number | null;
}

/* ------------------------------------------------------------------------------------ */
/* §4.2 Tenant et clés API                                                               */
/* ------------------------------------------------------------------------------------ */

/** Frontière d'isolation multi-tenant (contrat §4.2). */
export interface Tenant {
  tenant_id: string;
  name: string;
  mode: TenantMode;
  /** `true` = aucune action réelle pour ce tenant. */
  dry_run: boolean;
  /** Réseaux protégés (infra propre) sur lesquels **aucune** action n'est possible (§6). */
  autonomy_allowlist: string[];
  created_at: string;
  updated_at: string;
}

/** Corps de `POST /api/v1/tenants`. */
export interface CreateTenantInput {
  tenant_id: string;
  name: string;
  mode?: TenantMode;
  autonomy_allowlist?: string[];
  dry_run?: boolean;
}

/**
 * Corps de `PATCH /api/v1/tenants/{id}`.
 *
 * ⚠️ Activer `mode: "auto"` ou `dry_run: false` change le niveau d'autonomie d'un tenant :
 * c'est une décision de sécurité volontaire, limitée et journalisée (contrat §6).
 */
export interface UpdateTenantInput {
  mode?: TenantMode;
  dry_run?: boolean;
  name?: string;
  autonomy_allowlist?: string[];
}

/** Métadonnées d'une clé API. `api_key` n'est renseignée **qu'à la création** (contrat §4.2). */
export interface ApiKey {
  key_id: string;
  /** Valeur `ao_…` : **affichée une seule fois**, jamais relue, jamais journalisée. */
  api_key?: string;
  label: string | null;
  role: Role;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** Corps de `POST /api/v1/tenants/{id}/keys`. */
export interface CreateKeyInput {
  role: Role;
  label?: string;
}

/* ------------------------------------------------------------------------------------ */
/* §4.5 / §5 / §6 / §7 Règles, politiques, playbooks                                      */
/* ------------------------------------------------------------------------------------ */

/** Conditions d'une règle (`all` / `any` / `not` / `threshold`), contrat §5. */
export interface RuleMatch {
  all?: JsonObject[];
  any?: JsonObject[];
  not?: JsonObject[];
  threshold?: JsonObject;
}

/** Règle de détection (§4.5 liste, règle complète via `GET /rules/{rule_id}`, §5). */
export interface Rule {
  rule_id: string;
  title: string;
  description: string | null;
  /** `draft | test | stable | deprecated`. */
  status: string;
  severity: Severity;
  confidence: number;
  enabled: boolean;
  tags: string[];
  source_types: string[];
  kinds: EventKind[];
  /** Chemin du fichier YAML sur le serveur. */
  path: string;
  match: RuleMatch;
  dedup: JsonObject;
  risk: JsonObject;
  remediation: string | null;
  references: string[];
  /** YAML source, renvoyé par `GET /rules/{rule_id}`. */
  yaml_source?: string | null;
}

/** Résultat de `POST /api/v1/rules/validate` (contrat §4.5). */
export interface RuleValidation {
  valid: boolean;
  errors: JsonObject[];
}

/** Bloc `then` d'une politique (contrat §6). */
export interface PolicyThen {
  decision: DecisionKind;
  playbook?: string;
  params?: JsonObject;
  dry_run?: boolean;
  cooldown_seconds?: number;
  max_actions_per_hour?: number;
}

/** Bloc `rollback` d'une politique (contrat §6). */
export interface PolicyRollback {
  playbook?: string;
  auto_after_seconds?: number;
}

/** Politique de décision *policy-as-code* (contrat §6). */
export interface Policy {
  version: number;
  id: string;
  /** Plus grand = évalué d'abord. */
  priority: number;
  description: string | null;
  when: JsonObject;
  then: PolicyThen;
  rollback: PolicyRollback;
  /** Chemin du fichier sur le serveur, si exposé. */
  path?: string;
}

/** Réponse de `GET /api/v1/policies` : politiques chargées + ordre de priorité. */
export interface PolicyList {
  items: Policy[];
  count?: number;
  /** Champs supplémentaires éventuels (la réponse est ouverte côté serveur). */
  [key: string]: JsonValue | Policy[] | undefined;
}

/** Définition d'un paramètre de playbook (contrat §7). */
export interface PlaybookParam {
  type: string;
  required?: boolean;
  default?: JsonValue;
  description?: string;
  min?: number;
  max?: number;
}

/** Procédure d'action nommée, **toujours** accompagnée d'un rollback (contrat §4.5 / §7). */
export interface Playbook {
  name: string;
  description: string;
  params_schema: { [key: string]: PlaybookParam };
  /** `true` si un rollback existe réellement. */
  reversible: boolean;
  /** `true` si le playbook sait fonctionner en simulation. */
  dry_run_capable: boolean;
  /** Connecteurs utilisables (`cloudflare`, `null` / simulation…). */
  connectors: string[];
}

/** Réponse de `POST /api/v1/rules/reload` et `POST /api/v1/policies/reload`. */
export interface ReloadResult {
  loaded: number;
  errors: JsonObject[];
}

/* ------------------------------------------------------------------------------------ */
/* §4.8 Stats, collecteurs                                                               */
/* ------------------------------------------------------------------------------------ */

/** Compteurs agrégés 24 h / 7 j (contrat §4.8). */
export interface StatsOverview {
  window_24h: JsonObject;
  window_7d: JsonObject;
  events: JsonObject;
  findings_by_severity: { [key: string]: number };
  /** Délai moyen de prise en compte, en secondes. */
  mtta_seconds: number | null;
  /** Délai moyen de remédiation, en secondes. */
  mttr_seconds: number | null;
  top_rules: JsonObject[];
  actions_succeeded: number;
  actions_rolled_back: number;
  /** Mode d'autonomie effectif du tenant. */
  autonomy_mode: TenantMode | string;
}

/** État d'un collecteur : dernier run, items, erreurs (contrat §4.8). */
export interface CollectorStatus {
  name: string;
  type: string;
  enabled: boolean;
  status: string;
  last_run_at: string | null;
  last_success_at: string | null;
  items: number;
  errors: number;
  error: string | null;
}

/* ------------------------------------------------------------------------------------ */
/* Réponses composées                                                                    */
/* ------------------------------------------------------------------------------------ */

/** Finding issu d'une ingestion (élément de `findings[]`, contrat §4.3). */
export interface IngestOutcome {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  risk_score: number;
  decision: DecisionKind;
}

/** Réponse `202` de `POST /api/v1/events` (contrat §4.3). */
export interface IngestResult {
  accepted: number;
  rejected: number;
  event_ids: string[];
  findings: IngestOutcome[];
}

/** Réponse de `GET /api/v1/auth/whoami` (contrat §4.1). */
export interface WhoAmI {
  tenant_id: string;
  role: Role;
  capabilities: Capability[];
  /** `manual | supervised | auto`. */
  autonomy_mode: TenantMode | string;
  /** `true` = aucune action réelle ne sera exécutée. */
  dry_run: boolean;
  /** Champs supplémentaires éventuels. */
  [key: string]: JsonValue | Capability[] | undefined;
}

/** Réponse de `GET /healthz` (contrat §4.1). */
export interface HealthStatus {
  status: string;
  version: string;
  uptime_s: number;
}

/**
 * Réponse de `GET /readyz` (contrat §4.1).
 *
 * Un `503` alimente `status: "unavailable"` et `http_status: 503` **sans lever d'exception** :
 * c'est le comportement attendu par une sonde d'orchestrateur (voir `ThotSecureClient.readyz`).
 */
export interface ReadyStatus {
  status: string;
  http_status: number;
  version?: string;
  error?: string;
  details?: JsonObject;
}

/** Réponse de `GET /version` (contrat §4.1). */
export interface VersionInfo {
  version: string;
  commit: string;
  license: string;
  /** Mode d'autonomie global (`THOT_AUTONOMY`, contrat §9). */
  autonomy_mode: TenantMode | string;
  [key: string]: JsonValue | undefined;
}

/** Page de résultats d'une route de liste (`limit` + `cursor`). */
export interface Page<T> {
  items: T[];
  /** Curseur de la page suivante, `null` en fin de liste. */
  next_cursor: string | null;
  /** Charge utile brute (utile si le serveur ajoute des compteurs). */
  raw: JsonObject;
}

/* ------------------------------------------------------------------------------------ */
/* Corps de requête des routes d'action                                                 */
/* ------------------------------------------------------------------------------------ */

/** Corps de `POST /api/v1/actions/plan` (contrat §4.6) — aucun effet de bord. */
export interface PlanActionInput {
  finding_id: string;
  playbook: string;
  params?: JsonObject;
  /** `true` par défaut : la planification reste une simulation tant que ce n'est pas levé. */
  dry_run?: boolean;
}

/** Corps de `POST /api/v1/actions/{id}/ack|close|suppress` d'un finding (contrat §4.4). */
export interface AckFindingInput {
  comment?: string;
}

export interface CloseFindingInput {
  resolution: Resolution;
  comment?: string;
}

export interface SuppressFindingInput {
  duration_seconds?: number;
  reason?: string;
}

/** Options de reprise d'un export d'audit (contrat §4.7). */
export interface AuditExportOptions {
  format?: AuditExportFormat;
  since?: string;
  until?: string;
}
