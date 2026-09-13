/**
 * Types du widget « findings chauds » — Thot Secure (nom de code technique : Thot Secure).
 *
 * Source de vérité : `docs/architecture/api-contract.md`
 *   - §3.1 `Event`, §3.2 `Finding`, §3.4 `Action`, §3.5 `AuditRecord`
 *   - §4.8 flux WebSocket `GET /api/v1/ws/stream` :
 *     frames `{"type":"event|finding|action|audit|heartbeat","data":{…}}`
 *
 * Règles de conception :
 *  1. **Aucun `any`** : toute donnée serveur arrive en `unknown` et doit passer par les
 *     garde-fous de désérialisation de ce module (`normalizeFinding`, `asString`, …).
 *  2. Les noms de champs sont **exactement** ceux du contrat (`finding_id`, `risk_score`,
 *     `last_seen`…) : le widget ne renomme rien, il ne fait que tolérer l'absence de champs
 *     optionnels.
 *  3. Les champs optionnels sont déclarés `champ?: T | undefined` afin de rester compatibles
 *     avec `exactOptionalPropertyTypes` (une affectation explicite de `undefined` est licite).
 *  4. Aucune donnée n'est considérée comme fiable : le serveur (ou un proxy) peut envoyer des
 *     types inattendus, des chaînes vides ou du HTML. Les normalisateurs ne lèvent jamais.
 */

/* ------------------------------------------------------------------------------------ */
/* Constantes et types d'énumération (valeurs + types, utilisés aussi au runtime)        */
/* ------------------------------------------------------------------------------------ */

/**
 * Types de frames acceptés sur le flux. Les cinq premiers sont ceux du contrat §4.8 ;
 * `hello` est émis par le serveur de démonstration (`mock/stream-server.py`) et `raw`
 * désigne une frame illisible ou d'un type inconnu (jamais perdue : elle reste
 * consultable dans le panneau « derniers événements bruts »).
 */
export const FRAME_TYPES = [
  'event',
  'finding',
  'action',
  'audit',
  'heartbeat',
  'hello',
  'raw',
] as const;

export type FrameType = (typeof FRAME_TYPES)[number];

/** Sévérités du contrat §3.2. */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

export type Severity = (typeof SEVERITIES)[number];

/** Poids de tri/affichage par sévérité (le tri principal reste `risk_score`). */
export const SEVERITY_WEIGHTS: Readonly<Record<Severity, number>> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

/** Statuts de finding du contrat §3.2. */
export const FINDING_STATUSES = ['open', 'acked', 'closed', 'suppressed'] as const;

export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Statuts d'action du contrat §3.4. */
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

/** Types d'événements normalisés du contrat §3.1 (le champ `kind` reste tolérant). */
export type EventKind =
  | 'http.request'
  | 'http.response'
  | 'log.line'
  | 'tls.cert'
  | 'dependency'
  | 'config.audit'
  | 'syslog'
  | 'generic';

/* ------------------------------------------------------------------------------------ */
/* Schémas du contrat                                                                    */
/* ------------------------------------------------------------------------------------ */

/** §3.1 — `source` d'un événement. */
export interface EventSource {
  readonly type?: string | undefined;
  readonly name?: string | undefined;
  readonly host?: string | undefined;
}

/** §3.1 — fait brut normalisé. Le widget ne l'affiche que dans le panneau brut. */
export interface AegisEvent {
  readonly event_id: string;
  readonly schema_version?: string | undefined;
  readonly tenant_id?: string | undefined;
  readonly ts?: string | undefined;
  readonly kind?: string | undefined;
  readonly source?: EventSource | undefined;
  readonly severity_hint?: Severity | null | undefined;
  readonly labels?: Readonly<Record<string, string | number | boolean | null>> | undefined;
  readonly payload?: Readonly<Record<string, unknown>> | undefined;
  readonly raw_ref?: string | null | undefined;
}

/**
 * §3.2 — agrégat d'événements porteur d'un `risk_score`.
 * C'est la seule entité affichée dans la liste principale du widget.
 */
export interface Finding {
  readonly finding_id: string;
  readonly tenant_id?: string | undefined;
  readonly rule_id?: string | undefined;
  readonly rule_name?: string | undefined;
  readonly severity: Severity;
  readonly risk_score: number;
  readonly confidence?: number | undefined;
  readonly status?: FindingStatus | undefined;
  readonly title?: string | undefined;
  readonly description?: string | undefined;
  readonly remediation?: string | undefined;
  readonly tags?: readonly string[] | undefined;
  readonly mitre?: readonly string[] | undefined;
  readonly evidence?: Readonly<Record<string, unknown>> | undefined;
  readonly first_seen?: string | undefined;
  readonly last_seen?: string | undefined;
  readonly count?: number | undefined;
  readonly event_ids?: readonly string[] | undefined;
  readonly created_at?: string | undefined;
  readonly updated_at?: string | undefined;
}

/** §3.4 — cible d'une action. */
export interface ActionTarget {
  readonly type: string;
  readonly value: string;
}

/** §3.4 — bloc `rollback` d'une action (toute action est réversible, invariant §1.3). */
export interface ActionRollback {
  readonly available: boolean;
  readonly token?: string | null | undefined;
  readonly performed_at?: string | null | undefined;
  readonly result?: unknown;
}

/** §3.4 — instance d'exécution d'un playbook (affichée seulement dans le panneau brut). */
export interface Action {
  readonly action_id: string;
  readonly tenant_id?: string | undefined;
  readonly finding_id?: string | undefined;
  readonly policy_id?: string | undefined;
  readonly playbook?: string | undefined;
  readonly status: ActionStatus;
  readonly mode?: string | undefined;
  readonly dry_run?: boolean | undefined;
  readonly params?: Readonly<Record<string, unknown>> | undefined;
  readonly target?: ActionTarget | undefined;
  readonly requested_by?: string | undefined;
  readonly requested_at?: string | undefined;
  readonly approved_by?: string | null | undefined;
  readonly approved_at?: string | null | undefined;
  readonly executed_at?: string | null | undefined;
  readonly expires_at?: string | null | undefined;
  readonly result?: unknown;
  readonly rollback?: ActionRollback | undefined;
  readonly idempotency_key?: string | undefined;
  readonly audit_seq?: number | undefined;
}

/** §3.5 — entrée du journal d'audit chaîné. */
export interface AuditRecord {
  readonly seq: number;
  readonly ts: string;
  readonly tenant_id?: string | undefined;
  readonly actor?: string | undefined;
  readonly actor_role?: string | undefined;
  readonly action?: string | undefined;
  readonly target?: Readonly<Record<string, unknown>> | undefined;
  readonly before?: Readonly<Record<string, unknown>> | null | undefined;
  readonly after?: Readonly<Record<string, unknown>> | null | undefined;
  readonly prev_hash?: string | undefined;
  readonly hash?: string | undefined;
}

/** Charge utile de la frame `hello` (extension de démonstration, non normative). */
export interface HelloData {
  readonly server?: string | undefined;
  readonly version?: string | undefined;
  readonly tenant_id?: string | undefined;
  readonly heartbeat_seconds?: number | undefined;
  readonly types?: readonly string[] | undefined;
  readonly message?: string | undefined;
}

/* ------------------------------------------------------------------------------------ */
/* Frames du flux temps réel                                                             */
/* ------------------------------------------------------------------------------------ */

/**
 * Frame applicative décodée, telle que livrée aux callbacks.
 *
 * `data` reste en `unknown` : c'est à l'appelant de la normaliser (`normalizeFinding`).
 * `text` conserve la charge utile d'origine pour le panneau « brut » — utile pour
 * diagnostiquer une frame dont le type ou la structure surprend.
 */
export interface StreamFrame {
  readonly type: FrameType;
  readonly data: unknown;
  readonly raw: Readonly<Record<string, unknown>>;
  readonly text: string;
  /** Horodatage de réception (epoch millisecondes, horloge locale du navigateur). */
  readonly received_at: number;
  /** Numéro d'ordre croissant attribué par le client (utile pour compter les pertes). */
  readonly seq: number;
}

/* ------------------------------------------------------------------------------------ */
/* Configuration et état du widget                                                       */
/* ------------------------------------------------------------------------------------ */

/**
 * Configuration complète du widget.
 *
 * ⚠️ `apiKey` est la clé saisie par l'utilisateur : elle n'est **jamais** écrite dans le
 * dépôt, ni journalisée, ni incluse dans une URL affichée (voir `redactUrl`). Elle n'est
 * persistée dans `localStorage` que si `rememberApiKey` est explicitement coché.
 */
export interface WidgetConfig {
  readonly baseUrl: string;
  readonly tenantId: string;
  readonly apiKey: string;
  /** Types de frames conservés (les autres sont comptées puis ignorées). */
  readonly types: readonly FrameType[];
  /** Nombre maximum de cartes de findings affichées (défaut 25). */
  readonly maxCards: number;
  /** Nombre maximum de frames brutes conservées pour le panneau de diagnostic. */
  readonly maxRawFrames: number;
  /** Capacité de la file bornée qui tamponne les frames quand l'affichage est en pause. */
  readonly ringCapacity: number;
  /** Délai sans aucune frame au-delà duquel la connexion est jugée morte. */
  readonly heartbeatTimeoutMs: number;
  readonly maxReconnectAttempts: number;
  readonly backoffBaseMs: number;
  readonly backoffMaxMs: number;
  /**
   * Gabarit du lien facultatif de chaque carte. Variables : `{baseUrl}` et `{finding_id}`.
   * Une chaîne vide masque le bouton. Seuls les schémas `http`/`https` sont acceptés
   * (protection contre `javascript:` / `data:`).
   */
  readonly findingLinkTemplate: string;
  /** Mémoriser la clé API dans `localStorage` de ce poste (décoché par défaut). */
  readonly rememberApiKey: boolean;
}

/** État de connexion exposé par le client WebSocket. */
export type ConnectionState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'closed'
  | 'error';

/** Événement d'état (jamais de clé API : `url` est déjà masquée). */
export interface ConnectionStatusEvent {
  readonly state: ConnectionState;
  /** Numéro de la tentative de reconnexion en cours (0 = première connexion). */
  readonly attempt: number;
  readonly maxAttempts: number;
  /** Délai annoncé avant la prochaine tentative, en millisecondes. */
  readonly delayMs: number | null;
  /** Message lisible par un humain (déjà nettoyé via `redactUrl`). */
  readonly message: string | null;
  /** URL du flux, **masquée**. */
  readonly url: string | null;
  readonly at: number;
}

/** Codes d'erreur du widget (affichés à l'utilisateur, jamais de secret dedans). */
export type WidgetErrorCode =
  | 'config_error'
  | 'ws_error'
  | 'ws_closed'
  | 'ws_security'
  | 'parse_error'
  | 'ring_overflow'
  | 'callback_error';

/** Erreur affichable. Le message a déjà traversé `redactUrl`. */
export interface WidgetError {
  readonly code: WidgetErrorCode;
  readonly message: string;
  readonly url: string | null;
  readonly at: number;
}

/* ------------------------------------------------------------------------------------ */
/* Garde-fous de désérialisation (aucune confiance dans le serveur)                      */
/* ------------------------------------------------------------------------------------ */

/** `true` si la valeur est un objet JSON « dictionnaire » (pas un tableau, pas `null`). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Chaîne non vide, ou `null` (les chaînes vides et les espaces seuls sont rejetés). */
export function asString(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed === '' ? null : trimmed;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return null;
}

/** Nombre fini, ou `null` (accepte aussi une chaîne numérique : certains proxys envoient du texte). */
export function asNumber(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '') {
      return null;
    }
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/** Booléen, ou `null`. */
export function asBoolean(value: unknown): boolean | null {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if (lowered === 'true' || lowered === '1') {
      return true;
    }
    if (lowered === 'false' || lowered === '0') {
      return false;
    }
  }
  return null;
}

/** Liste de chaînes non vides (ignore les entrées d'un autre type). */
export function asStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const items: string[] = [];
  for (const item of value) {
    const text = asString(item);
    if (text !== null) {
      items.push(text);
    }
  }
  return items;
}

/** Borne une valeur numérique dans `[min, max]` (les `NaN` sont ramenés à `min`). */
export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(max, Math.max(min, value));
}

/** `true` si la valeur est une sévérité du contrat. */
export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

/** Sévérité du contrat, sinon `info` (une valeur inconnue ne doit pas casser l'affichage). */
export function coerceSeverity(value: unknown): Severity {
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if ((SEVERITIES as readonly string[]).includes(lowered)) {
      return lowered as Severity;
    }
  }
  return 'info';
}

/** `true` si la valeur est un type de frame connu. */
export function isFrameType(value: unknown): value is FrameType {
  return typeof value === 'string' && (FRAME_TYPES as readonly string[]).includes(value);
}

/** Statut de finding, ou `undefined` si la valeur n'est pas reconnue. */
export function coerceFindingStatus(value: unknown): FindingStatus | undefined {
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if ((FINDING_STATUSES as readonly string[]).includes(lowered)) {
      return lowered as FindingStatus;
    }
  }
  return undefined;
}

/** Statut d'action, ou `planned` si la valeur n'est pas reconnue. */
export function coerceActionStatus(value: unknown): ActionStatus {
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if ((ACTION_STATUSES as readonly string[]).includes(lowered)) {
      return lowered as ActionStatus;
    }
  }
  return 'planned';
}

/** Identifiant de secours, déterministe, pour une frame `finding` sans `finding_id`. */
function syntheticFindingId(raw: Record<string, unknown>): string {
  const ruleId = asString(raw['rule_id']) ?? 'regle-inconnue';
  const seen = asString(raw['last_seen']) ?? asString(raw['first_seen']) ?? '';
  const title = (asString(raw['title']) ?? '').slice(0, 32);
  return 'synthetique:' + ruleId + ':' + seen + ':' + title;
}

/**
 * Convertit une charge utile inconnue en `Finding` exploitable.
 *
 * Retourne `null` seulement si la frame ne contient ni `finding_id` ni `title` : dans ce cas
 * il n'y a réellement rien à afficher (la frame brute reste visible dans le panneau brut).
 * `risk_score` absent ou non numérique est ramené à `0` : le widget n'invente jamais un score.
 */
export function normalizeFinding(value: unknown): Finding | null {
  if (!isRecord(value)) {
    return null;
  }
  const findingId = asString(value['finding_id']);
  const title = asString(value['title']);
  if (findingId === null && title === null) {
    return null;
  }
  const severity = coerceSeverity(value['severity']);
  const risk = asNumber(value['risk_score']);
  const confidence = asNumber(value['confidence']);
  const count = asNumber(value['count']);
  const tags = asStringArray(value['tags']);
  const mitre = asStringArray(value['mitre']);
  const evidence = value['evidence'];
  const eventIds = asStringArray(value['event_ids']);

  return {
    finding_id: findingId ?? syntheticFindingId(value),
    tenant_id: asString(value['tenant_id']) ?? undefined,
    rule_id: asString(value['rule_id']) ?? undefined,
    rule_name: asString(value['rule_name']) ?? undefined,
    severity,
    risk_score: risk === null ? 0 : clamp(risk, 0, 100),
    confidence: confidence === null ? undefined : clamp(confidence, 0, 1),
    status: coerceFindingStatus(value['status']),
    title: title ?? undefined,
    description: asString(value['description']) ?? undefined,
    remediation: asString(value['remediation']) ?? undefined,
    tags: tags === null ? undefined : tags,
    mitre: mitre === null ? undefined : mitre,
    evidence: isRecord(evidence) ? evidence : undefined,
    first_seen: asString(value['first_seen']) ?? undefined,
    last_seen: asString(value['last_seen']) ?? undefined,
    count: count === null ? undefined : Math.max(0, Math.trunc(count)),
    event_ids: eventIds === null ? undefined : eventIds,
    created_at: asString(value['created_at']) ?? undefined,
    updated_at: asString(value['updated_at']) ?? undefined,
  };
}

/**
 * Convertit une charge utile inconnue en `Action` exploitable.
 * Retourne `null` s'il n'y a pas d'`action_id` (rien d'identifiable à afficher).
 */
export function normalizeAction(value: unknown): Action | null {
  if (!isRecord(value)) {
    return null;
  }
  const actionId = asString(value['action_id']);
  if (actionId === null) {
    return null;
  }
  const params = value['params'];
  const target = value['target'];
  const rollback = value['rollback'];
  const dryRun = asBoolean(value['dry_run']);
  const auditSeq = asNumber(value['audit_seq']);

  let normalizedTarget: ActionTarget | undefined;
  if (isRecord(target)) {
    const targetType = asString(target['type']);
    const targetValue = asString(target['value']);
    if (targetType !== null && targetValue !== null) {
      normalizedTarget = { type: targetType, value: targetValue };
    }
  }

  let normalizedRollback: ActionRollback | undefined;
  if (isRecord(rollback)) {
    const available = asBoolean(rollback['available']);
    normalizedRollback = {
      available: available === null ? false : available,
      token: asString(rollback['token']),
      performed_at: asString(rollback['performed_at']),
      result: rollback['result'],
    };
  }

  return {
    action_id: actionId,
    tenant_id: asString(value['tenant_id']) ?? undefined,
    finding_id: asString(value['finding_id']) ?? undefined,
    policy_id: asString(value['policy_id']) ?? undefined,
    playbook: asString(value['playbook']) ?? undefined,
    status: coerceActionStatus(value['status']),
    mode: asString(value['mode']) ?? undefined,
    dry_run: dryRun === null ? undefined : dryRun,
    params: isRecord(params) ? params : undefined,
    target: normalizedTarget,
    requested_by: asString(value['requested_by']) ?? undefined,
    requested_at: asString(value['requested_at']) ?? undefined,
    approved_by: asString(value['approved_by']),
    approved_at: asString(value['approved_at']),
    executed_at: asString(value['executed_at']),
    expires_at: asString(value['expires_at']),
    result: value['result'],
    rollback: normalizedRollback,
    idempotency_key: asString(value['idempotency_key']) ?? undefined,
    audit_seq: auditSeq === null ? undefined : Math.trunc(auditSeq),
  };
}

/** Convertit la charge utile d'une frame `hello` (extension de démonstration, tolérante). */
export function normalizeHello(value: unknown): HelloData {
  if (!isRecord(value)) {
    return {};
  }
  const heartbeat = asNumber(value['heartbeat_seconds']);
  const types = asStringArray(value['types']);
  return {
    server: asString(value['server']) ?? undefined,
    version: asString(value['version']) ?? undefined,
    tenant_id: asString(value['tenant_id']) ?? undefined,
    heartbeat_seconds: heartbeat === null ? undefined : heartbeat,
    types: types === null ? undefined : types,
    message: asString(value['message']) ?? undefined,
  };
}
