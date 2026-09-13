/**
 * Client HTTP typé Thot Secure — couvre **toutes** les routes du contrat §4.
 *
 * Principes :
 *  1. `X-API-Key` est le seul mécanisme d'authentification (contrat §4).
 *  2. Le `tenant_id` n'est **jamais** un paramètre choisi par l'utilisateur :
 *     il provient de `GET /auth/whoami` et sert de périmètre de données. Toute
 *     donnée reçue dont le `tenant_id` diffère du périmètre est rejetée
 *     (`forbidden`) avant tout rendu — exigence produit de sûreté.
 *  3. Les erreurs sont normalisées en `ThotSecureError` à partir de
 *     `{"error":{"code","message","details"}}` (contrat §4.6).
 *  4. `AbortSignal` est propagé tel quel ; une annulation est réémise en
 *     erreur `AbortError` non encapsulée, pour que TanStack Query l'ignore.
 */
import type {
  AckFindingRequest,
  Action,
  ActionPlanRequest,
  ActionQuery,
  ApiErrorBody,
  ApiErrorCode,
  ApiKeyCreated,
  ApiKeyInfo,
  ApproveActionRequest,
  AuditExportFormat,
  AuditQuery,
  AuditRecord,
  AuditVerifyResult,
  CloseFindingRequest,
  CollectorRunResult,
  CollectorState,
  CreateApiKeyRequest,
  Event,
  EventInput,
  EventQuery,
  Finding,
  FindingDetail,
  FindingQuery,
  FindingSort,
  FindingStatus,
  FindingStatusResponse,
  HealthResponse,
  IngestResponse,
  JsonObject,
  JsonValue,
  ListEnvelope,
  Playbook,
  PoliciesResponse,
  PolicyReloadResult,
  ReadyResponse,
  RejectActionRequest,
  ReportFormat,
  RuleDetail,
  RuleReloadResult,
  RuleSummary,
  RuleValidationResult,
  ServerVersion,
  StatsOverview,
  SuppressFindingRequest,
  Tenant,
  TenantCreateRequest,
  TenantPatchRequest,
  WhoAmI,
} from './types';

/* -------------------------------------------------------------------------- */
/* Constantes                                                                  */
/* -------------------------------------------------------------------------- */

export const API_KEY_HEADER = 'X-API-Key';
export const DEFAULT_API_BASE_URL = '/api/v1';
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

const CODE_BY_STATUS: Record<number, ApiErrorCode> = {
  400: 'validation_error',
  401: 'unauthenticated',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  422: 'unprocessable',
  429: 'rate_limited',
  500: 'internal_error',
  502: 'internal_error',
  503: 'internal_error',
  504: 'internal_error',
};

/* -------------------------------------------------------------------------- */
/* Erreur normalisée                                                           */
/* -------------------------------------------------------------------------- */

export interface ThotSecureErrorInit {
  code: ApiErrorCode;
  message: string;
  status?: number;
  details?: JsonObject | null;
  path?: string | null;
  requestId?: string | null;
  cause?: unknown;
}

export class ThotSecureError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly details: JsonObject | null;
  readonly path: string | null;
  readonly requestId: string | null;

  constructor(init: ThotSecureErrorInit) {
    super(init.message, init.cause !== undefined ? { cause: init.cause } : undefined);
    this.name = 'ThotSecureError';
    this.code = init.code;
    this.status = init.status ?? 0;
    this.details = init.details ?? null;
    this.path = init.path ?? null;
    this.requestId = init.requestId ?? null;
  }

  /** `true` si réessayer ne peut pas aboutir sans intervention humaine. */
  get isClientError(): boolean {
    return this.status >= 400 && this.status < 500;
  }

  get isAuthError(): boolean {
    return this.code === 'unauthenticated' || this.code === 'missing_api_key';
  }

  get isForbidden(): boolean {
    return this.code === 'forbidden';
  }

  get isTenantMismatch(): boolean {
    return this.code === 'tenant_mismatch' || this.code === 'forbidden';
  }
}

export function isThotSecureError(value: unknown): value is ThotSecureError {
  return value instanceof ThotSecureError;
}

export function isAbortError(value: unknown): boolean {
  if (!value) return false;
  if (typeof value === 'object' && 'name' in value) {
    return (value as { name?: unknown }).name === 'AbortError';
  }
  return false;
}

/** Message affichable pour n'importe quelle erreur (jamais de HTML). */
export function errorMessage(value: unknown): string {
  if (isThotSecureError(value)) return value.message;
  if (value instanceof Error) return value.message;
  if (typeof value === 'string') return value;
  return 'Erreur inconnue.';
}

/**
 * Politique de retry TanStack Query : jamais sur 4xx/annulation, deux essais
 * sur réseau/5xx.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (isAbortError(error)) return false;
  if (isThotSecureError(error)) {
    if (error.code === 'unauthenticated' || error.code === 'forbidden') return false;
    if (error.code === 'missing_api_key' || error.code === 'tenant_mismatch') return false;
    if (error.isClientError) return false;
  }
  return failureCount < 2;
}

/* -------------------------------------------------------------------------- */
/* Résolution des URL                                                          */
/* -------------------------------------------------------------------------- */

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

/**
 * Base d'API : `VITE_THOT_API_URL` si défini, sinon le proxy relatif
 * `/api/v1` (proxy Vite en dev, nginx en production).
 */
export function resolveApiBaseUrl(explicit?: string): string {
  const fromEnv =
    explicit ??
    (typeof import.meta !== 'undefined' && import.meta.env
      ? import.meta.env.VITE_THOT_API_URL
      : undefined);
  const raw = (fromEnv ?? DEFAULT_API_BASE_URL).trim();
  if (raw === '') return DEFAULT_API_BASE_URL;
  return stripTrailingSlash(raw);
}

/**
 * Base « racine » (hors `/api/v1`) pour `/healthz`, `/readyz`, `/version` et
 * `/openapi.json` (contrat §4.1). Si la base ne contient pas `/api/v1`, la
 * racine est la base elle-même.
 */
export function resolveRootBaseUrl(apiBaseUrl?: string): string {
  const base = stripTrailingSlash(resolveApiBaseUrl(apiBaseUrl));
  return base.endsWith('/api/v1') ? base.slice(0, -'/api/v1'.length) : base;
}

/* -------------------------------------------------------------------------- */
/* Utilitaires internes                                                        */
/* -------------------------------------------------------------------------- */

type QueryValue = string | number | boolean | null | undefined;

/** Construit la chaîne de requête en omettant `undefined`, `null` et `''`. */
export function buildQuery(params: Record<string, QueryValue> | undefined): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query === '' ? '' : `?${query}`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function asJsonObject(value: unknown): JsonObject | null {
  return asRecord(value) === null ? null : (value as JsonObject);
}

/**
 * Normalise une réponse de liste : `{"items":[…]}` (contrat) ou tableau nu
 * (tolérance défensive). Toute autre forme lève `bad_response`.
 */
export function normalizeList<T>(payload: unknown, path: string): ListEnvelope<T> {
  if (Array.isArray(payload)) {
    return { items: payload as T[], cursor: null, next_cursor: null, total: null };
  }
  const record = asRecord(payload);
  if (record) {
    const items = record['items'] ?? record['data'] ?? record['results'];
    if (Array.isArray(items)) {
      const cursor = asString(record['cursor']);
      const nextCursor = asString(record['next_cursor']) ?? asString(record['nextCursor']) ?? cursor;
      return {
        items: items as T[],
        cursor,
        next_cursor: nextCursor,
        total: asNumber(record['total']) ?? asNumber(record['count']),
      };
    }
  }
  throw new ThotSecureError({
    code: 'bad_response',
    status: 200,
    path,
    message: 'Réponse de liste inattendue (clé « items » absente).',
  });
}

interface RawRequest {
  path: string;
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  /** `true` : la route est hors préfixe `/api/v1` (`/healthz`, `/version`…). */
  rootScoped?: boolean;
  /** `false` : endpoint public, aucun en-tête d'authentification. */
  authenticated?: boolean;
  query?: Record<string, QueryValue>;
  jsonBody?: unknown;
  rawBody?: string;
  contentType?: string;
  responseKind?: 'json' | 'text' | 'void';
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface ThotSecureClientOptions {
  baseUrl?: string;
  apiKey?: string | null;
  /**
   * Périmètre de données, **imposé par la clé API** (valeur de
   * `whoami.tenant_id`). Jamais saisi par l'utilisateur.
   */
  tenantId?: string | null;
}

/* -------------------------------------------------------------------------- */
/* Client                                                                      */
/* -------------------------------------------------------------------------- */

export class ThotSecureClient {
  readonly baseUrl: string;
  readonly rootUrl: string;
  apiKey: string | null;
  tenantId: string | null;

  constructor(options: ThotSecureClientOptions = {}) {
    this.baseUrl = resolveApiBaseUrl(options.baseUrl);
    this.rootUrl = resolveRootBaseUrl(this.baseUrl);
    this.apiKey = options.apiKey ?? null;
    this.tenantId = options.tenantId ?? null;
  }

  /** Met à jour les identifiants (clé + périmètre issu de `whoami`). */
  setCredentials(apiKey: string | null, tenantId: string | null): void {
    this.apiKey = apiKey;
    this.tenantId = tenantId;
  }

  get isAuthenticated(): boolean {
    return typeof this.apiKey === 'string' && this.apiKey.trim() !== '';
  }

  /**
   * Périmètre de données courant. Lève si inconnu : mieux vaut refuser une
   * requête que d'interroger l'API sans périmètre explicite.
   */
  requireTenantScope(): string {
    const tenantId = this.tenantId;
    if (!tenantId) {
      throw new ThotSecureError({
        code: 'tenant_mismatch',
        status: 0,
        message:
          'Périmètre tenant inconnu : « whoami » doit être chargé avant toute requête de données.',
      });
    }
    return tenantId;
  }

  /** Vérifie qu'un identifiant de tenant correspond bien au périmètre de la clé. */
  assertTenantScope(tenantId: string | null | undefined, resource: string): void {
    const scope = this.requireTenantScope();
    if (!tenantId || tenantId !== scope) {
      throw new ThotSecureError({
        code: 'tenant_mismatch',
        status: 403,
        message: `Accès refusé : « ${resource} » appartient au tenant « ${tenantId ?? 'inconnu'} », hors du périmètre « ${scope} » de la clé API.`,
      });
    }
  }

  /**
   * Filtre de sûreté appliqué à toute liste de données : une ligne dont le
   * `tenant_id` diffère du périmètre fait échouer la requête entière (fail
   * closed) plutôt que d'afficher partiellement des données d'un autre tenant.
   */
  private guardTenant<T extends { tenant_id?: string | null }>(items: T[], resource: string): T[] {
    const scope = this.tenantId;
    if (!scope) return items;
    for (const item of items) {
      const itemTenant = item.tenant_id;
      if (itemTenant !== undefined && itemTenant !== null && itemTenant !== scope) {
        throw new ThotSecureError({
          code: 'forbidden',
          status: 403,
          message: `Données hors périmètre reçues pour « ${resource} » (tenant « ${itemTenant} » ≠ « ${scope} »). Affichage bloqué.`,
        });
      }
    }
    return items;
  }

  private async send<T>(request: RawRequest): Promise<T> {
    const base = request.rootScoped ? this.rootUrl : this.baseUrl;
    const url = `${base}${request.path}${buildQuery(request.query)}`;

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (request.authenticated !== false) {
      const key = this.apiKey;
      if (!key || key.trim() === '') {
        throw new ThotSecureError({
          code: 'missing_api_key',
          status: 401,
          path: request.path,
          message: 'Aucune clé API configurée : saisissez une clé `ao_…` pour interroger l’API.',
        });
      }
      headers[API_KEY_HEADER] = key;
    }

    let body: string | undefined;
    if (request.rawBody !== undefined) {
      body = request.rawBody;
      headers['Content-Type'] = request.contentType ?? 'text/plain; charset=utf-8';
    } else if (request.jsonBody !== undefined) {
      body = JSON.stringify(request.jsonBody);
      headers['Content-Type'] = 'application/json';
    }

    // Annulation externe + délai maximal, fusionnés dans un seul signal.
    const controller = new AbortController();
    const timeoutMs = request.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs);
    const externalSignal = request.signal;
    const onExternalAbort = (): void => controller.abort(externalSignal?.reason);
    if (externalSignal) {
      if (externalSignal.aborted) {
        clearTimeout(timer);
        throw new DOMException('Requête annulée.', 'AbortError');
      }
      externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }

    let response: Response;
    try {
      response = await fetch(url, {
        method: request.method ?? 'GET',
        headers,
        body,
        signal: controller.signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch (cause) {
      if (isAbortError(cause) || externalSignal?.aborted) {
        // Une annulation volontaire n'est pas une erreur applicative.
        if (externalSignal?.aborted) throw new DOMException('Requête annulée.', 'AbortError');
        throw new ThotSecureError({
          code: 'network_error',
          status: 0,
          path: request.path,
          message: `Délai dépassé (${timeoutMs} ms) : API Thot Secure injoignable.`,
          cause,
        });
      }
      throw new ThotSecureError({
        code: 'network_error',
        status: 0,
        path: request.path,
        message: 'API Thot Secure injoignable (réseau ou proxy).',
        cause,
      });
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    }

    if (response.status === 204) {
      await response.text().catch(() => '');
      return undefined as T;
    }

    if (!response.ok) throw await this.toError(response, request.path);

    const kind = request.responseKind ?? 'json';
    if (kind === 'text') return (await response.text()) as unknown as T;
    if (kind === 'void') {
      await response.text().catch(() => '');
      return undefined as T;
    }

    const text = await response.text();
    if (text.trim() === '') return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch (cause) {
      throw new ThotSecureError({
        code: 'bad_response',
        status: response.status,
        path: request.path,
        message: 'Réponse JSON invalide.',
        cause,
      });
    }
  }

  private async toError(response: Response, path: string): Promise<ThotSecureError> {
    let code: ApiErrorCode = CODE_BY_STATUS[response.status] ?? 'internal_error';
    let message = `Erreur HTTP ${response.status}.`;
    let details: JsonObject | null = null;

    const raw = await response.text().catch(() => '');
    if (raw.trim() !== '') {
      try {
        const parsed: unknown = JSON.parse(raw);
        const envelope = asRecord(asRecord(parsed)?.['error']);
        if (envelope) {
          code = (asString(envelope['code']) as ApiErrorCode | null) ?? code;
          message = asString(envelope['message']) ?? message;
          details = asJsonObject(envelope['details']);
        } else {
          // Repli : `HTTPException` FastAPI (`{"detail": "…"}`).
          message = asString(asRecord(parsed)?.['detail']) ?? message;
        }
      } catch {
        message = raw.slice(0, 300);
      }
    }

    const requestId =
      response.headers.get('x-request-id') ?? response.headers.get('x-correlation-id');

    return new ThotSecureError({
      code,
      status: response.status,
      message,
      details,
      path,
      requestId,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.1 Santé, méta, observabilité                                         */
  /* ---------------------------------------------------------------------- */

  health(options: RequestOptions = {}): Promise<HealthResponse> {
    return this.send<HealthResponse>({
      path: '/healthz',
      rootScoped: true,
      authenticated: false,
      responseKind: 'json',
      signal: options.signal,
      timeoutMs: 8_000,
    });
  }

  readyz(options: RequestOptions = {}): Promise<ReadyResponse> {
    return this.send<ReadyResponse>({
      path: '/readyz',
      rootScoped: true,
      authenticated: false,
      responseKind: 'json',
      signal: options.signal,
      timeoutMs: 8_000,
    });
  }

  serverVersion(options: RequestOptions = {}): Promise<ServerVersion> {
    return this.send<ServerVersion>({
      path: '/version',
      rootScoped: true,
      authenticated: false,
      responseKind: 'json',
      signal: options.signal,
      timeoutMs: 8_000,
    });
  }

  /** `GET /api/v1/auth/whoami` — tenant, rôle, capacités, autonomie. */
  whoami(options: RequestOptions = {}): Promise<WhoAmI> {
    return this.send<WhoAmI>({ path: '/auth/whoami', signal: options.signal });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.2 Tenants & clés                                                     */
  /* ---------------------------------------------------------------------- */

  async listTenants(options: RequestOptions = {}): Promise<ListEnvelope<Tenant>> {
    const payload = await this.send<unknown>({ path: '/tenants', signal: options.signal });
    return normalizeList<Tenant>(payload, '/tenants');
  }

  createTenant(body: TenantCreateRequest, options: RequestOptions = {}): Promise<Tenant> {
    return this.send<Tenant>({ path: '/tenants', method: 'POST', jsonBody: body, signal: options.signal });
  }

  getTenant(tenantId: string, options: RequestOptions = {}): Promise<Tenant> {
    return this.send<Tenant>({
      path: `/tenants/${encodeURIComponent(tenantId)}`,
      signal: options.signal,
    });
  }

  patchTenant(
    tenantId: string,
    patch: TenantPatchRequest,
    options: RequestOptions = {},
  ): Promise<Tenant> {
    return this.send<Tenant>({
      path: `/tenants/${encodeURIComponent(tenantId)}`,
      method: 'PATCH',
      jsonBody: patch,
      signal: options.signal,
    });
  }

  /** Création de clé — `api_key` n'est renvoyée qu'une seule fois. */
  createApiKey(
    tenantId: string,
    body: CreateApiKeyRequest,
    options: RequestOptions = {},
  ): Promise<ApiKeyCreated> {
    return this.send<ApiKeyCreated>({
      path: `/tenants/${encodeURIComponent(tenantId)}/keys`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  async listApiKeys(
    tenantId: string,
    options: RequestOptions = {},
  ): Promise<ListEnvelope<ApiKeyInfo>> {
    const payload = await this.send<unknown>({
      path: `/tenants/${encodeURIComponent(tenantId)}/keys`,
      signal: options.signal,
    });
    return normalizeList<ApiKeyInfo>(payload, '/tenants/{id}/keys');
  }

  revokeApiKey(keyId: string, options: RequestOptions = {}): Promise<void> {
    return this.send<void>({
      path: `/keys/${encodeURIComponent(keyId)}`,
      method: 'DELETE',
      responseKind: 'void',
      signal: options.signal,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.3 Événements                                                         */
  /* ---------------------------------------------------------------------- */

  /**
   * Ingestion : un `Event` ou `{"events":[Event,…]}` (≤ 500).
   * Le `tenant_id` est forcé depuis la clé ; un événement déclarant un autre
   * tenant est refusé côté client avant tout envoi.
   */
  ingestEvents(
    input: EventInput | EventInput[] | { events: EventInput[] },
    options: RequestOptions = {},
  ): Promise<IngestResponse> {
    const scope = this.requireTenantScope();
    const rawEvents: EventInput[] = Array.isArray(input)
      ? input
      : 'events' in input
        ? input.events
        : [input];

    if (rawEvents.length === 0) {
      throw new ThotSecureError({
        code: 'validation_error',
        status: 400,
        path: '/events',
        message: 'Aucun événement à ingérer.',
      });
    }
    if (rawEvents.length > 500) {
      throw new ThotSecureError({
        code: 'validation_error',
        status: 400,
        path: '/events',
        message: `Lot trop volumineux (${rawEvents.length}) : maximum 500 événements par appel.`,
      });
    }

    const events = rawEvents.map((event) => {
      if (event.tenant_id && event.tenant_id !== scope) {
        throw new ThotSecureError({
          code: 'tenant_mismatch',
          status: 403,
          path: '/events',
          message: `Événement refusé : « tenant_id » = « ${event.tenant_id} » hors du périmètre « ${scope} » de la clé API.`,
        });
      }
      return { ...event, tenant_id: scope };
    });

    return this.send<IngestResponse>({
      path: '/events',
      method: 'POST',
      jsonBody: { events },
      signal: options.signal,
    });
  }

  async listEvents(
    query: EventQuery = {},
    options: RequestOptions = {},
  ): Promise<ListEnvelope<Event>> {
    this.requireTenantScope();
    const payload = await this.send<unknown>({
      path: '/events',
      query: {
        kind: query.kind,
        source_type: query.source_type,
        since: query.since,
        until: query.until,
        q: query.q,
        limit: query.limit,
        cursor: query.cursor,
      },
      signal: options.signal,
    });
    const envelope = normalizeList<Event>(payload, '/events');
    this.guardTenant(envelope.items, 'events');
    return envelope;
  }

  async getEvent(eventId: string, options: RequestOptions = {}): Promise<Event> {
    const event = await this.send<Event>({
      path: `/events/${encodeURIComponent(eventId)}`,
      signal: options.signal,
    });
    this.guardTenant([event], 'event');
    return event;
  }

  /* ---------------------------------------------------------------------- */
  /* §4.4 Findings                                                           */
  /* ---------------------------------------------------------------------- */

  async listFindings(
    query: FindingQuery = {},
    options: RequestOptions = {},
  ): Promise<ListEnvelope<Finding>> {
    this.requireTenantScope();
    const payload = await this.send<unknown>({
      path: '/findings',
      query: {
        status: query.status,
        severity: query.severity,
        rule_id: query.rule_id,
        since: query.since,
        until: query.until,
        min_risk: query.min_risk,
        sort: query.sort,
        limit: query.limit,
        cursor: query.cursor,
      },
      signal: options.signal,
    });
    const envelope = normalizeList<Finding>(payload, '/findings');
    this.guardTenant(envelope.items, 'findings');
    return envelope;
  }

  /** `GET /findings/{id}` → finding + actions liées. */
  async getFinding(findingId: string, options: RequestOptions = {}): Promise<FindingDetail> {
    const finding = await this.send<FindingDetail>({
      path: `/findings/${encodeURIComponent(findingId)}`,
      signal: options.signal,
    });
    this.guardTenant([finding], 'finding');
    if (Array.isArray(finding.actions)) this.guardTenant(finding.actions, 'action');
    return finding;
  }

  ackFinding(
    findingId: string,
    body: AckFindingRequest = {},
    options: RequestOptions = {},
  ): Promise<FindingStatusResponse> {
    return this.send<FindingStatusResponse>({
      path: `/findings/${encodeURIComponent(findingId)}/ack`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  closeFinding(
    findingId: string,
    body: CloseFindingRequest,
    options: RequestOptions = {},
  ): Promise<FindingStatusResponse> {
    return this.send<FindingStatusResponse>({
      path: `/findings/${encodeURIComponent(findingId)}/close`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  suppressFinding(
    findingId: string,
    body: SuppressFindingRequest,
    options: RequestOptions = {},
  ): Promise<FindingStatusResponse> {
    return this.send<FindingStatusResponse>({
      path: `/findings/${encodeURIComponent(findingId)}/suppress`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  /** Rapport exploitable (md | html | json | sarif) renvoyé en texte brut. */
  findingReport(
    findingId: string,
    format: ReportFormat,
    options: RequestOptions = {},
  ): Promise<string> {
    return this.send<string>({
      path: `/findings/${encodeURIComponent(findingId)}/report`,
      query: { format },
      responseKind: 'text',
      signal: options.signal,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.5 Règles, politiques, playbooks                                      */
  /* ---------------------------------------------------------------------- */

  async listRules(options: RequestOptions = {}): Promise<ListEnvelope<RuleSummary>> {
    const payload = await this.send<unknown>({ path: '/rules', signal: options.signal });
    return normalizeList<RuleSummary>(payload, '/rules');
  }

  getRule(ruleId: string, options: RequestOptions = {}): Promise<RuleDetail> {
    return this.send<RuleDetail>({
      path: `/rules/${encodeURIComponent(ruleId)}`,
      signal: options.signal,
    });
  }

  /** Validation d'une règle YAML/JSON (le corps est envoyé tel quel). */
  validateRule(source: string, options: RequestOptions = {}): Promise<RuleValidationResult> {
    return this.send<RuleValidationResult>({
      path: '/rules/validate',
      method: 'POST',
      rawBody: source,
      contentType: 'text/yaml; charset=utf-8',
      signal: options.signal,
    });
  }

  reloadRules(options: RequestOptions = {}): Promise<RuleReloadResult> {
    return this.send<RuleReloadResult>({
      path: '/rules/reload',
      method: 'POST',
      jsonBody: {},
      signal: options.signal,
    });
  }

  listPolicies(options: RequestOptions = {}): Promise<PoliciesResponse> {
    return this.send<PoliciesResponse>({ path: '/policies', signal: options.signal });
  }

  reloadPolicies(options: RequestOptions = {}): Promise<PolicyReloadResult> {
    return this.send<PolicyReloadResult>({
      path: '/policies/reload',
      method: 'POST',
      jsonBody: {},
      signal: options.signal,
    });
  }

  async listPlaybooks(options: RequestOptions = {}): Promise<ListEnvelope<Playbook>> {
    const payload = await this.send<unknown>({ path: '/playbooks', signal: options.signal });
    return normalizeList<Playbook>(payload, '/playbooks');
  }

  /* ---------------------------------------------------------------------- */
  /* §4.6 Actions (SOAR)                                                     */
  /* ---------------------------------------------------------------------- */

  /** Planification sans effet de bord (`planned`). */
  planAction(body: ActionPlanRequest, options: RequestOptions = {}): Promise<Action> {
    return this.send<Action>({
      path: '/actions/plan',
      method: 'POST',
      jsonBody: {
        finding_id: body.finding_id,
        playbook: body.playbook,
        params: body.params ?? {},
        dry_run: body.dry_run ?? true,
      },
      signal: options.signal,
    });
  }

  async listActions(
    query: ActionQuery = {},
    options: RequestOptions = {},
  ): Promise<ListEnvelope<Action>> {
    this.requireTenantScope();
    const payload = await this.send<unknown>({
      path: '/actions',
      query: {
        status: query.status,
        playbook: query.playbook,
        finding_id: query.finding_id,
        limit: query.limit,
        cursor: query.cursor,
      },
      signal: options.signal,
    });
    const envelope = normalizeList<Action>(payload, '/actions');
    this.guardTenant(envelope.items, 'actions');
    return envelope;
  }

  async getAction(actionId: string, options: RequestOptions = {}): Promise<Action> {
    const action = await this.send<Action>({
      path: `/actions/${encodeURIComponent(actionId)}`,
      signal: options.signal,
    });
    this.guardTenant([action], 'action');
    return action;
  }

  approveAction(
    actionId: string,
    body: ApproveActionRequest = {},
    options: RequestOptions = {},
  ): Promise<Action> {
    return this.send<Action>({
      path: `/actions/${encodeURIComponent(actionId)}/approve`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  rejectAction(
    actionId: string,
    body: RejectActionRequest,
    options: RequestOptions = {},
  ): Promise<Action> {
    return this.send<Action>({
      path: `/actions/${encodeURIComponent(actionId)}/reject`,
      method: 'POST',
      jsonBody: body,
      signal: options.signal,
    });
  }

  /** Exécution — refusée par l'API si `pending_approval` non approuvé (409). */
  executeAction(actionId: string, options: RequestOptions = {}): Promise<Action> {
    return this.send<Action>({
      path: `/actions/${encodeURIComponent(actionId)}/execute`,
      method: 'POST',
      jsonBody: {},
      signal: options.signal,
    });
  }

  /** Annulation (undo) — refusée si déjà `rolled_back` (409). */
  rollbackAction(actionId: string, options: RequestOptions = {}): Promise<Action> {
    return this.send<Action>({
      path: `/actions/${encodeURIComponent(actionId)}/rollback`,
      method: 'POST',
      jsonBody: {},
      signal: options.signal,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.7 Audit                                                              */
  /* ---------------------------------------------------------------------- */

  async listAudit(
    query: AuditQuery = {},
    options: RequestOptions = {},
  ): Promise<ListEnvelope<AuditRecord>> {
    this.requireTenantScope();
    const payload = await this.send<unknown>({
      path: '/audit',
      query: {
        since: query.since,
        until: query.until,
        action: query.action,
        actor: query.actor,
        limit: query.limit,
        cursor: query.cursor,
      },
      signal: options.signal,
    });
    const envelope = normalizeList<AuditRecord>(payload, '/audit');
    this.guardTenant(envelope.items, 'audit');
    return envelope;
  }

  /** Vérifie la chaîne de hash append-only (contrat §3.5). */
  verifyAudit(options: RequestOptions = {}): Promise<AuditVerifyResult> {
    return this.send<AuditVerifyResult>({
      path: '/audit/verify',
      responseKind: 'json',
      signal: options.signal,
    });
  }

  /** Export SIEM/SOAR (jsonl | cef) renvoyé en texte brut. */
  auditExport(format: AuditExportFormat, options: RequestOptions = {}): Promise<string> {
    return this.send<string>({
      path: '/audit/export',
      query: { format },
      responseKind: 'text',
      signal: options.signal,
      timeoutMs: 60_000,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* §4.8 Stats, collecteurs                                                 */
  /* ---------------------------------------------------------------------- */

  statsOverview(options: RequestOptions = {}): Promise<StatsOverview> {
    return this.send<StatsOverview>({ path: '/stats/overview', signal: options.signal });
  }

  async listCollectors(options: RequestOptions = {}): Promise<ListEnvelope<CollectorState>> {
    const payload = await this.send<unknown>({ path: '/collectors', signal: options.signal });
    return normalizeList<CollectorState>(payload, '/collectors');
  }

  /** Run manuel d'un collecteur, sur les cibles déclarées du tenant. */
  runCollector(name: string, options: RequestOptions = {}): Promise<CollectorRunResult> {
    return this.send<CollectorRunResult>({
      path: `/collectors/${encodeURIComponent(name)}/run`,
      method: 'POST',
      jsonBody: {},
      signal: options.signal,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Instance partagée                                                           */
/* -------------------------------------------------------------------------- */

/** Client « applicatif » : ses identifiants sont pilotés par `AuthProvider`. */
export const apiClient = new ThotSecureClient();

/** Fabrique un client isolé (tests, exports, scripts). */
export function createThotSecureClient(options: ThotSecureClientOptions = {}): ThotSecureClient {
  return new ThotSecureClient(options);
}

/** Réexport pratique pour typer les champs de tri côté pages. */
export type { FindingSort, FindingStatus, JsonValue };
export type { ApiErrorBody };
