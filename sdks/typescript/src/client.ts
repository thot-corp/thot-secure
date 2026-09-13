/**
 * Client TypeScript officiel pour l'API REST Thot Secure v0.1.0 (ex-Thot Secure).
 *
 * Le client couvre **l'intégralité** de la surface décrite par le contrat d'interface
 * (`docs/architecture/api-contract.md` §4), sans inventer de route :
 *
 * * §4.1 santé / méta / observabilité ;
 * * §4.2 tenants et clés API ;
 * * §4.3 événements (unitaire et par lots ≤ 500) ;
 * * §4.4 findings (ack / close / suppress / rapport) ;
 * * §4.5 règles, politiques, playbooks ;
 * * §4.6 actions SOAR (plan / approve / reject / execute / rollback) ;
 * * §4.7 audit (liste, vérification de chaîne, export SIEM) ;
 * * §4.8 stats, collecteurs, flux temps réel.
 *
 * Les **noms de méthodes sont identiques au SDK Python** (`list_findings`, `plan_action`…) afin
 * que la documentation soit valable pour les deux langages ; seule la forme des paramètres suit
 * l'idiome de chaque écosystème (objet d'options en TypeScript, arguments nommés en Python).
 *
 * Sécurité : la clé API n'est **jamais** journalisée, `fetch` est injectable (tests hors ligne),
 * les délais sont bornés par `AbortSignal`, et l'URL du WebSocket est masquée par `redactUrl()`
 * avant toute trace.
 */

import {
  ThotSecureError,
  RateLimitedError,
  ServerError,
  TransportError,
  ValidationError,
  errorFromResponse,
  redactUrl,
} from "./errors";
import { chunked, newEventId, readEnv } from "./helpers";
import { isRetrySafe, retryingFetch, type RetryInfo, type RetryPolicy } from "./retry";
import type {
  AckFindingInput,
  Action,
  ActionStatus,
  AuditExportFormat,
  AuditExportOptions,
  AuditRecord,
  AuditVerification,
  ApiKey,
  CloseFindingInput,
  CollectorStatus,
  CreateKeyInput,
  CreateTenantInput,
  Event,
  EventInput,
  EventKind,
  Finding,
  FindingSort,
  FindingStatus,
  HealthStatus,
  IngestResult,
  JsonObject,
  Page,
  PlanActionInput,
  Playbook,
  PolicyList,
  ReadyStatus,
  ReloadResult,
  ReportFormat,
  Resolution,
  Role,
  Rule,
  RuleValidation,
  Severity,
  StatsOverview,
  SuppressFindingInput,
  Tenant,
  TenantMode,
  UpdateTenantInput,
  VersionInfo,
  WhoAmI,
} from "./types";
import {
  ACTION_STATUSES,
  AUDIT_EXPORT_FORMATS,
  FINDING_SORTS,
  MAX_BATCH_SIZE,
  REPORT_FORMATS,
  RESOLUTIONS,
  ROLES,
  SEVERITIES,
  TENANT_MODES,
} from "./types";
import {
  ThotSecureStream,
  buildWebSocketUrl,
  type StreamFrame,
  type StreamOptions,
  type WebSocketLike,
} from "./ws";

/** Racine par défaut du service (contrat §4 : préfixe `/api/v1` ajouté par le client). */
export const DEFAULT_BASE_URL = "http://127.0.0.1:8080";

/** Préfixe des routes métier (contrat §4). */
export const API_PREFIX = "/api/v1";

/** Signature minimale de `fetch` acceptée par le client (injectable pour les tests). */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Journalisation minimale : aucun secret n'y transite jamais. */
export interface Logger {
  debug(message: string, context?: Record<string, unknown>): void;
  info(message: string, context?: Record<string, unknown>): void;
  warn(message: string, context?: Record<string, unknown>): void;
  error(message: string, context?: Record<string, unknown>): void;
}

/** Options du client (toutes les valeurs par défaut sont sûres). */
export interface ThotSecureClientOptions {
  /** Racine du service. Défaut : `THOT_SECURE_URL`, puis `THOT_URL`, puis `http://127.0.0.1:8080`. */
  baseUrl?: string | undefined;
  /** Clé API `ao_…`. Défaut : `THOT_SECURE_API_KEY`, puis `THOT_API_KEY`. */
  apiKey?: string | undefined;
  /** Tenant utilisé pour les routes préfixées et l'URL du WebSocket. */
  tenantId?: string | undefined;
  /** Délai par requête, en millisecondes (défaut 30 000). */
  timeoutMs?: number | undefined;
  /** Nombre de tentatives supplémentaires (défaut 3). */
  maxRetries?: number | undefined;
  /** Surcharge fine de la politique de reprise. */
  retryPolicy?: Partial<RetryPolicy> | undefined;
  /** Implémentation `fetch` (tests, proxy maison, instrumentation). */
  fetch?: FetchLike | undefined;
  /** En-tête `User-Agent`. */
  userAgent?: string | undefined;
  /** Journalisation (défaut : avertissements sur la console). */
  logger?: Logger | undefined;
  /** Attente injectable (tests déterministes). */
  sleep?: ((delayMs: number, signal?: AbortSignal) => Promise<void>) | undefined;
  /** Source d'aléa injectable pour le jitter. */
  random?: (() => number) | undefined;
  /** Fabrique de WebSocket (tests, `ws` en Node < 22). */
  webSocketFactory?: ((url: string) => WebSocketLike) | undefined;
}

/** Sous-ensemble de l'API `WebSocket` utilisée par le SDK (défini dans `ws.ts`, réexporté ici). */
export type { WebSocketLike };

/** Options communes à tous les appels HTTP. */
export interface RequestOptions {
  /** Annulation de l'appel (et de son éventuelle reprise). */
  signal?: AbortSignal | undefined;
  /** Surcharge du délai par requête. */
  timeoutMs?: number | undefined;
  /** Clé d'idempotence : rend un `POST` réessayable sans risque de doublon (contrat §4.6). */
  idempotencyKey?: string | undefined;
  /** En-têtes supplémentaires. */
  headers?: Record<string, string> | undefined;
  /** Force ou interdit la reprise (`undefined` = décision automatique). */
  retrySafe?: boolean | undefined;
}

/** Options des routes de liste paginées. */
export interface PaginatedRequestOptions extends RequestOptions {
  /** Nombre maximal de pages suivies par les itérateurs (`iter_*`). Défaut 1000. */
  maxPages?: number | undefined;
}

interface ListEventsOptions extends PaginatedRequestOptions {
  kind?: EventKind | undefined;
  source_type?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
  q?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

interface ListFindingsOptions extends PaginatedRequestOptions {
  status?: FindingStatus | undefined;
  severity?: Severity | undefined;
  rule_id?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
  min_risk?: number | undefined;
  sort?: FindingSort | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

interface ListActionsOptions extends PaginatedRequestOptions {
  status?: ActionStatus | undefined;
  playbook?: string | undefined;
  finding_id?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

interface ListAuditOptions extends PaginatedRequestOptions {
  since?: string | undefined;
  until?: string | undefined;
  action?: string | undefined;
  actor?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

/** Options d'ingestion par lots (`ingest_events`). */
export interface IngestOptions extends RequestOptions {
  /** Taille des lots ; le contrat impose ≤ 500 (défaut 500). */
  chunkSize?: number | undefined;
  /**
   * Rappel appelé après **chaque** lot confirmé : c'est le point d'ancrage de la contre-pression
   * (le flux source ne doit produire le lot suivant qu'une fois celui-ci accepté).
   */
  onBatch?: ((result: IngestResult, batchIndex: number) => void | Promise<void>) | undefined;
}

/** Options de `get_report()` / `export_audit()`. */
export interface BinaryRequestOptions extends RequestOptions {
  /** `true` → `Uint8Array` au lieu d'une chaîne UTF-8. */
  asBytes?: boolean | undefined;
}

/** Options de `readyz()`. */
export interface ReadyzOptions extends RequestOptions {
  /** `true` → lève `ServerError` sur `503` au lieu de retourner `status: "unavailable"`. */
  raiseOnError?: boolean | undefined;
}

interface PerformOptions {
  query?: Record<string, string | number | boolean | null | undefined> | undefined;
  json?: unknown;
  text?: { body: string; contentType: string } | undefined;
  headers?: Record<string, string> | undefined;
  auth?: boolean | undefined;
  accept?: string | undefined;
  request?: RequestOptions | undefined;
}

/** Valeur exploitable dans une chaîne de requête. */
type QueryValue = string | number | boolean | null | undefined;

/** Journalisation par défaut : silencieuse en `debug`/`info`, visible pour les avertissements. */
const defaultLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (message, context) => {
    console.warn(`[thot-secure-sdk] ${message}`, context ?? "");
  },
  error: (message, context) => {
    console.error(`[thot-secure-sdk] ${message}`, context ?? "");
  },
};

/** Sérialise des paramètres de requête (booléens en minuscules, `null`/`undefined` retirés). */
function queryString(params: Record<string, QueryValue> | undefined): string {
  if (!params) {
    return "";
  }
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") {
      continue;
    }
    search.set(key, typeof value === "boolean" ? (value ? "true" : "false") : String(value));
  }
  const serialized = search.toString();
  return serialized === "" ? "" : `?${serialized}`;
}

/** Normalise les formes de réponse d'une route de liste (`{"items":[…]}`, `{"data":[…]}`, `[…]`). */
export function pageFromPayload<T>(payload: unknown): Page<T> {
  if (Array.isArray(payload)) {
    return { items: payload as T[], next_cursor: null, raw: {} };
  }
  if (typeof payload === "object" && payload !== null) {
    const record = payload as Record<string, unknown>;
    const rawItems = record["items"] ?? record["data"];
    let items: T[];
    if (Array.isArray(rawItems)) {
      items = rawItems as T[];
    } else if (rawItems === null || rawItems === undefined) {
      items = [];
    } else {
      items = [rawItems as T];
    }
    const cursor = record["next_cursor"] ?? record["cursor"];
    return {
      items,
      next_cursor: typeof cursor === "string" ? cursor : null,
      raw: record as JsonObject,
    };
  }
  return { items: [], next_cursor: null, raw: {} };
}

/** Itère une route paginée en suivant `next_cursor`, avec protection anti-boucle. */
async function* paginate<T>(
  fetchPage: (cursor: string | null, signal?: AbortSignal | undefined) => Promise<Page<T>>,
  options: PaginatedRequestOptions,
): AsyncGenerator<T, void, undefined> {
  const maxPages = options.maxPages ?? 1000;
  const seen = new Set<string>();
  let cursor: string | null = options.cursor ?? null;
  let pages = 0;
  for (;;) {
    const page = await fetchPage(cursor, options.signal);
    for (const item of page.items) {
      yield item;
    }
    pages += 1;
    const next = page.next_cursor;
    if (next === null || next === "" || seen.has(next) || pages >= maxPages) {
      return;
    }
    seen.add(next);
    cursor = next;
  }
}

/** Vérifie qu'une valeur appartient à une énumération du contrat. */
function requireEnum<T extends string>(
  value: T,
  allowed: readonly T[],
  label: string,
): T {
  if (!allowed.includes(value)) {
    throw new ValidationError(`${label} invalide : « ${value} » (attendu : ${allowed.join(", ")})`, {
      code: "validation_error",
      details: { field: label, value, allowed: [...allowed] },
    });
  }
  return value;
}

/**
 * Client synchrone… pardon, **asynchrone** : toutes les méthodes retournent une `Promise`.
 *
 * ```ts
 * const client = new ThotSecureClient({
 *   baseUrl: process.env.THOT_SECURE_URL,
 *   apiKey: process.env.THOT_SECURE_API_KEY,
 *   tenantId: "acme",
 * });
 * const page = await client.list_findings({ status: "open", sort: "risk_score" });
 * client.close();
 * ```
 */
export class ThotSecureClient {
  /** Racine du service, sans `/` final. */
  readonly base_url: string;
  /** Clé API éventuelle (jamais journalisée, jamais incluse dans un `toString`). */
  readonly api_key: string | undefined;
  /** Tenant par défaut. */
  readonly tenant_id: string | undefined;
  /** Délai par requête, en millisecondes. */
  readonly timeout_ms: number;
  /** Nombre de tentatives supplémentaires. */
  readonly max_retries: number;
  /** En-tête `User-Agent`. */
  readonly user_agent: string;

  private readonly fetchImpl: FetchLike;
  private readonly logger: Logger;
  private readonly retryPolicy: Partial<RetryPolicy>;
  private readonly sleep: ((delayMs: number, signal?: AbortSignal | undefined) => Promise<void>) | undefined;
  private readonly random: (() => number) | undefined;
  private readonly webSocketFactory: ((url: string) => WebSocketLike) | undefined;
  private closed = false;

  constructor(options: ThotSecureClientOptions = {}) {
    const baseUrl =
      options.baseUrl ?? readEnv("THOT_SECURE_URL", "THOT_URL") ?? DEFAULT_BASE_URL;
    const normalized = baseUrl.replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(normalized)) {
      throw new ValidationError(
        `baseUrl doit commencer par http:// ou https:// (reçu : « ${baseUrl} »)`,
        { code: "validation_error" },
      );
    }
    this.base_url = normalized;
    this.api_key = options.apiKey ?? readEnv("THOT_SECURE_API_KEY", "THOT_API_KEY");
    this.tenant_id = options.tenantId ?? readEnv("THOT_SECURE_TENANT_ID", "THOT_TENANT_ID");
    this.timeout_ms = options.timeoutMs ?? 30_000;
    this.max_retries = Math.max(0, options.maxRetries ?? 3);
    this.user_agent = options.userAgent ?? "thot-secure-sdk-typescript/0.1.0";

    const globalFetch = globalThis.fetch;
    if (options.fetch === undefined && typeof globalFetch !== "function") {
      throw new ThotSecureError(
        "aucune implémentation de fetch disponible : utilisez Node ≥ 18, un navigateur récent, " +
          "ou passez `fetch` explicitement au constructeur",
        { code: "transport_error", retryable: false },
      );
    }
    this.fetchImpl = options.fetch ?? ((input, init) => globalFetch(input, init));
    this.logger = options.logger ?? defaultLogger;
    this.retryPolicy = options.retryPolicy ?? {};
    this.sleep = options.sleep;
    this.random = options.random;
    this.webSocketFactory = options.webSocketFactory;
  }

  /* ------------------------------------------------------------------------------ */
  /* Cycle de vie et utilitaires bas niveau                                          */
  /* ------------------------------------------------------------------------------ */

  /** Représentation sûre : la clé API n'y apparaît jamais. */
  override toString(): string {
    return `ThotSecureClient(base_url=${this.base_url}, tenant_id=${this.tenant_id ?? "null"}, api_key=${
      this.api_key ? "'***'" : "null"
    })`;
  }

  /** Libère les ressources. Le client reste utilisable (stateless) mais les flux sont coupés. */
  close(): void {
    this.closed = true;
  }

  /** `true` après `close()`. */
  get is_closed(): boolean {
    return this.closed;
  }

  /** Construit une URL absolue à partir d'un chemin (`/healthz`, `/api/v1/…` ou URL complète). */
  private url(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      return path;
    }
    return `${this.base_url}${path.startsWith("/") ? "" : "/"}${path}`;
  }

  /** Construit le chemin métier (`/api/v1/…`). */
  private api(path: string): string {
    return `${API_PREFIX}${path.startsWith("/") ? "" : "/"}${path}`;
  }

  /** Construit les en-têtes d'un appel. */
  private buildHeaders(options: PerformOptions): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: options.accept ?? "application/json",
      "User-Agent": this.user_agent,
    };
    if (options.auth !== false && this.api_key !== undefined && this.api_key !== "") {
      headers["X-API-Key"] = this.api_key;
    }
    const idempotencyKey = options.request?.idempotencyKey;
    if (idempotencyKey !== undefined && idempotencyKey !== "") {
      headers["Idempotency-Key"] = idempotencyKey;
    }
    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
    } else if (options.text !== undefined) {
      headers["Content-Type"] = options.text.contentType;
    }
    return { ...headers, ...(options.headers ?? {}) };
  }

  /** Exécute un appel HTTP avec la politique de reprise du SDK. */
  private async perform(
    method: string,
    path: string,
    options: PerformOptions = {},
  ): Promise<Response> {
    if (this.closed) {
      throw new ThotSecureError("client fermé (close() a été appelé)", {
        code: "client_closed",
        retryable: false,
      });
    }
    const request = options.request ?? {};
    const fullUrl = this.url(path) + queryString(options.query);
    const headers = this.buildHeaders(options);

    let body: string | undefined;
    if (options.json !== undefined) {
      body = JSON.stringify(options.json);
    } else if (options.text !== undefined) {
      body = options.text.body;
    }

    const retrySafe = request.retrySafe ?? isRetrySafe(method, request.idempotencyKey);
    const timeoutMs = request.timeoutMs ?? this.timeout_ms;

    const response = await retryingFetch(
      (attempt) => this.dispatch(method, fullUrl, headers, body, timeoutMs, request.signal, attempt),
      {
        policy: { ...this.retryPolicy, maxRetries: this.retryPolicy.maxRetries ?? this.max_retries },
        retrySafe,
        signal: request.signal,
        sleep: this.sleep,
        random: this.random,
        onRetry: (info: RetryInfo) => {
          this.logger.warn(
            `nouvel essai dans ${info.delayMs} ms (${info.reason}) ${method} ${redactUrl(fullUrl) ?? ""}`,
            { attempt: info.attempt, status_code: info.statusCode },
          );
        },
      },
    );

    if (response.status >= 400) {
      throw await this.toError(response, method, fullUrl);
    }
    return response;
  }

  /** Un aller-retour HTTP, avec délai d'attente par tentative. */
  private async dispatch(
    method: string,
    fullUrl: string,
    headers: Record<string, string>,
    body: string | undefined,
    timeoutMs: number,
    signal: AbortSignal | undefined,
    attempt: number,
  ): Promise<Response> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const onOuterAbort = (): void => controller.abort();
    signal?.addEventListener("abort", onOuterAbort, { once: true });

    try {
      const init: RequestInit = { method, headers, signal: controller.signal };
      if (body !== undefined) {
        init.body = body;
      }
      return await this.fetchImpl(fullUrl, init);
    } catch (error) {
      if (signal?.aborted === true) {
        throw error;
      }
      if (timedOut) {
        throw new TransportError(
          `délai dépassé après ${timeoutMs} ms (tentative ${attempt + 1})`,
          { method, url: fullUrl },
        );
      }
      throw new TransportError(`échec du transport : ${describeError(error)}`, {
        method,
        url: fullUrl,
        cause: error,
      });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onOuterAbort);
    }
  }

  /** Convertit une réponse en erreur typée du contrat (§4.6). */
  private async toError(response: Response, method: string, fullUrl: string): Promise<ThotSecureError> {
    let rawText = "";
    try {
      rawText = await response.text();
    } catch {
      rawText = "";
    }
    let payload: unknown = null;
    if (rawText.trim() !== "") {
      try {
        payload = JSON.parse(rawText);
      } catch {
        payload = null;
      }
    }
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    return errorFromResponse(response.status, payload, {
      method,
      url: fullUrl,
      headers,
      rawText,
    });
  }

  /** Décode le corps JSON d'une réponse (`null` si le corps est vide). */
  private async parseJson<T>(response: Response): Promise<T> {
    const text = await response.text();
    if (text.trim() === "") {
      return null as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch (error) {
      throw new ThotSecureError(
        `réponse non JSON (${response.status}) : ${text.slice(0, 200)}`,
        { code: "invalid_response", statusCode: response.status, cause: error },
      );
    }
  }

  /** Appel JSON typé. */
  private async jsonCall<T>(method: string, path: string, options: PerformOptions = {}): Promise<T> {
    const response = await this.perform(method, path, options);
    return this.parseJson<T>(response);
  }

  /** Appel texte (rapports, métriques, export d'audit). */
  private async textCall(method: string, path: string, options: PerformOptions = {}): Promise<string> {
    const response = await this.perform(method, path, options);
    return response.text();
  }

  /** Appel binaire (rapports, export d'audit). */
  private async bytesCall(
    method: string,
    path: string,
    options: PerformOptions = {},
  ): Promise<Uint8Array> {
    const response = await this.perform(method, path, options);
    return new Uint8Array(await response.arrayBuffer());
  }

  /** Résout le tenant à utiliser (`read:stats` self, contrat §4.2). */
  private requireTenant(tenantId?: string | undefined): string {
    const resolved = tenantId ?? this.tenant_id;
    if (resolved === undefined || resolved === "") {
      throw new ValidationError(
        "aucun tenant_id : passez-le en argument, au constructeur, ou via THOT_SECURE_TENANT_ID",
        { code: "validation_error" },
      );
    }
    return resolved;
  }

  /** Renseigne `tenant_id` depuis la configuration du client s'il a été omis. */
  private fillTenant(event: EventInput): EventInput {
    if (
      (event.tenant_id === undefined || event.tenant_id === "") &&
      this.tenant_id !== undefined &&
      this.tenant_id !== ""
    ) {
      return { ...event, tenant_id: this.tenant_id };
    }
    return event;
  }

  /* ============================================================================== */
  /* §4.1 Santé, méta, observabilité                                                 */
  /* ============================================================================== */

  /** `GET /api/v1/auth/whoami` → tenant, rôle, capacités, mode d'autonomie. */
  async whoami(request: RequestOptions = {}): Promise<WhoAmI> {
    return this.jsonCall<WhoAmI>("GET", this.api("/auth/whoami"), { request });
  }

  /** `GET /healthz` (public) → `{"status","version","uptime_s"}`. */
  async healthz(request: RequestOptions = {}): Promise<HealthStatus> {
    return this.jsonCall<HealthStatus>("GET", "/healthz", { request, auth: false });
  }

  /**
   * `GET /readyz` (public) — vérifie DB + bus + règles.
   *
   * Par défaut, un `503` ne lève **pas** d'exception : il retourne
   * `{ status: "unavailable", http_status: 503, … }`, comportement attendu par une sonde
   * d'orchestrateur. Utilisez `{ raiseOnError: true }` pour lever à la place.
   */
  async readyz(options: ReadyzOptions = {}): Promise<ReadyStatus> {
    const { raiseOnError, ...request } = options;
    try {
      const payload = await this.jsonCall<ReadyStatus>("GET", "/readyz", { request, auth: false });
      return { ...payload, http_status: 200 };
    } catch (error) {
      if (error instanceof ServerError && raiseOnError !== true) {
        return {
          status: "unavailable",
          http_status: error.statusCode ?? 503,
          error: error.message,
          details: error.details as JsonObject,
        };
      }
      throw error;
    }
  }

  /** `GET /version` (public) → version, commit, licence, mode d'autonomie global. */
  async version(request: RequestOptions = {}): Promise<VersionInfo> {
    return this.jsonCall<VersionInfo>("GET", "/version", { request, auth: false });
  }

  /** `GET /metrics` (public, réseau interne) → exposition Prometheus en texte. */
  async metrics(request: RequestOptions = {}): Promise<string> {
    return this.textCall("GET", "/metrics", {
      request,
      auth: false,
      accept: "text/plain",
    });
  }

  /* ============================================================================== */
  /* §4.2 Tenants et clés                                                            */
  /* ============================================================================== */

  /** `GET /api/v1/tenants` (capacité `admin:tenants`). */
  async list_tenants(request: RequestOptions = {}): Promise<Page<Tenant>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/tenants"), { request });
    return pageFromPayload<Tenant>(payload);
  }

  /** `POST /api/v1/tenants` (capacité `admin:tenants`). */
  async create_tenant(input: CreateTenantInput, request: RequestOptions = {}): Promise<Tenant> {
    if (input.mode !== undefined) {
      requireEnum(input.mode, TENANT_MODES, "mode");
    }
    return this.jsonCall<Tenant>("POST", this.api("/tenants"), {
      request,
      json: {
        tenant_id: input.tenant_id,
        name: input.name,
        ...(input.mode !== undefined ? { mode: input.mode } : {}),
        ...(input.autonomy_allowlist !== undefined
          ? { autonomy_allowlist: input.autonomy_allowlist }
          : {}),
        ...(input.dry_run !== undefined ? { dry_run: input.dry_run } : {}),
      },
    });
  }

  /** `GET /api/v1/tenants/{id}` (capacité `read:stats`, self). */
  async get_tenant(tenantId?: string | undefined, request: RequestOptions = {}): Promise<Tenant> {
    return this.jsonCall<Tenant>("GET", this.api(`/tenants/${encodeURIComponent(this.requireTenant(tenantId))}`), {
      request,
    });
  }

  /**
   * `PATCH /api/v1/tenants/{id}` (capacité `admin:tenants`).
   *
   * ⚠️ Activer `mode: "auto"` ou `dry_run: false` change le niveau d'autonomie d'un tenant :
   * c'est une décision de sécurité volontaire, limitée et journalisée (contrat §6).
   */
  async update_tenant(
    input: UpdateTenantInput,
    tenantId?: string | undefined,
    request: RequestOptions = {},
  ): Promise<Tenant> {
    if (input.mode !== undefined) {
      requireEnum(input.mode, TENANT_MODES, "mode");
    }
    const payload: Record<string, unknown> = {};
    if (input.mode !== undefined) {
      payload["mode"] = input.mode;
    }
    if (input.dry_run !== undefined) {
      payload["dry_run"] = input.dry_run;
    }
    if (input.name !== undefined) {
      payload["name"] = input.name;
    }
    if (input.autonomy_allowlist !== undefined) {
      payload["autonomy_allowlist"] = input.autonomy_allowlist;
    }
    if (Object.keys(payload).length === 0) {
      throw new ValidationError(
        "update_tenant : aucun champ à modifier (mode, dry_run, name, autonomy_allowlist)",
        { code: "validation_error" },
      );
    }
    return this.jsonCall<Tenant>(
      "PATCH",
      this.api(`/tenants/${encodeURIComponent(this.requireTenant(tenantId))}`),
      { request, json: payload },
    );
  }

  /**
   * `POST /api/v1/tenants/{id}/keys` (capacité `admin:keys`).
   *
   * La valeur `api_key` n'est **affichée qu'une seule fois** : le SDK ne la journalise jamais.
   */
  async create_key(
    input: CreateKeyInput = { role: "responder" },
    tenantId?: string | undefined,
    request: RequestOptions = {},
  ): Promise<ApiKey> {
    requireEnum(input.role, ROLES, "role");
    return this.jsonCall<ApiKey>(
      "POST",
      this.api(`/tenants/${encodeURIComponent(this.requireTenant(tenantId))}/keys`),
      {
        request,
        json: { role: input.role, ...(input.label !== undefined ? { label: input.label } : {}) },
      },
    );
  }

  /** `GET /api/v1/tenants/{id}/keys` (capacité `admin:keys`). */
  async list_keys(
    tenantId?: string | undefined,
    request: RequestOptions = {},
  ): Promise<Page<ApiKey>> {
    const payload = await this.jsonCall<unknown>(
      "GET",
      this.api(`/tenants/${encodeURIComponent(this.requireTenant(tenantId))}/keys`),
      { request },
    );
    return pageFromPayload<ApiKey>(payload);
  }

  /** `DELETE /api/v1/keys/{key_id}` (capacité `admin:keys`) → `204`. */
  async revoke_key(keyId: string, request: RequestOptions = {}): Promise<void> {
    await this.perform("DELETE", this.api(`/keys/${encodeURIComponent(keyId)}`), { request });
  }

  /* ============================================================================== */
  /* §4.3 Événements                                                                */
  /* ============================================================================== */

  /** `POST /api/v1/events` avec un événement unique (capacité `write:events`). */
  async ingest_event(event: EventInput, request: RequestOptions = {}): Promise<IngestResult> {
    return this.jsonCall<IngestResult>("POST", this.api("/events"), {
      request,
      json: this.fillTenant(event),
    });
  }

  /**
   * `POST /api/v1/events` avec `{"events": […]}` (capacité `write:events`).
   *
   * Le contrat impose **au plus 500 événements par lot** : les lots plus grands sont découpés
   * automatiquement et les réponses fusionnées. `onBatch` est appelé après chaque lot confirmé —
   * c'est le point d'ancrage de la contre-pression (ne produisez le lot suivant qu'à ce moment).
   */
  async ingest_events(
    events: Iterable<EventInput> | AsyncIterable<EventInput>,
    options: IngestOptions = {},
  ): Promise<IngestResult> {
    const chunkSize = options.chunkSize ?? MAX_BATCH_SIZE;
    if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_BATCH_SIZE) {
      throw new ValidationError(`chunkSize doit être un entier entre 1 et ${MAX_BATCH_SIZE}`, {
        code: "validation_error",
      });
    }
    let total: IngestResult = { accepted: 0, rejected: 0, event_ids: [], findings: [] };
    let batchIndex = 0;
    for await (const batch of chunked(events, chunkSize)) {
      const payload = await this.jsonCall<IngestResult>("POST", this.api("/events"), {
        request: options,
        json: { events: batch.map((event) => this.fillTenant(event)) },
      });
      total = mergeIngestResults(total, payload);
      await options.onBatch?.(payload, batchIndex);
      batchIndex += 1;
    }
    return total;
  }

  /** `GET /api/v1/events` (capacité `read:events`) — `limit ≤ 500`, défaut 100. */
  async list_events(options: ListEventsOptions = {}): Promise<Page<Event>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/events"), {
      request: options,
      query: {
        kind: options.kind,
        source_type: options.source_type,
        since: options.since,
        until: options.until,
        q: options.q,
        limit: options.limit,
        cursor: options.cursor,
      },
    });
    return pageFromPayload<Event>(payload);
  }

  /** `GET /api/v1/events/{event_id}` (capacité `read:events`). */
  async get_event(eventId: string, request: RequestOptions = {}): Promise<Event> {
    return this.jsonCall<Event>("GET", this.api(`/events/${encodeURIComponent(eventId)}`), { request });
  }

  /** Itère sur tous les événements en suivant le curseur. */
  iter_events(options: ListEventsOptions = {}): AsyncGenerator<Event, void, undefined> {
    return paginate<Event>(
      (cursor, signal) =>
        this.list_events({ ...options, cursor: cursor ?? undefined, signal }),
      options,
    );
  }

  /* ============================================================================== */
  /* §4.4 Findings                                                                  */
  /* ============================================================================== */

  /** `GET /api/v1/findings` (capacité `read:findings`). `sort` ∈ `risk_score|last_seen`. */
  async list_findings(options: ListFindingsOptions = {}): Promise<Page<Finding>> {
    if (options.sort !== undefined) {
      requireEnum(options.sort, FINDING_SORTS, "sort");
    }
    if (options.severity !== undefined) {
      requireEnum(options.severity, SEVERITIES, "severity");
    }
    const payload = await this.jsonCall<unknown>("GET", this.api("/findings"), {
      request: options,
      query: {
        status: options.status,
        severity: options.severity,
        rule_id: options.rule_id,
        since: options.since,
        until: options.until,
        min_risk: options.min_risk,
        sort: options.sort,
        limit: options.limit,
        cursor: options.cursor,
      },
    });
    return pageFromPayload<Finding>(payload);
  }

  /** `GET /api/v1/findings/{id}` → `Finding` + actions liées (`finding.actions`). */
  async get_finding(findingId: string, request: RequestOptions = {}): Promise<Finding> {
    return this.jsonCall<Finding>("GET", this.api(`/findings/${encodeURIComponent(findingId)}`), {
      request,
    });
  }

  /** `POST /api/v1/findings/{id}/ack` (capacité `write:findings`). */
  async ack_finding(
    findingId: string,
    input: AckFindingInput = {},
    request: RequestOptions = {},
  ): Promise<{ status: string }> {
    return this.jsonCall<{ status: string }>(
      "POST",
      this.api(`/findings/${encodeURIComponent(findingId)}/ack`),
      { request, json: compact(input) },
    );
  }

  /** `POST /api/v1/findings/{id}/close` (capacité `write:findings`). */
  async close_finding(
    findingId: string,
    input: CloseFindingInput,
    request: RequestOptions = {},
  ): Promise<{ status: string }> {
    requireEnum<Resolution>(input.resolution, RESOLUTIONS, "resolution");
    return this.jsonCall<{ status: string }>(
      "POST",
      this.api(`/findings/${encodeURIComponent(findingId)}/close`),
      { request, json: compact({ resolution: input.resolution, comment: input.comment }) },
    );
  }

  /**
   * `POST /api/v1/findings/{id}/suppress` (capacité `write:findings`).
   *
   * Crée une exception temporaire sur la règle : à utiliser avec un motif explicite.
   */
  async suppress_finding(
    findingId: string,
    input: SuppressFindingInput = {},
    request: RequestOptions = {},
  ): Promise<{ status: string }> {
    return this.jsonCall<{ status: string }>(
      "POST",
      this.api(`/findings/${encodeURIComponent(findingId)}/suppress`),
      {
        request,
        json: compact({
          duration_seconds: input.duration_seconds ?? 86_400,
          reason: input.reason,
        }),
      },
    );
  }

  /**
   * `GET /api/v1/findings/{id}/report?format=md|html|json|sarif` (capacité `read:findings`).
   *
   * Retourne le texte du rapport ; utilisez `get_report_bytes()` pour les octets bruts.
   */
  async get_report(
    findingId: string,
    options: ({ format?: ReportFormat | undefined } & RequestOptions) = {},
  ): Promise<string> {
    const format = options.format ?? "md";
    requireEnum(format, REPORT_FORMATS, "format");
    const { format: _ignored, ...request } = options;
    return this.textCall("GET", this.api(`/findings/${encodeURIComponent(findingId)}/report`), {
      request,
      query: { format },
    });
  }

  /** Même route que `get_report()`, mais retourne les octets bruts (BOM/UTF-8 préservés). */
  async get_report_bytes(
    findingId: string,
    options: ({ format?: ReportFormat | undefined } & RequestOptions) = {},
  ): Promise<Uint8Array> {
    const format = options.format ?? "md";
    requireEnum(format, REPORT_FORMATS, "format");
    const { format: _ignored, ...request } = options;
    return this.bytesCall("GET", this.api(`/findings/${encodeURIComponent(findingId)}/report`), {
      request,
      query: { format },
    });
  }

  /** Itère sur tous les findings en suivant le curseur. */
  iter_findings(options: ListFindingsOptions = {}): AsyncGenerator<Finding, void, undefined> {
    return paginate<Finding>(
      (cursor, signal) => this.list_findings({ ...options, cursor: cursor ?? undefined, signal }),
      options,
    );
  }

  /* ============================================================================== */
  /* §4.5 Règles, politiques, playbooks                                              */
  /* ============================================================================== */

  /** `GET /api/v1/rules` (capacité `read:rules`). */
  async list_rules(request: RequestOptions = {}): Promise<Page<Rule>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/rules"), { request });
    return pageFromPayload<Rule>(payload);
  }

  /** `GET /api/v1/rules/{rule_id}` → règle complète + YAML source (`rule.yaml_source`). */
  async get_rule(ruleId: string, request: RequestOptions = {}): Promise<Rule> {
    return this.jsonCall<Rule>("GET", this.api(`/rules/${encodeURIComponent(ruleId)}`), { request });
  }

  /**
   * `POST /api/v1/rules/validate` (capacité `admin:rules`).
   *
   * `rule` peut être le **YAML source** (chaîne) ou un objet JSON de règle.
   */
  async validate_rule(
    rule: string | JsonObject,
    request: RequestOptions = {},
  ): Promise<RuleValidation> {
    if (typeof rule === "string") {
      return this.jsonCall<RuleValidation>("POST", this.api("/rules/validate"), {
        request,
        text: { body: rule, contentType: "application/yaml" },
      });
    }
    if (typeof rule === "object" && rule !== null && !Array.isArray(rule)) {
      return this.jsonCall<RuleValidation>("POST", this.api("/rules/validate"), {
        request,
        json: rule,
      });
    }
    throw new ValidationError("validate_rule attend une chaîne YAML ou un objet de règle", {
      code: "validation_error",
    });
  }

  /** `POST /api/v1/rules/reload` (capacité `admin:rules`) → `{"loaded":n,"errors":[…]}`. */
  async reload_rules(request: RequestOptions = {}): Promise<ReloadResult> {
    return this.jsonCall<ReloadResult>("POST", this.api("/rules/reload"), { request, json: {} });
  }

  /** `GET /api/v1/policies` (capacité `read:policies`) : politiques + ordre de priorité. */
  async list_policies(request: RequestOptions = {}): Promise<PolicyList> {
    return this.jsonCall<PolicyList>("GET", this.api("/policies"), { request });
  }

  /** `POST /api/v1/policies/reload` (capacité `admin:policies`). */
  async reload_policies(request: RequestOptions = {}): Promise<ReloadResult> {
    return this.jsonCall<ReloadResult>("POST", this.api("/policies/reload"), { request, json: {} });
  }

  /** `GET /api/v1/playbooks` (capacité `read:rules`). */
  async list_playbooks(request: RequestOptions = {}): Promise<Page<Playbook>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/playbooks"), { request });
    return pageFromPayload<Playbook>(payload);
  }

  /* ============================================================================== */
  /* §4.6 Actions SOAR                                                              */
  /* ============================================================================== */

  /**
   * `POST /api/v1/actions/plan` (capacité `execute:actions`) — **aucun effet de bord**.
   *
   * `dry_run` vaut `true` par défaut : la planification reste une simulation tant que l'appelant
   * ne lève pas explicitement ce garde-fou (contrat §1, invariant 1).
   */
  async plan_action(
    input: { finding_id: string; playbook: string; params?: JsonObject | undefined; dry_run?: boolean | undefined },
    request: RequestOptions = {},
  ): Promise<Action> {
    return this.jsonCall<Action>("POST", this.api("/actions/plan"), {
      request,
      json: {
        finding_id: input.finding_id,
        playbook: input.playbook,
        params: input.params ?? {},
        dry_run: input.dry_run ?? true,
      },
    });
  }

  /** `GET /api/v1/actions` (capacité `read:findings`). */
  async list_actions(options: ListActionsOptions = {}): Promise<Page<Action>> {
    if (options.status !== undefined) {
      requireEnum(options.status as (typeof ACTION_STATUSES)[number], ACTION_STATUSES, "status");
    }
    const payload = await this.jsonCall<unknown>("GET", this.api("/actions"), {
      request: options,
      query: {
        status: options.status,
        playbook: options.playbook,
        finding_id: options.finding_id,
        limit: options.limit,
        cursor: options.cursor,
      },
    });
    return pageFromPayload<Action>(payload);
  }

  /** `GET /api/v1/actions/{id}` (capacité `read:findings`). */
  async get_action(actionId: string, request: RequestOptions = {}): Promise<Action> {
    return this.jsonCall<Action>("GET", this.api(`/actions/${encodeURIComponent(actionId)}`), {
      request,
    });
  }

  /** `POST /api/v1/actions/{id}/approve` (capacité `approve:actions`) → `approved`. */
  async approve_action(
    actionId: string,
    input: { comment?: string | undefined } = {},
    request: RequestOptions = {},
  ): Promise<Action> {
    return this.jsonCall<Action>(
      "POST",
      this.api(`/actions/${encodeURIComponent(actionId)}/approve`),
      { request, json: compact({ comment: input.comment }) },
    );
  }

  /** `POST /api/v1/actions/{id}/reject` (capacité `approve:actions`) → `rejected` (terminal). */
  async reject_action(
    actionId: string,
    input: { reason?: string | undefined } = {},
    request: RequestOptions = {},
  ): Promise<Action> {
    return this.jsonCall<Action>(
      "POST",
      this.api(`/actions/${encodeURIComponent(actionId)}/reject`),
      { request, json: compact({ reason: input.reason }) },
    );
  }

  /**
   * `POST /api/v1/actions/{id}/execute` (capacité `execute:actions`).
   *
   * Le serveur refuse (`409`) une action encore `pending_approval`. L'appel devient réessayable
   * dès qu'une `idempotencyKey` est fournie : c'est la **seule** façon dont le SDK réessaiera
   * automatiquement cette route (`POST`).
   */
  async execute_action(
    actionId: string,
    options: ({ dry_run?: boolean | undefined } & RequestOptions) = {},
  ): Promise<Action> {
    const { dry_run, ...request } = options;
    return this.jsonCall<Action>(
      "POST",
      this.api(`/actions/${encodeURIComponent(actionId)}/execute`),
      {
        request,
        json: compact({ idempotency_key: request.idempotencyKey, dry_run }),
      },
    );
  }

  /**
   * `POST /api/v1/actions/{id}/rollback` (capacité `execute:actions`).
   *
   * Refuse (`409`) une action déjà `rolled_back`.
   */
  async rollback_action(
    actionId: string,
    options: ({ reason?: string | undefined } & RequestOptions) = {},
  ): Promise<Action> {
    const { reason, ...request } = options;
    return this.jsonCall<Action>(
      "POST",
      this.api(`/actions/${encodeURIComponent(actionId)}/rollback`),
      {
        request,
        json: compact({ reason, idempotency_key: request.idempotencyKey }),
      },
    );
  }

  /** Itère sur toutes les actions en suivant le curseur. */
  iter_actions(options: ListActionsOptions = {}): AsyncGenerator<Action, void, undefined> {
    return paginate<Action>(
      (cursor, signal) => this.list_actions({ ...options, cursor: cursor ?? undefined, signal }),
      options,
    );
  }

  /* ============================================================================== */
  /* §4.7 Audit                                                                     */
  /* ============================================================================== */

  /** `GET /api/v1/audit` (capacité `read:audit`). */
  async list_audit(options: ListAuditOptions = {}): Promise<Page<AuditRecord>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/audit"), {
      request: options,
      query: {
        since: options.since,
        until: options.until,
        action: options.action,
        actor: options.actor,
        limit: options.limit,
        cursor: options.cursor,
      },
    });
    return pageFromPayload<AuditRecord>(payload);
  }

  /** Itère sur tout le journal d'audit en suivant le curseur. */
  iter_audit(options: ListAuditOptions = {}): AsyncGenerator<AuditRecord, void, undefined> {
    return paginate<AuditRecord>(
      (cursor, signal) => this.list_audit({ ...options, cursor: cursor ?? undefined, signal }),
      options,
    );
  }

  /** `GET /api/v1/audit/verify` (capacité `read:audit`) → `{"valid","records","broken_at"}`. */
  async verify_audit(request: RequestOptions = {}): Promise<AuditVerification> {
    return this.jsonCall<AuditVerification>("GET", this.api("/audit/verify"), { request });
  }

  /**
   * `GET /api/v1/audit/export?format=jsonl|cef` (capacité `read:audit`).
   *
   * Flux destiné à un SIEM/SOAR : retourne du texte (ou des octets via `export_audit_bytes()`).
   */
  async export_audit(
    options: (AuditExportOptions & BinaryRequestOptions) = {},
  ): Promise<string> {
    const format = options.format ?? "jsonl";
    requireEnum<AuditExportFormat>(format, AUDIT_EXPORT_FORMATS, "format");
    const { format: _format, asBytes: _asBytes, ...request } = options;
    return this.textCall("GET", this.api("/audit/export"), {
      request,
      query: { format, since: options.since, until: options.until },
      accept: "text/plain",
    });
  }

  /** Même route que `export_audit()`, mais retourne les octets bruts. */
  async export_audit_bytes(
    options: (AuditExportOptions & BinaryRequestOptions) = {},
  ): Promise<Uint8Array> {
    const format = options.format ?? "jsonl";
    requireEnum<AuditExportFormat>(format, AUDIT_EXPORT_FORMATS, "format");
    const { format: _format, asBytes: _asBytes, ...request } = options;
    return this.bytesCall("GET", this.api("/audit/export"), {
      request,
      query: { format, since: options.since, until: options.until },
      accept: "text/plain",
    });
  }

  /* ============================================================================== */
  /* §4.8 Stats, collecteurs, flux temps réel                                        */
  /* ============================================================================== */

  /** `GET /api/v1/stats/overview` (capacité `read:stats`). */
  async stats_overview(request: RequestOptions = {}): Promise<StatsOverview> {
    return this.jsonCall<StatsOverview>("GET", this.api("/stats/overview"), { request });
  }

  /** `GET /api/v1/collectors` (capacité `read:stats`). */
  async list_collectors(request: RequestOptions = {}): Promise<Page<CollectorStatus>> {
    const payload = await this.jsonCall<unknown>("GET", this.api("/collectors"), { request });
    return pageFromPayload<CollectorStatus>(payload);
  }

  /**
   * `POST /api/v1/collectors/{name}/run` (capacité `execute:actions`).
   *
   * Déclenche un run **sur les cibles déclarées du tenant** uniquement : le SDK n'expose aucune
   * primitive de balayage arbitraire (contrat §10, « zéro capacité offensive »).
   */
  async run_collector(name: string, request: RequestOptions = {}): Promise<JsonObject> {
    return this.jsonCall<JsonObject>(
      "POST",
      this.api(`/collectors/${encodeURIComponent(name)}/run`),
      { request, json: {} },
    );
  }

  /**
   * URL WebSocket `/api/v1/ws/stream` avec `api_key` et `tenant_id`.
   *
   * ⚠️ L'URL retournée **contient la clé API** (les navigateurs ne peuvent pas poser d'en-tête
   * sur `ws://`). Ne la journalisez jamais telle quelle : utilisez `redactUrl()`.
   */
  ws_url(path?: string): string {
    return buildWebSocketUrl(this.base_url, {
      apiKey: this.api_key,
      tenantId: this.tenant_id,
      path,
    });
  }

  /** Itère sur les frames du flux temps réel (reconnexion, filtrage, arrêt propre). */
  stream(options: StreamOptions = {}): AsyncGenerator<StreamFrame, void, undefined> {
    const stream = new ThotSecureStream({
      url: this.ws_url(),
      webSocketFactory: this.webSocketFactory,
      logger: this.logger,
      sleep: this.sleep,
      random: this.random,
    });
    return stream.stream(options);
  }
}

/** Retire les clés dont la valeur est `undefined` (corps de requête compact). */
function compact(source: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

/** Fusionne deux réponses d'ingestion (utilisé quand un lot est découpé). */
export function mergeIngestResults(left: IngestResult, right: IngestResult): IngestResult {
  return {
    accepted: left.accepted + right.accepted,
    rejected: left.rejected + right.rejected,
    event_ids: [...left.event_ids, ...right.event_ids],
    findings: [...left.findings, ...right.findings],
  };
}

/** Message d'erreur lisible sans jamais exposer de secret. */
function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return "erreur inconnue";
}

/** Réexport utilitaire : identifiant d'événement conforme au §3.1 (UUID v4). */
export { newEventId, RateLimitedError };
