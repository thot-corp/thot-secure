/**
 * Hiérarchie d'erreurs du SDK Thot Secure (ex-Thot Secure).
 *
 * Le contrat d'interface (`docs/architecture/api-contract.md` §4.6) normalise les erreurs :
 *
 * ```json
 * {"error": {"code": "forbidden", "message": "…", "details": {}}}
 * ```
 *
 * avec `400 validation_error`, `401 unauthenticated`, `403 forbidden`, `404 not_found`,
 * `409 conflict`, `422 unprocessable`, `429 rate_limited`, `500 internal_error`.
 *
 * Règles de sécurité appliquées par ce module :
 *
 * * **aucune** erreur, aucun message et aucun log ne contient la clé API : toute URL est passée
 *   par `redactUrl()` avant d'être attachée à une erreur (le WebSocket transporte la clé en
 *   paramètre de requête, faute d'en-tête possible côté navigateur) ;
 * * `error.code` du contrat **prime** sur le statut HTTP ;
 * * `retryable` indique si un nouvel essai a un sens (utilisé par la couche `retry.ts`).
 *
 * Le nom de classe reste `ThotSecureError` (le renommage global du projet est en cours) ; l'alias
 * `ThotSecureError` est exporté pour le code qui utilise déjà le nouveau nom.
 */

/** Paramètres communs de construction d'une erreur du SDK. */
export interface ThotSecureErrorOptions {
  /** Code du contrat (`forbidden`, `rate_limited`…). */
  code?: string | undefined;
  /** Statut HTTP associé, `null` pour une erreur purement locale. */
  statusCode?: number | undefined;
  /** Bloc `details` du contrat (jamais de secret). */
  details?: Record<string, unknown> | undefined;
  /** Méthode HTTP de l'appel fautif. */
  method?: string | undefined;
  /** URL de l'appel fautif — masquée automatiquement par `redactUrl()`. */
  url?: string | undefined;
  /** Identifiant de corrélation renvoyé par le serveur (`X-Request-Id`). */
  requestId?: string | undefined;
  /** Cause d'origine (erreur réseau, `AbortError`…). */
  cause?: unknown;
  /** `true` si un nouvel essai a du sens. */
  retryable?: boolean | undefined;
}

/** Paramètres supplémentaires de `RateLimitedError`. */
export interface RateLimitedOptions extends ThotSecureErrorOptions {
  /** Délai conseillé, **en secondes** (sémantique de l'en-tête HTTP `Retry-After`). */
  retryAfter?: number | undefined;
}

/** Paramètres de `errorFromResponse()`. */
export interface ErrorFromResponseOptions {
  method?: string | undefined;
  url?: string | undefined;
  headers?: Record<string, string> | undefined;
  /** Corps brut, utilisé si la charge utile n'est pas du JSON exploitable. */
  rawText?: string | undefined;
}

/** Paramètres de requête qui ne doivent jamais apparaître dans un message d'erreur. */
const SENSITIVE_QUERY_PARAMS: readonly string[] = [
  "api_key",
  "apikey",
  "token",
  "access_token",
  "refresh_token",
  "key",
  "password",
  "secret",
];

/** Valeur de remplacement des données masquées. */
export const REDACTED = "[REDACTED]";

/**
 * Masque les paramètres sensibles d'une URL.
 *
 * `https://h/api/v1/ws/stream?api_key=ao_secret&tenant_id=acme` devient
 * `https://h/api/v1/ws/stream?api_key=***&tenant_id=acme`.
 */
export function redactUrl(url: string | null | undefined): string | undefined {
  if (url === null || url === undefined || url === "") {
    return undefined;
  }
  let result = url;
  for (const param of SENSITIVE_QUERY_PARAMS) {
    const pattern = new RegExp(`([?&]${param}=)[^&#\\s]*`, "gi");
    result = result.replace(pattern, "$1***");
  }
  return result;
}

/** Masque les en-têtes sensibles d'un dictionnaire (journalisation sûre). */
export function redactHeaders(
  headers: Record<string, string> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) {
    return out;
  }
  for (const [key, value] of Object.entries(headers)) {
    const normalized = key.toLowerCase();
    if (
      normalized === "x-api-key" ||
      normalized === "authorization" ||
      normalized === "cookie" ||
      normalized === "set-cookie" ||
      normalized === "proxy-authorization"
    ) {
      out[key] = "***";
    } else {
      out[key] = value;
    }
  }
  return out;
}

/** Erreur de base du SDK Thot Secure. */
export class ThotSecureError extends Error {
  /** Code du contrat ; `internal_error` par défaut. */
  readonly code: string;
  /** Statut HTTP associé, `null` si l'erreur est locale. */
  readonly statusCode: number | null;
  /** Bloc `details` du contrat. */
  readonly details: Record<string, unknown>;
  /** Méthode HTTP de l'appel fautif. */
  readonly method: string | undefined;
  /** URL masquée de l'appel fautif. */
  readonly url: string | undefined;
  /** Identifiant de corrélation éventuel. */
  readonly requestId: string | undefined;
  /** `true` si un nouvel essai a du sens. */
  readonly retryable: boolean;

  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ThotSecureError";
    this.code = options.code ?? "internal_error";
    this.statusCode = options.statusCode ?? null;
    this.details = options.details ?? {};
    this.method = options.method;
    this.url = redactUrl(options.url);
    this.requestId = options.requestId;
    this.retryable = options.retryable ?? false;
    // Conserve `instanceof` même après une compilation vers une cible ancienne.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Représentation compacte : `message (status=403, code=forbidden, GET /api/v1/…)`. */
  override toString(): string {
    const meta: string[] = [];
    if (this.statusCode !== null) {
      meta.push(`status=${this.statusCode}`);
    }
    if (this.code) {
      meta.push(`code=${this.code}`);
    }
    if (this.method) {
      meta.push(`${this.method} ${this.url ?? ""}`);
    }
    if (this.requestId) {
      meta.push(`request_id=${this.requestId}`);
    }
    return meta.length > 0 ? `${this.message} (${meta.join(", ")})` : this.message;
  }
}

/** Erreur réseau ou de transport : DNS, TLS, connexion coupée, délai dépassé. */
export class TransportError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "transport_error",
      retryable: options.retryable ?? true,
    });
    this.name = "TransportError";
  }
}

/** Erreur de la couche WebSocket : handshake, trame invalide, connexion fermée. */
export class WebSocketError extends TransportError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, { ...options, code: options.code ?? "websocket_error" });
    this.name = "WebSocketError";
  }
}

/** **401** — clé API absente, inconnue ou révoquée. */
export class AuthenticationError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "unauthenticated",
      statusCode: options.statusCode ?? 401,
    });
    this.name = "AuthenticationError";
  }
}

/** **403** — clé valide mais capacité RBAC manquante (contrat §4). */
export class PermissionDeniedError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "forbidden",
      statusCode: options.statusCode ?? 403,
    });
    this.name = "PermissionDeniedError";
  }
}

/** **404** — ressource inexistante **ou** appartenant à un autre tenant (isolation §1). */
export class NotFoundError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "not_found",
      statusCode: options.statusCode ?? 404,
    });
    this.name = "NotFoundError";
  }
}

/** **409** — conflit d'état (exécuter une action non approuvée, rollback déjà effectué…). */
export class ConflictError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "conflict",
      statusCode: options.statusCode ?? 409,
    });
    this.name = "ConflictError";
  }
}

/** **400 / 422** — corps de requête invalide (côté serveur ou détecté côté client). */
export class ValidationError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "validation_error",
      statusCode: options.statusCode ?? 400,
    });
    this.name = "ValidationError";
  }
}

/** **429** — quota dépassé ; `retryAfter` (secondes) indique le délai conseillé. */
export class RateLimitedError extends ThotSecureError {
  /** Délai conseillé en secondes, `null` si le serveur ne l'a pas communiqué. */
  readonly retryAfter: number | null;

  constructor(message: string, options: RateLimitedOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "rate_limited",
      statusCode: options.statusCode ?? 429,
      retryable: options.retryable ?? true,
    });
    this.name = "RateLimitedError";
    this.retryAfter = options.retryAfter ?? null;
  }

  /** Même délai exprimé en millisecondes (commodité pour `setTimeout`). */
  get retryAfterMs(): number | null {
    return this.retryAfter === null ? null : Math.round(this.retryAfter * 1000);
  }
}

/** **5xx** — erreur interne du serveur Thot Secure. */
export class ServerError extends ThotSecureError {
  constructor(message: string, options: ThotSecureErrorOptions = {}) {
    super(message, {
      ...options,
      code: options.code ?? "internal_error",
      statusCode: options.statusCode ?? 500,
      retryable: options.retryable ?? true,
    });
    this.name = "ServerError";
  }
}

/** Famille d'erreur déduite d'un code HTTP ou du `error.code` du contrat. */
export type ErrorKind =
  | "authentication"
  | "permission"
  | "not_found"
  | "conflict"
  | "validation"
  | "rate_limited"
  | "server"
  | "generic";

/** Code du contrat associé à chaque famille (repli quand le serveur n'en fournit pas). */
const KIND_TO_CODE: Record<ErrorKind, string> = {
  authentication: "unauthenticated",
  permission: "forbidden",
  not_found: "not_found",
  conflict: "conflict",
  validation: "validation_error",
  rate_limited: "rate_limited",
  server: "internal_error",
  generic: "internal_error",
};

const CODE_TO_KIND: Record<string, ErrorKind> = {
  validation_error: "validation",
  invalid_request: "validation",
  unauthenticated: "authentication",
  unauthorized: "authentication",
  forbidden: "permission",
  not_found: "not_found",
  conflict: "conflict",
  unprocessable: "validation",
  rate_limited: "rate_limited",
  internal_error: "server",
};

/** Traduit un `error.code` du contrat en famille d'erreur (fallback : statut HTTP). */
export function errorKindFor(code: string | null | undefined, statusCode: number): ErrorKind {
  if (code !== null && code !== undefined && code !== "") {
    const known = CODE_TO_KIND[code];
    if (known !== undefined) {
      return known;
    }
  }
  return errorKindFromStatus(statusCode);
}

/** Traduit un statut HTTP en famille d'erreur. */
export function errorKindFromStatus(statusCode: number): ErrorKind {
  switch (statusCode) {
    case 400:
    case 422:
      return "validation";
    case 401:
      return "authentication";
    case 403:
      return "permission";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    default:
      return statusCode >= 500 ? "server" : "generic";
  }
}

function instantiate(
  kind: ErrorKind,
  message: string,
  options: ThotSecureErrorOptions,
): ThotSecureError {
  switch (kind) {
    case "authentication":
      return new AuthenticationError(message, options);
    case "permission":
      return new PermissionDeniedError(message, options);
    case "not_found":
      return new NotFoundError(message, options);
    case "conflict":
      return new ConflictError(message, options);
    case "validation":
      return new ValidationError(message, options);
    case "rate_limited":
      return new RateLimitedError(message, options);
    case "server":
      return new ServerError(message, options);
    default:
      return new ThotSecureError(message, options);
  }
}

/** Lit un en-tête sans tenir compte de la casse. */
function headerValue(headers: Record<string, string> | undefined, name: string): string | null {
  if (!headers) {
    return null;
  }
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) {
      return value;
    }
  }
  return null;
}

/**
 * Convertit un en-tête `Retry-After` en **secondes**.
 * Accepte un nombre de secondes ou une date HTTP (RFC 9110).
 */
export function parseRetryAfterHeader(
  value: string | null | undefined,
  now: number = Date.now(),
): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  const text = value.trim();
  if (text === "") {
    return null;
  }
  const seconds = Number(text);
  if (Number.isFinite(seconds)) {
    return Math.max(0, seconds);
  }
  const when = Date.parse(text);
  if (Number.isNaN(when)) {
    return null;
  }
  return Math.max(0, (when - now) / 1000);
}

function coerceNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/**
 * Construit l'erreur adéquate depuis une réponse HTTP en erreur.
 *
 * Priorité : `error.code` du contrat → statut HTTP → corps brut (`rawText`).
 */
export function errorFromResponse(
  statusCode: number,
  payload: unknown = null,
  options: ErrorFromResponseOptions = {},
): ThotSecureError {
  let code: string | null = null;
  let message: string | null = null;
  let details: Record<string, unknown> = {};

  if (typeof payload === "object" && payload !== null && !Array.isArray(payload)) {
    const record = payload as Record<string, unknown>;
    const rawError = record["error"];
    if (typeof rawError === "object" && rawError !== null && !Array.isArray(rawError)) {
      const errorRecord = rawError as Record<string, unknown>;
      const rawCode = errorRecord["code"];
      code = typeof rawCode === "string" ? rawCode : null;
      const rawMessage = errorRecord["message"];
      message = typeof rawMessage === "string" ? rawMessage : null;
      const rawDetails = errorRecord["details"];
      if (typeof rawDetails === "object" && rawDetails !== null && !Array.isArray(rawDetails)) {
        details = rawDetails as Record<string, unknown>;
      }
    } else if (typeof record["detail"] === "string") {
      // FastAPI renvoie parfois {"detail": "..."} : on l'accepte sans le masquer.
      message = record["detail"];
    } else if (Array.isArray(record["detail"])) {
      message = "validation error";
      details = { errors: record["detail"] };
    }
  }

  if (message === null) {
    const trimmed = options.rawText?.trim();
    message = trimmed !== undefined && trimmed !== "" ? trimmed.slice(0, 500) : `HTTP ${statusCode}`;
  }

  const kind = errorKindFor(code, statusCode);
  const requestId = headerValue(options.headers, "x-request-id") ?? headerValue(options.headers, "x-correlation-id");

  const base: ThotSecureErrorOptions = {
    code: code ?? undefined,
    statusCode,
    details,
    method: options.method,
    url: options.url,
    requestId: requestId ?? undefined,
  };

  if (kind === "rate_limited") {
    const headerRetryAfter = parseRetryAfterHeader(headerValue(options.headers, "retry-after"));
    const detailRetryAfter = coerceNumber(details["retry_after"]);
    return new RateLimitedError(message, { ...base, retryAfter: headerRetryAfter ?? detailRetryAfter ?? undefined });
  }

  // Repli du code : celui de la famille retenue si le serveur n'en a pas fourni.
  const fallbackCode = KIND_TO_CODE[kind] ?? "internal_error";
  return instantiate(kind, message, { ...base, code: base.code ?? fallbackCode });
}

/** `true` si la valeur est une erreur du SDK (utilisable comme garde de type). */
export function isThotSecureError(value: unknown): value is ThotSecureError {
  return value instanceof ThotSecureError;
}
