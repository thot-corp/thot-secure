/**
 * SDK TypeScript officiel — Thot Secure (nom technique `thotsecure`) v0.1.0.
 *
 * Point d'entrée **ESM** du paquet `@thotsecure/sdk` : il expose le client REST, le client de flux
 * WebSocket, la hiérarchie d'erreurs, la politique de reprise, les helpers d'intégration et tous
 * les types du contrat d'interface (`docs/architecture/api-contract.md` §3 et §4).
 *
 * ```ts
 * import { ThotSecureClient, redactUrl, VERSION } from "@thotsecure/sdk";
 *
 * const client = new ThotSecureClient({
 *   baseUrl: process.env.THOT_SECURE_URL,
 *   apiKey: process.env.THOT_SECURE_API_KEY,
 *   tenantId: "acme",
 * });
 *
 * const page = await client.list_findings({ status: "open", sort: "risk_score" });
 * for (const finding of page.items) {
 *   console.log(finding.finding_id, finding.risk_score);
 * }
 *
 * // Flux temps réel (arrêt propre via AbortController ou close())
 * const controller = new AbortController();
 * for await (const frame of client.stream({ types: ["finding"], signal: controller.signal })) {
 *   console.log(frame.type, frame.data);
 * }
 * client.close();
 * ```
 *
 * **Zéro dépendance runtime** : `fetch`, `AbortController`, `Web Crypto` et `WebSocket` sont ceux
 * de la plateforme (Node ≥ 20, navigateurs récents). Aucun paquet tiers n'est requis, ni à
 * l'exécution ni au bundling (`tsup` en `platform: "neutral"`).
 *
 * ⚠️ **Ne jamais embarquer une clé API dans un front public.** Une clé `ao_…` posée dans un
 * bundle JavaScript est lisible par n'importe qui : faites passer les appels par votre propre
 * service, qui détient la clé côté serveur, et n'exposez au navigateur qu'un jeton à courte durée
 * de vie (voir `README.md`, section « Sécurité »).
 */

/* ------------------------------------------------------------------------------------ */
/* Version                                                                              */
/* ------------------------------------------------------------------------------------ */

/** Version du SDK TypeScript. */
export const VERSION = "0.1.0";

/** Version du contrat d'interface implémentée (`docs/architecture/api-contract.md`). */
export const API_CONTRACT_VERSION = "0.1.0";

/* ------------------------------------------------------------------------------------ */
/* Types du contrat (§3) et constantes d'énumération                                     */
/* ------------------------------------------------------------------------------------ */

export * from "./types";

/* ------------------------------------------------------------------------------------ */
/* Client REST                                                                          */
/* ------------------------------------------------------------------------------------ */

export {
  ThotSecureClient,
  API_PREFIX,
  DEFAULT_BASE_URL,
  mergeIngestResults,
  pageFromPayload,
} from "./client";

export type {
  ThotSecureClientOptions,
  BinaryRequestOptions,
  FetchLike,
  IngestOptions,
  Logger,
  PaginatedRequestOptions,
  ReadyzOptions,
  RequestOptions,
} from "./client";

/* ------------------------------------------------------------------------------------ */
/* Flux temps réel (WebSocket)                                                          */
/* ------------------------------------------------------------------------------------ */

export {
  ThotSecureStream,
  BACKOFF_BASE_MS,
  BACKOFF_MAX_MS,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_STALE_TIMEOUT_MS,
  FRAME_TYPES,
  HELLO_TYPE,
  RAW_TYPE,
  WS_CLOSED,
  WS_OPEN,
  WS_PATH,
  buildWebSocketUrl,
  computeReconnectDelay,
} from "./ws";

export type {
  ThotSecureStreamOptions,
  BuildWebSocketUrlOptions,
  ReconnectInfo,
  StreamFrame,
  StreamLogger,
  StreamOptions,
  WebSocketFactory,
  WebSocketLike,
} from "./ws";

/* ------------------------------------------------------------------------------------ */
/* Erreurs (§4.6)                                                                       */
/* ------------------------------------------------------------------------------------ */

export {
  ThotSecureError,
  AuthenticationError,
  ConflictError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitedError,
  REDACTED,
  ServerError,
  TransportError,
  ValidationError,
  WebSocketError,
  errorFromResponse,
  errorKindFor,
  errorKindFromStatus,
  isThotSecureError,
  parseRetryAfterHeader,
  redactHeaders,
  redactUrl,
} from "./errors";

export type {
  ThotSecureErrorOptions,
  ErrorFromResponseOptions,
  ErrorKind,
  RateLimitedOptions,
} from "./errors";

/* ------------------------------------------------------------------------------------ */
/* Politique de reprise                                                                 */
/* ------------------------------------------------------------------------------------ */

export {
  DEFAULT_RETRY_POLICY,
  IDEMPOTENT_METHODS,
  RETRY_STATUS_CODES,
  abortError,
  computeBackoffDelay,
  computeRetryDelay,
  isAbortError,
  isRetrySafe,
  isRetryableStatus,
  parseRetryAfter,
  resolveRetryPolicy,
  retryingFetch,
  sleepMs,
  throwIfAborted,
} from "./retry";

export type { RetryInfo, RetryOptions, RetryPolicy } from "./retry";

/* ------------------------------------------------------------------------------------ */
/* Helpers d'intégration                                                                */
/* ------------------------------------------------------------------------------------ */

export {
  DEFAULT_IP_FIELDS,
  ENV_API_KEY,
  ENV_TENANT_ID,
  ENV_URL,
  REDACTED_JWT,
  chunked,
  hmacSha256Hex,
  isSensitiveKey,
  newEventId,
  normalizeEvent,
  normalizeKey,
  normalizeNginxLine,
  nowIso,
  parseHttpLogLine,
  parseJsonl,
  parseTimestamp,
  pseudonymizeIp,
  pseudonymizeIpFields,
  readEnv,
  redactSecrets,
  scrubString,
  severityHintForStatus,
  truncatePayload,
} from "./helpers";

export type {
  NginxLogFields,
  NormalizeOptions,
  ParseJsonlOptions,
  PseudonymizeIpFieldsOptions,
  PseudonymizeIpOptions,
  RedactSecretsOptions,
  TruncatePayloadOptions,
} from "./helpers";
