/**
 * Client WebSocket natif du SDK TypeScript Thot Secure (ex-Thot Secure).
 *
 * Cible : `GET /api/v1/ws/stream?api_key=…&tenant_id=…` (contrat §4.8). Les navigateurs ne
 * peuvent pas poser d'en-tête sur une connexion `ws://` : la clé passe donc en paramètre de
 * requête — c'est pourquoi **aucune erreur ni aucun log de ce module ne contient l'URL brute**
 * (elle est nettoyée par `redactUrl()`).
 *
 * Trames attendues : `{"type":"event|finding|action|audit|heartbeat","data":{…}}`, plus la trame
 * `hello` que le serveur émet à l'ouverture du flux (accusé de mise en relation).
 *
 * Ce module s'appuie sur l'API `WebSocket` **native** (navigateur, Node ≥ 22) : aucune dépendance
 * runtime n'est ajoutée. La fabrique peut être injectée (`webSocketFactory`) pour les tests hors
 * ligne ou pour Node antérieur (`new WebSocket(...)` du paquet `ws`).
 *
 * Fonctionnalités : reconnexion avec backoff exponentiel plafonné à 30 s et jitter, détection de
 * `heartbeat` et `hello`, détection de connexion morte (aucune trame reçue), filtrage par type de
 * trame, itérateur asynchrone `stream()` et arrêt propre (`close()` / `AbortSignal`).
 *
 * Limite assumée : l'API WebSocket des navigateurs n'expose **pas** l'envoi de `ping` (RFC 6455
 * opcode 0x9). La vivacité est donc vérifiée passivement (délai sans trame) et non par un ping
 * applicatif — contrairement au SDK Python, qui pilote la socket lui-même.
 */

import { ThotSecureError, ValidationError, WebSocketError, redactUrl } from "./errors";
import { isAbortError, sleepMs } from "./retry";
import type { JsonObject, JsonValue } from "./types";

/* ====================================================================================== */
/* Constantes du contrat                                                                   */
/* ====================================================================================== */

/** Chemin du flux temps réel (contrat §4.8). */
export const WS_PATH = "/api/v1/ws/stream";

/** Types de trame documentés par le contrat §4.8. */
export const FRAME_TYPES: readonly string[] = ["event", "finding", "action", "audit", "heartbeat"];

/** Trame d'accusé de mise en relation, émise par le serveur à l'ouverture. */
export const HELLO_TYPE = "hello";

/** Type utilisé lorsqu'un message reçu n'est pas du JSON conforme au contrat. */
export const RAW_TYPE = "raw";

/** Plafond du backoff de reconnexion (30 s), comme le SDK Python. */
export const BACKOFF_MAX_MS = 30_000;

/** Base du backoff de reconnexion. */
export const BACKOFF_BASE_MS = 500;

/** Délai par défaut sans aucune trame avant de considérer la connexion morte. */
export const DEFAULT_STALE_TIMEOUT_MS = 90_000;

/** Délai par défaut d'établissement de la connexion. */
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

/* ====================================================================================== */
/* Surface WebSocket (structurelle, compatible navigateur et `ws`)                          */
/* ====================================================================================== */

/** Sous-ensemble de l'API `WebSocket` utilisé par le SDK. */
export interface WebSocketLike {
  /** 0 = CONNECTING, 1 = OPEN, 2 = CLOSING, 3 = CLOSED. */
  readonly readyState: number;
  /** URL de la connexion (contient la clé API : ne jamais la journaliser telle quelle). */
  readonly url?: string | undefined;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (event: unknown) => void): void;
  removeEventListener(type: string, listener: (event: unknown) => void): void;
}

/** Fabrique de WebSocket (injectable : tests hors ligne, polyfill, Node antérieur). */
export type WebSocketFactory = (url: string) => WebSocketLike;

/** États normalisés de `WebSocket.readyState`. */
export const WS_OPEN = 1;
export const WS_CLOSED = 3;

/** Fabrique par défaut : `WebSocket` natif de la plateforme. */
function defaultWebSocketFactory(url: string): WebSocketLike {
  const ctor = (globalThis as { WebSocket?: new (target: string) => unknown }).WebSocket;
  if (typeof ctor !== "function") {
    throw new WebSocketError(
      "aucune implémentation de WebSocket disponible : utilisez un navigateur récent, Node ≥ 22, " +
        "ou passez `webSocketFactory` (par exemple `new WebSocket(url)` du paquet `ws`)",
      { code: "websocket_unavailable", retryable: false },
    );
  }
  return new ctor(url) as WebSocketLike;
}

/* ====================================================================================== */
/* Construction de l'URL                                                                   */
/* ====================================================================================== */

/** Options de `buildWebSocketUrl()`. */
export interface BuildWebSocketUrlOptions {
  /** Clé API `ao_…` (le WebSocket ne peut pas porter d'en-tête côté navigateur). */
  apiKey?: string | undefined;
  /** Tenant à écouter. */
  tenantId?: string | undefined;
  /** Chemin du flux (défaut `WS_PATH`). */
  path?: string | undefined;
}

/**
 * Construit l'URL `ws://` / `wss://` du flux, avec `api_key` et `tenant_id`.
 *
 * `http://` → `ws://`, `https://` → `wss://`. Un préfixe de chemin du `baseUrl` (déploiement
 * derrière un reverse-proxy) est conservé.
 *
 * ⚠️ L'URL retournée **contient la clé API** : ne la journalisez jamais telle quelle, utilisez
 * `redactUrl()`.
 */
export function buildWebSocketUrl(
  baseUrl: string,
  options: BuildWebSocketUrlOptions = {},
): string {
  const raw = baseUrl.trim();
  if (raw === "") {
    throw new ValidationError("buildWebSocketUrl : baseUrl requis", { code: "validation_error" });
  }
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch (error) {
    throw new ValidationError(`buildWebSocketUrl : URL invalide « ${baseUrl} »`, {
      code: "validation_error",
      cause: error,
    });
  }
  const protocol = parsed.protocol.toLowerCase();
  let scheme: string;
  if (protocol === "https:" || protocol === "wss:") {
    scheme = "wss";
  } else if (protocol === "http:" || protocol === "ws:") {
    scheme = "ws";
  } else {
    throw new ValidationError(
      `buildWebSocketUrl : schéma non supporté « ${parsed.protocol} » (attendu http, https, ws ou wss)`,
      { code: "validation_error" },
    );
  }

  const prefix = parsed.pathname.replace(/\/+$/, "");
  const requested = options.path ?? WS_PATH;
  const suffix = requested.startsWith("/") ? requested : `/${requested}`;

  const search = new URLSearchParams();
  if (options.apiKey !== undefined && options.apiKey !== "") {
    search.set("api_key", options.apiKey);
  }
  if (options.tenantId !== undefined && options.tenantId !== "") {
    search.set("tenant_id", options.tenantId);
  }
  const query = search.toString();
  return `${scheme}://${parsed.host}${prefix}${suffix}${query === "" ? "" : `?${query}`}`;
}

/* ====================================================================================== */
/* Backoff de reconnexion                                                                  */
/* ====================================================================================== */

/**
 * Calcule le délai de reconnexion : backoff exponentiel plafonné à `maxMs`, avec jitter
 * multiplicatif dans `[0.5, 1[` (évite que tous les clients se reconnectent au même instant).
 *
 * @param attempt index de la tentative échouée (0 pour la première).
 */
export function computeReconnectDelay(
  attempt: number,
  baseMs: number = BACKOFF_BASE_MS,
  maxMs: number = BACKOFF_MAX_MS,
  random: () => number = Math.random,
): number {
  const safeAttempt = Math.max(0, Math.floor(attempt));
  const raw = Math.min(maxMs, baseMs * 2 ** safeAttempt);
  const sample = random();
  const jitter = 0.5 + 0.5 * Math.min(1, Math.max(0, Number.isFinite(sample) ? sample : 1));
  return Math.round(raw * jitter);
}

/* ====================================================================================== */
/* Types publics                                                                           */
/* ====================================================================================== */

/** Trame applicative décodée depuis le flux. */
export interface StreamFrame {
  /** `event`, `finding`, `action`, `audit`, `heartbeat`, `hello`, `raw` ou `unknown`. */
  type: string;
  /** Contenu de `data` (structure ouverte du contrat). */
  data: JsonValue;
  /** Objet JSON complet reçu (permet de lire les champs annexes). */
  raw: JsonObject;
  /** Horodatage de réception local (ISO 8601 UTC). */
  received_at: string;
}

/** Journalisation minimale acceptée par le flux (compatible avec le `Logger` du client). */
export interface StreamLogger {
  debug?(message: string, context?: Record<string, unknown>): void;
  info?(message: string, context?: Record<string, unknown>): void;
  warn(message: string, context?: Record<string, unknown>): void;
  error?(message: string, context?: Record<string, unknown>): void;
}

/** Information transmise à `onReconnect`. */
export interface ReconnectInfo {
  /** Numéro de la tentative de reconnexion (1 pour la première). */
  attempt: number;
  /** Délai observé avant la nouvelle tentative, en millisecondes. */
  delayMs: number;
  /** Cause lisible de la coupure. */
  reason: string;
  /** Code de fermeture WebSocket observé, `null` si inconnu. */
  closeCode: number | null;
}

/** Options de `ThotSecureStream`. */
export interface ThotSecureStreamOptions {
  /** URL complète du flux (`buildWebSocketUrl()`). */
  url: string;
  /** Fabrique de WebSocket (défaut : `WebSocket` natif). */
  webSocketFactory?: WebSocketFactory | undefined;
  /** Journalisation. */
  logger?: StreamLogger | undefined;
  /** Attente injectable (tests déterministes). */
  sleep?: ((delayMs: number, signal?: AbortSignal | undefined) => Promise<void>) | undefined;
  /** Source d'aléa injectable pour le jitter. */
  random?: (() => number) | undefined;
  /** Base du backoff (défaut 500 ms). */
  backoffBaseMs?: number | undefined;
  /** Plafond du backoff (défaut et maximum 30 s). */
  backoffMaxMs?: number | undefined;
  /** Délai d'établissement de la connexion (défaut 10 s). */
  connectTimeoutMs?: number | undefined;
  /** Délai sans trame avant de considérer la connexion morte (défaut 90 s). */
  staleTimeoutMs?: number | undefined;
}

/** Options d'un appel à `stream()`. */
export interface StreamOptions {
  /** Filtre les types de trame (`["finding"]`…). Un filtre explicite exclut `hello`. */
  types?: readonly string[] | undefined;
  /** `true` : conserve les trames `heartbeat` (ignorées par défaut). */
  includeHeartbeat?: boolean | undefined;
  /** Arrête l'itérateur après N trames livrées. */
  maxMessages?: number | undefined;
  /** Arrêt propre : l'itérateur se termine et la connexion est fermée. */
  signal?: AbortSignal | undefined;
  /** `false` : aucune reconnexion, la coupure est propagée (défaut `true`). */
  reconnect?: boolean | undefined;
  /** Nombre maximal de tentatives de reconnexion consécutives (défaut 10). */
  maxReconnectAttempts?: number | undefined;
  /** Rappel invoqué avant chaque reconnexion. */
  onReconnect?: ((info: ReconnectInfo) => void) | undefined;
  /** Surcharge du délai « connexion morte » pour cet appel. */
  staleTimeoutMs?: number | undefined;
}

/* ====================================================================================== */
/* File d'attente de trames                                                                */
/* ====================================================================================== */

/** File interne : découple la réception (événements) de la consommation (itérateur). */
class FrameQueue {
  private items: StreamFrame[] = [];
  private waiters: Array<() => void> = [];
  private closed = false;
  private failure: Error | null = null;
  private code: number | null = null;

  push(frame: StreamFrame): void {
    if (this.closed) {
      return;
    }
    this.items.push(frame);
    this.wake();
  }

  shift(): StreamFrame | undefined {
    return this.items.shift();
  }

  get size(): number {
    return this.items.length;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  /** Erreur associée à la fermeture (coupure, erreur de transport). */
  get error(): Error | null {
    return this.failure;
  }

  /** Code de fermeture WebSocket observé, `null` si inconnu. */
  get closeCode(): number | null {
    return this.code;
  }

  markClosed(failure?: Error, code?: number | null): void {
    if (failure !== undefined && this.failure === null) {
      this.failure = failure;
    }
    if (code !== undefined && code !== null && this.code === null) {
      this.code = code;
    }
    this.closed = true;
    this.wake();
  }

  /** Attend une trame, la fermeture de la file, ou l'annulation du signal. */
  wait(signal?: AbortSignal | undefined): Promise<void> {
    if (this.items.length > 0 || this.closed || signal?.aborted === true) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      const done = (): void => {
        signal?.removeEventListener("abort", done);
        resolve();
      };
      this.waiters.push(done);
      signal?.addEventListener("abort", done, { once: true });
    });
  }

  private wake(): void {
    const waiters = this.waiters;
    this.waiters = [];
    for (const waiter of waiters) {
      waiter();
    }
  }
}

/* ====================================================================================== */
/* Utilitaires d'événement                                                                 */
/* ====================================================================================== */

/** Message lisible pour un événement de transport inconnu. */
function describeEvent(event: unknown): string {
  if (event instanceof Error) {
    return event.message;
  }
  if (typeof event === "object" && event !== null) {
    const record = event as Record<string, unknown>;
    const message = record["message"];
    if (typeof message === "string" && message !== "") {
      return message;
    }
    const reason = record["reason"];
    if (typeof reason === "string" && reason !== "") {
      return reason;
    }
    const type = record["type"];
    if (typeof type === "string" && type !== "") {
      return `événement « ${type} »`;
    }
  }
  return "événement de transport";
}

/** Code de fermeture porté par un événement `close`. */
function closeCodeOf(event: unknown): number | null {
  if (typeof event === "object" && event !== null) {
    const code = (event as Record<string, unknown>)["code"];
    if (typeof code === "number" && Number.isFinite(code)) {
      return code;
    }
  }
  return null;
}

/** Charge utile texte (ou binaire) d'un événement `message`. */
function messageDataOf(event: unknown): string | null {
  if (typeof event === "string") {
    return event;
  }
  if (typeof event !== "object" || event === null) {
    return null;
  }
  const data = (event as Record<string, unknown>)["data"];
  if (typeof data === "string") {
    return data;
  }
  if (typeof ArrayBuffer !== "undefined" && data instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(data));
  }
  if (typeof Uint8Array !== "undefined" && data instanceof Uint8Array) {
    return new TextDecoder().decode(data);
  }
  return null;
}

/** Décide si une trame doit être livrée à l'appelant. */
function shouldDeliver(
  frame: StreamFrame,
  wanted: ReadonlySet<string> | null,
  includeHeartbeat: boolean,
): boolean {
  if (wanted !== null) {
    return wanted.has(frame.type.toLowerCase());
  }
  if (frame.type === "heartbeat") {
    return includeHeartbeat;
  }
  return true;
}

/* ====================================================================================== */
/* Client de flux                                                                          */
/* ====================================================================================== */

/**
 * Client du flux temps réel : reconnexion, détection de `heartbeat`/`hello`, filtrage par type,
 * itérateur asynchrone et arrêt propre.
 *
 * ```ts
 * const client = new ThotSecureClient({ apiKey: process.env.THOT_SECURE_API_KEY, tenantId: "acme" });
 * const controller = new AbortController();
 * for await (const frame of client.stream({ types: ["finding"], signal: controller.signal })) {
 *   console.log(frame.type, frame.data);
 * }
 * ```
 */
export class ThotSecureStream {
  /** URL du flux — **contient la clé API** : utilisez `redactUrl()` pour la journaliser. */
  readonly url: string;
  /** Nombre de reconnexions effectuées depuis la création de l'objet. */
  reconnect_count = 0;
  /** Dernier `heartbeat` reçu (ISO 8601 UTC), `null` si aucun. */
  last_heartbeat_at: string | null = null;

  private readonly webSocketFactory: WebSocketFactory | undefined;
  private readonly logger: StreamLogger | undefined;
  private readonly sleep: (delayMs: number, signal?: AbortSignal | undefined) => Promise<void>;
  private readonly random: () => number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly connectTimeoutMs: number;
  private readonly staleTimeoutMs: number;
  private socket: WebSocketLike | null = null;
  private detach: (() => void) | null = null;
  private queue: FrameQueue | null = null;
  private closed = false;

  constructor(options: ThotSecureStreamOptions) {
    const url = options.url?.trim() ?? "";
    if (url === "") {
      throw new ValidationError("ThotSecureStream : URL de flux requise", { code: "validation_error" });
    }
    if (!/^wss?:\/\//i.test(url)) {
      throw new ValidationError(
        `ThotSecureStream : l'URL doit commencer par ws:// ou wss:// (reçu : « ${redactUrl(url) ?? ""} »)`,
        { code: "validation_error" },
      );
    }
    this.url = url;
    this.webSocketFactory = options.webSocketFactory;
    this.logger = options.logger;
    this.sleep = options.sleep ?? sleepMs;
    this.random = options.random ?? Math.random;
    this.backoffBaseMs = Math.max(0, options.backoffBaseMs ?? BACKOFF_BASE_MS);
    this.backoffMaxMs = Math.max(
      0,
      Math.min(BACKOFF_MAX_MS, options.backoffMaxMs ?? BACKOFF_MAX_MS),
    );
    this.connectTimeoutMs = Math.max(0, options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS);
    this.staleTimeoutMs = Math.max(0, options.staleTimeoutMs ?? DEFAULT_STALE_TIMEOUT_MS);
  }

  /** Représentation sûre : jamais de clé API en clair. */
  override toString(): string {
    return `ThotSecureStream(url=${redactUrl(this.url) ?? ""}, reconnect_count=${this.reconnect_count})`;
  }

  /** URL du flux (contient la clé API : à ne pas journaliser telle quelle). */
  buildUrl(): string {
    return this.url;
  }

  /** `true` après `close()`. */
  get is_closed(): boolean {
    return this.closed;
  }

  /** `true` si la socket est ouverte. */
  get is_connected(): boolean {
    return this.socket !== null && this.socket.readyState === WS_OPEN;
  }

  /**
   * Arrêt propre : ferme la connexion courante (trame `Close` 1000) et termine tout itérateur
   * `stream()` en cours. L'objet n'est plus réutilisable ; créez-en un nouveau pour repartir.
   */
  close(code = 1000, reason = "client closed"): void {
    this.closed = true;
    const socket = this.socket;
    this.socket = null;
    this.queue?.markClosed();
    this.queue = null;
    const detach = this.detach;
    this.detach = null;
    if (detach !== null) {
      detach();
    }
    if (socket !== null) {
      try {
        socket.close(code, reason);
      } catch {
        // Fermeture best effort : la connexion est peut-être déjà morte.
      }
    }
  }

  /**
   * Itère sur les trames du flux, en se reconnectant si nécessaire.
   *
   * * les `heartbeat` sont ignorés sauf `includeHeartbeat: true` ;
   * * `hello` est livré quand aucun filtre `types` n'est fourni ;
   * * une coupure déclenche une reconnexion avec backoff exponentiel plafonné à 30 s et jitter ;
   * * au-delà de `maxReconnectAttempts`, l'erreur de transport est propagée ;
   * * `signal` (ou `close()`) termine l'itérateur proprement.
   */
  async *stream(options: StreamOptions = {}): AsyncGenerator<StreamFrame, void, undefined> {
    const wanted =
      options.types === undefined || options.types.length === 0
        ? null
        : new Set(options.types.map((type) => type.toLowerCase()));
    const includeHeartbeat = options.includeHeartbeat === true;
    const maxMessages = options.maxMessages ?? null;
    const reconnect = options.reconnect !== false;
    const maxAttempts = Math.max(0, options.maxReconnectAttempts ?? 10);
    const staleTimeoutMs = Math.max(0, options.staleTimeoutMs ?? this.staleTimeoutMs);
    const signal = options.signal;

    let delivered = 0;
    let attempt = 0;

    for (;;) {
      if (this.closed || signal?.aborted === true) {
        return;
      }

      if (this.socket === null) {
        const queue = new FrameQueue();
        this.queue = queue;
        try {
          await this.connect(queue, staleTimeoutMs, signal);
          attempt = 0;
        } catch (error) {
          if (this.closed || signal?.aborted === true || isAbortError(error)) {
            return;
          }
          const retryable = error instanceof ThotSecureError ? error.retryable : true;
          if (!reconnect || !retryable || attempt >= maxAttempts) {
            throw error;
          }
          const delayMs = this.delayFor(attempt);
          attempt += 1;
          this.reconnect_count += 1;
          options.onReconnect?.({
            attempt,
            delayMs,
            reason: error instanceof Error ? error.message : "connexion impossible",
            closeCode: null,
          });
          this.log(
            "warn",
            `connexion au flux impossible — nouvelle tentative ${attempt}/${maxAttempts} dans ${delayMs} ms`,
            { url: redactUrl(this.url) },
          );
          try {
            await this.sleep(delayMs, signal);
          } catch {
            return; // annulation pendant l'attente
          }
          continue;
        }
      }

      const queue = this.queue;
      if (queue === null) {
        return;
      }

      // --- lecture des trames de la connexion courante -----------------------------------
      for (;;) {
        const frame = queue.shift();
        if (frame !== undefined) {
          if (shouldDeliver(frame, wanted, includeHeartbeat)) {
            yield frame;
            delivered += 1;
            if (maxMessages !== null && delivered >= maxMessages) {
              this.close(1000, "max messages reached");
              return;
            }
          }
          continue;
        }
        if (queue.isClosed || this.socket === null) {
          break;
        }
        await queue.wait(signal);
        if (this.closed || signal?.aborted === true) {
          return;
        }
      }

      // --- connexion interrompue ---------------------------------------------------------
      if (this.closed || signal?.aborted === true) {
        return;
      }
      const failure =
        queue.error ??
        new WebSocketError("flux WebSocket interrompu par le serveur", { url: this.url });
      const closeCode = queue.closeCode;
      this.detachSocket();

      if (!reconnect || attempt >= maxAttempts) {
        throw failure;
      }
      const delayMs = this.delayFor(attempt);
      attempt += 1;
      this.reconnect_count += 1;
      options.onReconnect?.({
        attempt,
        delayMs,
        reason: failure.message,
        closeCode,
      });
      this.log(
        "warn",
        `flux interrompu (${failure.message}) — reconnexion ${attempt}/${maxAttempts} dans ${delayMs} ms`,
        { url: redactUrl(this.url) },
      );
      try {
        await this.sleep(delayMs, signal);
      } catch {
        return; // annulation pendant l'attente
      }
    }
  }

  /* ------------------------------------------------------------------------------ */
  /* Internes                                                                        */
  /* ------------------------------------------------------------------------------ */

  private log(
    level: "debug" | "info" | "warn" | "error",
    message: string,
    context: Record<string, unknown>,
  ): void {
    const logger = this.logger;
    if (logger === undefined) {
      return;
    }
    const line = `[thot-secure-sdk/ws] ${message}`;
    switch (level) {
      case "debug":
        logger.debug?.(line, context);
        return;
      case "info":
        logger.info?.(line, context);
        return;
      case "error":
        if (typeof logger.error === "function") {
          logger.error(line, context);
          return;
        }
        logger.warn(line, context);
        return;
      default:
        logger.warn(line, context);
    }
  }

  private delayFor(attempt: number): number {
    return computeReconnectDelay(attempt, this.backoffBaseMs, this.backoffMaxMs, this.random);
  }

  /** Détache la connexion courante sans marquer le flux comme fermé. */
  private detachSocket(): void {
    const detach = this.detach;
    this.detach = null;
    this.socket = null;
    this.queue = null;
    if (detach !== null) {
      detach();
    }
  }

  /** Ouvre la connexion et résout lorsque l'ouverture est confirmée. */
  private connect(
    queue: FrameQueue,
    staleTimeoutMs: number,
    signal?: AbortSignal | undefined,
  ): Promise<void> {
    if (signal?.aborted === true) {
      this.queue = null;
      return Promise.reject(
        new WebSocketError("connexion annulée avant ouverture", {
          url: this.url,
          code: "aborted",
          retryable: false,
        }),
      );
    }
    const factory = this.webSocketFactory ?? defaultWebSocketFactory;
    let socket: WebSocketLike;
    try {
      socket = factory(this.url);
    } catch (error) {
      this.queue = null;
      return Promise.reject(
        error instanceof ThotSecureError
          ? error
          : new WebSocketError(
              `connexion WebSocket impossible : ${error instanceof Error ? error.message : "erreur inconnue"}`,
              { url: this.url, cause: error, retryable: true },
            ),
      );
    }
    this.socket = socket;

    return new Promise<void>((resolve, reject) => {
      let opened = false;
      let staleTimer: ReturnType<typeof setTimeout> | null = null;
      let connectTimer: ReturnType<typeof setTimeout> | null = null;

      const clearStale = (): void => {
        if (staleTimer !== null) {
          clearTimeout(staleTimer);
          staleTimer = null;
        }
      };
      const clearConnect = (): void => {
        if (connectTimer !== null) {
          clearTimeout(connectTimer);
          connectTimer = null;
        }
      };
      const armStale = (): void => {
        clearStale();
        if (staleTimeoutMs <= 0) {
          return;
        }
        staleTimer = setTimeout(() => {
          this.log(
            "warn",
            `aucune trame depuis ${staleTimeoutMs} ms : connexion considérée morte`,
            { url: redactUrl(this.url) },
          );
          queue.markClosed(
            new WebSocketError(
              `aucune trame reçue pendant ${staleTimeoutMs} ms (heartbeat attendu)`,
              { url: this.url, retryable: true },
            ),
          );
          try {
            socket.close(1000, "stale");
          } catch {
            // best effort
          }
        }, staleTimeoutMs);
      };

      const onAbort = (): void => {
        if (opened) {
          return;
        }
        opened = true;
        cleanup();
        try {
          socket.close(1000, "client aborted");
        } catch {
          // best effort
        }
        reject(
          new WebSocketError("connexion annulée avant ouverture", {
            url: this.url,
            code: "aborted",
            retryable: false,
          }),
        );
      };

      const cleanup = (): void => {
        clearStale();
        clearConnect();
        socket.removeEventListener("open", onOpen);
        socket.removeEventListener("message", onMessage);
        socket.removeEventListener("error", onError);
        socket.removeEventListener("close", onClose);
        signal?.removeEventListener("abort", onAbort);
        if (this.socket === socket) {
          this.socket = null;
        }
      };
      this.detach = cleanup;

      const onOpen = (): void => {
        if (opened) {
          return;
        }
        opened = true;
        clearConnect();
        armStale();
        this.log("debug", "flux temps réel connecté", { url: redactUrl(this.url) });
        resolve();
      };

      const onMessage = (event: unknown): void => {
        armStale();
        const text = messageDataOf(event);
        if (text === null) {
          return;
        }
        const frame = this.decode(text);
        if (frame !== null) {
          if (frame.type === "heartbeat") {
            this.last_heartbeat_at = frame.received_at;
          }
          queue.push(frame);
        }
      };

      const onError = (event: unknown): void => {
        const error = new WebSocketError(`erreur de transport WebSocket : ${describeEvent(event)}`, {
          url: this.url,
          retryable: true,
        });
        queue.markClosed(error);
        if (!opened) {
          opened = true;
          cleanup();
          reject(error);
        }
      };

      const onClose = (event: unknown): void => {
        const code = closeCodeOf(event);
        const error = new WebSocketError(
          code === null
            ? "flux WebSocket fermé par le serveur"
            : `flux WebSocket fermé par le serveur (code ${code})`,
          { url: this.url, retryable: true },
        );
        queue.markClosed(error, code);
        if (!opened) {
          opened = true;
          cleanup();
          reject(error);
        }
      };

      if (connectTimeoutMs > 0) {
        connectTimer = setTimeout(() => {
          if (opened) {
            return;
          }
          opened = true;
          cleanup();
          try {
            socket.close(1000, "connect timeout");
          } catch {
            // best effort
          }
          reject(
            new WebSocketError(
              `délai d'établissement de la connexion dépassé (${connectTimeoutMs} ms)`,
              { url: this.url, retryable: true },
            ),
          );
        }, connectTimeoutMs);
      }

      socket.addEventListener("open", onOpen);
      socket.addEventListener("message", onMessage);
      socket.addEventListener("error", onError);
      socket.addEventListener("close", onClose);
      signal?.addEventListener("abort", onAbort, { once: true });

      if (socket.readyState === WS_OPEN) {
        onOpen();
      }
    });
  }

  /** Décode un message texte en trame applicative (`null` si totalement inexploitable). */
  private decode(text: string): StreamFrame | null {
    const receivedAt = new Date().toISOString();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      return {
        type: RAW_TYPE,
        data: text.slice(0, 2048),
        raw: {},
        received_at: receivedAt,
      };
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return {
        type: RAW_TYPE,
        data: parsed as JsonValue,
        raw: {},
        received_at: receivedAt,
      };
    }
    const record = parsed as Record<string, unknown>;
    const rawType = record["type"];
    const frame: StreamFrame = {
      type: typeof rawType === "string" && rawType !== "" ? rawType : "unknown",
      data: (record["data"] ?? null) as JsonValue,
      raw: record as JsonObject,
      received_at: receivedAt,
    };
    if (frame.type === HELLO_TYPE) {
      this.log("debug", "flux confirmé par le serveur (trame hello)", {
        url: redactUrl(this.url),
      });
    }
    return frame;
  }
}
