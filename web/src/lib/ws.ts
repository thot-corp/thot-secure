/**
 * Flux temps réel — `WS /api/v1/ws/stream` (contrat §4.8).
 *
 * Le WebSocket accepte `?api_key=…&tenant_id=…` car les navigateurs ne peuvent
 * pas poser d'en-tête `X-API-Key` sur `ws://` (contrat §4).
 *
 * Le cœur du module est `LiveStreamClient`, agnostique de React : il gère la
 * connexion, la reconnexion exponentielle **avec jitter** plafonnée à 30 s, la
 * détection de `heartbeat`, la pause/reprise du tampon, et expose un instantané
 * immuable consommé par `useLiveStream`.
 */
import { useCallback, useEffect, useMemo, useSyncExternalStore } from 'react';

import { useAuth } from './auth';
import { resolveApiBaseUrl } from './api';
import type {
  JsonObject,
  LiveFrame,
  LiveFrameType,
  Severity,
} from './types';
import { LIVE_FRAME_TYPES } from './types';

/* -------------------------------------------------------------------------- */
/* Constantes de réglage                                                       */
/* -------------------------------------------------------------------------- */

export const LIVE_STREAM_PATH = '/ws/stream';
export const DEFAULT_BUFFER_SIZE = 500;
export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 45_000;
export const DEFAULT_WATCHDOG_INTERVAL_MS = 5_000;
export const DEFAULT_BASE_BACKOFF_MS = 500;
export const MAX_BACKOFF_MS = 30_000;
export const DEFAULT_JITTER_RATIO = 0.5;

/** Codes de fermeture considérés comme « non réessayable » (auth/périmètre). */
export const UNAUTHORIZED_CLOSE_CODES: readonly number[] = [1008, 4001, 4003, 4401, 4403];

/* -------------------------------------------------------------------------- */
/* Types publics                                                               */
/* -------------------------------------------------------------------------- */

export type LiveStreamStatus =
  | 'idle'
  | 'connecting'
  | 'open'
  | 'reconnecting'
  | 'closed'
  | 'unauthorized'
  | 'error';

export interface LiveStreamState {
  status: LiveStreamStatus;
  /** Nombre de tentatives de reconnexion consécutives. */
  attempts: number;
  /** Délai programmé avant la prochaine tentative (ms), `null` si aucune. */
  nextRetryMs: number | null;
  lastMessageAt: number | null;
  lastHeartbeatAt: number | null;
  /** Nombre de heartbeats reçus depuis l'ouverture du flux. */
  heartbeats: number;
  lastError: string | null;
  lastCloseCode: number | null;
  lastCloseReason: string | null;
  /** Frames utiles reçues (hors heartbeat). */
  received: number;
  /** Frames illisibles ignorées. */
  invalidFrames: number;
  /** Frames perdues par dépassement de tampon. */
  dropped: number;
  /** Frames mises en attente pendant la pause. */
  buffered: number;
  paused: boolean;
  frames: readonly LiveFrame[];
}

/** Sous-ensemble structurel de `WebSocket` utilisé par le client. */
export interface WebSocketLike {
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onclose: ((event: { code?: number; reason?: string; wasClean?: boolean }) => void) | null;
  close(code?: number, reason?: string): void;
}

export type WebSocketFactory = (url: string) => WebSocketLike;

export interface BackoffOptions {
  baseMs: number;
  maxMs: number;
  jitterRatio: number;
  random: () => number;
}

export interface LiveStreamOptions {
  apiKey: string | null;
  tenantId: string | null;
  baseUrl?: string;
  bufferSize?: number;
  heartbeatTimeoutMs?: number;
  watchdogIntervalMs?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
  jitterRatio?: number;
  maxAttempts?: number;
  now?: () => number;
  random?: () => number;
  socketFactory?: WebSocketFactory;
  onFrame?: (frame: LiveFrame) => void;
}

export interface LocationLike {
  protocol: string;
  host: string;
}

/* -------------------------------------------------------------------------- */
/* Fonctions pures (testables sans DOM)                                        */
/* -------------------------------------------------------------------------- */

/**
 * Backoff exponentiel plafonné avec jitter « égal » :
 * `delay = min(maxMs, baseMs · 2^attempt) · (1 − jitterRatio + jitterRatio · r)`
 * avec `r ∈ [0,1)`. Plafond dur : `MAX_BACKOFF_MS` (30 s).
 */
export function computeBackoff(attempt: number, options: Partial<BackoffOptions> = {}): number {
  const baseMs = options.baseMs ?? DEFAULT_BASE_BACKOFF_MS;
  const maxMs = Math.min(options.maxMs ?? MAX_BACKOFF_MS, MAX_BACKOFF_MS);
  const jitterRatio = Math.min(Math.max(options.jitterRatio ?? DEFAULT_JITTER_RATIO, 0), 1);
  const random = options.random ?? Math.random;

  const safeAttempt = Number.isFinite(attempt) ? Math.max(0, Math.floor(attempt)) : 0;
  // 2^attempt explose vite : on borne l'exposant avant le calcul.
  const exponential = baseMs * Math.pow(2, Math.min(safeAttempt, 16));
  const capped = Math.min(maxMs, exponential);
  const factor = 1 - jitterRatio + jitterRatio * random();
  return Math.max(0, Math.min(maxMs, Math.round(capped * factor)));
}

/** Base WebSocket dérivée de la base d'API (`http(s)://` → `ws(s)://`). */
export function toWebSocketBase(apiBaseUrl: string | undefined, location: LocationLike): string {
  const apiBase = resolveApiBaseUrl(apiBaseUrl);
  if (/^https?:\/\//i.test(apiBase)) {
    return apiBase.replace(/^http(s?):\/\//i, (_match, secure: string) =>
      secure === 's' ? 'wss://' : 'ws://',
    );
  }
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const path = apiBase.startsWith('/') ? apiBase : `/${apiBase}`;
  return `${protocol}//${location.host}${path}`;
}

/** URL complète du flux, clé et tenant encodés. */
export function resolveWebSocketUrl(args: {
  apiKey: string;
  tenantId: string;
  baseUrl?: string;
  location?: LocationLike;
}): string {
  const location: LocationLike =
    args.location ??
    (typeof window !== 'undefined' && window.location
      ? { protocol: window.location.protocol, host: window.location.host }
      : { protocol: 'http:', host: '127.0.0.1:8080' });
  const base = toWebSocketBase(args.baseUrl, location);
  const query = `api_key=${encodeURIComponent(args.apiKey)}&tenant_id=${encodeURIComponent(args.tenantId)}`;
  return `${base}${LIVE_STREAM_PATH}?${query}`;
}

/** Analyse défensive d'une frame brute. `null` si illisible. */
export function parseLiveFrame(raw: unknown): LiveFrame | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  const type = record['type'];
  if (typeof type !== 'string') return null;
  if (!(LIVE_FRAME_TYPES as readonly string[]).includes(type)) return null;
  const data = record['data'];
  const dataObject =
    data !== null && typeof data === 'object' && !Array.isArray(data) ? (data as JsonObject) : {};
  return { type: type as LiveFrameType, data: dataObject };
}

/* -------------------------------------------------------------------------- */
/* Projection d'affichage                                                      */
/* -------------------------------------------------------------------------- */

export interface LiveRow {
  key: string;
  type: LiveFrameType;
  ts: string | null;
  severity: Severity | null;
  status: string | null;
  title: string;
  summary: string;
  raw: JsonObject;
}

const SEVERITY_VALUES: readonly string[] = ['info', 'low', 'medium', 'high', 'critical'];

function pickString(source: JsonObject, key: string): string | null {
  const value = source[key];
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

function pickNumber(source: JsonObject, key: string): number | null {
  const value = source[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function pickObject(source: JsonObject, key: string): JsonObject | null {
  const value = source[key];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as JsonObject;
}

function pickSeverity(source: JsonObject, key: string): Severity | null {
  const raw = pickString(source, key);
  if (raw !== null && SEVERITY_VALUES.includes(raw)) return raw as Severity;
  return null;
}

function joinParts(parts: readonly (string | null)[], separator = ' · '): string {
  return parts.filter((part): part is string => Boolean(part && part !== '')).join(separator);
}

/** Projette une frame brute en ligne affichable, sans jamais interpréter de HTML. */
export function toLiveRow(frame: LiveFrame, index: number): LiveRow {
  const data = frame.data;
  const labels = pickObject(data, 'labels');
  const source = pickObject(data, 'source');
  const target = pickObject(data, 'target');

  const identity =
    pickString(data, 'event_id') ??
    pickString(data, 'finding_id') ??
    pickString(data, 'action_id') ??
    (pickNumber(data, 'seq') !== null ? `seq-${String(pickNumber(data, 'seq'))}` : null) ??
    `#${index}`;

  const key = `${frame.type}-${identity}-${index}`;

  switch (frame.type) {
    case 'finding': {
      const decision = pickString(data, 'decision');
      return {
        key,
        type: frame.type,
        ts: pickString(data, 'last_seen') ?? pickString(data, 'created_at'),
        severity: pickSeverity(data, 'severity'),
        status: pickString(data, 'status'),
        title: pickString(data, 'title') ?? pickString(data, 'rule_id') ?? 'Finding',
        summary: joinParts([
          pickString(data, 'rule_id'),
          `risque ${pickString(data, 'risk_score') ?? '—'}`,
          decision ? `décision ${decision}` : null,
        ]),
        raw: data,
      };
    }
    case 'action': {
      return {
        key,
        type: frame.type,
        ts: pickString(data, 'requested_at') ?? pickString(data, 'executed_at'),
        severity: null,
        status: pickString(data, 'status'),
        title: pickString(data, 'playbook') ?? 'Action',
        summary: joinParts([
          target ? pickString(target, 'value') : null,
          pickString(data, 'dry_run') === 'true' ? 'dry-run' : null,
          pickString(data, 'requested_by'),
        ]),
        raw: data,
      };
    }
    case 'audit': {
      const auditTarget = pickObject(data, 'target');
      return {
        key,
        type: frame.type,
        ts: pickString(data, 'ts'),
        severity: null,
        status: null,
        title: pickString(data, 'action') ?? 'Audit',
        summary: joinParts([
          pickString(data, 'actor'),
          auditTarget ? pickString(auditTarget, 'id') : null,
        ]),
        raw: data,
      };
    }
    case 'event': {
      return {
        key,
        type: frame.type,
        ts: pickString(data, 'ts'),
        severity: pickSeverity(data, 'severity_hint'),
        status: null,
        title: pickString(data, 'kind') ?? 'Événement',
        summary: joinParts([
          source ? pickString(source, 'type') : null,
          labels ? pickString(labels, 'src_ip') : null,
          labels ? pickString(labels, 'path') : null,
        ]),
        raw: data,
      };
    }
    case 'heartbeat':
    default: {
      return {
        key,
        type: frame.type,
        ts: pickString(data, 'ts'),
        severity: null,
        status: null,
        title: 'Heartbeat',
        summary: pickString(data, 'status') ?? 'flux actif',
        raw: data,
      };
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Client de flux                                                              */
/* -------------------------------------------------------------------------- */

function defaultSocketFactory(url: string): WebSocketLike {
  // Adaptation structurelle : seuls les handlers et `close()` sont utilisés.
  return new WebSocket(url) as unknown as WebSocketLike;
}

function createInitialState(): LiveStreamState {
  return {
    status: 'idle',
    attempts: 0,
    nextRetryMs: null,
    lastMessageAt: null,
    lastHeartbeatAt: null,
    heartbeats: 0,
    lastError: null,
    lastCloseCode: null,
    lastCloseReason: null,
    received: 0,
    invalidFrames: 0,
    dropped: 0,
    buffered: 0,
    paused: false,
    frames: [],
  };
}

export class LiveStreamClient {
  private readonly apiKey: string | null;
  private readonly tenantId: string | null;
  private readonly baseUrl: string | undefined;
  private readonly bufferSize: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly watchdogIntervalMs: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly jitterRatio: number;
  private readonly maxAttempts: number;
  private readonly clock: () => number;
  private readonly random: () => number;
  private readonly factory: WebSocketFactory;
  private readonly onFrame: ((frame: LiveFrame) => void) | undefined;

  private state: LiveStreamState = createInitialState();
  private readonly listeners = new Set<(state: LiveStreamState) => void>();

  private socket: WebSocketLike | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;
  private buffer: LiveFrame[] = [];
  private stopping = false;
  private running = false;

  constructor(options: LiveStreamOptions) {
    this.apiKey = options.apiKey;
    this.tenantId = options.tenantId;
    this.baseUrl = options.baseUrl;
    this.bufferSize = Math.max(1, options.bufferSize ?? DEFAULT_BUFFER_SIZE);
    this.heartbeatTimeoutMs = Math.max(
      1_000,
      options.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS,
    );
    this.watchdogIntervalMs = Math.max(500, options.watchdogIntervalMs ?? DEFAULT_WATCHDOG_INTERVAL_MS);
    this.baseBackoffMs = Math.max(1, options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS);
    this.maxBackoffMs = Math.min(options.maxBackoffMs ?? MAX_BACKOFF_MS, MAX_BACKOFF_MS);
    this.jitterRatio = options.jitterRatio ?? DEFAULT_JITTER_RATIO;
    this.maxAttempts = options.maxAttempts ?? Number.POSITIVE_INFINITY;
    this.clock = options.now ?? (() => Date.now());
    this.random = options.random ?? Math.random;
    this.factory = options.socketFactory ?? defaultSocketFactory;
    this.onFrame = options.onFrame;
  }

  /* ---------------------------- Abonnement ------------------------------- */

  getState = (): LiveStreamState => this.state;

  subscribe = (listener: (state: LiveStreamState) => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private setState(partial: Partial<LiveStreamState>): void {
    const previous = this.state;
    const merged: LiveStreamState = { ...previous, ...partial };
    let changed = false;
    for (const key of Object.keys(partial) as (keyof LiveStreamState)[]) {
      if (!Object.is(previous[key], merged[key])) {
        changed = true;
        break;
      }
    }
    if (!changed) return;
    this.state = merged;
    for (const listener of this.listeners) listener(this.state);
  }

  /* ------------------------------ Cycle de vie --------------------------- */

  start(): void {
    if (this.running) return;
    this.running = true;
    this.stopping = false;

    if (!this.apiKey || !this.tenantId) {
      this.setState({
        status: 'idle',
        lastError: null,
      });
      return;
    }

    this.setState({ status: 'connecting', attempts: 0, nextRetryMs: null, lastError: null });
    this.openSocket();
  }

  stop(): void {
    this.stopping = true;
    this.running = false;
    this.clearRetryTimer();
    this.stopWatchdog();
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close(1000, 'client shutdown');
      } catch {
        /* socket déjà fermé */
      }
    }
    this.setState({
      status: 'closed',
      nextRetryMs: null,
      paused: false,
      buffered: 0,
    });
    this.buffer = [];
  }

  /** Force une reconnexion immédiate (bouton « reconnecter »). */
  reconnectNow(): void {
    this.clearRetryTimer();
    this.stopWatchdog();
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onclose = null;
      try {
        socket.close(4000, 'manual reconnect');
      } catch {
        /* socket déjà fermé */
      }
    }
    if (!this.running) {
      this.start();
      return;
    }
    this.setState({ attempts: 0, status: 'connecting', nextRetryMs: null });
    this.openSocket();
  }

  /** Met le flux en pause : les frames suivantes sont mises en tampon borné. */
  pause(): void {
    this.setState({ paused: true });
  }

  /** Reprend le flux et vide le tampon dans l'ordre de réception. */
  resume(): void {
    if (!this.state.paused) return;
    const pending = this.buffer;
    this.buffer = [];
    if (pending.length === 0) {
      this.setState({ paused: false, buffered: 0 });
      return;
    }
    const combined = [...this.state.frames, ...pending];
    const overflow = Math.max(0, combined.length - this.bufferSize);
    this.setState({
      paused: false,
      buffered: 0,
      dropped: this.state.dropped + overflow,
      frames: overflow > 0 ? combined.slice(overflow) : combined,
    });
  }

  /** Vide la table affichée (les compteurs cumulés sont conservés). */
  clear(): void {
    this.buffer = [];
    this.setState({ frames: [], buffered: 0, dropped: 0 });
  }

  /* -------------------------------- Interne ------------------------------ */

  private openSocket(): void {
    const apiKey = this.apiKey;
    const tenantId = this.tenantId;
    if (!apiKey || !tenantId || this.stopping) return;

    const url = resolveWebSocketUrl({
      apiKey,
      tenantId,
      ...(this.baseUrl !== undefined ? { baseUrl: this.baseUrl } : {}),
    });

    let socket: WebSocketLike;
    try {
      socket = this.factory(url);
    } catch (cause) {
      this.setState({
        lastError: cause instanceof Error ? cause.message : 'Création du WebSocket impossible.',
      });
      this.scheduleReconnect();
      return;
    }

    this.socket = socket;
    socket.onopen = () => {
      if (this.socket !== socket) return;
      this.setState({
        status: 'open',
        attempts: 0,
        nextRetryMs: null,
        lastError: null,
        lastMessageAt: this.clock(),
      });
      this.startWatchdog();
    };
    socket.onmessage = (event) => {
      if (this.socket !== socket) return;
      this.handleMessage(event?.data);
    };
    socket.onerror = () => {
      if (this.socket !== socket) return;
      this.setState({ lastError: 'Erreur de transport sur le flux temps réel.' });
    };
    socket.onclose = (event) => {
      if (this.socket !== socket) return;
      this.socket = null;
      this.stopWatchdog();
      this.handleClose(event?.code ?? 1006, event?.reason ?? '');
    };
  }

  private handleMessage(raw: unknown): void {
    const now = this.clock();
    this.setState({ lastMessageAt: now });

    const frame = parseLiveFrame(raw);
    if (!frame) {
      this.setState({ invalidFrames: this.state.invalidFrames + 1 });
      return;
    }

    if (frame.type === 'heartbeat') {
      this.setState({
        heartbeats: this.state.heartbeats + 1,
        lastHeartbeatAt: now,
      });
      return;
    }

    if (this.state.paused) {
      const nextBuffer = [...this.buffer, frame];
      const overflow = Math.max(0, nextBuffer.length - this.bufferSize);
      this.buffer = overflow > 0 ? nextBuffer.slice(overflow) : nextBuffer;
      this.setState({
        buffered: this.buffer.length,
        dropped: this.state.dropped + overflow,
        received: this.state.received + 1,
      });
    } else {
      const combined = [...this.state.frames, frame];
      const overflow = Math.max(0, combined.length - this.bufferSize);
      this.setState({
        frames: overflow > 0 ? combined.slice(overflow) : combined,
        dropped: this.state.dropped + overflow,
        received: this.state.received + 1,
      });
    }

    this.onFrame?.(frame);
  }

  private handleClose(code: number, reason: string): void {
    if (this.stopping) {
      this.setState({ status: 'closed', lastCloseCode: code, lastCloseReason: reason });
      return;
    }

    if (UNAUTHORIZED_CLOSE_CODES.includes(code)) {
      // Inutile d'insister : clé invalide/révoquée ou tenant hors périmètre.
      this.running = false;
      this.setState({
        status: 'unauthorized',
        nextRetryMs: null,
        lastCloseCode: code,
        lastCloseReason: reason,
        lastError:
          'Flux refusé par le serveur : clé API invalide ou révoquée, ou tenant hors périmètre.',
      });
      return;
    }

    this.setState({ lastCloseCode: code, lastCloseReason: reason });
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.stopping) return;
    if (this.state.attempts >= this.maxAttempts) {
      this.setState({
        status: 'error',
        nextRetryMs: null,
        lastError: 'Flux interrompu : nombre maximal de tentatives atteint.',
      });
      return;
    }

    const delay = computeBackoff(this.state.attempts, {
      baseMs: this.baseBackoffMs,
      maxMs: this.maxBackoffMs,
      jitterRatio: this.jitterRatio,
      random: this.random,
    });

    this.clearRetryTimer();
    this.setState({
      status: 'reconnecting',
      attempts: this.state.attempts + 1,
      nextRetryMs: delay,
      lastError: this.state.lastError ?? 'Connexion au flux interrompue, nouvelle tentative…',
    });

    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.openSocket();
    }, delay);
  }

  private startWatchdog(): void {
    this.stopWatchdog();
    this.watchdogTimer = setInterval(() => {
      const { lastMessageAt } = this.state;
      if (lastMessageAt === null) return;
      if (this.clock() - lastMessageAt <= this.heartbeatTimeoutMs) return;
      // Flux muet (heartbeat manquant) : on recycle la connexion.
      const socket = this.socket;
      this.socket = null;
      this.stopWatchdog();
      if (socket) {
        socket.onclose = null;
        try {
          socket.close(4000, 'heartbeat timeout');
        } catch {
          /* socket déjà fermé */
        }
      }
      this.setState({ lastError: 'Heartbeat manquant : connexion recyclée.' });
      this.scheduleReconnect();
    }, this.watchdogIntervalMs);
  }

  private stopWatchdog(): void {
    if (this.watchdogTimer !== null) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  private clearRetryTimer(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Hook React                                                                  */
/* -------------------------------------------------------------------------- */

export interface UseLiveStreamOptions {
  enabled?: boolean;
  bufferSize?: number;
  heartbeatTimeoutMs?: number;
}

export interface UseLiveStreamResult extends LiveStreamState {
  pause: () => void;
  resume: () => void;
  clear: () => void;
  reconnect: () => void;
}

/**
 * S'abonne au flux temps réel du tenant. Le client est recréé si la clé API ou
 * le tenant changent (donc jamais de fuite d'un flux vers un autre tenant).
 */
export function useLiveStream(
  tenantId: string | null,
  options: UseLiveStreamOptions = {},
): UseLiveStreamResult {
  const { apiKey, apiBaseUrl } = useAuth();
  const enabled = options.enabled ?? true;

  const client = useMemo(
    () =>
      new LiveStreamClient({
        apiKey: enabled ? apiKey : null,
        tenantId: enabled ? tenantId : null,
        baseUrl: apiBaseUrl,
        ...(options.bufferSize !== undefined ? { bufferSize: options.bufferSize } : {}),
        ...(options.heartbeatTimeoutMs !== undefined
          ? { heartbeatTimeoutMs: options.heartbeatTimeoutMs }
          : {}),
      }),
    [apiBaseUrl, apiKey, enabled, options.bufferSize, options.heartbeatTimeoutMs, tenantId],
  );

  useEffect(() => {
    client.start();
    return () => client.stop();
  }, [client]);

  const state = useSyncExternalStore(client.subscribe, client.getState);

  const pause = useCallback(() => client.pause(), [client]);
  const resume = useCallback(() => client.resume(), [client]);
  const clear = useCallback(() => client.clear(), [client]);
  const reconnect = useCallback(() => client.reconnectNow(), [client]);

  return useMemo(
    () => ({ ...state, pause, resume, clear, reconnect }),
    [state, pause, resume, clear, reconnect],
  );
}
