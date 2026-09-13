/**
 * Client WebSocket autonome du widget — Thot Secure (nom de code technique : Thot Secure).
 *
 * Ce fichier n'utilise **que** l'API `WebSocket` native du navigateur : aucune dépendance,
 * aucun import de `sdks/typescript` (le SDK officiel est la bonne option en production, mais
 * il est volontairement absent de cet exemple pour qu'il reste ouvrable hors ligne).
 *
 * Cible : `GET /api/v1/ws/stream?api_key=…&tenant_id=…` (contrat §4.8). Les navigateurs ne
 * peuvent pas poser d'en-tête `X-API-Key` sur `ws://` (contrat §4.1) : la clé voyage donc en
 * paramètre de requête. Conséquence directe : **toute URL construite ici contient un secret**.
 * Elle n'est jamais journalisée ni affichée telle quelle, uniquement via `redactUrl()`.
 *
 * Limite importante et documentée (voir README) : l'API `WebSocket` du navigateur n'expose
 * **aucune** méthode pour envoyer une trame de contrôle `ping` (RFC 6455 §5.5.2) ni pour lire
 * les `pong`. Impossible donc de reproduire le heartbeat bas niveau du SDK Python officiel
 * (`sdks/python/thotsecure_sdk/ws.py` envoie de vraies trames `ping`). On compense par un
 * **watchdog applicatif** : si aucune frame, `heartbeat` compris, n'arrive pendant
 * `heartbeatTimeoutMs`, la connexion est déclarée morte, fermée et la reconnexion démarre.
 */

import { FRAME_TYPES, isFrameType, isRecord } from './types.js';
import type {
  ConnectionState,
  ConnectionStatusEvent,
  FrameType,
  StreamFrame,
  WidgetError,
  WidgetErrorCode,
} from './types.js';

/** Chemin du flux temps réel (contrat §4.8). */
export const WS_PATH = '/api/v1/ws/stream';

/**
 * Paramètres de requête susceptibles de transporter un secret. `api_key` et `tenant_id`
 * viennent du contrat ; les autres sont masqués par prudence (proxy, pare-feu applicatif,
 * passerelle d'authentification).
 */
const SENSITIVE_QUERY_KEYS: readonly string[] = [
  'api_key',
  'apikey',
  'api-key',
  'access_token',
  'token',
  'password',
  'secret',
  'key',
];

/**
 * Masque tout secret présent dans une URL (ou dans un texte qui contient une URL).
 *
 * À utiliser **systématiquement** avant un `console.*`, un message d'erreur, un attribut du
 * DOM ou une notification : l'URL du flux contient `api_key=…`.
 */
export function redactUrl(url: string): string {
  if (url === '') {
    return '';
  }
  let redacted = url;
  for (const key of SENSITIVE_QUERY_KEYS) {
    const pattern = new RegExp('([?&]' + key + '=)[^&#\\s]*', 'gi');
    redacted = redacted.replace(pattern, '$1***');
  }
  // Identifiants éventuels dans la partie autorité : http://user:pass@hote/…
  redacted = redacted.replace(/(\/\/[^/@\s]+):[^/@\s]*@/g, '$1:***@');
  return redacted;
}

/** Options de `buildWsUrl`. */
export interface BuildWsUrlOptions {
  readonly apiKey?: string | undefined;
  readonly tenantId?: string | undefined;
  /** Remplace le chemin par défaut (réservé aux tests / proxys particuliers). */
  readonly path?: string | undefined;
}

/**
 * Construit l'URL `ws://` / `wss://` du flux à partir de l'URL de base de l'API.
 *
 * - `http://` → `ws://`, `https://` → `wss://` ; `ws://`/`wss://` sont conservés tels quels ;
 * - un schéma absent (`127.0.0.1:8080`) est interprété comme `http://` ;
 * - un préfixe de chemin est conservé (`https://hote/thotsecure` → `…/thotsecure/api/v1/ws/stream`)
 *   pour les déploiements derrière un reverse-proxy ;
 * - `api_key` et `tenant_id` ne sont ajoutés que s'ils sont non vides.
 *
 * ⚠️ L'URL retournée **contient la clé API** : ne la journalisez jamais, utilisez `redactUrl`.
 */
export function buildWsUrl(baseUrl: string, options: BuildWsUrlOptions = {}): string {
  const raw = baseUrl.trim();
  if (raw === '') {
    throw new Error('buildWsUrl : URL de base requise (ex. « http://127.0.0.1:8000 »).');
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw) ? raw : 'http://' + raw;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error('buildWsUrl : URL de base invalide (' + redactUrl(raw) + ').');
  }

  let scheme: string;
  switch (parsed.protocol) {
    case 'http:':
    case 'ws:':
      scheme = 'ws:';
      break;
    case 'https:':
    case 'wss:':
      scheme = 'wss:';
      break;
    default:
      throw new Error(
        'buildWsUrl : schéma non supporté (' +
          parsed.protocol +
          ') — utilisez http:// ou https:// (le passage en ws:// / wss:// est automatique).',
      );
  }

  const prefix = parsed.pathname.replace(/\/+$/, '');
  const path = options.path === undefined ? WS_PATH : options.path;
  const params = new URLSearchParams();
  const apiKey = options.apiKey === undefined ? '' : options.apiKey.trim();
  const tenantId = options.tenantId === undefined ? '' : options.tenantId.trim();
  if (apiKey !== '') {
    params.set('api_key', apiKey);
  }
  if (tenantId !== '') {
    params.set('tenant_id', tenantId);
  }
  const query = params.toString();
  return scheme + '//' + parsed.host + prefix + path + (query === '' ? '' : '?' + query);
}

/**
 * File d'attente bornée (ring buffer) : quand l'affichage est en pause, les frames continuent
 * d'arriver. On garde les `capacity` plus récentes et on compte les pertes, plutôt que de
 * laisser la mémoire croître sans limite sur un flux bavard.
 */
export class RingBuffer<T> {
  private readonly capacity: number;
  private readonly items: T[] = [];
  private droppedCount = 0;

  constructor(capacity: number) {
    const requested = Number.isFinite(capacity) ? Math.trunc(capacity) : 1;
    this.capacity = Math.max(1, requested);
  }

  push(item: T): void {
    if (this.items.length >= this.capacity) {
      this.items.shift();
      this.droppedCount += 1;
    }
    this.items.push(item);
  }

  /** Vide la file et retourne les éléments conservés, du plus ancien au plus récent. */
  drain(): T[] {
    const drained = this.items.slice();
    this.items.length = 0;
    return drained;
  }

  clear(): void {
    this.items.length = 0;
  }

  get size(): number {
    return this.items.length;
  }

  get dropped(): number {
    return this.droppedCount;
  }
}

/** Fabrique de `WebSocket` — injectable pour tester le client sans réseau. */
export type WebSocketFactory = (url: string) => WebSocket;

/** Options du client de flux. */
export interface AegisStreamClientOptions {
  readonly baseUrl: string;
  readonly apiKey?: string | undefined;
  readonly tenantId?: string | undefined;
  /** Types conservés. Liste vide ou absente = tous les types. */
  readonly types?: readonly FrameType[] | undefined;
  readonly maxReconnectAttempts?: number | undefined;
  readonly backoffBaseMs?: number | undefined;
  readonly backoffMaxMs?: number | undefined;
  readonly heartbeatTimeoutMs?: number | undefined;
  readonly ringCapacity?: number | undefined;
  readonly onFrame?: ((frame: StreamFrame) => void) | undefined;
  readonly onStatus?: ((status: ConnectionStatusEvent) => void) | undefined;
  readonly onError?: ((error: WidgetError) => void) | undefined;
  readonly webSocketFactory?: WebSocketFactory | undefined;
  /** Source d'aléa du jitter (injectable pour rendre les tests déterministes). */
  readonly random?: (() => number) | undefined;
  /** Horloge (injectable pour les tests). */
  readonly now?: (() => number) | undefined;
}

/** Message lisible pour un `unknown` attrapé dans un `catch`. */
export function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.name + ' : ' + error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  try {
    const serialized = JSON.stringify(error);
    return typeof serialized === 'string' ? serialized : String(error);
  } catch {
    return String(error);
  }
}

/**
 * Décode une charge utile textuelle en `StreamFrame` **sans jamais lever**.
 *
 * Une frame illisible (JSON invalide, texte vide, type inconnu) devient une frame de type
 * `raw` : elle ne casse pas la boucle de lecture et reste consultable dans l'interface.
 */
export function parseStreamFrame(text: string, seq: number, receivedAt: number): StreamFrame {
  const trimmed = text.trim();
  if (trimmed === '') {
    return { type: 'raw', data: '', raw: {}, text, received_at: receivedAt, seq };
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(trimmed) as unknown;
  } catch {
    return { type: 'raw', data: text, raw: {}, text, received_at: receivedAt, seq };
  }

  if (!isRecord(decoded)) {
    return { type: 'raw', data: decoded, raw: {}, text, received_at: receivedAt, seq };
  }

  const rawType = decoded['type'];
  if (!isFrameType(rawType)) {
    // Type inconnu (extension serveur, faute de frappe…) : on conserve l'objet entier.
    return { type: 'raw', data: decoded, raw: decoded, text, received_at: receivedAt, seq };
  }
  return { type: rawType, data: decoded['data'], raw: decoded, text, received_at: receivedAt, seq };
}

/** Description lisible d'une fermeture WebSocket. */
function describeCloseEvent(event: CloseEvent): string {
  const parts: string[] = ['code ' + String(event.code)];
  if (event.reason !== '') {
    parts.push('« ' + redactUrl(event.reason).slice(0, 160) + ' »');
  }
  parts.push(event.wasClean ? 'fermeture propre' : 'fermeture anormale');
  return parts.join(' — ');
}

/** Libellés français des codes de fermeture les plus courants. */
function explainCloseCode(code: number): string | null {
  switch (code) {
    case 1000:
      return 'fermeture normale';
    case 1001:
      return 'le serveur se déconnecte (redémarrage prévu ?)';
    case 1002:
      return 'erreur de protocole';
    case 1003:
      return 'type de données non accepté par le serveur';
    case 1006:
      return 'connexion perdue sans trame de fermeture (réseau coupé, proxy, service arrêté)';
    case 1008:
      return 'message refusé par la politique du serveur';
    case 1011:
      return 'erreur interne du serveur';
    case 1013:
      return 'serveur surchargé, réessayez plus tard';
    case 4000:
      return 'watchdog applicatif : plus aucune frame reçue';
    case 4001:
      return 'clé API absente ou invalide';
    case 4003:
      return 'accès refusé pour ce rôle (capacité read:events requise)';
    case 4401:
      return 'authentification requise (clé API manquante)';
    case 4403:
      return 'accès interdit (tenant ou rôle insuffisant)';
    default:
      return null;
  }
}

/**
 * Client du flux temps réel : reconnexion automatique, filtrage par type, file bornée,
 * watchdog de connexion morte.
 *
 * Cycle de vie typique :
 * ```ts
 * const client = new AegisStreamClient({ baseUrl, apiKey, tenantId, onFrame, onStatus, onError });
 * client.start();
 * // …
 * client.close();
 * ```
 */
export class AegisStreamClient {
  /** URL du flux — **contient la clé API**. Ne jamais l'afficher sans `redactUrl`. */
  readonly url: string;

  /** URL de base de l'API telle que fournie (sans clé) — pratique pour composer des liens. */
  readonly baseUrl: string;

  private readonly apiKey: string;
  private readonly tenantId: string;
  private readonly maxReconnectAttempts: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly createSocket: WebSocketFactory;
  private readonly random: () => number;
  private readonly now: () => number;
  private readonly onFrame: ((frame: StreamFrame) => void) | undefined;
  private readonly onStatus: ((status: ConnectionStatusEvent) => void) | undefined;
  private readonly onError: ((error: WidgetError) => void) | undefined;

  private readonly pending: RingBuffer<StreamFrame>;
  private types: readonly FrameType[];
  private socket: WebSocket | null = null;
  private state: ConnectionState = 'idle';
  private attempt = 0;
  private stopped = true;
  private paused = false;
  private sequence = 0;
  private received = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private watchdogTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: AegisStreamClientOptions) {
    this.baseUrl = options.baseUrl;
    this.apiKey = options.apiKey === undefined ? '' : options.apiKey;
    this.tenantId = options.tenantId === undefined ? '' : options.tenantId;
    this.types = options.types === undefined ? [] : options.types.slice();

    const maxAttempts = options.maxReconnectAttempts === undefined ? 10 : options.maxReconnectAttempts;
    this.maxReconnectAttempts = Math.max(0, Math.trunc(maxAttempts));
    const backoffBase = options.backoffBaseMs === undefined ? 500 : options.backoffBaseMs;
    this.backoffBaseMs = Math.max(1, backoffBase);
    const backoffMax = options.backoffMaxMs === undefined ? 30000 : options.backoffMaxMs;
    this.backoffMaxMs = Math.max(this.backoffBaseMs, backoffMax);
    const heartbeat = options.heartbeatTimeoutMs === undefined ? 45000 : options.heartbeatTimeoutMs;
    this.heartbeatTimeoutMs = Math.max(1000, heartbeat);

    const ringCapacity = options.ringCapacity === undefined ? 500 : options.ringCapacity;
    this.pending = new RingBuffer<StreamFrame>(ringCapacity);

    this.onFrame = options.onFrame;
    this.onStatus = options.onStatus;
    this.onError = options.onError;
    this.random = options.random === undefined ? Math.random : options.random;
    this.now = options.now === undefined ? Date.now : options.now;
    this.createSocket =
      options.webSocketFactory === undefined
        ? (url: string): WebSocket => new WebSocket(url)
        : options.webSocketFactory;

    // La construction de l'URL peut échouer (URL vide, schéma exotique) : l'erreur est
    // remontée à l'appelant, qui l'affiche après passage par `redactUrl`.
    this.url = buildWsUrl(this.baseUrl, { apiKey: this.apiKey, tenantId: this.tenantId });
  }

  /* ------------------------------------------------------------------ état public */

  get status(): ConnectionState {
    return this.state;
  }

  /** Nombre total de frames reçues (y compris celles filtrées ou illisibles). */
  get framesReceived(): number {
    return this.received;
  }

  /** Nombre de frames actuellement tamponnées pendant la pause. */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** Nombre de frames perdues par débordement de la file bornée. */
  get droppedCount(): number {
    return this.pending.dropped;
  }

  get isPaused(): boolean {
    return this.paused;
  }

  get isConnected(): boolean {
    return this.socket !== null && this.socket.readyState === 1; // WebSocket.OPEN
  }

  /* ------------------------------------------------------------------ cycle de vie */

  /** (Re)démarre la connexion. Sans effet si une connexion est déjà en cours. */
  start(): void {
    if (!this.stopped && (this.socket !== null || this.reconnectTimer !== null)) {
      return;
    }
    this.stopped = false;
    this.attempt = 0;
    this.openSocket();
  }

  /** Arrêt propre : plus aucune reconnexion, socket fermée, file vidée. */
  close(reason = 'déconnexion demandée'): void {
    this.stopped = true;
    this.clearReconnectTimer();
    this.disarmWatchdog();
    const socket = this.socket;
    this.socket = null;
    if (socket !== null) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close(1000, reason.slice(0, 60));
      } catch {
        // Fermeture best effort : une socket déjà morte lève selon les navigateurs.
      }
    }
    this.pending.clear();
    this.emitStatus('closed', reason, null);
  }

  /** Met la livraison en pause : les frames sont conservées dans la file bornée. */
  pause(): void {
    this.paused = true;
  }

  /**
   * Reprend la livraison : les frames tamponnées sont livrées dans l'ordre, puis le flux
   * reprend en direct. Un éventuel débordement de la file est signalé à l'utilisateur.
   */
  resume(): void {
    this.paused = false;
    const drained = this.pending.drain();
    const dropped = this.pending.dropped;
    if (dropped > 0) {
      this.emitError(
        'ring_overflow',
        String(dropped) +
          ' frame(s) ont été perdues : la file d’attente bornée a débordé pendant la pause. ' +
          'Reprenez l’affichage plus tôt ou augmentez la capacité de la file.',
      );
    }
    for (const frame of drained) {
      this.deliver(frame);
    }
  }

  /** Remplace le filtre de types (liste vide = tous les types). */
  setTypes(types: readonly FrameType[]): void {
    this.types = types.slice();
  }

  get filteredTypes(): readonly FrameType[] {
    return this.types;
  }

  /* ------------------------------------------------------------------ socket */

  private openSocket(): void {
    this.clearReconnectTimer();
    this.emitStatus(
      this.attempt > 0 ? 'reconnecting' : 'connecting',
      this.attempt > 0
        ? 'connexion en cours (tentative ' + String(this.attempt) + '/' + String(this.maxReconnectAttempts) + ')'
        : 'connexion en cours…',
      null,
    );

    let socket: WebSocket;
    try {
      socket = this.createSocket(this.url);
    } catch (error) {
      // Cas typiques : URL refusée, ou `SecurityError` quand la page est ouverte en `file://`
      // et que le navigateur bloque `ws://` (contenu mixte). Le message est nettoyé.
      const detail = redactUrl(describeError(error));
      this.emitError(
        'ws_security',
        'ouverture du WebSocket impossible : ' +
          detail +
          ' — si la page est ouverte directement en file://, servez le dossier ' +
          '(« python -m http.server 8000 ») ou utilisez wss://.',
      );
      this.scheduleReconnect('échec de création du WebSocket');
      return;
    }

    this.socket = socket;

    socket.onopen = (): void => {
      if (this.socket !== socket) {
        return;
      }
      this.attempt = 0;
      this.armWatchdog();
      this.emitStatus('connected', 'connecté au flux ' + redactUrl(this.url), null);
    };

    socket.onmessage = (event: MessageEvent<unknown>): void => {
      if (this.socket !== socket) {
        return;
      }
      this.handleMessage(event.data);
    };

    socket.onerror = (): void => {
      if (this.socket !== socket) {
        return;
      }
      // Le navigateur ne détaille jamais l'erreur WebSocket (raison de sécurité) : on signale
      // le fait, `onclose` enchaînera avec le code de fermeture et la reconnexion.
      this.emitError(
        'ws_error',
        'erreur de transport sur le flux (détail masqué par le navigateur) — ' +
          'vérifiez que l’API est démarrée et que le rôle de la clé possède « read:events ».',
      );
    };

    socket.onclose = (event: CloseEvent): void => {
      if (this.socket !== socket) {
        return;
      }
      this.socket = null;
      this.disarmWatchdog();
      if (this.stopped) {
        this.emitStatus('closed', 'déconnecté', null);
        return;
      }
      const explained = explainCloseCode(event.code);
      const detail = describeCloseEvent(event);
      this.scheduleReconnect(explained === null ? detail : detail + ' (' + explained + ')');
    };
  }

  private handleMessage(data: unknown): void {
    // Le watchdog est réarmé à **chaque** message, y compris les `heartbeat` : c'est la seule
    // preuve de vie dont dispose le navigateur, faute de trames de contrôle `ping`/`pong`.
    this.armWatchdog();
    const receivedAt = this.now();

    if (typeof data === 'string') {
      this.ingestText(data, receivedAt);
      return;
    }
    if (data instanceof ArrayBuffer) {
      try {
        this.ingestText(new TextDecoder('utf-8').decode(data), receivedAt);
      } catch (error) {
        this.emitError('parse_error', 'trame binaire illisible : ' + redactUrl(describeError(error)));
      }
      return;
    }
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      // Lecture asynchrone : on ne bloque pas la boucle d'événements.
      data
        .text()
        .then((text: string) => {
          this.ingestText(text, receivedAt);
        })
        .catch((error: unknown) => {
          this.emitError('parse_error', 'trame Blob illisible : ' + redactUrl(describeError(error)));
        });
      return;
    }
    this.emitError('parse_error', 'type de charge utile WebSocket non pris en charge (ignorée).');
  }

  private ingestText(text: string, receivedAt: number): void {
    this.received += 1;
    const frame = parseStreamFrame(text, this.sequence, receivedAt);
    this.sequence += 1;

    if (frame.type === 'raw' && frame.raw['type'] === undefined) {
      // JSON illisible : signalé une fois, mais la frame reste visible dans le panneau brut.
      const preview = text.slice(0, 120);
      this.emitError('parse_error', 'frame illisible (JSON attendu) : ' + redactUrl(preview));
    }

    if (!this.accepts(frame.type)) {
      return;
    }
    this.deliver(frame);
  }

  private accepts(type: FrameType): boolean {
    if (this.types.length === 0) {
      return true;
    }
    return this.types.includes(type);
  }

  private deliver(frame: StreamFrame): void {
    if (this.paused) {
      this.pending.push(frame);
      return;
    }
    if (this.onFrame !== undefined) {
      this.callSafely('onFrame', () => {
        this.onFrame?.(frame);
      });
    }
  }

  /* ------------------------------------------------------------------ reconnexion */

  /**
   * Backoff exponentiel plafonné **avec jitter** : `min(max, base × 2^tentative)` pondéré par
   * un facteur aléatoire dans `[0,5 ; 1]`, pour éviter que plusieurs widgets se reconnectent
   * exactement au même instant après un redémarrage de l'API.
   */
  private computeBackoff(attempt: number): number {
    const exponential = Math.min(this.backoffMaxMs, this.backoffBaseMs * Math.pow(2, attempt));
    const jitter = 0.5 + 0.5 * this.random();
    return Math.max(1, Math.round(exponential * jitter));
  }

  private scheduleReconnect(reason: string): void {
    if (this.stopped || this.socket !== null || this.reconnectTimer !== null) {
      return;
    }
    if (this.attempt >= this.maxReconnectAttempts) {
      this.emitStatus(
        'error',
        'reconnexion abandonnée après ' +
          String(this.maxReconnectAttempts) +
          ' tentative(s) — ' +
          reason +
          '. Utilisez « Connecter » pour réessayer.',
        null,
      );
      this.emitError(
        'ws_closed',
        'flux interrompu et reconnexion abandonnée (' +
          String(this.maxReconnectAttempts) +
          ' tentatives) — ' +
          reason,
      );
      return;
    }

    const delay = this.computeBackoff(this.attempt);
    this.attempt += 1;
    this.emitStatus('reconnecting', reason, delay);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.stopped) {
        this.openSocket();
      }
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /* ------------------------------------------------------------------ watchdog */

  private armWatchdog(): void {
    this.disarmWatchdog();
    this.watchdogTimer = setTimeout(() => {
      this.watchdogTimer = null;
      this.handleWatchdogExpiry();
    }, this.heartbeatTimeoutMs);
  }

  private disarmWatchdog(): void {
    if (this.watchdogTimer !== null) {
      clearTimeout(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  /**
   * Connexion déclarée morte : aucune frame (même `heartbeat`) depuis `heartbeatTimeoutMs`.
   *
   * Le navigateur ne permet pas d'envoyer une trame de contrôle `ping` pour sonder le lien
   * (l'API `WebSocket` ne l'expose pas) : on ferme donc la socket avec le code applicatif 4000
   * et on laisse le backoff reprendre la main. Le serveur, lui, voit une fermeture propre.
   */
  private handleWatchdogExpiry(): void {
    const socket = this.socket;
    if (socket === null) {
      return;
    }
    this.emitError(
      'ws_closed',
      'aucune frame reçue depuis ' +
        String(this.heartbeatTimeoutMs) +
        ' ms : connexion considérée morte (watchdog applicatif) — fermeture puis reconnexion. ' +
        'Le navigateur ne peut pas émettre de trame de contrôle ping : ' +
        'vérifiez que le serveur envoie bien des frames « heartbeat » (contrat §4.8).',
    );
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    this.socket = null;
    try {
      socket.close(4000, 'watchdog');
    } catch {
      // Best effort.
    }
    this.scheduleReconnect('watchdog : aucune frame depuis ' + String(this.heartbeatTimeoutMs) + ' ms');
  }

  /* ------------------------------------------------------------------ notifications */

  private emitStatus(state: ConnectionState, message: string | null, delayMs: number | null): void {
    this.state = state;
    if (this.onStatus === undefined) {
      return;
    }
    const event: ConnectionStatusEvent = {
      state,
      attempt: this.attempt,
      maxAttempts: this.maxReconnectAttempts,
      delayMs,
      message: message === null ? null : redactUrl(message),
      url: redactUrl(this.url),
      at: this.now(),
    };
    this.callSafely('onStatus', () => {
      this.onStatus?.(event);
    });
  }

  private emitError(code: WidgetErrorCode, message: string): void {
    if (this.onError === undefined) {
      return;
    }
    const error: WidgetError = {
      code,
      message: redactUrl(message),
      url: redactUrl(this.url),
      at: this.now(),
    };
    this.callSafely('onError', () => {
      this.onError?.(error);
    });
  }

  /**
   * Un callback fourni par l'appelant ne doit jamais casser la boucle de lecture : ses
   * exceptions sont capturées et signalées dans la console (message nettoyé, jamais d'URL brute).
   */
  private callSafely(name: string, callback: () => void): void {
    try {
      callback();
    } catch (error) {
      const detail = redactUrl(describeError(error));
      if (typeof console !== 'undefined') {
        console.error('[thotsecure-widget] rappel ' + name + ' en échec : ' + detail);
      }
    }
  }
}

/** Types de frames du contrat §4.8 (réexport pratique pour l'appelant). */
export const CONTRACT_FRAME_TYPES: readonly FrameType[] = FRAME_TYPES;
