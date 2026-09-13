/**
 * Tests du flux temps réel (`src/lib/ws.ts`).
 *
 * Aucun réseau, aucun DOM : `WebSocket` est remplacé par une implémentation
 * locale (`FakeSocket`) injectée via l'option `socketFactory`, et l'horloge de
 * backoff est fournie (`random`/`now`). On vérifie :
 *  1. les fonctions pures (URL `ws(s)://`, backoff plafonné avec jitter) ;
 *  2. l'analyse défensive des frames (entrée non fiable) et leur projection ;
 *  3. le cycle de vie du client : tampon borné, pause/reprise, heartbeat,
 *     fermeture non autorisée (aucune reconnexion), reconnexion manuelle.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LiveFrame, LiveFrameType } from '@/lib/types';
import type { UseLiveStreamResult, WebSocketLike } from '@/lib/ws';
import {
  DEFAULT_BUFFER_SIZE,
  DEFAULT_BASE_BACKOFF_MS,
  LiveStreamClient,
  MAX_BACKOFF_MS,
  UNAUTHORIZED_CLOSE_CODES,
  computeBackoff,
  parseLiveFrame,
  resolveWebSocketUrl,
  toLiveRow,
  toWebSocketBase,
} from '@/lib/ws';

/* -------------------------------------------------------------------------- */
/* Faux WebSocket                                                              */
/* -------------------------------------------------------------------------- */

class FakeSocket implements WebSocketLike {
  static instances: FakeSocket[] = [];

  static reset(): void {
    FakeSocket.instances = [];
  }

  static last(): FakeSocket {
    const socket = FakeSocket.instances[FakeSocket.instances.length - 1];
    if (!socket) throw new Error('aucun WebSocket n’a été créé');
    return socket;
  }

  static count(): number {
    return FakeSocket.instances.length;
  }

  readonly url: string;
  onopen: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onclose: ((event: { code?: number; reason?: string; wasClean?: boolean }) => void) | null = null;

  closedWith: { code?: number; reason?: string } | null = null;

  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }

  close(code?: number, reason?: string): void {
    this.closedWith = { code, reason };
  }

  /* --- Pilotes de test ------------------------------------------------- */

  emitOpen(): void {
    this.onopen?.({});
  }

  emitFrame(frame: unknown): void {
    this.onmessage?.({ data: typeof frame === 'string' ? frame : JSON.stringify(frame) });
  }

  emitRaw(data: unknown): void {
    this.onmessage?.({ data });
  }

  emitError(): void {
    this.onerror?.({});
  }

  emitClose(code: number, reason = ''): void {
    this.onclose?.({ code, reason, wasClean: code === 1000 });
  }
}

interface Harness {
  client: LiveStreamClient;
  states: string[];
  frames: LiveFrame[];
}

function makeClient(options: {
  apiKey?: string | null;
  tenantId?: string | null;
  bufferSize?: number;
  baseBackoffMs?: number;
  jitterRatio?: number;
  maxAttempts?: number;
} = {}): Harness {
  const states: string[] = [];
  const frames: LiveFrame[] = [];

  const client = new LiveStreamClient({
    apiKey: options.apiKey === undefined ? 'ao_test_key' : options.apiKey,
    tenantId: options.tenantId === undefined ? 'acme' : options.tenantId,
    bufferSize: options.bufferSize ?? 4,
    baseBackoffMs: options.baseBackoffMs ?? 100,
    jitterRatio: options.jitterRatio ?? 0,
    maxAttempts: options.maxAttempts ?? Number.POSITIVE_INFINITY,
    random: () => 0.5,
    now: () => 1_700_000_000_000,
    socketFactory: (url: string) => new FakeSocket(url),
    onFrame: (frame) => frames.push(frame),
  });

  client.subscribe((state) => states.push(state.status));
  return { client, states, frames };
}

function findingFrame(id: string): { type: LiveFrameType; data: Record<string, unknown> } {
  return {
    type: 'finding',
    data: {
      finding_id: id,
      severity: 'high',
      risk_score: 78.5,
      status: 'open',
      title: `Finding ${id}`,
      rule_id: 'AO-WEB-001',
      decision: 'require_approval',
      last_seen: '2026-02-14T10:04:12Z',
    },
  };
}

afterEach(() => {
  FakeSocket.reset();
  vi.useRealTimers();
});

/* -------------------------------------------------------------------------- */
/* 1. Fonctions pures                                                          */
/* -------------------------------------------------------------------------- */

describe('backoff exponentiel', () => {
  it('part de la base, double et se plafonne à 30 s', () => {
    expect(computeBackoff(0, { baseMs: 500, jitterRatio: 0, random: () => 0.5 })).toBe(500);
    expect(computeBackoff(1, { baseMs: 500, jitterRatio: 0, random: () => 0.5 })).toBe(1_000);
    expect(computeBackoff(3, { baseMs: 500, jitterRatio: 0, random: () => 0.5 })).toBe(4_000);
    expect(computeBackoff(40, { baseMs: 500, jitterRatio: 0, random: () => 0.5 })).toBe(MAX_BACKOFF_MS);
  });

  it('applique un jitter borné et ne dépasse jamais le plafond', () => {
    const low = computeBackoff(2, { baseMs: 1_000, jitterRatio: 0.5, random: () => 0 });
    const high = computeBackoff(2, { baseMs: 1_000, jitterRatio: 0.5, random: () => 1 });
    expect(low).toBe(2_000);
    expect(high).toBe(4_000);
    expect(computeBackoff(30, { baseMs: 5_000, jitterRatio: 1, random: () => 1 })).toBeLessThanOrEqual(MAX_BACKOFF_MS);
    expect(computeBackoff(0)).toBeGreaterThan(0);
    expect(DEFAULT_BASE_BACKOFF_MS).toBeLessThan(MAX_BACKOFF_MS);
  });

  it('traite une tentative invalide comme la première', () => {
    expect(computeBackoff(Number.NaN, { baseMs: 200, jitterRatio: 0, random: () => 0 })).toBe(200);
    expect(computeBackoff(-5, { baseMs: 200, jitterRatio: 0, random: () => 0 })).toBe(200);
  });
});

describe('URL du flux', () => {
  it('convertit http(s) en ws(s) et conserve le préfixe de l’API', () => {
    expect(toWebSocketBase('http://127.0.0.1:8080/api/v1', { protocol: 'http:', host: 'x' })).toBe(
      'ws://127.0.0.1:8080/api/v1',
    );
    expect(toWebSocketBase('https://soc.example/api/v1', { protocol: 'https:', host: 'x' })).toBe(
      'wss://soc.example/api/v1',
    );
    expect(toWebSocketBase('/api/v1', { protocol: 'https:', host: 'soc.example' })).toBe(
      'wss://soc.example/api/v1',
    );
  });

  it('encode la clé et le tenant dans la requête (contrat §4)', () => {
    const url = resolveWebSocketUrl({
      apiKey: 'ao_test_key',
      tenantId: 'acme corp',
      baseUrl: '/api/v1',
      location: { protocol: 'http:', host: '127.0.0.1:5173' },
    });

    expect(url.startsWith('ws://127.0.0.1:5173/api/v1/ws/stream?')).toBe(true);
    expect(url).toContain('api_key=ao_test_key');
    expect(url).toContain('tenant_id=acme%20corp');
  });
});

/* -------------------------------------------------------------------------- */
/* 2. Analyse et projection des frames                                         */
/* -------------------------------------------------------------------------- */

describe('analyse défensive des frames', () => {
  it('rejette tout ce qui n’est pas une frame connue', () => {
    expect(parseLiveFrame('pas du json')).toBeNull();
    expect(parseLiveFrame('[]')).toBeNull();
    expect(parseLiveFrame('null')).toBeNull();
    expect(parseLiveFrame('{"type":"inconnu","data":{}}')).toBeNull();
    expect(parseLiveFrame(undefined)).toBeNull();
  });

  it('accepte une frame valide et force `data` en objet', () => {
    expect(parseLiveFrame('{"type":"heartbeat","data":{"ts":"2026-02-14T10:00:00Z"}}')).toEqual({
      type: 'heartbeat',
      data: { ts: '2026-02-14T10:00:00Z' },
    });
    expect(parseLiveFrame('{"type":"event","data":"charge brutale"}')).toEqual({
      type: 'event',
      data: {},
    });
  });
});

describe('projection d’affichage', () => {
  it('projette un finding sans interpréter de balisage', () => {
    const frame = parseLiveFrame(
      JSON.stringify({
        type: 'finding',
        data: {
          finding_id: 'f1',
          title: '<script>alert(1)</script>',
          severity: 'critical',
          risk_score: 91.2,
          status: 'open',
          decision: 'auto',
        },
      }),
    );
    expect(frame).not.toBeNull();
    if (!frame) return;

    const row = toLiveRow(frame, 0);
    expect(row.type).toBe('finding');
    expect(row.severity).toBe('critical');
    // La charge reste une chaîne : elle sera rendue comme nœud texte par React.
    expect(row.title).toBe('<script>alert(1)</script>');
    expect(row.summary).toContain('risque 91.2');
    expect(row.summary).toContain('décision auto');
  });

  it('projette une action, un audit, un événement et un heartbeat', () => {
    const action = parseLiveFrame(
      JSON.stringify({
        type: 'action',
        data: {
          action_id: 'a1',
          playbook: 'block-source-ip',
          status: 'pending_approval',
          target: { type: 'ip', value: '203.0.113.9' },
          requested_by: 'api-key:ci',
          dry_run: true,
        },
      }),
    );
    const audit = parseLiveFrame(
      JSON.stringify({ type: 'audit', data: { seq: 42, action: 'action.approve', actor: 'api-key:ci', target: { id: 'a1' } } }),
    );
    const event = parseLiveFrame(
      JSON.stringify({
        type: 'event',
        data: { event_id: 'e1', kind: 'http.request', severity_hint: 'low', source: { type: 'web_probe' }, labels: { src_ip: '10.0.0.1' } },
      }),
    );
    const heartbeat = parseLiveFrame(JSON.stringify({ type: 'heartbeat', data: { status: 'ok' } }));

    expect(action && toLiveRow(action, 0).summary).toContain('203.0.113.9');
    expect(audit && toLiveRow(audit, 0).title).toBe('action.approve');
    expect(event && toLiveRow(event, 0).severity).toBe('low');
    expect(heartbeat && toLiveRow(heartbeat, 0).title).toBe('Heartbeat');
    expect(action && toLiveRow(action, 0).key).toContain('a1');
  });
});

/* -------------------------------------------------------------------------- */
/* 3. Cycle de vie du client                                                   */
/* -------------------------------------------------------------------------- */

describe('cycle de vie du flux', () => {
  it('reste inactif sans clé API ni tenant', () => {
    const harness = makeClient({ apiKey: null });
    harness.client.start();
    expect(harness.client.getState().status).toBe('idle');
    expect(FakeSocket.count()).toBe(0);
    harness.client.stop();
  });

  it('ouvre le flux, compte les frames et met les heartbeats à part', () => {
    const harness = makeClient();
    harness.client.start();

    const socket = FakeSocket.last();
    expect(socket.url).toContain('/api/v1/ws/stream?api_key=ao_test_key');
    socket.emitOpen();
    expect(harness.client.getState().status).toBe('open');

    socket.emitFrame(findingFrame('f1'));
    socket.emitFrame(findingFrame('f2'));
    socket.emitFrame({ type: 'heartbeat', data: { ts: '2026-02-14T10:00:00Z' } });
    socket.emitRaw('{illisible');
    socket.emitFrame({ type: 'inconnu', data: {} });

    const state = harness.client.getState();
    expect(state.frames).toHaveLength(2);
    expect(state.received).toBe(2);
    expect(state.heartbeats).toBe(1);
    expect(state.invalidFrames).toBe(2);
    expect(state.lastMessageAt).not.toBeNull();
    // `onFrame` ne reçoit jamais un heartbeat.
    expect(harness.frames).toHaveLength(2);
    // Historique d'états notifié aux abonnés (`useSyncExternalStore`).
    expect(harness.states).toContain('connecting');
    expect(harness.states).toContain('open');

    harness.client.stop();
    expect(socket.closedWith?.code).toBe(1000);
  });

  it('borne le tampon et comptabilise les frames perdues', () => {
    const harness = makeClient({ bufferSize: 3 });
    harness.client.start();
    const socket = FakeSocket.last();
    socket.emitOpen();

    for (const id of ['f1', 'f2', 'f3', 'f4', 'f5']) socket.emitFrame(findingFrame(id));

    const state = harness.client.getState();
    expect(state.frames).toHaveLength(3);
    expect(state.dropped).toBe(2);
    expect(state.received).toBe(5);
    expect(DEFAULT_BUFFER_SIZE).toBeGreaterThanOrEqual(3);

    harness.client.stop();
  });

  it('met en pause, tamponne, puis restitue à la reprise', () => {
    const harness = makeClient({ bufferSize: 10 });
    harness.client.start();
    const socket = FakeSocket.last();
    socket.emitOpen();

    socket.emitFrame(findingFrame('f1'));
    harness.client.pause();
    expect(harness.client.getState().paused).toBe(true);

    socket.emitFrame(findingFrame('f2'));
    socket.emitFrame(findingFrame('f3'));
    expect(harness.client.getState().frames).toHaveLength(1);
    expect(harness.client.getState().buffered).toBe(2);

    harness.client.resume();
    const state = harness.client.getState();
    expect(state.paused).toBe(false);
    expect(state.buffered).toBe(0);
    expect(state.frames).toHaveLength(3);

    harness.client.clear();
    expect(harness.client.getState().frames).toHaveLength(0);

    harness.client.stop();
  });

  it('ne réessaie pas après une fermeture non autorisée', () => {
    const harness = makeClient();
    harness.client.start();
    const socket = FakeSocket.last();
    socket.emitOpen();

    socket.emitClose(UNAUTHORIZED_CLOSE_CODES[0] ?? 4401, 'clé révoquée');

    const state = harness.client.getState();
    expect(state.status).toBe('unauthorized');
    expect(state.nextRetryMs).toBeNull();
    expect(state.attempts).toBe(0);
    expect(state.lastError).toContain('clé API invalide ou révoquée');

    harness.client.stop();
  });

  it('reconnecte avec un backoff plafonné après une coupure réseau', async () => {
    vi.useFakeTimers();
    const harness = makeClient({ baseBackoffMs: 100, jitterRatio: 0 });
    harness.client.start();
    expect(FakeSocket.count()).toBe(1);

    FakeSocket.last().emitOpen();
    FakeSocket.last().emitClose(1006, 'coupure');

    expect(harness.client.getState().status).toBe('reconnecting');
    expect(harness.client.getState().attempts).toBe(1);
    expect(harness.client.getState().nextRetryMs).toBe(100);

    await vi.advanceTimersByTimeAsync(120);
    expect(FakeSocket.count()).toBe(2);
    // L'état reste « reconnexion » jusqu'à l'ouverture effective du nouveau socket.
    expect(harness.client.getState().status).toBe('reconnecting');

    FakeSocket.last().emitOpen();
    expect(harness.client.getState().status).toBe('open');
    expect(harness.client.getState().attempts).toBe(0);

    harness.client.stop();
  });

  it('reconnecte immédiatement à la demande', () => {
    const harness = makeClient();
    harness.client.start();
    const first = FakeSocket.last();
    first.emitOpen();

    harness.client.reconnectNow();
    expect(first.closedWith?.code).toBe(4000);
    expect(FakeSocket.count()).toBe(2);

    const second = FakeSocket.last();
    second.emitOpen();
    expect(harness.client.getState().status).toBe('open');
    expect(harness.client.getState().attempts).toBe(0);

    harness.client.stop();
  });

  it('signale une erreur de transport sans perdre l’état du flux', () => {
    const harness = makeClient();
    harness.client.start();
    FakeSocket.last().emitOpen();
    FakeSocket.last().emitError();

    expect(harness.client.getState().lastError).toContain('transport');
    expect(harness.client.getState().status).toBe('open');

    harness.client.stop();
  });

  it('abandonne après le nombre maximal de tentatives', async () => {
    vi.useFakeTimers();
    const harness = makeClient({ maxAttempts: 1, baseBackoffMs: 10, jitterRatio: 0 });
    harness.client.start();
    FakeSocket.last().emitClose(1006, 'coupure');
    await vi.advanceTimersByTimeAsync(20);
    FakeSocket.last().emitClose(1006, 'coupure 2');

    expect(harness.client.getState().status).toBe('error');
    expect(harness.client.getState().lastError).toContain('nombre maximal de tentatives');

    harness.client.stop();
  });
});

/* -------------------------------------------------------------------------- */
/* Contrat de types du hook (compilation seulement)                            */
/* -------------------------------------------------------------------------- */

describe('contrat du hook', () => {
  it('expose les actions attendues par l’interface', () => {
    const keys: readonly (keyof UseLiveStreamResult)[] = [
      'status',
      'frames',
      'buffered',
      'paused',
      'dropped',
      'pause',
      'resume',
      'clear',
      'reconnect',
    ];
    expect(keys.length).toBeGreaterThan(0);
  });
});
