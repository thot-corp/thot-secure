/**
 * Tests du client HTTP typé (`src/lib/api.ts`).
 *
 * Aucun accès réseau : `fetch` est remplacé par une fonction de test qui répond
 * des objets `Response` construits localement. On vérifie quatre familles de
 * comportements :
 *  1. construction d'URL et en-tête `X-API-Key` (la clé ne doit jamais finir
 *     dans une URL) ;
 *  2. normalisation des erreurs `{"error":{code,message,details}}` et politique
 *     de réessai ;
 *  3. garde de périmètre tenant (fail closed) ;
 *  4. annulation, dépassement de délai et réponses vides.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_API_BASE_URL,
  ThotSecureError,
  buildQuery,
  createThotSecureClient,
  errorMessage,
  isAbortError,
  normalizeList,
  resolveApiBaseUrl,
  resolveRootBaseUrl,
  shouldRetry,
} from '@/lib/api';

/* -------------------------------------------------------------------------- */
/* Bancs d'essai                                                               */
/* -------------------------------------------------------------------------- */

interface RecordedCall {
  url: string;
  init: RequestInit;
}

const recordedCalls: RecordedCall[] = [];

/** Extrait une URL lisible sans dépendre du type exact de l'entrée `fetch`. */
function toUrl(input: unknown): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  if (input !== null && typeof input === 'object' && 'url' in input) {
    const candidate = (input as { url?: unknown }).url;
    if (typeof candidate === 'string') return candidate;
  }
  return String(input);
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** Installe un `fetch` simulé ; les appels sont enregistrés dans `recordedCalls`. */
function installFetch(responder: (call: RecordedCall) => Response | Promise<Response>): void {
  vi.stubGlobal('fetch', (input: unknown, init?: RequestInit): Promise<Response> => {
    const call: RecordedCall = { url: toUrl(input), init: init ?? {} };
    recordedCalls.push(call);
    return Promise.resolve(responder(call));
  });
}

function makeClient(overrides: { apiKey?: string | null; tenantId?: string | null } = {}): ReturnType<
  typeof createThotSecureClient
> {
  return createThotSecureClient({
    baseUrl: DEFAULT_API_BASE_URL,
    apiKey: overrides.apiKey === undefined ? 'ao_test_key' : overrides.apiKey,
    tenantId: overrides.tenantId === undefined ? 'acme' : overrides.tenantId,
  });
}

function lastCall(): RecordedCall {
  const call = recordedCalls[recordedCalls.length - 1];
  if (!call) throw new Error('fetch n’a pas été appelé');
  return call;
}

function headerOf(call: RecordedCall, name: string): string | null {
  const headers = call.init.headers;
  if (headers === undefined || headers === null || Array.isArray(headers)) return null;
  const record = headers as Record<string, string>;
  return record[name] ?? null;
}

afterEach(() => {
  vi.unstubAllGlobals();
  recordedCalls.length = 0;
  vi.useRealTimers();
});

/* -------------------------------------------------------------------------- */
/* 1. URL et en-têtes                                                          */
/* -------------------------------------------------------------------------- */

describe('résolution des URL', () => {
  it('utilise /api/v1 par défaut et retire les barres obliques finales', () => {
    expect(resolveApiBaseUrl('')).toBe(DEFAULT_API_BASE_URL);
    expect(resolveApiBaseUrl('/api/v1/')).toBe('/api/v1');
    expect(resolveApiBaseUrl('http://127.0.0.1:8080/api/v1//')).toBe('http://127.0.0.1:8080/api/v1');
  });

  it('dérive la racine hors /api/v1 pour les endpoints publics', () => {
    expect(resolveRootBaseUrl('/api/v1')).toBe('');
    expect(resolveRootBaseUrl('http://127.0.0.1:8080/api/v1')).toBe('http://127.0.0.1:8080');
    expect(resolveRootBaseUrl('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
  });

  it('construit la chaîne de requête en omettant les valeurs vides', () => {
    expect(buildQuery({ limit: 50, cursor: null, status: '', q: undefined, min_risk: 70 })).toBe(
      '?limit=50&min_risk=70',
    );
    expect(buildQuery({})).toBe('');
    expect(buildQuery(undefined)).toBe('');
  });
});

describe('authentification', () => {
  it('envoie la clé API dans l’en-tête X-API-Key et jamais dans l’URL', async () => {
    installFetch(() =>
      jsonResponse({
        tenant_id: 'acme',
        role: 'analyst',
        capabilities: ['read:findings'],
        autonomy: 'supervised',
        dry_run: true,
      }),
    );

    const client = makeClient();
    const whoami = await client.whoami();

    expect(whoami.tenant_id).toBe('acme');
    const call = lastCall();
    expect(call.url).toBe('/api/v1/auth/whoami');
    expect(call.url).not.toContain('ao_test_key');
    expect(call.url).not.toContain('api_key');
    expect(headerOf(call, 'X-API-Key')).toBe('ao_test_key');
    expect(call.init.method ?? 'GET').toBe('GET');
  });

  it('échoue avant tout appel réseau quand aucune clé n’est configurée', async () => {
    installFetch(() => jsonResponse({}));
    const client = makeClient({ apiKey: null });

    await expect(client.whoami()).rejects.toMatchObject({ code: 'missing_api_key', status: 401 });
    expect(recordedCalls).toHaveLength(0);
  });

  it('interroge les endpoints publics sans en-tête d’authentification', async () => {
    installFetch(() => jsonResponse({ status: 'ok', version: '0.1.0', uptime_s: 12 }));
    const client = makeClient({ apiKey: null });

    const health = await client.health();
    expect(health.version).toBe('0.1.0');
    const call = lastCall();
    expect(call.url).toBe('/healthz');
    expect(call.init.headers).toEqual({ Accept: 'application/json' });
  });
});

/* -------------------------------------------------------------------------- */
/* 2. Erreurs                                                                  */
/* -------------------------------------------------------------------------- */

describe('normalisation des erreurs', () => {
  it('extrait code, message et détails de l’enveloppe du contrat', async () => {
    installFetch(() =>
      jsonResponse(
        {
          error: {
            code: 'forbidden',
            message: 'capacité « execute:actions » requise',
            details: { capability: 'execute:actions' },
          },
        },
        403,
        { 'x-request-id': 'req-42' },
      ),
    );

    const client = makeClient();
    const failure = await client.statsOverview().catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(ThotSecureError);
    const error = failure as ThotSecureError;
    expect(error.code).toBe('forbidden');
    expect(error.status).toBe(403);
    expect(error.message).toContain('execute:actions');
    expect(error.details).toEqual({ capability: 'execute:actions' });
    expect(error.requestId).toBe('req-42');
    expect(error.isForbidden).toBe(true);
  });

  it('déduit le code depuis le statut HTTP quand le corps est vide', async () => {
    installFetch(() => new Response('', { status: 409 }));
    const client = makeClient();

    await expect(client.executeAction('a1')).rejects.toMatchObject({ code: 'conflict', status: 409 });
  });

  it('tolère le repli FastAPI `{"detail": …}`', async () => {
    installFetch(() => jsonResponse({ detail: 'Clé API inconnue.' }, 401));
    const client = makeClient();

    await expect(client.whoami()).rejects.toMatchObject({
      code: 'unauthenticated',
      message: 'Clé API inconnue.',
    });
  });

  it('ne réessaie jamais une erreur 4xx et réessaie deux fois un 5xx', () => {
    const forbidden = new ThotSecureError({ code: 'forbidden', message: 'interdit', status: 403 });
    const server = new ThotSecureError({ code: 'internal_error', message: 'panne', status: 500 });
    const abort = new DOMException('annulé', 'AbortError');

    expect(shouldRetry(0, forbidden)).toBe(false);
    expect(shouldRetry(0, abort)).toBe(false);
    expect(shouldRetry(0, server)).toBe(true);
    expect(shouldRetry(1, server)).toBe(true);
    expect(shouldRetry(2, server)).toBe(false);
  });

  it('produit toujours un message affichable sans HTML', () => {
    expect(errorMessage(new ThotSecureError({ code: 'not_found', message: '<img src=x>', status: 404 }))).toBe(
      '<img src=x>',
    );
    expect(errorMessage('texte brut')).toBe('texte brut');
    expect(errorMessage(undefined)).toBe('Erreur inconnue.');
    expect(isAbortError(new DOMException('x', 'AbortError'))).toBe(true);
    expect(isAbortError(new Error('x'))).toBe(false);
  });
});

/* -------------------------------------------------------------------------- */
/* 3. Listes et périmètre tenant                                               */
/* -------------------------------------------------------------------------- */

describe('normalisation des listes', () => {
  it('accepte `{"items":[…]}` et le tableau nu', () => {
    expect(normalizeList<number>({ items: [1, 2], next_cursor: 'c2', total: 2 }, '/x')).toEqual({
      items: [1, 2],
      cursor: null,
      next_cursor: 'c2',
      total: 2,
    });
    expect(normalizeList<number>([1, 2], '/x').items).toEqual([1, 2]);
  });

  it('refuse une forme inattendue plutôt que d’afficher un résultat partiel', () => {
    expect(() => normalizeList<number>({ ok: true }, '/findings')).toThrowError(/items/);
  });
});

describe('garde de périmètre tenant', () => {
  it('exige un périmètre connu avant toute requête de données', async () => {
    installFetch(() => jsonResponse({ items: [] }));
    const client = makeClient({ tenantId: null });

    await expect(client.listFindings()).rejects.toMatchObject({ code: 'tenant_mismatch' });
    expect(recordedCalls).toHaveLength(0);
  });

  it('bloque toute ligne appartenant à un autre tenant (fail closed)', async () => {
    installFetch(() =>
      jsonResponse({
        items: [
          { finding_id: 'f1', tenant_id: 'acme' },
          { finding_id: 'f2', tenant_id: 'autre-tenant' },
        ],
      }),
    );

    const client = makeClient({ tenantId: 'acme' });
    await expect(client.listFindings()).rejects.toMatchObject({ code: 'forbidden', status: 403 });
  });

  it('force le tenant_id de la clé lors de l’ingestion', async () => {
    installFetch(() => jsonResponse({ accepted: 1, rejected: 0, event_ids: ['e1'], findings: [] }));
    const client = makeClient({ tenantId: 'acme' });

    await client.ingestEvents({
      event_id: 'e1',
      ts: '2026-02-14T10:00:00.000Z',
      kind: 'http.request',
      source: { type: 'web_probe' },
      severity_hint: 'info',
      labels: { src_ip: '203.0.113.9' },
      payload: { status: 403 },
    });

    const body = JSON.parse(String(lastCall().init.body)) as {
      events: { tenant_id?: string }[];
    };
    expect(body.events[0]?.tenant_id).toBe('acme');
  });

  it('refuse un événement déclarant un autre tenant', async () => {
    installFetch(() => jsonResponse({}));
    const client = makeClient({ tenantId: 'acme' });

    await expect(
      client.ingestEvents({
        event_id: 'e1',
        tenant_id: 'autre-tenant',
        ts: '2026-02-14T10:00:00.000Z',
        kind: 'http.request',
        source: { type: 'web_probe' },
        severity_hint: null,
        labels: {},
        payload: {},
      }),
    ).rejects.toMatchObject({ code: 'tenant_mismatch' });
    expect(recordedCalls).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* 4. Mutations, annulation, délais                                            */
/* -------------------------------------------------------------------------- */

describe('mutations', () => {
  it('planifie une action en dry_run par défaut (aucun effet de bord)', async () => {
    installFetch(() => jsonResponse({ action_id: 'a1', status: 'planned', dry_run: true }));

    const client = makeClient();
    const action = await client.planAction({ finding_id: 'f1', playbook: 'block-source-ip' });

    expect(action.status).toBe('planned');
    const call = lastCall();
    expect(call.url).toBe('/api/v1/actions/plan');
    expect(call.init.method).toBe('POST');
    expect(headerOf(call, 'Content-Type')).toBe('application/json');
    expect(JSON.parse(String(call.init.body))).toEqual({
      finding_id: 'f1',
      playbook: 'block-source-ip',
      params: {},
      dry_run: true,
    });
  });

  it('transmet l’identifiant encodé dans le chemin', async () => {
    installFetch(() => jsonResponse({ action_id: 'a 1', status: 'approved' }));
    const client = makeClient();

    await client.approveAction('a 1', { comment: 'validé' });
    expect(lastCall().url).toBe('/api/v1/actions/a%201/approve');
  });

  it('ne rend rien sur un 204 (révocation de clé)', async () => {
    installFetch(() => new Response(null, { status: 204 }));
    const client = makeClient();

    await expect(client.revokeApiKey('key-1')).resolves.toBeUndefined();
    expect(lastCall().init.method).toBe('DELETE');
  });

  it('renvoie le verdict d’intégrité de l’audit', async () => {
    installFetch(() => jsonResponse({ valid: false, records: 12, broken_at: 7 }));
    const client = makeClient();

    const verdict = await client.verifyAudit();
    expect(verdict.valid).toBe(false);
    expect(verdict.broken_at).toBe(7);
  });
});

describe('annulation et délais', () => {
  it('propage une annulation en AbortError sans l’encapsuler', async () => {
    installFetch(() => jsonResponse({ status: 'ok' }));
    const client = makeClient();
    const controller = new AbortController();
    controller.abort();

    const failure = await client.health({ signal: controller.signal }).catch((cause: unknown) => cause);
    expect(isAbortError(failure)).toBe(true);
    expect(failure).not.toBeInstanceOf(ThotSecureError);
    expect(recordedCalls).toHaveLength(0);
  });

  it('convertit un dépassement de délai en network_error explicite', async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      'fetch',
      (_input: unknown, init?: RequestInit): Promise<Response> =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          });
        }),
    );

    const client = makeClient();
    const promise = client.health();
    const assertion = expect(promise).rejects.toMatchObject({ code: 'network_error', status: 0 });

    // `client.health()` applique un délai de 8 s (contrat §4.1).
    await vi.advanceTimersByTimeAsync(9_000);
    await assertion;
  });

  it('signale une réponse JSON invalide au lieu de rendre des données douteuses', async () => {
    installFetch(() => new Response('ceci n’est pas du JSON', { status: 200 }));
    const client = makeClient();

    await expect(client.statsOverview()).rejects.toMatchObject({ code: 'bad_response', status: 200 });
  });
});
