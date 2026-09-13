/**
 * Tests du client REST — **exécutables hors ligne**.
 *
 * `fetch` est entièrement simulé (aucun accès réseau) et l'attente de reprise est injectée, ce qui
 * rend les scénarios de 429/503 déterministes et instantanés.
 *
 * Couverture : construction d'URL, en-tête `X-API-Key`, sérialisation des corps et des filtres,
 * mapping des erreurs du contrat §4.6 (401/403/404/409/422/429), reprise sur `503`, respect de
 * `Retry-After`, pagination, découpage des lots d'ingestion, sonde `/readyz` non bloquante et
 * comportement du flux WebSocket côté URL.
 */

import { describe, expect, it } from "vitest";

import { ThotSecureClient, type FetchLike, type ThotSecureClientOptions } from "../src/client";
import {
  AuthenticationError,
  ConflictError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitedError,
  ServerError,
  ThotSecureError,
  ValidationError,
  redactUrl,
} from "../src/errors";
import { buildWebSocketUrl, computeReconnectDelay, WS_PATH } from "../src/ws";

/** Appel HTTP capturé par le faux `fetch`. */
interface CapturedCall {
  url: string;
  init: RequestInit;
}

/** Fabrique un `fetch` simulé qui enregistre chaque appel. */
function capture(
  handler: (call: CapturedCall) => Response | Promise<Response>,
): { fetch: FetchLike; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const impl: FetchLike = (input, init) => {
    const call: CapturedCall = { url: input, init };
    calls.push(call);
    return Promise.resolve(handler(call));
  };
  return { fetch: impl, calls };
}

/** Réponse JSON minimale. */
function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

/** Corps d'erreur normalisé du contrat §4.6. */
function errorBody(code: string, message = "erreur simulée"): unknown {
  return { error: { code, message, details: {} } };
}

interface Harness {
  client: ThotSecureClient;
  calls: CapturedCall[];
  sleeps: number[];
}

/** Client prêt à l'emploi, avec `fetch` simulé et attente capturée. */
function makeClient(
  handler: (call: CapturedCall) => Response | Promise<Response>,
  options: Partial<ThotSecureClientOptions> = {},
): Harness {
  const captured = capture(handler);
  const sleeps: number[] = [];
  const client = new ThotSecureClient({
    baseUrl: "http://127.0.0.1:8080",
    apiKey: "ao_test_key_0001",
    tenantId: "acme",
    fetch: captured.fetch,
    sleep: async (delayMs) => {
      sleeps.push(delayMs);
    },
    random: () => 1,
    ...options,
  });
  return { client, calls: captured.calls, sleeps };
}

/** En-têtes d'un appel capturé, sous forme de dictionnaire insensible à la casse. */
function headersOf(call: CapturedCall): Record<string, string> {
  const raw = (call.init.headers ?? {}) as Record<string, string>;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

/* ====================================================================================== */
/* URL, en-têtes, sérialisation                                                            */
/* ====================================================================================== */

describe("ThotSecureClient — URL et en-têtes", () => {
  it("appelle le chemin /api/v1 attendu avec l'en-tête X-API-Key", async () => {
    const { client, calls } = makeClient(() =>
      jsonResponse(200, {
        tenant_id: "acme",
        role: "responder",
        capabilities: ["read:events"],
        autonomy_mode: "supervised",
        dry_run: true,
      }),
    );

    const who = await client.whoami();

    expect(who.tenant_id).toBe("acme");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("http://127.0.0.1:8080/api/v1/auth/whoami");
    expect(calls[0]?.init.method).toBe("GET");
    const headers = headersOf(calls[0] as CapturedCall);
    expect(headers["x-api-key"]).toBe("ao_test_key_0001");
    expect(headers["accept"]).toBe("application/json");
    expect(headers["user-agent"]).toContain("thot-secure-sdk-typescript");
  });

  it("n'envoie aucune clé sur les routes publiques", async () => {
    const { client, calls } = makeClient(() =>
      jsonResponse(200, { status: "ok", version: "0.1.0", uptime_s: 12 }),
    );

    await client.healthz();

    expect(calls[0]?.url).toBe("http://127.0.0.1:8080/healthz");
    expect(headersOf(calls[0] as CapturedCall)["x-api-key"]).toBeUndefined();
  });

  it("accepte une racine avec slash final et des espaces parasites", async () => {
    const { client, calls } = makeClient(() => jsonResponse(200, { items: [] }), {
      baseUrl: "http://127.0.0.1:8080/",
    });

    await client.list_tenants();

    expect(calls[0]?.url).toBe("http://127.0.0.1:8080/api/v1/tenants");
  });

  it("refuse une racine sans schéma http(s)", () => {
    expect(() => new ThotSecureClient({ baseUrl: "127.0.0.1:8080" })).toThrow(ValidationError);
  });
});

describe("ThotSecureClient — sérialisation", () => {
  it("sérialise un événement en JSON, tenant renseigné depuis le client", async () => {
    const { client, calls } = makeClient(() =>
      jsonResponse(202, { accepted: 1, rejected: 0, event_ids: ["e1"], findings: [] }),
    );

    await client.ingest_event({ kind: "http.request", labels: { src_ip: "203.0.113.9" } });

    const call = calls[0] as CapturedCall;
    expect(call.url).toBe("http://127.0.0.1:8080/api/v1/events");
    expect(call.init.method).toBe("POST");
    expect(headersOf(call)["content-type"]).toBe("application/json");
    expect(JSON.parse(String(call.init.body))).toEqual({
      kind: "http.request",
      labels: { src_ip: "203.0.113.9" },
      tenant_id: "acme",
    });
  });

  it("sérialise les filtres de liste en chaîne de requête", async () => {
    const { client, calls } = makeClient(() => jsonResponse(200, { items: [], next_cursor: null }));

    await client.list_findings({
      status: "open",
      severity: "high",
      min_risk: 70,
      sort: "risk_score",
      limit: 25,
    });

    const url = new URL(calls[0]?.url ?? "");
    expect(url.pathname).toBe("/api/v1/findings");
    expect(url.searchParams.get("status")).toBe("open");
    expect(url.searchParams.get("severity")).toBe("high");
    expect(url.searchParams.get("min_risk")).toBe("70");
    expect(url.searchParams.get("sort")).toBe("risk_score");
    expect(url.searchParams.get("limit")).toBe("25");
    // Les filtres non fournis ne sont pas envoyés.
    expect(url.searchParams.has("cursor")).toBe(false);
  });

  it("refuse une valeur hors énumération sans appeler le réseau", async () => {
    const { client, calls } = makeClient(() => jsonResponse(200, { items: [] }));

    await expect(client.list_findings({ sort: "score" as never })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(calls).toHaveLength(0);
  });

  it("découpe un lot d'ingestion au-delà de la taille demandée", async () => {
    const { client, calls } = makeClient(() =>
      jsonResponse(202, { accepted: 1, rejected: 0, event_ids: ["e"], findings: [] }),
    );

    const result = await client.ingest_events(
      [
        { kind: "log.line", labels: { n: 1 } },
        { kind: "log.line", labels: { n: 2 } },
        { kind: "log.line", labels: { n: 3 } },
      ],
      { chunkSize: 2 },
    );

    expect(calls).toHaveLength(2);
    expect((JSON.parse(String(calls[0]?.init.body)) as { events: unknown[] }).events).toHaveLength(2);
    expect((JSON.parse(String(calls[1]?.init.body)) as { events: unknown[] }).events).toHaveLength(1);
    expect(result.accepted).toBe(2);
    expect(result.event_ids).toEqual(["e", "e"]);
  });

  it("transmet la clé d'idempotence dans l'en-tête et le corps", async () => {
    const { client, calls } = makeClient(() => jsonResponse(200, { action_id: "a1" }));

    await client.execute_action("a1", { idempotencyKey: "acme:block:203.0.113.9:1739527200" });

    const call = calls[0] as CapturedCall;
    expect(headersOf(call)["idempotency-key"]).toBe("acme:block:203.0.113.9:1739527200");
    const body = JSON.parse(String(call.init.body)) as Record<string, unknown>;
    expect(body["idempotency_key"]).toBe("acme:block:203.0.113.9:1739527200");
    expect(body["dry_run"]).toBeUndefined();
  });
});

/* ====================================================================================== */
/* Mapping des erreurs (§4.6)                                                              */
/* ====================================================================================== */

describe("ThotSecureClient — mapping des erreurs", () => {
  const cases: Array<{ status: number; code: string; expected: unknown }> = [
    { status: 401, code: "unauthenticated", expected: AuthenticationError },
    { status: 403, code: "forbidden", expected: PermissionDeniedError },
    { status: 404, code: "not_found", expected: NotFoundError },
    { status: 409, code: "conflict", expected: ConflictError },
    { status: 422, code: "unprocessable", expected: ValidationError },
  ];

  for (const { status, code, expected } of cases) {
    it(`traduit ${status} (${code}) en erreur typée`, async () => {
      const { client } = makeClient(() => jsonResponse(status, errorBody(code, `refus ${status}`)));

      const error = await client.get_finding("f1").catch((reason: unknown) => reason);

      expect(error).toBeInstanceOf(expected);
      expect(error).toBeInstanceOf(ThotSecureError);
      expect((error as ThotSecureError).statusCode).toBe(status);
      expect((error as ThotSecureError).code).toBe(code);
      expect((error as ThotSecureError).message).toBe(`refus ${status}`);
      expect((error as ThotSecureError).url).toBe("http://127.0.0.1:8080/api/v1/findings/f1");
    });
  }

  it("expose Retry-After d'un 429 en secondes et en millisecondes", async () => {
    const { client, calls, sleeps } = makeClient(() =>
      jsonResponse(429, errorBody("rate_limited", "trop de requêtes"), { "Retry-After": "2" }),
    );

    const error = await client.get_event("e1").catch((reason: unknown) => reason);

    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfter).toBe(2);
    expect((error as RateLimitedError).retryAfterMs).toBe(2000);
    expect((error as RateLimitedError).retryable).toBe(true);
    // 429 est réessayable : une tentative initiale + 3 reprises (politique par défaut).
    expect(calls.length).toBe(4);
    expect(sleeps).toEqual([2000, 2000, 2000]);
  });

  it("retombe sur le statut HTTP quand le corps n'est pas celui du contrat", async () => {
    const { client } = makeClient(
      () => new Response("<html>Bad Gateway</html>", { status: 500 }),
    );

    const error = await client.stats_overview().catch((reason: unknown) => reason);

    expect(error).toBeInstanceOf(ServerError);
    expect((error as ServerError).statusCode).toBe(500);
    expect((error as ServerError).message).toContain("Bad Gateway");
  });

  it("ne laisse jamais fuiter la clé API dans une erreur d'URL", () => {
    const { client } = makeClient(() => jsonResponse(200, {}));

    const url = client.ws_url();
    expect(url).toContain("api_key=ao_test_key_0001");
    expect(redactUrl(url)).not.toContain("ao_test_key_0001");
    expect(redactUrl(url)).toContain("api_key=***");
  });
});

/* ====================================================================================== */
/* Reprise et sondes                                                                       */
/* ====================================================================================== */

describe("ThotSecureClient — reprise et sondes", () => {
  it("réessaie un GET sur 503 puis réussit", async () => {
    let attempts = 0;
    const { client, calls, sleeps } = makeClient(() => {
      attempts += 1;
      if (attempts === 1) {
        return jsonResponse(503, errorBody("internal_error", "indisponible"));
      }
      return jsonResponse(200, { items: [], next_cursor: null });
    });

    const page = await client.list_events();

    expect(page.items).toEqual([]);
    expect(calls).toHaveLength(2);
    // attempt 0 : 500 ms × jitter(1) = 500 ms.
    expect(sleeps).toEqual([500]);
  });

  it("respecte Retry-After lors de la reprise", async () => {
    let attempts = 0;
    const { client, sleeps } = makeClient(() => {
      attempts += 1;
      if (attempts === 1) {
        return jsonResponse(503, errorBody("internal_error", "indisponible"), {
          "Retry-After": "3",
        });
      }
      return jsonResponse(200, { items: [], next_cursor: null });
    });

    await client.list_events();

    expect(sleeps).toEqual([3000]);
  });

  it("ne réessaie pas un POST sans clé d'idempotence", async () => {
    const { client, calls } = makeClient(() =>
      jsonResponse(503, errorBody("internal_error", "indisponible")),
    );

    await expect(client.execute_action("a1")).rejects.toBeInstanceOf(ServerError);
    expect(calls).toHaveLength(1);
  });

  it("réessaie un POST dès qu'une clé d'idempotence est fournie", async () => {
    let attempts = 0;
    const { client, calls } = makeClient(() => {
      attempts += 1;
      if (attempts === 1) {
        return jsonResponse(503, errorBody("internal_error", "indisponible"));
      }
      return jsonResponse(200, { action_id: "a1", status: "succeeded" });
    });

    await client.execute_action("a1", { idempotencyKey: "k-1" });

    expect(calls).toHaveLength(2);
  });

  it("retourne un statut indisponible sur /readyz 503 sans lever d'exception", async () => {
    const { client } = makeClient(() =>
      jsonResponse(503, errorBody("internal_error", "bus indisponible")),
    );

    const ready = await client.readyz();

    expect(ready.http_status).toBe(503);
    expect(ready.status).toBe("unavailable");
    expect(ready.error).toContain("bus indisponible");
  });

  it("lève sur /readyz 503 quand raiseOnError est demandé", async () => {
    const { client } = makeClient(() =>
      jsonResponse(503, errorBody("internal_error", "bus indisponible")),
    );

    await expect(client.readyz({ raiseOnError: true })).rejects.toBeInstanceOf(ServerError);
  });

  it("suit le curseur de pagination", async () => {
    const pages = [
      jsonResponse(200, { items: [{ event_id: "e1" }], next_cursor: "c1" }),
      jsonResponse(200, { items: [{ event_id: "e2" }], next_cursor: null }),
    ];
    let index = 0;
    const { client, calls } = makeClient(() => pages[index++] ?? jsonResponse(200, { items: [] }));

    const ids: string[] = [];
    for await (const event of client.iter_events()) {
      ids.push(event.event_id);
    }

    expect(ids).toEqual(["e1", "e2"]);
    expect(calls).toHaveLength(2);
    expect(new URL(calls[1]?.url ?? "").searchParams.get("cursor")).toBe("c1");
  });

  it("refuse d'utiliser un client fermé", async () => {
    const { client, calls } = makeClient(() => jsonResponse(200, { items: [] }));

    client.close();

    await expect(client.list_events()).rejects.toThrow(/client fermé/);
    expect(calls).toHaveLength(0);
  });
});

/* ====================================================================================== */
/* Flux WebSocket (URL et backoff)                                                         */
/* ====================================================================================== */

describe("Flux WebSocket — URL et backoff", () => {
  it("construit une URL ws:// avec api_key et tenant_id", () => {
    const url = buildWebSocketUrl("https://thot.example.org", {
      apiKey: "ao_secret",
      tenantId: "acme",
    });

    const parsed = new URL(url);
    expect(parsed.protocol).toBe("wss:");
    expect(parsed.host).toBe("thot.example.org");
    expect(parsed.pathname).toBe(WS_PATH);
    expect(parsed.searchParams.get("api_key")).toBe("ao_secret");
    expect(parsed.searchParams.get("tenant_id")).toBe("acme");
  });

  it("conserve le préfixe de chemin d'un déploiement derrière un reverse-proxy", () => {
    const url = buildWebSocketUrl("http://127.0.0.1:8080/aegis", { tenantId: "acme" });

    const parsed = new URL(url);
    expect(parsed.protocol).toBe("ws:");
    expect(parsed.pathname).toBe(`/aegis${WS_PATH}`);
    expect(parsed.searchParams.get("tenant_id")).toBe("acme");
  });

  it("plafonne le backoff de reconnexion à 30 s et borne le jitter", () => {
    expect(computeReconnectDelay(0, 500, 30_000, () => 1)).toBe(500);
    expect(computeReconnectDelay(1, 500, 30_000, () => 1)).toBe(1000);
    expect(computeReconnectDelay(10, 500, 30_000, () => 1)).toBe(30_000);
    expect(computeReconnectDelay(10, 500, 30_000, () => 0)).toBe(15_000);
    // Jamais au-delà du plafond, quelle que soit la tentative.
    expect(computeReconnectDelay(30, 500, 30_000, () => 1)).toBe(30_000);
  });
});
