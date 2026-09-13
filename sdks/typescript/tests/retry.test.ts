/**
 * Tests de la politique de reprise — **exécutables hors ligne**.
 *
 * Aucun réseau, aucune attente réelle : `send`, `sleep`, `random` et `now` sont injectés, ce qui
 * rend le backoff, le jitter et le respect de `Retry-After` parfaitement déterministes.
 *
 * Couverture : backoff exponentiel plafonné, jitter borné dans `[0.5, 1[`, absence de reprise sur
 * une méthode non idempotente sans clé d'idempotence, annulation immédiate, erreurs non
 * réessayables et plafonnement d'un `Retry-After` abusif côté serveur.
 */

import { describe, expect, it } from "vitest";

import { ValidationError, parseRetryAfterHeader } from "../src/errors";
import {
  DEFAULT_RETRY_POLICY,
  IDEMPOTENT_METHODS,
  RETRY_STATUS_CODES,
  abortError,
  computeBackoffDelay,
  computeRetryDelay,
  isAbortError,
  isRetrySafe,
  isRetryableStatus,
  resolveRetryPolicy,
  retryingFetch,
  sleepMs,
  type RetryPolicy,
} from "../src/retry";

/** Réponse minimale. */
function response(status: number, headers: Record<string, string> = {}): Response {
  return new Response(status >= 400 ? '{"error":{"code":"internal_error"}}' : "{}", {
    status,
    headers,
  });
}

/** Options de reprise déterministes : jitter maximal, aucune attente réelle. */
function deterministicOptions(overrides: {
  policy?: Partial<RetryPolicy>;
  retrySafe: boolean;
  sleeps?: number[];
  signal?: AbortSignal;
}): Parameters<typeof retryingFetch>[1] {
  return {
    policy: overrides.policy,
    retrySafe: overrides.retrySafe,
    signal: overrides.signal,
    random: () => 1,
    sleep: async (delayMs) => {
      overrides.sleeps?.push(delayMs);
    },
  };
}

/* ====================================================================================== */
/* Idempotence et classification                                                           */
/* ====================================================================================== */

describe("isRetrySafe — idempotence des méthodes", () => {
  it("autorise les méthodes idempotentes de la RFC 9110", () => {
    for (const method of IDEMPOTENT_METHODS) {
      expect(isRetrySafe(method)).toBe(true);
    }
    expect(isRetrySafe("get")).toBe(true);
  });

  it("interdit POST et PATCH sans clé d'idempotence", () => {
    expect(isRetrySafe("POST")).toBe(false);
    expect(isRetrySafe("PATCH")).toBe(false);
    expect(isRetrySafe("POST", null)).toBe(false);
    expect(isRetrySafe("POST", "   ")).toBe(false);
  });

  it("autorise POST et PATCH dès qu'une clé d'idempotence est fournie", () => {
    expect(isRetrySafe("POST", "acme:block-source-ip:203.0.113.9:1739527200")).toBe(true);
    expect(isRetrySafe("PATCH", "k-1")).toBe(true);
  });
});

describe("isRetryableStatus — statuts transitoires", () => {
  it("ne réessaie que 429, 502, 503 et 504", () => {
    expect(RETRY_STATUS_CODES).toEqual([429, 502, 503, 504]);
    expect(isRetryableStatus(503)).toBe(true);
    expect(isRetryableStatus(429, DEFAULT_RETRY_POLICY)).toBe(true);
    expect(isRetryableStatus(500)).toBe(false);
    expect(isRetryableStatus(422)).toBe(false);
    expect(isRetryableStatus(200)).toBe(false);
  });
});

/* ====================================================================================== */
/* Backoff et jitter                                                                       */
/* ====================================================================================== */

describe("computeBackoffDelay — backoff exponentiel et jitter borné", () => {
  const policy: RetryPolicy = { ...DEFAULT_RETRY_POLICY, backoffBaseMs: 100, backoffMaxMs: 800 };

  it("double à chaque tentative sans dépasser le plafond", () => {
    expect(computeBackoffDelay(0, policy, () => 0.5)).toBe(100);
    expect(computeBackoffDelay(1, policy, () => 0.5)).toBe(200);
    expect(computeBackoffDelay(2, policy, () => 0.5)).toBe(400);
    expect(computeBackoffDelay(3, policy, () => 0.5)).toBe(800);
    expect(computeBackoffDelay(4, policy, () => 0.5)).toBe(800);
    expect(computeBackoffDelay(64, policy, () => 0.5)).toBe(800);
  });

  it("borne le jitter dans [0.5 × délai, délai]", () => {
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const raw = Math.min(policy.backoffMaxMs, policy.backoffBaseMs * 2 ** attempt);
      for (const sample of [0, 0.13, 0.5, 0.87, 1, 1.5, -1, Number.NaN]) {
        const delay = computeBackoffDelay(attempt, policy, () => sample);
        expect(delay).toBeGreaterThanOrEqual(Math.round(raw * 0.5));
        expect(delay).toBeLessThanOrEqual(raw);
      }
    }
  });

  it("normalise les entrées aberrantes (tentative négative ou non entière)", () => {
    expect(computeBackoffDelay(-5, policy, () => 1)).toBe(100);
    expect(computeBackoffDelay(2.7, policy, () => 1)).toBe(400);
  });

  it("applique le plafond par défaut de 30 s", () => {
    expect(DEFAULT_RETRY_POLICY.backoffMaxMs).toBe(30_000);
    expect(computeBackoffDelay(20, DEFAULT_RETRY_POLICY, () => 1)).toBe(30_000);
  });

  it("resolveRetryPolicy complète une politique partielle et refuse les valeurs négatives", () => {
    const resolved = resolveRetryPolicy({ maxRetries: -3, backoffBaseMs: 250 });
    expect(resolved.maxRetries).toBe(0);
    expect(resolved.backoffBaseMs).toBe(250);
    expect(resolved.backoffMaxMs).toBe(DEFAULT_RETRY_POLICY.backoffMaxMs);
    expect(resolved.retryStatusCodes).toBe(DEFAULT_RETRY_POLICY.retryStatusCodes);
  });
});

describe("computeRetryDelay — Retry-After prioritaire et plafonné", () => {
  const policy: RetryPolicy = { ...DEFAULT_RETRY_POLICY, maxRetryAfterMs: 10_000 };
  const cappedPolicy: RetryPolicy = { ...DEFAULT_RETRY_POLICY, maxRetryAfterMs: 1500 };

  it("respecte un Retry-After en secondes", () => {
    expect(computeRetryDelay(0, { policy, retryAfterHeader: "2", random: () => 1 })).toBe(2000);
    expect(computeRetryDelay(3, { policy, retryAfterHeader: "1", random: () => 0.1 })).toBe(1000);
  });

  it("plafonne un Retry-After abusif par maxRetryAfterMs", () => {
    expect(
      computeRetryDelay(0, { policy: cappedPolicy, retryAfterHeader: "3600", random: () => 1 }),
    ).toBe(1500);
  });

  it("accepte la forme date HTTP du Retry-After", () => {
    const now = Date.parse("2026-02-14T10:00:00Z");
    const header = new Date(now + 4000).toUTCString();
    expect(
      computeRetryDelay(0, { policy, retryAfterHeader: header, now: () => now, random: () => 1 }),
    ).toBe(4000);
    expect(
      computeRetryDelay(0, {
        policy: cappedPolicy,
        retryAfterHeader: header,
        now: () => now,
        random: () => 1,
      }),
    ).toBe(1500);
  });

  it("retombe sur le backoff calculé sans en-tête exploitable", () => {
    const policy2: RetryPolicy = { ...DEFAULT_RETRY_POLICY, backoffBaseMs: 100, maxRetryAfterMs: 60_000 };
    expect(computeRetryDelay(2, { policy: policy2, retryAfterHeader: "soon", random: () => 1 })).toBe(400);
    expect(computeRetryDelay(0, { policy: policy2, retryAfterHeader: null, random: () => 1 })).toBe(100);
  });

  it("parseRetryAfterHeader couvre secondes, date HTTP et valeurs invalides", () => {
    const now = Date.parse("2026-02-14T10:00:00Z");
    expect(parseRetryAfterHeader("30", now)).toBe(30);
    expect(parseRetryAfterHeader(new Date(now + 10_000).toUTCString(), now)).toBe(10);
    expect(parseRetryAfterHeader("-5", now)).toBe(0);
    expect(parseRetryAfterHeader("n'importe quoi", now)).toBeNull();
    expect(parseRetryAfterHeader(null, now)).toBeNull();
    expect(parseRetryAfterHeader("", now)).toBeNull();
  });
});

/* ====================================================================================== */
/* Boucle de reprise                                                                       */
/* ====================================================================================== */

describe("retryingFetch — boucle de reprise", () => {
  it("réessaie un statut transitoire puis rend la réponse finale", async () => {
    const sleeps: number[] = [];
    let attempts = 0;
    const result = await retryingFetch(
      async () => {
        attempts += 1;
        return attempts < 3 ? response(503) : response(200);
      },
      deterministicOptions({
        retrySafe: true,
        sleeps,
        policy: { maxRetries: 3, backoffBaseMs: 100, backoffMaxMs: 1000 },
      }),
    );

    expect(result.status).toBe(200);
    expect(attempts).toBe(3);
    expect(sleeps).toEqual([100, 200]);
  });

  it("ne réessaie pas du tout quand retrySafe est faux (POST sans clé d'idempotence)", async () => {
    const sleeps: number[] = [];
    let attempts = 0;
    const result = await retryingFetch(
      async () => {
        attempts += 1;
        return response(503);
      },
      deterministicOptions({ retrySafe: false, sleeps }),
    );

    // La réponse est rendue telle quelle : c'est l'appelant qui la transforme en erreur typée.
    expect(result.status).toBe(503);
    expect(attempts).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it("s'arrête après maxRetries et rend le dernier statut transitoire", async () => {
    const sleeps: number[] = [];
    let attempts = 0;
    const result = await retryingFetch(
      async () => {
        attempts += 1;
        return response(429);
      },
      deterministicOptions({
        retrySafe: true,
        sleeps,
        policy: { maxRetries: 2, backoffBaseMs: 50, backoffMaxMs: 500 },
      }),
    );

    expect(result.status).toBe(429);
    expect(attempts).toBe(3);
    expect(sleeps).toEqual([50, 100]);
  });

  it("réessaie une erreur réseau puis réussit", async () => {
    let attempts = 0;
    const result = await retryingFetch(
      async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new TypeError("fetch failed");
        }
        return response(200);
      },
      deterministicOptions({ retrySafe: true, policy: { maxRetries: 2 } }),
    );

    expect(result.status).toBe(200);
    expect(attempts).toBe(2);
  });

  it("propage une erreur réseau quand la politique est épuisée", async () => {
    let attempts = 0;
    await expect(
      retryingFetch(
        async () => {
          attempts += 1;
          throw new TypeError("fetch failed");
        },
        deterministicOptions({ retrySafe: true, policy: { maxRetries: 1 } }),
      ),
    ).rejects.toBeInstanceOf(TypeError);
    expect(attempts).toBe(2);
  });

  it("ne réessaie jamais une erreur marquée non réessayable", async () => {
    let attempts = 0;
    await expect(
      retryingFetch(
        async () => {
          attempts += 1;
          throw new ValidationError("422 : corps invalide");
        },
        deterministicOptions({ retrySafe: true }),
      ),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(attempts).toBe(1);
  });

  it("n'appelle même pas le transport si le signal est déjà annulé", async () => {
    const controller = new AbortController();
    controller.abort();
    let attempts = 0;

    const error = await retryingFetch(
      async () => {
        attempts += 1;
        return response(200);
      },
      deterministicOptions({ retrySafe: true, signal: controller.signal }),
    ).catch((reason: unknown) => reason);

    expect(isAbortError(error)).toBe(true);
    expect(attempts).toBe(0);
  });

  it("n'attend ni ne réessaie quand l'annulation survient pendant l'attente", async () => {
    const controller = new AbortController();
    const sleeps: number[] = [];
    let attempts = 0;

    const pending = retryingFetch(
      async () => {
        attempts += 1;
        return response(503);
      },
      {
        retrySafe: true,
        signal: controller.signal,
        random: () => 1,
        sleep: async (delayMs) => {
          sleeps.push(delayMs);
          controller.abort();
          throw abortError();
        },
      },
    );

    const error = await pending.catch((reason: unknown) => reason);
    expect(isAbortError(error)).toBe(true);
    expect(attempts).toBe(1);
    expect(sleeps).toHaveLength(1);
  });

  it("déclenche onRetry avec le délai et la cause observée", async () => {
    const infos: Array<{ attempt: number; delayMs: number; statusCode: number | null }> = [];
    let attempts = 0;

    await retryingFetch(
      async () => {
        attempts += 1;
        return attempts === 1 ? response(503) : response(200);
      },
      {
        retrySafe: true,
        random: () => 1,
        sleep: async () => undefined,
        policy: { maxRetries: 2, backoffBaseMs: 100, backoffMaxMs: 1000 },
        onRetry: (info) => {
          infos.push({ attempt: info.attempt, delayMs: info.delayMs, statusCode: info.statusCode });
        },
      },
    );

    expect(infos).toEqual([{ attempt: 0, delayMs: 100, statusCode: 503 }]);
  });

  it("sleepMs se termine immédiatement pour un délai nul", async () => {
    await expect(sleepMs(0)).resolves.toBeUndefined();
  });
});
