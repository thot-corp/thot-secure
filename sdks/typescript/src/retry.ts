/**
 * Politique de reprise (retry) du SDK Thot Secure.
 *
 * Règles, alignées sur le SDK Python de référence et sur le contrat §4.6 :
 *
 * 1. **Réessai** uniquement sur `429`, `502`, `503`, `504` et sur les erreurs réseau ;
 * 2. **jamais** de réessai d'une opération non idempotente (`POST`, `PATCH`) sans clé
 *    d'idempotence explicite — sinon un `POST /actions/{id}/execute` rejoué exécuterait deux fois
 *    la même contre-mesure ;
 * 3. backoff exponentiel plafonné avec **jitter multiplicatif** dans `[0.5, 1[` (évite que tous
 *    les clients se reconnectent au même instant) ;
 * 4. en-tête `Retry-After` **respecté** lorsqu'il est présent (plafonné par `maxRetryAfterMs`) ;
 * 5. l'annulation (`AbortSignal`) interrompt immédiatement l'attente et n'est **jamais** réessayée.
 */

import { ThotSecureError, parseRetryAfterHeader } from "./errors";

/** Méthodes idempotentes par définition (RFC 9110) : réessayables sans risque. */
export const IDEMPOTENT_METHODS: readonly string[] = ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"];

/** Statuts déclenchant un nouvel essai (contrat §4.6 + transitoires usuels). */
export const RETRY_STATUS_CODES: readonly number[] = [429, 502, 503, 504];

/** Paramètres de la politique de reprise. */
export interface RetryPolicy {
  /** Nombre de tentatives **supplémentaires** (hors tentative initiale). */
  maxRetries: number;
  /** Base du backoff exponentiel, en millisecondes. */
  backoffBaseMs: number;
  /** Plafond du backoff, en millisecondes. */
  backoffMaxMs: number;
  /** Plafond appliqué à un `Retry-After` serveur, en millisecondes. */
  maxRetryAfterMs: number;
  /** Statuts HTTP considérés comme réessayables. */
  retryStatusCodes: readonly number[];
}

/** Politique par défaut : 3 essais supplémentaires, base 500 ms, plafond 30 s. */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxRetries: 3,
  backoffBaseMs: 500,
  backoffMaxMs: 30_000,
  maxRetryAfterMs: 60_000,
  retryStatusCodes: RETRY_STATUS_CODES,
};

/** Informations transmises à `onRetry` (journalisation / métriques). */
export interface RetryInfo {
  /** Index de la tentative qui vient d'échouer (0 = tentative initiale). */
  attempt: number;
  /** Délai d'attente avant la prochaine tentative, en millisecondes. */
  delayMs: number;
  /** Cause lisible (`HTTP 503`, `erreur réseau`…). */
  reason: string;
  /** Statut HTTP observé, `null` pour une erreur réseau. */
  statusCode: number | null;
}

/** Options de `retryingFetch()`. */
export interface RetryOptions {
  /** Surcharge partielle de `DEFAULT_RETRY_POLICY`. */
  policy?: Partial<RetryPolicy> | undefined;
  /** `false` interdit tout nouvel essai (méthode non idempotente sans clé d'idempotence). */
  retrySafe: boolean;
  /** Annulation : interrompt l'attente et empêche tout réessai. */
  signal?: AbortSignal | undefined;
  /** Attente injectable (tests déterministes). */
  sleep?: ((delayMs: number, signal?: AbortSignal) => Promise<void>) | undefined;
  /** Source d'aléa injectable pour le jitter (tests déterministes). */
  random?: (() => number) | undefined;
  /** Rappel invoqué avant chaque nouvel essai. */
  onRetry?: ((info: RetryInfo) => void) | undefined;
  /** Horloge injectable (parsing de `Retry-After` en date HTTP). */
  now?: (() => number) | undefined;
}

/**
 * Indique si un appel peut être rejoué sans risque d'effet de bord dupliqué.
 *
 * `POST` / `PATCH` ne sont réessayés que si l'appelant fournit une clé d'idempotence explicite :
 * le serveur déduplique alors l'opération (contrat §4.6, `Idempotency-Key`).
 */
export function isRetrySafe(method: string, idempotencyKey?: string | null): boolean {
  if (IDEMPOTENT_METHODS.includes(method.toUpperCase())) {
    return true;
  }
  return typeof idempotencyKey === "string" && idempotencyKey.trim() !== "";
}

/** `true` si le statut HTTP déclenche un nouvel essai. */
export function isRetryableStatus(status: number, policy: RetryPolicy = DEFAULT_RETRY_POLICY): boolean {
  return policy.retryStatusCodes.includes(status);
}

/**
 * Calcule le délai de backoff exponentiel plafonné, avec jitter dans `[0.5, 1[`.
 *
 * @param attempt index de la tentative échouée (0 pour la première).
 */
export function computeBackoffDelay(
  attempt: number,
  policy: RetryPolicy = DEFAULT_RETRY_POLICY,
  random: () => number = Math.random,
): number {
  const safeAttempt = Math.max(0, Math.floor(attempt));
  const raw = Math.min(policy.backoffMaxMs, policy.backoffBaseMs * 2 ** safeAttempt);
  const jitter = 0.5 + 0.5 * Math.min(1, Math.max(0, random()));
  return Math.round(raw * jitter);
}

/** Fusionne une politique partielle avec les valeurs par défaut. */
export function resolveRetryPolicy(override?: Partial<RetryPolicy> | undefined): RetryPolicy {
  if (!override) {
    return { ...DEFAULT_RETRY_POLICY };
  }
  return {
    maxRetries: Math.max(0, Math.floor(override.maxRetries ?? DEFAULT_RETRY_POLICY.maxRetries)),
    backoffBaseMs: Math.max(0, override.backoffBaseMs ?? DEFAULT_RETRY_POLICY.backoffBaseMs),
    backoffMaxMs: Math.max(0, override.backoffMaxMs ?? DEFAULT_RETRY_POLICY.backoffMaxMs),
    maxRetryAfterMs: Math.max(0, override.maxRetryAfterMs ?? DEFAULT_RETRY_POLICY.maxRetryAfterMs),
    retryStatusCodes: override.retryStatusCodes ?? DEFAULT_RETRY_POLICY.retryStatusCodes,
  };
}

/** Construit l'erreur d'annulation (`AbortError`), y compris hors navigateur. */
export function abortError(message = "opération annulée"): Error {
  if (typeof DOMException === "function") {
    return new DOMException(message, "AbortError");
  }
  const error = new Error(message);
  error.name = "AbortError";
  return error;
}

/** `true` si l'erreur est une annulation volontaire (jamais réessayée). */
export function isAbortError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    (error as { name?: unknown }).name === "AbortError"
  );
}

/** Lève immédiatement si le signal est déjà annulé. */
export function throwIfAborted(signal?: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw abortError();
  }
}

/** Attente annulable (résolue à l'expiration, rejetée si le signal est annulé). */
export function sleepMs(delayMs: number, signal?: AbortSignal | undefined): Promise<void> {
  if (delayMs <= 0) {
    throwIfAborted(signal);
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(abortError());
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, delayMs);
    const onAbort = (): void => {
      cleanup();
      reject(abortError());
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Délai à observer après un échec.
 *
 * Un `Retry-After` serveur (secondes ou date HTTP) prime sur le backoff calculé ; il est plafonné
 * par `maxRetryAfterMs` pour qu'un serveur ne puisse pas bloquer un client indéfiniment.
 */
export function computeRetryDelay(
  attempt: number,
  options: {
    policy: RetryPolicy;
    retryAfterHeader?: string | null | undefined;
    random?: (() => number) | undefined;
    now?: (() => number) | undefined;
  },
): number {
  const { policy, retryAfterHeader } = options;
  const parsed = parseRetryAfterHeader(retryAfterHeader ?? null, options.now?.() ?? Date.now());
  if (parsed !== null) {
    return Math.min(policy.maxRetryAfterMs, Math.round(parsed * 1000));
  }
  return computeBackoffDelay(attempt, policy, options.random ?? Math.random);
}

/** Résultat interne : distingue « réponse exploitable » de « échec à rejouer ». */
type Outcome =
  /** Statut non réessayable : réponse finale. */
  | { kind: "response"; response: Response }
  /** Statut réessayable (429/502/503/504) : la réponse est conservée pour un éventuel retour final. */
  | { kind: "http"; response: Response }
  /** Erreur réseau ou de transport. */
  | { kind: "network"; error: unknown };

/**
 * Exécute `send` en appliquant la politique de reprise.
 *
 * `send` reçoit le numéro de tentative (0 = tentative initiale) et doit retourner la `Response`
 * brute **sans lever** pour un statut ≥ 400 : c'est la classification ci-dessous qui décide.
 *
 * @returns la `Response` finale — y compris un dernier `429`/`503` : c'est à l'appelant de la
 *          transformer en erreur typée (`RateLimitedError`, `ServerError`…).
 */
export async function retryingFetch(
  send: (attempt: number) => Promise<Response>,
  options: RetryOptions,
): Promise<Response> {
  const policy = resolveRetryPolicy(options.policy);
  const sleep = options.sleep ?? sleepMs;

  let attempt = 0;
  for (;;) {
    throwIfAborted(options.signal);

    let outcome: Outcome;
    try {
      const response = await send(attempt);
      outcome = isRetryableStatus(response.status, policy)
        ? { kind: "http", response }
        : { kind: "response", response };
    } catch (error) {
      if (isAbortError(error) || options.signal?.aborted === true) {
        // Une annulation volontaire n'est jamais réessayée.
        throw error;
      }
      const retryable = error instanceof ThotSecureError ? error.retryable : true;
      if (!retryable) {
        throw error;
      }
      outcome = { kind: "network", error };
    }

    if (outcome.kind === "response") {
      return outcome.response;
    }

    // Fin de la politique de reprise : on rend la main, sans masquer la cause d'origine.
    if (!options.retrySafe || attempt >= policy.maxRetries) {
      if (outcome.kind === "http") {
        return outcome.response;
      }
      throw outcome.error;
    }

    const statusCode = outcome.kind === "http" ? outcome.response.status : null;
    const reason = outcome.kind === "http" ? `HTTP ${outcome.response.status}` : "erreur réseau";
    const retryAfterHeader = outcome.kind === "http" ? outcome.response.headers.get("retry-after") : null;
    const delayMs = computeRetryDelay(attempt, {
      policy,
      retryAfterHeader,
      random: options.random,
      now: options.now,
    });
    options.onRetry?.({ attempt, delayMs, reason, statusCode });
    await sleep(delayMs, options.signal);
    attempt += 1;
  }
}

export { parseRetryAfterHeader as parseRetryAfter };
