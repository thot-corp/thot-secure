/**
 * Helpers d'intégration du SDK TypeScript Thot Secure (ex-Thot Secure).
 *
 * Ces fonctions évitent de réécrire la glue à chaque intégration, exactement comme
 * `thotsecure_sdk/helpers.py` côté Python :
 *
 * * `normalizeNginxLine()` / `normalizeEvent()` — transforme une ligne de journal Nginx/Apache
 *   (« combined » ou « common »), une ligne JSON structurée ou un objet applicatif en `Event`
 *   conforme au contrat §3.1 (`labels` plat, `payload` ≤ 32 Kio, `kind` énuméré) ;
 * * `redactSecrets()` — masque les en-têtes et champs sensibles **avant** toute journalisation ou
 *   ingestion (`authorization`, `cookie`, `set-cookie`, `password`, `token`, `api_key`, JWT…) ;
 * * `pseudonymizeIp()` / `pseudonymizeIpFields()` — pseudonymisation HMAC-SHA256 déterministe des
 *   adresses IP (**obligation RGPD** : une adresse IP est une donnée à caractère personnel) ;
 * * `parseJsonl()` — lecture tolérante d'un flux JSONL (une ligne = un objet JSON) ;
 * * `chunked()` — découpage en lots ≤ 500 événements (contrat §4.3) ;
 * * utilitaires divers : `readEnv()`, `newEventId()`, `nowIso()`, `truncatePayload()`.
 *
 * Zéro dépendance runtime : SHA-256 et HMAC sont implémentés ici même, ce qui rend
 * `pseudonymizeIp()` **synchrone** et utilisable aussi bien dans un navigateur (où `crypto.subtle`
 * est asynchrone) que dans Node, sans jamais bloquer sur une promesse.
 *
 * ⚠️ `normalizeNginxLine()` conserve l'IP source en clair par défaut. Passez `ipSalt` pour la
 * pseudonymiser : si votre base est un traitement de données personnelles, l'IP en clair doit
 * rester l'exception, pas la règle.
 */

import { REDACTED, ValidationError } from "./errors";
import { EVENT_KINDS, MAX_BATCH_SIZE, MAX_PAYLOAD_BYTES } from "./types";
import type {
  Event,
  EventKind,
  JsonObject,
  JsonValue,
  Labels,
  Scalar,
  SeverityHint,
} from "./types";

/* ====================================================================================== */
/* Constantes                                                                              */
/* ====================================================================================== */

/** Valeur de remplacement d'un JWT reconnu dans une chaîne. */
export const REDACTED_JWT = "[REDACTED_JWT]";

/** Champs d'adresse IP traités par défaut par `pseudonymizeIpFields()`. */
export const DEFAULT_IP_FIELDS: readonly string[] = [
  "src_ip",
  "source_ip",
  "dst_ip",
  "dest_ip",
  "destination_ip",
  "client_ip",
  "remote_addr",
  "remote_ip",
  "real_ip",
  "forwarded_for",
  "x_forwarded_for",
  "host_ip",
  "server_ip",
  "peer_ip",
  "ip",
  "ip_address",
];

/** Variables d'environnement lues par `readEnv()` par défaut (repli `THOT_*`). */
export const ENV_URL = "THOT_SECURE_URL";
export const ENV_API_KEY = "THOT_SECURE_API_KEY";
export const ENV_TENANT_ID = "THOT_SECURE_TENANT_ID";

/* ====================================================================================== */
/* Environnement                                                                           */
/* ====================================================================================== */

/**
 * Lecture d'une variable d'environnement, dans l'ordre des noms fournis.
 *
 * Chaque nom est cherché tel quel, puis sous l'orthographe héritée `THOT_*` du projet
 * (renommage en cours) : `THOT_SECURE_URL` retombe automatiquement sur `THOT_URL`, et
 * inversement. La valeur n'est **jamais** journalisée : `THOT_SECURE_API_KEY` passe par ici.
 */
export function readEnv(...names: readonly string[]): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  if (env === undefined) {
    return undefined;
  }
  for (const name of names) {
    for (const candidate of [name, ...legacyEnvNames(name)]) {
      const value = env[candidate];
      if (typeof value === "string" && value !== "") {
        return value;
      }
    }
  }
  return undefined;
}

/** Orthographes de repli d'une variable d'environnement (compatibilité du renommage). */
function legacyEnvNames(name: string): string[] {
  const prefixes = ["THOT_SECURE_", "THOT_", "THOT_", "AEGIS_OPS_"];
  for (const prefix of prefixes) {
    if (!name.startsWith(prefix)) {
      continue;
    }
    const suffix = name.slice(prefix.length);
    return prefixes
      .filter((other) => other !== prefix)
      .map((other) => `${other}${suffix}`);
  }
  return [];
}

/* ====================================================================================== */
/* Identifiants et horodatages                                                             */
/* ====================================================================================== */

/** Sous-ensemble de l'API Web Crypto utilisé par le SDK. */
interface CryptoLike {
  randomUUID?: () => string;
  getRandomValues?: <T extends ArrayBufferView>(array: T) => T;
}

/** Octets aléatoires (Web Crypto ; repli `Math.random` documenté et non cryptographique). */
function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const cryptoObj = (globalThis as { crypto?: CryptoLike }).crypto;
  if (typeof cryptoObj?.getRandomValues === "function") {
    cryptoObj.getRandomValues(out);
    return out;
  }
  // Repli dégradé : uniquement pour des identifiants d'événement, jamais pour un secret ni un sel.
  for (let index = 0; index < length; index += 1) {
    out[index] = Math.floor(Math.random() * 256);
  }
  return out;
}

/** Identifiant d'événement (UUID v4), comme dans l'exemple du contrat §3.1. */
export function newEventId(): string {
  const cryptoObj = (globalThis as { crypto?: CryptoLike }).crypto;
  if (typeof cryptoObj?.randomUUID === "function") {
    return cryptoObj.randomUUID();
  }
  const bytes = randomBytes(16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40; // version 4
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80; // variante RFC 4122
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Horodatage ISO 8601 UTC en millisecondes, au format du contrat (`…Z`). */
export function nowIso(): string {
  return new Date().toISOString();
}

/* ====================================================================================== */
/* Analyse d'horodatages                                                                   */
/* ====================================================================================== */

const MONTHS: Readonly<Record<string, number>> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

const CLF_TS_RE =
  /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-])(\d{2})(\d{2})?$/;

const SYSLOG_TS_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/;

const NAIVE_ISO_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;

/**
 * Construit une date UTC sans dépendre de la locale du système (Windows FR incluse).
 *
 * `Date.parse("14/Feb/2026:10:00:00 +0100")` échoue sur la plupart des moteurs : l'analyse est
 * donc faite ici, à la main.
 */
function utcDate(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
): Date | null {
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return null;
  }
  if (hour > 23 || minute > 59 || second > 60) {
    return null;
  }
  const millis = Date.UTC(year, month - 1, day, hour, minute, second);
  return Number.isNaN(millis) ? null : new Date(millis);
}

/**
 * Analyse un horodatage de journal : ISO 8601, CLF Nginx/Apache, syslog RFC 3164 ou epoch.
 *
 * @returns une `Date` exploitable, ou `null` si la valeur n'est pas reconnue.
 */
export function parseTimestamp(value: unknown): Date | null {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return null;
    }
    // Les horodatages numériques sont interprétés en millisecondes (convention JavaScript).
    return new Date(value);
  }
  if (typeof value !== "string") {
    return null;
  }
  const text = value.trim();
  if (text === "") {
    return null;
  }

  const clf = CLF_TS_RE.exec(text);
  if (clf !== null) {
    const [, day, monthName, year, hour, minute, second, sign, offsetHour, offsetMinute] = clf;
    const month = MONTHS[(monthName ?? "").toLowerCase()];
    if (month === undefined) {
      return null;
    }
    const base = utcDate(
      Number(year),
      month,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
    );
    if (base === null) {
      return null;
    }
    const offset =
      (Number(offsetHour) * 60 + Number(offsetMinute ?? "0")) * 60_000 * (sign === "-" ? -1 : 1);
    return new Date(base.getTime() - offset);
  }

  const syslog = SYSLOG_TS_RE.exec(text);
  if (syslog !== null) {
    const [, monthName, day, hour, minute, second] = syslog;
    const month = MONTHS[(monthName ?? "").toLowerCase()];
    if (month === undefined) {
      return null;
    }
    // RFC 3164 n'inclut pas l'année : on suppose l'année courante (UTC).
    return utcDate(
      new Date().getUTCFullYear(),
      month,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
    );
  }

  if (/^\d{9,13}$/.test(text)) {
    const numeric = Number(text);
    return new Date(text.length <= 10 ? numeric * 1000 : numeric);
  }

  // ISO sans fuseau : on force UTC plutôt que de laisser le moteur utiliser le fuseau local.
  const candidate = NAIVE_ISO_RE.test(text) ? `${text.replace(" ", "T")}Z` : text;
  const parsed = Date.parse(candidate);
  return Number.isNaN(parsed) ? null : new Date(parsed);
}

/* ====================================================================================== */
/* Redaction des secrets                                                                   */
/* ====================================================================================== */

/** Clés dont la valeur est masquée, quelle que soit la casse (`-` et `_` équivalents). */
const SENSITIVE_EXACT: ReadonlySet<string> = new Set([
  "authorization",
  "auth",
  "authentication",
  "proxy_authorization",
  "cookie",
  "cookies",
  "set_cookie",
  "setcookie",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "token",
  "jwt",
  "bearer",
  "secret",
  "secrets",
  "client_secret",
  "api_key",
  "apikey",
  "x_api_key",
  "access_key",
  "secret_key",
  "private_key",
  "credentials",
  "credential",
  "session",
  "session_id",
  "sessionid",
  "csrf",
  "csrf_token",
  "xsrf",
  "signature",
  "nonce",
  "refresh_token",
  "access_token",
  "id_token",
  "aws_secret_access_key",
]);

/** Fragments de nom qui suffisent à considérer un champ comme sensible (fail-closed). */
const SENSITIVE_PARTS: ReadonlySet<string> = new Set([
  "authorization",
  "cookie",
  "cookies",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "token",
  "tokens",
  "jwt",
  "secret",
  "secrets",
  "credential",
  "credentials",
  "session",
  "sessionid",
  "csrf",
  "xsrf",
  "nonce",
  "signature",
  "privatekey",
]);

/*
 * Ordre d'application — du motif le plus spécifique au plus général :
 *
 * 1. le JWT complet (`eyJ….….…`) : sinon ses segments seraient hachés en morceaux ;
 * 2. le schéma d'authentification **avec son justificatif** (`Bearer …`) : masquer le seul mot
 *    « Bearer » laisserait le jeton en clair juste après — c'est le piège à éviter ;
 * 3. l'en-tête `Cookie` / `Set-Cookie` : sa valeur entière est masquée (elle contient un
 *    identifiant de session, donc un secret d'authentification) ;
 * 4. les clés d'API du projet (`ao_…`) ;
 * 5. les paires `clé=valeur` d'une query string (`token=…`, `api_key=…`) ;
 * 6. les identifiants d'URL (`https://user:motdepasse@hôte`).
 */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g;
const AUTH_SCHEME_RE = /\b(bearer|basic|token|apikey|api[_-]?key)(\s+)([A-Za-z0-9._\-+/=]{6,})/gi;
const COOKIE_HEADER_RE = /\b(set-cookie|cookie)\s*:\s*[^\r\n]+/gi;
const PROJECT_KEY_RE = /\bao_[A-Za-z0-9_-]{8,}\b/g;
const KV_SECRET_RE =
  /\b(api[_-]?key|apikey|access_token|refresh_token|id_token|token|password|passwd|secret|signature)=([^&\s"';]+)/gi;
const URL_CREDENTIAL_RE = /([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;

/** Normalise un nom de champ : minuscules, séparateurs unifiés en `_`. */
export function normalizeKey(key: string): string {
  return key
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * `true` si le nom de champ désigne une donnée à masquer.
 *
 * En cas de doute on masque (fail-closed) : un faux positif produit un journal inexploitable,
 * un faux négatif produit une fuite de secret.
 */
export function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized === "") {
    return false;
  }
  if (SENSITIVE_EXACT.has(normalized)) {
    return true;
  }
  const parts = normalized.split("_").filter((part) => part !== "");
  if (parts.some((part) => SENSITIVE_PARTS.has(part))) {
    return true;
  }
  return parts.includes("api") && parts.includes("key");
}

/** Masque les secrets **contenus dans une chaîne** (JWT, `Bearer …`, `token=…`, `ao_…`). */
export function scrubString(value: string): string {
  return value
    .replace(JWT_RE, REDACTED_JWT)
    .replace(AUTH_SCHEME_RE, (_match, scheme: string, spacing: string) => `${scheme}${spacing}${REDACTED}`)
    .replace(COOKIE_HEADER_RE, (_match, name: string) => `${name}: ${REDACTED}`)
    .replace(PROJECT_KEY_RE, REDACTED)
    .replace(KV_SECRET_RE, (_match, name: string) => `${name}=${REDACTED}`)
    .replace(URL_CREDENTIAL_RE, (_match, scheme: string) => `${scheme}${REDACTED}:${REDACTED}@`);
}

/** Masque la valeur d'un champ sensible, en conservant le schéma d'authentification. */
function maskValue(value: unknown): unknown {
  if (typeof value === "string") {
    const parts = value.trim().split(/\s+/, 2);
    const scheme = parts[0]?.toLowerCase() ?? "";
    if (parts.length === 2 && ["bearer", "basic", "token", "apikey"].includes(scheme)) {
      return `${parts[0]} ${REDACTED}`;
    }
    return REDACTED;
  }
  return REDACTED;
}

/** Options de `redactSecrets()`. */
export interface RedactSecretsOptions {
  /** Profondeur maximale de récursion (défaut 32) : au-delà, la valeur est masquée. */
  maxDepth?: number | undefined;
}

function redactValue(
  value: unknown,
  depth: number,
  maxDepth: number,
  seen: WeakSet<object>,
): unknown {
  if (depth > maxDepth) {
    return REDACTED;
  }
  if (typeof value === "string") {
    return scrubString(value);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (seen.has(value)) {
    return REDACTED; // structure cyclique
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1, maxDepth, seen));
  }
  if (value instanceof Map) {
    const out: unknown[] = [];
    for (const [key, item] of value) {
      out.push([
        redactValue(key, depth + 1, maxDepth, seen),
        redactValue(item, depth + 1, maxDepth, seen),
      ]);
    }
    return out;
  }
  if (value instanceof Set) {
    return Array.from(value, (item) => redactValue(item, depth + 1, maxDepth, seen));
  }

  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    out[key] = isSensitiveKey(key) ? maskValue(item) : redactValue(item, depth + 1, maxDepth, seen);
  }
  return out;
}

/**
 * Retourne une copie de `data` où les champs sensibles sont masqués.
 *
 * Le traitement est récursif (objets, tableaux, `Map`, `Set`) et couvre :
 *
 * * les **clés** sensibles : `authorization`, `cookie`, `set-cookie`, `password`, `token`,
 *   `api_key`, `secret`, `session`, `signature`… (casse et séparateurs ignorés) ;
 * * les **JWT** (`eyJ…`) et schémas d'authentification (`Bearer …`) présents dans les valeurs,
 *   même sous une clé anodine comme `raw` ou `query` ;
 * * les paires `token=…` / `password=…` d'une query string et les identifiants d'URL.
 *
 * Aucun secret en clair ne doit être journalisé : appelez ce helper avant tout `console.log` ou
 * tout envoi d'événement contenant des en-têtes HTTP bruts.
 */
export function redactSecrets<T>(data: T, options: RedactSecretsOptions = {}): T {
  const maxDepth = options.maxDepth ?? 32;
  return redactValue(data, 0, maxDepth, new WeakSet<object>()) as T;
}

/* ====================================================================================== */
/* SHA-256 et HMAC-SHA256 (implémentation locale, synchrone, sans dépendance)               */
/* ====================================================================================== */

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(value: number, bits: number): number {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

/** SHA-256 (FIPS 180-4) sur des octets. */
function sha256Bytes(message: Uint8Array): Uint8Array {
  const length = message.length;
  const padded = new Uint8Array((((length + 8) >> 6) + 1) << 6);
  padded.set(message);
  padded[length] = 0x80;
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const bitLength = length * 8;
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x1_0000_0000));
  view.setUint32(padded.length - 4, bitLength >>> 0);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      w[index] = view.getUint32(offset + index * 4);
    }
    for (let index = 16; index < 64; index += 1) {
      const x = w[index - 15] ?? 0;
      const y = w[index - 2] ?? 0;
      const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
      const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
      w[index] = ((w[index - 16] ?? 0) + s0 + (w[index - 7] ?? 0) + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let index = 0; index < 64; index += 1) {
      const sigma1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const choose = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + sigma1 + choose + (SHA256_K[index] ?? 0) + (w[index] ?? 0)) >>> 0;
      const sigma0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const majority = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (sigma0 + majority) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  const out = new DataView(digest.buffer);
  out.setUint32(0, h0);
  out.setUint32(4, h1);
  out.setUint32(8, h2);
  out.setUint32(12, h3);
  out.setUint32(16, h4);
  out.setUint32(20, h5);
  out.setUint32(24, h6);
  out.setUint32(28, h7);
  return digest;
}

/** HMAC-SHA256 (RFC 2104) en hexadécimal minuscule. */
export function hmacSha256Hex(key: string, message: string): string {
  const encoder = new TextEncoder();
  let keyBytes = encoder.encode(key);
  if (keyBytes.length > 64) {
    keyBytes = sha256Bytes(keyBytes);
  }
  const block = new Uint8Array(64);
  block.set(keyBytes);

  const inner = new Uint8Array(64 + encoder.encode(message).length);
  const outer = new Uint8Array(64 + 32);
  for (let index = 0; index < 64; index += 1) {
    const byte = block[index] ?? 0;
    inner[index] = byte ^ 0x36;
    outer[index] = byte ^ 0x5c;
  }
  inner.set(encoder.encode(message), 64);
  outer.set(sha256Bytes(inner), 64);
  return Array.from(sha256Bytes(outer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/* ====================================================================================== */
/* Pseudonymisation RGPD des adresses IP                                                   */
/* ====================================================================================== */

/** Adresse analysée : version, forme canonique, et réseau éventuel. */
interface ParsedIp {
  version: 4 | 6;
  /** Forme canonique (octets normalisés, IPv6 compressé en minuscules). */
  canonical: string;
}

function isIpv4(text: string): boolean {
  const parts = text.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every(
    (part) => /^\d{1,3}$/.test(part) && (part === "0" || !part.startsWith("0")) && Number(part) <= 255,
  );
}

/** Développe une notation IPv6 en 8 groupes hexadécimaux, ou `null` si elle est invalide. */
function expandIpv6(text: string): string[] | null {
  const lower = text.toLowerCase();
  if (lower === "" || lower.includes("%")) {
    return null; // identifiant de zone (`fe80::1%eth0`) non supporté
  }
  const halves = lower.split("::");
  if (halves.length > 2) {
    return null;
  }
  const toGroups = (chunk: string): string[] | null => {
    if (chunk === "") {
      return [];
    }
    const raw = chunk.split(":");
    const groups: string[] = [];
    for (let index = 0; index < raw.length; index += 1) {
      const item = raw[index] ?? "";
      if (item.includes(".")) {
        // IPv4 embarquée : uniquement en dernière position, et elle occupe deux groupes.
        if (index !== raw.length - 1 || !isIpv4(item)) {
          return null;
        }
        const bytes = item.split(".").map((value) => Number(value));
        groups.push(
          (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)).toString(16),
          (((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0)).toString(16),
        );
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(item)) {
        return null;
      }
      groups.push(item.replace(/^0+(?=.)/, ""));
    }
    return groups;
  };

  const head = toGroups(halves[0] ?? "");
  const tail = halves.length === 2 ? toGroups(halves[1] ?? "") : [];
  if (head === null || tail === null) {
    return null;
  }
  if (halves.length === 1) {
    return head.length === 8 ? head : null;
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 1) {
    return null;
  }
  return [...head, ...Array.from({ length: missing }, () => "0"), ...tail];
}

/** Forme canonique d'une IPv6 : minuscules, zéros de tête supprimés, plus longue plage compressée. */
function compressIpv6(groups: readonly string[]): string {
  if (groups.length !== 8) {
    return groups.join(":");
  }
  let bestStart = -1;
  let bestLength = 0;
  let start = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    const isZero = index < groups.length && Number.parseInt(groups[index] ?? "1", 16) === 0;
    if (isZero) {
      if (start === -1) {
        start = index;
      }
      continue;
    }
    if (start !== -1) {
      const length = index - start;
      if (length > bestLength) {
        bestStart = start;
        bestLength = length;
      }
      start = -1;
    }
  }
  if (bestLength < 2) {
    return groups.join(":");
  }
  const head = groups.slice(0, bestStart).join(":");
  const tail = groups.slice(bestStart + bestLength).join(":");
  return `${head}::${tail}`;
}

/** Analyse une IP ou un CIDR (IPv4/IPv6). Retourne la forme canonique, ou `null`. */
function parseIp(raw: string): ParsedIp | null {
  const text = raw.trim();
  if (text === "") {
    return null;
  }
  const address = text.includes("/") ? (text.split("/")[0] ?? "") : text;
  if (isIpv4(address)) {
    return { version: 4, canonical: address.split(".").map((part) => String(Number(part))).join(".") };
  }
  const groups = expandIpv6(address);
  if (groups === null) {
    return null;
  }
  return { version: 6, canonical: compressIpv6(groups) };
}

/** Options de `pseudonymizeIp()`. */
export interface PseudonymizeIpOptions {
  /**
   * Conserve le réseau (`/24` en IPv4, `/64` en IPv6) à côté du pseudonyme, ce qui permet des
   * analyses par sous-réseau — à n'activer que si c'est réellement nécessaire.
   */
  keepPrefix?: boolean | undefined;
  /** Préfixe lisible des pseudonymes (défaut `ip-`). */
  prefix?: string | undefined;
}

/**
 * Pseudonymise une adresse IP de façon **déterministe** (HMAC-SHA256 + sel).
 *
 * Pourquoi : une adresse IP est une donnée à caractère personnel (RGPD, art. 4.1). Le pseudonyme
 * permet de corréler les événements d'une même source sans jamais stocker l'IP en clair. Le sel
 * est un secret d'organisation : sans lui, un attaquant disposant du pseudonyme peut tester des IP
 * candidates (attaque par dictionnaire, l'espace IPv4 étant petit).
 *
 * @returns `ip-<32 hex>` ou `ip-<32 hex>@<réseau>` si `keepPrefix` est actif.
 * @throws ValidationError si l'entrée n'est pas une IP/CIDR valide ou si le sel est vide.
 */
export function pseudonymizeIp(
  ip: string,
  salt: string,
  options: PseudonymizeIpOptions = {},
): string {
  if (typeof salt !== "string" || salt === "") {
    throw new ValidationError(
      "pseudonymizeIp exige un sel non vide (secret d'organisation) : sans sel, la " +
        "pseudonymisation est réversible par force brute",
      { code: "validation_error" },
    );
  }
  if (typeof ip !== "string" || ip.trim() === "") {
    throw new ValidationError("pseudonymizeIp : adresse IP vide", { code: "validation_error" });
  }
  const parsed = parseIp(ip);
  if (parsed === null) {
    throw new ValidationError(`pseudonymizeIp : « ${ip.trim()} » n'est pas une IP ni un CIDR valide`, {
      code: "validation_error",
      details: { value: ip.trim() },
    });
  }

  const keepPrefix = options.keepPrefix === true;
  const prefix = options.prefix ?? "ip-";
  const digest = hmacSha256Hex(salt, parsed.canonical);
  const token = `${prefix}${digest.slice(0, 32)}`;

  let network: string | null = null;
  if (keepPrefix) {
    if (parsed.version === 4) {
      const octets = parsed.canonical.split(".");
      octets[3] = "0";
      network = `${octets.join(".")}/24`;
    } else {
      const groups = expandIpv6(parsed.canonical) ?? [];
      network = `${groups.slice(0, 4).join(":")}::/64`;
    }
  }
  return network === null ? token : `${token}@${network}`;
}

/** Options de `pseudonymizeIpFields()`. */
export interface PseudonymizeIpFieldsOptions extends PseudonymizeIpOptions {
  /** Champs traités (défaut : `DEFAULT_IP_FIELDS`). */
  fields?: readonly string[] | undefined;
}

function pseudonymizeValue(
  value: unknown,
  salt: string,
  wanted: ReadonlySet<string>,
  options: PseudonymizeIpOptions,
  depth: number,
): unknown {
  if (depth > 32) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => pseudonymizeValue(item, salt, wanted, options, depth + 1));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (wanted.has(normalizeKey(key)) && typeof item === "string" && item.trim() !== "" && item.trim() !== "-") {
      try {
        out[key] = pseudonymizeIp(item, salt, options);
        continue;
      } catch {
        out[key] = item; // valeur non IP : laissée intacte (le helper ne fait jamais échouer une ingestion)
        continue;
      }
    }
    out[key] = pseudonymizeValue(item, salt, wanted, options, depth + 1);
  }
  return out;
}

/**
 * Pseudonymise récursivement les champs d'adresse IP d'une structure.
 *
 * Les valeurs qui ne sont pas des IP valides sont laissées intactes (`"unknown"`, `"-"`) : le
 * helper ne doit jamais faire échouer une ingestion.
 */
export function pseudonymizeIpFields<T>(
  data: T,
  salt: string,
  options: PseudonymizeIpFieldsOptions = {},
): T {
  if (typeof salt !== "string" || salt === "") {
    return data;
  }
  const fields = options.fields ?? DEFAULT_IP_FIELDS;
  const wanted = new Set(fields.map((field) => normalizeKey(field)));
  return pseudonymizeValue(data, salt, wanted, options, 0) as T;
}

/* ====================================================================================== */
/* Normalisation des journaux HTTP                                                         */
/* ====================================================================================== */

/** Champs bruts extraits d'une ligne de journal HTTP (Nginx/Apache). */
export interface NginxLogFields {
  src_ip: string | null;
  vhost: string | null;
  ident: string | null;
  user: string | null;
  ts: string | null;
  method: string | null;
  path: string | null;
  query: string | null;
  protocol: string | null;
  status: number | null;
  bytes: number | null;
  referer: string | null;
  user_agent: string | null;
}

/** Journal « combined » Nginx/Apache : hôte virtuel optionnel, puis la ligne standard. */
const COMBINED_RE =
  /^(?:(?<vhost>[A-Za-z0-9_.\-]+(?::\d+)?)\s+)?(?<srcIp>[0-9A-Fa-f:.]+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<ts>[^\]]+)\]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+(?<bytes>\d+|-)(?:\s+"(?<referer>[^"]*)"\s+"(?<userAgent>[^"]*)")?(?:\s+(?<extra>\S+))?\s*$/;

const REQUEST_RE = /^(?<method>[A-Za-z]+)\s+(?<target>\S+)(?:\s+(?<protocol>HTTP\/[\d.]+))?$/;

function nullIfDash(value: string | undefined): string | null {
  if (value === undefined || value === "" || value === "-") {
    return null;
  }
  return value;
}

/**
 * Analyse une ligne de journal Nginx/Apache (formats `combined` et `common`).
 *
 * @returns les champs bruts, ou `null` si la ligne n'est pas reconnue.
 */
export function parseHttpLogLine(line: string): NginxLogFields | null {
  const match = COMBINED_RE.exec(line.trim());
  if (match === null) {
    return null;
  }
  const groups = match.groups ?? {};
  const request = groups["request"] ?? "";
  const parsed = request !== "" && request !== "-" ? REQUEST_RE.exec(request) : null;
  const target = parsed?.groups?.["target"] ?? null;

  let path: string | null = target;
  let query: string | null = null;
  if (target !== null && target.includes("?")) {
    const index = target.indexOf("?");
    path = target.slice(0, index);
    query = target.slice(index + 1);
  }

  const rawBytes = groups["bytes"];
  const bytes = rawBytes === undefined || rawBytes === "-" ? null : Number(rawBytes);
  const rawStatus = groups["status"];

  return {
    src_ip: groups["srcIp"] ?? null,
    vhost: nullIfDash(groups["vhost"]),
    ident: nullIfDash(groups["ident"]),
    user: nullIfDash(groups["user"]),
    ts: groups["ts"] ?? null,
    method: parsed?.groups?.["method"] ?? null,
    path,
    query,
    protocol: parsed?.groups?.["protocol"] ?? null,
    status: rawStatus === undefined ? null : Number(rawStatus),
    bytes: bytes === null || Number.isNaN(bytes) ? null : bytes,
    referer: nullIfDash(groups["referer"]),
    user_agent: nullIfDash(groups["userAgent"]),
  };
}

/** Alias courants rencontrés dans les journaux structurés (JSON) → champs canoniques. */
const FIELD_ALIASES: Readonly<Record<string, readonly string[]>> = {
  src_ip: ["src_ip", "source_ip", "client_ip", "remote_addr", "remote_ip", "real_ip", "ip"],
  host: ["host", "server_name", "vhost", "http_host", "hostname"],
  ts: ["ts", "time", "timestamp", "@timestamp", "time_local", "datetime"],
  method: ["method", "http_method", "request_method", "verb"],
  path: ["path", "uri", "request_uri", "url_path", "endpoint"],
  query: ["query", "query_string", "args", "search"],
  protocol: ["protocol", "server_protocol", "http_version"],
  status: ["status", "status_code", "response_status", "code"],
  bytes: ["bytes", "body_bytes_sent", "bytes_sent", "size", "response_size"],
  referer: ["referer", "referrer", "http_referer"],
  user_agent: ["user_agent", "http_user_agent", "agent", "ua"],
  message: ["message", "msg", "log", "event"],
  user: ["user", "remote_user", "username", "auth_user"],
  duration_ms: ["duration_ms", "request_time", "response_time", "elapsed_ms"],
};

function pick(record: Record<string, unknown>, field: string): unknown {
  for (const alias of FIELD_ALIASES[field] ?? [field]) {
    const value = record[alias];
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return undefined;
}

/** Convertit une valeur quelconque en scalaire JSON (les structures sont sérialisées). */
function asScalar(value: unknown): Scalar {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/** Indice de sévérité déduit du code HTTP de réponse. */
export function severityHintForStatus(status: number | null): SeverityHint {
  if (status === null) {
    return null;
  }
  if (status >= 500 && status < 600) {
    return "medium";
  }
  if (status >= 400 && status < 500) {
    return "low";
  }
  if (status >= 200 && status < 400) {
    return "info";
  }
  return null;
}

/** Options de `normalizeEvent()` / `normalizeNginxLine()`. */
export interface NormalizeOptions {
  /** Tenant de rattachement — **obligatoire** (le contrat l'impose sur tout objet). */
  tenantId: string;
  /** Nom du collecteur (`prod-edge`…). */
  sourceName?: string | undefined;
  /** Type de source (`log_tail`, `web_probe`, `syslog`…). */
  sourceType?: string | undefined;
  /** Hôte émetteur. */
  sourceHost?: string | undefined;
  /** Force le `kind` (sinon déduit : `http.request` si méthode/chemin/statut, `log.line` sinon). */
  kind?: EventKind | undefined;
  /** Force l'`event_id` (sinon UUID v4 généré). */
  eventId?: string | undefined;
  /** Force l'horodatage (sinon celui de la ligne, sinon maintenant). */
  ts?: string | number | Date | undefined;
  /** Force `severity_hint` (sinon déduit du statut HTTP). */
  severityHint?: SeverityHint | undefined;
  /** Étiquettes supplémentaires (aplaties dans `labels`). */
  extraLabels?: Readonly<Record<string, unknown>> | undefined;
  /** Champs supplémentaires ajoutés au `payload`. */
  extraPayload?: JsonObject | undefined;
  /**
   * Sel de pseudonymisation des IP. **Obligation RGPD** : sans lui, l'IP source reste en clair
   * dans `labels.src_ip` et dans le `payload`.
   */
  ipSalt?: string | undefined;
  /** Champs IP à pseudonymiser (défaut : `DEFAULT_IP_FIELDS`). */
  ipFields?: readonly string[] | undefined;
  /** Masque les secrets contenus dans la ligne (défaut `true`). */
  redact?: boolean | undefined;
  /** Référence vers la donnée brute si le `payload` a été tronqué. */
  rawRef?: string | undefined;
  /** Plafond du `payload` sérialisé (défaut 32 Kio, contrat §3.1). */
  maxPayloadBytes?: number | undefined;
}

/** Taille sérialisée d'une valeur, en octets UTF-8. */
function serializedSize(value: unknown): number {
  try {
    return new TextEncoder().encode(JSON.stringify(value) ?? "").length;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

/** Options de `truncatePayload()`. */
export interface TruncatePayloadOptions {
  maxBytes?: number | undefined;
  /** Clés préservées en priorité lors du retrait (`status`, `method`, `path`). */
  keepKeys?: readonly string[] | undefined;
}

/**
 * Ramène un `payload` sous `maxBytes` et indique si une troncature a eu lieu (contrat §3.1).
 *
 * Stratégie : troncature des chaînes les plus longues, puis retrait des clés les plus
 * volumineuses (en préservant `keepKeys`), puis marqueur de repli si nécessaire.
 */
export function truncatePayload(
  payload: JsonObject,
  options: TruncatePayloadOptions = {},
): { payload: JsonObject; truncated: boolean } {
  const maxBytes = options.maxBytes ?? MAX_PAYLOAD_BYTES;
  const keepKeys = options.keepKeys ?? ["status", "method", "path"];
  const result: JsonObject = { ...payload };
  if (serializedSize(result) <= maxBytes) {
    return { payload: result, truncated: false };
  }

  for (let round = 0; round < 64 && serializedSize(result) > maxBytes; round += 1) {
    let longestKey: string | null = null;
    let longestLength = 256;
    for (const [key, value] of Object.entries(result)) {
      if (typeof value === "string" && value.length > longestLength) {
        longestKey = key;
        longestLength = value.length;
      }
    }
    if (longestKey === null) {
      break;
    }
    const current = result[longestKey];
    result[longestKey] = `${String(current).slice(0, 256)}…[tronqué]`;
  }

  for (let round = 0; round < 64 && serializedSize(result) > maxBytes; round += 1) {
    let biggestKey: string | null = null;
    let biggestSize = -1;
    for (const [key, value] of Object.entries(result)) {
      if (keepKeys.includes(key)) {
        continue;
      }
      const size = serializedSize({ [key]: value });
      if (size > biggestSize) {
        biggestKey = key;
        biggestSize = size;
      }
    }
    if (biggestKey === null) {
      break;
    }
    delete result[biggestKey];
  }

  if (serializedSize(result) > maxBytes) {
    return {
      payload: { _truncated: true, _original_keys: Object.keys(payload).sort().join(",") },
      truncated: true,
    };
  }
  return { payload: result, truncated: true };
}

/**
 * Construit un `Event` conforme au contrat §3.1 depuis une ligne de journal ou un objet.
 *
 * `source` accepte :
 * * une ligne de journal Nginx/Apache (`combined` ou `common`) ;
 * * une ligne JSON structurée ;
 * * un objet applicatif (le SDK y cherche les alias usuels : `client_ip`, `request_uri`,
 *   `status_code`, `@timestamp`…).
 *
 * Le résultat respecte : `kind` énuméré, `labels` plat à valeurs scalaires, `payload` ≤ 32 Kio
 * (au-delà : troncature et `raw_ref` renseigné).
 *
 * @throws ValidationError si `tenantId` est vide ou si le `kind` demandé n'est pas énuméré.
 */
export function normalizeEvent(
  source: string | Readonly<Record<string, unknown>>,
  options: NormalizeOptions,
): Event {
  const tenantId = options.tenantId;
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new ValidationError(
      "normalizeEvent exige un tenantId (le contrat l'impose sur tout objet)",
      { code: "validation_error" },
    );
  }

  const extraPayload: JsonObject = {};
  let record: Record<string, unknown> = {};

  if (typeof source === "string") {
    const text = source.trim();
    if (text.startsWith("{")) {
      try {
        const parsed: unknown = JSON.parse(text);
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
          record = parsed as Record<string, unknown>;
        }
      } catch {
        record = {};
      }
    }
    if (Object.keys(record).length === 0) {
      const httpRecord = parseHttpLogLine(text);
      if (httpRecord !== null) {
        record = { ...httpRecord };
      } else {
        extraPayload["message"] = text;
      }
    }
  } else if (typeof source === "object" && source !== null && !Array.isArray(source)) {
    record = { ...source };
  } else {
    throw new ValidationError("normalizeEvent attend une chaîne ou un objet", {
      code: "validation_error",
      details: { received: typeof source },
    });
  }

  const rawStatus = pick(record, "status");
  const statusValue = rawStatus === undefined ? null : Number(rawStatus);
  const status = statusValue !== null && Number.isFinite(statusValue) ? statusValue : null;

  const method = pick(record, "method");
  const path = pick(record, "path");
  const query = pick(record, "query");
  const protocol = pick(record, "protocol");
  const host = options.sourceHost ?? pick(record, "host");
  const userAgent = pick(record, "user_agent");
  const referer = pick(record, "referer");
  const rawBytes = pick(record, "bytes");
  const user = pick(record, "user");
  const message = pick(record, "message");
  const duration = pick(record, "duration_ms");
  const requestTs = options.ts ?? pick(record, "ts");

  let fallbackMessage = message;
  if (
    method === undefined &&
    path === undefined &&
    fallbackMessage === undefined &&
    Object.keys(extraPayload).length === 0
  ) {
    // Aucun champ exploitable : on conserve au moins la ligne brute comme message.
    fallbackMessage = typeof source === "string" ? source : JSON.stringify(source);
  }

  const resolvedKind: EventKind =
    options.kind ??
    (method !== undefined || path !== undefined || status !== null ? "http.request" : "log.line");
  if (!EVENT_KINDS.includes(resolvedKind)) {
    throw new ValidationError(
      `kind invalide : « ${String(resolvedKind)} » (attendu : ${EVENT_KINDS.join(", ")})`,
      { code: "validation_error" },
    );
  }

  const labels: Labels = {};
  if (method !== undefined) {
    labels["method"] = asScalar(method);
  }
  if (path !== undefined) {
    labels["path"] = asScalar(path);
  }
  if (protocol !== undefined) {
    labels["protocol"] = asScalar(protocol);
  }
  if (query !== undefined) {
    labels["query"] = asScalar(query);
  }
  if (host !== undefined) {
    labels["host"] = asScalar(host);
  }
  if (user !== undefined) {
    labels["user"] = asScalar(user);
  }
  const srcIp = pick(record, "src_ip");
  if (srcIp !== undefined) {
    labels["src_ip"] = asScalar(srcIp);
  }
  for (const [key, value] of Object.entries(options.extraLabels ?? {})) {
    labels[key] = asScalar(value);
  }

  const payload: JsonObject = {};
  if (status !== null) {
    payload["status"] = status;
  }
  if (rawBytes !== undefined) {
    const numericBytes = Number(rawBytes);
    payload["bytes"] = Number.isFinite(numericBytes) ? numericBytes : asScalar(rawBytes);
  }
  if (userAgent !== undefined) {
    payload["user_agent"] = asScalar(userAgent);
  }
  if (referer !== undefined) {
    payload["referer"] = asScalar(referer);
  }
  if (fallbackMessage !== undefined) {
    payload["message"] = asScalar(fallbackMessage);
  }
  if (duration !== undefined) {
    payload["duration_ms"] = asScalar(duration);
  }
  for (const [key, value] of Object.entries(extraPayload)) {
    payload[key] = value;
  }
  for (const [key, value] of Object.entries(options.extraPayload ?? {})) {
    payload[key] = value;
  }

  const maxPayloadBytes = options.maxPayloadBytes ?? MAX_PAYLOAD_BYTES;
  const truncated = truncatePayload(payload, { maxBytes: maxPayloadBytes });
  let rawRef = options.rawRef ?? null;
  if (truncated.truncated && rawRef === null) {
    rawRef = `truncated:payload>${maxPayloadBytes}`;
  }

  const parsedTs = parseTimestamp(requestTs);
  const iso = parsedTs === null ? nowIso() : parsedTs.toISOString();
  if (requestTs !== undefined && parsedTs === null) {
    truncated.payload["raw_ts"] = asScalar(requestTs);
  }

  const hostValue = host === undefined ? (options.sourceName ?? "unknown") : asScalar(host);

  let event: Event = {
    event_id: options.eventId ?? newEventId(),
    schema_version: "1",
    tenant_id: tenantId,
    ts: iso,
    kind: resolvedKind,
    source: {
      type: options.sourceType ?? "log_tail",
      name: options.sourceName ?? "thot-secure-sdk",
      host: String(hostValue),
    },
    severity_hint:
      options.severityHint === undefined ? severityHintForStatus(status) : options.severityHint,
    labels,
    payload: truncated.payload,
    raw_ref: rawRef,
  };

  if (options.redact !== false) {
    event = redactSecrets(event);
  }
  if (options.ipSalt !== undefined && options.ipSalt !== "") {
    event = pseudonymizeIpFields(event, options.ipSalt, {
      fields: options.ipFields ?? DEFAULT_IP_FIELDS,
    });
  }
  return event;
}

/**
 * Transforme une ligne de journal Nginx/Apache (« combined » ou « common ») en `Event`.
 *
 * Raccourci documenté de `normalizeEvent()` : accepte aussi une ligne JSON, ce qui permet de
 * brancher la même fonction sur `access.log` et sur un flux JSONL hétérogène.
 */
export function normalizeNginxLine(line: string, options: NormalizeOptions): Event {
  if (typeof line !== "string" || line.trim() === "") {
    throw new ValidationError("normalizeNginxLine : ligne vide", { code: "validation_error" });
  }
  return normalizeEvent(line, options);
}

/* ====================================================================================== */
/* JSONL et découpage en lots                                                              */
/* ====================================================================================== */

/** Options de `parseJsonl()`. */
export interface ParseJsonlOptions {
  /** `true` : les lignes invalides sont ignorées (flux vivant dont la dernière ligne est partielle). */
  skipInvalid?: boolean | undefined;
  /** Numéro de la première ligne (utilisé dans les messages d'erreur). */
  startLine?: number | undefined;
}

/**
 * Analyse un texte JSONL (une ligne = un objet JSON).
 *
 * Les lignes vides sont ignorées. Par défaut, une ligne invalide lève une erreur indiquant son
 * numéro ; `skipInvalid: true` l'ignore silencieusement.
 */
export function parseJsonl(text: string, options: ParseJsonlOptions = {}): JsonValue[] {
  const out: JsonValue[] = [];
  const startLine = options.startLine ?? 1;
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? "").trim();
    if (line === "") {
      continue;
    }
    try {
      out.push(JSON.parse(line) as JsonValue);
    } catch (error) {
      if (options.skipInvalid === true) {
        continue;
      }
      throw new ValidationError(
        `JSONL invalide à la ligne ${startLine + index} : ${error instanceof Error ? error.message : "erreur inconnue"}`,
        { code: "validation_error", details: { line: startLine + index } },
      );
    }
  }
  return out;
}

/** Convertit un itérable (sync ou async) en itérable asynchrone. */
function toAsyncIterable<T>(items: Iterable<T> | AsyncIterable<T>): AsyncIterable<T> {
  const candidate = items as AsyncIterable<T>;
  if (typeof candidate[Symbol.asyncIterator] === "function") {
    return candidate;
  }
  const sync = items as Iterable<T>;
  return (async function* iterate(): AsyncGenerator<T, void, undefined> {
    yield* sync;
  })();
}

/**
 * Découpe un itérable en lots de `size` éléments (≤ 500 par défaut, contrat §4.3).
 *
 * Accepte un itérable synchrone **ou** asynchrone : c'est ce qui permet à `ingest_events()` de
 * consommer un flux sans le charger entièrement en mémoire.
 */
export async function* chunked<T>(
  items: Iterable<T> | AsyncIterable<T>,
  size: number = MAX_BATCH_SIZE,
): AsyncGenerator<T[], void, undefined> {
  if (!Number.isInteger(size) || size < 1) {
    throw new ValidationError("chunked : size doit être un entier ≥ 1", { code: "validation_error" });
  }
  let batch: T[] = [];
  for await (const item of toAsyncIterable(items)) {
    batch.push(item);
    if (batch.length >= size) {
      yield batch;
      batch = [];
    }
  }
  if (batch.length > 0) {
    yield batch;
  }
}
