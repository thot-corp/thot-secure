# SDK TypeScript — Thot Secure (nom technique `thotsecure`) v0.1.0

SDK officiel pour l'API REST **Thot Secure** (SOAR/CSPM **défensif**), conforme au contrat
d'interface [`docs/architecture/api-contract.md`](../../docs/architecture/api-contract.md) §3 et §4.

* **Zéro dépendance runtime** : `fetch`, `AbortController`, `Web Crypto` et `WebSocket` sont ceux
  de la plateforme (Node ≥ 20, navigateurs récents). Aucun paquet tiers n'est requis, ni à
  l'exécution ni au bundling (`tsup`, `platform: "neutral"`).
* **Couverture complète du §4** : santé (§4.1), tenants et clés (§4.2), événements (§4.3),
  findings (§4.4), règles/politiques/playbooks (§4.5), actions SOAR (§4.6), audit (§4.7),
  stats/collecteurs/flux temps réel (§4.8).
* **Aucune capacité offensive** : le SDK ne fait que parler à l'API (pas de scan, pas de force
  brute, pas d'exploitation). `run_collector()` ne cible que les cibles déclarées du tenant.
* **Sûreté par défaut** : `dry_run` reste `true` (le SDK ne le lève jamais tout seul), `fetch`
  est injectable pour les tests hors ligne, et aucun message d'erreur ne contient la clé API.

## Installation

```bash
npm install @thotsecure/sdk
# ou
pnpm add @thotsecure/sdk
yarn add @thotsecure/sdk
```

Le paquet publie de l'**ESM** (`dist/index.js`), du **CJS** (`dist/index.cjs`) et des déclarations
(`dist/index.d.ts`). Node ≥ 20 est requis (WebSocket natif : Node ≥ 22).

## Configuration

Variables d'environnement lues par le client (dans l'ordre) :

| Variable | Rôle |
|---|---|
| `THOT_SECURE_URL`, `THOT_URL` | racine du service (défaut `http://127.0.0.1:8080`) |
| `THOT_SECURE_API_KEY`, `THOT_API_KEY` | clé API `ao_…` |
| `THOT_SECURE_TENANT_ID`, `THOT_TENANT_ID` | tenant utilisé pour les routes `{id}` et le flux |

Les orthographes héritées `THOT_*` restent acceptées en repli (`readEnv()` les essaie
automatiquement), le temps du renommage.

```ts
import { ThotSecureClient } from "@thotsecure/sdk";

const client = new ThotSecureClient({
  baseUrl: process.env.THOT_SECURE_URL,
  apiKey: process.env.THOT_SECURE_API_KEY,
  tenantId: "acme",
  timeoutMs: 30_000, // délai par requête
  maxRetries: 3, // tentatives supplémentaires (GET/DELETE, et POST avec clé d'idempotence)
});

console.log(await client.whoami());
```

## Exemples par famille de routes

### §4.1 Santé, méta, observabilité

```ts
await client.healthz();          // GET /healthz
await client.readyz();           // GET /readyz — 503 ⇒ { status: "unavailable" } sans exception
await client.readyz({ raiseOnError: true }); // … ou lève ServerError
await client.version();          // GET /version
await client.metrics();          // GET /metrics (texte Prometheus)
await client.whoami();           // GET /api/v1/auth/whoami
```

### §4.2 Tenants et clés

```ts
await client.list_tenants();
await client.create_tenant({ tenant_id: "acme", name: "ACME SAS", mode: "supervised" });

// ⚠️ Activer `auto` ou `dry_run: false` change le niveau d'autonomie : décision de sécurité
// volontaire, limitée et journalisée (contrat §6).
await client.update_tenant({ mode: "auto", dry_run: false }, "acme");

const created = await client.create_key({ role: "responder", label: "ci" }, "acme");
console.log(created.api_key); // affichée UNE SEULE FOIS — ne la journalisez jamais
await client.list_keys("acme");
await client.revoke_key(created.key_id);
```

### §4.3 Événements

```ts
import { normalizeNginxLine, pseudonymizeIp } from "@thotsecure/sdk";

// Une ligne de journal Nginx « combined » → Event conforme au §3.1.
const event = normalizeNginxLine(
  '203.0.113.9 - - [14/Feb/2026:10:00:00 +0000] "POST /login HTTP/1.1" 403 512 "-" "curl/8.5"',
  {
    tenantId: "acme",
    sourceName: "prod-edge",
    sourceType: "log_tail",
    ipSalt: process.env.THOT_PSEUDONYMIZATION_SALT, // RGPD : pseudonymise labels.src_ip
  },
);

await client.ingest_event(event);

// Lot : découpage automatique au-delà de 500 événements (contrat §4.3).
await client.ingest_events(events, {
  chunkSize: 500,
  onBatch: async (result, index) => {
    // Contre-pression : ne produisez le lot suivant qu'ici.
    console.log(`lot ${index} accepté : ${result.accepted}`);
  },
});

await client.list_events({ kind: "http.request", since: "2026-02-14T00:00:00Z", limit: 100 });
await client.get_event("e6f0f0c4-4f0a-4a4f-9c9a-2b0f1f6b7a11");
for await (const item of client.iter_events({ q: "union select" })) {
  console.log(item.event_id);
}
```

### §4.4 Findings

```ts
const page = await client.list_findings({ status: "open", severity: "high", min_risk: 70, sort: "risk_score" });
const finding = await client.get_finding(page.items[0]!.finding_id); // + actions liées

await client.ack_finding(finding.finding_id, { comment: "revue en cours" });
await client.close_finding(finding.finding_id, { resolution: "true_positive", comment: "corrigé" });
await client.suppress_finding(finding.finding_id, { duration_seconds: 86_400, reason: "FP connu" });

// Rapport produit par le serveur (md | html | json | sarif)
const sarif = await client.get_report(finding.finding_id, { format: "sarif" });
```

### §4.5 Règles, politiques, playbooks

```ts
await client.list_rules();
await client.get_rule("AO-WEB-001");                  // + YAML source
await client.validate_rule("id: AO-TEST-1\n");          // YAML ou objet JSON
await client.reload_rules();                            // admin:rules
await client.list_policies();
await client.reload_policies();                         // admin:policies
await client.list_playbooks();
```

### §4.6 Actions SOAR

```ts
// Planification : aucun effet de bord, `dry_run` par défaut.
const action = await client.plan_action({
  finding_id: finding.finding_id,
  playbook: "block-source-ip",
  params: { target: "203.0.113.9", duration_seconds: 3600 },
});

await client.approve_action(action.action_id, { comment: "validé par astreinte" });
// `execute` refuse (409) une action encore `pending_approval` ; fournissez une clé
// d'idempotence pour rendre l'appel réessayable sans risque de double exécution.
await client.execute_action(action.action_id, {
  idempotencyKey: `${action.tenant_id}:${action.playbook}:203.0.113.9:1739527200`,
});
await client.rollback_action(action.action_id, { reason: "faux positif" });

await client.list_actions({ status: "pending_approval", limit: 50 });
```

### §4.7 Audit

```ts
await client.list_audit({ action: "action.execute", limit: 50 });
const verification = await client.verify_audit(); // { valid, records, broken_at }
if (!verification.valid) {
  throw new Error(`chaîne d'audit cassée à la séquence ${verification.broken_at}`);
}
const cef = await client.export_audit({ format: "cef", since: "2026-02-01T00:00:00Z" });
```

### §4.8 Stats, collecteurs, flux temps réel

```ts
await client.stats_overview();
await client.list_collectors();
await client.run_collector("http_probe"); // cibles déclarées du tenant uniquement

// Flux WebSocket : reconnexion (backoff ≤ 30 s + jitter), heartbeat, filtrage, arrêt propre.
const controller = new AbortController();
for await (const frame of client.stream({
  types: ["finding", "action"],
  signal: controller.signal,
  onReconnect: (info) => console.warn(`reconnexion ${info.attempt} dans ${info.delayMs} ms`),
})) {
  console.log(frame.type, frame.data);
}
controller.abort(); // ou client.close()

console.log(client.ws_url()); // ⚠️ contient la clé API : utilisez redactUrl() pour tracer
```

## Helpers d'intégration

```ts
import {
  normalizeNginxLine,
  normalizeEvent,
  parseHttpLogLine,
  parseJsonl,
  redactSecrets,
  pseudonymizeIp,
  pseudonymizeIpFields,
  parseTimestamp,
  truncatePayload,
  chunked,
  newEventId,
  nowIso,
  readEnv,
} from "@thotsecure/sdk";

// Journal → Event (§3.1)
normalizeEvent({ client_ip: "203.0.113.9", request_uri: "/login", status: 403 }, { tenantId: "acme" });

// Masquage avant journalisation : le motif le plus spécifique est traité en premier
// (JWT → « Bearer … » → en-tête Cookie → clés `ao_…` → `token=…` → identifiants d'URL).
redactSecrets({ authorization: "Bearer ao_live_abcdef123456", headers: { Cookie: "session=abc" } });

// RGPD : une IP est une donnée personnelle → pseudonymisation HMAC-SHA256 déterministe.
pseudonymizeIp("203.0.113.9", process.env.THOT_PSEUDONYMIZATION_SALT!); // "ip-<32 hex>"

// JSONL tolérant (flux vivant dont la dernière ligne est partielle)
parseJsonl('{"a":1}\n\n{"b":2}', { skipInvalid: true });
```

## Sécurité

> **⚠️ N'embarquez JAMAIS une clé API dans un front public.**
> Une clé `ao_…` livrée dans un bundle JavaScript est lisible par n'importe qui (onglet réseau,
> source map, cache CDN). Elle donne accès aux findings, à l'audit et — selon son rôle — au
> déclenchement d'actions de remédiation. Le SDK TypeScript fonctionne dans un navigateur, mais
> uniquement avec un **jeton à courte durée de vie** émis par **votre** service :
>
> 1. le navigateur parle à votre backend (session utilisateur, cookie `HttpOnly`) ;
> 2. votre backend détient la clé `ao_…` (variable d'environnement, coffre-fort) et relaie les
>    appels ;
> 3. le navigateur ne reçoit qu'un jeton limité en portée et en durée, jamais la clé.
>
> Pour le flux temps réel, le WebSocket porte la clé en paramètre de requête (les navigateurs ne
> peuvent pas poser d'en-tête sur `ws://`) : faites passer ce flux par votre backend, ou
> n'utilisez `client.stream()` que côté serveur.

* **Aucun secret dans les erreurs ni dans les logs** : `redactUrl()` masque `api_key`, `token`… et
  `client.toString()` n'affiche jamais la clé.
* **Aucun secret en dur** dans le SDK : tout passe par `readEnv()` / les options du constructeur.
* **TLS vérifié par défaut** : le SDK ne propose **aucune** option de désactivation de la
  vérification TLS. Si vous devez tout de même accepter un certificat auto-signé (laboratoire
  isolé), faites-le en amont avec un `fetch` personnalisé ou un `NODE_EXTRA_CA_CERTS` — c'est
  explicite, visible dans votre code, et cela ne désactive pas TLS pour le reste de l'application.
* **`dry_run` reste `true`** tant que vous ne le levez pas explicitement : `plan_action()` est une
  simulation sans effet de bord.
* **Reprise prudente** : seuls `429/502/503/504` et les erreurs réseau sont réessayés, et jamais un
  `POST`/`PATCH` sans clé d'idempotence.

## Limites connues

* **WebSocket** : l'API WebSocket des navigateurs n'expose pas l'envoi de `ping` (RFC 6455 opcode
  0x9). La vivacité est donc détectée **passivement** (`staleTimeoutMs`, 90 s par défaut : aucune
  trame reçue ⇒ la connexion est considérée morte et rouverte). Le SDK Python, qui pilote la socket
  lui-même, peut en plus émettre un ping applicatif.
* **Pas de WebSocket natif avant Node 22** : passez `webSocketFactory` (par exemple
  `(url) => new WebSocket(url)` du paquet `ws`) — c'est une dépendance de **votre** application, pas
  du SDK.
* **Fragmentation** : le décodage repose entièrement sur l'implémentation `WebSocket` de la
  plateforme (navigateur/Node), qui assemble déjà les messages fragmentés ; le SDK ne voit que des
  messages complets.
* **`readyz()` ne lève pas** sur `503` par défaut (comportement attendu par une sonde
  d'orchestrateur) : utilisez `{ raiseOnError: true }` si vous voulez l'exception.
* **Hors périmètre** : console embarquée (§4.9), `GET /ui/*` et `GET /openapi.json` ne sont pas
  exposés — ce ne sont pas des routes d'API métier.

## Développement

```bash
npm install        # installe les outils de build/test (aucune dépendance runtime)
npm run typecheck  # tsc --noEmit (strict : exactOptionalPropertyTypes, noUncheckedIndexedAccess)
npm test           # vitest run — tests hors ligne, fetch simulé
npm run build      # tsup → dist/index.js + dist/index.cjs + dist/index.d.ts
```

## Licence

Apache-2.0 — projet Thot Secure (nom technique `thotsecure`).
