# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

While the version is below `1.0.0`, the project follows the pre-1.0 rule stated
in [`CONTRIBUTING.md`](CONTRIBUTING.md#6-versioning--semantic-versioning):
a breaking change to the frozen interface contract
(`docs/architecture/api-contract.md`) is released as a **minor** bump and is
listed under `### Changed` with a `BREAKING` prefix.

Categories used: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`. Dates are `YYYY-MM-DD`.

---

## [Unreleased]

### Added

- Nothing yet — this section collects changes for the next release.

### Changed

- Nothing yet.

### Deprecated

- Nothing yet.

### Removed

- Nothing yet.

### Fixed

- Nothing yet.

### Security

- Nothing yet.

---

## [0.1.0] - 2026-09-13

First public release: the Thot Secure MVP. A defensive, multi-tenant SOAR/CSPM
platform that ingests telemetry, detects with declarative rules, scores risk,
decides with policy-as-code, and applies **reversible** counter-measures that are
recorded in a tamper-evident audit chain.

Safe by default: `THOT_DRY_RUN=true` and `THOT_AUTONOMY=supervised`. Every
connector works in simulated mode before you have any credentials, so the platform
is safe to plug in and observe before it is allowed to act.

> The release date is fixed when the `v0.1.0` tag is cut. The version is published
> through the release workflow, which attaches a signed SBOM and a provenance
> attestation to the GitHub Release.

### Added

#### PostgreSQL / TimescaleDB persistence backend

SQLite remains the default because it needs no dependency and no service. What was
missing was a **credible production target**: `THOT_DB_URL=postgresql://…` now selects a
complete adapter instead of raising.

- **`src/thotsecure/storage/postgres.py`** — the full storage contract (51 methods), with
  the driver imported lazily (`psycopg` 3, falling back to `psycopg2`) so that
  `import thotsecure` still pulls in no database driver, and `pip install -e ".[postgres]"`
  is only needed when PostgreSQL is actually chosen.
- **One factory, `create_store(settings)`**, decides the backend from the URL. Every caller
  goes through it — service, CLI and tests — so a PostgreSQL deployment can no longer end up
  with a stray SQLite store in a corner.
- **A shared conformance suite** (`tests/test_storage_conformance.py`) runs the same
  assertions against either backend; CI replays it against a real TimescaleDB service
  container, **twice**: once with `psycopg2`, once with `psycopg` 3 (different batch paths).
- **`StoreProtocol`** (`src/thotsecure/storage/base.py`) makes the contract explicit, and the
  type annotations across the codebase now say `StoreProtocol` rather than the SQLite class —
  the previous annotations were simply wrong on PostgreSQL.
- **`pg_advisory_xact_lock` on the audit chain**: the lock is taken *before* reading the last
  link, then `nextval('audit_log_seq')`, then a single `INSERT`. `FOR UPDATE` was rejected
  and the reason is written down: it protects neither an empty log nor a new last link.
- **Hypertable, compression, continuous aggregate and native retention** DDL split into
  idempotent sections, each in its own transaction; retention falls back to bounded batched
  `DELETE` when TimescaleDB is absent.
- **`THOT_DB_SSLMODE`** (automatic by default: `prefer` outside production, `require` in
  production — never `disable`) and **`THOT_DB_POOL_MAX_SIZE`**.
- DSN password is **never logged**: `mask_dsn()` and `redact_dsn_in_text()` are applied to
  driver error messages too, since a psycopg error routinely echoes the connection string.
- **`thotsecure doctor` and `GET /readyz` are backend-aware**: they report the real store
  location (file path, or masked DSN for PostgreSQL) and a `backend` field, instead of a
  SQLite path that does not exist.

#### Native connectors: Cloudflare, AWS WAF, Slack, GitHub Issues

The five limitations listed in the 0.1.0 README included "only the local connectors have a
real effect". Four native drivers now close most of that gap — in the standard library only
(`urllib`, `hmac`, `hashlib`, `json`, `ssl`), with no vendor SDK to trust or to audit.

- **Cloudflare** — `block_ip` / `unblock_ip` through IP Access Rules, plus `rate_limit` /
  `remove_rate_limit` through the `http_ratelimit` ruleset phase. The created `rule_id` is the
  rollback token, so the rollback deletes the exact rule it created; a lost token degrades to
  a value lookup, and the difference is visible in the result.
- **AWS WAF** — `GetIPSet` → `UpdateIPSet` with a hand-written SigV4 signer, verified against
  **the official AWS test vectors** and against an independent reimplementation, including a
  `POST` with a body. `WAFOptimisticLockException` is retried **exactly once** with a fresh
  `LockToken`, then reported; a missing lock token prevents any write at all.
- **Slack** and **GitHub Issues** — structured notification with a correction message for
  rollback, and issue creation/closing. The Slack webhook URL **is** the secret and is never
  logged; the GitHub token appears in no result.
- **`DEFAULT_CONNECTORS` is unchanged: everything stays `simulation`** except the harmless
  local quarantine and local ticketing. Switching one logical name to a native driver is a
  per-tenant, per-name decision documented in `config/connectors.example.yaml`, with the
  minimal IAM policy and token scopes written out.
- **Deliberate omissions**, because a connector that "succeeds" without effect is worse than
  an absent one: no `notify` on Cloudflare (no ad-hoc message API) and no `rate_limit` on
  AWS WAF (it would mean editing a `RateBasedStatement`, whose reversibility cannot be
  guaranteed).
- **A shared HTTP client** centralises three guarantees: TLS verified by default (disabling
  it logs a warning), no exception ever escapes a connector, and no header, body or secret is
  ever logged. Plain HTTP to a remote host is refused.

#### Statistical anomaly detection — the complement to deterministic rules

A rule answers "is this pattern present?". It cannot answer "is this volume *abnormal
for this asset*", which is exactly the ground covered by slow and distributed attacks.
The detector ships **disabled by default** (`THOT_ANOMALY_ENABLED=false`): a statistical
detector with a bad threshold produces noise, and noise in security costs more than no
detection at all.

- **`src/thotsecure/detection/anomaly.py`** — EWMA + z-score baseline per entity, with a
  variance floor, a warm-up period, a minimum observed volume and a bounded entity map
  (a scanning attack must not turn the detector into a memory exhaustion vector).
- **Three signals**: `rate_anomaly` (volume deviation), `source_cardinality_anomaly`
  (spike in distinct source addresses — the signature of a distributed attack), and
  `new_source` (first observation of an entity for a tenant).
- **Every signal carries its own justification**: observed value, expected value and
  deviation in standard deviations, stored in the finding and readable without opening
  the code.
- **Signals are ordinary events** (`kind: anomaly`, `source.type: baseline`) travelling
  the same path as any other event: rules → scoring → decision → guard-rails → audit.
  There is no parallel route, so an anomaly cannot bypass a guard-rail.
- **Five shipped rules** (`rules/anomaly/`) grading severity by deviation band, plus two
  decision policies: `approval-volume-anomaly` (rate limiting proposed, human approval)
  and `notify-distributed-anomaly` (a ticket, never an automatic block — blocking one
  address does nothing against hundreds, and blocking a range risks cutting legitimate
  clients).
- **`anomaly.detected`** audit records, linking each signal to the event that produced it.
- Detection of an anomaly is never re-analysed as input, so a signal cannot cascade.
- An **injectable clock** makes interval rollover testable in milliseconds instead of
  requiring a 60-second test that nobody would run.
- Documented in [`docs/detection/anomaly.md`](docs/detection/anomaly.md), including the
  recommended enablement procedure (observe for 3–7 days, then tune).

#### Collectors and normalization

- **Defensive collector framework** (`src/thotsecure/collectors/`) with a common
  lifecycle, per-run state (last run, items, errors) exposed through
  `GET /api/v1/collectors`, and manual triggering on declared tenant targets
  through `POST /api/v1/collectors/{name}/run`.
- **`http_probe`** — passive inspection of an HTTP endpoint the tenant declares
  as owned: status, headers, TLS certificate details, redirects. It is not a
  scanner and it never sends attack payloads.
- **`log_tail`** — tailing of local log files with bounded read-ahead and
  restart-safe offsets.
- **`dependency_scan`** — inventory of installed dependencies and their versions
  for supply-chain findings.
- **`config_audit`** — collection of configuration state (TLS settings,
  exposed services, container hardening flags) for CSPM checks.
- **`syslog`** listener and a `generic` JSON-lines ingest path.
- **Event normalization** to the canonical `Event` schema of the interface
  contract (§3.1): enumerated `kind`, flat scalar `labels` used as the rule
  namespace, `severity_hint`, and a 32 KiB `payload` cap with truncation and
  `raw_ref` overflow handling.
- **Declared-scope enforcement** (`THOT_TARGETS_FILE`, `config/targets.yaml`):
  a collector refuses to touch a target the tenant has not declared, and there is
  no default target.

#### Event bus

- **Pluggable bus** (`src/thotsecure/bus/`) with three backends selected by
  `THOT_BUS`: `memory` (default, fan-out with per-subscriber queues),
  `sqlite` (durable, replayable, at-least-once) and `nats`
  (`THOT_NATS_URL`, using the embedded stdlib client).
- **Backpressure handling**: bounded subscriber queues with drop accounting
  rather than unbounded memory growth.

#### Detection engine

- **Declarative YAML rule engine** (`src/thotsecure/detection/`) implementing the
  rule schema of the interface contract (§5): `id`, `title`, `status`, `severity`,
  `confidence`, `enabled`, `tags`, `source_types`, `kinds`, `match`, `dedup`,
  `risk`, `false_positives`, `remediation`, `references`.
- **All documented operators**: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`,
  `not_in`, `contains`, `icontains`, `startswith`, `endswith`, `regex`, `exists`,
  `cidr`, `len_gt`, `len_lt`, evaluated against dotted paths into the event.
- **Boolean composition** with `match.all` (AND), `match.any` (OR) and
  `match.not` (exclusion).
- **Threshold aggregation** (`count`, `window_seconds`, `group_by`) with sliding
  windows, so a burst of low-severity events can produce one high-severity
  finding instead of hundreds of noise records.
- **Deduplication** on a configurable key with a TTL, collapsing repeats into a
  single finding with a `count` and an updated `last_seen`.
- **Sigma-lite compatibility**: translation of a documented subset of Sigma keys
  (`title`, `id`, `level`, `logsource`, `detection.selection|condition|filter`)
  with an explicit warning, so existing content can be reused.
- **Fail-soft rule loading**: an invalid rule is rejected with a structured
  diagnostic and never breaks the engine or the load of the other rules.
- **Regex timeouts** on rule evaluation, to contain catastrophic backtracking in
  contributed rules.
- **Rule hot reload** from `THOT_RULES_DIR` through
  `POST /api/v1/rules/reload`, returning loaded and rejected counts.
- **Rule library** shipped in `rules/`, organized by family
  (`AO-WEB-###`, `AO-CLOUD-###`, `AO-DEP-###`, `AO-TLS-###`, `AO-AUTH-###`,
  `AO-HOST-###`), each with `false_positives`, `remediation` and OWASP/MITRE
  references.

#### Risk scoring

- **Deterministic risk score** (`src/thotsecure/scoring/`) in the `0–100` range,
  monotonically increasing in severity, confidence and asset criticality, with
  the rule's `risk.base` as the starting point.
- **Per-asset criticality multipliers** and a documented, testable formula so
  that a score can be explained field by field.

#### Policy-as-code and decision

- **YAML policy engine** (`src/thotsecure/decision/`) implementing the contract
  schema (§6): `priority`, `when`, `then`, `rollback`, with AND semantics across
  `when` keys, list-as-OR, and comparators `gt`, `gte`, `lt`, `lte`, `in`,
  `not_in`, `matches` over `finding.*`, `tenant.*`, `environment`,
  `time.hour_utc`, `day.weekday`.
- **Decision outcomes** `auto`, `require_approval`, `notify_only` and `ignore`,
  with `notify_only` as the fallback when no policy matches — silence requires an
  explicit `ignore` policy.
- **Approval gate** with `pending_approval`, `approved` and `rejected` states,
  endpoints `POST /api/v1/actions/{id}/approve` and `/reject`, and an
  `approved_by` / `approved_at` record on every action.
- **Optional Rego support** through `THOT_OPA_BIN` and
  `policies/rego/thotsecure.rego`, used when the OPA binary is present and falling
  back to YAML otherwise.
- **Non-bypassable execution guard-rails** enforced by the engine, not by policy
  configuration: per-tenant `max_actions_per_hour` (default 20), per
  `(tenant, playbook, target)` cooldown, protected targets from
  `autonomy_allowlist` that no policy may act upon, a global `dry_run` that
  overrides every policy, and mandatory approval for any target outside the
  tenant's declared scope.

#### Playbooks, actions and rollback

- **Playbook runtime** (`src/thotsecure/actions/`) for the contract schema (§7):
  typed `params` with defaults, ranges and required flags, a connector call list,
  and a mandatory rollback list.
- **Shipped playbooks** in `playbooks/`: `block-source-ip` /
  `unblock-source-ip`, `rate-limit-source`, `quarantine-artifact`,
  `revoke-session`, `rotate-secret`, `isolate-host`, `patch-dependency` (opens a
  pull request and never auto-merges), `harden-endpoint`, `notify`, `open-ticket`.
- **Reversible by construction**: every destructive capability ships with its
  inverse, the rollback token is stored on the action, and
  `POST /api/v1/actions/{id}/rollback` is refused with `409` only when the action
  was already rolled back or the rollback window expired.
- **Simulated connectors by default**: an unconfigured connector returns a
  rollback token and logs `simulated: true`, so the whole pipeline can be
  exercised end to end before any credential exists.
- **Connectors**: `cloudflare`, `aws-waf`, `modsecurity`, `nginx-local`, plus the
  `null`/simulation connector.
- **Action lifecycle** — `planned`, `pending_approval`, `approved`, `rejected`,
  `executing`, `succeeded`, `failed`, `expired`, `rolled_back` — with expiry,
  `idempotency_key` deduplication, and an out-of-band `dry_run` flag recorded on
  every action.
- **Planning without side effects**: `POST /api/v1/actions/plan` returns a
  `planned` action and changes nothing.

#### Tamper-evident audit

- **Append-only, hash-chained audit log** (`src/thotsecure/audit/`) using the
  canonical hash formula of the contract (§3.5), with `prev_hash` linkage and a
  `sha256:genesis` anchor.
- **Verification** through `GET /api/v1/audit/verify` and
  `thotsecure audit verify`, reporting validity, record count and the sequence
  number where a chain break was detected.
- **SIEM/SOAR export** through `GET /api/v1/audit/export?format=jsonl|cef` and
  `thotsecure audit tail`.
- **Every decision and action is traceable**: actions carry `policy_id` and
  `audit_seq`, and records capture `actor`, `actor_role`, `before` and `after`.

#### Multi-tenancy, RBAC and API keys

- **Tenant model** (`src/thotsecure/tenancy/`) with `mode`
  (`manual`/`supervised`/`auto`), per-tenant `dry_run`, an `autonomy_allowlist`
  of protected targets, and `tenant_id` present on every persisted object.
- **Strict tenant isolation** enforced in the storage layer on every query, with
  a dedicated CI test that attempts cross-tenant access.
- **Role-based access control** with four roles and 15 named capabilities
  (`viewer`, `analyst`, `responder`, `admin`), enforced by a FastAPI dependency
  **and** re-checked in the core, so an alternative transport cannot bypass it.
- **API keys** (`ao_…`) generated per tenant with a label and role, stored only
  as `scrypt` hashes, displayed exactly once at creation, revocable immediately
  through `DELETE /api/v1/keys/{key_id}`, with `last_used_at` tracking.
- **Rate limiting** on ingestion (`THOT_RATE_LIMIT_PER_MIN`, default 600) and
  a bounded request body size, returning `429 rate_limited` when exceeded.

#### REST API v1

- **Full `/api/v1` surface** as frozen in the interface contract (§4):
  health/meta/observability, tenants and keys, events, findings, rules,
  policies, playbooks, actions, audit, stats, reports, collectors, and the
  real-time stream.
- **`X-API-Key` authentication**, with `?api_key=` accepted on the WebSocket
  path only, because browsers cannot set headers on `ws://`.
- **Normalized error envelope** `{"error":{"code","message","details"}}` with the
  documented codes `400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`.
- **Cursor pagination** with bounded `limit` (≤ 500, default 100) across events,
  findings, actions and audit.
- **Batch ingestion** of up to 500 events per request, with `tenant_id` forced
  from the presented key and a `202` response summarizing accepted, rejected,
  event identifiers and the findings produced.
- **Findings workflow**: `ack`, `close` with a resolution of
  `true_positive`/`false_positive`/`mitigated`, and `suppress` which creates a
  scoped rule exception with an expiry.
- **`GET /healthz`, `/readyz`, `/version`, `/metrics`** — liveness, dependency
  readiness (DB, bus, rules), version/commit/license/autonomy, and Prometheus
  text exposition.
- **OpenAPI 3.1** generated by FastAPI at `/openapi.json`.

#### Real-time stream and embedded console

- **WebSocket stream** at `/api/v1/ws/stream` carrying `event`, `finding`,
  `action`, `audit` and `heartbeat` frames, scoped to the authenticated tenant's
  capabilities.
- **Embedded console** at `/` — a Jinja2 + vanilla-JS UI requiring **no Node
  build**: live stream, findings with filters and risk scores, action approval
  and rollback views, audit tail with chain verification, and the rule browser.
- **Support page** at `/ui/support` with the official donation addresses in
  plain text, an anti-scam warning, and non-financial ways to help.
- **Static assets** served from `/ui/static/*`, with no user-controlled template
  evaluation.

#### Reporting

- **Finding reports** in `markdown`, `html`, `json` and **SARIF 2.1.0** through
  `GET /api/v1/findings/{id}/report?format=…` and
  `thotsecure report <finding_id> --format …`, with SARIF suitable for upload to
  GitHub Code Scanning.
- **CEF export** for SIEM ingestion, alongside JSONL.

#### CLI

- **`thotsecure` command-line interface** (`src/thotsecure/cli.py`) covering the full
  contract surface (§8): `serve`, `init-db`, `doctor`, `tenant create|list`,
  `key create|revoke`, `rules list|validate`, `policies validate`,
  `ingest`, `findings list|show`, `actions list|plan|approve|execute|rollback`,
  `audit verify|tail`, `report`, `probe`, `demo`.
- **Documented exit codes** — `0` success, `1` error, `2` usage, `3` negative
  verification (for example a broken audit chain) — so the CLI is safe in CI.
- **`--json` on every command** for automation, and `thotsecure demo` for a
  self-contained dataset that produces findings, a decision and an action.
- **`thotsecure doctor`** validating configuration, database, directories,
  permissions and safety defaults, and reporting when an unsafe default is in
  effect.

#### Python SDK and client libraries

- **Official Python SDK** (`src/thotsecure/sdk/`) usable as a library and from the
  CLI: typed models, automatic retries with backoff, idempotent action helpers,
  and pagination iterators.
- **TypeScript SDK** (`sdks/typescript/`) and **Go SDK** (`sdks/go/`) generated
  from and validated against `/openapi.json`, with TLS verification on by
  default and no credentials written to disk.

#### Deployment and packaging

- **Container image** built from `deploy/Dockerfile`, running as a non-root user
  with a read-only-compatible filesystem layout and no build toolchain in the
  final stage.
- **Docker Compose** stack (`deploy/`) for a single-node evaluation deployment,
  with a documented reverse-proxy configuration for TLS termination.
- **Kubernetes manifests** and a **Helm chart** with resource limits, liveness
  and readiness probes, a `NetworkPolicy` default-deny posture, a
  `PodSecurityContext` that forbids privilege escalation, and an optional
  `Ingress`.
- **Terraform module** and **Ansible role** for repeatable deployment of the
  supporting infrastructure.
- **Configuration reference** for all `THOT_*` variables (§9), with safe
  defaults, and a startup warning when `THOT_SECRET_KEY` is generated
  implicitly or the bootstrap key is left unchanged.
- **SQLite** as the default datastore, with PostgreSQL/TimescaleDB DDL included
  for operators who need it now; first-class adapter support is scheduled for a
  later release (see [`ROADMAP.md`](ROADMAP.md)).

#### Governance, templates and CI/CD

- **Apache License 2.0** (`LICENSE`) with attribution terms in `NOTICE`,
  including an explicit statement that the project contains no offensive
  capability.
- **Contribution process** (`CONTRIBUTING.md`) using the **DCO**
  (`git commit -s`) and Conventional Commits, with no CLA and no copyright
  assignment.
- **Governance model** (`GOVERNANCE.md`) covering roles, lazy consensus, voting,
  nominations, removal, conflict resolution, license changes and the
  constitutional invariants — including the two-thirds threshold required to
  amend an invariant, and the rule that no threshold permits adding an offensive
  capability.
- **Maintainer roster** (`MAINTAINERS.md`) and **code ownership**
  (`CODEOWNERS`) mapped to the target tree.
- **Security policy** (`SECURITY.md`) with private disclosure channels
  (GitHub Security Advisories and `security@thotsecure.dev`), response commitments
  (72-hour acknowledgement, 7-day triage, 30-day fix for critical), scope,
  explicit out-of-scope rules, the CVE and credit policies, and a "this project
  is defensive" section.
- **Contributor Covenant 2.1** (`CODE_OF_CONDUCT.md`).
- **Public roadmap** (`ROADMAP.md`) with a status and an acceptance criterion for
  every item.
- **Contribution templates**: pull request checklist, and issue forms for bug
  reports, feature requests, rule proposals, false positives, and security
  contact redirection (which never allows public disclosure).
- **CI/CD workflows** with least-privilege `permissions` and `concurrency`
  groups: test matrix on Python 3.11/3.12/3.13, web typecheck and build, Docker
  build check, `markdownlint`, CodeQL for Python and TypeScript, OpenSSF
  Scorecard with SARIF upload, Syft SBOM generation with Sigstore signing and
  provenance attestation, tagged release with notes extracted from this file and
  multi-arch image publication to GHCR, and MkDocs build with GitHub Pages
  deployment.
- **Repository hygiene**: `.editorconfig`, `.gitattributes` with LF
  normalization and `linguist-generated` marking, `pre-commit` hooks
  (whitespace, YAML, large files, private keys, Ruff, Gitleaks, markdownlint,
  yamllint), Dependabot across pip, npm, gomod, GitHub Actions and Docker, a
  complete label taxonomy, label sync and labeler workflows, stale-issue
  management, and a first-time-contributor welcome workflow.

### Changed

- Initial release: no compatibility surface exists yet. Every schema in
  `docs/architecture/api-contract.md` is frozen for the `0.1.x` line, and any
  subsequent change to it is a breaking change for this project.
- **Store construction goes through one factory.** `thotsecure.storage.create_store(settings)`
  replaces direct `Store(path)` instantiations in the service layer. The SQLite class is no
  longer a de-facto singleton: annotations throughout the codebase now read `StoreProtocol`,
  which is what the code always assumed.
- **New environment variables**, all additive and optional: `THOT_DB_SSLMODE`,
  `THOT_DB_POOL_MAX_SIZE`, and the nine `THOT_ANOMALY_*` settings (see
  [contract §9](docs/architecture/api-contract.md)).
- **`GET /readyz` gained a `backend` field**, and its `path` field now reports the SQLite file
  path or the **masked** PostgreSQL DSN. The field names and the SQLite value are unchanged.
- **`THOT_DB_URL` accepts `postgres`, `postgresql`, `+psycopg` and `+psycopg2`**; asynchronous
  drivers are refused at configuration time rather than at first use.

### Deprecated

- Nothing deprecated in this release.

### Removed

- Nothing removed in this release.

### Fixed

- **`thotsecure doctor` crashed on a Windows console using the cp1252 code page** —
  the very first command a new user is told to run ended in a `UnicodeEncodeError`
  because box-drawing characters could not be encoded. Output encoding is now forced
  to UTF-8 where possible, with an ASCII fallback for the symbols. A cosmetic problem
  must never prevent a security diagnostic from being displayed.
- **The CLI and the server generated different signing keys** when `THOT_SECRET_KEY`
  was unset, so an API key created with the CLI could not be verified by the server.
  The key is now persisted in `data/secret.key` (mode 0600) and therefore shared by
  every process of the same deployment.
- **`token=...` was not redacted** from logs and reports; the assignment pattern now
  covers `token`, `pass`, `credential`, `session_id` and related names, with tests
  asserting both that secrets are masked and that ordinary text is left intact.
- **Circular import** between the service layer and the API package, which made the
  package unimportable in some orders. Observability (metrics, rate limiting) moved
  out of `thotsecure.api` into `thotsecure.observability`.
- **Nine authoring errors** in the shipped detection library (YAML foldings, a
  missing parameter type) meant rules were silently rejected at load time — an
  absent detection, not a harmless formatting mistake. A dedicated test now fails
  the build when any shipped rule, policy, playbook or example configuration is
  rejected.
- **Release workflow failed at its first job**: the `CITATION.cff` version check
  imported PyYAML without installing it, which fails on a fresh runner. The check
  now parses the field without any third-party dependency, so the release path
  installs nothing.
- **Documentation build failed under `--strict`**: 18 links in `docs/cli.md` carried
  one `../` too many, 5 links pointed outside `docs/` (unresolvable by MkDocs), and 4
  anchors were stale. A dependency-free link checker
  (`scripts/check-docs-links.py`) now runs before the build, suggests close anchors,
  and is covered by its own test.
- **Dependabot failed on every scheduled run**: the `docker` ecosystem pointed at
  `/deploy`, a directory with no Dockerfile.
- **OpenSSF Scorecard turned the repository red** when the `scorecard-action` image
  could not be pulled from a registry — an infrastructure problem unrelated to code
  quality. The job no longer blocks the build; its findings are still published.
- **The Compose validation step reported a false failure**: `docker-compose.yml`
  declares its secrets with `${VAR:?message}` (deliberately, so a deployment cannot
  start with a default signing key), which makes `docker compose config` fail when
  they are absent. CI now supplies throwaway values for that step, and validates the
  structure rather than the presence of a real secret.
- **Auto-labelling never ran**: the label taxonomy workflow was registered but had
  zero runs, because a workflow added to a repository does not trigger on the push
  that adds it — so no label existed and every labeler run failed. The path filter
  now includes the workflow file itself.
- **Shipped playbooks failed on an unresolved placeholder**: `block-source-ip` and
  `isolate-host` pass `${finding.remediation}` to their ticket or notification, but the
  execution context never provided that field. `render_params` raises on an unresolved
  placeholder — correctly, since sending the literal `${params.target}` to a WAF API would be
  worse — so the **whole playbook failed**, including the step marked `optional: true`. The
  visible symptom was silent: no ticket, no notification, an action in `failed`. The field is
  now part of the finding context, and a test asserts that a shipped ticket actually contains
  the remediation text.
- **`${params.rollback_token}` was never resolved**: `_build_context` merged the caller's
  context *after* the parameter set, so the `params` carried by the context overwrote the
  rollback token that `rollback()` had just injected. Every block whose rollback transmits
  `${params.rollback_token}` failed, which is precisely the path used to delete a rule by
  identifier rather than by value lookup. Precedence is now explicit and documented, with a
  test that reads the closed ticket back from disk.
- **A failed rollback is now recorded instead of raised**: a `PlaybookError` during rollback
  used to escape the engine, leaving the action in its previous state with no audit record of
  the attempt. It is now audited as a failed `action.rollback`, and — the important part —
  `rollback.available` and the token are **kept**, so the operator can repair the playbook and
  retry. An action whose rollback failed is *still applied*; losing the only means of undoing
  one's own countermeasure would be a self-inflicted outage.
- **The connector registry resolved relative paths from the process working directory**:
  `directory`, `quarantine_dir`, `deny_file`, `state_file` and `allowed_roots` are now resolved
  from `root_dir`, like every other path in the product. Started from a different directory (a
  systemd unit, a scheduled task, a container with another `WORKDIR`), the product used to
  write its tickets, quarantine and Nginx deny file somewhere else entirely — silently, and
  precisely where an operator would not look for evidence.
- **`thotsecure` could not start at all on PostgreSQL**: `ensure_directories()` created the
  parent of `db_path`, which raises a `ConfigError` as soon as `THOT_DB_URL` is not SQLite.
  Directory creation is now conditional on the backend, and the error message of `db_path`
  points at `store_location()` for the correct way to describe a store.
- **`THOT_DB_URL` validation contradicted the adapter**: the settings validator accepted
  `postgresql+asyncpg://`, a driver the synchronous adapter rejects — a URL accepted at
  configuration time and refused at first use. The validator now accepts exactly what the
  adapter supports (SQLite, `postgresql`, `+psycopg`, `+psycopg2`) and refuses asynchronous
  drivers with an explicit message.
- **A phantom dependency made the whole API unimportable on a clean install**:
  `python-multipart` is required by FastAPI as soon as `Form(...)` is used, and the embedded
  console uses it for its login, logout, approval and audit-verification forms. It was
  installed on the development machine but **absent from `pyproject.toml`**, so on a clean CI
  checkout `import thotsecure.main` raised at import time, `tests/test_api.py` could not even
  be collected, and the suite stopped at 76 tests out of 378. It is now a declared runtime
  dependency, and `tests/test_dependencies_declared.py` compares the package's **real** imports
  (parsed with `ast`) against what the project declares — it immediately found a second one,
  `cryptography`, used by the TLS collector's key-strength check. That one is genuinely
  optional, so it is now a discoverable extra, `pip install "thotsecure[tls]"`, instead of a
  feature nobody could find.
- **The PostgreSQL schema could not be created at all**: the DDL created the partial index
  `idx_events_claims` on `claimed_at` *before* the `ALTER TABLE ... ADD COLUMN claimed_at`
  statements that create the column. On a fresh database PostgreSQL rejects an index on a
  column that does not exist yet, so the whole schema initialisation failed and every
  PostgreSQL conformance test errored out. Columns first, index afterwards — and the ordering
  is now commented so it is not "tidied up" by mistake.
- **`claim_pending_events(lease_seconds=0)` silently did something else**: a zero lease was
  clamped to one second, which broke the documented meaning of the value — "the previous worker
  is dead, make its reservations reclaimable now". Zero is now honoured, and negative values
  are treated as zero rather than as a one-second lease.
- **`docker-compose.yml` was not deployable**: `uid` and `gid` are not accepted keys of the
  long-syntax `tmpfs:` block, so `docker compose config` rejected the shipped file. `mode: 1777`
  already makes ownership irrelevant for a temporary directory.
- **The syslog collector used an ambiguous date parse**: RFC 3164 timestamps carry no year, and
  Python 3.13 deprecates asking `strptime` for a date without one. The project turns
  `DeprecationWarning` from its own modules into errors, so the pytest step failed on 3.13
  only. The timestamp is now parsed component by component, with the year-boundary correction
  kept and invalid input (31 February, out-of-range hour) rejected explicitly.
- **The documentation build failed on links leaving `docs/`**: MkDocs cannot resolve a relative
  link to a repository-root file, even though the file exists on disk — 21 such links pointed at
  `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` and friends from inside the documentation.
  They now use the absolute URL of the file on the forge, and
  `scripts/check-docs-links.py` reports this class of link explicitly instead of treating it as
  a valid internal link.
- **A green lint job was never reachable**: `ruff check .` reported **1479** diagnostics, so the
  job had failed on every push since the first commit. Automatic corrections brought that down
  to 238, and the rest was fixed by hand — see *Changed* below for what remains ignored and why.
- **GitHub Pages deployment failed on a repository setting**: the build job ran
  `actions/configure-pages`, so a repository whose Pages source was not yet set to "GitHub
  Actions" showed a red build even though the documentation compiled cleanly. Configuration
  moved to the privileged deploy job, where a failure is reported as a warning with the exact
  one-time action the owner must take, instead of a permanent red cross that trains people to
  ignore it.
- **Auto-labelling failed on every pull request, including Dependabot's**: the workflow passed
  `sync-labels: ''` to `actions/labeler@v5`, and the action parses that input as YAML — an empty
  string is not a valid scalar of the Core 1.2 schema, so the job died with a `TypeError` before
  labelling anything. The input is gone (its default is already `false`), and a test now asserts
  it is not reintroduced.
- **Three references pointed at labels that did not exist** — and a label that does not exist is
  silently ignored, never an error: Dependabot asked for `dependencies`, `security`,
  `area/packaging`, `area/ci` and `area/sdk`; two issue templates asked for `security` and
  `type/false-positive`. Dependency pull requests therefore arrived with **no labels at all**,
  which is precisely how they end up unread. Labels now come from the single taxonomy
  (`dependabot.yml` uses `area/deploy`, `area/sdks` and `type/security`; the templates use
  `false-positive` and `type/security`), `dependencies` is declared, and
  `tests/test_github_metadata.py` cross-checks every consumer of a label against
  `.github/labels.yml` so the next mismatch fails the build instead of disappearing.
- **The bootstrap API key could not authenticate, so the first documented journey did not
  work.** Authentication splits a presented key into `thot_<key_id>_<secret>` to find the
  record, but the shipped default was `ao_dev_local_change_me`: it was stored at bootstrap and
  then rejected on **every** call with `401 format de clé API invalide`. The error message
  talked about the key that was sent, never about the one that had been configured, so the
  cause was invisible. The default is now `thot_BOOTSTRAP_changemebeforefirstuse`, the format is
  **validated at configuration time** with the expected shape in the message, and two tests
  cover it: an out-of-format key is refused at startup, and a valid custom key really does open
  a session end to end.
- **An ingestion response listed the same finding once per matching event.** A threshold rule
  that matches N events evaluates the *same* finding N times, and `outcome.findings` was a
  concatenation of each event's result: 200 ingested events produced **200 entries for a single
  finding**, each carrying the `count` of its own instant. A caller reading that list concludes
  there are 200 findings, and may read an intermediate count — which is exactly the reading that
  makes a correct count look wrong. The response now keeps **one entry per finding, in its final
  state**, and exposes `count` on the serialised finding so a client no longer has to guess.
  The reported symptom itself (`count=7` for 200 events) was **not** reproducible: the stored
  count was 200 both before and after this change, and the new test asserts it.

- **The optional React dashboard now builds, and its job is blocking.** Getting it green took
  three distinct migrational changes, because none of the version bumps was a bump:

  - **React 19** (`react`, `react-dom`, `@types/react`, `@types/react-dom` must move together —
    `react-dom` had been left on 18 while `react` was on 19, and npm refuses, rightly, to resolve
    that tree). `@types/react` 19 removes the global `JSX` namespace, so the 54 `JSX.Element`
    annotations across 25 files import the type from `react` instead.
  - **ESLint 10** no longer reads the eslintrc format and rejects `--ext`; `web/eslint.config.js`
    replaces `.eslintrc.cjs`, with the same rules, one by one. `eslint-plugin-react-hooks` 7
    applies the React Compiler rules, which flagged four genuine patterns — form resets inside
    effects and `Date.now()` during render — all **fixed rather than disabled**: the resets now
    happen during render (the documented "adjust state when a prop changes" pattern) and the
    clock is a small render clock that also refreshes the "expired" badge on its own.
  - **Tailwind 4** moved its PostCSS plugin to `@tailwindcss/postcss` and dropped the
    `@tailwind …` directives; `@config` now references `tailwind.config.ts` explicitly, without
    which the whole SOC theme would have been silently ignored.

  Two real defects surfaced on the way: `EmptyState` was not re-exported by `@/components/ui`
  although `DashboardPage` imports it (`TS2459` — the dashboard did not compile at all), and five
  `?? []` fallbacks rebuilt an array on every render, which `react-hooks/exhaustive-deps`
  correctly rejected.

- **`web/package-lock.json` is committed, and `npm ci` is mandatory.** The lockfile was missing,
  so the job ran a non-reproducible `npm install` and could not be blocking. When the lockfile
  arrived, it was stale — `npm ci` failed on the drift, which is exactly its job. Regenerating it
  (330 packages, generated on a Node 20 runner) was the fix; replacing `npm ci` with `npm install`
  would have removed the symptom and the guarantee with it. The `continue-on-error` on typecheck,
  build and lint is gone: a green light that tolerates a failure is worth nothing, and it is what
  let a dashboard that did not compile stay unnoticed.

### Security

- **Safe defaults**: `THOT_DRY_RUN=true` and `THOT_AUTONOMY=supervised`
  out of the box; raising autonomy is an explicit, audited, per-tenant decision.
- **API keys are never stored in clear text** — only `scrypt` hashes, with the
  plaintext value shown once at creation.
- **Tenant isolation is enforced on every query and covered by a dedicated CI
  test**, so a regression fails the build rather than shipping.
- **Audit chain of hashes** over canonical JSON, with a verification endpoint
  and export, so that tampering is detectable rather than merely discouraged.
- **No offensive capability**, by design and as a constitutional invariant: no
  exploit code, no aggressive scanning, no brute-forcing, no denial of service,
  no hack-back. The `probe` collector audits only targets a tenant has declared
  as owned.
- **Regex evaluation timeouts** and a bounded request body to limit
  denial-of-service surface on ingestion and rule matching.
- **No user-controlled template evaluation** in the console or in reports.
- **Simulated connectors by default**, so a misconfigured deployment cannot
  change production infrastructure before credentials are deliberately supplied.
- **Signed supply chain from the first release**: SBOM (SPDX and CycloneDX),
  Sigstore keyless signature and a build provenance attestation attached to the
  release artefacts.

### Known limitations in 0.1.0

Recorded here so that they are expectations rather than surprises. Each is
tracked in [`ROADMAP.md`](ROADMAP.md).

- **PostgreSQL/TimescaleDB**: the adapter is written and exercised by the shared
  storage conformance suite, which CI runs against a real TimescaleDB service
  container. It has **not** yet been operated at production scale by the
  maintainers, and no migration of a large SQLite database has been measured.
- **WAF connectors**: Cloudflare and AWS WAF connectors are implemented against the
  documented APIs, with signature and payload verification covered offline. They
  have **not** been validated against live accounts, which is a required step
  before enabling them in production (the procedure is documented).
- **Anomaly detection** is statistical (EWMA + z-score), not machine learning, and
  it analyses one entity at a time: no multi-signal correlation yet. It is
  disabled by default and needs 3–7 days of tuning on the target environment.
- **Rego evaluation requires an external OPA binary**; there is no embedded
  evaluator. The YAML engine remains the default and the fallback.
- **Authentication is API-key only** — no SSO/OIDC, no per-user accounts.
- **`mypy` runs in CI in non-blocking mode** while type coverage improves.
- **The React dashboard in `web/` is optional** and not required for the embedded
  console, which is fully functional without a Node toolchain.

[Unreleased]: https://github.com/thot-corp/thot-secure/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/thot-corp/thot-secure/compare/v0.0.0...v0.1.0
