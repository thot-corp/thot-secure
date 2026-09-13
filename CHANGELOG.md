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

### Deprecated

- Nothing deprecated in this release.

### Removed

- Nothing removed in this release.

### Fixed

- Initial release: no fixes carried over from a previous version.

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

- SQLite is the only fully supported datastore; PostgreSQL/TimescaleDB DDL ships
  but the adapter is not production-ready.
- WAF connectors other than the simulation are implemented against documented
  APIs but have not been validated against live Cloudflare or AWS WAF accounts.
- Rego evaluation requires an external OPA binary; there is no embedded
  evaluator.
- Authentication is API-key only — no SSO/OIDC, no per-user accounts.
- `mypy` runs in CI in non-blocking mode while type coverage improves.
- The React dashboard in `web/` is optional and not required for the embedded
  console, which is fully functional without a Node toolchain.

[Unreleased]: https://github.com/thot-corp/thot-secure/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/thot-corp/thot-secure/compare/v0.0.0...v0.1.0
