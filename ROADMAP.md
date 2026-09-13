# Thot Secure Roadmap

Status of every item is tracked here and reviewed quarterly in a public
`Roadmap review - <quarter>` issue. See
[`GOVERNANCE.md` §8](GOVERNANCE.md#8-public-roadmap) for the rules that govern
this file.

**What this roadmap is.** A statement of intent, in rough order of priority
within each milestone. It is **not** a commitment, a schedule, or a
service-level agreement. Thot Secure has no paid support tier, no donation-funded
staffing, and no sponsor who can move an item up the list.

**What is fixed.** The constitutional invariants in
[`GOVERNANCE.md` §9](GOVERNANCE.md#9-constitutional-invariants) are not
roadmap items and are not negotiable: no offensive capability, safe defaults,
reversible actions, approval gates, tenant isolation, tamper-evident audit,
non-bypassable guard-rails, declared scope only, and a permanently open
Apache-2.0 license. An item that contradicts an invariant is declined with a
pointer to that section, not silently dropped.

## Status legend

| Status | Meaning |
|---|---|
| ✅ **Done** | Merged, released and covered by tests. |
| 🚧 **In progress** | Actively being worked on, with a named owner or an open pull request. |
| 📋 **Planned** | Agreed and specified; nobody is working on it yet. |
| 🔍 **Exploring** | The problem is understood, the design is not settled. |
| ⛔ **Blocked** | Waiting on something outside the project's control. |
| ❌ **Dropped** | Will not be done; the reason is recorded. |

**Acceptance criteria** are written so that a reviewer can decide pass or fail
without asking the author what was meant. "Better performance" is not a
criterion; a measured number against a described environment is.

## How to get involved

- Pick up an item marked 📋 or 🔍 and open an issue saying so — that is how a
  status changes to 🚧.
- Small, self-contained items suitable for a first contribution are labelled
  [`good first issue`](https://github.com/thot-corp/thot-secure/labels/good%20first%20issue).
  The reserved block at the end of this file lists what we expect to be
  available there.
- Larger items start as an RFC issue before any code is written, so the shape is
  agreed first.
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first; in particular, the rule that
  no contribution may add offensive capability.

---

## v0.1.0 — MVP (current)

✅ **Released.** A defensive, multi-tenant SOAR/CSPM platform with collectors, an
event bus, a YAML detection engine, risk scoring, policy-as-code, reversible
playbooks, a hash-chained audit log, RBAC, REST API v1, a CLI, an embedded
console, SARIF/CEF reporting, deployment artefacts, and Python/TypeScript/Go
SDKs. See [`CHANGELOG.md`](CHANGELOG.md#010---2026-xx-xx) for the full inventory
and the known limitations of this version.

---

## v0.2.0 — Scale, real connectors, native policy

Target: make Thot Secure usable against real production infrastructure at more than
a laboratory scale, without changing the safety model.

| Item | Status | Acceptance criterion |
|---|---|---|
| **PostgreSQL / TimescaleDB adapter** — first-class support alongside SQLite, selected through `THOT_DB_URL`. | 🚧 In progress | The full test suite passes against PostgreSQL 16 and TimescaleDB 2.x; the retention job is implemented as a hypertable policy and verified by a test that ages events past `THOT_RETENTION_DAYS`; a migration path from an existing SQLite database is documented and exercised in `tests/test_storage.py`; tenant isolation is re-verified on the new backend by the existing cross-tenant test. |
| **Cloudflare WAF connector (real)** — `block_ip` / `unblock_ip` / rate-limit rules against the live API. | 📋 Planned | Connector passes an integration test against a recorded API fixture set **and** a manual validation run against a Cloudflare account documented in the pull request; rollback removes the exact rule it created, verified by reading back the rule list; API token scopes required are documented in `docs/`; behaviour when the API is unreachable is a recorded failure with no partial change, covered by a test. |
| **AWS WAF connector (real)** — IP sets and rate-based rules via the AWS API. | 📋 Planned | Same bar as the Cloudflare connector; IP-set update uses optimistic concurrency with a `LockToken` retry, rollback restores the previous IP set contents exactly, and a test asserts that a failed update leaves the set unchanged. |
| **Native OPA integration** — evaluate `policies/rego/*.rego` without an external binary becoming a hard dependency. | 📋 Planned | Policies are evaluated through OPA when `THOT_OPA_BIN` is set and through the YAML engine otherwise, with the two engines asserted to agree on a shared conformance fixture set; `policies/rego/thotsecure.rego` ships complete with the guard-rails of contract §6 expressed as Rego rules; the guard-rail tests from `tests/test_decision.py` run against both engines. |
| **SSO / OIDC authentication** — per-user login with group-to-role mapping. | 📋 Planned | A user authenticates against a standard OIDC provider (Keycloak and one hosted provider verified); group claims map to `viewer`/`analyst`/`responder`/`admin` via documented configuration; sessions are short-lived and revocable; API keys keep working and remain the recommended path for automation; a test asserts that an unmapped group grants no capability, and that tenant isolation is unaffected by the identity source. |
| **Rule pack versioning** — signed, versioned detection packs that can be installed and pinned. | 🔍 Exploring | A pack can be installed from a URL or a local archive, is verified against a Sigstore signature, records its version, and can be pinned and rolled back; installing a pack cannot enable a rule that adds an action, and a test asserts that a pack installation never changes `THOT_DRY_RUN` or autonomy settings. |
| **Ingestion throughput benchmark in CI** — regression guard for the pipeline. | 📋 Planned | A benchmark ingests a fixed 10,000-event corpus on a 2-vCPU runner and publishes p50/p95 latency for normalization, rule evaluation and persistence; CI fails when p95 regresses by more than 25 % against the stored baseline; the baseline and runner class are recorded in the repository. |
| **Retention and archival policy** — move aged events to object storage instead of deleting them. | 🔍 Exploring | Events older than `THOT_RETENTION_DAYS` can be exported to a configured S3-compatible bucket and purged locally, with a verification step that refuses to purge an unverified export; a test covers a failed upload leaving local data intact. |

---

## v0.3.0 — Extensibility, analytics, search

Target: let the community extend Thot Secure without forking it, and make large
event volumes searchable.

| Item | Status | Acceptance criterion |
|---|---|---|
| **Plugin marketplace** — a registry of installable detectors, connectors, playbooks and reporters. | 🔍 Exploring | A plugin declares a manifest (name, version, type, capabilities, required permissions); installation requires an explicit operator confirmation of the declared capabilities; a plugin is denied by default any capability it did not declare, verified by a test with a deliberately over-reaching plugin; at least three example plugins built by third parties are published with source available; the security review requirements for a listing are documented in `SECURITY.md` or an adjacent policy. |
| **Anomaly detection (ML)** — statistical baselining on top of, never instead of, deterministic rules. | 🔍 Exploring | A per-tenant baseline is computed from historical event rates and entity behaviour; deviations produce a **finding with an explanation** (which signal, which baseline, which deviation), never an action on their own; false-positive rate on the project's reference dataset is measured and published; the model runs offline with no telemetry leaving the deployment; deterministic rules remain able to suppress or override an anomaly finding. |
| **OpenSearch / Elasticsearch backend** — full-text and aggregations over events. | 📋 Planned | Events are indexed with a documented mapping; the `q` filter of `GET /api/v1/events` maps to a real search query with the same semantics as the SQLite implementation, verified by a shared conformance test; tenant isolation is enforced at query construction and re-verified by the cross-tenant test; index lifecycle and retention are documented. |
| **Sigma conversion round-trip** — a documented, tested subset with a compatibility report. | 📋 Planned | A converter imports a defined subset of Sigma rules and emits Thot Secure YAML; a compatibility report lists the supported and unsupported constructs; every converted rule from the reference corpus round-trips with a semantic-equivalence test; conversion never silently drops a condition, and an unconvertible rule is rejected with a diagnostic. |
| **Multi-region / HA control plane** — run more than one Thot Secure node against the same datastore. | 🔍 Exploring | Two nodes share a datastore and a bus; action idempotency holds when both attempt the same action, verified by a concurrent test; the audit chain remains strictly ordered and verifies after concurrent writes; leader election or a documented single-writer design is chosen in an RFC before implementation. |
| **Notification integrations** — Slack, Teams, PagerDuty, generic webhooks. | 📋 Planned | Each integration is a connector following the existing playbook contract, works in simulated mode, and has a rollback that removes the message or resolves the incident where the API allows it; secrets are read from configuration and never logged; a failing integration does not fail the action that triggered it. |
| **Terraform provider** — manage tenants, policies and playbooks as infrastructure. | 🔍 Exploring | Tenants, policies and playbooks can be created, read and updated through a provider with import support; `terraform plan` is non-destructive by default; the provider refuses to disable `dry_run` without an explicit, documented flag. |

---

## v1.0.0 — Production readiness

Target: the release that an organisation can deploy with an internal change
board and an auditor in the room. Everything here is about evidence, stability
and supportability rather than new capability.

| Item | Status | Acceptance criterion |
|---|---|---|
| **Frozen public API with a stability guarantee** | 📋 Planned | The `/api/v1` surface is declared stable: no breaking change without a major version, a deprecation window of at least one minor release, and a published migration note; the interface contract is promoted from "frozen for the sprint" to a versioned specification with a documented change process; a conformance test suite validates the specification against a running instance. |
| **Documented SLA for enterprise support** | 📋 Planned | Published support tiers with response and resolution targets, a named escalation path, and a clearly stated scope of what is and is not covered; **no support tier is funded by or granted through donations**, and the community edition keeps every safety feature — there is no paid-only security capability; the escalation path is exercised in a documented game day. |
| **SOC 2 readiness** | 📋 Planned | A control matrix maps each relevant Trust Services Criterion to a project control, with evidence an auditor can inspect: change management through reviewed pull requests and protected branches, access reviews for maintainers, an incident response runbook that has been exercised, vendor and dependency management through the SBOM and Dependabot, and monitoring/alerting for the project's own infrastructure; a gap analysis is published with the remaining gaps stated plainly rather than glossed over. |
| **Formal data-protection documentation** | 📋 Planned | A data-flow document describes every field Thot Secure stores, where it lives, how long it is retained and how it is deleted; GDPR-oriented guidance covers controller/processor roles for MSP deployments and data-subject requests against event and finding data; the retention job is demonstrated to delete what the document says it deletes. |
| **High-availability reference architecture** | 📋 Planned | A published architecture for a multi-node deployment with a documented recovery point and recovery time objective, a tested backup and restore procedure, and a documented failure mode for each component; an automated restore test runs on a schedule and its results are published. |
| **Third-party security audit** | 🔍 Exploring | An independent audit of the authentication, tenant isolation, audit chain and action/rollback paths is completed and its report published in full, including unresolved findings with their remediation status; the audit's scope and methodology are published alongside it. |
| **Stable SDKs with published compatibility policy** | 📋 Planned | Python, TypeScript and Go SDKs reach `1.0` with semantic-versioned releases, a documented compatibility matrix against API versions, generated clients kept in step with `/openapi.json` by CI, and deprecation warnings before the removal of any client method. |
| **Multi-arch signed images and reproducible builds** | 📋 Planned | Images are built for `linux/amd64` and `linux/arm64`, signed with Sigstore, accompanied by an SBOM and provenance attestation, and reproducible enough that a documented rebuild reproduces the image digest; verification instructions are published for operators. |
| **Accessibility and internationalisation of the console** | 🔍 Exploring | The embedded console meets WCAG 2.1 AA on the documented pages, verified with an automated audit plus a manual keyboard-only pass; UI strings are externalised for translation with at least one non-English locale shipped; no JavaScript build step is introduced as a requirement. |

---

## Reserved space for `good first issue` work

This section holds candidate first contributions that maintainers expect to
label as `good first issue` — self-contained, documented, with no design decision
left open. It exists so that newcomers have a reliable place to look, and so
that the label stays honest per
[`CONTRIBUTING.md` §11](CONTRIBUTING.md#11-good-first-issue).

| Candidate | Area | Expected shape |
|---|---|---|
| Add detection rules for a documented technique family | `rules/` | One YAML rule conforming to contract §5, positive and negative tests, `false_positives` and OWASP/MITRE references. |
| False-positive refinements on existing rules | `rules/`, `tests/test_rules_engine.py` | A regression test reproducing the false positive, then the narrowest rule change that removes it. |
| Document a deployment path end to end | `docs/` | A tested walkthrough for Docker Compose or Helm, from `git clone` to first finding, including the safe-default warnings. |
| SDK usage examples | `sdks/`, `docs/` | A runnable example per SDK against a local instance, with the `X-API-Key` flow and error handling shown. |
| CLI ergonomics and help text | `src/thotsecure/cli.py`, `tests/test_cli.py` | Better `--help` output, consistent `--json` behaviour, exit code coverage per contract §8. |
| Translation of the console strings | `src/thotsecure/ui/` | Externalise strings without introducing a Node build requirement. |
| Report templates | `src/thotsecure/reports/`, `tests/test_reports.py` | A new output format or a refined Markdown/HTML template, with a valid-output test (SARIF stays schema-valid). |
| Connector for a self-hosted WAF or proxy | `playbooks/`, `src/thotsecure/actions/` | A connector that works in simulated mode, declares its parameters, and ships with a working rollback and a rollback test. |

When an item here is taken, it moves to the milestone table above with a 🚧
status and an owner.
