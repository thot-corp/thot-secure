# Security Policy

Thot Secure is a defensive security platform: it ingests telemetry, detects,
scores, decides and applies **reversible** counter-measures on infrastructure
you own or are authorized to operate. A vulnerability in Thot Secure is
consequential — it can widen a tenant boundary, forge an audit trail, or trigger
an unwanted change on production infrastructure. We take reports seriously and
we will not shoot the messenger.

This document explains where to report, what we commit to, what is in scope, and
what is not.

---

## 1. The single most important rule

**Do not report a vulnerability in a public GitHub issue, pull request,
discussion, chat or social media post.**

A public report puts every deployment at risk before a fix exists. Reports sent
to a public channel are removed, and we will ask you to resubmit through one of
the private channels below. If you are unsure whether something is a
vulnerability, report it privately anyway — we would rather triage a false
alarm than handle a public disclosure.

---

## 2. Private reporting channels

### Preferred: GitHub Security Advisories

Open a private advisory from the repository's **Security** tab:
`https://github.com/thotsecure/thot-secure/security/advisories/new`.

This is the preferred channel because it keeps the report, the reproduction,
the patch and the CVE request in one private place, gives you credit in the
published advisory, and lets us request a CVE identifier on your behalf in a
single click.

### Alternative: email

`security@thotsecure.dev` — encrypted to the project PGP key below.

Use email if you cannot use GitHub, if your report contains material you do not
wish to upload, or if the GitHub advisory form is itself affected.

### What not to use

Do not use `conduct@thotsecure.dev` for vulnerabilities (that address is for the
[Code of Conduct](CODE_OF_CONDUCT.md)), and do not open an issue titled
"security bug" with details.

---

## 3. PGP key

Reports to `security@thotsecure.dev` may be encrypted. The project's reporting key
is an Ed25519 (sign + certify) key with an encryption subkey, published here and
in the repository's `.well-known` location once the website is live.

| Property | Value |
|---|---|
| User ID | `Thot Secure Security Team <security@thotsecure.dev>` |
| Algorithm | Ed25519 (primary, certify + sign) with Curve25519 (X25519) encryption subkey |
| Key ID (long) | `F05DB21C8E634D7A` |
| Key ID (short) | `8E634D7A` |
| Key fingerprint | `9F3C 1A7E 4B82 D560 3CE1  7A94 F05D B21C 8E63 4D7A` |
| Created | `2026-01-05` |
| Expires | `2028-01-05` (rotated every two years) |

> **The armored block below is a structural placeholder, not a usable key.**
> It is replaced with the real public key during repository bootstrap, before
> the first public release. Until that replacement happens, treat this section
> as unimplemented and use the GitHub Security Advisories channel, which needs
> no key. **Always verify the fingerprint against at least two independent
> sources** before encrypting anything to it — a fingerprint posted in a single
> place is not a trust anchor, and Thot Secure will never ask for a private key or
> a seed phrase over any channel.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: PLACEHOLDER - structural example, not a usable key.
Comment: Replaced at repository bootstrap; verify the fingerprint out-of-band.

xjMEZXqT8BYJKwYBBAHaRw8BAQdA7mQ2vK3pR9cT1sV5nH8jL0dW4yB6uF2aE7gI3kM9
P1HNIIhBZWdpc09wcyBTZWN1cml0eSBUZWFtIDxzZWN1cml0eUBhZWdpc29wcy5kZXY+
iQkMFhgTCgMFAAMFA3wQAAoJEPBdshyOY016PLMA/0Xk2mQv7hR1T4nJ9dP0cW8bY6sK
zQ5vL3gH1aT0uE9eAP9sV2mK7nQ4xR8cT1sV5nH8jL0dW4yB6uF2aE7gI3kM9P1g=
=PLCE
-----END PGP PUBLIC KEY BLOCK-----
```

Key rotation is announced in [`CHANGELOG.md`](CHANGELOG.md) and on the security
page, with the new fingerprint, at least 30 days before the old key expires.

---

## 4. What to include in a report

A precise report is fixed far faster than a vague one. Please include:

1. **Summary** — one paragraph on the weakness and its impact.
2. **Affected component and version** — `GET /version` output, the container
   image digest or the commit SHA. `0.1.x` is the only supported line today.
3. **Deployment shape** — self-hosted, container, Kubernetes; single-tenant or
   MSP multi-tenant; `THOT_ENV`, and which of `DRY_RUN`, `AUTONOMY` and
   `TLS_ENABLED` were in effect. Most of our severity depends on these.
4. **Prerequisites** — the role and capabilities of the API key you used
   (`viewer`, `analyst`, `responder`, `admin`) and whether a valid key was
   needed at all.
5. **Reproduction** — a numbered sequence, a minimal script, or a
   `curl`/`httpie` transcript. Redact real hostnames, IPs, API keys and
   telemetry; a synthetic tenant such as `acme` is enough.
6. **Impact** — what an attacker actually gains. "Cross-tenant read of another
   tenant's findings", "audit chain can be rewritten without detection",
   "playbook executes without approval", "API key exposed in a log line".
7. **Suggested fix or mitigation** — optional but genuinely useful.
8. **Your disclosure preference** — anonymous, credited, or credited with a
   link.

Please do not attach live credentials, real customer data or production
captures. We will never ask for them.

---

## 5. Response commitments

These are best-effort commitments made by a volunteer team, stated as targets so
you can plan around them. We would rather tell you we are late than go silent.

| Stage | Target | What it means |
|---|---|---|
| **Acknowledgement** | **72 hours** | A human confirms receipt and gives you a tracking reference. |
| **Triage** | **7 calendar days** | Severity is assigned, the issue is reproduced or a reproduction is requested, and you receive a first assessment with a rough fix timeline. |
| **Fix for critical severity** | **30 calendar days** | A fix or a documented, working mitigation is released for critical issues (see the severity table below). |
| Fix for high severity | 60 days | |
| Fix for medium / low | next planned minor release, or 90 days, whichever comes first | |
| **Public advisory** | Coordinated with you | Published after a fixed release is available, typically with the fix. |

If a fix slips past a commitment, we will contact you with the reason and a new
date — before the deadline, not after it.

### Severity

| Severity | Examples |
|---|---|
| **Critical** | Cross-tenant data access; authentication bypass; API key or `THOT_SECRET_KEY` disclosure; audit-chain forgery or undetected rewriting; unauthorized action execution (an action runs without approval or outside `DRY_RUN`); remote code execution. |
| **High** | Privilege escalation between roles (`viewer` → `responder`); policy or guard-rail bypass (hourly cap, cooldown, protected-target allow-list); rollback that silently fails to reverse an action; rule-engine regex denial of service on ingestion. |
| **Medium** | Stored or reflected XSS in the embedded console; SSRF from a collector against a non-declared target; information disclosure limited to data the caller can already read; rate-limit bypass with limited impact. |
| **Low** | Hardening gaps with no demonstrated impact; verbose errors; missing security header where a concrete exploit path is not shown. |

---

## 6. Scope

### In scope

- `src/thotsecure/**` — the application package, all layers.
- **API v1** (`/api/v1/**`) — authentication, RBAC and capability checks,
  request validation, rate limiting, error handling, WebSocket authentication.
- **Multi-tenant isolation** — any path that returns, mutates or leaks another
  tenant's events, findings, actions, keys or audit records.
- **Audit chain** — hash computation, append-only guarantees,
  `GET /api/v1/audit/verify`, and the JSONL/CEF exports.
- **Detection engine** — rule parsing, operator evaluation, regex handling,
  Sigma-lite translation (including untrusted rule input).
- **Decision engine** — policy evaluation and, especially, the non-bypassable
  guard-rails: per-tenant hourly cap, cooldown, protected targets, global
  `dry_run`, out-of-scope-target approval.
- **Actions and rollback** — approval gate, idempotency, expiry, and whether
  rollback truly reverses the effect.
- **Collectors** — scope enforcement: no collection or probing outside the
  tenant's declared targets.
- **Reports** — injection into SARIF/HTML/CEF/Markdown output.
- **CLI** — argument handling, credential storage, command injection through
  user-supplied values.
- **Embedded console** (`src/thotsecure/ui/**`) — XSS, CSRF, template injection.
- **Deployment artefacts** — `deploy/**` (Dockerfile, Compose, Kubernetes,
  Helm charts, Terraform, Ansible): insecure defaults, over-broad RBAC,
  exposed dashboards, secrets in images.
- **SDKs** — `sdks/python`, `sdks/typescript`, `sdks/go`: TLS verification,
  credential handling, injectable parameters.
- **Supply chain** — dependency confusion, typosquatting of project packages,
  and CI workflows that can be triggered by an untrusted pull request to
  exfiltrate secrets or push to a protected branch.

### Out of scope

- **Automated scanner output without demonstrated impact.** A raw report from a
  scanner, a "best practices" checklist, a CVE number pasted into an issue, or a
  list of dependency versions that are merely outdated will be closed. To be
  actionable, a report must show a reachable code path in Thot Secure and the
  concrete impact of exercising it. If you can demonstrate a real path, we will
  treat it as in scope regardless of how it was found.
- **Missing hardening with no exploit.** Absent HSTS or CSP on a
  self-hosted instance, cookie flags on an authenticated-by-header API, TLS
  configuration of a sample reverse proxy, and similar items without a
  demonstrated impact.
- **Denial of service by resource exhaustion on an instance you control.**
  Sending 10 GB of events to your own deployment, or exhausting disk with
  retention you configured, is a configuration matter. Structural DoS that
  requires no authenticated access, or that a single unauthenticated request
  can trigger, *is* in scope.
- **Self-XSS, clickjacking on unauthenticated pages, and social engineering.**
- **Vulnerabilities in third-party components with no Thot Secure-specific
  impact.** Report those upstream to the component's maintainers; tell us only
  if Thot Secure uses the component in a way that makes the issue exploitable
  where the upstream maintainers consider it out of scope.
- **Findings that require an already-compromised host or cluster admin.**
  Someone with root on the Thot Secure host, or with permission to edit the
  deployment, is outside the threat model; the audit chain is designed to make
  such tampering *detectable*, not impossible.
- **Anything that requires attacking a third party.** Do not test against
  systems you do not own or are not explicitly authorized to test. Reports
  derived from unauthorized testing of third-party infrastructure will be
  rejected, and we may report the activity.
- **Offensive tooling requests.** "Thot Secure should scan/exploit X" is not a
  vulnerability; it is contrary to the project's design. See
  [`GOVERNANCE.md`](GOVERNANCE.md#constitutional-invariants).
- **Reports produced exclusively by an LLM without validation**, unsupported
  code excerpts, and speculative chains with no reproduction. We will happily
  discuss a hypothesis, but we cannot triage a guess.
- **The addresses in `.github/FUNDING.yml`.** Donations are voluntary and no
  counterpart is offered; a misdirected donation is not a security issue.

### Safe harbor

We will not pursue or support legal action against researchers who:

- test only against their own deployment or one they are authorized to test;
- keep within the scope above and stop as soon as they have demonstrated impact,
  without exfiltrating data, pivoting further, degrading service, or accessing
  another tenant's data beyond the minimum needed to prove the issue;
- report privately and give us the agreed disclosure window;
- do not exploit the finding for any purpose beyond the report.

Good-faith research conducted under these terms is authorized by the project. If
a third party raises a complaint about your research, we will make this policy
known.

---

## 7. CVE identifiers

**We want a CVE for anything that affects users**, and we will request one for
you through GitHub Security Advisories, which is a CVE Numbering Authority for
open source projects.

- Request a CVE in your report, or tell us at any point that you would like one.
- A CVE is issued for issues with a demonstrated security impact in a released
  version: roughly, our severity levels *critical* and *high*, plus *medium*
  issues with a clear security consequence (XSS, SSRF, information disclosure).
- We do not request CVEs for issues that are fixed before the first public
  release and never affected users, for hardening-only changes, for
  documentation, or for upstream component bugs that we merely vendor.
- We assign CVSS v4.0 vectors ourselves and publish them in the advisory. If you
  disagree with the score, say so — the vector is published with its rationale
  and we will revisit it rather than argue about the number.
- If you have already requested a CVE from another CNA, tell us so we do not
  create a duplicate.
- Advisory identifiers follow the form `GHSA-xxxx-xxxx-xxxx`, with the CVE
  listed alongside.

---

## 8. Credit policy

Contributors who report a valid issue are credited by default, in:

- the published GitHub Security Advisory,
- the `### Security` section of [`CHANGELOG.md`](CHANGELOG.md) for the fixing
  release,
- the security acknowledgements list on the project website, once it exists.

Credit is given as the name or handle and the link you prefer. You may also ask
to remain **anonymous**, and we will honour that without asking why: the
advisory will then read "reported by an anonymous researcher". We do not offer
payment, bounties, merchandise or priority support in exchange for reports, and
no donation buys a security outcome.

Duplicates are credited to the first report we receive with enough detail to
reproduce. If two reports arrive together and both are needed to understand the
issue, both reporters are credited. We ask that you do not publish your own
write-up before the advisory and the fixed release; once they are out, you are
free to publish whatever you like, and we will link to it from the advisory if
you send us the URL.

---

## 9. This project is defensive

Thot Secure is built exclusively for defense, and this is a constitutional
invariant of the project, not a marketing statement
([`GOVERNANCE.md`](GOVERNANCE.md#constitutional-invariants)).

**The project contains no offensive capability.** There is no exploit code, no
aggressive or high-rate scanning, no brute-forcing or password spraying, no
denial-of-service tooling, no "hack-back" or retaliation against third parties,
and no evasion or persistence mechanism designed to run on systems you do not
own. The `probe` collector audits only targets a tenant has explicitly declared
as owned in `config/targets.yaml`, and it refuses anything else.

**A security report that asks us to add an offensive feature is not a
vulnerability.** We will close it and point at this section. Conversely, a
report showing that the defensive guarantees *fail* is exactly what we want:

- a counter-measure that executes while `DRY_RUN=true`;
- an action that runs without approval, or outside the tenant's declared targets;
- a rollback that reports success without reversing the effect;
- an audit record that can be altered without breaking the chain;
- a guard-rail (hourly cap, cooldown, protected-target allow-list) that a policy
  can override;
- any path that reads or writes another tenant's data.

If you break one of those guarantees, you have found the most valuable class of
bug in this codebase. Please tell us privately.

**When testing, stay inside your own perimeter.** Do not run Thot Secure
collectors, probes or playbooks against infrastructure you do not own or are not
authorized to operate, and do not use a report as an excuse to test a third
party. Verify that your testing complies with the law and with the policies of
the networks you use; we cannot authorize anything beyond this project's own
code and deployments.

---

## 10. Hardening your own deployment

Most real-world Thot Secure incidents will be a deployment left on its development
defaults. Before exposing an instance:

1. Change `THOT_BOOTSTRAP_API_KEY` and set a strong, unique
   `THOT_SECRET_KEY`. Rotate every key that was created with a default.
2. Keep `THOT_DRY_RUN=true` until you have validated your policies against a
   non-production tenant.
3. Keep `THOT_AUTONOMY=supervised`: start in `manual`, move tenant by tenant.
4. Declare `config/targets.yaml` and populate `autonomy_allowlist` with your own
   protected infrastructure.
5. Terminate TLS at a reverse proxy or enable `THOT_TLS_ENABLED`, and never
   expose `/metrics` or the API to the public internet without authentication.
6. Restrict who holds `admin` keys; `admin` implies `responder`, which can
   change infrastructure.
7. Back up the SQLite database, and verify the audit chain
   (`GET /api/v1/audit/verify`, or `thotsecure audit verify`) on a schedule.
   A backup you have never verified is not a backup, and an audit chain you have
   never verified is not evidence.
8. Report and rotate any credential you believe was exposed, then open a
   security advisory if the exposure came from a defect here.

---

## 11. Supported versions

| Version | Supported | Notes |
|---|---|---|
| `0.1.x` | ✅ | Current MVP line; security fixes. |
| `< 0.1.0` | ❌ | Pre-release snapshots, no support. |

Until `1.0.0`, only the latest `0.1.x` patch release receives security fixes.
Fixes are released as patch versions, backported only to the current minor line.
