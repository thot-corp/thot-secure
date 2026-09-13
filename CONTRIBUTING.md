# Contributing to Thot Secure

Thanks for considering a contribution. Thot Secure is a **defensive** SOAR/CSPM
platform: it collects telemetry, detects, scores, decides and applies
*reversible* counter-measures to infrastructure you own or are authorized to
operate. Everything in this repository serves that goal.

Three documents complete this one and are worth reading before you start:

| Document | What it covers |
|---|---|
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Expected behaviour in every project space |
| [`GOVERNANCE.md`](GOVERNANCE.md) | Who decides what, how consensus and votes work |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability (never in a public issue) |

By participating you agree to follow the Code of Conduct. By submitting a
contribution you agree to the Developer Certificate of Origin (see
[DCO](#developer-certificate-of-origin-dco) below).

---

## 1. The one hard rule: no offensive capability

Thot Secure is defensive by construction, and this is a **constitutional
invariant** of the project (see [`GOVERNANCE.md`](GOVERNANCE.md#constitutional-invariants)).
A pull request will be closed without further review if it adds, or enables,
any of the following:

- exploit code, payloads, or proof-of-concept attacks against a third party;
- aggressive or high-rate scanning, credential brute-forcing, password
  spraying, or fuzzing of systems you do not own;
- denial-of-service, resource-exhaustion, or destructive actions;
- "hack-back", retaliation, or any automated action against an attacker's
  infrastructure that is not a local, reversible defensive control;
- data exfiltration, covert channels, persistence mechanisms, or evasion of
  detection on someone else's system;
- telemetry collection from endpoints outside the tenant's declared scope.

Legitimate defensive work that *looks* adjacent is welcome and reviewed on its
merits: detection rules for attacker techniques, hardening checks, safe
verification that a control is in place, parsers, and reporting.

Every action playbook must ship with a rollback. Every action must honour
`DRY_RUN=true`, which is the default.

---

## 2. Ways to contribute

You do not need to write Python to move this project forward.

- **Detection rules** — new YAML rules in `rules/`. High value, low
  entry cost. See [§7](#7-adding-a-detection-rule).
- **False-positive reports** — a rule that fires on legitimate traffic is a
  bug. Open a `false_positive.yml` issue.
- **Policies and playbooks** — decision logic in `policies/`, response
  procedures in `playbooks/`.
- **Documentation** — `docs/` (MkDocs Material), tutorials, translations.
- **SDKs** — `sdks/python`, `sdks/typescript`, `sdks/go`.
- **Deployment** — `deploy/` (Docker, Compose, Kubernetes, Helm, Terraform,
  Ansible).
- **Tests** — the suite in `tests/` is `unittest`-based and runs with the
  standard library alone.
- **Triage** — reproducing issues, labelling, closing duplicates. Ask for the
  triage role in an issue if you would like to help there.

Look for issues labelled
[`good first issue`](https://github.com/thot-corp/thot-secure/labels/good%20first%20issue)
and [`help wanted`](https://github.com/thot-corp/thot-secure/labels/help%20wanted).
If you want to work on something that is not tracked yet, open an issue first
so we can agree on the shape before you spend time on a patch.

---

## 3. Development setup

Requirements: **Python 3.11+** (CI covers 3.11, 3.12 and 3.13), `git`, and —
only for the optional React dashboard in `web/` — Node.js 20+.

```console
git clone https://github.com/thot-corp/thot-secure.git
cd thot-secure
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

python -m pip install -e ".[dev]"
```

The core (`thotsecure.core`) depends only on the standard library plus `pydantic`
and `PyYAML`. FastAPI, Jinja2 and uvicorn belong to the API layer. Please keep
that boundary intact: a heavy import in `thotsecure.core` will be caught in review.

Then install the git hooks:

```console
pre-commit install
pre-commit run --all-files
```

### Running the tests

The official command, and the one CI runs, is:

```console
python -m unittest discover -s tests -t . -v
```

`pytest` also works and is executed in CI for compatibility:

```console
pytest -q
```

Neither command requires network access or a running service: tests use
temporary SQLite databases, in-memory buses and local loopback servers.

### Linting and types

```console
ruff check .
ruff format --check .
mypy src
```

`mypy` is informational for now — it reports but does not block a merge while
the type coverage of the codebase catches up.

### Repository layout

```
src/thotsecure/     application package (core, storage, bus, audit, tenancy,
                  collectors, detection, scoring, decision, actions, reports,
                  api, ui, cli.py, sdk/)
rules/            detection rules (YAML, shipped with the product)
policies/         decision policies (YAML) + policies/rego/
playbooks/        action playbooks (YAML, action + rollback)
sdks/{python,typescript,go}/
web/              React + TypeScript dashboard (optional Vite build)
deploy/           Dockerfile, compose, k8s, helm, terraform, ansible
docs/             MkDocs Material sources (mkdocs.yml at the repository root)
content/          editorial artefacts (blog, forums, social, video)
tests/            unittest suite, pytest-compatible
```

---

## 4. Branching model

- **`main` is protected.** Direct pushes are disabled, force-pushes and
  deletions are rejected, and every change lands through a pull request that
  passes CI and has at least one maintainer approval.
- **Work on a branch in your own fork**, with a name that follows one of these
  prefixes:

  | Prefix | Use for |
  |---|---|
  | `feat/*` | new functionality (`feat/cloudflare-connector`) |
  | `fix/*` | bug fixes (`fix/audit-chain-race`) |
  | `rule/*` | detection rules (`rule/AO-WEB-042`) |
  | `docs/*` | documentation only |
  | `chore/*` | tooling, dependencies, CI |
  | `refactor/*` | internal change with no behaviour change |
  | `perf/*` | performance work |
  | `test/*` | tests only |
  | `hotfix/*` | urgent fix branched from a release tag |

- **Release branches** are cut as `release/x.y` from `main` when a release
  candidate is stabilised. Tags are annotated and named `vX.Y.Z`.
- Rebase on `main` rather than merging `main` into your branch, so the history
  stays linear and reviewable. Never rebase a branch that is already under
  review by someone else without telling them.

---

## 5. Commit messages — Conventional Commits

Thot Secure uses [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Release notes and version bumps are generated from the commit history, so the
format is not cosmetic.

```
<type>(<scope>)!: <description>

[optional body]

[optional footer(s)]
Signed-off-by: Your Name <you@example.com>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`. In addition, the project uses `rule` for a
detection-rule addition or change and `security` for a vulnerability fix.

**Scopes** mirror the package layout: `core`, `storage`, `bus`, `audit`,
`tenancy`, `collectors`, `detection`, `scoring`, `decision`, `actions`,
`reports`, `api`, `ui`, `cli`, `sdk`, `rules`, `policies`, `playbooks`,
`deploy`, `docs`, `web`, `ci`.

Examples:

```
feat(detection): add threshold aggregation on labels.src_ip
fix(audit): use canonical JSON for hash computation
rule(AO-WEB-042): detect path traversal in multipart filenames
docs(contributing): document the DCO workflow
ci(release): sign release SBOM with cosign keyless
```

A breaking change is signalled by `!` after the type or scope **and** by a
`BREAKING CHANGE:` footer. Security fixes are drafted privately and land with a
`security` type once the advisory is published.

---

## 6. Versioning — Semantic Versioning

Thot Secure follows [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) with the
usual pre-1.0 caveat, stated explicitly so there is no ambiguity:

| Change | Pre-1.0 (`0.y.z`) | From 1.0.0 |
|---|---|---|
| Breaking API, config, rule or policy schema change | minor bump (`0.y+1.0`) | major bump |
| New feature, backwards compatible | minor bump | minor bump |
| Bug fix, backwards compatible | patch bump | patch bump |
| Detection rule added | patch bump | patch bump |
| Documentation only | no release required | no release required |

While the project is pre-1.0, the frozen contract in
`docs/architecture/api-contract.md` governs the MVP: changing an endpoint path,
a JSON field name, an enum value or the rule/policy schema is a breaking change
even in `0.y`, and it is called out under `### Changed → BREAKING` in
`CHANGELOG.md`.

Every user-visible change must add an entry under `## [Unreleased]` in
[`CHANGELOG.md`](CHANGELOG.md) using the [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
Dates are `YYYY-MM-DD`.

---

## 7. Adding a detection rule

Detection rules are the most common contribution. The format is frozen in
[§5 of the interface contract](docs/architecture/api-contract.md); a rule that
does not validate is rejected at load time with a diagnostic and never breaks
the engine.

**Procedure**

1. **Pick the next free identifier** in the family you are extending.
   Identifiers are `AO-<FAMILY>-<NNN>`: `AO-WEB-###` for HTTP/web,
   `AO-CLOUD-###` for cloud and container configuration, `AO-DEP-###` for
   dependencies and supply chain, `AO-TLS-###` for transport and certificates,
   `AO-AUTH-###` for authentication and session abuse, `AO-HOST-###` for host
   and system telemetry. Identifiers are never reused or renumbered.
2. **Check for an existing rule** covering the same behaviour. Extend it with
   `any`/`all` branches instead of shipping a near-duplicate.
3. **Write the rule** in `rules/<family>/AO-XXX-NNN.yaml`.
4. **Validate it locally**:

   ```console
   thotsecure rules validate --path rules
   ```

   The command exits `0` when every rule in the tree is valid, `1` on error and
   `2` on usage error, so it is safe to use in scripts and hooks.
5. **Add tests** in `tests/test_rules_engine.py` (or a new
   `tests/test_rules_<family>.py`): one case that must match, one look-alike
   case that must **not** match, and — if you use `threshold` — one case below
   and one above the threshold. Rules without a negative test are not merged.
6. **Document the false positives you expect** in the `false_positives:` list.
   This field is read by humans during triage and by the `false_positive.yml`
   issue template.
7. **Reference public sources**: an OWASP Top 10 / ASVS category, a MITRE
   ATT&CK technique identifier in both `mitre:` and `tags` (`mitre:T1190`), and
   at least one authoritative URL in `references:`.
8. **Open a pull request** titled `rule(AO-XXX-NNN): <short title>` and use the
   `rule_proposal.yml` issue template if you would rather discuss the idea
   before writing code.

**Example — a complete, conformant rule**

```yaml
id: AO-WEB-001
title: SQL injection attempt in query string
description: Détecte les motifs d'injection SQL dans les paramètres de requête.
status: stable            # draft | test | stable | deprecated
severity: high            # info | low | medium | high | critical
confidence: 0.85          # 0.0 → 1.0
enabled: true
tags: [web, owasp:a03, mitre:T1190]
source_types: [web_probe, log_tail]
kinds: [http.request]
match:
  all:                    # logical AND
    - field: labels.path
      op: regex
      value: "(?i)(union[\\s/*]+select|or\\s+1=1|sleep\\(\\d+\\)|benchmark\\()"
  any: []                 # logical OR (at least one)
  not: []                 # logical NOT (none)
  threshold:              # optional aggregation
    count: 3
    window_seconds: 60
    group_by: [labels.src_ip, labels.path]
dedup:
  key: [rule_id, labels.src_ip]
  ttl_seconds: 900
risk:
  base: 60
  asset_criticality: 1.0
false_positives:
  - Requêtes contenant le mot "union" dans un champ de recherche libre.
remediation: Bloquer l'IP source au WAF 1 h, vérifier les logs applicatifs, patcher l'entrée.
references:
  - https://owasp.org/Top10/A03_2021-Injection/
```

**Field and operator reference**

- `field` is a dotted path into the event: `labels.<name>`, `payload.<name>`,
  `source.host`, `kind`, `ts`, `severity_hint`, `tenant_id`. `labels` is a flat
  map of scalars, which is what makes it usable for grouping and dedup keys.
- Supported `op` values: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`,
  `contains`, `icontains`, `startswith`, `endswith`, `regex`, `exists`, `cidr`,
  `len_gt`, `len_lt`.
- `regex` uses Python `re` semantics and is compiled with an execution timeout;
  avoid catastrophic backtracking, prefer a bounded character class over a
  nested quantifier, and anchor where you can.
- `match.all` is an AND, `match.any` an OR, `match.not` an exclusion. Empty
  lists are valid and mean "no constraint".
- `threshold` aggregates matching events into one finding, grouped by
  `group_by`, over a sliding `window_seconds` window.
- Keep `dedup.key` narrow enough that unrelated sources do not collapse into a
  single finding, and `dedup.ttl_seconds` consistent with the noise level.
- Use `status: draft` or `test` for a rule that still needs field validation;
  only `stable` rules are announced in release notes. `deprecated` rules stay
  in the tree, disabled, so that history and identifiers remain traceable.

**Style rules for rules**

- English identifiers, titles and descriptions; the shipped library is
  language-neutral and consumed by SIEM/SOAR pipelines.
- `title` describes the observed behaviour, not the attacker ("SQL injection
  attempt in query string", not "SQL hacker detected").
- No rule may trigger an action by itself: rules produce findings, policies
  decide, playbooks act. Autonomy is configured per tenant, never in a rule.
- Prefer precise signals over broad pattern lists; a rule that fires on every
  `404` will be closed.

---

## 8. Adding a policy or a playbook

- **Policies** live in `policies/*.yaml` and follow the schema in
  [§6 of the contract](docs/architecture/api-contract.md). Validate with
  `thotsecure policies validate`. Remember that the execution guard-rails
  (per-tenant hourly cap, per-target cooldown, protected targets, global
  `dry_run`, out-of-scope targets requiring approval) are applied *after* your
  policy and cannot be overridden by it.
- **Playbooks** live in `playbooks/*.yaml` and follow
  [§7 of the contract](docs/architecture/api-contract.md). A playbook without a
  `rollback:` block is rejected: reversibility is not optional. New connectors
  must work in simulated mode when unconfigured, returning a rollback token and
  logging `simulated: true`.
- Any playbook listed in `src/thotsecure/actions/` must be reachable through the
  CLI and the API, and covered by `tests/test_actions_rollback.py`.

---

## 9. Pull request requirements

Before you request review, every item below must hold. The pull request
template repeats the list as a checklist — please actually tick it, rather
than ticking it by reflex.

- [ ] **Tests pass** locally: `python -m unittest discover -s tests -t . -v`
      (and `pytest` if you touched anything importable).
- [ ] **New behaviour is tested.** A bug fix comes with a regression test that
      fails before the fix. A new rule comes with positive, negative and
      threshold tests.
- [ ] **`thotsecure rules validate`** passes if `rules/` changed, and
      **`thotsecure policies validate`** passes if `policies/` changed.
- [ ] **No secrets.** No API keys, tokens, passwords, private keys, real
      customer hostnames or production telemetry — not in the diff, not in
      fixtures, not in commit messages, not in screenshots.
- [ ] **No offensive capability**, as defined in [§1](#1-the-one-hard-rule-no-offensive-capability).
- [ ] **Every action is reversible**: a new or modified playbook ships with a
      working rollback and a test that exercises it.
- [ ] **DCO signed off** on every commit (`git commit -s`).
- [ ] **`CHANGELOG.md` updated** under `## [Unreleased]` for any user-visible
      change, and `docs/` updated when behaviour, configuration or the CLI
      changes.
- [ ] **Conventional Commit** messages, and a branch name matching
      [§4](#4-branching-model).
- [ ] **Focused diff.** One logical change per pull request; unrelated
      reformatting makes review slower and hides regressions.
- [ ] **Safe defaults preserved.** Do not flip `DRY_RUN`, weaken the approval
      gate, or relax multi-tenant isolation to make a test pass.

### Review process

- A reviewer from the relevant area, listed in [`CODEOWNERS`](CODEOWNERS), is
  requested automatically. At least one maintainer approval is required, and
  any `@thotsecure/security` review requested on a security-sensitive path is
  blocking.
- Reviewers aim to give a first response within **3 working days**; if nobody
  has responded after a week, a polite ping on the pull request is welcome.
- Maintainers merge with a merge commit for feature work so that the changelog
  can be generated from the branch. Squashing is fine for small fixes.
- Address review comments with new commits rather than force-pushes, so that
  reviewers can see what changed since their last pass.
- If a discussion stalls, see
  [Conflict resolution](GOVERNANCE.md#conflict-resolution) — the process is
  written down precisely so disagreements do not depend on who is loudest.

---

## 10. Developer Certificate of Origin (DCO)

**Thot Secure uses the DCO and does not require a CLA.** There is no copyright
assignment, no form to sign and no bot that blocks you until a legal document
is filed: you keep the copyright on your contribution, and you certify that you
have the right to submit it under the project's license.

You certify by adding a `Signed-off-by` trailer to every commit, which
`git commit -s` does for you:

```console
git commit -s -m "fix(detection): handle null labels in regex operator"
```

The trailer must be a real name and a reachable address:

```
Signed-off-by: Jane Doe <jane@example.com>
```

This is the [Developer Certificate of Origin 1.1](https://developers.google.com/open-source/dco):

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

To add a missing trailer to the last commit:

```console
git commit --amend -s --no-edit
```

For a range of commits, `git rebase --signoff <base>` adds the trailer to each
one. Contributions whose sign-off is missing are flagged by the DCO check and
cannot be merged until it is present.

**Licensing of contributions.** Thot Secure is released under the
[Apache License 2.0](LICENSE). By submitting a contribution you agree that it
is licensed under the same terms, per Section 5 of that license, and you
acknowledge the attribution terms in [`NOTICE`](NOTICE). Do not submit code you
cannot license this way; if you are porting logic from another project, say so
in the pull request and check its license compatibility first.

---

## 11. `good first issue`

Issues that are self-contained, documented and safe for a newcomer are labelled
`good first issue`. To keep that label honest, a maintainer adding it commits
to:

- writing the acceptance criteria in the issue body;
- pointing at the exact files to touch;
- naming a person who will review the pull request;
- keeping the scope under roughly a day of work, with no design decision left
  open.

If you pick one up and get stuck, ask in the issue. A stalled
`good first issue` is a maintainer problem, not a contributor problem — say so
and we will fix the issue description rather than leave you guessing.

---

## 12. Coding style

- **Python**: `ruff` (lint + `ruff format`), line length and ruleset from
  `pyproject.toml`. Public functions have type hints; `mypy src` should not get
  worse. Docstrings on public modules, classes and functions.
- **Core boundary**: `thotsecure.core` imports the standard library plus
  `pydantic` and `PyYAML` only.
- **YAML**: 2-space indentation, no tabs, LF line endings, a trailing newline,
  and a document start marker only when it adds clarity. `yamllint` runs in
  pre-commit with the repository configuration.
- **Markdown**: `markdownlint` rules as configured, ATX headings, one
  top-level heading per file, fenced code blocks with a language.
- **TypeScript / React** (`web/`): the configured ESLint and `tsc --noEmit`
  checks; the dashboard build is optional and the embedded Jinja2 console must
  keep working without Node.
- **Errors**: raise the project's typed exceptions from `thotsecure.core.errors`
  so the API can map them onto the documented error codes.
- **Logging**: structured JSON in production, never log credentials, API keys
  or raw payloads that may contain personal data.
- **Time and identifiers**: UTC everywhere, ISO 8601 with `Z`, UUIDv4 for new
  identifiers.

---

## 13. Support and funding

This is a volunteer-maintained project; nobody is paid to review a pull
request. Thank you for your patience.

Thot Secure accepts voluntary donations with **no counterpart and no influence on
the roadmap** — donations never buy a merge, a feature, a priority or a
support guarantee. The official addresses are listed in
[`.github/FUNDING.yml`](.github/FUNDING.yml), in the support page of the
product and in [`docs/support.md`](docs/support.md). Verify them from the
repository: Thot Secure will never ask for a private key, a seed phrase, or a
payment to unblock an issue or a release.

The single most useful contribution is not money: it is a detection rule with
a negative test, or a precise bug report.
