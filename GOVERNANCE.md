# Thot Secure Governance

This document describes how the Thot Secure project is governed: who has which
responsibilities, how decisions are made, how people join and leave the
maintainer group, and which decisions cannot be made by a simple majority.

It is deliberately explicit. A security project whose decision process is
"whoever is loudest wins" cannot be trusted to keep its guarantees, so the
process is written down and applies to everyone, including the people who wrote
it.

- Roles and responsibilities → [§2](#2-roles)
- How everyday decisions happen → [§3](#3-decision-making)
- Nominations → [§4](#4-nomination-process)
- Removing a maintainer → [§5](#5-removal-and-emeritus-status)
- Disagreements → [§6](#6-conflict-resolution)
- License changes → [§7](#7-license-changes)
- Roadmap → [§8](#8-public-roadmap)
- The invariants nobody can vote away → [§9](#9-constitutional-invariants)

---

## 1. Scope and principles

Thot Secure is a **defensive** SOAR/CSPM platform, licensed under the
[Apache License 2.0](LICENSE) and developed in the open on GitHub. Governance
rests on five principles:

1. **Defense only.** The project's defining constraint is that it has no
   offensive capability. This is an architectural invariant, not a
   configuration option.
2. **Safe by default.** `DRY_RUN=true`, `AUTONOMY=supervised`, an approval gate
   in front of critical actions, and reversible-by-construction actions. A pull
   request that weakens a default carries the burden of proof, not the reviewer.
3. **Lazy consensus first.** Most changes need no vote: they need a proposal,
   a fair window for objection, and no sustained objection. Votes are reserved
   for the cases listed in [§3](#3-decision-making).
4. **Merit and demonstrated work.** Roles are earned through sustained, reviewed
   contribution, not through funding, seniority, employer, or volume of
   comments. There is no membership fee, and no company owns the project.
5. **Transparency.** Decisions, their rationale and their votes are recorded in
   public issues. The only exceptions are security vulnerabilities before
   disclosure and conduct reports, which are handled privately.

### Current maintainers

See [`MAINTAINERS.md`](MAINTAINERS.md) for the live roster, areas of ownership
and `.github/CODEOWNERS` for the machine-readable path-to-team mapping.

---

## 2. Roles

Roles are additive: every maintainer is also a reviewer, a triager and a
contributor. Progression is by invitation and demonstrated contribution; there
is no application form and no interview.

### 2.1 Contributor

Anyone who opens an issue, reports a false positive, writes a detection rule,
sends a pull request, improves documentation or helps in discussions. No
commitment of time is expected or implied. Contributors are bound by the
[Code of Conduct](CODE_OF_CONDUCT.md) and certify their commits under the
[Developer Certificate of Origin](CONTRIBUTING.md#10-developer-certificate-of-origin-dco).

### 2.2 Triager

**Adds value by:** reproducing reports, labelling issues, closing duplicates and
support questions, keeping the backlog honest, and routing security reports to
the private channel instead of answering them in public.

**Gains:** the ability to label, assign, close and reopen issues and to
triage incoming pull requests (requesting changes, but not approving).

**Expected commitment:** a few hours a month is genuinely useful. There is no
minimum.

**Becoming one:** a maintainer nominates a contributor who has shown good
judgement in issue threads for at least a month. Triagers are listed in
[`MAINTAINERS.md`](MAINTAINERS.md) and granted the `triage` repository role.

### 2.3 Reviewer

**Adds value by:** reviewing pull requests in a defined area, with an actual
read of the diff; enforcing the invariants and the interface contract; asking
for tests, rollback paths and changelog entries; and approving when the change
is genuinely ready.

**Gains:** approval rights in their area. `CODEOWNERS` requests their review
automatically, and their approval counts toward the two-approval requirement for
breaking changes.

**Specific reviewer areas** mirror the package layout:

| Area | Scope |
|---|---|
| Detection | `rules/`, `src/thotsecure/detection/`, `src/thotsecure/scoring/` |
| Actions | `playbooks/`, `src/thotsecure/actions/`, `src/thotsecure/decision/` |
| API & SDK | `src/thotsecure/api/`, `src/thotsecure/sdk/`, `sdks/` |
| Data & audit | `src/thotsecure/storage/`, `src/thotsecure/audit/`, `src/thotsecure/bus/`, `src/thotsecure/tenancy/` |
| Collectors | `src/thotsecure/collectors/` |
| UI | `src/thotsecure/ui/`, `web/` |
| Deployment | `deploy/` |
| Docs | `docs/`, `content/`, root Markdown |

**Becoming one:** sustained, high-quality contributions to an area, plus review
comments that other maintainers find useful. Nominated per
[§4](#4-nomination-process).

### 2.4 Maintainer

**Adds value by:** holding merge rights and the final responsibility for the
repository's health — releases, security advisories, roadmap, contributor
experience, CI, and the invariants.

**Gains:** write access, merge rights, release and tag rights, label and
milestone administration, and a vote in [§3](#3-decision-making) and
[§9](#9-constitutional-invariants) decisions. Maintainers have GitHub
`maintain` or `admin` permission depending on their responsibilities; `admin` is
granted only to maintainers who hold the security or release duty.

**Responsibilities, explicitly:**

1. Keep `main` green and released: do not merge red, do not leave a release
   half-published.
2. Uphold the [constitutional invariants](#9-constitutional-invariants) even
   when a popular feature request conflicts with them.
3. Meet the security commitments in [`SECURITY.md`](SECURITY.md) — 72-hour
   acknowledgement, 7-day triage — or hand the report to another maintainer who
   can.
4. Review incoming pull requests in your area, or explicitly delegate.
5. Keep [`ROADMAP.md`](ROADMAP.md) and [`CHANGELOG.md`](CHANGELOG.md) current;
   a stale roadmap is treated as a bug.
6. Act on Code of Conduct reports that reach you.
7. Answer at least a "still active?" ping within 30 days. Absence is fine and
   expected; silence is not.

**Becoming one:** see [§4](#4-nomination-process).

### 2.5 Security maintainer

A maintainer holding the security duty: triages the private GitHub Security Advisories,
handles private advisories, assigns severity and CVSS vectors, requests CVEs,
coordinates disclosure and writes the advisory. At least **two** maintainers
must hold this duty at any time so that a report is never blocked on one
person's availability.

### 2.6 Release maintainer

A maintainer holding the release duty for a cycle: cuts tags, verifies that the
release workflow produced signed artefacts, an SBOM and an attestation, and
extracts the release notes from [`CHANGELOG.md`](CHANGELOG.md). The release duty
rotates, and its holder must be a security maintainer, because releases are the
channel through which fixes reach users.

### 2.7 Emeritus

Maintainers who step back after substantial service are listed as `EMERITUS` in
[`MAINTAINERS.md`](MAINTAINERS.md). See [§5](#5-removal-and-emeritus-status).

---

## 3. Decision-making

### 3.1 Lazy consensus (the default)

**Lazy consensus is the default mechanism for every decision in this project.**
It means: propose, wait, and proceed unless someone objects with a reason.

The mechanism:

1. **Propose** in a public issue or pull request, stating the change, the
   motivation and the consequences. Apply the `lazy-consensus` label.
2. **Wait** for the review window: **7 calendar days** for ordinary changes,
   **14 days** for anything touching the interface contract, the invariants, the
   packaging, or a released schema.
3. **Object** within that window, if you have a substantive objection. An
   objection must state the technical or project reason, not just a preference:
   "this breaks single-tenant installs because X" is an objection; "I do not
   like the name" is a comment, not an objection.
4. **Resolve** the objection: the proposer addresses it and the objector
   withdraws it, or the discussion continues, or it escalates to a vote.
5. **Proceed.** If the window closed with no unaddressed objection, any
   maintainer may merge or implement.

Silence is consent under this rule. That is why the labels and the windows
exist: nobody should discover after the fact that a decision was taken in a
channel they do not read. Important proposals are also announced in the
repository's Discussions category so that the window is visible.

### 3.2 When a vote is required

A vote is required for:

- any change to an interface-contract field, endpoint path, enum value, or
  rule/policy/playbook schema;
- a breaking change in a released version;
- adding or removing a maintainer;
- a change to the license or to the `NOTICE` terms
  ([§7](#7-license-changes));
- a change to this governance document;
- amending a [constitutional invariant](#9-constitutional-invariants);
- adopting a new runtime dependency for `thotsecure.core`;
- changing the official donation addresses in `.github/FUNDING.yml`;
- any decision where lazy consensus failed, i.e. where an objection stands after
  discussion;
- creating a foundation, transferring repository ownership, or adopting a
  trademark policy.

Everything else is lazy consensus.

### 3.3 Vote mechanics

| Parameter | Value |
|---|---|
| Eligible voters | Maintainers listed as active in `MAINTAINERS.md` |
| Quorum | **Two thirds** of active maintainers must cast a vote |
| Ordinary threshold | **Simple majority** of votes cast |
| Invariant amendment threshold | **Two thirds** of votes cast (see [§9](#9-constitutional-invariants)) |
| Voting window | **7 days** for ordinary votes, **14 days** for license and invariant votes |
| Ballot | `+1` (approve), `-1` (block, with a written technical reason), `abstain` |
| Location | A public issue, with the result and the tally recorded in a final comment |

Rules that make votes mean something:

- A `-1` **must** carry a written technical or project-level reason. An
  unexplained `-1` is recorded as an abstention.
- A single `-1` on an ordinary vote does not block: the majority decides. But a
  maintainer may escalate to [§6](#6-conflict-resolution) rather than let a
  majority override a well-argued technical objection, and that escalation is
  not penalised — it is the mechanism working.
- A maintainer who is the author of the proposal may vote, but the tally is
  published with authorship noted.
- A maintainer who does not vote within the window is not counted toward quorum
  for that vote, but also may not object to the outcome afterwards.
- Ties fail. The proposal returns to discussion rather than being decided by
  seniority, by a coin toss, or by whoever merges first.
- Withdrawn votes are recorded as abstentions, with the change visible, so a
  tally cannot be quietly reshaped.
- Votes on security issues happen privately, in the advisory, and are summarised
  publicly once the advisory is published.

### 3.4 Emergency decisions

A security fix under active exploitation, or a repository compromise, may
require immediate action without the windows above. The security maintainers
acting together may:

- merge a fix directly, with a retrospective review afterwards;
- revoke credentials, tokens and keys;
- force-push to a protected branch to remove a leaked secret or a malicious
  commit, and then publish exactly what was removed and why.

Emergency actions must be disclosed in an issue within 7 days, including the
participants and the reasoning. Emergency authority does not extend to changing
an invariant, a license, or a donation address — those wait for their process.

---

## 4. Nomination process

Any active maintainer may nominate a contributor for `triager`, `reviewer` or
`maintainer`, by any private channel to the maintainer group. Nominations are
not a secret ballot among strangers: the nominee's public work *is* the
application.

**Procedure**

1. **Nomination** — a maintainer opens a private discussion (GitHub team
   discussion or an email to the maintainer group) stating the nominee, the
   role, the area, and concrete evidence: merged pull requests, reviews, triage,
   rule contributions, incidents handled.
2. **Private discussion** — **7 days**. Maintainers may raise concerns. A
   concern about conduct is handled per the [Code of Conduct](CODE_OF_CONDUCT.md)
   and is not debated in the thread with the nominee present.
3. **Vote** — per [§3.3](#33-vote-mechanics): quorum two thirds of active
   maintainers, **two thirds** of votes cast in favour for `maintainer` and
   `reviewer`, simple majority for `triager`.
4. **Acceptance** — the nominee is asked, and may decline without the
   nomination being recorded publicly. Nobody is drafted into a maintainer role.
5. **Onboarding** — access is granted and recorded, and the new role is added to
   [`MAINTAINERS.md`](MAINTAINERS.md) in the same pull request that records the
   vote. The `CODEOWNERS` file is updated if the role implies an area.
6. **Announcement** — a public post in Discussions, unless the person prefers
   not to be announced, plus a line in the `### Added` section of the
   `[Unreleased]` changelog entry when relevant.

**Onboarding checklist** for a new maintainer:

- [ ] 2FA enabled on the GitHub account, with recovery codes stored safely.
- [ ] Access to the maintainer discussion channel.
- [ ] Understanding of the [constitutional invariants](#9-constitutional-invariants)
      and the [`SECURITY.md`](SECURITY.md) commitments.
- [ ] A named mentor among the existing maintainers for the first cycle.
- [ ] `CODEOWNERS` and `MAINTAINERS.md` updated.
- [ ] Read access to security advisories granted if the security duty applies,
      together with a run-through of the advisory workflow.

**Eligibility.** Sustained contribution over time, in the area concerned, with
good judgement. There is no fixed number of commits and no tenure clock; the
question is whether the project would be better with this person holding the
role. A contributor whose only activity is a large donation is **not** eligible
on that basis — funding never confers a role, access, or influence over the
roadmap.

---

## 5. Removal and emeritus status

### 5.1 Voluntary step-down (emeritus)

A maintainer may step back at any time, for any reason or none, by saying so.
They are moved to `EMERITUS` in [`MAINTAINERS.md`](MAINTAINERS.md), keeping the
credit for their work. Access is reduced to what they ask to keep; most emeritus
maintainers keep triage access and no merge rights.

Emeritus maintainers are welcome back. A returning emeritus maintainer is
restored by a simple majority vote, without a second nomination period, if the
return happens within 12 months; after that, the normal
[nomination process](#4-nomination-process) applies.

### 5.2 Involuntary removal

A maintainer may be removed for:

- **persistent inactivity** — no response to a "still active?" ping for 30 days,
  or no substantive activity for 6 months, with two attempts made to reach them
  through separate channels;
- **repeated failure to uphold responsibilities** — merging red, ignoring
  security reports, or leaving releases broken, after written feedback;
- **sustained conduct violations**, per the enforcement guidelines of the
  [Code of Conduct](CODE_OF_CONDUCT.md);
- **acting against the invariants**, for example by merging an offensive
  capability or removing a guard-rail without the required vote;
- **a security compromise or a credible risk of one** — a compromised account,
  or refusal to enable 2FA.

Involuntary removal requires a **two-thirds vote of active maintainers**, a
quorum of two thirds, and a **14-day** discussion that includes the person
concerned, who must be told of the concerns and given the opportunity to
respond. Except in a conduct case or a security incident, the discussion is
public and the outcome is recorded with its reasoning.

In an immediate-risk case (a compromised account, an active malicious commit),
access may be suspended first and the vote held within 7 days. The suspension
and its reason are recorded.

Removal from a role is not a ban from the community: a removed maintainer may
keep contributing as a contributor unless the Code of Conduct process says
otherwise.

### 5.3 Area ownership

If a maintainer or reviewer responsible for an area becomes inactive, the area
is reassigned by lazy consensus in `CODEOWNERS`. An orphaned area with no
reviewer is a project-level problem and is tracked in
[`ROADMAP.md`](ROADMAP.md) until it is resolved — an unreviewed path is where
bad code hides.

---

## 6. Conflict resolution

Disagreements are normal and useful; the process below exists so they resolve on
the merits.

**Escalation ladder** — stop at the first step that produces a resolution:

1. **Direct discussion** on the issue or pull request. Assume competence and
   good faith. Quote the technical claim, not the person.
2. **Written summary.** If a thread exceeds roughly 20 comments without
   converging, any participant may open a dedicated issue titled
   `Decision: <question>` containing a neutral summary of both positions, the
   evidence for each, and the options. This alone resolves a surprising number
   of disputes, because writing the other side's argument down is hard.
3. **Maintainer discussion.** Maintainers discuss among themselves, publicly
   where possible, and propose a resolution with its rationale. The proposer of
   the original change gets the right of reply before the decision is final.
4. **Vote.** Per [§3.3](#33-vote-mechanics). A tie fails, which means the status
   quo wins and the proposal must be reworked.
5. **Mediation.** For a persistent impasse that is not about conduct, the
   maintainers may ask an uninvolved maintainer — or, if none is available, a
   respected member of the wider security community — to mediate. The mediator
   publishes a recommendation; the maintainers act on it by vote.
6. **Conduct matters** leave this ladder and go to the Code of Conduct process
   by direct message on GitHub. Conduct is never decided by a technical vote.

**Principles that apply throughout:**

- **Forking is a legitimate outcome.** Thot Secure is Apache-2.0. If a
  disagreement cannot be resolved, forking is permitted and will not be
  obstructed: the license grants that right, and this document acknowledges it.
  A maintainer must not retaliate against a fork, its maintainers, or its users.
- **No decision by exhaustion.** Nobody wins by replying more often, by waiting
  for the other person to sleep, or by reopening a settled issue.
- **Reversibility.** When evidence is missing and the change is cheap to
  reverse, prefer a time-boxed trial with an explicit review date over a
  permanent argument.
- **Record the reasoning.** Every escalated decision ends with a comment that
  states what was decided, why, and what would change our mind. A future
  contributor should be able to reconstruct the decision without reading the
  whole thread.
- **Technical objections are protected.** A maintainer who blocks a decision for
  a stated technical reason is never removed for it, and is never pressured to
  withdraw it.

---

## 7. License changes

Thot Secure is licensed under the **Apache License, Version 2.0** (see
[`LICENSE`](LICENSE)), with attribution terms in [`NOTICE`](NOTICE). This has
been true since the first commit, and the project intends it to remain true.

The project also states, as an invariant, that it will stay
**OSI-approved open source** and that no version of Thot Secure will be relicensed
into a proprietary, source-available-restricted or "open core with a closed
crust" model.

**Procedure for any license change:**

1. **Public proposal** in an issue, with the exact new license text, the
   motivation, a compatibility analysis, and the consequences for existing
   users, distributors, and package ecosystems.
2. **Public comment period of at least 30 days**, announced in Discussions.
3. **Supermajority vote**: quorum of two thirds of active maintainers, **two
   thirds of votes cast in favour**. A license vote is one of the few decisions
   where a single `-1` with a technical reason forces escalation to
   [§6](#6-conflict-resolution) before the result is applied.
4. **Contributor consent is required.** The
   [DCO](CONTRIBUTING.md#10-developer-certificate-of-origin-dco) certifies the
   right to submit code under the project's license; it is **not** a copyright
   assignment and it does **not** authorise relicensing. Any license change
   therefore requires either the explicit consent of every copyright holder
   whose code is still in the tree, or the removal of that code. The proposal
   must state which approach is taken, and the resulting list must be public.
5. **Recorded** in this file, in [`NOTICE`](NOTICE), in `LICENSE`, and as a
   `BREAKING CHANGE` entry under `### Changed` in
   [`CHANGELOG.md`](CHANGELOG.md).

**Forbidden changes**, which no vote can carry:

- relicensing to a license that is not OSI-approved;
- adding terms that restrict defensive use, auditing, benchmarking, or forking;
- adding a contributor license agreement that assigns copyright;
- changing the license of `rules/`, `policies/` or `playbooks/` to something
  more restrictive than the code they configure, since those artefacts are
  meant to be reused by defenders.

**Dual licensing.** The project does not offer a proprietary dual license, and
will not: a defensive tool that is only fully available to paying customers is
not the tool this project set out to build.

**Dependency licensing.** New runtime dependencies must be OSI-approved and
compatible with Apache-2.0 (permissive licenses such as MIT, BSD, ISC,
Apache-2.0; weak copyleft such as MPL-2.0 or LGPL only with a recorded
rationale and after a vote). Strong copyleft (GPL, AGPL) in `thotsecure.core` is
not accepted. The SBOM produced by the release workflow is the authoritative
inventory, and license scanning is part of CI.

---

## 8. Public roadmap

The roadmap is public and lives in [`ROADMAP.md`](ROADMAP.md). Rules:

- **Every item carries a status and an acceptance criterion.** "Improve
  performance" is not a roadmap item; "p95 ingestion latency under 50 ms for
  500-event batches on a 2-vCPU host, measured by a benchmark in CI" is.
- **Anybody may propose an item**, by opening an issue that a maintainer later
  folds into the roadmap. Proposals that contradict an invariant are declined
  with a pointer to [§9](#9-constitutional-invariants), not silently dropped.
- **Order of work** is decided by maintainers through lazy consensus, weighing
  security impact, user demand, contributor availability, and reversibility.
- **Releases are cut from the roadmap, not from announcements.** A target
  version in the roadmap is an intention, not a commitment or a date. Nothing
  here is a service-level agreement; there is no paid support tier, and no
  donation changes an item's position.
- **Reviewed quarterly**, in a public `Roadmap review - <quarter>` issue:
  statuses are updated, completed items move out, and anything that will not be
  done is removed with a reason. Items that have silently rotted for two
  consecutive reviews are removed.
- **Deprecations are announced a release ahead**, with a `Deprecated` changelog
  entry and a migration note, never with a surprise removal.
- **Long-form design work** for a roadmap item happens as an RFC issue before
  implementation, so that the shape is agreed before the code is written.

---

## 9. Constitutional invariants

These are the rules that define the project. They are above lazy consensus,
above a simple majority, and above convenience. Changing one is possible — that
is what a two-thirds majority is for — but the change must survive a public
argument first.

**A1. No offensive capability.** Thot Secure contains no exploit code, no
aggressive or high-rate scanning, no brute-forcing or credential attacks, no
denial-of-service or destructive capability, no hack-back or retaliation
against third parties, no data exfiltration, and no collection or action outside
a tenant's declared scope. No vote, no sponsor, no customer and no donation can
change this. See [Amendment limits](#amendment-limits) below.

**A2. Safe by default.** `THOT_DRY_RUN=true` and
`THOT_AUTONOMY=supervised` are the shipping defaults. Raising autonomy is an
explicit, per-tenant, auditable decision.

**A3. Every action is reversible.** A playbook without a working rollback is a
bug. Rollback must actually reverse the effect, not merely report success, and
the claim is tested in CI.

**A4. Nothing critical happens without approval or explicit autonomy.** Every
critical action passes through `require_approval`, or through an `auto` mode
that the tenant has explicitly enabled, and is recorded with `actor`,
`policy_id`, `before` and `after`.

**A5. Strict tenant isolation.** No caller ever reads or writes another
tenant's data, and this is tested in CI on every pull request.

**A6. Tamper-evident audit.** The audit log is append-only and hash-chained;
verification is exposed (`GET /api/v1/audit/verify`) and export to a SIEM is
supported. Tampering must be detectable.

**A7. Guard-rails are not configurable away by a policy.** The per-tenant hourly
cap, the per-target cooldown, protected targets, the global `dry_run` override,
and the approval requirement for out-of-scope targets are enforced by the engine
and cannot be overridden by a policy file.

**A8. The core stays lean and auditable.** `thotsecure.core` depends on the
standard library plus `pydantic` and `PyYAML` only. API-layer frameworks stay in
the API layer.

**A9. Declared scope only.** Collectors, probes and actions operate only on
targets a tenant has explicitly declared. There is no default target, and no
"scan the internet" mode.

**A10. Apache-2.0, permanently open.** The project stays OSI-approved and
permissively licensed, with no proprietary dual license, per
[§7](#7-license-changes).

### Amending an invariant

1. **Public RFC issue**, stating the invariant, the exact proposed wording, the
   technical motivation, and the security consequences of the change.
2. **Public comment period of at least 14 days**, announced in Discussions.
3. **Vote**: quorum of two thirds of active maintainers, and **at least two
   thirds of votes cast in favour**. A `-1` with a written technical reason
   forces escalation to [§6](#6-conflict-resolution) before the amendment takes
   effect.
4. **Documentation**: the change is recorded in this file with its rationale and
   the date, mirrored in [`SECURITY.md`](SECURITY.md) and
   [`NOTICE`](NOTICE) where the invariant is restated, and noted under
   `### Changed` in [`CHANGELOG.md`](CHANGELOG.md).

### Amendment limits

Some amendments are not available at any threshold:

- **A1 cannot be amended to permit an offensive capability.** Clarifying its
  wording, tightening its scope, or adding a new prohibition is allowed and
  requires the two-thirds vote above. Adding, enabling, or permitting offensive
  capability is **never** permitted — not by vote, not by unanimity, not by
  sponsor request, and not in the name of "red teaming", "research", "testing
  the defenses of customers", or "feature parity with competitors". A
  contributor who wants that capability must fork the project under a different
  name, and this document grants that right explicitly while stating that such a
  fork is not Thot Secure.
- **A5, A6 and A7 cannot be amended to make a guarantee advisory rather than
  enforced.** Tenant isolation, audit integrity and the guard-rails may be
  strengthened, and their implementation may change; they may not be downgraded
  to "best effort", to an opt-in setting, or to documentation-only promises.
- **A10 cannot be amended to a non-OSI license**, per
  [§7](#7-license-changes).

A pull request that violates an invariant may be closed by any maintainer
without a vote, with a link to the invariant and an invitation to discuss the
invariant itself through the amendment process above.

---

## 10. Changes to this document

Amendments to `GOVERNANCE.md` follow the process for amending an invariant when
they touch [§9](#9-constitutional-invariants), and the ordinary vote process
otherwise: a public proposal, a 7-day comment window, a quorum of two thirds and
a simple majority, announced in Discussions and recorded in the `[Unreleased]`
changelog section.

The changelog entry is the audit trail for governance itself, and it is the
reason governance changes are listed there alongside code changes.
