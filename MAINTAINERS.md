# Maintainers

This file is the **live roster** of the people responsible for Thot Secure. It is
the authoritative list used by the governance rules in
[`GOVERNANCE.md`](GOVERNANCE.md): the maintainers listed as *active* here are the
eligible voters for every vote described in
[§3.3 of that document](GOVERNANCE.md#33-vote-mechanics).

`CODEOWNERS` is generated from the **GitHub team** column below: it maps paths
to teams, not to individuals, so that people can join and leave a role without
rewriting path rules. Teams are listed in `.github/CODEOWNERS`.

> **Identifiers below are placeholders** for the project bootstrap. Handles,
> names and team slugs are finalised when the `thotsecure` GitHub organisation is
> created; until then, treat the **areas, timezones and coverage spread** as the
> real information and the handles as slots to fill. Any change to this file
> requires a pull request that records the vote from
> [`GOVERNANCE.md` §4](GOVERNANCE.md#4-nomination-process).

---

## 1. Security contacts

These are the addresses that matter operationally. They are monitored by the
people named in §3 and §4.

| Purpose | Contact | Received by |
|---|---|---|
| Vulnerability reports | `security@thotsecure.dev` + [GitHub Security Advisories](https://github.com/thotsecure/thot-secure/security/advisories/new) | All security maintainers (§3) |
| Code of Conduct reports | `conduct@thotsecure.dev` | Enforcement contacts listed in §6 |
| General maintainer contact | `maintainers@thotsecure.dev` | All active maintainers |
| Donations / support page | `support@thotsecure.dev` | Support duty (no counterpart offered) |

Never send a vulnerability report to a public issue, discussion, or chat.
See [`SECURITY.md`](SECURITY.md).

---

## 2. Roles at a glance

| Role | Merge rights | Votes | Documented in |
|---|---|---|---|
| Contributor | — | — | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Triager | labels, assign, close, triage reviews | — | §5 below |
| Reviewer | approve in an area | — | §4 below |
| Maintainer | write, merge, release, administer | ✅ | §3 below |
| Security maintainer | as maintainer, plus advisory/CVE duty | ✅ | §3 below |
| Release maintainer | as maintainer, plus tag and release duty | ✅ | §3 below |
| Emeritus | none (by default) | — | §7 below |

A person may hold several roles. Every maintainer is also a reviewer and a
triager for practical purposes.

---

## 3. Maintainers

Active maintainers, eligible to vote. Each maintains at least one area and
agrees to the responsibilities in
[`GOVERNANCE.md` §2.4](GOVERNANCE.md#24-maintainer).

| Handle | Role | Area / scope | Timezone | GitHub team | Security duty | Status |
|---|---|---|---|---|---|---|
| `@thotsecure-lead` | Maintainer, release duty | Core, packaging, releases, `deploy/`, CI | UTC+01:00 (Europe/Paris) | `@thotsecure/core` | — | Active |
| `@thotsecure-sec` | Maintainer, **security duty** | Security review, `SECURITY.md`, advisories, `src/thotsecure/audit/`, `src/thotsecure/tenancy/` | UTC+00:00 (Europe/London) | `@thotsecure/security` | ✅ primary | Active |
| `@thotsecure-det` | Maintainer | Detection, `rules/`, `src/thotsecure/detection/`, `src/thotsecure/scoring/`, `src/thotsecure/collectors/` | UTC-05:00 (America/New_York) | `@thotsecure/detection` | — | Active |
| `@thotsecure-act` | Maintainer | Actions, `playbooks/`, `src/thotsecure/decision/`, `src/thotsecure/actions/` | UTC+05:30 (Asia/Kolkata) | `@thotsecure/actions` | ✅ secondary | Active |
| `@thotsecure-docs` | Maintainer | Documentation, `docs/`, `content/`, embedded console `src/thotsecure/ui/` | UTC+09:00 (Asia/Tokyo) | `@thotsecure/docs` | — | Active |

**Coverage the roster must maintain.** At least **two** maintainers hold the
security duty, spanning at least two distinct timezones, so that the 72-hour
acknowledgement commitment in [`SECURITY.md`](SECURITY.md) is met even during
holidays. At least **two** maintainers hold release privileges. If either
condition stops being met, filling the gap takes priority over feature work and
is tracked in [`ROADMAP.md`](ROADMAP.md).

**Timezones** exist here for a practical reason: a rotation that covers
UTC-08:00 to UTC+10:00 means a critical report is acknowledged by a human while
the reporter is still awake.

---

## 4. Reviewers

Reviewers approve pull requests in their area; their approval counts toward the
two approvals required for a breaking change
([`GOVERNANCE.md` §3](#3-decision-making)).

| Handle | Area / scope | Timezone | GitHub team | Status |
|---|---|---|---|---|
| `@rev-det-rules` | Rule library: `rules/**` | UTC+02:00 (Europe/Berlin) | `@thotsecure/detection` | Active |
| `@rev-api-sdk` | API v1, `sdks/**`, `src/thotsecure/sdk/` | UTC-03:00 (America/Sao_Paulo) | `@thotsecure/core` | Active |
| `@rev-collectors` | Collectors: `src/thotsecure/collectors/**`, scope enforcement | UTC+08:00 (Asia/Singapore) | `@thotsecure/detection` | Active |
| `@rev-deploy` | Deployment: `deploy/**` (Docker, Compose, K8s, Helm, Terraform, Ansible) | UTC+01:00 (Europe/Amsterdam) | `@thotsecure/core` | Active |
| `@rev-web` | Dashboard: `web/**`, `src/thotsecure/ui/**` | UTC-07:00 (America/Denver) | `@thotsecure/docs` | Active |
| `@rev-docs` | Documentation: `docs/**`, root Markdown, `content/**` | UTC+05:00 (Asia/Karachi) | `@thotsecure/docs` | Active |

Reviewer expectations: a substantive review within **3 working days** of being
requested, or an explicit hand-off. Reviewing a diff means reading the diff.

---

## 5. Triagers

Triagers reproduce reports, label issues, close duplicates and route security
reports to the private channel.

| Handle | Focus | Timezone | GitHub team | Status |
|---|---|---|---|---|
| `@triage-inbox` | Incoming issues, `needs-triage` queue, first response | UTC+01:00 (Europe/Paris) | `@thotsecure/core` | Active |
| `@triage-rules` | `rule_proposal.yml` and `false_positive.yml` queues | UTC-04:00 (America/Toronto) | `@thotsecure/detection` | Active |
| `@triage-ci` | Failing CI, flaky tests, dependency PRs from Dependabot | UTC+03:00 (Europe/Helsinki) | `@thotsecure/core` | Active |

Triage service target: a new issue has a label and either a first human reply or
a routing decision within **7 days**. An unlabelled issue in `needs-triage` for
longer than that is a bug in the triage process, not in the reporter.

---

## 6. Code of Conduct enforcement contacts

Reports sent to `conduct@thotsecure.dev` are received **only** by the people
listed here. They are not discussed in public, and they are not shared with the
maintainer group as a whole without the reporter's consent.

| Handle | Role in enforcement | Conflict-of-interest exclusions |
|---|---|---|
| `@thotsecure-sec` | Primary enforcement contact | Recuses if the report concerns them |
| `@thotsecure-lead` | Secondary enforcement contact | Recuses if the report concerns them |
| `@thotsecure-docs` | Ombudsperson (escalation if both above are conflicted) | — |

At least two contacts must be available at all times. If a report concerns a
person on this list, that person is excluded from handling it, and the
ombudsperson takes over. The process and the possible outcomes are the
enforcement guidelines in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## 7. EMERITUS

Maintainers who have stepped back after substantial service. Emeritus
maintainers keep the credit for their work, are listed permanently, and are
welcome to return per
[`GOVERNANCE.md` §5.1](GOVERNANCE.md#51-voluntary-step-down-emeritus).

| Handle | Former role | Area | Served | Status |
|---|---|---|---|---|
| *(none yet — this section is populated on the first emeritus transition)* | | | | |

An emeritus entry records:

```
| `@handle` | Maintainer | detection, rules | 2026-01 → 2026-11 | EMERITUS |
```

Emeritus maintainers may be granted triage access on request. Merge rights are
not retained by default, because merge rights are an active responsibility, not
an honour. Reinstatement within 12 months is by simple majority vote; after
that, a fresh nomination is required.

---

## 8. Adding and removing maintainers

This is a summary. The normative procedure is
[`GOVERNANCE.md` §4](GOVERNANCE.md#4-nomination-process) (nomination) and
[§5](GOVERNANCE.md#5-removal-and-emeritus-status) (removal).

### Adding (nomination)

1. An active maintainer nominates the person privately, with evidence: merged
   pull requests, reviews, triage, rules contributed, incidents handled.
2. **7-day** private discussion among maintainers. Conduct concerns follow the
   Code of Conduct process instead.
3. Vote: quorum of two thirds of active maintainers; **two thirds** in favour
   for maintainer and reviewer, simple majority for triager.
4. The nominee is asked and may decline, privately and without a record.
5. Onboarding: 2FA enabled, security-channel access if the security duty
   applies, a named mentor for one cycle, and this file plus `CODEOWNERS`
   updated **in the pull request that records the vote**.
6. Announced in Discussions unless the person prefers otherwise.

### Removing

| Situation | Process |
|---|---|
| Voluntary step-down | Say so, at any time, for any reason. Move to `EMERITUS` (§7). |
| Inactivity | Two contact attempts; if there is no response for 30 days, or no substantive activity for 6 months, a removal vote is held. |
| Neglect of duties | Written feedback first. If it recurs, a two-thirds removal vote after a 14-day discussion. |
| Conduct | Code of Conduct enforcement guidelines. |
| Acting against an invariant, or merging an offensive capability | Two-thirds removal vote; access may be suspended immediately if there is active risk. |
| Compromised account or refusal to enable 2FA | Access suspended immediately, vote within 7 days. |

Every removal is recorded in this file with the role and the area, and the
reason is recorded in the vote's public issue — except where a conduct or
security incident requires otherwise, in which case the fact of the removal is
recorded and the detail stays private.

### Access checklist on any change

- [ ] GitHub organisation team membership updated (`core`, `detection`,
      `actions`, `docs`, `security`).
- [ ] Repository permission updated (`triage`, `write`, `maintain`, `admin`).
- [ ] This file updated.
- [ ] `.github/CODEOWNERS` updated if the area changed.
- [ ] Security-advisory access granted or revoked if the security duty applies.
- [ ] Secret and environment access reviewed (release workflows, package
      registries, signing identities) if the release duty applies.

The last item is the one that gets forgotten. Release privileges and signing
access are revoked in the same pull request as the role change.

---

## 9. Expectations and availability

- **Security duty is a real commitment.** A maintainer holding it must be
  reachable within 72 hours, or must hand the duty over explicitly. Silent
  unavailability is what turns a responsible-disclosure process into a public
  disclosure.
- **Absence is normal.** Holidays, exams, jobs and life happen. Say "away until
  the 12th" in the maintainer channel and nothing else is expected. Unexplained
  silence for 30 days is what triggers the inactivity process.
- **Nobody is on call.** Thot Secure is a volunteer project with no SLA, no paid
  support and no donation-funded staffing. The response targets in
  [`SECURITY.md`](SECURITY.md) are best-effort commitments made by people who
  may be asleep, and they are published so that reporters can plan around them.
- **No role is bought.** Donations, sponsorships and infrastructure grants never
  confer a role, a vote, a merge, a priority or influence over the roadmap. If
  you are offered a role in exchange for funding, decline it and tell the
  maintainer group.
- **Recusal.** A maintainer recuses from any decision in which they have a
  financial or employment conflict of interest — for example reviewing a
  vendor's connector when their employer sells a competing product — and the
  recusal is recorded.

---

## 10. Machine-readable ownership

`.github/CODEOWNERS` maps every path in the target tree of the interface
contract (`docs/architecture/api-contract.md` §2) to one of five GitHub teams:

| Team | Covers |
|---|---|
| `@thotsecure/core` | `src/thotsecure/{core,storage,bus,reports,api,sdk}`, `cli.py`, `sdks/`, `deploy/`, `.github/workflows/`, packaging |
| `@thotsecure/detection` | `rules/`, `src/thotsecure/{detection,scoring,collectors}`, test fixtures for rules |
| `@thotsecure/actions` | `playbooks/`, `policies/`, `src/thotsecure/{decision,actions}` |
| `@thotsecure/docs` | `docs/`, `content/`, `web/`, `src/thotsecure/ui/`, root Markdown |
| `@thotsecure/security` | Security-sensitive paths: `audit/`, `tenancy/`, auth in `api/`, `SECURITY.md`, security workflows |

Governance, license and security files additionally request
`@thotsecure/security` review, because changing them changes the project's
guarantees.
