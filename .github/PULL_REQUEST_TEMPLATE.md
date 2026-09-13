<!--
Thanks for contributing to Thot Secure!

A few things that will make this pull request faster to review:

* Keep it focused — one logical change per pull request.
* Read CONTRIBUTING.md if you have not: https://github.com/thotsecure/thot-secure/blob/main/CONTRIBUTING.md
* Conventional-commit style title and commits: `feat(detection): ...`, `fix(audit): ...`, `rule(AO-WEB-042): ...`
* Every commit needs a DCO sign-off (`git commit -s`). There is no CLA.
* Do not use this template for a security vulnerability. Use the private
  channel in SECURITY.md instead: https://github.com/thotsecure/thot-secure/security/advisories/new
-->

## What does this change?

<!--
A short description of the change and the problem it solves.
Link the issue it closes: "Closes #123" / "Fixes #123".
-->

Closes #

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Detection rule (`rules/`)
- [ ] Policy (`policies/`) or playbook (`playbooks/`)
- [ ] Breaking change (contract, schema, config or CLI behaviour)
- [ ] Documentation
- [ ] Refactor / performance / tests / CI / tooling
- [ ] Security fix (see the note below)

<!--
If this is a security fix, the technical detail belongs in a private advisory,
not here. State only that it is a security fix and link the advisory if one
exists. Never paste a reproduction, a payload or an exploit path into a public
pull request.
-->

## How was this tested?

<!--
Be specific. "Ran the test suite" is not an answer; "added
tests/test_rules_engine.py::test_threshold_boundary, which fails on main and
passes here" is. Include the commands you ran and their outcome, and describe
any manual verification.
-->

```console
# commands you ran
```

## Reviewer notes

<!--
Anything that helps the review: a design decision you had to make, a tradeoff,
an alternative you rejected and why, a part of the diff you are unsure about,
or a follow-up you deliberately left out of scope.
-->

---

## Checklist

### Tests and validation

- [ ] **Tests pass locally**: `python -m unittest discover -s tests -t . -v`
- [ ] **`pytest` passes** (or the change is covered by the unittest suite only, and that is correct)
- [ ] **New behaviour is tested** — a bug fix comes with a regression test that fails before the fix; a new rule comes with a positive **and** a negative case
- [ ] **`thotsecure rules validate`** passes (if `rules/` was changed)
- [ ] **`thotsecure policies validate`** passes (if `policies/` was changed)
- [ ] **`ruff check` and `ruff format --check`** pass
- [ ] `mypy src` was not made worse (blocking is not required yet)

### Security and safety

- [ ] **No secrets**: no API keys, tokens, passwords, private keys, real customer hostnames or production telemetry — in the diff, the tests, the fixtures, the commit messages or any screenshot
- [ ] **No offensive capability**: no exploit code, no aggressive or high-rate scanning, no brute-forcing, no denial of service, no hack-back, no collection outside a tenant's declared scope
- [ ] **Every action is reversible**: a new or modified playbook ships with a working rollback, and a test exercises it
- [ ] **Safe defaults preserved**: `DRY_RUN=true` and `AUTONOMY=supervised` are still the shipping defaults, and the approval gate, tenant isolation and audit chain were not weakened to make this pass
- [ ] **The execution guard-rails still hold**: per-tenant hourly cap, per-target cooldown, protected targets, and out-of-scope targets requiring approval are unaffected — or the change to them is explained above and respects GOVERNANCE.md §9
- [ ] **The core boundary is intact**: `thotsecure.core` still imports only the standard library, `pydantic` and `PyYAML`
- [ ] **No vulnerability details** are disclosed in this pull request, its title, its commits or its comments

### Process

- [ ] **DCO signed off** on every commit (`git commit -s`) — `Signed-off-by:` present and correct
- [ ] **`CHANGELOG.md` updated** under `## [Unreleased]`, in the right category, for any user-visible change
- [ ] **Documentation updated** when behaviour, configuration, the API, or the CLI changes (`docs/`, and `docs/architecture/api-contract.md` if the interface contract is affected)
- [ ] **Conventional Commits** used for the title and every commit
- [ ] **Branch name** follows the convention (`feat/*`, `fix/*`, `rule/*`, `docs/*`, `chore/*`, …)
- [ ] **No unrelated changes**: no drive-by reformatting, no dependency bumps unrelated to the change
- [ ] **Breaking changes are declared**: a `BREAKING CHANGE:` footer, a `### Changed → BREAKING` changelog entry, and a migration note — or "not applicable"

### Rules, policies and playbooks (only if applicable)

- [ ] Rule IDs are new and unique; no existing ID was renumbered or reused
- [ ] `false_positives` is filled in with the realistic benign cases, not left empty
- [ ] At least one OWASP and/or MITRE ATT&CK reference is present, in `references` and as a `mitre:T####` tag
- [ ] `remediation` describes a concrete, ideally reversible next step
- [ ] Rule `status` is `draft`/`test` unless the rule was validated against real telemetry
- [ ] The playbook works in simulated mode when its connector is unconfigured, and logs `simulated: true`
- [ ] Any new policy cannot override the engine guard-rails, and a test proves it

---

<sub>By submitting this pull request I confirm that my contribution is made under the terms of the
<a href="https://github.com/thotsecure/thot-secure/blob/main/LICENSE">Apache License 2.0</a>, that I have the
right to submit it, and that I agree to the
<a href="https://github.com/thotsecure/thot-secure/blob/main/CODE_OF_CONDUCT.md">Code of Conduct</a>.</sub>
