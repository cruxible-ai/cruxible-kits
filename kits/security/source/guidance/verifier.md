# Judging a security finding

Guides: security.finding.verdict, security.finding.severity, security.finding.justification,
security.finding.fixed_by, security.finding.rests_on, security.code_fact.category,
security.code_fact.holds.
Adapted from cloudflare/security-audit-skill (MIT).

A verdict is your judgment of a finding someone else reported, on evidence you checked
yourself. Your job is to try to refute it. If you reported it, stop and hand it to
another agent: the reporter, the verifier and the approver are three different agents.
Judge it before reading other agents' verdicts or attestations on it.

## The bar for `confirmed`

Confirmed only when you can name all six, from source and bounded local evidence:

1. the lower-trust principal (who acts);
2. the input or action they control;
3. the control that should stop them;
4. the boundary that control fails to hold;
5. the principal or resource affected;
6. the result you observed in a bounded local check (a test, harness, fixture, rendered
   policy or dummy-tenant call) through the target's own interface: a function call, a
   CLI command, a message, a file, an HTTP request.

Confirmed cites that observed run output: the check's output file or test log, a file in
the workspace catalog. Source alone shows a path, not a result. If you couldn't run the check (no adequate
sandbox, a missing toolchain), the finding is blocked, not confirmed. When the finding
falls in a domain one of the kit's reference pages covers (`reference/`), that page's
validation hints are part of this bar.

## How to judge

1. Re-read every cited location yourself: the code `reported_at` cites and each trace
   step. The first step must be a real entry point for the lower-trust principal; the
   last must be the claimed effect.
2. Reconstruct the strongest controls on the path: validation, identity, authorization,
   normalization, lifecycle, framework defaults, containment. The finding survives only
   if it survives the strongest reading. Comparable software sharing the pattern
   calibrates severity; it never dismisses a demonstrated result.
3. Reproduce the minimum result in a sandbox with no external network. Stop at the first
   proof. Never probe deployed systems, shared services or real accounts.
4. Claim no stronger result than you observed: not a crash as code execution, not
   ordinary work as a shared outage, not a same-principal action as privilege gain.

## The outcomes

Write your reasoning as a new section of the finding's notes file
(`security/findings/<repo>/<finding-key>.md`) in the same write as the verdict, and cite
that section (`{kind: section, ref: ID}`): a section the write itself appends counts as
your own words. `because` is one line of at most 280 characters, and enough on its own only
for a plain refutation.

- **Confirmed:** `verdict` cites the observed run output (file evidence
  `path#<quoted result line>` on the output file or test log); `severity` cites your
  reasoning section.
- **Refuted:** `verdict` and `justification` cite your reasoning section.

Cite the narrowest passage that decides the judgment: a whole file reopens it on every
edit, and no citation never reopens it.

| Outcome | Write | The section says |
|---|---|---|
| Confirmed | `verdict = confirmed`, `severity` | root cause; conditions; the check and its result; likelihood and impact, separately; the smallest source fix at the last trusted decision point, with a regression test |
| Refuted: the trace is wrong | `verdict = false_positive`, `justification` (`rule_misfire`, `test_or_dead_code`) | where the trace breaks |
| Refuted: real code, no boundary crossed | `verdict = not_exploitable`, `justification` (`not_attacker_controlled`, `not_reachable`, `sanitized`, `no_boundary_crossed`: the effect stays within the attacker's own authority) | the control or missing prerequisite that stops it |
| Blocked on a fact outside source | no verdict, no severity: attest `--unsure` on `reported_at`, with `--valid-until` | the exact missing fact, why it decides the outcome, and a safe check (a bounded local step, or what an owner should look at); never live probing |

Blocked is not a parking place. If source refutes the trace, refute it; if the fact can be
answered locally, answer it. When the fact arrives, judge the finding and let the
attestation lapse.

An unsure attestation stays on the `reported_at` Claim it examined. When `reported_at` is
revised (the code moved, or another report), the attestation doesn't follow: the finding
comes back through drift, and you judge it again.

Deployment controls, proxies, identity policy and topology are real controls. When the
repository doesn't show them, assume neither that they exist nor that they don't.

## Codebase facts

The repository's facts (`security.code_facts`: what enforces what, where trust changes,
which helpers are hazards) are other agents' reading of the code, each citing the passage
that decides it. Read them before reconstructing a control, then check the ones your
verdict leans on: a fact is a lead, not proof. Link the verdict's finding to each fact it
rests on with `rests_on`. If a fact no longer holds, set its `holds` to `partly` or `no`
citing the passage (see the hunter guidance for recording a new one); core does not bring
back what rests on it, so look that up with the `*_resting_on` Queries.

## Severity

Only confirmed findings get your severity, and it can't exceed the impact you
demonstrated. A scan's severity on the same finding is the tool's observation; yours,
normative, replaces it.

| Severity | Anchor |
|---|---|
| critical | an unauthenticated actor gains code execution, full data-store access, or takeover of arbitrary accounts |
| high | an explicit security control is fully defeated with real consequences: auth bypass, cross-tenant read/write, stored script running for other users, authenticated code execution, unauthenticated stop of a shared service |
| medium | a real boundary violation with limited reach, uncommon preconditions, or a narrow set of resources |
| low | disclosure of non-secret internals, an effect needing sustained effort for little gain, or a minimal-impact prerequisite of a larger issue |

High or medium? Does the result fully defeat an explicit control for an action with real
consequences, or only weaken it? If you can't state the concrete damage, it is lower than
it feels.

## Review

Write the verdict with `accept: never`. A different agent approves it after reading this
guidance and trying once more to break it: re-read the cited code, rerun the check, look
for the control you missed. Neither the reporter nor the verifier approves. A revision that
strengthens the verdict or changes the trace, the result or the severity is a new judgment
and needs an approver who took no part in the earlier one. On a local instance approval is
an honor system: the three agents may sign as the same principal, and use separate
principals only where the instance has them. No Mandate settles a verdict.

When the cited code changes (`cruxible next` lists the finding's `reported_at` as
`citation_drifted`), re-judge it before relying on the verdict.

## Fixed

`fixed_by` cites the change that removes the boundary crossing at the last trusted point,
plus its regression test. A change that only hides the symptom is not `fixed_by`.

## Anti-patterns

- A checklist deviation reported as a vulnerability.
- Defense-in-depth advice with no reachable boundary violation.
- Testing against live or shared environments.
- Guessing provider, proxy, browser, identity or deployment behavior not in source.
- Treating an actor's intended authority over their own data as a boundary crossing.
- Reporting a stronger effect than the one observed.
- A severity on a blocked finding.
