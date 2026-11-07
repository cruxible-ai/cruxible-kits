# Judging a security finding

Guides: security.finding.verdict, security.finding.severity, security.finding.justification.
Adapted from cloudflare/security-audit-skill (MIT).
Calls recorded: the source's `informational` anchor is dropped (the severity enum is low..critical); a confirmed minimal-impact finding is `low`.

You are judging a finding someone else reported. Your job is to try to refute it.
You did not write it: if you did, stop and hand it to another agent.

## The bar for `confirmed`

A finding is confirmed only when you can name all six, from source and bounded local evidence:

1. the lower-trust principal (who acts);
2. the input or action they control;
3. the control that should stop them;
4. the boundary that control fails to hold;
5. the principal or resource affected;
6. the result you observed, or an owner could observe.

Missing any one: it is not confirmed. A missing best practice, a guess about deployment,
a generic crash, or an effect on the actor's own data is not a finding.

## How to judge

1. Re-read every cited source location yourself. The first step of the trace must be a
   real entry point for the lower-trust principal; the last must be the claimed effect.
2. Reconstruct the strongest controls on the path: validation, identity, authorization,
   normalization, lifecycle, framework defaults, containment. A finding survives only if
   it survives the strongest reading of them.
3. Reproduce the minimum result locally when you safely can (a unit test, a fixture, a
   dummy tenant), inside a sandbox with no external network. Stop at the first proof.
   Never probe deployed systems, shared services or real accounts.
4. Claim no stronger result than you observed.

## The three outcomes

- **Confirmed:** set `verdict = confirmed` and `severity`. Write the root cause, the
  conditions, and the smallest source fix at the last trusted decision point in a section,
  and cite it.
- **Refuted:** set `verdict = false_positive` (the trace is wrong) or `not_exploitable`
  (the trace is real but no boundary is crossed), with a `justification`. Cite your reasoning.
- **Blocked on a fact outside source:** don't guess. Attest `--unsure` on the finding's
  `reported_at`, citing a section that names the exact missing fact (a proxy setting, an
  IAM policy, a deployment flag) and a safe way for an owner to check it. Set
  `valid_until`. Never give a blocked finding a severity.

Deployment controls, proxies, identity policy and topology are real controls. When the
repository doesn't show them, neither assume they exist nor assume they don't.

## Severity

Only confirmed findings get a severity, and it can't exceed the impact you demonstrated.

| Severity | Anchor |
|---|---|
| critical | an unauthenticated actor gains code execution, full data-store access, or takeover of arbitrary accounts |
| high | an explicit security control is fully defeated with real consequences: auth bypass, cross-tenant read/write, stored script running for other users, authenticated code execution, unauthenticated stop of a shared service |
| medium | a real boundary violation with limited reach, uncommon preconditions, or a narrow set of resources |
| low | disclosure of non-secret internals, or an effect needing sustained effort for little gain |

High or medium? Ask: does the result fully defeat an explicit control for an action with
real consequences, or only weaken it? If you can't state the concrete damage, it is lower
than it feels.

## Writing the verdict

Write it with `accept: never`. A different agent approves it, after reading this guidance
and trying once more to break your reasoning.

## Anti-patterns

- A checklist deviation reported as a vulnerability.
- Defense-in-depth advice with no reachable boundary violation.
- Testing against live or shared environments.
- Guessing provider, proxy, browser, identity or deployment behavior not in source.
- Treating an actor's intended authority over their own data as a boundary crossing.
- Reporting a stronger effect than the one observed.
- A severity on a blocked finding.
