# Judging a dependency exposure

Guides: security.exposure.justification, security.app_exposure.justification.

A worklist row (`security.urgent_exposures`, `security.kev_triage_backlog`) says: OSV lists
this vulnerability for this exact package release, and this inventory holds it. That is a
lead, not a finding. Your job is to decide whether the vulnerable code can actually be
reached here, and to show why.

## What you are judging

- **The package release** (`security.component`, keyed by purl@version) is the same in every
  inventory. OSV's `affected_by` is about it.
- **The occurrence** (`security.occurrence`: inventory, component) is how one inventory holds
  it. Most reasons a vulnerability doesn't apply are about this use, not the package.

Read the advisory and the fix versions in the `osv.match` document OSV's `affected_by` Claim
cites (each record's `fixed`), then the code that uses the package.

## The bar

A not_affected judgment shows reachability or the boundary, from source and bounded local
evidence. Name:

1. the vulnerable function, class or option the advisory names;
2. how this code reaches it, or why it can't (the entry points, the call path);
3. for an input-driven bug, who controls the input and the boundary in between;
4. the control or configuration you rely on, and where it lives.

Cite the code you read (file evidence, `path#anchor`) and put longer reasoning in a section
you cite. A low EPSS score, no KEV listing or a quiet advisory is not a reason.

## The outcomes

- **Affected**: leave the row. Remediate (the fixed versions are in the cited document) or
  escalate. Write nothing.
- **Not affected, package level**: only `vulnerable_code_not_present`. The vulnerable code is
  not in this package release at all (OSV's range is wrong for it, the fix was backported, the
  module is not built). It holds for every inventory, so it is one write that retires OSV's
  observation, states `affected_by` none of the vulnerability and sets
  `security.exposure.justification` (`triage.judgment`).
- **Not affected, app level**: one of `component_not_present` (listed but not shipped or
  loaded), `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary` or `inline_mitigations_already_exist`.
  It holds for this inventory only: one write setting `security.app_exposure.justification`
  on the occurrence's pair (`triage.app_judgment`). It never states the global none.
- **Blocked on a fact you can't see**: don't guess. Attest `--unsure` on OSV's `affected_by`
  Claim, naming the missing fact and how an owner can check it, with `--valid-until` no later
  than the KEV due date (`triage.investigation`). The pair stays in the backlog, marked.

## Review

Write a judgment with `accept: never`. A different agent, under its own principal, approves it
after reading this guidance and trying once to break it: re-read the cited code, look for
another path to the vulnerable code, check the control really applies. Never approve your own
judgment. No Mandate settles a justification.

To withdraw one, retire its justification and, for a package-level one, its none in one write
(`triage.reverse_judgment`).

## Anti-patterns

- An app-level reason stated at package level: it would silence every inventory.
- `vulnerable_code_not_present` for code that is present but unused: that is
  `vulnerable_code_not_in_execute_path`, for one inventory.
- Judging from the advisory summary without reading the code that uses the package.
- Holding a KEV-listed pair past its due date instead of judging it.
- Treating an exposure as fixed because a newer version exists somewhere: it leaves the
  worklists when the inventory's SBOM no longer lists the vulnerable release.
