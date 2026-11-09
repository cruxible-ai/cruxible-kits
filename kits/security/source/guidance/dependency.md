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

Cite the code you read as the justification's evidence:
`"evidence": {"kind": "file", "file": "PATH#ANCHOR"}` on the justification change, where
ANCHOR is the exact passage you relied on, found once in the file. Catalogue the file first
(`cruxible files add NAME PATH`). When that passage changes, `next` lists the judgment as
`citation_drifted`, so it gets judged again. A change cites one piece of evidence: put longer
reasoning in the write's `because` or a notes file beside the code. Cite a notes section or
your own words instead only when no code passage carries the judgment; both are admitted, but
neither drifts with the code. A low EPSS score, no KEV listing or a quiet advisory is not a
reason.

## The outcomes

- **Affected**: leave the row. Remediate (the fixed versions are in the cited document) or
  escalate. Write nothing.
- **Not affected, package level**: only `vulnerable_code_not_present`. The vulnerable code is
  not in this package release at all (OSV's range is wrong for it, the fix was backported, the
  module is not built). It holds for every inventory, so it is one write with four changes:
  `retire` OSV's `affected_by` Claim; `add` `affected_by` with value
  `{"none": "security.vulnerability/<cve id>"}` and role `normative` on the component; `create`
  the `security.exposure` pair keyed by `component` and `vulnerability`; `set` its
  `justification`.
- **Not affected, app level**: one of `component_not_present` (listed but not shipped or
  loaded), `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary` or `inline_mitigations_already_exist`.
  It holds for this inventory only: one write with two changes: `create` the
  `security.app_exposure` pair keyed by `occurrence` (the worklist row's occurrence) and
  `vulnerability`; `set` its `justification`. It never states the global none.
- **Blocked on a fact you can't see**: don't guess. Attest unsure on OSV's `affected_by`
  Claim, naming the missing fact and how an owner can check it:
  `cruxible claim attest CLAIM --unsure --because "..." --valid-until TIME`, with TIME no later
  than the end of the KEV due date when the vulnerability has one. The pair stays in the
  backlog, marked.
- **A KEV pair whose due date has passed**: it can't be held, since any hold would already
  have ended. Judge it now with what you can see. If one fact you can't see still decides it,
  treat the pair as affected: remediate, or escalate to the owner naming that fact. Never
  leave it unjudged.

## Review

Write a judgment with `accept: never`. A different agent, under its own principal, approves it
after reading this guidance and trying once to break it: re-read the cited code, look for
another path to the vulnerable code, check the control really applies. Never approve your own
judgment. No Mandate settles a justification.

To withdraw one, retire its justification and, for a package-level one, its none in one write
(one `retire` change each). The pair Subject stays as history.

## Anti-patterns

- An app-level reason stated at package level: it would silence every inventory.
- `vulnerable_code_not_present` for code that is present but unused: that is
  `vulnerable_code_not_in_execute_path`, for one inventory.
- Judging from the advisory summary without reading the code that uses the package.
- Holding a KEV-listed pair past its due date instead of judging it.
- Treating an exposure as fixed because a newer version exists somewhere: it leaves the
  worklists when the inventory's SBOM no longer lists the vulnerable release.
