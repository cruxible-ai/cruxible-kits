# Judging a dependency exposure

Guides: security.exposure.justification, security.app_exposure.justification,
security.app_exposure.verdict, security.app_exposure.rests_on.

A worklist row (`security.urgent_exposures`, `security.kev_triage_backlog`) says: OSV lists
this vulnerability for this exact package release, this inventory holds it, and nobody has
judged it. That is a lead, not a finding. Your job is to decide whether the vulnerable code
can actually be reached here, and to show why.

## What you are judging

- **The package release** (`security.component`, keyed by purl@version) is the same in every
  inventory. OSV's `affected_by` is about it.
- **The occurrence** (`security.occurrence`: inventory, component) is how one inventory holds
  it. Most reasons a vulnerability doesn't apply are about this use, not the package.

Read the advisory and the fix versions in the `osv.match` document OSV's `affected_by` Claim
cites (each record's `fixed`), then the code that uses the package.

## Where the work arrives

Urgent exposures arrive in the Line inbox: the `security.exposure-attention.unjudged` Line
posts one item per pair nobody has judged whose vulnerability is KEV-listed, or has an EPSS
score at or above the Line's `min_epss` threshold, or has no EPSS score yet (a Line on
`security.exposure-attention.unjudged-inventory` does the same for one inventory), and
`security.exposure-attention.contested` one per pair whose judgment does not count
(contested, or `affected` beside a justification), most urgent first, at most 100 per run.
A pair scored under the threshold, or whose EPSS score is contested, is not posted unless
it is KEV-listed; it is still on the worklist. The inbox item carries no score. When a score arrives, a pair at or above the threshold stays the same item (seen again, its status and decision kept); a pair below it stops being posted, and its item stays in the inbox as it was, no longer seen again (core does not withdraw inbox items). `next` shows each Line's unread items as
`line_inbox_unread`. An item names the inventory, the component, the CVE and the occurrence
(`get security.occurrence/<occurrence>`). After judging the pair, link the item to the pair
the write created (`cruxible inbox link ITEM --subject security.app_exposure/<id>`) or `ack`
it. `security.urgent_exposures` and `security.kev_triage_backlog` stay the whole worklist,
past what one run posts and below the threshold. A decided item stays decided when the same pair comes back in the
same state, as when a judgment is withdrawn: `security.pair_without_judgment_exposures` lists
worklist pairs that exist with no judgment on them (withdrawn, or created before judging). A
judgment whose cited code changed comes back through `next` on its own (`citation_drifted`),
not through the inbox.

An OSV advisory with no CVE id yet arrives in the `security.osv-unkeyed` inbox instead: one
item per advisory and component (`osv_id`, `purl`); past the first thousand pairs, in the
inboxes of its page Lines (`security.osv-unkeyed.2` and on), once enabled. There is no vulnerability Subject and no
pair to judge, because everything here is keyed by CVE id. Read the advisory
(`https://osv.dev/vulnerability/<osv_id>`) and decide: remediate, or `ack` the item. When OSV
lists a CVE for it, the next OSV run records an ordinary `affected_by` and the pair joins the
worklist; the item is no longer posted.

## The bar

A judgment either way shows reachability or the boundary, from source and bounded local
evidence. Name:

1. the vulnerable function, class or option the advisory names;
2. how this code reaches it, or why it can't (the entry points, the call path);
3. for an input-driven bug, who controls the input and the boundary in between;
4. the control or configuration you rely on, and where it lives.

Cite the code you read as the judgment's evidence:
`"evidence": {"kind": "file", "file": "PATH#ANCHOR"}` on the justification or verdict change, where
ANCHOR is the exact passage you relied on, found once in the file. Catalogue the file first
(`cruxible files add NAME PATH`). When that passage changes, `next` lists the judgment as
`citation_drifted`. Cite the narrowest passage that decides the judgment: a whole file
reopens it on every edit, and no citation never reopens it.

A quoted code line (`--evidence-file PATH#TEXT`) is a pointer for reviewers: it shows where
to look. It is not a witness that the judgment still holds. Only a change to those exact
bytes reopens it, and a judgment that depends on code elsewhere can go false while the
quoted line stays the same: `vulnerable_code_not_in_execute_path` because a function is
never called stops holding when a new caller appears in another file. When a check decides
the judgment, cite the check's result where one exists: a scanner's findings imported
through `security.sarif-import`, or the output file of a bounded local check (file evidence
on its result line), so running the check again moves the evidence. Prose (the advisory, a
notes section with your reasoning) keeps quote and section citations. A change
cites one piece of evidence. `because` is one line of at most 280 characters; reasoning that
needs more goes in a section of a notes file beside the code. Cite that section or your own
words instead of the code only when no code passage carries the judgment; both are admitted,
but neither drifts with the code. A low EPSS score, no KEV listing or a quiet advisory is not a
reason. When the judgment rests on how the code works beyond the passage you cite (a
`security.code_fact` in `security.code_facts`, such as which helper all logging goes
through), link the pair to it with `rests_on` in the write that sets the judgment, not
before: a pair holding only `rests_on` reads like one whose judgment was withdrawn. Record a
missing fact as the hunter guidance says.

## The outcomes

- **Affected**: the vulnerable code is reachable here. Record it, then remediate (the fixed
  versions are in the `osv.match` document OSV's `affected_by` Claim cites) or escalate. One
  write with two changes: `create` the `security.app_exposure` pair keyed by `occurrence`
  and `vulnerability`; `set` its `verdict` to `affected`, citing the code that reaches the
  vulnerable function (the passage on the call path) as its evidence. No justification. The
  row leaves the worklists for `security.confirmed_exposures`; every other inventory's row
  stays. A confirmed-affected finding is always app level: the package-level pair holds
  only `vulnerable_code_not_present`.
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
  `vulnerability`; `set` its `justification`. The justification alone is the not_affected
  judgment; a `verdict` of `not_affected` beside it is optional. It never states the global
  none.
- **Blocked on a fact you can't see**: don't guess. Attest unsure on OSV's `affected_by`
  Claim, naming the missing fact and how an owner can check it:
  `cruxible claim attest CLAIM --unsure --because "..." --valid-until TIME`, with TIME at most
  14 days ahead, or the end of the KEV due date if that is sooner and still in the future. The
  pair stays in the backlog, marked.
- **A KEV pair whose due date has passed**: the passed date neither shortens nor cancels a
  hold (most KEV entries are past due), so hold it for at most 14 days like any other pair.
  When the hold ends, judge it with what you can see. If one fact you can't see still decides
  it, write the `affected` verdict, naming that fact in the write's `because`, then remediate
  or escalate to the owner. Never leave it unjudged.

A pair holds one judgment: a justification (not_affected) or the verdict `affected`, never
both. A pair holding both, a `not_affected` verdict with no justification, or a contested
verdict or justification (two agents' values standing side by side) counts as not judged: it
stays in the worklists and in neither track record until one value is settled.

## Review

Write a judgment with `accept: never`. A different agent reviews and approves it after reading
this guidance and trying once to break it: re-read the cited code, look for another path to the
vulnerable code (or, for `affected`, check the path really reaches it), check the control
really applies. Reject a write that sets both a verdict of `affected` and a justification.
Never approve your own judgment: the reviewer acts as its own principal (the kit's default
setup has a `reviewer` principal, normally a subagent using the CLI as `reviewer`). On an
instance one person runs with self-approval, that person approves. No Mandate settles a
justification or a verdict.

To withdraw one, retire its justification (or its `affected` verdict) and, for a
package-level one, its none in one write (one `retire` change each). The pair Subject stays
as history. To turn an `affected` verdict into not_affected, write once: `set` the `verdict`
to `not_affected` (it revises the affected Claim) and `set` the `justification`.

A confirmed exposure clears when the inventory's SBOM no longer lists the vulnerable
release: the row leaves `security.confirmed_exposures`, and `next` lists the verdict as
`claim_dependency_stale` (its occurrence is no longer observed). Check that the new SBOM
really dropped the release, then retire the verdict to clear that row.

## Anti-patterns

- An app-level reason stated at package level: it would silence every inventory.
- `vulnerable_code_not_present` for code that is present but unused: that is
  `vulnerable_code_not_in_execute_path`, for one inventory.
- Judging from the advisory summary without reading the code that uses the package.
- Holding a pair past its cap (14 days, or a KEV due date still ahead) instead of judging it.
- Proving a pair reachable and writing nothing: the worklist can't tell it from a pair
  nobody looked at. Write the `affected` verdict.
- Treating an exposure as fixed because a newer version exists somewhere: it leaves the
  worklists when the inventory's SBOM no longer lists the vulnerable release.
