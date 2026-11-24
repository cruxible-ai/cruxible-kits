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

A judgment is made per package release: after an upgrade, the new version's pair is unjudged
again even when OSV lists the same CVE for it. The vulnerability's card (`cruxible get
security.vulnerability/<cve id>`) names every pair on it, an earlier version's included after
that release left the SBOM; `cruxible get <pair> --detail history` shows its value, Claim and
reason, and `cruxible get <claim> --detail evidence` the file it cites, so re-check that
reasoning and citation against the new release instead of deriving them again.

OSV's `affected_by` Claim names where to upgrade in its reason: `cruxible get <claim>
--detail evidence` prints `OSV GHSA-... lists CVE-... for <purl> (fixed in: 2.12.2, 2.15.0,
2.3.1)`, every version OSV's advisories list as fixed for that package (one per release line;
the kit compares no versions, so pick the one above yours), as OSV listed them when it first
reported the pair. The Claim cites the `osv.match` document (`CAP-...` in the same output),
which holds the advisory id, the CVE ids and the current fixed versions (each `affected`
record's `fixed`); its bytes are base64 in `capture read`'s JSON: `cruxible capture read CAP-... | jq -r .material.body_access.body_base64 |
base64 -d`. Read the advisory itself at `https://osv.dev/vulnerability/<osv_id>`, then the
code that uses the package.

A distro package (purl type `deb`, `rpm`, `apk`) is asked about by the source package its
SBOM states, so OSV's finding for `glibc` lands on the binary `libc6`: judge whether this
binary carries and exposes the vulnerable code (a library split into several binaries
often ships it in only one). A distro package whose SBOM states no release or source is
not checked, never clean: regenerate the SBOM with a tool that records them (Syft, Trivy)
rather than judging it.

Your judgments are what `cruxible kit run security:export-vex` exports as VEX: a resolved justification
as `not_affected`, the `affected` verdict as affected, and everything else, a contested
judgment included, as under investigation.

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
it. `security.asset_urgent_exposures` is the same worklist with each inventory's IT asset
beside it (owner, environment, exposure, criticality; empty when the inventory is linked to
no `it.asset`), most exposed then most critical asset first: work it top down when where the
software runs bears on the judgment. `exposure` and `criticality` are ranked, so
`cruxible query it.asset --where 'exposure>=internal'` finds every networked asset.
`security.urgent_exposures` and `security.kev_triage_backlog` stay the whole worklist,
past what one run posts and below the threshold. A decided item stays decided when the same pair comes back in the
same state, as when a judgment is withdrawn: `security.pair_without_judgment_exposures` lists
worklist pairs that exist with no judgment on them (withdrawn, or created before judging). A
judgment whose cited code changed comes back through `next` on its own (`citation_drifted`),
not through the inbox.

OSV advisories with no CVE id yet arrive as one item in the `security.osv-unkeyed` inbox
instead: `count`, a `sample` of the first 20 (`osv_id`, `purl`), and `matches`, the OSV match
document whose `unkeyed` list holds them all (`cruxible capture read <matches>`, decoded as
above). There is no
vulnerability Subject and no pair to judge, because everything here is keyed by CVE id. Read
each advisory (`https://osv.dev/vulnerability/<osv_id>`) and decide: remediate, or `ack` the
item. The same set on a later run is the item seen again; a changed set is a new item. When
OSV lists a CVE for an advisory, the next OSV run records an ordinary `affected_by` and the
pair joins the worklist.

## The bar

A judgment either way shows reachability or the boundary, from source and bounded local
evidence. Name:

1. the vulnerable function, class or option the advisory names;
2. how this code reaches it, or why it can't (the entry points, the call path);
3. for an input-driven bug, who controls the input and the boundary in between;
4. the control or configuration you rely on, and where it lives.

Cite the code you read as the judgment's evidence:
`"evidence": {"kind": "file", "file": "PATH#ANCHOR"}` on the justification or verdict change, where
PATH is the file's registered name or its workspace path (the write catalogues a cited file)
and ANCHOR is the exact line you relied on, found once in the file. As below, the quote is a
pointer for reviewers. When that line changes, `next` lists the judgment as
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

## Pin what the judgment relied on

A judgment is made from live facts: this inventory still lists the release, OSV still lists
the CVE, the service is internal-only. Pin each one you relied on, on the justification or
verdict change: `"based_on": ["kind/id#field", ...]` in the write file (or `--based-on
kind/id#field`, repeatable, on `cruxible set` and `cruxible write`). The write resolves each to
that field's one live Claim and pins its exact version. While nothing pinned changes, the
judgment stays quiet, however often the Lines re-observe the same values. When one is revised
or retired, `next` lists the judgment as `claim_dependency_stale`, naming the Claim that
changed; the judgment still stands until you re-judge it.

| Judgment | Pin |
|---|---|
| any app-level one (`justification` or `verdict`) | the use you judged: `security.occurrence/<occurrence>#scope` |
| a reason about who can reach the code (`vulnerable_code_cannot_be_controlled_by_adversary` for an internal-only service, `inline_mitigations_already_exist` at an edge the asset sits behind) | the deployment: `it.asset/<slug>#exposure` (the asset `security.asset_urgent_exposures` shows for the row) |
| `affected` | OSV's `affected_by` Claim for this CVE, by id (`CLM-...`, from `cruxible get security.component/<purl>`): the field is many-valued, so `security.component/<purl>#affected_by` refuses `based_on_ambiguous` when OSV lists several CVEs |
| resting on a codebase fact (`rests_on`) | `security.code_fact/<id>#holds` for each: when someone sets it to `partly` or `no`, the judgment comes back on its own |
| a decision a KEV due date forced (an `affected` verdict written when the hold on a past-due KEV pair ran out) | `security.vulnerability/<cve id>#kev_due_date` |

A package-level judgment pins nothing OSV wrote (its own write retires OSV's observation);
pin a codebase fact it rests on. KEV and EPSS are never the reason for a judgment (see
the bar). Pin `#epss_score` only when the score itself decided something you want to look at
again when it moves: FIRST revises it most days, so the pin reopens the judgment that often.

An internal-only judgment, one write (`cruxible write judgment.json --no-accept`):

```json
{
 "because": "Internal-only service: no untrusted client reaches the JNDI lookup.",
 "changes": [
  {"op": "create", "label": "pair", "subject_kind": "security.app_exposure",
   "key": [{"predicate": "security.app_exposure.occurrence", "value": "security.occurrence/OCCURRENCE"},
           {"predicate": "security.app_exposure.vulnerability", "value": "security.vulnerability/cve-2021-44228"}]},
  {"op": "set", "subject": {"created": "pair"}, "field": "justification",
   "value": "vulnerable_code_cannot_be_controlled_by_adversary", "role": "normative",
   "evidence": {"kind": "file", "file": "PATH#ANCHOR"},
   "based_on": ["security.occurrence/OCCURRENCE#scope", "it.asset/payments-api#exposure"]}
 ]
}
```

When the asset's `exposure` later becomes `internet`, `next` names this judgment. Re-judge
it: set the new value (or the same one, re-checked) with `--based-on` the same fields, which
pins their current versions, or retire it. A field pinned by mistake is dropped with `cruxible
set ... --clear-based-on`.

## The outcomes

- **Affected**: the vulnerable code is reachable here. Record it, then remediate (the fixed
  versions are in the reason of OSV's `affected_by` Claim, `cruxible get <claim>`) or
  escalate. One
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
really applies, check each fact the judgment relies on is pinned (above). Reject a write
that sets both a verdict of `affected` and a justification, and one whose reason relies on a
deployment or a codebase fact it does not pin.
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

A not_affected judgment whose release leaves the SBOM (an upgrade lists a new
purl@version, or the package is removed) is handled the same way. The app-level
judgment leaves `security.app_not_affected_judgments` (the current track record lists a
judgment only while its occurrence holds a scope) for
`security.departed_app_not_affected_judgments`, and `next` lists its justification as
`claim_dependency_stale`, naming the occurrence that left. It was a judgment about the old
release only:

1. Check the new SBOM really dropped the release (`security.inventory_components
   --param inventory=security.inventory/<id>`).
2. Judge the new release's pair on its own when it reaches the worklist: re-check the old
   reasoning and citation against it (see "What you are judging"), never copy the old
   judgment across.
3. Retire the old justification to clear the `next` row (`cruxible retire CLAIM --reason
   "release left the inventory"`); the pair Subject and its history stay. Leave it only when
   you expect the release back (a planned rollback): listed again, its occurrence holds a
   scope and the judgment is current again.

A package-level judgment (`security.not_affected_judgments`) is about the release itself,
wherever it is installed, so it stays listed after one inventory drops it.

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
- "Internal-only" (or any deployment reason) without `it.asset/<slug>#exposure` pinned:
  nothing brings the judgment back when the service is exposed.
