# Security kit for Cruxible 0.5

This kit is a starting point, not a schema you have to adopt. It seeds an
instance with security vocabulary, guidance Documents, reference pages and an
automation template you tailor. From there the instance is yours to grow:
revise the kit's definitions, add your own, and adapt or replace its
automation, all by ordinary authoring. Facts copied from sources settle
automatically; judgments always need review.

This release is kit version **1.3.0**, built for Cruxible **0.5** and
provider protocol **2**. It requires the base kit (`base` 1.0.0, which
`cruxible init` installs) for reading workspace files and fetching web pages.
It covers two loops:

| Loop | What it does |
|---|---|
| Dependency | Import a CycloneDX SBOM, ask OSV which vulnerabilities affect its components, read CISA KEV and FIRST EPSS for them, then judge each exposure: a not_affected justification, or an `affected` verdict that keeps it on the confirmed list until fixed |
| Audit | Agents (and optionally SARIF scanners) report code findings by key, a second agent judges each one, and coverage units record what was checked against which code |

Every observation cites retained source bytes. Missing or incomplete input
stays unknown; it never means unaffected or clean.

| Installed definitions | Purpose |
|---|---|
| `security.inventory`, `security.component` | An application's inventory and exact package releases |
| `security.occurrence` | The pair (inventory, component), with its scope |
| `security.vulnerability`, `security.component.affected_by` | OSV's affected packages and vulnerabilities |
| `security.exposure`, `security.app_exposure` | Package-level and app-level judgment pairs: a `justification` (not_affected), or on the app-level pair the `verdict` `affected` |
| `security.urgent_exposures`, `security.kev_triage_backlog` | Exposures nobody has judged, with KEV and EPSS context |
| `security.unjudged_exposures_over`, `security.inventory_unjudged_exposures_over` | Exposures nobody has judged whose vulnerability is KEV-listed, or has an EPSS score at or above `min_epss`, or has no EPSS score yet, in every inventory or in one: what the unjudged attention Lines post |
| `security.confirmed_exposures` | Exposures judged `affected` whose SBOM still lists the component: fix pending, with KEV and EPSS context |
| `security.covered_app_exposures`, `security.covered_package_exposures`, `security.pair_without_judgment_exposures` | Exposures a resolved not_affected judgment covers (app or package level), and worklist pairs that exist with no judgment on them (a withdrawn judgment, or a pair created before judging; a Query cannot tell which): with the worklist and confirmed list, the row counts say how many are covered, new, confirmed and in that last state |
| `security.watched_vulnerabilities` | Vulnerabilities affecting imported components |
| `security.finding` | One weakness at one place in one repository: `rule`, `reported_by`, `reported_at`, `verification`, `severity`, and the judgments `verdict`, `justification`, `fixed_by`, `found_in` |
| `security.coverage_unit` | One surface of one repository checked for one concern, with its `status` |
| `security.finding_verdicts`, `security.coverage_plan`, `security.findings_by_unit` | Audit worklists: findings with their verdicts, units to take up next, findings per unit |
| `security.code_fact` | One thing true of a repository's code that security judgments rest on (`repo`, `topic`), with its `category` and whether it `holds`, citing the code that decides it |
| `rests_on` (findings, app exposures, coverage units), `security.code_facts`, `security.*_resting_on`, `security.*_on_weakened_facts`, `security.weakened_causes_of_*` | Which judgments rest on which facts; a repository's facts; what to look at again when a fact changes or stops holding (core does not bring those judgments back by itself) |
| `security.osv-unkeyed` | The Procedure that posts one inbox item when OSV lists advisories with no CVE id yet (no Claim can record them), pointing at the match document that lists them |
| `security.sarif-import`, `security.sarif-attention` | Procedures that turn a SARIF file into findings, and post regressions and location gaps to an inbox |
| `security.osv.query`, `security.osv.match`, `security.sbom.components`, `security.sarif.findings` | The capabilities the Procedures' provider slots name: what each call sends and gets back. A derived document's fields are declared on its CaptureKind (`security.osv-matches`, `security.sbom-components`, `security.sarif-findings`), so any provider that returns that layout can serve the slot |
| `security.guidance.dependency` | Governed guidance for dependency judgments |
| `security.guidance.hunter`, `.verifier`, `.coverage` | Governed guidance for reporting findings, judging them, and keeping coverage |

The [reference/](reference/) pages are hunting strategy by domain (web and
auth, client side, cloud, AI and LLM, memory safety and more), starting from
[reference/attack-classes.md](reference/attack-classes.md). They are plain
files for the reader; the kit doesn't install them.

The kit needs three providers. Two are its own and ship inside it:
`security-osv-provider` serves `security.sbom.components`,
`security.osv.query` and `security.osv.match`, and `security-sarif-provider`
serves `security.sarif.findings` (pure: no network, no clock). The third is
general purpose: `cruxible-provider-web` 0.7.0 serves the base kit's
`web.fetch` and `web.fetch.pages` (the KEV and EPSS reads). General-purpose
providers are not bundled: the kit names the package at an exact version, and
`kit add` installs that version from the package index (PyPI unless the
operator names another), unless a build already installed serves those
operations. The SBOM and SARIF files are read by core's builtin
`workspace.file`. Each provider carries registration schema 3 (its own copies
of the Contracts and layouts it serves) and a frozen lock; installing a
provider can download the dependencies its lock pins. For a machine with no
index access, see the isolated-deployment page of the Cruxible docs.

## Install and first answers

Use Cruxible 0.5 with its daemon running and a Git workspace selected. From a
checkout of this repository (replace paths for your workspace):

```sh
cruxible init --principal-id owner \
  --reviewer-key-dir /outside/workspace/reviewer-keys --require-independent-approval
# init prints the base kit's proposal; the reviewer approves it (see Review below):
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
cruxible kit status --offline
# Preview the install (writes nothing); it prints the coordinate to commit at:
cruxible kit add /path/to/cruxible-kits/kits/security
cruxible kit add /path/to/cruxible-kits/kits/security --commit --at OID
# The commit prints three provider-install proposals. The reviewer approves each:
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
# Then the kit's definitions are proposed automatically; kit status names that proposal:
cruxible kit status --offline
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
cruxible kit status --offline
```

The base kit must be installed first: `init` proposes it, and once it is
accepted `cruxible kit status --offline` shows `base`. Without it, `kit add`
refuses with the repair `cruxible kit add base`. Nothing else needs to be
accepted beforehand. Under independent approval a kit add is four proposals,
not one: one install proposal for each of the three providers (each carries
its own copies of the shapes it serves), then the kit's definitions, which
are proposed automatically, as the kit's author, once the three installs
have activated, because they are checked against the installed providers.
The reviewer approves all four. With one owner and self-approval (below) the
same commit installs everything in one step.
`cruxible kit add security:1.3.0` installs the same release from the registry
(`ghcr.io/cruxible-ai/kits/security:1.3.0`) once it is published; before
then it refuses (`cruxible.kit.not_found`), so use the local directory. The
same holds for a refusal whose repair is `cruxible kit add security`
(`requires_missing`, from something that requires this kit): that command
fetches the registry release, so until it is published run `cruxible kit add
/path/to/cruxible-kits/kits/security` instead.

`cruxible kit add PATH` without `--commit` previews the plan and writes
nothing (`--json` for the full plan).

### Review: a second agent approves

An agent never approves its own proposals. `--reviewer-key-dir` adds a second
principal, `reviewer`, with its key and settings (`cruxible.env`) in that
directory, outside the workspace; `--require-independent-approval` makes the
approval policy `independent_approval_required`, so every proposal (the base
kit's, each provider install, the kit's definitions, the automation
template's, each judgment) activates only once a principal other than its
author approves it; the author's own `proposal approve` is refused
(`cruxible.approval.creator_forbidden`). This cosign between agents is a
convention, not a security boundary: both keys are files the same OS user can
read. The reviewer is normally a subagent the working
agent starts for each proposal. Subagents share the parent session's MCP
servers, which act as the parent's principal, so the reviewer uses the CLI as
`reviewer`:

```sh
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal review PROPOSAL_ID
# Approving activates the proposal once the requirement is met:
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
```

`CRUXIBLE_PRINCIPAL_ID=reviewer` loads the reviewer's remembered settings (key
included) for that command only. A person reviewing at their own terminal can
switch instead with `cruxible context use --principal reviewer`, which changes
the principal for every command on this instance until `cruxible context use
--principal owner` switches back. `cruxible next` lists what waits for review
(`proposal_awaiting_approval`) when read as `reviewer`, each row with the
command that approves it (`cruxible proposal approve ID --signer-id
reviewer`, which also works from the owner's session). On an instance that
was initialized without a reviewer, add one first and then the policy:
`cruxible principal add reviewer --key-dir /outside/workspace/reviewer-keys
--signer-key OWNER_KEY --mode graph_write`, then `cruxible authoring example
approval-policy > policy.json` and `cruxible authoring submit policy.json`.

The kit's definitions proposal is planned against the instance as it was when
it was proposed. If other writes land before the reviewer approves it, it is
stale and the approval refuses (`readmit_requires_resubmission`): run the same
`cruxible kit add ... --commit` again (with `--at` the new coordinate), have
the reviewer approve the new proposal, and withdraw the stale one (`cruxible
proposal withdraw PROPOSAL_ID --reason TEXT`), which otherwise stays open. A
provider-install proposal does not go stale this way: its approval lands the
same change set at the new head and signs that.

If you want to approve everything yourself, initialize without the reviewer:
`cruxible init --principal-id owner` leaves the policy `self_approval_allowed`,
where `init` installs the base kit, `kit add --commit` installs the kit, and
the owner's own `proposal approve` signs and activates each proposal; nothing
waits for a second principal.

Copy [automation.json](automation.json) to your workspace and tailor it before
submitting. It is a template, never installed or submitted by `kit add`:

- Choose the Line names and update their Mandates and Runbook steps to match.
  Keep `security.start` as the Runbook name if using the commands below.
- Set the SBOM Line's `relative_path` (the SBOM file in your workspace) and
  `logical_source`. What the file must contain is in the description of each
  input a Line needs, which `cruxible runbook preview security.start` lists per
  step (`cruxible get Contract:security.sbom-import.params` shows the same
  text). A generator for your project's ecosystem writes the SBOM; Cruxible
  does not, and the SBOM covers only what its generator read: anything it did
  not read is never asked about and never shows as clean. For example, for a
  Python project with a `requirements.txt` (`cyclonedx-py requirements` reads
  only the root `requirements.txt`, not other requirement files or a lock):

  ```sh
  uvx --from cyclonedx-bom cyclonedx-py requirements requirements.txt --of JSON -o sbom.cdx.json
  ```

  For a demo, copy
  [examples/sboms/log4j-demo-app.cdx.json](examples/sboms/log4j-demo-app.cdx.json)
  to `sbom.cdx.json` instead.
- Set the one daily cron time in UTC (the `security.maintain-daily` Trigger,
  14:00 UTC as shipped; see [Schedule](#schedule)) and each Mandate's
  `valid_from` and `expires_at` to your observation window.
- Review the settlement scopes below before adopting them.

```sh
cruxible authoring submit automation.json --no-accept --brief
cruxible proposal list --status open
# The reviewer (see Review above) reviews and approves it:
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal review PROPOSAL_ID
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
# (Owner-only setup, self_approval_allowed: `cruxible proposal approve PROPOSAL_ID --yes`.)
cruxible runbook preview security.start
# Posts OSV advisories with no CVE id (below) when the OSV step lands its result:
cruxible line enable security.osv-unkeyed
# Review the preview separately before running (about half a minute on a 32-component SBOM):
cruxible runbook run security.start
cruxible query --name security.urgent_exposures
cruxible next
```

The Runbook imports the SBOM, queries OSV, reads KEV and EPSS in order, then
posts pairs to the Line inbox (one item per pair, at most 100 per run, most
urgent first): `cruxible next` shows them as `line_inbox_unread`.

- `security.exposure-attention.unjudged` posts each pair nobody has judged whose
  vulnerability is KEV-listed, or has an EPSS score at or above the Line's
  `min_epss` parameter (`0.1` as shipped), or has no EPSS score yet, in every
  inventory (`security.unjudged_exposures_over`). Raise or lower `min_epss` by
  editing the Line; `0` posts every pair nobody has judged. FIRST scores a new
  CVE a day or more after it is published, so the newest CVEs post rather than
  wait. The inbox item carries no score: when a score arrives, a pair at or
  above the threshold stays the same item (seen again, its status and decision
  kept), and a pair below it stops being posted while its item stays in the
  inbox as it was, no longer seen again (core does not withdraw inbox items).
  A pair whose EPSS score is contested is not posted unless it is KEV-listed.
- `security.exposure-attention.contested` posts every pair whose judgment does
  not count (contested, or `affected` beside a justification), with no
  threshold.

Item fields are typed references (`security.exposure-attention@2`):
`inventory`, `component` and `cve_id` are keys of their Subject kinds,
`occurrence` is the occurrence's Subject id, and `state` says why the pair is
there (`unjudged` or `contested`).

OSV advisories with no CVE id yet (a GHSA or PYSEC advisory with no CVE alias)
get one summary item in a separate inbox, `security.osv-unkeyed`. Every finding
is keyed by its CVE id, so such an advisory has no vulnerability Subject, no
Claim and no worklist row. When an OSV result lists any, the
`security.osv-unkeyed` Line posts ONE `security.osv-unkeyed@1` item, however
many there are: `count` (the advisory and component pairs), `sample` (the first
20 pairs: `osv_id`, read it at `https://osv.dev/vulnerability/<osv_id>`, and
`purl`), `matches` (the OSV match document holding every pair under `unkeyed`:
`cruxible capture read <matches>`, below) and `set_digest` (the SHA-256 of the whole
set, the item's identity). Read the list and the advisories and decide (upgrade,
or `ack` the item). A rerun that finds the same set sees the same item again; a
set that changes (an advisory gains a CVE, a new one appears) is a new item, and
the old one stays in the inbox as it was (core does not withdraw inbox items).
An advisory that gains a CVE becomes an ordinary `affected_by` finding on the
next OSV run (on the worklist like any other). The Line is not a Runbook step:
its own Trigger, `security.osv-matches-landed`, runs it whenever the OSV step
lands its result, so it posts only while it is enabled (the `line enable`
above). It changes no accepted state. If the Line was not enabled when OSV ran,
enable it and rerun OSV (`cruxible line run security.osv-query`, or the next
daily run): that result posts the item.

The match document's bytes are base64 in `capture read`'s JSON: `cruxible
capture read <matches> | jq -r .material.body_access.body_base64 | base64 -d |
jq .unkeyed` prints every pair (`cruxible get Capture:<matches>` shows the
Capture's metadata). The document holds advisory ids, their CVE ids and fixed
versions only; read each advisory itself at
`https://osv.dev/vulnerability/<osv_id>`.

An inbox item is a call for attention, not storage. When the list an author
wants seen already exists as state (a Query) or as evidence (a Capture, such as
the OSV match document), post one summary item that points at it (a count, a
short sample, the Query name or the Capture), keyed by what changes when the
list does. Post one item per element only when each needs its own decision and
that decision is recorded nowhere else.

`security.urgent_exposures` and `security.kev_triage_backlog` stay the whole
worklist, whatever the threshold. The preview notes that the two attention
steps read fields `written by no Line (direct entry only)` (`reads_unwritten`
in `--json`): they read the judgments, which agents write and no Line does.

To give one inventory its own threshold, add a Line on the
`security.exposure-attention.unjudged-inventory` Procedure (it reads
`security.inventory_unjudged_exposures_over`) with that inventory's
`inventory_id` and threshold, for example:

```json
{
 "kind": "line",
 "name": "security.exposure-attention.unjudged.app",
 "procedure_name": "security.exposure-attention.unjudged-inventory",
 "bindings": {},
 "parameters": {"inventory": "INVENTORY_ID", "min_epss": "0.05"},
 "acquisition": {},
 "max_authority": "observe"
}
```

Add it to the `security.maintain` Runbook's steps after the shipped attention
Lines. Its items have the same fields as the shipped Line's. Items are kept
per Line: a pair both Lines post is two items, one in each Line's inbox, and
deciding one leaves the other unread. To give every inventory its own
threshold, remove the shipped unjudged Line from the template and add one
per-inventory Line for each inventory, so no pair is posted twice.
It stops on failure or when writes need review. Review and accept those proposals
before rerunning; a step with no new writes passes through. Network calls are
real: OSV uses `api.osv.dev`, KEV uses `www.cisa.gov`, and EPSS uses
`api.first.org`. A source refusal is not a clean security result.

After the initial run, one Trigger keeps the facts current:
`security.maintain-daily` runs the `security.maintain` Runbook (OSV, then KEV,
then EPSS, then the two attention Lines) once a day, and each OSV result runs
`security.osv-unkeyed` through its own Trigger. In a run the Trigger starts,
each step runs under its Line's own enablement, and the Runbook never adds
authority of its own: a step whose Line is not enabled stops the run there.
(A `runbook run` you start yourself runs every step as you, enabled or not.)
Enable all seven Lines with `cruxible
line enable NAME`: `security.sbom-import.app`, `security.osv-query`,
`security.kev-triage`, `security.epss-triage`,
`security.exposure-attention.unjudged`, `security.exposure-attention.contested`
and `security.osv-unkeyed`. `cruxible next` lists any of them you have never
enabled as `line_not_enabled`; that row is expected for a Line you chose to
leave off (for example the SBOM import, if you only ever run it by hand with
`line run`). Editing a Line disables it again. The SBOM import is not on the clock: the
SBOM changes when the repository does, so rerun `cruxible runbook run
security.start` (or `cruxible line run security.sbom-import.app`) with fresh
SBOM bytes. Renew Mandates before expiry and review Procedure upgrades.

### Schedule

The kit ships one daily Trigger, `security.maintain-daily`, at 14:00 UTC
(`"schedule": {"kind": "cron", "expression": "0 14 * * *"}` in
`automation.json`). The expression is standard five-field cron, always read in
UTC. To change it, edit the Trigger's `expression` before submitting the
template, or later revise the Trigger with an ordinary authoring change set
(the same member with a new expression) and have it reviewed like any other.
The Trigger fires only while the daemon runs, and an instant missed while it
was down is not run later. `cruxible next` then shows a
`trigger_instants_missed` row for `security.maintain-daily` whose repair is
`cruxible runbook run security.maintain`: run it to catch up.

A run in which nothing upstream changed still fetches OSV, KEV and EPSS and
records what it read, so it takes time and stored bytes
<!-- TODO(0.5.0): measured bytes per unchanged run -->; weigh that before
running it more often than daily. The records are part of the instance: the
daemon's `exhaust` directory is backed up with the ledger, and no command
prunes it.

## The audit loop

The audit loop needs no automation to start. Agents write through ordinary
`cruxible write` calls, and each field's card links the guidance that governs
it (`cruxible get Document:security.guidance.hunter`, and so on):

1. A hunter works one coverage unit (`repo`, `surface`, `concern`), writes its
   trace to a notes file in the workspace catalog, and reports the finding:
   `reported_at` and `reported_by` cite the code, `rule` cites the notes
   file's `Trace` section, `found_in` links the unit. It leaves the verdict
   alone.
2. A different agent, the verifier, tries to refute it. A `confirmed` verdict
   cites the observed run output of a bounded local check (a catalogued test
   log or output file); its reasoning goes in a new section of the notes file
   in the same write. A refutation cites that section with a `justification`.
   A third agent approves the verdict; no Mandate settles a judgment.
3. `security.coverage_plan` lists units never checked, deferred or blocked;
   `cruxible next` lists findings and units whose cited code changed.

A quoted code line (`--evidence-file PATH#TEXT`) is a pointer for reviewers,
not a witness that resurfaces a judgment: `next` reopens the judgment only when
those exact bytes change, and a judgment that depends on code elsewhere (a
dependency `not_affected` because a function is never called, a finding
refuted as `not_reachable`) can go false while the quoted line stays the same.
Such a code-dependent judgment cites a check result where one exists: a
scanner's findings imported through `security.sarif-import` (below), or the
output file of a bounded local check. Prose (an advisory, a notes section with
the reasoning) keeps quote and section citations.

The citations above are guidance, not something the core enforces. The core
admits a judgment field's value on its author's own words, or on a workspace
file or section citation, wherever the field does not require captured
evidence; of the judgment fields only `security.finding.verification` does
(a SARIF findings payload), beside the source facts the Lines copy (scope,
KEV, EPSS). A verdict or justification written with no citation
is therefore admitted, and it is the reviewer, reading the guidance each
field's card links, who rejects it.

The loop needs three agents: the hunter, the verifier and the approver. In
the default setup the approver is the `reviewer` principal (see
[Review](#review-a-second-agent-approves)): the verifier's write is its own
proposal, and a different principal approves it. The hunter and the verifier
may both write as the owner. Where you want them as separate principals, add
them with `cruxible principal add NAME --key-dir /outside/workspace/NAME-keys
--signer-key OWNER_KEY`, which writes each key and its `cruxible.env` settings
to that directory (a principal that approves also needs `--mode
graph_write`).

To import a scanner's SARIF file, author a Line for `security.sarif-import`
yourself (the automation template doesn't include one): bind `read` to
`cruxible-builtin#workspace.file` and `derive` to
`security-sarif-provider#sarif.findings`, with parameters `relative_path` (the
SARIF file), `logical_source` (`sarif.<scanner>`) and `repo`
(`host/owner/repo`). A full scan that no longer reports a finding marks it
`fixed`; a partial scan never does. Scanner observations land on the same
finding Subjects as agents' reports.

## Automation authority

The committed template retains its existing `max_authority: settle` on the four
source Lines. It does **not** start propose-only. These scoped grants may settle source
observations without another approval after you approve the template:

| Line | Settle Mandate | What may settle |
|---|---|---|
| `security.sbom-import.app` | `security.sbom-import.app-settle` | Create inventory, component and occurrence Subjects; create/revise scope on extracted records; retire scope on absence |
| `security.osv-query` | `security.osv-query-settle` | Create vulnerability Subjects; create/revise component `affected_by` on extracted records; retire on complete answered absence |
| `security.kev-triage` | `security.kev-triage-settle` | Create/revise `listed_in` on extracted/absent records; create/revise KEV dates on extracted records and retire dates on absence; create/revise ransomware use on extracted records |
| `security.epss-triage` | `security.epss-triage-settle` | Create/revise EPSS score, percentile and date from extracted records |
| `security.exposure-attention.unjudged`, `.contested` (and any per-inventory Line you add), `security.osv-unkeyed` | none (`max_authority: observe`) | Nothing: they only post inbox items, and change no accepted state |

No Mandate settles `security.exposure.justification`,
`security.app_exposure.justification` or `security.app_exposure.verdict`. Read
the installed governed dependency guidance before proposing a judgment; a
different actor should review it. An app-level judgment affects one
occurrence; a package-level normative none applies across inventories. OSV
cannot overwrite a held normative none and reports disagreement to the Line
inbox.

A proven-reachable exposure gets the app-level `verdict` `affected`, citing
the code on the call path, with no justification. It moves from the worklists
to `security.confirmed_exposures`, and clears when the inventory's SBOM no
longer lists the vulnerable release; `cruxible next` then lists the verdict
as `claim_dependency_stale`. A pair holding both a justification and an
`affected` verdict, or a contested verdict or justification, counts as not
judged and stays in the worklists.

## Limits and maintenance

Distro purls (`deb`, `rpm`, `apk`) need source-package mapping and are currently
**not checked** by OSV. Failed/incomplete OSV responses never authorize absence
retirement. The SBOM workspace-file limit is 1 MiB: split larger inventories.
An SBOM saying a package is present does not establish runtime reachability.

EPSS asks FIRST for exactly the watched CVEs, at most 100 per request, so a CVE
OSV adds is scored on the next EPSS run with no Line change. A request that
fails leaves the run incomplete; a CVE FIRST has not scored gets no score.
With nothing watched (a repository with no vulnerable dependency), EPSS sends no
request and writes nothing, and the run completes cleanly.

[source/README.md](source/README.md) describes the repeatable release build and
gates. [examples/README.md](examples/README.md) describes the example inputs.
