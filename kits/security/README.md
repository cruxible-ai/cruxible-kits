# Security kit for Cruxible 0.5

This kit is a starting point, not a schema you have to adopt. It seeds an
instance with security vocabulary, guidance Documents, reference pages and an
automation template you tailor. From there the instance is yours to grow:
revise the kit's definitions, add your own, and adapt or replace its
automation, all by ordinary authoring. Facts copied from sources settle
automatically; judgments always need review.

This local release is kit version **1.3.0**, built for Cruxible **0.5** and
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
| `security.osv-unkeyed` | The Procedure that posts each OSV advisory with no CVE id yet to an inbox, since no Claim can record it |
| `security.sarif-import`, `security.sarif-attention` | Procedures that turn a SARIF file into findings, and post regressions and location gaps to an inbox |
| `security.osv.query`, `security.osv.match`, `security.sbom.components`, `security.sarif.findings` | The capabilities the Procedures' provider slots name: what each call sends and gets back. A derived document's fields are declared on its CaptureKind (`security.osv-matches`, `security.sbom-components`, `security.sarif-findings`), so any provider that returns that layout can serve the slot |
| `security.guidance.dependency` | Governed guidance for dependency judgments |
| `security.guidance.hunter`, `.verifier`, `.coverage` | Governed guidance for reporting findings, judging them, and keeping coverage |

The [reference/](reference/) pages are hunting strategy by domain (web and
auth, client side, cloud, AI and LLM, memory safety and more), starting from
[reference/attack-classes.md](reference/attack-classes.md). They are plain
files for the reader; the kit doesn't install them.

The bundled `security-osv-provider` serves `security.sbom.components`,
`security.osv.query` and `security.osv.match`; bundled `cruxible-provider-web`
0.7.0 serves the base kit's `web.fetch` and `web.fetch.pages` (the KEV and EPSS
reads); bundled `security-sarif-provider` serves `security.sarif.findings`
(pure: no network, no clock). The SBOM and SARIF files are read by core's
builtin `workspace.file`. Each provider carries registration schema 3 (its own
copies of the Contracts and layouts it serves), a frozen lock and its runtime
dependency wheel. Provider installation can download the registry dependencies
pinned by those locks.

## Install and first answers

Use Cruxible 0.5 with its daemon running and a Git workspace selected. From a
checkout of this repository (replace paths for your workspace):

```sh
cruxible init --principal-id owner \
  --reviewer-key-dir /outside/workspace/reviewer-keys --require-independent-approval
# The base kit's proposal from init waits for the reviewer (see Review below):
cruxible kit status --offline
# Read the current coordinate, then review the manifest and guidance:
cruxible orient --json
# Use coordinate.git_oid as OID for the explicit install:
cruxible kit add /path/to/cruxible-kits/kits/security --commit --at OID --json
# The reviewer approves the kit's proposal, then:
cruxible kit status --offline
```

The base kit must be installed first: `init` proposes it, and once it is
accepted `cruxible kit status --offline` shows `base`. Without it, `kit add`
refuses with the repair `cruxible kit add base`. Nothing else needs to be
accepted beforehand: installation installs the three providers (each carries
its own copies of the shapes it serves) and proposes the kit's definitions.
`cruxible kit add security:1.3.0` is **available only after the registry
release**; use the local directory now.

`cruxible kit add PATH --json` without `--commit` previews the plan and writes
nothing.

### Review: a second agent approves

An agent never approves its own proposals. `--reviewer-key-dir` adds a second
principal, `reviewer`, with its key and settings (`cruxible.env`) in that
directory, outside the workspace; `--require-independent-approval` makes the
approval policy `independent_approval_required`, so every proposal (the kit's,
the automation template's, each judgment) activates only once a principal other
than its author approves it. The reviewer is normally a subagent the working
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
(`proposal_awaiting_approval`) when read as `reviewer`.

If you want to approve everything yourself, initialize without the reviewer:
`cruxible init --principal-id owner` leaves the policy `self_approval_allowed`
(the default), where the owner's own `proposal approve` signs and activates
each proposal and nothing waits for a second principal.

Copy [automation.json](automation.json) to your workspace and tailor it before
submitting. It is a template, never installed or submitted by `kit add`:

- Choose the Line names and update their Mandates and Runbook steps to match.
  Keep `security.start` as the Runbook name if using the commands below.
- Set the SBOM Line's `relative_path` (the SBOM file in your workspace) and
  `logical_source`. What the file must contain is in the description of each
  input a Line needs, which `cruxible runbook preview security.start` lists per
  step (`cruxible get Contract:security.sbom-import.params` shows the same
  text). A generator for your project's ecosystem writes the SBOM; Cruxible
  does not. For example, for a Python project with a `requirements.txt`:

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
# Review the preview separately before running:
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
`inventory`, `component` and `cve_id` are keys of their Subject kinds, and
`occurrence` is the occurrence's Subject id.

OSV advisories with no CVE id yet (a GHSA or PYSEC advisory with no CVE alias)
arrive in a separate inbox, `security.osv-unkeyed`. Every finding is keyed by
its CVE id, so such an advisory has no vulnerability Subject, no Claim and no
worklist row; instead the `security.osv-unkeyed` Line posts one
`security.osv-unkeyed@1` item per advisory and component: `osv_id` (read it at
`https://osv.dev/vulnerability/<osv_id>`) and `purl` (the component's key). Read
the advisory and decide (upgrade, or `ack` the item). The Line is not a Runbook
step: its own Trigger, `security.osv-matches-landed`, runs it whenever the OSV
step lands its result, so it posts only while it is enabled (the `line enable`
above). One run posts at most 1,000 items, so it posts the first thousand pairs
(by component, then advisory) and the template carries a Line per further page:
`security.osv-unkeyed.2` for pairs 1,001 to 2,000, and so on to
`security.osv-unkeyed.20`, which takes every pair past 19,000. A page Line
runs only once enabled; when a run reports its page full (1,000 items
posted), enable the next one (`cruxible line enable security.osv-unkeyed.2`).
When an earlier pair leaves, later pairs move up one place, so a pair on a page
boundary is posted again as a new item by the neighbouring page's Line. It changes no accepted state. A rerun that finds the same advisory still
without a CVE sees the same item again. When OSV later lists a CVE for the
advisory, the next OSV run records it as an ordinary `affected_by` finding (on
the worklist like any other) and the item is no longer posted; it stays in the
inbox as it was (core does not withdraw inbox items). If the Line was not
enabled when OSV ran, enable it and rerun OSV (`cruxible line run
security.osv-query`, or the next daily run): that result posts them.

`security.urgent_exposures` and `security.kev_triage_backlog` stay the whole
worklist, whatever the threshold. The preview lists `reads_unwritten` for the
two attention steps: they read the judgments, which agents write and no Line
does.

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
`security.osv-unkeyed` through its own Trigger. Each step runs under its Line's own enablement, so
enable each of those Lines with `cruxible line enable NAME`; a step whose Line
is not enabled stops the run there, and the Runbook never adds authority of its
own. Editing a Line disables it again. The SBOM import is not on the clock: the
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
A run in which nothing upstream changed still fetches OSV, KEV and EPSS and
records what it read, so it takes time and stored bytes; see the release notes
for the per-run figure before running it more often than daily.

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

The loop needs three agents: the hunter, the verifier and the approver. In
the default setup the approver is the `reviewer` principal (see
[Review](#review-a-second-agent-approves)): the verifier's write is its own
proposal, and a different principal approves it. The hunter and the verifier
may both write as the owner. Where you want them as separate principals, add
them with `cruxible principal add NAME --key-dir /outside/workspace/NAME-keys
--signer-key OWNER_KEY`, which writes each key and its `cruxible.env` settings
to that directory.

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
