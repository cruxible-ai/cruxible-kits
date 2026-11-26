# Security kit for Cruxible 0.6

This kit is a starting point, not a schema you have to adopt. It seeds an
instance with security vocabulary, guidance Documents, reference pages and an
automation template you tailor. From there the instance is yours to grow:
revise the kit's definitions, add your own, and adapt or replace its
automation, all by ordinary authoring. Facts copied from sources settle
automatically; judgments always need review.

This release is kit version **1.4.0**, built for Cruxible **0.6** (0.6.0 or
later) and provider protocol **2**; its own providers run on
`cruxible-provider-runtime` 0.6.0 or later. It requires the base kit (`base` 1.0.0, which
`cruxible init` installs) for reading workspace files and fetching web pages.
It covers two loops:

| Loop | What it does |
|---|---|
| Dependency | Import a CycloneDX or SPDX JSON SBOM (container distro packages included), ask OSV which vulnerabilities affect its components, read CISA KEV and FIRST EPSS for them, then judge each exposure: a not_affected justification, or an `affected` verdict that keeps it on the confirmed list until fixed |
| Audit | Agents (and optionally SARIF scanners) report code findings by key, a second agent judges each one, and coverage units record what was checked against which code |

Every observation cites retained source bytes. Missing or incomplete input
stays unknown; it never means unaffected or clean.

| Installed definitions | Purpose |
|---|---|
| `security.inventory`, `security.component` | An application's inventory and exact package releases |
| `security.occurrence` | The pair (inventory, component), with its scope and, for a distro package, the OSV source package it is asked as (`osv_package`) |
| `security.vulnerability`, `security.component.affected_by` | OSV's affected packages and vulnerabilities |
| `security.exposure`, `security.app_exposure` | Package-level and app-level judgment pairs: a `justification` (not_affected), or on the app-level pair the `verdict` `affected` |
| `security.urgent_exposures`, `security.kev_triage_backlog` | Exposures nobody has judged, with KEV and EPSS context |
| `security.unjudged_exposures_over`, `security.inventory_unjudged_exposures_over` | Exposures nobody has judged whose vulnerability is KEV-listed, or has an EPSS score at or above `min_epss`, or has no EPSS score yet, in every inventory or in one: what the unjudged attention Lines post |
| `security.confirmed_exposures` | Exposures judged `affected` whose SBOM still lists the component: fix pending, with KEV and EPSS context |
| `security.not_affected_judgments`, `security.app_not_affected_judgments`, `security.departed_app_not_affected_judgments` | The track record: every package-level judgment; every app-level judgment whose component the inventory's SBOM still lists; and the app-level judgments on a release the SBOM no longer lists (an upgrade or removal), kept as history |
| `security.covered_app_exposures`, `security.covered_package_exposures`, `security.pair_without_judgment_exposures` | Exposures a resolved not_affected judgment covers (app or package level), and worklist pairs that exist with no judgment on them (a withdrawn judgment, or a pair created before judging; a Query cannot tell which): with the worklist and confirmed list, the row counts say how many are covered, new, confirmed and in that last state |
| `it.asset`, `security.inventory.asset`, `security.asset_urgent_exposures` | The deployment anchor: one IT asset (`slug`; `title`, `owner`, `environment`, `exposure`, `criticality`), an inventory's optional link to the asset it runs as, and the worklist with each row's asset beside it (empty for an inventory with no asset). A judgment that relies on the asset pins it (`--based-on it.asset/<slug>#exposure`) and comes back in `next` when it changes ([Deployment context](#deployment-context-itasset)) |
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

## Quickstart: zero authoring

Cruxible 0.6 installs the kit as one proposal and adopts its automation from
recipes the kit ships: you name values (`--param`), never edit JSON. In a Git
workspace with the daemon running:

```sh
# 1. Own the instance; the reviewer approves the base kit init proposes.
cruxible init --principal-id owner --require-independent-approval
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
# 2. Install the kit: ONE proposal (its providers and definitions together).
cruxible kit add security:1.4.0 --commit
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
# 3. Adopt the shared Lines and Runbooks, then one SBOM import per SBOM file.
cruxible kit adopt security --yes
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
cruxible kit adopt security:sbom --param name=app --param relative_path=sbom.cdx.json --yes
cruxible kit adopt security:sbom --param name=api --param relative_path=services/api/sbom.cdx.json --yes
cruxible kit adopt security:schedule --yes          # optional: the daily Trigger
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve ID1 ID2 ID3 --yes
# 4. Enable, run, read, export.
cruxible line enable security.osv-unkeyed --runbook security.start
cruxible runbook preview security.start
cruxible runbook run security.start
cruxible next
cruxible kit run security:export-vex -- --format openvex -o vex.openvex.json
```

`PROPOSAL_ID` is the short id each command prints (12 hex characters; `cruxible
proposal list --status open` lists them). Until `security:1.4.0` is published
to the registry, install from a checkout: `cruxible kit add
/path/to/cruxible-kits/kits/security --commit`.

`cruxible kit run security:init-plan` reads the workspace (SBOMs, SARIF files,
lockfiles, Dockerfiles, the origin remote) and prints these commands with your
paths filled in, plus a generator command when no SBOM exists yet (one per
ecosystem, each writing its own `sbom-<ecosystem>.cdx.json` when there are
several), and for each SARIF file the commands that enable its attention Line and
run its import. It writes nothing, calls nothing and follows no symbolic link.

| Recipe | `kit adopt` | Adds |
|---|---|---|
| `default` | `security` | OSV, KEV and EPSS Lines and Mandates, the attention and OSV unkeyed Lines, the `security.start` and `security.maintain` Runbooks (`min_epss`, `expires`) |
| `sbom` | `security:sbom --param name=N --param relative_path=P` | One SBOM import Line `security.sbom-import.N` (CycloneDX or SPDX JSON at `P`) and its Mandates; adopt once per SBOM |
| `sarif` | `security:sarif --param name=N --param relative_path=P --param repo=host/owner/repo` | One scanner's SARIF import Line, Mandates, attention Line and landing Trigger; adopt once per scanner |
| `schedule` | `security:schedule` | The daily Trigger `security.maintain-daily` (`cron`, 14:00 UTC as shipped); leave it out when CI runs the Runbooks |

`security.start` runs the SBOM imports as one fan-out step, `{"procedure":
"security.sbom-import"}`: every live Line of that Procedure, in Line-name order,
so the second (or tenth) SBOM joins the Runbook with no edit, and `line enable
--runbook security.start` enables them all. With no SBOM Line yet the step is
skipped and the run goes on. `cruxible kit adopt security --list` shows every
recipe's parameters; `--dry-run` previews a recipe (Lines, providers, network
origins, Mandate grants and expiry) and `--render` prints its change set. Each
adoption is an ordinary governed change set under your principal, reviewed
like any other. The rest of this README is the hand-authored path
([automation.json](automation.json)) and what each part does.

## Install and first answers

Use Cruxible 0.6 with its daemon running and a Git workspace selected. From a
checkout of this repository (replace paths for your workspace):

```sh
cruxible init --principal-id owner --require-independent-approval
# init makes the reviewer too (key beside the owner's, outside the workspace) and
# prints the base kit's proposal; the reviewer approves it (see Review below):
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
cruxible kit status --offline
# Preview the install without writing or prompting:
cruxible kit add /path/to/cruxible-kits/kits/security --dry-run
# The commit prints ONE proposal: the three providers and the kit's definitions.
cruxible kit add /path/to/cruxible-kits/kits/security --commit
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal review PROPOSAL_ID
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
cruxible kit status --offline
```

The base kit must be installed first: `init` proposes it, and once it is
accepted `cruxible kit status --offline` shows `base`. Without it, `kit add`
refuses with the repair `cruxible kit add base`. Nothing else needs to be
accepted beforehand. Under independent approval a kit add is one proposal:
the three provider builds (each carrying its own copies of the shapes it
serves) and the kit's definitions, checked together; `proposal review` lists
every provider's operations and network endpoints beside the definitions, and
one approval activates them all. With one owner and self-approval (below) the
same commit installs everything at once.
`cruxible kit add security:1.4.0` installs the same release from the registry
(`ghcr.io/cruxible-ai/kits/security:1.4.0`) once it is published; before
then it refuses (`cruxible.kit.not_found`), so use the local directory. The
same holds for a refusal whose repair is `cruxible kit add security`
(`requires_missing`, from something that requires this kit): that command
fetches the registry release, so until it is published run `cruxible kit add
/path/to/cruxible-kits/kits/security` instead.

`cruxible kit add PATH --dry-run` previews the plan without writing or
prompting (`--json` prints the full plan non-interactively). In an interactive
terminal, bare `cruxible kit add PATH` previews and asks `Commit this change?
[y/N]` (`--yes` commits without asking); without a TTY it previews and prints
the `--commit --at OID` command.

### Review: a second agent approves

An agent never approves its own proposals. `--require-independent-approval`
adds a second principal, `reviewer`, with its key and settings (`cruxible.env`)
in a directory beside the owner's key, outside the workspace and the daemon
state (`$XDG_CONFIG_HOME/cruxible/keys/INSTANCE/reviewer`; init prints its
`CRUXIBLE_ENV_FILE`, and `--reviewer-key-dir DIR` puts it elsewhere), and makes
the approval policy `independent_approval_required`, so every proposal (the base
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

The kit add proposal is planned against the instance as it was when it was
proposed. If other writes land before the reviewer approves it, approval lands
the same change set at the new head and signs that when it still applies there;
when it does not, the approval refuses (`readmit_requires_resubmission`): run
the same `cruxible kit add ... --commit` again, have the reviewer approve the
new proposal, and withdraw the stale one (`cruxible proposal withdraw
PROPOSAL_ID --reason TEXT`), which otherwise stays open.

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

  An SPDX JSON SBOM works the same way (a container image: `syft IMAGE -o
  spdx-json=sbom.spdx.json`; see [SBOM formats](#sbom-formats-and-container-distro-packages)).

  For a demo, copy
  [examples/sboms/log4j-demo-app.cdx.json](examples/sboms/log4j-demo-app.cdx.json)
  to `sbom.cdx.json` instead.
- Set the one daily cron time in UTC (the `security.maintain-daily` Trigger,
  14:00 UTC as shipped; see [Schedule](#schedule)). There are no dates to edit:
  every Mandate is `"expires": "90d"` with no `valid_from`, so its window starts
  when you submit the template and runs 90 days (Cruxible 0.6 stores both as
  instants). Renew before then (`cruxible next` lists each as `mandate_expiring`).
- Review the settlement scopes below before adopting them.

```sh
cruxible authoring submit automation.json --no-accept --brief
cruxible proposal list --status open
# The reviewer (see Review above) reviews and approves it:
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal review PROPOSAL_ID
CRUXIBLE_PRINCIPAL_ID=reviewer cruxible proposal approve PROPOSAL_ID --yes
# (Owner-only setup, self_approval_allowed: `cruxible proposal approve PROPOSAL_ID --yes`.)
cruxible runbook preview security.start
# Enable every Line at once: the six the start Runbook names, and the unkeyed Line
# (no Runbook step: it posts OSV advisories with no CVE id when OSV lands a result):
cruxible line enable security.osv-unkeyed --runbook security.start
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

For an advisory with a CVE, the fixed versions also travel on the `affected_by`
Claim itself: its reason reads `OSV GHSA-jfh8-c2jp-5v3q lists CVE-2021-44228
for pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 (fixed in: 2.12.2,
2.15.0, 2.3.1)`, so `cruxible get <claim>` shows where to upgrade without
decoding the match document. They are no Claim (nothing reacts to their
change): the reason records them as OSV listed them when it first reported the
pair, and the newest match document holds the current list.

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
`cruxible line enable security.osv-unkeyed --runbook security.start` enables
all seven Lines in one command, one receipt line each (enabled, already
enabled, or refused with its repair): `security.osv-unkeyed`, then every Line
the start Runbook names (`security.sbom-import.app`, `security.osv-query`,
`security.kev-triage`, `security.epss-triage`,
`security.exposure-attention.unjudged` and
`security.exposure-attention.contested`). The unkeyed Line is named on its own
because no Runbook step can name it (it binds the Capture that triggers it).
`cruxible next` lists any of them you have never
enabled as `line_not_enabled`; that row is expected for a Line you chose to
leave off (for example the SBOM import, if you only ever run it by hand with
`line run`). Editing a Line disables it again. The SBOM import is not on the clock: the
SBOM changes when the repository does, so rerun `cruxible runbook run
security.start` (or `cruxible line run security.sbom-import.app`) with fresh
SBOM bytes. Renew Mandates before expiry (`cruxible line grant LINE
--settle-observations` re-grants KEV's and EPSS's for another 90 days) and review
Procedure upgrades.

### Schedule

The kit ships one daily Trigger, `security.maintain-daily`, at 14:00 UTC
(`"schedule": {"kind": "cron", "expression": "0 14 * * *"}`): the
`schedule` recipe (`cruxible kit adopt security:schedule`, or `--param
cron="30 6 * * *"` for another time), also in `automation.json`. A
repository whose CI runs the Runbooks leaves it out. The expression is
standard five-field cron, always read in UTC. To change it, adopt the recipe
with another `cron`, edit the Trigger's `expression` before submitting the
template, or later revise the Trigger with an ordinary authoring change set
(the same member with a new expression) and have it reviewed like any other.
The Trigger fires only while the daemon runs, and an instant missed while it
was down is not run later. `cruxible next` then shows a
`trigger_instants_missed` row for `security.maintain-daily` whose repair is
`cruxible runbook run security.maintain`: run it to catch up.

A run in which nothing upstream changed still fetches OSV, KEV and EPSS and
records what it read, so it takes time and stored bytes
<!-- TODO: measured bytes per unchanged run -->; weigh that before
running it more often than daily. The records are part of the instance: the
daemon's `exhaust` directory is backed up with the ledger, and no command
prunes it.

## Deployment context: `it.asset`

Whether a vulnerable release matters depends on where it runs. `it.asset` is one
lean kind for the deployment facts dependency judgments rely on, keyed by `slug`:
`title`, `owner` (the team that answers for it), `environment` (`prod`,
`staging`, `dev`), `exposure` (ranked `isolated` < `internal` < `internet`)
and `criticality` (ranked `low` < `medium` < `high` < `critical`). The two
ranked fields are ordered enums (Cruxible 0.6), so queries compare and sort
them by rank: `cruxible query it.asset --where 'criticality>=high' --order-by
-exposure` lists the high and critical assets, internet-facing first (`where`
`criticality__gte="high"` in the SDK). `security.inventory.asset`
links an SBOM inventory to the asset it runs as (when one build runs as several,
link the most exposed). Both are optional: an inventory with no asset is triaged
exactly as before. One write records an asset and links it (`cruxible write
asset.json`; the reviewer approves it like any other write):

```json
{
 "because": "Payments API: prod, reachable only through the internal load balancer (infra/lb.tf).",
 "changes": [
  {"op": "create", "label": "asset", "subject_kind": "it.asset",
   "key": [{"predicate": "it.asset.slug", "value": "payments-api"}]},
  {"op": "set", "subject": {"created": "asset"}, "field": "title", "value": "Payments API"},
  {"op": "set", "subject": {"created": "asset"}, "field": "owner", "value": "payments-team"},
  {"op": "set", "subject": {"created": "asset"}, "field": "environment", "value": "prod"},
  {"op": "set", "subject": {"created": "asset"}, "field": "exposure", "value": "internal"},
  {"op": "set", "subject": {"created": "asset"}, "field": "criticality", "value": "critical"},
  {"op": "set", "subject": "security.inventory/pkg:maven/com.example/payments-api@1.4.0",
   "field": "asset", "value": {"created": "asset"}}
 ]
}
```

`cruxible query --name security.asset_urgent_exposures` is the worklist
(`security.urgent_exposures`, same rows) with each row's asset, owner,
environment, exposure and criticality, ranked by deployment risk: the most
exposed asset first, then the most critical, then KEV-listed, then EPSS; rows of
an inventory with no asset come last. A judgment that relies on the asset pins
the fields it relied on (Cruxible 0.6 `based_on`), so it stays quiet while they
hold and comes back on its own when one changes. For an internal-only service
(`cruxible write judgment.json --no-accept`; the reviewer approves it):

```json
{
 "because": "Internal-only service: no untrusted client reaches the JNDI lookup (notes/log4shell.md#reachability).",
 "changes": [
  {"op": "create", "label": "pair", "subject_kind": "security.app_exposure",
   "key": [{"predicate": "security.app_exposure.occurrence", "value": "security.occurrence/OCCURRENCE"},
           {"predicate": "security.app_exposure.vulnerability", "value": "security.vulnerability/cve-2021-44228"}]},
  {"op": "set", "subject": {"created": "pair"}, "field": "justification",
   "value": "vulnerable_code_cannot_be_controlled_by_adversary", "role": "normative",
   "based_on": ["it.asset/payments-api#exposure", "security.occurrence/OCCURRENCE#scope"]}
 ]
}
```

The write resolves each `kind/id#field` to that field's one live Claim and pins
its exact version. When the asset's `exposure` later becomes `internet` (or the
SBOM drops the release, retiring the `scope`), `cruxible next` lists the
judgment as `claim_dependency_stale`, naming the Claim that changed: re-judge it
and pin again, or retire it. The governed dependency guidance says which fields
each judgment pins.

The `it.` prefix is reserved for a future IT asset kit (inbound discovery Lines
and the inventory kinds they need). This kit holds only the anchor its
judgments rest on, and adds no host, cluster, network or vendor kinds; it owns
`it.` until that kit does.

## The audit loop

The audit loop needs no automation to start. Agents write ordinary Claims, and
each field's card links the guidance that governs it (`cruxible get
Document:security.guidance.hunter`, and so on). The
[security-audit skill](skills/security-audit/SKILL.md) runs the loop from that
live guidance. Pick the surface by what the agent can do:

| Surface | For | Why |
|---|---|---|
| Typed Python SDK: `cruxible python` with `.cruxible/world.pyi` | coding agents, whenever Python runs | the instance's kinds, fields and enum members as types (`cruxible python --check` refuses a misspelling before the write), notes sections as evidence (`cx.section(...)`), pins with `based_on=`; runs with the CLI's own interpreter in any repository, whatever its own Python or venv |
| MCP | agents with no code execution | the same verbs as tools |
| CLI: `cruxible orient`, `cruxible next`, `cruxible write --example`, `cruxible proposal ...` | quick inspection, and as a backup | one command per read or write |

```bash
cruxible python - <<'PY'
from typing import TYPE_CHECKING, cast
from cruxible_client import Cruxible
if TYPE_CHECKING:
    from world import World
with Cruxible.connect() as cx:
    w = cast("World", cx.world())
    print(w.describe())
PY
```

Whatever the surface, each Claim carries one piece of evidence: a code
location or a fact's `holds` cites a single quoted line (`path#<quoted line>`,
found once in the file, never a multi-line function body), and a judgment
cites the notes section holding its reasoning (a `confirmed` verdict cites its
check's output line instead). An agent's `severity` is written with role
`normative`. The steps:

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

To import a scanner's SARIF file, adopt the `sarif` recipe once per scanner
(`cruxible kit adopt security:sarif --param name=semgrep --param
relative_path=scans/semgrep.sarif --param repo=github.com/acme/api`), or submit
[examples/sarif/automation-sarif.json](examples/sarif/automation-sarif.json), the
same change set for one scanner, by hand: the `security.sarif-import.semgrep`
Line (`read` bound to `cruxible-builtin#workspace.file`, `derive` to
`security-sarif-provider#sarif.findings`, parameters `relative_path`,
`logical_source` `sarif.semgrep` and `repo`), its Mandates (`expires: 90d`) and
the attention Line its landing Trigger runs. Tailor the suffix, the repository
and the SARIF path; [examples/sarif/semgrep-demo.sarif](examples/sarif/semgrep-demo.sarif)
is a demo log to try it with ([examples/README.md](examples/README.md#static-analysis-sarif)).
A full scan that no longer reports a finding marks it `fixed`; a partial scan
never does. Scanner observations land on the same finding Subjects as agents'
reports.

## Automation authority

The committed template retains its existing `max_authority: settle` on the four
source Lines. It does **not** start propose-only. These scoped grants may settle source
observations without another approval after you approve the template. Each is
valid for 90 days from submission (`"expires": "90d"`):

| Line | Settle Mandate | What may settle |
|---|---|---|
| `security.sbom-import.app` | `security.sbom-import.app-settle` (`scope: observations`) | Every ClaimType the import writes (`scope`, `osv_package`), pinned at its digest: create/revise on extracted records, retire on absence; create the inventory, component and occurrence Subjects |
| `security.osv-query` | `security.osv-query-settle` (scope named by hand) | Create vulnerability Subjects; create/revise component `affected_by` on extracted records; retire on complete answered absence |
| `security.kev-triage` | `security.kev-triage-settle` (`scope: observations`) | Every KEV ClaimType the Procedure writes, pinned at its digest: create/revise on extracted records; `listed_in`'s inverse and the dates' retirement on complete absence; create the `security.catalog` Subject |
| `security.epss-triage` | `security.epss-triage-settle` (`scope: observations`) | Every EPSS ClaimType the Procedure writes (score, percentile, date), pinned at its digest: create/revise on extracted records |
| `security.exposure-attention.unjudged`, `.contested` (and any per-inventory Line you add), `security.osv-unkeyed` | none (`max_authority: observe`) | Nothing: they only post inbox items, and change no accepted state |

`scope: observations` (Cruxible 0.6) is one grant over every ClaimType a Line's
Procedure writes, lowered at submission to the same per-ClaimType scope you
would write by hand; core refuses it for a Procedure that writes any ClaimType
permitting `normative`, so it can never settle a judgment. Its
`subject_creation` may name the nested key ends a creating spec makes (the SBOM
import's inventory and component, beside the occurrence). Only OSV keeps a
scope named by hand, one ClaimType, because `affected_by` also carries an
agent's package-level "none of V" judgment (it permits `normative`).

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

## Provider upgrades

The kit's own pure operations (`sbom.components`, `osv.match`,
`sarif.findings`) are `@derive` functions on `cruxible-provider-runtime` 0.6:
each declares `effect: pure` with no endpoint, so a rebuilt build of the same
operations is a pure, non-widening move. Install it with `cruxible provider
install WHEEL --lock LOCK --dependency RUNTIME_WHEEL --move`: one proposal
registers the build and moves every Line bound to the old build onto it, and
the reviewer approves it once. What each Line's settle grant does on that
move is core's rule, not the kit's:

- A settle grant that covers only observation ClaimTypes, **creates no
  Subjects** and is read by no Mandate condition keeps settle, and its Line
  stays enabled on its successor (the move output says `retains observation
  settle on ...`).
- Any other grant demotes to propose in the same proposal and says why. As
  shipped, `security.sbom-import.app-settle` and `security.osv-query-settle`
  create Subjects (the inventory, components and occurrences; vulnerabilities),
  so both demote (`subject_creation`), and their Lines need `cruxible line
  enable --runbook security.start` again and a re-grant (submit the template's
  Mandate again). An operator whose inventory already exists can grant the
  SBOM Line `scope: observations` without `subject_creation`, so a release that
  adds a package goes to review; that grant then survives every pure move with
  its enablement.
- `kit add` and `kit upgrade` never keep settle, even for a pure build.

`test_cli_gate.py` runs exactly this on a real daemon: the shipped grants
demote with `subject_creation`, and the SBOM grant without it keeps settle
(`security.occurrence.scope` and `.osv_package`) and its Line's enablement.

## SBOM formats and container distro packages

The SBOM import reads CycloneDX JSON and SPDX 2.2/2.3 JSON (GitHub's
dependency-graph export, `syft -o spdx-json`, `trivy --format spdx-json`),
detected by content. In SPDX, a package with a `purl` external reference is a
component, the described package names the inventory, and relationships give
the scope (`DEV_`/`TEST_`/`BUILD_DEPENDENCY_OF` excluded,
`OPTIONAL_DEPENDENCY_OF` optional, the rest required).

OSV keys distro packages (`deb`, `rpm`, `apk`) by release and **source**
package (`libc6` is `glibc` to OSV), and a component's purl key drops both.
So the import records what the SBOM states as the occurrence's `osv_package`
(`ECOSYSTEM|NAME|VERSION`, listed by `security.osv_distro_packages`), and OSV is
asked by it:

| purl | OSV ecosystem |
|---|---|
| `pkg:deb/debian/...?distro=debian-12` | `Debian:12` |
| `pkg:deb/ubuntu/...?distro=ubuntu-22.04` | `Ubuntu:22.04` |
| `pkg:apk/alpine/...?distro=alpine-3.19.1` (Trivy: `distro=3.19.1`) | `Alpine:v3.19` |
| `pkg:apk/wolfi/...`, `pkg:apk/chainguard/...` | `Wolfi`, `Chainguard` |
| `pkg:rpm/redhat/...` | `Red Hat` |
| `pkg:rpm/rocky/...?distro=rocky-9.3`, `pkg:rpm/almalinux/...?distro=almalinux-9.3` | `Rocky Linux:9`, `AlmaLinux:9` |

The source package comes from the purl's `upstream` qualifier, Syft
(`syft:package:metadata:source`) or Trivy (`aquasecurity:trivy:SrcName`)
properties, or SPDX `sourceInfo`; in a Syft SBOM a deb or apk package with no
source stated is its own source (Syft states it only when it differs).
Nothing is guessed: a distro package with no or an unknown release, or no
stated source, is never asked and reads **not checked**, never clean; the
derived SBOM document counts each reason under `distro`
(`no_distro_qualifier`, `unknown_distro`, `no_source_package`, `no_version`).
OSV's finding lands on the binary component (`libc6` affected by glibc's CVE),
with the release's own fixed versions in its reason.

## Exporting VEX

The kit's read-only script `export-vex` ([scripts/export_vex.py](scripts/export_vex.py))
writes the judgments as a CycloneDX 1.5 VEX or OpenVEX v0.2.0 document
(standard library and `cruxible_client` only). `cruxible kit run` checks the
script against the installed release (the receipt's bundle digest and the
file's sha256) and runs it here, never in the daemon:

```sh
cruxible kit run security:export-vex -- --format openvex -o vex.openvex.json
cruxible kit run security:export-vex -- --format cyclonedx --inventory pkg:maven/com.example/app@1.0.0 > vex.cdx.json
```

From a pulled kit directory, `cruxible python scripts/export_vex.py --format
openvex` runs the same file.

Every read is pinned to the head as the export starts, and the document names
that coordinate (instance, generation, git oid, state digest); the timestamp is
the generation's own and the serial derives from the coordinate, so a re-export
at the same coordinate is byte-identical. One statement per current exposure:
confirmed `affected` (CycloneDX `exploitable`, with OSV's fixed versions),
resolved app- or package-level not_affected (with its justification and
reason), and everything else on the worklist, contested judgments included,
as `in_triage` / `under_investigation`; the export refuses rather than ever
state a contested pair `not_affected`. Releases the SBOM no longer lists are
left out. Each statement cites its Claims and their Captures.

## Limits and maintenance

Failed/incomplete OSV responses never authorize absence
retirement. The SBOM workspace-file limit is 1 MiB: split larger inventories.
An SBOM saying a package is present does not establish runtime reachability.

EPSS asks FIRST for exactly the watched CVEs, at most 100 per request, so a CVE
OSV adds is scored on the next EPSS run with no Line change. A request that
fails leaves the run incomplete; a CVE FIRST has not scored gets no score.
With nothing watched (a repository with no vulnerable dependency), EPSS sends no
request and writes nothing, and the run completes cleanly.

[source/README.md](source/README.md) describes the repeatable release build and
gates. [examples/README.md](examples/README.md) describes the example inputs.
