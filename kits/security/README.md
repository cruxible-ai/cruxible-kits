# Security kit for Cruxible 0.5

This kit is a starting point, not a schema you have to adopt. It seeds an
instance with security vocabulary, guidance Documents, reference pages and an
automation template you tailor. From there the instance is yours to grow:
revise the kit's definitions, add your own, and adapt or replace its
automation, all by ordinary authoring. Facts copied from sources settle
automatically; judgments always need review.

This local release is kit version **1.3.0**, built for Cruxible **0.5** and
provider protocol **2**. It covers two loops:

| Loop | What it does |
|---|---|
| Dependency | Import a CycloneDX SBOM, ask OSV which vulnerabilities affect its components, read CISA KEV and FIRST EPSS for them, then judge whether each exposure applies |
| Audit | Agents (and optionally SARIF scanners) report code findings by key, a second agent judges each one, and coverage units record what was checked against which code |

Every observation cites retained source bytes. Missing or incomplete input
stays unknown; it never means unaffected or clean.

| Installed definitions | Purpose |
|---|---|
| `security.inventory`, `security.component` | An application's inventory and exact package releases |
| `security.occurrence` | The pair (inventory, component), with its scope |
| `security.vulnerability`, `security.component.affected_by` | OSV's affected packages and vulnerabilities |
| `security.exposure`, `security.app_exposure` | Package-level and app-level judgment pairs |
| `security.urgent_exposures`, `security.kev_triage_backlog` | Unjustified exposures, with KEV and EPSS context |
| `security.watched_vulnerabilities` | Vulnerabilities affecting imported components |
| `security.finding` | One weakness at one place in one repository: `rule`, `reported_by`, `reported_at`, `verification`, `severity`, and the judgments `verdict`, `justification`, `fixed_by`, `found_in` |
| `security.coverage_unit` | One surface of one repository checked for one concern, with its `status` |
| `security.finding_verdicts`, `security.coverage_plan`, `security.findings_by_unit` | Audit worklists: findings with their verdicts, units to take up next, findings per unit |
| `security.sarif-import`, `security.sarif-attention` | Procedures that turn a SARIF file into findings, and post regressions and location gaps to an inbox |
| `security.guidance.dependency` | Governed guidance for dependency judgments |
| `security.guidance.hunter`, `.verifier`, `.coverage` | Governed guidance for reporting findings, judging them, and keeping coverage |

The [reference/](reference/) pages are hunting strategy by domain (web and
auth, client side, cloud, AI and LLM, memory safety and more), starting from
[reference/attack-classes.md](reference/attack-classes.md). They are plain
files for the reader; the kit doesn't install them.

The bundled `security-osv-provider` serves `sbom.components`, `osv.query` and
`osv.match`; bundled `cruxible-provider-web` serves the KEV/EPSS HTTP reads;
bundled `security-sarif-provider` serves `sarif.findings` (pure: no network,
no clock). All carry registration schema 2, frozen locks and their runtime
dependency wheel. Provider installation can download the registry dependencies
pinned by those locks.

## Install and first answers

Use Cruxible 0.5 with its daemon running and a Git workspace selected. From a
checkout of this repository (replace paths for your workspace):

```sh
cruxible init --principal-id owner --reviewer-key-dir /outside/workspace/reviewer-keys
# Read the current coordinate, then review the manifest and guidance:
cruxible orient --json
# Use coordinate.git_oid as OID for the explicit install:
cruxible kit add /path/to/cruxible-kits/kits/security --commit --at OID --json
cruxible kit status --offline
```

No Contracts or providers need to be accepted beforehand. Installation governs
the bundled operation Contracts, installs the providers, and proposes the rest.
If your approval policy requires review, approve the proposal as a different
actor and activate it before continuing. `cruxible kit add security:1.3.0` is
**available only after the registry release**; use the local directory now.

`cruxible kit add PATH --json` without `--commit` previews the plan and writes
nothing.

Copy [automation.json](automation.json) to your workspace and tailor it before
submitting. It is a template, never installed or submitted by `kit add`:

- Choose the Line names and update their Mandates, Triggers and Runbook steps
  to match. Keep `security.start` as the Runbook name if using the commands below.
- Set the SBOM Line's `relative_path` and logical source. For a demo, copy
  [examples/sboms/log4j-demo-app.cdx.json](examples/sboms/log4j-demo-app.cdx.json)
  to the template's `sbom.cdx.json` workspace path.
- Set the three daily cron schedules in UTC and each Mandate's `valid_from`
  and `expires_at` to your observation window.
- Review the settlement scopes below before adopting them.

```sh
cruxible authoring submit automation.json --no-accept --json
cruxible proposal list --status open
cruxible proposal review PROPOSAL_ID
# A second actor, with its own registered principal and signing key:
cruxible --principal-id reviewer proposal approve PROPOSAL_ID --key /outside/workspace/reviewer-keys/reviewer.ed25519 --yes
cruxible runbook preview security.start
# Review the preview separately before running:
cruxible runbook run security.start
cruxible query --name security.urgent_exposures
cruxible next
```

The Runbook imports the SBOM, queries OSV, then reads KEV and EPSS in order.
It stops on failure or when writes need review. Review and accept those proposals
before rerunning; a step with no new writes passes through. Network calls are
real: OSV uses `api.osv.dev`, KEV uses `www.cisa.gov`, and EPSS uses
`api.first.org`. A source refusal is not a clean security result.

After the initial run, enable each Line with `cruxible line enable NAME` to let
its Trigger run it. Editing a Line or its Trigger disables it again. Renew
Mandates before expiry, review Procedure upgrades, and supply fresh SBOM bytes.

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

The loop needs three principals: the hunter, the verifier and the approver.
`cruxible init` registers two (owner and reviewer); add the third with
`cruxible principal add verifier --key-dir /outside/workspace/verifier-keys
--signer-key OWNER_KEY`, which writes its key and `cruxible.env` settings to
that directory.

To import a scanner's SARIF file, author a Line for `security.sarif-import`
yourself (the automation template doesn't include one): bind `read` to
`cruxible-builtin#workspace.file` and `derive` to
`security-sarif-provider#sarif.findings`, with parameters `relative_path` (the
SARIF file), `logical_source` (`sarif.<scanner>`) and `repo`
(`host/owner/repo`). A full scan that no longer reports a finding marks it
`fixed`; a partial scan never does. Scanner observations land on the same
finding Subjects as agents' reports.

## Automation authority

The committed template retains its existing `max_authority: settle` on all four
Lines. It does **not** start propose-only. These scoped grants may settle source
observations without another approval after you approve the template:

| Line | Settle Mandate | What may settle |
|---|---|---|
| `security.sbom-import.app` | `security.sbom-import.app-settle` | Create inventory, component and occurrence Subjects; create/revise scope on extracted records; retire scope on absence |
| `security.osv-query` | `security.osv-query-settle` | Create vulnerability Subjects; create/revise component `affected_by` on extracted records; retire on complete answered absence |
| `security.kev-triage` | `security.kev-triage-settle` | Create/revise `listed_in` on extracted/absent records; create/revise KEV dates on extracted records and retire dates on absence; create/revise ransomware use on extracted records |
| `security.epss-triage` | `security.epss-triage-settle` | Create/revise EPSS score, percentile and date from extracted records |

No Mandate settles `security.exposure.justification` or
`security.app_exposure.justification`. Read the installed governed dependency
guidance before proposing either judgment; a different actor should review it.
An app-level judgment affects one occurrence; a package-level normative none
applies across inventories. OSV cannot overwrite a held normative none and
reports disagreement to the Line inbox.

## Limits and maintenance

Distro purls (`deb`, `rpm`, `apk`) need source-package mapping and are currently
**not checked** by OSV. Failed/incomplete OSV responses never authorize absence
retirement. The SBOM workspace-file limit is 1 MiB: split larger inventories.
An SBOM saying a package is present does not establish runtime reachability.

EPSS asks FIRST for exactly the watched CVEs, at most 100 per request, so a CVE
OSV adds is scored on the next EPSS run with no Line change. A request that
fails leaves the run incomplete; a CVE FIRST has not scored gets no score.

[source/README.md](source/README.md) describes the repeatable release build and
gates. [examples/README.md](examples/README.md) describes the example inputs.
