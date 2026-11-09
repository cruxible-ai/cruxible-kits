# Security kit for Cruxible 0.5

Import a CycloneDX SBOM, ask OSV which vulnerabilities affect its components,
and read CISA KEV and FIRST EPSS for those vulnerabilities. Every observation
cites retained source bytes. Missing or incomplete input stays unknown; it never
means unaffected. This local release is kit version **1.3.0**, rebuilt for
Cruxible **0.5** and provider protocol **2**.

| Installed definitions | Purpose |
|---|---|
| `security.inventory`, `security.component` | An application's inventory and exact package releases |
| `security.occurrence` | The pair (inventory, component), with its scope |
| `security.vulnerability`, `security.component.affected_by` | OSV's affected packages and vulnerabilities |
| `security.exposure`, `security.app_exposure` | Package-level and app-level judgment pairs |
| `security.urgent_exposures`, `security.kev_triage_backlog` | Unjustified exposures, with KEV and EPSS context |
| `security.watched_vulnerabilities` | Vulnerabilities affecting imported components |
| `security.guidance.dependency` | Governed guidance for reviewing dependency judgments |

The bundled `security-osv-provider` serves `sbom.components`, `osv.query` and
`osv.match`; bundled `cruxible-provider-web` serves the KEV/EPSS HTTP reads.
Both carry registration schema 2, frozen locks and their runtime dependency
wheel. Provider installation can download the registry dependencies pinned by
those locks. The old analysis/sources providers, system-model and incident
recipes are not part of this release.

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

On the pinned core (`07b11ba84`), a first preview of a kit containing governed
Documents can refuse with `cruxible.kit.document_bodies_not_staged`: the preview
adapter does not stage their bodies. The explicit `--commit --at OID` path stages
the bundled bodies before planning. It does not bypass the approval policy.

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

The generated EPSS Line currently has a literal `?cve=` URL: it does not insert
the watched CVEs automatically. FIRST may return a partial page of its entire
catalog; the completeness check then records an incomplete result and scores
stay unknown. Selecting the watched CVEs dynamically remains a follow-up.

[source/README.md](source/README.md) describes the repeatable release build and
gates. [examples/README.md](examples/README.md) describes the example inputs.
The optional SARIF/audit work remains in source and has its own gates; its
provider and definitions are not bundled by this dependency release recipe.
