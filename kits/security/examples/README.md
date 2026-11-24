# Examples

Inputs for the security kit (Cruxible 0.6):

| File | Meaning |
|---|---|
| `sboms/log4j-demo-app.cdx.json` | Demo application containing log4j-core 2.14.1; a useful live OSV/KEV example, not real deployed software |
| `sboms/cruxible-env.cdx.json` | A recorded Python environment inventory, not a statement of your current environment |
| `sboms/env_sbom.py` | Write an inventory from the Python environment running it |
| `sarif/automation-sarif.json` | A ready-to-submit SARIF intake for one scanner: the import Line, its Mandates (`expires: 90d`) and the attention Line with its landing Trigger |
| `sarif/semgrep-demo.sarif` | A Semgrep SARIF 2.1.0 log of a demo app (`github.com/example/demo-app`) with two findings: SQL injection in `app/db.py` and path traversal in `app/files.py` |

## The dependency loop

Install the local kit directory first (the instance must hold the base kit,
which `cruxible init` installs), then copy the template and example into your
attached Git workspace:

```sh
cp /path/to/cruxible-kits/kits/security/automation.json automation.json
cp /path/to/cruxible-kits/kits/security/examples/sboms/log4j-demo-app.cdx.json sbom.cdx.json
```

Tailor the Line names and references and the daily UTC cron time; there are no
dates to edit (every Mandate is valid for 90 days from submission). The SBOM
Line must read `sbom.cdx.json` (or the workspace-relative path you choose).
Submit with `cruxible authoring submit automation.json --no-accept`, review it
and approve it (`cruxible proposal approve PROPOSAL_ID --yes`: on a one-owner
instance your own approval activates it; under `independent_approval_required`
a different principal approves), then run `cruxible runbook preview
security.start`. Review its availability, order, settlement scopes and the
inputs each step lists as needed before `cruxible runbook run security.start`,
and enable every Line with `cruxible line enable security.osv-unkeyed --runbook
security.start`.

The Runbook makes real OSV, CISA and FIRST network calls. Refusals or incomplete
answers remain gaps. No recorded responses are substituted by this example.
See [the installation instructions](../README.md#install-and-first-answers).

## Static analysis (SARIF)

The SARIF intake needs no network. To try it with the demo log:

```sh
mkdir -p scans
cp /path/to/cruxible-kits/kits/security/examples/sarif/semgrep-demo.sarif scans/semgrep.sarif
cp /path/to/cruxible-kits/kits/security/examples/sarif/automation-sarif.json automation-sarif.json
cruxible authoring submit automation-sarif.json --no-accept
# the reviewer approves it, then:
cruxible line enable security.sarif-import.semgrep security.sarif-attention.semgrep
cruxible line run security.sarif-import.semgrep
cruxible query --name security.finding_verdicts --param repo=github.com/example/demo-app
```

For your own scanner, tailor three things before submitting: the Line suffix
(`semgrep`, in every Line, Mandate and Trigger name and the logical source
`sarif.semgrep`), the repository (`repo`, as `host/owner/repo`; a SARIF run
whose `versionControlProvenance` names another repository writes nothing), and
the SARIF file's workspace path (`relative_path`). One scanner per change set:
copy it again with another suffix for a second scanner, so absence only ever
retires what that scanner's own file wrote. A scan counts as full only when
its run declares the property `"cruxible.coverage": "full"` (add it to the
SARIF run's `properties` when the scan covered the whole repository with no
baseline or path filter, as the demo log does) and every invocation succeeded;
a full scan that no longer reports a finding marks it `fixed`, and a partial
scan never does.

The import settles the scanner's observations (rule, reported_by, severity,
reported_at, verification) and never a verdict. Its grant names those
ClaimTypes by hand: `severity` also permits `normative` (a verifier's own
severity replaces the scanner's), so Cruxible refuses `scope: observations`
for this Line. The findings are then judged as the
[audit loop](../README.md#the-audit-loop) describes.
