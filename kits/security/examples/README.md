# Consumer automation example

`automation.json` is an inert authoring ChangeSet. Installing the kit does not
submit it.

**Nine of its Lines are examples named for the kit's own repository**:
`security.repo-pull.cruxible-ci`, `security.repo-parse.cruxible-ci`,
`security.registry-pull.cruxible`, `security.registry-parse.cruxible`,
`security.registry-pull.cruxible-client`, `security.registry-parse.cruxible-client`
and `security.sarif-import.cruxible` / `security.sarif-attention.cruxible` with
`security.harden`. Rename them for your own repositories and packages (and their
`parameters`, Triggers and Mandates), or leave them out of what you submit: a Line
you submit and never enable shows in `cruxible next` as `line_not_enabled` on every
run. The quickstart needs none of them. Copy it into your workspace and let your agent adapt nineteen Line names and inputs,
Trigger targets and UTC cron times, and eleven Mandate namespaces. Update all
references when renaming. Replace `NOW` and `EXPIRES` with UTC timestamps
(e.g. now and 90 days later). Landing Triggers name the contract and its logical source.

The system model's members name one repository (`cruxible-ai/cruxible`, its
`main` workflows) and two PyPI projects: replace their Line `parameters` with
your own sources. Each source is a pull Line (cron) and a parse Line (its
landing Trigger) with the same source in its parameters; `security.harden`
takes your default branch and the pull Procedure names it names in gap
items. Add a pair per further source; a source you pull only once (a tag, a
commit an HQ5 gap names) needs only its parse Line and landing Trigger, since
the pull Procedures run directly (`cruxible procedure run`).

The code findings' members are one repository's pair of Lines,
`security.sarif-import.cruxible` and `security.sarif-attention.cruxible` (parameter
`repo_ref`, `github.com/owner/repo`), each with a `security.file-v1` landing Trigger,
and the import's propose Mandate. Add a pair per repository you scan; every other
repository's log halts `wrong_repo`. Let the principal that runs your scans enable
the import Line: its runs act as that principal, so under
`independent_approval_required` its proposals need another reviewer. No Mandate covers
a verdict.

Incident response's members are `security.inventory-import.prod` (parameter `scope`:
one Line and `security.file-erasable-v1` landing Trigger per inventory scope; a
scan or SBOM naming another scope halts `other_scope`), `security.credential-import`
with its `security.file-erasable-v1` landing Trigger, and the propose Mandates of
the inventory, log and credential imports. Let the principal that acquires your scans
and state reads (not the one who patches or rotates) arm the import Lines. Each
incident's respond Line and log import Line are declared with the incident itself
([Declare the incident](../walkthroughs.md#declare-the-incident) in the kit's walkthroughs); `incident-status.md` is an example
status page with a projection block the incident's status query renders. No Mandate
covers an audit result, a verification, a remediation, a credential fact or an
incident field.

Submit with `cruxible authoring submit automation.json`, inspect the resulting
proposal, obtain the consumer's required approvals and activate it through the
ordinary proposal flow. Enable each Line explicitly with `cruxible line enable
NAME`. Start with these propose grants; review the resulting SBOM, KEV, EPSS and
applicability proposals.

For KEV/EPSS graduation, review the field scopes and keyed-vulnerability
condition in the main README's [Measure and graduate](../README.md#measure-and-graduate) and
`gate/recipe.py`'s `graduate()`. Submit that separate ChangeSet through the same
approval flow and re-enable the two changed Lines. Applicability stays propose-only.
Compatible named Procedure revisions retain Line bytes and enablements. Exact
Procedure revisions carry Mandates to propose-only; review and re-grant settle.
The gate loads this file and supplies fixture bindings and validity timestamps.

For an observation window anchored on a landing, author a window-close Trigger
by contract name too (choose the Line/action and duration for your workflow):

```json
{"kind": "trigger", "name": "consumer.kev-window-close",
 "line_name": "security.kev-triage",
 "schedule": {"kind": "window_close", "window": {"kind": "capture_event",
   "capture_contract": "security.fetched-v1", "logical_sources": ["cisa.kev.catalog"], "duration_seconds": 86400}}}
```

Prepare resolves the current CaptureContract; retained Triggers and windows
retain their source filters; execution records resolved exact digests.
