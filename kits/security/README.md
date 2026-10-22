# Security kit

## What it is

The security kit gives your agents a cited model of what you ship and how it is
published, joined to public vulnerability evidence and to the weaknesses found in
your own code, and carries them through an incident: patch, audit, rotate. It holds your releases and their components, your repositories' CI
workflows and jobs, and the registries you publish to with the files they serve;
beside them, what CISA KEV, FIRST EPSS, OSV.dev and CVE records say about
vulnerabilities, and what your scanners and agent reviewers report about your
code, with the verdict your reviewers reached. Every fact points to the
retained copy of the source it was read from. Judgments, such as whether a
release is affected or what explains a mismatch, are proposed by agents and
settled by your review, or automatically by automation that has earned it.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which of my releases are exposed to a vulnerability attackers exploit, and which first? | `security.urgent_exposures`: releases assessed affected (by OSV per SBOM component, or by a CVE record's version ranges), KEV-listed first, then by EPSS score; `component` names the dependency OSV found it in; `asset` is a host that declares installing it (`asset_observed` when a scan also sees it running there) and `observed` a host only a scan sees |
| Is release X affected by this KEV entry? | `security.triage` for the CVE: each release's assessment, with the CVE's KEV and EPSS facts |
| Which internet-facing hosts run an affected, KEV-listed release? | `security.kev_exposure`: your inventory of hosts and what they install, joined to the assessments |
| What can publish to PyPI without a `v*` tag? | `security.publish_paths` (HQ1): jobs in your repository's workflows that can publish to the target, whose triggers the target's publish gate does not allow |
| Which credentialed jobs run mutable third-party code? | `security.mutable_actions` (HQ3): actions not pinned to a commit SHA in jobs that hold a write permission or a secret |
| Does what PyPI serves match what we built? | `security.served_vs_declared` (HQ5): PyPI's digests and provenance against the workflow and commit that declare them |
| Which exploited vulnerabilities has nobody triaged yet? | `security.kev_triage_backlog`: assessments of KEV-listed CVEs with no status, or inconclusive |
| Which weaknesses in our code are still open, and who says so? | `security.open_findings`: every finding of a repository not verified fixed, with its verdict (`conflict` while disputed), severity, location, finders and remediation |
| Do we serve a release with a confirmed, unfixed weakness? | `security.published_findings` (HQ6): confirmed findings not verified fixed in a release a gated target serves a file of |
| How often is each scanner or agent right? | `security.finder_record`: every finding with the finders that reported it and its verdict; upheld (confirmed, not_exploitable) against overturned (false_positive) |
| In an incident: which deployments run an affected release, is each patched, were we exploited, which keys need rotating? | the incident's respond Line (RQ1-RQ5) and `security.incident_exposure`, `security.open_patches`, `security.audit_status`, `security.incident_credentials`, `security.incident_status` ([Respond to an incident](#respond-to-an-incident)) |

Ask any of them with `cruxible query --name NAME`. The hardening questions
(HQ1-HQ6) are also asked for you on a schedule, and each answer is **found**,
**none** (looked, nothing matches) or **unknown** (not read yet: it names the
pull that would answer it); never "none" for something nobody read.

An agent doing this work can load two skills. The [security intake
skill](skills/security-intake/SKILL.md) pulls your state in: an SBOM per
repository, a runtime inventory per scope, services and their credentials, and
log sources, then whatever an unknown answer names. The [security analyst
skill](skills/security-analyst/SKILL.md) gives the order to work these
questions in, and the rules that keep its judgments reviewable.

**Coming from the Cruxible quickstart?** You've done [Install and first
answers](#install-and-first-answers), declared an incident and added its respond
Line. To carry the response through (patches, log audits, key rotations, and
the log import Line and re-ask Triggers the quickstart left out), continue at
[Respond to an incident](#respond-to-an-incident). For your CI and registries,
see [Your systems](#your-systems-the-hardening-questions); for scanner and
reviewer findings in your own code, [Your code's findings](#your-codes-findings).

## How it models your world

Four words carry the rest of this README. A **Subject** is one thing the kit
models, of one kind: a repository, a job, a release, a vulnerability. A
**Claim** is one statement about a Subject (a field and its value) with a role,
either an *observation* (what a source said) or *normative* (what someone
decided), and the evidence it cites. A **Capture** is the retained copy of what
a source returned (a KEV catalog, a repository's workflow files at a commit, a
PyPI answer), kept by content digest so a Claim can point to it. A **Line** is
standing automation: one deterministic Procedure with its inputs, started by
Triggers (a schedule, or a Capture landing) and capped at what it may do:
observe, propose for review, or settle.

<!-- concept-map: checked by source/reference.py -->
```mermaid
flowchart LR
  subgraph systems["Your systems"]
    direction TB
    repo["security.repo"]
    workflow["security.workflow"]
    job["security.job<br/>permissions, secrets, actions"]
    target["security.target<br/>PyPI project, GHCR image, ..."]
    artifact["security.artifact<br/>one published file"]
    change["security.change<br/>a commit"]
    product["security.product"]
    release["security.release<br/>components: purl@version"]
    asset["security.asset<br/>a host or workload"]
    service["security.service<br/>its owner, its log sources"]
    credential["security.credential<br/>a key's non-secret id"]
    finding["security.finding<br/>a weakness in our code"]
  end
  subgraph world["The world's evidence"]
    direction TB
    kev(["CISA KEV"])
    epss(["FIRST EPSS"])
    osv(["OSV.dev, CVE records"])
    registry(["PyPI, GitHub releases"])
    scans(["SARIF scans: Semgrep, CodeQL, agents"])
    inventory(["Runtime inventory: your scans, Syft"])
    logs(["Your log tools, your key issuers"])
    vulnerability["security.vulnerability"]
  end
  subgraph judged["Judgments, and what we have read"]
    direction TB
    assessment["security.assessment<br/>affected / not_affected / inconclusive"]
    signal["security.signal<br/>something to explain"]
    remediation["security.remediation"]
    exception["security.exception<br/>an accepted risk, until it expires"]
    coverage["security.coverage<br/>a source read in full, at a revision"]
    incident["security.incident<br/>one response, its window"]
    audit["security.audit<br/>exploited in the window?"]
  end
  workflow -->|workflow.repo| repo
  job -->|job.workflow| workflow
  job -->|job.publishes_to| target
  target -->|target.source_repo| repo
  artifact -->|artifact.target| target
  artifact -->|artifact.published_by| workflow
  artifact -->|artifact.built_from| change
  artifact -->|artifact.release| release
  release -->|release.product| product
  asset -->|asset.installs| release
  kev -->|vulnerability.kev_listed| vulnerability
  epss -->|vulnerability.epss_score| vulnerability
  osv -->|assessment.status| assessment
  registry -->|artifact.sha256, artifact.published_by| artifact
  assessment -->|assessment.vulnerability| vulnerability
  assessment -->|assessment.release| release
  signal -->|signal.observed| artifact
  signal -->|signal.explained_by| job
  remediation -->|work.job| job
  scans -->|finding.reported_by, finding.rule| finding
  finding -->|finding.repo| repo
  finding -->|finding.affects| release
  finding -->|finding.fixed_by| change
  remediation -->|work.finding| finding
  signal -->|signal.explained_by| finding
  remediation -->|work.assessment| assessment
  exception -->|work.asset| asset
  exception -->|work.assessment| assessment
  workflow -->|workflow.coverage| coverage
  coverage -->|coverage.of| repo
  inventory -->|asset.runs, asset.scanned_in| asset
  asset -->|asset.runs| release
  asset -->|asset.serves| service
  incident -->|incident.vulnerability| vulnerability
  audit -->|audit.incident| incident
  audit -->|audit.service| service
  logs -->|audit.read, credential.key_id| audit
  credential -->|credential.used_by| service
  remediation -->|work.asset| asset
  remediation -->|work.credential| credential
  remediation -->|work.audit| audit
```

**Your systems.** What you ship and how it is published. Pull Lines read your
repository's workflow files at a ref and your registries' published files; parse
Lines turn each read into observations: a workflow's triggers, a job's
permissions, secrets, actions and publish targets, a published file's digest and
the workflow and commit that built it. Releases and their components come from
your CycloneDX SBOMs, hosts and what they install from your own inventory, and
what each host or workload actually runs from your runtime-inventory scans.
Nothing here is asserted by the kit: each fact cites the Capture it was read
from, and the one policy statement, a target's `publish_gate`, is yours. A
finding is one weakness in your own code: what scanners and agents report about
it cites their SARIF log, and its `verdict` is your reviewers' decision.

**The world's evidence.** What public sources say. KEV and EPSS facts land on a
vulnerability (`security.vulnerability`, keyed by CVE id), verbatim from the
catalog or the daily file; OSV.dev and CVE records decide applicability; PyPI and
GitHub releases say what a registry actually serves. World evidence attaches to
your systems in two places: a vulnerability meets a release in an
**assessment**, and what a registry serves meets the workflow and commit that
declare it on an **artifact**.

**Judgments, and what we have read.** An assessment is one (release, CVE) pair,
proposed from OSV or a CVE record, or decided by an analyst. A signal is a
mismatch or event to explain (a served digest that differs from the declared
one); hypotheses (`explained_by`) compete until a cited change resolves them. A
remediation (or an exception, or a compensating control) is the work you decide
on. Coverage is the kit's record of what it has read in full and at which
revision: absence counts as an answer only inside a current coverage, so a
stale or missing read makes an answer unknown, not none. An incident groups the
CVEs of one response; an audit asks, per service, whether you were exploited in
its window, starting from the log sources the service lists; a credential is a
key you may need to rotate, by its non-secret id.

<!-- BEGIN GENERATED: glance -->
<!-- Generated by source/reference.py from the definitions. -->

| `security` 1.3.0 | Count |
|---|---|
| [Kinds of thing it models](reference.md#what-it-models) | 23 |
| [Fields (ClaimTypes) across them](reference.md#what-it-models) | 132 |
| [Evidence sources (Capture contracts)](reference.md#where-evidence-comes-from) | 17 |
| [Procedures / Blueprints](reference.md#what-runs-on-its-own) | 21 / 9 |
| [Queries](reference.md#what-you-can-ask) | 45 |
| [Example Lines / Triggers / Mandates](reference.md#what-runs-on-its-own) | 19 / 21 / 11 |

<!-- END GENERATED: glance -->

Full reference: every kind, field, contract, Line and query, with diagrams of
where evidence comes from and what starts what, in [reference.md](reference.md)
(generated from this release's definitions).

## One finding, end to end

A mutable action in a job that can publish, found and fixed, with the names the
example automation uses for `cruxible-ai/cruxible`:

1. **Pull (automatic).** Every 6 hours the Line `security.repo-pull.cruxible-ci`
   runs the Blueprint `security.repo-acquire`, which reads `.github/workflows/`
   at `main` and retains it as one Capture under `security.repo-snapshot-v1`.
   The Line's max authority is `observe`: it records the read and nothing else.
2. **Parse (a proposal).** The landing starts `security.repo-parse.cruxible-ci`.
   It proposes observation Claims citing that Capture, among them, for the job
   `publish.yml#publish-client`, `security.job.permission` `id-token:write` and
   `security.job.uses` `pkg:githubactions/actions/checkout@v4`, plus the source's
   `security.coverage.revision` (the commit read). A person or agent reviews and
   activates the proposal (`cruxible proposal review ID`, `cruxible proposal
   activate ID`); an unchanged read proposes nothing.
3. **Ask (automatic).** `security.harden` runs daily and on each landing (or
   `cruxible line run security.harden`) and reads only accepted Claims, so its
   first run after the activation asks HQ3 through `security.mutable_actions`:
   the job holds a write credential and runs an action pinned to a tag, not a
   40-hex commit SHA. The answer is **found**, posted as one inbox item naming
   the job and the action. Harden only observes and posts; it never changes what
   the instance holds.
4. **Decide (needs someone).** An agent reads the finding (`cruxible inbox list
   --line security.harden`) and records the decision: a `security.remediation`
   with `security.work.job` naming the job and `security.work.rationale`, or a
   `security.exception` if the risk is accepted. These are normative Claims in
   the agent's own words; your instance's approval policy decides whether they
   wait for review.
5. **Close (automatic, then a proposal).** After the pin merges, the next pull
   reads a new revision; the parse proposes revising `job.uses` to the SHA and
   the one `coverage.revision` Claim, and nothing else. Once that is accepted,
   harden's next run answers HQ3 **none** for the job, naming the revision it
   read.

The parse step can itself become automatic: once its proposals have been
reviewed long enough, a settle Mandate lets the Line settle verbatim parses
([Measure and graduate](#measure-and-graduate)). Judgments (a status an analyst
decides, `explained_by`, a publish gate) always stay with people and agents.

## Install and first answers

1. **Install.** `cruxible kit add security:1.3.0` previews the change; commit it
   at the coordinate the preview prints: `cruxible kit add security:1.3.0
   --commit --at OID`. This installs the kit's definitions and its Providers
   (the packages its Procedures call to fetch and parse): the bundled
   `security-analysis-provider` (deterministic parsing and classification, no
   network) and
   `security-sources-provider` (OSV.dev, EPSS, GitHub repository, PyPI and
   release-asset reads), and `cruxible-provider-web` 0.2.2 by name from PyPI,
   verified against the recorded hashes.
2. **Adapt the automation.** The kit carries definitions only; the
   [example ChangeSet](examples/automation.json) is an inert starting point,
   explained in [examples/README.md](examples/README.md). Choose Line names;
   the Provider for each of the nine Blueprints (a Blueprint is a Procedure
   whose Provider you choose when you instantiate it; the example binds the KEV,
   CVE, GitHub release and history reads to `cruxible-provider-web` and the rest
   to `security-sources-provider`); your sources (repository, PyPI projects);
   cron times; and Mandate expiry.
3. **Submit it**: `cruxible authoring submit automation.json`, then review and
   activate it under your approval policy. It instantiates nine Blueprints and
   authors nineteen disabled Lines, twenty-one Triggers and eleven propose-only
   Mandates (a Mandate grants a Procedure the right to propose or settle within
   a scope).
4. **Enable the vulnerability Lines**: `for l in kev-daily kev-triage
   kev-attention epss-daily epss-triage sbom-import osv-applicability
   cve-applicability; do cruxible line enable security.$l; done`. Changing a
   Line, or a Trigger aimed at it, disables it again; `cruxible next` names the
   `line enable` that restarts it.
5. **Import an SBOM.** Put a CycloneDX JSON SBOM in the attached workspace (its
   `metadata.component` names the product and version) and read it:

   ```sh
   echo '{"relative_path": "sboms/app.cdx.json"}' > sbom.json
   cruxible procedure run security.sbom-acquire sbom.json
   ```

   Its landing runs `security.sbom-import`, which proposes the product, release,
   supplier and one `security.release.component` per component purl; review and
   activate it (`cruxible proposal list`, `review`, `activate`). Re-reading an
   SBOM proposes only what is new: a new `metadata.component` version is a new
   release of the same product, a changed SBOM adds its new components, and a
   changed supplier revises the held one. Superseded releases and components an
   SBOM no longer lists are kept; retire them yourself.
6. **Ask OSV**: `cruxible line run security.osv-applicability`, then review and
   activate its proposal: one assessment per (release, CVE) OSV relates.
7. **KEV and EPSS**: `cruxible line run security.kev-daily` and `cruxible line
   run security.epss-daily`, then activate the two triage proposals. From here
   the cron Triggers repeat steps 6 and 7 daily.
8. **The answer**: `cruxible query --name security.urgent_exposures`.

What stays yours: approving the automation, enabling Lines, providing SBOMs and
CVE record requests, reviewing applicability proposals, renewing Mandates before
they expire, and re-instantiating a Blueprint an upgrade changes.

## Your systems: the hardening questions

Stating a target's publish gate is what asks the questions about it.
`security.harden` answers each one per gated target and per read source as
**found** (posted as a finding), **none** (a current coverage answers it and
nothing matches; kept in the run summary, never stored) or **unknown** (no
current coverage: posted as one gap item per source, naming the pull that
answers it, however many questions wait on it).

| # | Question | Found when |
|---|---|---|
| HQ1 `security.publish_paths` | Every path that can publish to T; does any bypass T's gate? | a job with `publishes_to` T whose workflow has a trigger the gate does not list |
| HQ2 `security.credentialed_jobs` | Which jobs hold write credentials, and what triggers them? | a write permission or secret in a job `pull_request_target`, `workflow_run` or `issue_comment` can trigger, or `workflow_dispatch` without an environment |
| HQ3 `security.mutable_actions` | Mutable third-party code inside credentialed jobs? | an action not pinned to a 40-hex SHA in such a job |
| HQ4 `security.shared_dependencies` | Single points of compromise on T's publish paths? | a mutable action or secret every publishing job of T shares |
| HQ5 `security.served_vs_declared` | Does what T serves match the path that declares it? | `published_by`/`publish_environment` not among the publishing jobs at `built_from`, or `declared_sha256` differs from `sha256` |

`job.publishes_to` follows the credential a registry accepts: PyPI needs
`id-token: write` and a publish step, GHCR `packages: write`, a GitHub release
`contents: write`, Pages `pages: write`. A job holding it can publish to every
target of that registry whose `source_repo` is the repository, so "can publish"
leans to over-approximating; harden also counts every credentialed job of a
read source, so a target stated after the last pull is answered at once.

Facts are per source: `main` and a `v0.3.2` tag are two sources with their own
workflows, jobs and coverage. A key that names another Subject uses its readable
locator text (`github.com/owner/repo@ref:path`), and each such key has a
Subject-valued twin (`workflow.repo`, `job.workflow`, `artifact.target`) the
queries traverse.

### Walkthrough

1. **Ask.** State each target's gate (and, outside PyPI, its source repository;
   a PyPI target's comes from its provenance):

   ```json
   {"kind": "change_set", "rationale": "Ask about our release targets.", "members": [
    {"kind": "subject", "subject_kind": "security.target", "key": {"registry": "pypi", "name": "cruxible"}, "rationale": "We publish it."},
    {"kind": "claim", "subject": {"subject_kind": "security.target", "key": {"registry": "pypi", "name": "cruxible"}},
     "predicate": "security.target.publish_gate", "object": {"kind": "literal", "value": "push:tags:v*"},
     "role": "normative", "rationale": "Only a v* tag push may publish.",
     "source": {"kind": "self_source", "body": "gate: push:tags:v*\n"}}]}
   ```

2. **Harden**: enable the system model's Lines (in the example
   `security.repo-pull.cruxible-ci`, `security.repo-parse.cruxible-ci`, the two
   `security.registry-pull.*` and `security.registry-parse.*` Lines, and
   `security.harden`) and run `cruxible line run security.harden`. Every answer
   starts unknown; `cruxible inbox list --line
   security.harden` holds one gap item per source, `{source, pull, input}`, however
   many questions wait on it. Answer one by running its pull with its input:
   `cruxible procedure run security.registry-acquire input.json`.

3. **Parse.** A parse Line reads one source's pulls (its taps are keyed by its
   parameters, never by the landed Capture): the example has
   `security.repo-parse.cruxible-ci` (`main`'s workflows) and
   `security.registry-parse.cruxible`/`-client`, each with its landing Trigger;
   every other landing halts `other_source`. For another source, copy a parse Line
   member with its parameters (`source`, `repo_source`, `forge_host`, `full_name`,
   `ref`, `scope`, `path`) and its landing Trigger, and enable it. Review and
   activate the parse proposals, then run `security.harden` again (its landing
   Triggers fire before you accept, so under propose re-run it after accepting).

4. **Keep it current.** The pull Lines run on cron (the repository every 6 h,
   PyPI daily). The coverage revision is restated on every pull: identical bytes
   are a recorded re-observation (no proposal, no generation) that keeps it fresh;
   a new revision revises that one `coverage.revision` Claim, and only the facts
   that changed change. If pulls stop, coverage goes stale after `stale_after` (12 h, twice
   the cron), reads absent, and every answer resting on it turns unknown, naming
   the source. Widen it by revising the ClaimType (installed definitions are
   yours). Citations of a revision-pinned source (a tag, a SHA) never drift.

5. **Declared vs served.** The digest a release manifest declares and the one a
   registry serves are separate observations from separate sources, compared by
   HQ5, which posts a disagreement citing both Claims. They never compete as two
   answers to one field; that is reserved for competing explanations of a signal.

6. **Investigate a signal** with one pull per hop, each cited:

   | Hop | Pull | Records |
   |---|---|---|
   | 0 | none (an HQ5 finding) | `security.signal` by key (`detector` `security.hq5`) with `signal.observed` and an investigation note section, in one write |
   | 1 | `security.asset-fetch` | `artifact.sha256` (what is served) |
   | 2 | `security.repo-acquire` at the tag, scope `release.manifest` (its parse Line) | `artifact.declared_sha256`; coverage at that SHA |
   | 3 | `security.release-acquire` | `artifact.uploaded_by` |
   | 4 | none if HQ2 already covers the source | the jobs that can write release assets |
   | 5 | `security.history-acquire` (workflow runs) | run attempts and times, cited in the note |
   | 6 | none | hypotheses: `signal.explained_by` (one write each; a second with `--contend`); the slot reads contested |
   | 7 | `security.history-acquire` (commits of a path) | `security.change`; the right hypothesis is revised to it, the other retired `was-wrong`, and the slot resolves |
   | 8 | none | `security.remediation` with `work.job` |

The parse Lines start at propose. Their facts are verbatim parses, so they can
graduate to settle like KEV and EPSS (**Measure and graduate**), with a
condition that holds per target; `signal.explained_by` and `publish_gate` never
enter a Mandate.

## Your code's findings

What your scanners and agent reviewers find in your own code, adjudicated by your
reviewers and joined to what you ship.

| Question | Where the answer comes from |
|---|---|
| What is open in this repository? | `security.open_findings` (parameter `repo_ref`, `github.com/owner/repo`) |
| Is it real? | its `verdict`: `confirmed` (needs a reproduction or a code read as retained evidence), `not_exploitable` or `false_positive` with a `justification`; `conflict` while two reviewers disagree |
| Do we ship it? | HQ6 `security.published_findings`, asked by `security.harden` of every gated target |
| Is the fix real? | `verification`: `fixed` when a full re-scan of the reporting rules no longer reports it (or the PoC passes); `present` again is a regression. `security.unverified_fixes` lists a `fixed_by` without one |
| Which finder to trust? | `security.finder_record`: count upheld against overturned per `reported_by` or `rule` |

**How a finding fits the model.** `security.finding` (in "Your systems" above) is
keyed by `repo_ref`, `weakness` and `locus`, never a line number:

- `weakness` is `CWE-<n>`, the smallest CWE the rule names (`RULE:<tool>/<ruleId>` when
  it names none);
- `locus` is `<repo-relative path>#<locator>`, the first tier the SARIF result offers:
  the **symbol** (`logicalLocations[0].fullyQualifiedName`, or
  `properties["cruxible.symbol"]`), the **snippet** (`snippet:` and 12 hex of the
  whitespace-collapsed sink line), the tool's **line hash** (`line-hash:` and
  `partialFingerprints.primaryLocationLineHash`). A result with none is posted as a
  location gap, never a finding.

Every finder of one sink at one tier meets on the key: their reports add `rule` and
`reported_by` values to one finding. Semgrep's SARIF carries snippets and no symbols;
CodeQL's carries line hashes and no snippets, so its key differs and its finding is a
second Subject your reviewer adjudicates on its own. An agent finder emits SARIF 2.1.0
too (`tool.driver.name` its principal, `ruleId` a CWE id, the sink line as
`region.snippet.text`; add `cruxible.symbol` only where every finder of that code
would). A rename or move is a new key; the old finding is then verified absent.

What finders report (`rule`, `reported_by`, a scan's `severity`, `verification`) are
observations citing the SARIF log or a reproduction. What reviewers decide is
normative: `verdict` needs a retained Capture (a reproduction under
`security.reproduction-v1`, or the code read under `security.workspace-evidence-v1`;
own words are refused), and `location` (`path:start-end`) is a file citation of the
sink line, origin-only, so `cruxible next` resurfaces it (`citation_drifted`) when
that code changes. `affects` joins a finding to a release, service, job or artifact;
`fixed_by` to the fixing `security.change`; `work.finding` to a remediation or an
exception. Status is derived, never stored: new (no verdict), disputed (`conflict`),
confirmed / not exploitable / false positive, fixing (a remediation in progress),
fixed (`verification` `fixed`), accepted risk (an approved exception).

A dependency advisory a scanner reports (a CVE or GHSA rule in a manifest or
lockfile) is not a finding: the import counts it `routed_to_assessment`, and the
SBOM, OSV and KEV path owns it. A CVE in vendored code is a finding with
`vulnerability`.

**Independence is your approval policy.** Under `independent_approval_required`,
every change set needs an approval by an active ordinary principal other than its
creator (`cruxible.approval.creator_forbidden` refuses the creator's own), so a
finder cannot confirm its own report: a confirmation it writes waits for a
reviewer. The import Line's runs act as the principal that armed it (`cruxible line
enable`), so let the scanner arm it and its proposals need someone else too. Under
`self_approval_allowed` a finder's confirmation lands alone, and nothing in a query
shows who wrote a verdict. No Mandate ever covers `verdict`, `justification`,
`verification` or `affects`.

### A code finding, end to end

The gate's names, for `github.com/cruxible-ai/gate-app` (principals `scanner`,
`triage`, `reviewer`, `maintainer`):

1. **Scan and annotate.** `semgrep scan --sarif --output scans/semgrep.sarif`, then
   add to each run what the scanner knows and SARIF tools do not all write:
   `versionControlProvenance: [{"repositoryUri": "https://github.com/cruxible-ai/gate-app",
   "revisionId": "<commit>"}]` and `properties: {"cruxible.coverage": "full"}` (every rule
   of the configuration over the whole repository; `partial` otherwise, which never
   verifies a fix). SARIF carries code snippets, and `security.sarif-v1` keeps its
   bytes for good: don't acquire a secret scanner's results (their snippets are
   the secrets), and check a scan of code that embeds credentials before you do.
2. **Report (a proposal).** `cruxible procedure run security.sarif-acquire` with
   `{"relative_path": "scans/semgrep.sarif"}` retains it under `security.sarif-v1`; the
   landing runs `security.sarif-import.gate-app` (parameter `repo_ref`), which proposes
   `security.finding` `CWE-89` at `app/db.py#snippet:...` with `rule`
   `semgrep:sqli-fstring-execute`, `reported_by` `semgrep` and `severity` `high`. Another
   repository's Line halts `wrong_repo`; an unchanged scan halts `no_change`. The
   reviewer approves (`cruxible proposal approve ID`).
3. **Locate.** Catalogue the file (`cruxible files add gate-app-db app/db.py`), then
   `write` `{"op": "add", "field": "security.finding.location", "value": "app/db.py:12-12",
   "evidence": {"kind": "file", "file": "app/db.py#<the sink line>"}}`.
4. **Triage.** A false positive cites the code read: run `security.evidence-acquire` on
   the file with the guard, then set `verdict` `false_positive` and `justification`
   `sanitized`, citing that Capture, with a `Triage` section in `findings/<id>.md`.
5. **Confirm.** The reviewer adds a failing PoC test, retains its report
   (`security.reproduction-acquire`; kept for good, so strip tokens and
   environment dumps from it first), and in one write appends `findings/<id>.md#Reproduction`,
   sets `reproduction` (that section, own words), `verdict` `confirmed` citing the PoC
   Capture (`contend: true` when a contrary verdict stands), and `affects`
   `security.release/gate-app--1.0.0`. While both contend, the verdict reads `conflict`
   and `next` shows `claim_conflicted`; retiring the wrong call (`was-wrong`) resolves it.
6. **Remediate.** A `security.remediation` with `work.finding` and `progress`
   `in_progress`. While release 1.0.0 is served, HQ6 posts the finding.
7. **Fix and verify.** After the fix merges, `cruxible next` in the workspace shows
   `citation_drifted` on `location`. A full re-scan of the fixed revision lands; the
   import proposes `verification` `fixed` (a false positive is never verified). Then
   one write sets `fixed_by` (the `security.change` by key) and retires `location`
   `superseded`. A later full scan that reports it again proposes `present` and
   `security.sarif-attention` posts a regression.

Graduation never covers judgments. The import's report observations (the finding by
key, `rule`, `reported_by`, a scan's `severity`) may graduate to settle per finder
once its record holds, with `security.finding_settle_condition` as the condition; the
default is propose.

## Respond to an incident

Patch, audit and rotate when a vulnerability is exploited in the wild (the gate
walks PHP2Shell: CVE-2026-109618 and CVE-2026-109619, unauthenticated RCE in the
PHP runtime, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35). The kit runs no
response command and bakes in no service: your agent patches, queries logs and
rotates keys with your own tools. Cruxible holds what needs doing and why, who
approved it, and the evidence that it is done.

| Question | Where the answer comes from |
|---|---|
| RQ1 Which deployments run an affected release? | `security.incident_exposure` (parameter `incident`, its name): assets a scan observed running a release assessed affected |
| RQ2 Is each exposure patched? | `security.open_patches` (internet-facing first), `security.overdue_patches` (past `due_at` at the query's evaluation time), `security.incident_exceptions` (approved risk exceptions not yet expired) |
| RQ3 Were we exploited during the window? | `security.audit_status`: per service, the audit's log sources and the service's (`service_log_source`), complete reads, `window_end` and `result` |
| RQ4 Which credentials need rotating? | `security.incident_credentials`: each credential an audited service uses, its current key (`issued_at` before `window_start` = not rotated since exposure) and its rotations |
| RQ5 Can the incident close? | the incident's respond Line posts `ready_to_close` |
| Where does the incident stand? | `security.incident_status`, rendered into a page (below) |

**The pattern.** Every action is governed the same way, with machinery core
already has:

| Step | What happens | Evidence |
|---|---|---|
| 1. What needs doing | The incident's respond Line posts one inbox item per open question (a repeat sighting is counted on the same item; a changed answer is a new item) | `cruxible inbox list --line security.respond.<incident>` |
| 2. The plan | A `security.remediation`: a **patch** has `work.asset`, `work.assessment` and `target_release`; a **rotation** has `work.credential`, `work.audit` and `revokes_key` (the `key_id` held when it was raised); both carry `owner` and `due_at` | normative, with its `because` |
| 3. Approval | Under `independent_approval_required` someone other than its creator approves it (`creator_forbidden` refuses the creator) | the signed approval |
| 4. The act | Outside Cruxible: act only on an accepted remediation | |
| 5. Self-report | `remediation.progress` `completed`: it never closes anything | normative |
| 6. Evidence lands | A scan, a log read or a credential's key listing, as a workspace file acquired under its contract | a Capture |
| 7. Verified | The import proposes `work.verification` from that Capture: `verified`, or `failed` when it disagrees with the claim | observation |

**Trust model.** Approval is attribution and role separation, not a security
boundary against an agent that can read every principal's key. The kit's controls
are evidence: a patch closes only on a fresh inventory scan, a rotation only on a
fresh, separate read of the credential's state, an audit's none only on complete
log reads; a self-report never closes anything. Run an incident under
`independent_approval_required` with your security lead as the usual approver, and
let a principal other than the one who acted acquire the evidence that verifies the
action (`cruxible get ProcedureRun:RUN-...` shows each acquiring run's `actor`).
Core has one approval profile (one signer other than the creator), so "a lead must
approve rotations" is your convention, not a rule core enforces.

**Secrets never enter.** A credential is non-secret: issuer and name, where it is
used (`used_by`) and what it reaches (`reaches`), its current key's id
(`key_id`: the issuer's key id, or `fp:` and 16 hex of the secret's sha256),
`issued_at` and `issued_by`. The credential-state body is an allow-list; an unknown
field, or a key id shaped like a secret (longer than 40 characters, a known secret
prefix, high entropy), refuses the whole body and posts `secret_shape`, echoing no
value. The bytes are already retained when that happens: stop, rotate whatever it
exposed, and erase the Capture's body. The three incident contracts
(`security.runtime-inventory-v1`, `security.log-read-v1` and
`security.credential-state-v1`) declare `erasure: authorized_by_rule`, so
`cruxible capture erase CAP-... --because "..."` (preview, then `--commit --at`)
removes the bytes and keeps the envelope and an erasure record; never put the
secret in `--because`. A Capture under any other kit contract keeps its bytes.

The preview names every Claim that cites the Capture, and erasing changes what
they rest on:

- **A refused credential read** (`secret_shape`) is cited by nothing, since
  nothing was proposed from it. Erasing it is the whole repair; then acquire an
  allow-listed body.
- **A scan or log read that was imported** is cited by the Claims its import
  proposed (for a one-host scan, eight: the asset and what it runs, the scope's
  coverage, and the release's component). Once erased, they read `stale` and
  `cruxible next` lists each as `claim_evidence_erased`. Acquire a clean copy
  under the same contract (the secret removed, match summaries redacted) and
  re-bind each Claim the preview named onto it: `cruxible rebind CLM-...
  --capture CAP-... --because "..."`. An unchanged scan proposes nothing, so the
  re-bind is what moves them.
  <!-- update: erased-scan-answers -->
  Today, erasing an inventory scan hides that host from the respond Line's
  answers (RQ1 and RQ2 are neither found nor unknown for it) until you
  re-acquire the scan and re-bind its Claims, so do both straight away.
  <!-- update: erased-evidence-retire -->
  A Claim that hasn't been re-bound can't be retired or revised. Fields that
  cite the scan without needing it as evidence (an asset's `hostname`, a
  coverage's `scope` and `source`) can't be re-bound either, and stay `stale`.
  With `hostname` stale, the respond Line names the host by its Subject
  (`security.asset/...`) and posts its items afresh: a decision on the earlier
  items doesn't carry over.

See [Erasing a Capture that holds a
secret](https://docs.cruxible.ai/evidence-and-admission/#erasing-a-capture-that-holds-a-secret).

### The evidence each action lands

| Contract | Acquired by | Body (a workspace file, at most 1 MiB) | Read by |
|---|---|---|---|
| `security.runtime-inventory-v1` | `security.inventory-acquire` | the kit body `{"scope", "looked_for": ["php", "debian/php8.2"] or ["*"], "coverage": "full" or "partial", "assets": [{"hostname", "runs": ["pkg:generic/php@8.3.10"]}]}`, no timestamps; or a CycloneDX JSON SBOM of one asset (Syft, Trivy) with metadata properties `cruxible.scope` and `cruxible.asset` | `security.inventory-import.<scope>` (parameter `scope`) |
| `security.log-read-v1` | `security.log-acquire` | `{"audit": {"incident", "service"}, "source", "query", "from", "to", "complete", "records_scanned", "matches": [{"at", "summary"}]}`; `complete` = every record in [from, to] searched (no sampling, no result cap, retention reaching `from`); redact match summaries | `security.log-import.<incident>` (parameter `incident`) |
| `security.credential-state-v1` | `security.credential-acquire` | `{"issuer", "name", "read": "receipt" or "state_read", "keys": [{"key_id", "state": "active" / "inactive" / "revoked" / "deleted", "created_at", "revoked_at", "last_used_at", "created_by"}]}` and nothing else | `security.credential-import` |

What each import proposes:

- **Inventory.** Each asset by key and `asset.scanned_in` the scope's coverage;
  each release it runs (`product_name` the purl's whole namespace and name, so
  `pkg:deb/debian/php8.2@8.2.20-1~deb12u1` is `debian/php8.2` and
  `pkg:golang/github.com/cli/cli/v2@v2.86.0` is `github.com/cli/cli/v2`, never a
  last segment; `version` from the purl; the purl as `release.component`, so OSV
  decides a distro build) as `asset.runs`, observed
  beside the declared `installs`. A **full** kit scan restates the coverage
  revision (the digest of its `looked_for` and (asset, runs) set: an unchanged
  fleet, in any order, is a re-observation and proposes nothing, while freshness
  moves), retires runs it no longer sees of the products it looked for (a new
  version of a product revises the run it replaces; a run with nothing replacing it
  retires on the next read that stages nothing else for that asset), and
  proposes `verification` `verified` on an open patch whose asset no longer runs
  the affected release; a scan that still shows it on a patch claimed `completed`
  proposes `failed`. A **partial** scan only adds. A CycloneDX SBOM is one asset's
  complete run set: it adds, retires and verifies for that asset, never states the
  scope's coverage (its own timestamp makes every scan new content), and proposes
  only when the run set changed. None answers need a scope's full kit scan.
- **Log read.** One `security.audit.read` (`SOURCE FROM/TO`) for a complete read of
  a stated audit. An incomplete read is posted (`read_incomplete`, with why): a
  finding about your logs, not about the attacker. A read for an audit nobody
  stated is posted (`audit_not_stated`). Never a `result`.
- **Credential state.** From either kind of read, the current key's `key_id`,
  `issued_at` and `issued_by`. Only from a `state_read`: `revoked_key`, and a
  rotation's `verification`: `verified` when `revokes_key` is revoked, deleted or no
  longer listed and an active key issued after the incident's `window_start` exists;
  `failed` when the rotation is claimed `completed` and `revokes_key` is still
  listed. A receipt (what the issuer returned to the rotating agent) never
  verifies.

### Declare the incident

An incident (`security.incident`, keyed by `name`) groups the CVEs of one
response, so each service gets one audit however many CVEs. Declaring it is an
approved act: one ChangeSet with the incident's Claims, its respond Line and log
import Line, and their Triggers (Lines are authored disabled: enable both after
approval). Rename `php2shell` and the window for yours:

```json
{"kind": "change_set", "rationale": "Declare PHP2Shell.", "members": [
  {"kind": "subject", "subject_kind": "security.incident", "key": {"name": "PHP2Shell"},
   "rationale": "One response to CVE-2026-109618 and CVE-2026-109619."},
  {"kind": "claim", "subject": {"subject_kind": "security.incident", "key": {"name": "PHP2Shell"}},
   "predicate": "security.incident.window_start", "object": {"kind": "literal", "value": "2026-09-01T00:00:00Z"},
   "role": "normative", "rationale": "The earliest known exploitation minus a margin.",
   "source": {"kind": "self_source", "body": "window starts 2026-09-01\n"}},
  "... incident.vulnerability for each CVE, rotation_policy on_found_or_unknown, status open ...",
  {"kind": "line", "name": "security.respond.php2shell", "procedure_name": "security.respond",
   "max_authority": "observe",
   "parameters": {"incident": "PHP2Shell", "inventory_pull": "security.inventory-acquire",
                  "log_pull": "security.log-acquire", "credential_pull": "security.credential-acquire",
                  "record_pull": "security.cve-record-acquire"}},
  {"kind": "line", "name": "security.log-import.php2shell", "procedure_name": "security.log-import",
   "acquisition_policy_name": "security.acquisition", "max_authority": "propose",
   "trigger_input": "log", "parameters": {"incident": "PHP2Shell"}},
  {"kind": "trigger", "name": "security.log-landed.php2shell", "line_name": "security.log-import.php2shell",
   "schedule": {"kind": "capture_landing", "capture_contract": "security.log-read-v1"}},
  {"kind": "trigger", "name": "security.respond-daily.php2shell", "line_name": "security.respond.php2shell",
   "schedule": {"kind": "cron", "expression": "50 7 * * *"}},
  {"kind": "trigger", "name": "security.respond-after-rotation.php2shell", "line_name": "security.respond.php2shell",
   "schedule": {"kind": "window_close", "window": {"kind": "capture_event",
     "capture_contract": "security.credential-state-v1", "duration_seconds": 86400}}},
  {"kind": "trigger", "name": "security.respond-after-scan.php2shell", "line_name": "security.respond.php2shell",
   "schedule": {"kind": "window_close", "window": {"kind": "capture_event",
     "capture_contract": "security.runtime-inventory-v1", "duration_seconds": 86400}}}
]}
```

The window-close Triggers re-ask a day after a landing: an unverified patch or
rotation is sighted again (an item you acknowledged keeps your decision and counts
the recurrence, `recurred_since_disposition` in `cruxible inbox get`), and an answer
that changed is a new item. The log import's propose Mandate
(`security.log-import-propose`) is in [the example automation](examples/automation.json),
beside `security.inventory-import.prod` (one Line per inventory scope) and
`security.credential-import`. No Mandate covers `audit.result`, `audit.window_end`,
`audit.log_source`, `work.verification`, `remediation.*`, `credential.*` or any
incident field.

### The five questions, in three states

`security.respond` answers each question **found** (posted), **none** (the run
summary) or **unknown** (posted as a gap `{subject, pull, input}` naming the pull or
statement that answers it):

| # | found | none | unknown |
|---|---|---|---|
| RQ1 | `exposed`: a scan observed the asset running a release assessed affected | a current full scan that looked for the product shows no affected run | an asset that declares installing it, or a patched one, under no current coverage; an inconclusive assessment (an analyst's judgment answers it) |
| RQ2 | `patch_missing`; `patch_overdue`; `patch_disputed` (verification `failed`, or claimed `completed` while still running); `patch_regressed` (verified, then seen running again) | `verification` `verified` and no affected run, under current coverage | a claimed patch no scan has read since; an approved one on schedule is *pending*, and a missing or overdue one under an accepted risk is *excepted* (both summary only) |
| RQ3 | `exploited`: the result `exploited` | `not_exploited`, `window_end` stated, and for every `log_source` the union of its complete reads covers [`incident.window_start`, `window_end`] | no audit (the gap names the service's `log_source` list as `sources`), no log source, a source the service lists that the audit does not state, window open, no result, `inconclusive`, `conflict`, or an uncovered interval (named per source) |
| RQ4 | `rotate {credential, services: {audit, patch}, key_id, because}` for each credential a warranted service uses (`on_found_or_unknown`: RQ3 found or unknown; `all_exposed`: every exposed service); `rotation_disputed` | a rotation a state read verified, the current key issued after `window_start`; a credential no warranted service uses | claimed rotated, no separate state read yet |
| RQ5 | `ready_to_close`, listing audits still unknown as accepted residue with their rotations | | |

**Where the logs are.** State each service's log sources once, before any
incident: `security.service.log_source` is a pointer only (a short identifier
such as `caddy:app-1:/var/log/caddy/access.log`), citing a section of a doc
(`security/log-sources.md`) that holds the retention, the tool and query that
read it, and who owns it. An incident's audit starts from that list: the
respond Line's gap for a missing audit names it (`input.sources`), and a listed
source the audit leaves out keeps RQ3 unknown until the audit states it (and is
read in full). The audit's own `log_source` stays the set that incident
audited. A source that didn't exist over the window can't be read in full: say
so in the audit's section and accept it as residue, or correct the service's
list.

**Accepted risk.** A `security.exception` with `work.asset`, `work.assessment`,
`exception.approval` `approved` and `exception.expires_at` (its reason in a
section of the incident's note, cited by the approval) accepts an exposure's
risk for that CVE until it expires. While one holds for each of the release's
incident CVEs on that asset, RQ2 answers *excepted* instead of `patch_missing`
or `patch_overdue` (never instead of `patch_disputed` or `patch_regressed`), and
the status page shows `excepted_until`. Expiry is the query clock: at
`expires_at` the respond Line's next run (its daily Trigger) posts the exposure
again. RQ1 still finds it, so the incident doesn't close on an exception.

Rotating after a verified patch is the recommended order (rotating first lets the
attacker read the new key), but it is the agent's call: `rotate` is posted with the
service's audit and patch state, and nothing gates a rotation on the patch. Rotate
at once when a key is known leaked. A closed incident (`status` `closed`) posts
nothing.

Coverage goes stale 12 h after a scope's last full scan: every none resting on it
turns unknown, as `cruxible next` (`claim_stale_evidence`) says.

### PHP2Shell at Acme, end to end

The gate's flow. Services `storefront` (workloads `k8s:prod/storefront-a` and `-b`,
`pkg:generic/php@8.3.10`; credentials `stripe/storefront-live`,
`aws-iam/111122223333/storefront-app`), `partner-portal` (`app-1.acme.internal`,
`pkg:deb/debian/php8.2@8.2.20-1~deb12u1`; `postgres/partners-db/portal`) and
`ops-wiki` (`wiki-1.ops.acme.internal`, declared to install php 8.3.10, outside the
prod scope; `github/acme-ops/wiki-deploy`). Each service states its log sources
(`storefront/nginx-access` and `storefront/php-fpm`, `partner-portal/apache`,
`ops-wiki/nginx`), citing its section of `security/log-sources.md`. Principals `responder`, `ops` (acts),
`scanner`, `auditor`, `lead`, under `independent_approval_required`.

| # | Act (who) | What lands | Ask |
|---|---|---|---|
| 1 | KEV lists both CVEs | `kev-attention`: "KEV newly lists ...; inventory has php" | `cruxible inbox list --line security.kev-attention` |
| 2 | `responder` acquires both CVE records | `cve-applicability`: php 8.3.10 affected; `osv-applicability`: the Debian build affected (its distro advisory); `lead` approves | `query --name security.urgent_exposures`: php 8.3.10 declared on wiki-1 and `observed` on the storefront workloads, the Debian build `observed` on app-1 |
| 3 | `responder` declares the incident; `lead` approves; Lines enabled | | |
| 4 | `scanner` scans prod (a Syft SBOM of storefront-a, then the kit body for the scope) | respond: RQ1 found ×3, RQ1 unknown for wiki-1 (`inventory-acquire`), RQ2 `patch_missing` ×3 | `query --name security.incident_exposure --param incident=PHP2Shell` |
| 4a | `responder` excepts app-1's Debian build for both CVEs until a set time; `lead` approves | RQ2 for app-1 *excepted*; the status page shows `excepted_until`; past it, `patch_missing` again | `query --name security.incident_exceptions --param incident=PHP2Shell` |
| 5 | `responder` raises 3 patches (`target_release` php 8.3.36 / debian/php8.2 8.2.29-1~deb12u1, `due_at`); `lead` approves | `ops` rebuilds the image, upgrades app-1 | `query --name security.open_patches --param incident=PHP2Shell` |
| 6 | `ops` sets `progress` `completed`; `scanner` scans prod and ops | `verified` ×3 (a claimed patch still running: `failed`, `patch_disputed`); the ops scan finds wiki-1 running 8.3.10: a 4th patch | open_patches empty after acceptance |
| 7 | `auditor` states each service's audit from the gap's `sources` (the service's list; storefront's, stated without `php-fpm`, stays unknown naming it until added), runs the queries in your log tool, `log-acquire` each read | complete reads recorded; ops-wiki's read hits 14-day retention: `read_incomplete` | `query --name security.audit_status --param incident=PHP2Shell` |
| 8 | `auditor` writes each result, citing the decisive read, with a section of `incidents/php2shell.md`, and `window_end`; `lead` approves | RQ3: storefront found, partner-portal none, ops-wiki unknown (its reads cover only 10-04 to 10-17) | `inbox list --line security.respond.php2shell` |
| 9 | respond posts `rotate` ×3 (storefront's two, ops-wiki's deploy key); `responder` raises rotations; `lead` approves | `ops` rotates with the issuers' tools, records receipts | `query --name security.incident_credentials --param incident=PHP2Shell` |
| 10 | `scanner` acquires state reads | `verified` ×3; an AWS old key still active: `failed`, `rotation_disputed`, until `ops` deletes it and the next read verifies | |
| 11 | respond: RQ5 `ready_to_close` (residue: ops-wiki's audit) | `lead` sets `status` `closed` with a Closure section; `responder` approves | `next` is empty for the incident |

### An incident status page

`security.incident_status` (parameter `incident`) is one row per CVE, patch raised
for an exposed asset or exception accepting its risk, and credential of the
asset's service, with every state as held: `exposure` (the assessment), `host`
and `service`, `coverage` (the scope revision; empty: no current coverage),
`patch` (progress) and `patch_verified`, `excepted_until` (an approved exception's
expiry, until it passes), `audit` (the result; `(conflicted)` while disputed),
`credential` and `rotation_verified`. An empty cell is unknown, never none; none
is the respond Line's answer. An exposure nobody has raised a patch or an
exception for is not a row yet: the respond Line posts it (`patch_missing`). An
exception's expiry moves no state, so re-render the page after it (`block
sync`). Render it into a page with a projection block, which `next` flags
when the state behind it moves and `block sync` brings back in step
([example page](examples/incident-status.md)):

```markdown
## PHP2Shell: where we stand

<!-- cruxible:block:status -->
<!-- /cruxible:block:status -->
```

```bash
cruxible files add php2shell-status incidents/php2shell-status.md
cruxible block repin php2shell-status status --query QueryDefinition:security.incident_status \
  --params '{"incident": "PHP2Shell"}' --render
cruxible block sync --all   # after the state moves (next: projection_backing_stale)
```

## Vulnerabilities in depth

How the vulnerability half names things, decides applicability and keeps KEV
and EPSS current.

### Identity: how Subjects are named

Core names every security Subject; you never choose an id. Each kind is keyed
(its id is the readable rendering of its key) or minted:

| Kind | Key | Uniqueness | Example id |
|---|---|---|---|
| `security.vulnerability` | `cve_id` (trim, uppercase) | unique | `cve-2021-44228` |
| `security.release` | `product_name` + `version` | unique | `apache-log4j2--2.14.1` |
| `security.assessment` | `release_id` + `cve_id` | unique: one assessment per pair | `apache-log4j2-2.14.1--cve-2021-44228` |
| `security.asset` | `hostname` (trim, casefold) | unique | `web-1.example.com` |
| `security.product`, `security.supplier`, `security.team`, `security.service` | `name` (NFKC, trim, collapsed spaces, casefold) | hint | `apache-log4j2` |
| `security.remediation`, `security.exception`, `security.control` | minted | | `sub-...` |

A release's `product_name` is a literal key (key ClaimTypes are literal), beside
its Subject-valued `security.release.product`; an assessment's `release_id` is
the id core gave the release. Creating by a key a live Subject holds names that
Subject and creates nothing, so re-running an import or an analysis reuses what
exists.

**Watched is derived, never implied by existence.** A vulnerability is watched
(KEV and EPSS triage read it, applicability decides it for every related
release, KEV attention counts it as looked at) when **either**:

- an assessment links it to a release in inventory with status `affected` or
  `inconclusive` (the applicability Procedures create these), **or**
- it carries a `security.vulnerability.watch_reason`: an agent's or a person's
  normative decision to track it, and why.

A bare vulnerability Subject (created by key, nothing else) is tracked by
nothing. `security.watched_vulnerabilities` is that derivation; once every
assessment of a CVE is `not_affected` and nobody stated a reason, it drops out.
Track one by hand with a single write, which also creates it by key:

```sh
cruxible set security.vulnerability/CVE-2021-44228 watch_reason "Log4j in vendor appliances" \
  --because "Security review 2026-10-11."
```

In a JSON change set, a `subject` member plus a `watch_reason` claim member.

**Naming Subjects.** A reference takes key text as written, on every route
(`set`, `get`, `inbox link`, authoring): `security.vulnerability/CVE-2021-44228`,
`security.product/Apache Log4j2` (these resolve against accepted state). A
composite key, and any Subject the same change set creates, is named by kind and
key (a mapping of key parts, even for a one-key kind), never by a predicted id:
`{"subject_kind": "security.release", "key": {"product_name": "Apache Log4j2", "version": "2.14.1"}}`
(the SDK's `SubjectKeyReference`). Core resolves it to the Subject a `subject`
member of the same set lands on, else to the live holder of the key.

Inventory by hand, for what no SBOM describes (vendor products, hosts):

```json
{"kind": "change_set", "rationale": "Inventory.", "members": [
 {"kind": "subject", "subject_kind": "security.supplier", "key": "Apache Software Foundation", "rationale": "Our Log4j vendor."},
 {"kind": "subject", "subject_kind": "security.product", "key": "Apache Log4j2", "rationale": "We run it."},
 {"kind": "subject", "subject_kind": "security.release", "key": {"product_name": "Apache Log4j2", "version": "2.14.1"}, "rationale": "Installed on web-1."},
 {"kind": "subject", "subject_kind": "security.asset", "key": "web-1.example.com", "rationale": "The storefront host."},
 {"kind": "claim", "subject": {"subject_kind": "security.release", "key": {"product_name": "Apache Log4j2", "version": "2.14.1"}},
  "predicate": "security.release.product",
  "object": {"kind": "subject", "subject": {"subject_kind": "security.product", "key": {"name": "Apache Log4j2"}}}, "role": "normative", "rationale": "Its product.",
  "source": {"kind": "self_source", "body": "product: Apache Log4j2\n"}},
 {"kind": "claim", "subject": {"subject_kind": "security.product", "key": {"name": "Apache Log4j2"}}, "predicate": "security.product.supplied_by",
  "object": {"kind": "subject", "subject": {"subject_kind": "security.supplier", "key": {"name": "Apache Software Foundation"}}}, "role": "normative", "rationale": "Its vendor.",
  "source": {"kind": "self_source", "body": "supplier: Apache Software Foundation\n"}},
 {"kind": "claim", "subject": {"subject_kind": "security.asset", "key": {"hostname": "web-1.example.com"}}, "predicate": "security.asset.installs",
  "object": {"kind": "subject", "subject": {"subject_kind": "security.release", "key": {"product_name": "Apache Log4j2", "version": "2.14.1"}}},
  "role": "normative", "rationale": "Installed.",
  "source": {"kind": "self_source", "body": "installs Apache Log4j2 2.14.1\n"}},
 {"kind": "claim", "subject": {"subject_kind": "security.asset", "key": {"hostname": "web-1.example.com"}}, "predicate": "security.asset.internet_exposed",
  "object": {"kind": "literal", "value": true}, "role": "normative", "rationale": "Public.",
  "source": {"kind": "self_source", "body": "internet exposed\n"}}]}
```

Add another value of a many-valued field (`installs`, `serves`) with `cruxible
add`: two values of one many-valued slot in the same change set must each
disposition the other by a Claim ID the set itself mints.

### Applicability

An assessment is one (release, CVE) pair: `status` (`affected`, `not_affected`,
`inconclusive`) and, for `not_affected`, its VEX/CSAF `justification`
(`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`,
`inline_mitigations_already_exist`). Both are observations citing the source
Capture. Core cannot require a justification only when the status is
`not_affected`; the kit's Procedures always state one with it, and `cruxible
query --name security.assessment_index` shows any assessment without one.

- **`security.osv-applicability`** (open source, by SBOM component). Each run
  first retains OSV's own list of what it indexes (`ecosystems.txt`, under
  `security.osv-ecosystems-v1`). OSV is then asked about every component
  `purl@version` of every release whose ecosystem is on that list, and for the
  record of every watched CVE and its aliases. Which ecosystem answers for a
  purl type is kit data, carried in the Procedure with its sources (the purl
  spec's types, the OSV schema's ecosystems; `deb/debian` -> Debian, `golang` ->
  Go, `pypi` -> PyPI ...); edit it by authoring a successor of your
  `security.osv-applicability` Procedure. A component of any other type
  (`pkg:brew`, `pkg:generic`, `pkg:docker` ...) is never asked: OSV's empty
  answer there would read as "no advisories". The OSV Capture records it as
  `not_indexed` with why, and each release gets one
  `security.release.osv_coverage` Claim: `complete: N of N components answered`,
  or `partial: A of N components answered; not indexed: brew 1, generic 1`
  (and `unanswered K` for a query that failed). An empty OSV answer is a
  negative only under complete coverage. The run also states, for each watched
  CVE, the packages OSV's records say it affects
  (`security.vulnerability.package`, `pkg:deb/debian/php8.2`): OSV knows the CVE.
  A component OSV lists as affected
  -> `affected` (the CVE is created by key when new, and watched through that
  assessment). A watched CVE OSV has package data for
  but does not list -> `not_affected` with `vulnerable_code_not_present` when one
  of its packages is a component at another version OSV answered for. A failed
  OSV query for a relevant component -> `inconclusive`; a relevant component OSV
  never answered (not indexed) -> no answer (the coverage says partial). A release
  none of whose components is a
  package the CVE affects is not assessed at all: an SBOM release with no
  assessment for a CVE means OSV relates none of its components to it.
  (Writing `component_not_present` for every such pair is releases x watched
  CVEs: on the self-dogfood instance's second day, 509 answers and 2,545
  proposal items nobody needs to review.) An advisory with no CVE alias cannot
  be keyed; the run's result lists it under `unkeyed`.
- **`security.cve-applicability`** (vendor products, by CVE record). When a CVE
  record lands (`cruxible procedure run security.cve-record-acquire` with
  `{"url": "https://cveawg.mitre.org/api/cve/CVE-..."}`), every release whose
  product name equals an `affected` entry's product (letters and digits,
  case-insensitive) and whose supplier matches the vendor (or is unset) is
  decided by the entry's version ranges (`version`, `lessThan`,
  `lessThanOrEqual`, `changes`; a `lessThan` ending in `*` is open-ended) and
  `defaultStatus`. Conservative: a partial product match, a contradicting
  vendor, or a version the ranges cannot order -> `inconclusive`, never a guess.

A pair whose held answer is unchanged proposes nothing, so a daily re-run is
quiet; a changed answer revises the held Claims and retires a justification an
`affected` answer no longer has. Neither Procedure settles: a person or agent
reviews every applicability proposal.

#### Analyst judgments

`status` and `justification` have two roles, and every read shows which one a
Claim has:

| Role | Who states it | Evidence | Shown as |
|---|---|---|---|
| `observation` | an applicability Procedure (a source's verdict) | the OSV or CVE-record Capture it read | `role: observation` |
| `normative` | an analyst (their own judgment) | their own words, or a workspace file retained by `security.evidence-acquire` | `role: normative`; the analyst's reasoning is the write's `because` |

The normative role is what marks a judgment. `cruxible query security.assessment
--select status,justification --claims` prints each Claim's role, and `cruxible
get CLM-... --detail evidence` its evidence and `because`. The named worklists
(`assessment_index`, `triage`, `applicability_coverage`, `coverage_gaps`,
`urgent_exposures`, `change_impact`) carry a `status_role` column
(`observation` or `normative`). The Procedures never revise an assessment
whose status is normative: their result counts it under `judged`. Retire the
normative status (and justification) to hand the assessment back to them. An
observation in someone's own words has no admitted evidence: core writes it
with verdict `uncovered` (and warns), and no worklist shows it, since they read
supported Claims only.

The workflow, for a proposed `affected` or `inconclusive` you have reviewed:

1. Find it: `cruxible proposal review ID` (before activating), or after,
   `cruxible query --name security.assessment_index` / `security.coverage_gaps`.
2. Retain the evidence (optional; your own words are evidence too): put the
   file in the workspace (code, a config, an analysis note) and
   `echo '{"relative_path": "analysis/jinja2.md"}' > ev.json; cruxible procedure run
   security.evidence-acquire ev.json`; note its `Capture evidence: sha256:...`.
   Its bytes are kept for good (`security.workspace-evidence-v1` can't be
   erased), so check the file holds no secret first: retain a config with its
   credentials cut out, never as deployed.
3. Record the judgment in one write (`cruxible write judgment.json`), with your
   reasoning as its `because`:

   ```json
   {"because": "We compile only packaged templates; the attacker-controlled filename never reaches Jinja.",
    "subject": "security.assessment/gate-app-1.0.0--cve-2024-56201",
    "changes": [
     {"op": "set", "field": "status", "value": "not_affected", "role": "normative",
      "evidence": {"kind": "capture", "capture": "sha256:..."}},
     {"op": "set", "field": "justification", "value": "vulnerable_code_not_in_execute_path",
      "role": "normative", "evidence": {"kind": "capture", "capture": "sha256:..."}}]}
   ```

   Without `evidence` each change cites `because` as your own words. `role:
   normative` is the default for these two fields; stating it keeps the write
   readable.

A `not_affected` assessment no longer keeps its CVE watched; if the CVE should
stay on the watch list, state a `watch_reason`.

### KEV, EPSS and attention

`security.kev-triage` compares each retained KEV catalog with every watched
vulnerability and proposes (or, graduated, settles) the KEV fields that changed:
`kev_listed`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use`. A watched
CVE the catalog does not list gets `kev_listed = false` once. An identical
catalog halts `no_change`. `security.epss-triage` does the same for
`epss_score` and `epss_percentile`, verbatim from FIRST's daily file (scores
move a little most days, so expect a daily revision per watched CVE).

`security.kev-attention` reads the same catalog and posts one inbox item per CVE
added in the catalog's last 7 days whose vendor/product matches a release in
inventory that nobody watches the CVE for (no `watch_reason`, no affected or
inconclusive assessment), or nobody has assessed: possibly
exposed, nobody has looked. It never changes accepted state (`cruxible inbox
list --line security.kev-attention --status unread`). Matching leans to
matching (the product name equal to KEV's product or vendor + product, or the
supplier equal to KEV's vendor with one product name containing the other): a
false match costs an inbox item. The payload stays the same while the situation
does, so a daily re-sighting counts on the same item; an item you acknowledged
keeps your decision and counts each recurrence (`recurred_since_disposition`)
while the gap stays open. Close the gap
(assess the release, or state a `watch_reason`) to stop it.

## Predictions: the applicability bet

State what you expect before a source observes it, and let the observation
settle it. Create the assessment by key with `security.assessment.expected_status`
(`affected` or `not_affected`, normative; plus its `release` and
`vulnerability`, naming the assessment by its key), then propose a contract
whose hypothesis is that Claim and whose observation is the assessment's
`security.assessment.status`. The observation selector is the assessment's
artifact path, the id core gave it (`cruxible query --name
security.assessment_index` lists it):

```json
{"contract": {"identity": {"kind": "ResolutionContract", "name": "bet-log4j-2.17.1"},
 "hypothesis": "CLM-...",
 "observation": {"subject": {"tag": "playbill-semantic-address-v1",
   "artifact_path": "subjects/security.assessment/apache-log4j2-2.17.1--cve-2021-44228.json",
   "selector": {"scheme": "artifact-v1", "value": ""}}, "predicate": "security.assessment.status"},
 "rule": {"tag": "playbill-prediction-equality-rule-v1", "operator": "equality"},
 "window": {"kind": "fixed", "starts_at": "NOW", "duration_seconds": 2592000}}}
```

`cruxible prediction propose FILE`, activate it, and once an applicability
Procedure's status Claim is accepted inside the window, `cruxible prediction
settle NAME --observation CLM-...` records whether the bet held. Settlement is
manual in v1; a window that closes unobserved shows in `cruxible next` until the
contract is retired.

## Measure and graduate

`security.kev-triage` declares `kev-backlog-cleared`: the `kev_triage_backlog`
query must be empty 3 days after the Procedure is accepted (review when the
satisfied rate drops below 0.8 over 5 readings).
`cruxible procedure measure security.kev-triage --run-id RUN-...` and
`cruxible procedure readings security.kev-triage --subject-grain procedure_unit`.

When the readings justify it, settle the verbatim KEV and EPSS fields under
settle mandates and raise the triage Lines to `settle` (`gate/recipe.py`'s
`graduate()`):

```json
{"kind": "change_set", "rationale": "Graduate KEV and EPSS triage to settle.", "members": [
 {"kind": "procedure_mandate", "name": "security.kev-triage-settle", "procedure_name": "security.kev-triage", "grants": "settle",
  "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
  "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 16777216, "max_items": 5000, "max_repeat_attempts": 1},
  "scope": [{"claim_type": "security.vulnerability.kev_date_added", "change_kinds": ["create", "revise"]},
            {"claim_type": "security.vulnerability.kev_due_date", "change_kinds": ["create", "revise"]},
            {"claim_type": "security.vulnerability.kev_listed", "change_kinds": ["create", "revise"]},
            {"claim_type": "security.vulnerability.kev_ransomware_use", "change_kinds": ["create", "revise"]}],
  "condition": {"query_name": "security.settle_condition", "binding_parameter": "vulnerability_id",
    "required_fields": ["cve_id"], "fallback": "propose"}},
 {"kind": "procedure_mandate", "name": "security.epss-triage-settle", "procedure_name": "security.epss-triage", "grants": "settle",
  "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
  "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 33554432, "max_items": 5000, "max_repeat_attempts": 1},
  "scope": [{"claim_type": "security.vulnerability.epss_percentile", "change_kinds": ["create", "revise"]},
            {"claim_type": "security.vulnerability.epss_score", "change_kinds": ["create", "revise"]}],
  "condition": {"query_name": "security.settle_condition", "binding_parameter": "vulnerability_id",
    "required_fields": ["cve_id"], "fallback": "propose"}},
 {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage", "acquisition_policy_name": "security.acquisition", "max_authority": "settle", "trigger_input": "catalog"},
 {"kind": "line", "name": "security.epss-triage", "procedure_name": "security.epss-triage", "acquisition_policy_name": "security.acquisition", "max_authority": "settle", "trigger_input": "epss"}]}
```

Re-enable both Lines. The KEV and EPSS fields are verbatim copies of CISA's and
FIRST's data, so every change for a watched vulnerability settles. Core requires
a condition on every settle grant and that it return exactly one row per
target; `security.settle_condition` holds for any keyed vulnerability. It cannot
re-derive "watched" (that needs an optional hop, which core admits only in
path-shaped queries, whose rows are per path), and need not: the triage
Procedures only change watched vulnerabilities, so the grant's scope decides.
The Procedures do
not change, so their digests and track records carry through.

## Upgrading

From 1.1.0, `kit add security:1.2.0` adds the code findings' definitions (the
`security.finding` kind, its ClaimTypes, `security.sarif-v1` and
`security.reproduction-v1`, four Procedures, six queries), widens
`signal.explained_by` to a finding, adds HQ6 to `security.harden` (its Provider
interface gains the `hq6` rows) and bumps the bundled analysis Provider to 1.2.0;
everything else is unchanged except re-pinned Procedures (D8 carries the affected
Lines disabled and their Mandates propose-only, as below). Add the findings Lines
and Mandate from the example ChangeSet. From 1.0.2, 1.1.0 added the system model the
same way. The gate starts from the 1.2.0 bundle and upgrades to a gate-only 1.2.1
variant (`source/variants/1.2.1-gate`) whose analysis Provider
code and build differ. It also checks keeping a local query edit and blocking
downgrades.

Preview `cruxible kit add security:VERSION`, then commit that one upgrade with
`cruxible kit add security:VERSION --commit --at OID`. Changed bundled builds
are installed alongside the old builds and affected Procedures are re-pinned.
The preview lists carried Lines (same names, disabled) and Mandates losing settle;
Triggers retain their exact bytes.

Read `cruxible next`: each carried Line has `line_disabled_by_upgrade` and a
`cruxible line enable NAME` repair. Enable those Lines to resume proposing.
Re-author and approve the KEV/EPSS settle grants (the **Measure and graduate** recipe)
to restore settlement; enable any Line changed by that authoring. Other
Mandates stay propose-only.

## Operating notes

- **Network.** web.fetch reaches cisa.gov, cveawg.mitre.org and (for the
  system model's release and history pulls) api.github.com;
  `security-sources-provider` reaches api.osv.dev, epss.empiricalsecurity.com,
  api.github.com, raw.githubusercontent.com, pypi.org, and github.com with its
  asset hosts (its declared endpoints). No credential is sent: GitHub allows 60 unauthenticated API calls
  an hour, and a repository pull costs two plus one raw read per file. The SBOM is read from the attached workspace by
  core's built-in `workspace.file`; the Source request is the v2 form, so no
  workspace binding digest is ever authored.
- **Staleness.** The policy refuses a Capture older than 24 h: triage of a
  backfilled catalog after a long outage refuses; run the acquisition Line for a
  fresh one.
- **Storage.** Retained for at least 30 days each: the KEV catalog (~1.8 MB per
  acquisition), the EPSS daily file (~3.6 MB), each OSV answer (every advisory
  record it read) and each SBOM.
- **CVE Services throttles bursts**: fetch CVE records one at a time.
- **Blueprint drift.** Upgrading the kit changes Blueprints, not the Procedures
  instantiated from them; re-instantiate after an upgrade that changes one.
- **Mandates expire** after 90 days in the payloads above; renew them first.
- **Findings Lines per repository.** Each repository's `security.sarif-import` and
  `security.sarif-attention` Lines read every SARIF landing and halt `wrong_repo` for
  another repository's log after parsing it, so a landing costs one parse per
  repository Line. The import's tap reads the repository's held findings
  (`security.finding_index`, up to 2000; a truncated tap refuses rather than read a
  held finding as new).
- **Workspace files are at most 1 MiB.** Core's built-in `workspace.file` structures
  at most 1 MiB, so every workspace-file Procedure (SBOM, evidence, SARIF,
  reproduction, inventory, log read, credential state) budgets 1 MiB: split a larger
  SBOM, scan or inventory scope.
- **Incident Lines.** An inventory import reads one scope's held assets and runs
  (`security.inventory_index` and `security.inventory_patches`, up to 2000 rows each:
  split a scope that grows past it; a truncated tap refuses). The credential import
  reads every held credential (`security.rotation_work`). Respond and the log import
  read one incident's rows. A landing costs one import per scope or incident Line.
- **Secret slips.** A credential-state body is an allow-list, but its bytes are
  retained before the import refuses it; the three incident contracts authorize
  erasure (`cruxible capture erase`): see [Respond to an
  incident](#respond-to-an-incident). Every other kit contract (SBOM, evidence,
  SARIF, reproduction and the public-source reads) keeps its bytes for good, so
  check a file for secrets before you acquire it.

## For maintainers

### Building a release

```sh
python source/build_release.py SCRATCH_DIR --providers
```

with the interpreter of the cruxible build the release targets. It rebuilds both
bundled providers (registration, tests, wheel), starts a daemon on a fresh state
root under `SCRATCH_DIR`, installs `cruxible-provider-web` 0.2.2 and the bundled
wheels, runs `source/authoring/security_definitions.py definitions` and
`procedures` for 1.3.0, `kit build`s it, authors the 1.3.1 successors on the
same instance and builds those, then copies 1.3.0 over `cruxible-kit.json`,
`artifacts/` and `providers/` here and 1.3.1 over `source/variants/1.3.1-gate`,
and regenerates `reference.md` and this README's counts table from the copied
release (`python source/reference.py` does only that step; after editing
`examples/automation.json` run it too, and `--check` also refuses a concept map
that names a kind or field the kit does not define). The same sources build the same kit
digest. After changing a provider, bump its
version. `source/providers/cruxible-provider-web` holds the published 0.2.2
wheel, the lock it embeds and the runtime wheel that lock names by path, so
`kit build` can record the default's hashes; none of those files ship.
`source/variants/1.3.1-gate` is a release-gate fixture (changes `kev_exposure`,
adds `vulnerability.kev_cwes`, changes the kev-acquire Blueprint and the analysis
Provider's KEV rationale), not a published version.

### Release gate

`gate/test_security_kit_gate.py` runs the v1 release gate end to end on a fresh
daemon with a scratch state root and HOME: the kit is published to a throwaway
HTTPS OCI registry on 127.0.0.1, installed, instantiated, automated, fed an
inventory and an SBOM, run through OSV and CVE-record applicability, applicability
bets, KEV triage and attention, EPSS, a restart, measurement, graduation to
settle, the upgrade to `source/variants/1.3.1-gate` and the re-import of a changed
SBOM and a new release, then the system model: gates asked with every answer
unknown and one gap per source, pulls and parses, an unchanged re-pull
(re-observation), a moved `main`, fail-closed freshness, a declared/running
disagreement and a full investigation, then the code findings under independent
approval: a Semgrep report, an agent's duplicate, CodeQL's own key, a located,
triaged, contended and confirmed finding, HQ6, and a fix that drifts the location,
verifies by full re-scan and regresses, then an incident (PHP2Shell) under
independent approval: a KEV listing reaching exposure through a Syft SBOM and a
scope's inventory, distro builds left to OSV, patches closed only by a scan (a
claimed patch the scan disagrees with disputed), unchanged re-scans and stale
coverage, audits in three states (an incomplete read, a contended result, own words
refused), rotations verified only by a separate state read (an old key still
active, a secret-shaped body refused), a window-close re-ask, the status page and
closure, asserting each step's observable. The SARIF fixtures are in the analysis
Provider's `tests/data/sarif` (Semgrep's recorded, CodeQL's hand-built in its
shape), the incident's in `tests/data/incident` (recorded shapes: CVE JSON 5.1, an
NVD answer with null configurations, a Syft CycloneDX SBOM, log reads and key
listings). It is
offline from every security source: `gate/fixture-sources` (package
`security-gate-sources`) is cruxible-provider-web's own `WebFetch` and the kit's
own OSV, EPSS, repository and PyPI adapters (vendored by its
`build_registration.py`) answering from `responses/` (recorded once by
`record_responses.py` and `record_system_model.py`). Provider installs still
need PyPI.

The upgrade recovery probe deliberately retires and restores an EPSS score.
Core correctly reports `line_settled_prior_refusals` for that settlement on the
same evidence. The gate inspects its retirement receipt, submits the repair's
ready payload (the same EPSS Line capped at `propose`; `cruxible next` prints it
as a `cruxible authoring submit` command), and re-enables the Line before
checking that `next` is empty.

```sh
CRUXIBLE_BIN=$(command -v cruxible) python -m pytest kits/security/gate -x -q
```

It needs `git` and `openssl`, takes about forty minutes, and writes
`gate-results.md` and the command log to its scratch root
(`SECURITY_KIT_GATE_ROOT` to choose one). After changing the fixture, run its
`build_registration.py`, `uv lock` and `uv build --wheel --out-dir dist`.

### Self-dogfood

`examples/self-dogfood/` (at the repository root) runs the whole loop live over
Cruxible's own dependency tree: `sbom_from_uv_lock.py` writes a CycloneDX SBOM
per package from a uv.lock, and `run.py` imports them into a fresh instance,
asks OSV, KEV and EPSS, reads `urgent_exposures`, and times settle batches of
~400 KEV Claims.

A persistent instance runs the kit daily over the same dependencies:
`setup_persistent.py` creates it (KEV and EPSS triage graduated to settle,
applicability propose-only: the review queue), `daemon.sh` starts, stops and
checks its daemon, `refresh_sboms.py` re-imports the SBOMs whose bytes changed
after a dependency change, and `snapshot.py` appends one daily metrics line.
The instance root's `OPERATING.md` says how to run and read it.

Setup and refresh require `--core-repo PATH --core-sha FULL_SHA
--providers-repo PATH --providers-sha FULL_SHA`; no branch defaults are used.
Setup prints and retains these exact inputs in `source-pins.json` before
importing the SBOMs. Choose the actual repositories and reviewed commits; the
scripts never change those repositories.
