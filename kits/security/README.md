# security kit

Answers two questions with evidence. **Which of my releases are exposed to a
vulnerability attackers exploit, and which first?** And, from a symbolic model
of your systems (see [The system model](#the-system-model-what-your-systems-declare-and-serve)):
**can anything publish my artifacts except the path my policy allows, and does
what a registry serves match the path that declares it?** The kit keeps the first
answer current from five sources:

| Source | What it gives | How it arrives |
|---|---|---|
| CycloneDX SBOM (your workspace) | each release's components (`purl@version`) | `security.sbom-acquire` (direct run per SBOM) -> `security.sbom-import` |
| OSV.dev | which components an advisory affects, precisely by version | `security.osv-applicability` (daily, or on demand) |
| CVE record (cveawg.mitre.org) | vendor product version ranges | `security.cve-record-acquire` (direct run per CVE) -> `security.cve-applicability` |
| CISA KEV | exploited in the wild, due dates | `security.kev-acquire` (daily) -> `security.kev-triage`, `security.kev-attention` |
| FIRST EPSS | probability of exploitation | `security.epss-acquire` (daily) -> `security.epss-triage` |

Every observation Claim cites the retained Capture it was read from.
Applicability answers are proposed for review, never settled by the kit; the
verbatim KEV and EPSS fields can graduate to settling under a mandate. A kit
carries definitions only: the Lines, Triggers, mandates and inventory below are
yours to author.

## Quick start: from `kit add` to an exposure answer

Nine steps; provider installs take most of the time. Every manual step that
remains is listed at the end of this section.

1. **Install.** `cruxible kit add security:1.1.0` previews; commit it at the
   coordinate the preview prints: `cruxible kit add security:1.1.0 --commit --at OID`.
   This installs the bundled `security-analysis-provider` and
   `security-sources-provider` and the default `cruxible-provider-web` 0.2.2
   (by name from PyPI, verified against the recorded hashes).

2. **Choose the nine Blueprint bindings.** The example binds KEV, CVE, GitHub
   release, asset and history acquisition to `cruxible-provider-web`, and EPSS
   acquisition, OSV applicability and the repository and PyPI pulls to
   `security-sources-provider`. Inspect the installed ProviderInterfaces and
   adapt those bindings to your approved Providers.

3. **Adapt the [example ChangeSet](examples/automation.json)** using the
   [walkthrough](examples/README.md): choose instance and Line names, Provider
   bindings, namespaces, inputs, cron times and mandate expiry. Capture-landing
   Triggers name their CaptureContract; prepare resolves and pins its digest.

4. **Submit your adapted ChangeSet** with `cruxible authoring submit automation.json`.
   Review the proposal and satisfy your instance's approval policy before activation.
   It instantiates nine Blueprints and authors fifteen disabled Lines, seventeen
   Triggers and seven propose-only Mandates (eight Lines, eight Triggers and five
   Mandates are the vulnerability loop; the rest are the system model's). The gate
   and self-dogfood scripts read this exact file.

5. **Enable the Lines**: `for l in kev-daily kev-triage kev-attention epss-daily
   epss-triage sbom-import osv-applicability cve-applicability; do cruxible line
   enable security.$l; done` (the system model's Lines are enabled in its own
   walkthrough below). A change to a Line or to a Trigger aimed at it stops
   its enablement; `cruxible next` names the `line enable` that restarts it.

6. **Import an SBOM.** Put a CycloneDX JSON SBOM in the attached workspace (its
   `metadata.component` names the product and version) and read it:

   ```sh
   echo '{"relative_path": "sboms/app.cdx.json"}' > sbom.json
   cruxible procedure run security.sbom-acquire sbom.json
   ```

   The Capture's landing runs `security.sbom-import`, which proposes the product
   and release (created by key, or the ones you already have), the supplier, and
   one `security.release.component` per component purl. Review and activate it:
   `cruxible proposal list`, `cruxible proposal review ID`, `cruxible proposal
   activate ID`.

   Re-reading an SBOM proposes only what the instance does not hold yet: a new
   `metadata.component` version is a new release of the same product, a changed
   SBOM for a held release adds its new components, and a changed supplier
   revises the held one. A superseded release is kept, with its components and
   assessments, since it may still be deployed; retire it yourself when it is
   not. Components an SBOM no longer lists are not removed.

7. **Ask OSV**: `cruxible line run security.osv-applicability`, then review and
   activate its proposal. Each (release, CVE) OSV relates gets an assessment; a
   CVE found in a component is created by key and is watched through its
   `affected` assessment.

8. **KEV and EPSS**: `cruxible line run security.kev-daily` and `cruxible line
   run security.epss-daily`; activate the two triage proposals. (From here the
   cron Triggers do this daily.)

9. **The answer**: `cruxible query --name security.urgent_exposures`: every
   release assessed affected, KEV-listed first, then by EPSS score, with the
   assets that install it.

Consumers choose the automation and approve its proposal, enable Lines, provide
SBOM/CVE inputs, review applicability proposals and renew Mandates before expiry.
Blueprint instances remain consumer-authored; re-instantiate after a changed Blueprint.

## Identity

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

## Applicability

An assessment is one (release, CVE) pair: `status` (`affected`, `not_affected`,
`inconclusive`) and, for `not_affected`, its VEX/CSAF `justification`
(`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`,
`inline_mitigations_already_exist`). Both are observations citing the source
Capture. Core cannot require a justification only when the status is
`not_affected`; the kit's Procedures always state one with it, and `cruxible
query --name security.assessment_index` shows any assessment without one.

- **`security.osv-applicability`** (open source, by SBOM component). OSV is
  asked about every component `purl@version` of every release and for the
  record of every watched CVE and its aliases. A component OSV lists as affected
  -> `affected` (the CVE is created by key when new, and watched through that
  assessment). A watched CVE OSV has package data for
  but does not list -> `not_affected` with `vulnerable_code_not_present` when one
  of its packages is a component at another version. A failed OSV query for a
  relevant component -> `inconclusive`. A release none of whose components is a
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

### Analyst judgments

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

## KEV, EPSS and attention

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
is unread again at the next sighting while the gap stays open. Close the gap
(assess the release, or state a `watch_reason`) to stop it.

## The system model: what your systems declare and serve

Every fact about your systems is one source's observation, citing the Capture it
was read from; your policy (a target's publish gate) is the only normative
statement; and absence is an answer only inside a current **coverage** belief.

| Kind | Key | What it is |
|---|---|---|
| `security.repo` | `forge_host` + `full_name` (trim, casefold) | a source repository |
| `security.workflow` | `source` (`github.com/owner/repo@ref`) + `path` | one CI workflow file, as one source declares it |
| `security.job` | `workflow_ref` (`source:path`) + `job_key` | holds the permissions, secrets, environment and actions |
| `security.target` | `registry` (`pypi`, `ghcr`, `github_release`, `github_pages`) + `name` | where artifacts land: the trust boundary a gate guards |
| `security.artifact` | `target_ref` (`registry/name`) + `name` | one published file (a release asset as `tag/asset`) |
| `security.change` | `repo_ref` + `commit_sha` | a commit, created when a question needs it |
| `security.coverage` | `source` + `scope` (`ci.workflows`, `release.manifest`, `registry.files`) | the belief that the source was read in full at a revision |
| `security.signal` | `detector` + `fingerprint` | an observation an investigation starts from |

A key that names another Subject names it by its locator text, never by an id: a
parse creates a workflow and its jobs in one terminal, before any id exists. Each
such key has a Subject-valued twin (`workflow.repo`, `job.workflow`,
`artifact.target`) the queries traverse. Facts are per source: `main` and a
`v0.3.2` tag are two sources with their own workflows, jobs and coverage.

**Three states.** `security.harden` answers each question per target and per
covered source as **found** (the facts answer it, and it is a problem: posted as
a finding), **none** (a current coverage answers it and nothing matches: it
names the coverage's source and revision, and stays in the run summary; `none`
answers are never stored) or **unknown** (no current coverage: it names the
source and the pull that answers it, posted as one gap item per source).
"Nobody asked" is a target without a gate; "looked and found nothing" is current
coverage with no matching row.

| # | Question | found |
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
leans to over-approximating.

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

2. **Harden**: enable `security.harden` and run it (`cruxible line run
   security.harden`). Every answer starts unknown; `cruxible inbox list --line
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
   PyPI daily). Coverage is restated on every pull: identical bytes are a recorded
   re-observation (no proposal, no generation) that keeps it fresh; a new
   revision revises the one `coverage.revision` Claim and only the facts that
   changed. If pulls stop, coverage goes stale after `stale_after` (12 h, twice
   the cron), reads absent, and every answer resting on it turns unknown, naming
   the source. Widen it by revising the ClaimType (installed definitions are
   yours). Citations of a revision-pinned source (a tag, a SHA) never drift.

5. **Declared vs running** are separate per-source predicates compared by the
   queries and the classifier, never a contention: HQ5 posts a disagreement with
   both Claims (the declared digest from the manifest snapshot, the served one
   from the asset or registry). Contention is reserved for competing explanations.

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

From 1.0.2, `kit add security:1.1.0` adds the system model's definitions beside
the vulnerability loop's, which are unchanged except for the bundled Providers'
new builds (D8 carries the affected Lines disabled and their Mandates
propose-only, as below). The gate starts from the 1.1.0 bundle and upgrades to a
gate-only 1.1.1 variant (`source/variants/1.1.1-gate`) whose analysis Provider
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

## What 1.1.0 contains

| Kind | Count | Notes |
|---|---:|---|
| ClaimType | 87 | All v8. The system model's 41 (sixteen identity keys, their Subject-valued twins, per-source observations of what a repository declares and a registry serves, coverage with a 12 h `stale_after`, the normative `target.publish_gate`, `signal.observed`/`explained_by`, `work.job`) beside the vulnerability loop's 46: ten identity keys; inventory, applicability (`status` and `justification`: a source's observation or an analyst's normative judgment; `expected_status`), KEV, EPSS, `watch_reason` and remediation-work vocabulary. Observations require a Capture under a kit CaptureContract; a judgment cites the analyst's own words or a workspace file; relationships a Procedure reads from a source (`release.product`, `product.supplied_by`, `assessment.release`, `assessment.vulnerability`) cite that Capture, and their author's own words otherwise; other normative statements are supported by their own origin. |
| SubjectKind | 19 | See Identity and The system model. |
| CaptureContract | 12 | The system model's `security.repo-snapshot-v1`, `security.pypi-release-v1`, `security.github-release-v1`, `security.github-api-v1`, `security.release-asset-v1`; and `security.kev-http-v1`, `security.cve-record-http-v1`, `security.osv-query-v1`, `security.epss-daily-v1`, `security.cyclonedx-sbom-v1` (a workspace file), `security.workspace-evidence-v1` (a workspace file an analyst cites), `security.observation-output-v1` (acquisition terminals). |
| QueryDefinition | 28 | HQ1-HQ5 (`publish_paths`, `credentialed_jobs`, `mutable_actions`, `shared_dependencies`, `served_vs_declared`), `coverage_index` and the parse taps (`source_facts`, `repo_targets`, `registry_facts`); worklists (`urgent_exposures`, `kev_exposure`, `triage`, `coverage_gaps`, `remediation_work`, ...), the Procedures' state taps (`watched_vulnerabilities`, `release_inventory`, `assessment_index`), the settle condition and the triage backlog. CVE-scoped ones take `vulnerability` (`Subject:security.vulnerability/<id>`). |
| SourceAcquisitionPolicy | 1 | `security.acquisition`: aliases `catalog`, `record`, `epss`, `osv`, `snapshot`, `registry`, `release`, `asset`, `history` (attested), `sbom` and `evidence` (exact); each required, at most 24 h old, refused stale, unavailable or oversized. |
| Blueprint | 9 | `security.kev-acquire`, `security.cve-record-acquire`, `security.release-acquire`, `security.asset-fetch`, `security.history-acquire` (slot typed `web.fetch`), `security.epss-acquire` (`security.epss-daily`), `security.osv-applicability` (`security.osv-query`), `security.repo-acquire` (`security.repo-snapshot`), `security.registry-acquire` (`security.pypi-release`). |
| Procedure | 10 | `security.kev-triage` and `security.epss-triage` (settle terminal; they propose under a propose cap), `security.kev-attention` and `security.harden` (inbox), `security.sbom-acquire` and `security.evidence-acquire` (direct), `security.sbom-import`, `security.cve-applicability`, `security.repo-parse` and `security.registry-parse` (propose). |
| ProviderInterface | 14 | `web.fetch` (core's), nine analysis interfaces, four Source interfaces. |
| Providers | 3 | Bundled: `security-analysis-provider` 1.1.0 (deterministic parsing, decisions and the hardening classifier, no network) and `security-sources-provider` 1.1.0 (the OSV.dev, EPSS, GitHub repository and PyPI Sources). Default by name: `cruxible-provider-web` 0.2.2. |

## Operating notes

- **Network.** web.fetch reaches cisa.gov, cveawg.mitre.org and (for the
  system model's release, asset and history pulls) api.github.com and github.com;
  `security-sources-provider` reaches api.osv.dev, epss.empiricalsecurity.com,
  api.github.com, raw.githubusercontent.com and pypi.org (its declared
  endpoints). No credential is sent: GitHub allows 60 unauthenticated API calls
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

## Building a release

```sh
python source/build_release.py SCRATCH_DIR --providers
```

with the interpreter of the cruxible build the release targets. It rebuilds both
bundled providers (registration, tests, wheel), starts a daemon on a fresh state
root under `SCRATCH_DIR`, installs `cruxible-provider-web` 0.2.2 and the bundled
wheels, runs `source/authoring/security_definitions.py definitions` and
`procedures` for 1.1.0, `kit build`s it, authors the 1.1.1 successors on the
same instance and builds those, then copies 1.1.0 over `cruxible-kit.json`,
`artifacts/` and `providers/` here and 1.1.1 over `source/variants/1.1.1-gate`. The
same sources build the same kit digest. After changing a provider, bump its
version. `source/providers/cruxible-provider-web` holds the published 0.2.2
wheel, the lock it embeds and the runtime wheel that lock names by path, so
`kit build` can record the default's hashes; none of those files ship.
`source/variants/1.1.1-gate` is a release-gate fixture (changes `kev_exposure`,
adds `vulnerability.kev_cwes`, changes the kev-acquire Blueprint and the analysis
Provider's KEV rationale), not a published version.

## Release gate

`gate/test_security_kit_gate.py` runs the v1 release gate end to end on a fresh
daemon with a scratch state root and HOME: the kit is published to a throwaway
HTTPS OCI registry on 127.0.0.1, installed, instantiated, automated, fed an
inventory and an SBOM, run through OSV and CVE-record applicability, applicability
bets, KEV triage and attention, EPSS, a restart, measurement, graduation to
settle, the upgrade to `source/variants/1.1.1-gate` and the re-import of a changed
SBOM and a new release, then the system model: gates asked with every answer
unknown and one gap per source, pulls and parses, an unchanged re-pull
(re-observation), a moved `main`, fail-closed freshness, a declared/running
disagreement and a full investigation, asserting each step's observable. It is
offline from every security source: `gate/fixture-sources` (package
`security-gate-sources`) is cruxible-provider-web's own `WebFetch` and the kit's
own OSV, EPSS, repository and PyPI adapters (vendored by its
`build_registration.py`) answering from `responses/` (recorded once by
`record_responses.py` and `record_system_model.py`). Provider installs still
need PyPI.

The upgrade recovery probe deliberately retires and restores an EPSS score.
Core correctly reports `line_settled_prior_refusals` for that settlement on the
same evidence. The gate inspects its retirement receipt, authors an EPSS Line
successor capped at `propose`, and re-enables it before checking that `next` is
empty. `cruxible authoring example line` supplies an authoring template; the
resolution requires submitting and activating the successor.

```sh
CRUXIBLE_BIN=$(command -v cruxible) python -m pytest kits/security/gate -x -q
```

It needs `git` and `openssl`, takes about fifteen minutes, and writes
`gate-results.md` and the command log to its scratch root
(`SECURITY_KIT_GATE_ROOT` to choose one). After changing the fixture, run its
`build_registration.py`, `uv lock` and `uv build --wheel --out-dir dist`.

## Self-dogfood

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
