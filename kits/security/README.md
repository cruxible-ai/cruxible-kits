# security kit

Answers one question with evidence: **which of my releases are exposed to a
vulnerability attackers exploit, and which first?** The kit keeps that answer
current from five sources:

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

1. **Install.** `cruxible kit add security:1.0.1` previews; commit it at the
   coordinate the preview prints: `cruxible kit add security:1.0.1 --commit --at OID`.
   This installs the bundled `security-analysis-provider` and
   `security-sources-provider` and the default `cruxible-provider-web` 0.2.2
   (by name from PyPI, verified against the recorded hashes).

2. **Instantiate the four Blueprints** on the installed Providers
   (`cruxible authoring submit instances.json --and-activate`):

   ```json
   {"kind": "change_set", "rationale": "Instantiate the security Blueprints.", "members": [
    {"kind": "blueprint_instance", "name": "security.kev-acquire", "blueprint": "security.kev-acquire",
     "bindings": {"catalog": "cruxible-provider-web"}, "acquisition_policy": "security.acquisition"},
    {"kind": "blueprint_instance", "name": "security.cve-record-acquire", "blueprint": "security.cve-record-acquire",
     "bindings": {"record": "cruxible-provider-web"}, "acquisition_policy": "security.acquisition"},
    {"kind": "blueprint_instance", "name": "security.epss-acquire", "blueprint": "security.epss-acquire",
     "bindings": {"epss": "security-sources-provider"}, "acquisition_policy": "security.acquisition"},
    {"kind": "blueprint_instance", "name": "security.osv-applicability", "blueprint": "security.osv-applicability",
     "bindings": {"osv": "security-sources-provider"}, "acquisition_policy": "security.acquisition"}]}
   ```

3. **Read the four CaptureContract digests** the landing Triggers pin:

   ```sh
   for c in security.kev-http-v1 security.epss-daily-v1 security.cyclonedx-sbom-v1 security.cve-record-http-v1; do
     echo "$c $(cruxible get CaptureContract:$c --detail proof --json | jq -r .proof.artifact_digest)"; done
   ```

4. **Author the automation** in one change set: eight Lines, their Triggers and
   five propose mandates. `gate/recipe.py`'s `automation()` builds exactly this;
   by hand, replace `KEV`, `EPSS`, `SBOM`, `CVE` with step 3's digests and `NOW`
   with the current UTC time:

   ```json
   {"kind": "change_set", "rationale": "Automate KEV, EPSS, SBOM import and applicability.", "members": [
    {"kind": "line", "name": "security.kev-daily", "procedure_name": "security.kev-acquire", "acquisition_policy_name": "security.acquisition", "max_authority": "observe"},
    {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage", "acquisition_policy_name": "security.acquisition", "max_authority": "propose", "trigger_input": "catalog"},
    {"kind": "line", "name": "security.kev-attention", "procedure_name": "security.kev-attention", "acquisition_policy_name": "security.acquisition", "max_authority": "observe", "trigger_input": "catalog"},
    {"kind": "line", "name": "security.epss-daily", "procedure_name": "security.epss-acquire", "acquisition_policy_name": "security.acquisition", "max_authority": "observe"},
    {"kind": "line", "name": "security.epss-triage", "procedure_name": "security.epss-triage", "acquisition_policy_name": "security.acquisition", "max_authority": "propose", "trigger_input": "epss"},
    {"kind": "line", "name": "security.sbom-import", "procedure_name": "security.sbom-import", "acquisition_policy_name": "security.acquisition", "max_authority": "propose", "trigger_input": "sbom"},
    {"kind": "line", "name": "security.osv-applicability", "procedure_name": "security.osv-applicability", "acquisition_policy_name": "security.acquisition", "max_authority": "propose"},
    {"kind": "line", "name": "security.cve-applicability", "procedure_name": "security.cve-applicability", "acquisition_policy_name": "security.acquisition", "max_authority": "propose", "trigger_input": "record"},
    {"kind": "trigger", "name": "security.kev-daily", "line_name": "security.kev-daily", "schedule": {"kind": "cron", "expression": "17 14 * * *"}},
    {"kind": "trigger", "name": "security.epss-daily", "line_name": "security.epss-daily", "schedule": {"kind": "cron", "expression": "45 13 * * *"}},
    {"kind": "trigger", "name": "security.osv-daily", "line_name": "security.osv-applicability", "schedule": {"kind": "cron", "expression": "30 15 * * *"}},
    {"kind": "trigger", "name": "security.kev-landed", "line_name": "security.kev-triage", "schedule": {"kind": "capture_landing", "event": {"capture_contract_identity": {"kind": "CaptureContract", "name": "security.kev-http-v1"}, "capture_contract_digest": "KEV"}}},
    {"kind": "trigger", "name": "security.kev-landed-attention", "line_name": "security.kev-attention", "schedule": {"kind": "capture_landing", "event": {"capture_contract_identity": {"kind": "CaptureContract", "name": "security.kev-http-v1"}, "capture_contract_digest": "KEV"}}},
    {"kind": "trigger", "name": "security.epss-landed", "line_name": "security.epss-triage", "schedule": {"kind": "capture_landing", "event": {"capture_contract_identity": {"kind": "CaptureContract", "name": "security.epss-daily-v1"}, "capture_contract_digest": "EPSS"}}},
    {"kind": "trigger", "name": "security.sbom-landed", "line_name": "security.sbom-import", "schedule": {"kind": "capture_landing", "event": {"capture_contract_identity": {"kind": "CaptureContract", "name": "security.cyclonedx-sbom-v1"}, "capture_contract_digest": "SBOM"}}},
    {"kind": "trigger", "name": "security.cve-landed", "line_name": "security.cve-applicability", "schedule": {"kind": "capture_landing", "event": {"capture_contract_identity": {"kind": "CaptureContract", "name": "security.cve-record-http-v1"}, "capture_contract_digest": "CVE"}}},
    {"kind": "procedure_mandate", "name": "security.kev-triage-propose", "procedure_name": "security.kev-triage", "grants": "propose", "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 16777216, "max_items": 5000, "max_repeat_attempts": 1}},
    {"kind": "procedure_mandate", "name": "security.epss-triage-propose", "procedure_name": "security.epss-triage", "grants": "propose", "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 33554432, "max_items": 5000, "max_repeat_attempts": 1}},
    {"kind": "procedure_mandate", "name": "security.sbom-import-propose", "procedure_name": "security.sbom-import", "grants": "propose",
     "namespace": ["claims", "subjects/security.product", "subjects/security.release", "subjects/security.supplier"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 16777216, "max_items": 5000, "max_repeat_attempts": 1}},
    {"kind": "procedure_mandate", "name": "security.osv-applicability-propose", "procedure_name": "security.osv-applicability", "grants": "propose",
     "namespace": ["claims", "subjects/security.assessment", "subjects/security.vulnerability"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 600000000}, "max_provider_calls": 2, "max_capture_bytes": 67108864, "max_items": 5000, "max_repeat_attempts": 1}},
    {"kind": "procedure_mandate", "name": "security.cve-applicability-propose", "procedure_name": "security.cve-applicability", "grants": "propose",
     "namespace": ["claims", "subjects/security.assessment", "subjects/security.vulnerability"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2, "max_capture_bytes": 16777216, "max_items": 5000, "max_repeat_attempts": 1}}]}
   ```

   Cron is UTC. CISA publishes on US business days and FIRST publishes EPSS once a
   day around 12:00 UTC, so one fetch a day each is enough. A mandate of a
   Procedure that creates Subjects reaches `claims` and those kinds
   (`subjects/<kind>`) only: the key Claims a creation writes are covered by the
   creation itself.

5. **Enable the Lines**: `for l in kev-daily kev-triage kev-attention epss-daily
   epss-triage sbom-import osv-applicability cve-applicability; do cruxible line
   enable security.$l; done`. A change to a Line or to a Trigger aimed at it stops
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

Manual steps that remain (inputs to the kit-automation-template item): writing
the change sets of steps 2 and 4 (a Provider per slot, `NOW` timestamps);
reading four CaptureContract digests for the landing Triggers (step 3);
enabling eight Lines one by one (step 5); writing an input file and a direct run
per SBOM (step 6) and per CVE record (below); activating each proposal until a
Line graduates to settle; renewing the mandates before they expire (90 days);
re-instantiating the Blueprints after a kit upgrade that changes one.

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
| `observation` | an applicability Procedure (a source's verdict) | the OSV or CVE-record Capture it read | `role: observation`; no `judgment` |
| `normative` | an analyst (their own judgment) | their own words, or a workspace file retained by `security.evidence-acquire` | `role: normative`, plus the analyst's reasoning in `security.assessment.judgment` |

`cruxible query security.assessment --select status,justification,judgment
--claims` prints each Claim's role; the named worklists (`assessment_index`,
`triage`, `applicability_coverage`, `coverage_gaps`, `urgent_exposures`) carry a
`judgment` column, empty for a source's verdict. The Procedures never revise an
assessment with a `judgment`: their result counts it under `judged`. Retire the
judgment to hand the assessment back to them. An observation in someone's own
words has no admitted evidence: core writes it with verdict `uncovered` (and
warns), and no worklist shows it, since they read supported Claims only.

The workflow, for a proposed `affected` or `inconclusive` you have reviewed:

1. Find it: `cruxible proposal review ID` (before activating), or after,
   `cruxible query --name security.assessment_index` / `security.coverage_gaps`.
2. Retain the evidence (optional; your own words are evidence too): put the
   file in the workspace (code, a config, an analysis note) and
   `echo '{"relative_path": "analysis/jinja2.md"}' > ev.json; cruxible procedure run
   security.evidence-acquire ev.json`; note its `Capture evidence: sha256:...`.
3. Record the judgment in one write (`cruxible write judgment.json`):

   ```json
   {"because": "Analyst review of the OSV verdict: the vulnerable path is unreachable.",
    "subject": "security.assessment/gate-app-1.0.0--cve-2024-56201",
    "changes": [
     {"op": "set", "field": "status", "value": "not_affected", "role": "normative",
      "evidence": {"kind": "capture", "capture": "sha256:..."}},
     {"op": "set", "field": "justification", "value": "vulnerable_code_not_in_execute_path",
      "role": "normative", "evidence": {"kind": "capture", "capture": "sha256:..."}},
     {"op": "set", "field": "judgment",
      "value": "We compile only packaged templates; the attacker-controlled filename never reaches Jinja."}]}
   ```

   Without `evidence` each change cites `because` as your own words. Always set
   `judgment` with a normative status: it is what marks the assessment as yours
   and keeps the Procedures from overwriting it.

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

## What 1.0.1 contains

| Kind | Count | Notes |
|---|---:|---|
| ClaimType | 47 | All v8. Ten identity keys; inventory, applicability (`status` and `justification`: a source's observation or an analyst's normative judgment; `judgment`; `expected_status`), KEV, EPSS, `watch_reason` and remediation-work vocabulary. Observations require a Capture under a kit CaptureContract; a judgment cites the analyst's own words or a workspace file; relationships a Procedure reads from a source (`release.product`, `product.supplied_by`, `assessment.release`, `assessment.vulnerability`) cite that Capture, and their author's own words otherwise; other normative statements are supported by their own origin. |
| SubjectKind | 11 | See Identity. |
| CaptureContract | 7 | `security.kev-http-v1`, `security.cve-record-http-v1`, `security.osv-query-v1`, `security.epss-daily-v1`, `security.cyclonedx-sbom-v1` (a workspace file), `security.workspace-evidence-v1` (a workspace file an analyst cites), `security.observation-output-v1` (acquisition terminals). |
| QueryDefinition | 19 | Worklists (`urgent_exposures`, `kev_exposure`, `triage`, `coverage_gaps`, `remediation_work`, ...), the Procedures' state taps (`watched_vulnerabilities`, `release_inventory`, `assessment_index`), the settle condition and the triage backlog. CVE-scoped ones take `vulnerability` (`Subject:security.vulnerability/<id>`). |
| SourceAcquisitionPolicy | 1 | `security.acquisition`: aliases `catalog`, `record`, `epss`, `osv` (attested), `sbom` and `evidence` (exact); each required, at most 24 h old, refused stale, unavailable or oversized. |
| Blueprint | 4 | `security.kev-acquire`, `security.cve-record-acquire` (slot typed `web.fetch`), `security.epss-acquire` (`security.epss-daily`), `security.osv-applicability` (`security.osv-query`). |
| Procedure | 7 | `security.kev-triage` and `security.epss-triage` (settle terminal; they propose under a propose cap), `security.kev-attention` (inbox), `security.sbom-acquire` and `security.evidence-acquire` (direct), `security.sbom-import` and `security.cve-applicability` (propose). |
| ProviderInterface | 9 | `web.fetch` (core's), six analysis interfaces, two Source interfaces. |
| Providers | 3 | Bundled: `security-analysis-provider` 1.0.1 (deterministic parsing and decisions, no network) and `security-sources-provider` 1.0.0 (the OSV.dev and EPSS Sources). Default by name: `cruxible-provider-web` 0.2.2. |

## Operating notes

- **Network.** web.fetch reaches cisa.gov and cveawg.mitre.org;
  `security-sources-provider` reaches api.osv.dev and epss.empiricalsecurity.com
  (its declared endpoints). The SBOM is read from the attached workspace by
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
`procedures` for 1.0.1, `kit build`s it, authors the 1.1.0 successors on the
same instance and builds those, then copies 1.0.1 over `cruxible-kit.json`,
`artifacts/` and `providers/` here and 1.1.0 over `source/variants/1.1.0`. The
same sources build the same kit digest. After changing a provider, bump its
version. `source/providers/cruxible-provider-web` holds the published 0.2.2
wheel, the lock it embeds and the runtime wheel that lock names by path, so
`kit build` can record the default's hashes; none of those files ship.
`source/variants/1.1.0` is a release-gate fixture (changes `kev_exposure`, adds
`vulnerability.kev_cwes`, changes the kev-acquire Blueprint), not a published
version.

## Release gate

`gate/test_security_kit_gate.py` runs the v1 release gate end to end on a fresh
daemon with a scratch state root and HOME: the kit is published to a throwaway
HTTPS OCI registry on 127.0.0.1, installed, instantiated, automated, fed an
inventory and an SBOM, run through OSV and CVE-record applicability, applicability
bets, KEV triage and attention, EPSS, a restart, measurement, graduation to
settle, the upgrade to `source/variants/1.1.0` and the re-import of a changed
SBOM and a new release, asserting each step's
observable. It is offline from every security source: `gate/fixture-sources`
(package `security-gate-sources`) is cruxible-provider-web's own `WebFetch` and
the kit's own OSV and EPSS adapters (vendored by its `build_registration.py`)
answering from `responses/` (recorded once by `record_responses.py`). Provider
installs still need PyPI.

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
