# Security kit in depth

The detail behind the vulnerability answers, for when you need to know why an
answer is what it is, and how to bet on an applicability answer before a source
gives it. Start with the [README](README.md).

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
  `security.fetched-v1`). OSV is then asked about every component
  `purl@version` of every release whose ecosystem is on that list, and for the
  record of every watched CVE and its aliases. Which ecosystem answers for a
  purl type is kit data, carried in the Procedure with its sources (the purl
  spec's types, the OSV schema's ecosystems; `deb/debian` -> Debian, `golang` ->
  Go, `pypi` -> PyPI ...); edit it by authoring a successor of your
  `security.osv-applicability` Procedure. A component of any other type
  (`pkg:brew`, `pkg:generic`, `pkg:docker` ...) is never asked: OSV's empty
  answer there would read as "no advisories". The OSV Capture records it as
  `not_indexed` with why, and each release gets one
  `security.release.osv_coverage` Claim: `complete: N of N components answered;
  set D`, or `partial: A of N components answered; not indexed: brew 1, generic
  1; set D` (and `unanswered K` for a component whose query failed, came back
  truncated, or named an advisory whose record couldn't be read; `unidentified U`
  for components the SBOM lists without a purl, counted by the import as
  `security.release.unidentified_components`). `set D` binds the coverage to the
  exact component set OSV answered for (16 hex of the sha256 of the sorted
  purls): another set, even one of the same size, is unanswered until OSV
  answers again. An empty OSV answer is a negative only under complete coverage
  of the current set. The run also states, for each watched
  CVE, the packages OSV's records say it affects
  (`security.vulnerability.package`, `pkg:deb/debian/php8.2`): OSV knows the CVE.
  A component OSV lists as affected
  -> `affected` (the CVE is created by key when new, and watched through that
  assessment). A watched CVE OSV has package data for
  but does not list -> `not_affected` with `vulnerable_code_not_present` when one
  of its packages is a component at another version OSV answered for **and** OSV
  answered every component of the release (complete coverage): any other
  component could hold the package under another name. The negative names the
  components it rests on (`assessment.component`), so the respond Line reads it
  unproven once the release holds them differently. Of that package, with the
  coverage partial -> `inconclusive`. A failed OSV query for a relevant component
  -> `inconclusive`; a relevant component OSV never answered (not indexed) -> no
  answer (the coverage says partial). A release
  none of whose components is a
  package the CVE affects is not assessed at all: an SBOM release with no
  assessment for a CVE means OSV relates none of its components to it.
  (Writing `component_not_present` for every such pair is releases x watched
  CVEs: on the self-dogfood instance's second day, 509 answers and 2,545
  proposal items nobody needs to review.) An advisory with no CVE alias cannot
  be keyed; the run's result lists it under `unkeyed`.
- **`security.cve-applicability`** (vendor products, by CVE record). When a CVE
  record lands (`cruxible procedure run security.fetch` with
  `{"url": "https://cveawg.mitre.org/api/cve/CVE-...", "logical_source": "cve.record", "max_bytes": 1048576}`), each `affected` entry
  is matched to releases by data, never by a partial name:
  - its `collectionURL` + `packageName` against each component purl's full
    namespace and name (`https://pkg.go.dev` + `github.com/cli/cli/v2` names
    `pkg:golang/github.com/cli/cli/v2@v2.86.0`; decided by that component's
    version, which the assessment names as its `component`). Which purl type a
    collection names is kit data carried in the Procedure, citing the CVE schema
    and the purl spec; edit it by authoring a successor of your
    `security.cve-applicability`;
  - its `repo`, or a forge collection's `packageName` (`https://github.com` +
    `cli/cli` is `github.com/cli/cli`), against the release's source repository,
    where the system model knows it (`security.release_sources`: the repository a
    target serving the release is published from) or a forge purl names it
    (`pkg:github/cli/cli`);
  - its vendor/product, `packageName`, `repo` or `cpes` against the release's
    **product aliases** (`security.release.product_alias`, below). A CPE is
    parsed as CPE 2.3 writes it (escapes undone, case-insensitive) and compared
    whole: `foo-bar` and `foobar` are two products;
  - its product against the release's product name (the whole name, its name
    form: trimmed, case-insensitive), with a supplier equal to the vendor or
    unset. A vendor that differs, even one that contains the supplier's name, is
    another vendor (`inconclusive`) unless an alias says otherwise.

  Every way the record names a release counts: any `affected` answer (one copy
  of a module among several, say) makes the release `affected`; `not_affected`
  needs every one of them unaffected; anything else is `inconclusive`. A
  negative decided through components names them (`assessment.component`).

  A matched release is decided by the entry's version ranges (`version`,
  `lessThan`, `lessThanOrEqual`, `changes`; a `lessThan` ending in `*` is
  open-ended; a `version` written as comparisons, `< 2.97.0`, as GitHub's CNA
  writes them, is read as written) and `defaultStatus`. Conservative: a
  contradicting vendor, or a version the ranges cannot order -> `inconclusive`. A
  release the record doesn't name gets no assessment at all: an incident's
  respond Line reads that pair unknown, never none. The run also states the
  record's `title` for the CVE (a record of it was read). A release OSV answered
  for (its `osv_coverage`) is OSV's to decide once OSV knows the CVE
  (`security.vulnerability.package`), so the two Procedures never flip an
  assessment between them.

  **Product aliases.** When a record names your product differently (GitHub's
  CNA writes `cli/cli` for what Homebrew calls `gh`), state it once, citing
  evidence you retained with `security.evidence-acquire` (the Homebrew formula's
  JSON, whose source URL is `github.com/cli/cli`): `cruxible add
  security.release/gh--2.86.0 product_alias cli/cli --capture CAP-... --because
  "Homebrew's gh formula builds github.com/cli/cli"`. An alias is
  vendor/product as a record names it, a purl without version, a repository URL
  or a CPE prefix (`cpe:2.3:a:github:cli`). Re-acquire the record afterwards: the
  matcher reads aliases like the release's own name.

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
   Its bytes are kept for good (`security.file-v1` can't be
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

**Many releases at once (a bulk judgment).** The respond Line posts one
judgment gap per CVE (`statement`, `input.releases`: every release a judgment of
the CVE would answer, with `osv_not_indexed` when OSV indexes none of their
components), as it posts one record pull per CVE. A judgment over a set of
releases is one note and a few writes. Write the reasoning once, as a section of
the incident's note (or a retained workspace file), then one change set per
release: create the assessment by key and set `release`, `vulnerability`,
`status` and `justification`, each `normative` and citing that section. That's
5 changes a release, and a write takes at most 500 changes, so put at most **100
releases in one write** (run 2: 101 Homebrew releases were 505 changes, two
writes):

```json
{"because": "None of these Homebrew formulas is PHP or links libphp (brew info --json=v2, section 'Not PHP').",
 "docs": [{"op": "append", "file": "incidents/php2shell.md",
           "text": "## Not PHP\n\nThe workstation's formulas ... none is PHP or links libphp.\n"}],
 "changes": [
  {"op": "create", "label": "a-jq", "subject_kind": "security.assessment",
   "key": [{"predicate": "security.assessment.release_id", "value": "jq--1.7.1"},
           {"predicate": "security.assessment.cve_id", "value": "CVE-2026-109618"}]},
  {"op": "set", "subject": {"created": "a-jq"}, "field": "security.assessment.release",
   "value": "security.release/jq--1.7.1"},
  {"op": "set", "subject": {"created": "a-jq"}, "field": "security.assessment.vulnerability",
   "value": "security.vulnerability/cve-2026-109618"},
  {"op": "set", "subject": {"created": "a-jq"}, "field": "security.assessment.status",
   "value": "not_affected", "role": "normative",
   "evidence": {"kind": "section", "file": "incidents/php2shell.md", "section": ["Not PHP"], "own_words": true}},
  {"op": "set", "subject": {"created": "a-jq"}, "field": "security.assessment.justification",
   "value": "component_not_present", "role": "normative",
   "evidence": {"kind": "section", "file": "incidents/php2shell.md", "section": ["Not PHP"], "own_words": true}},
  "... the same five for each further release of input.releases, at most 100 per write ..."]}
```

Append the note in the first write only; the later writes cite the section it
added. Release ids are those the gap and `security.release_inventory` name. Run
the respond Line again after the last write: the CVE's gap is no longer posted.

### KEV, EPSS and attention

`security.kev-triage` compares each retained KEV catalog with every watched
vulnerability and proposes (or, graduated, settles) the KEV fields that changed.
Its terminal is a settle, but under the example automation's propose cap (the
Line's `max_authority` `propose`) a settle is a proposal that waits for your
approval like any other until you graduate it ([Measure and graduate](README.md#measure-and-graduate)). The fields:
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
