# Security kit walkthroughs

Three areas of the kit worked end to end as the release gate runs them: the
hardening questions about your CI and registries, the weaknesses found in your
own code, and responding to an incident. The [README](README.md) explains how
the kit models your world and runs on its own; start there.

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
   a PyPI target's comes from its provenance). From the Python SDK, the target is
   created by its key and its gate stated in one change set:

   ```python
   from cruxible_client import Cruxible

   cx = Cruxible.connect()
   draft = cx.changes(rationale="Ask about our release targets.")
   target = draft.subject(cx.new_subject(
       "security.target", key={"registry": "pypi", "name": "example-app"},
       rationale="We publish it."))
   draft.claim(subject=target, predicate="security.target.publish_gate", value="push:tags:v*",
               role="normative", rationale="Only a v* tag push may publish.",
               self_source="gate: push:tags:v*\n")
   intent = draft.submit()
   intent.outcome.status   # 'landed'
   ```

2. **Harden**: author your repositories' and PyPI projects' pull and parse Lines
   ([Add a repository](intake.md#add-a-repository), [Add a PyPI
   project](intake.md#add-a-pypi-project): `security.repo-pull.example-app`,
   `security.repo-parse.example-app`, `security.registry-pull.example-app`,
   `security.registry-parse.example-app`), enable them and the example's
   `security.harden`, and run `cruxible line run security.harden`. Every answer
   starts unknown; `cruxible inbox list --line
   security.harden` holds one gap item per source, `{source, pull, input}`, however
   many questions wait on it. Answer one by running its pull with its input:
   `cruxible procedure run security.registry-acquire input.json`.

3. **Parse.** A parse Line reads one source's pulls (its taps are keyed by its
   parameters, never by the landed Capture): intake's recipe authors
   `security.repo-parse.example-app` (`main`'s workflows) and
   `security.registry-parse.example-app`, each with its landing Trigger;
   every other landing halts `other_source`. For another source, author a parse
   Line with its parameters (`source`, `repo_source`, `forge_host`, `full_name`,
   `ref`, `scope`, `path`) and its landing Trigger as the recipe does, and enable it. Review and
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
   | 3 | `security.fetch` | `artifact.uploaded_by` |
   | 4 | none if HQ2 already covers the source | the jobs that can write release assets |
   | 5 | `security.fetch` (workflow runs) | run attempts and times, cited in the note |
   | 6 | none | hypotheses: `signal.explained_by` (one write each; a second with `--contend`); the slot reads contested |
   | 7 | `security.fetch` (commits of a path) | `security.change`; the right hypothesis is revised to it, the other retired `was-wrong`, and the slot resolves |
   | 8 | none | `security.remediation` with `work.job` |

The parse Lines start at propose; how they graduate to settle is in
[Measure and graduate](README.md#measure-and-graduate).

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

**How a finding fits the model.** `security.finding` (in "Your systems" in the [README's model](README.md#how-it-models-your-world)) is
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
`security.file-v1`, or the code read under `security.file-v1`;
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

For the repository `github.com/example-org/example-app`, its findings Lines
authored by intake's recipe ([Its scans](intake.md#its-scans)); the gate runs the
same steps on its fixture repository (principals `scanner`, `triage`, `reviewer`,
`maintainer`):

1. **Scan and annotate.** `semgrep scan --sarif --output scans/semgrep.sarif`, then
   add to each run what the scanner knows and SARIF tools do not all write:
   `versionControlProvenance: [{"repositoryUri": "https://github.com/example-org/example-app",
   "revisionId": "<commit>"}]` and `properties: {"cruxible.coverage": "full"}` (every rule
   of the configuration over the whole repository; `partial` otherwise, which never
   verifies a fix). SARIF carries code snippets, and `security.file-v1` keeps its
   bytes for good: don't acquire a secret scanner's results (their snippets are
   the secrets), and check a scan of code that embeds credentials before you do.
2. **Report (a proposal).** `cruxible procedure run security.sarif-acquire` with
   `{"relative_path": "scans/semgrep.sarif"}` retains it under `security.file-v1`; the
   landing runs `security.sarif-import.example-app` (parameter `repo_ref`), which proposes
   `security.finding` `CWE-89` at `app/db.py#snippet:...` with `rule`
   `semgrep:sqli-fstring-execute`, `reported_by` `semgrep` and `severity` `high`. Another
   repository's Line halts `wrong_repo`; an unchanged scan halts `no_change`. The
   reviewer approves (`cruxible proposal approve ID`).
3. **Locate.** Catalogue the file (`cruxible files add example-app-db app/db.py`), then
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
   `security.release/example-app--1.0.0`. While both contend, the verdict reads `conflict`
   and `next` shows `claim_conflicted`; retiring the wrong call (`was-wrong`) resolves it.
6. **Remediate.** A `security.remediation` with `work.finding` and `progress`
   `in_progress`. While release 1.0.0 is served, HQ6 posts the finding.
7. **Fix and verify.** After the fix merges, `cruxible next` in the workspace shows
   `citation_drifted` on `location`. A full re-scan of the fixed revision lands; the
   import proposes `verification` `fixed` (a false positive is never verified). Then
   one write sets `fixed_by` (the `security.change` by key) and retires `location`
   `superseded`. A later full scan that reports it again proposes `present` and
   `security.sarif-attention` posts a regression.

Graduation never covers judgments; how the import's report observations may
graduate is in [Measure and graduate](README.md#measure-and-graduate).

## Respond to an incident

Patch, audit and rotate when a vulnerability is exploited in the wild (the gate
walks PHP2Shell: CVE-2026-109618 and CVE-2026-109619, unauthenticated RCE in the
PHP runtime, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35). The kit runs no
response command and bakes in no service: your agent patches, queries logs and
rotates keys with your own tools. Cruxible holds what needs doing and why, who
approved it, and the evidence that it is done.

| Question | Where the answer comes from |
|---|---|
| RQ1 Which deployments run an affected release? | `security.incident_affected` (parameter `incident`, its name): the releases assessed affected or inconclusive, affected first, with the assets a scan observed running them; `security.incident_exposure`: every assessment of the incident's CVEs, affected first, then not_affected; `security.scanned_runs`: every other release a scan observed, answered for each incident CVE; `security.deployments`: every asset with its nones (the products a full scan showed it running none of) |
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
state read that lists the old key revoked or deleted (or states it is complete and
no longer lists it), an audit's none only on complete log reads; a self-report never
closes anything. Each of these is a body your agent writes from its own tool's
answer, so it is an attestation: the kit checks that it is internally consistent
and complete as stated, never where it came from. That a state read is later,
separate and acquired by someone other than the rotator is your convention, which
you check when you review the verification. Run an incident under
`independent_approval_required` with your security lead as the usual approver, and
let a principal other than the one who acted acquire the evidence that verifies the
action (`cruxible get ProcedureRun:RUN-...` shows each acquiring run's `actor`).
Core has one approval profile (one signer other than the creator), so "a lead must
approve rotations" is your convention, not a rule core enforces. **A solo
maintainer** under `self_approval_allowed` (the quickstart default: "Required
approvals: none") gets no role separation from approval at all: the approval is
the same person as the change. That's fine: the evidence rules are the control
(a full scan, a state read showing the old key retired, complete log reads), and
they hold whoever approves, as far as the bodies are honest. Independent approval adds a second person, not a stronger proof.

**Secrets never enter.** A credential is non-secret: issuer and name, where it is
used (`used_by`) and what it reaches (`reaches`), its current key's id
(`key_id`: the issuer's key id, or `fp:` and 16 hex of the secret's sha256),
`issued_at` and `issued_by`. The credential-state body is an allow-list; an unknown
field, a key id shaped like a secret (longer than 40 characters, a known secret
prefix, high entropy), or an issuer, name or `created_by` holding a secret-shaped
token refuses the whole body and posts `secret_shape` with a fixed message: no
value and no field name from the body is echoed (a JSON key can be the secret).
The inventory and log-read imports refuse the same way (a position such as
`assets[2].runs[0]`, never the value), and a log read whose incident, service,
source or `incomplete_reason` holds a secret-shaped token is refused, since those
are copied into the audit's Claims and inbox items. The bytes are already retained when that happens: stop, rotate whatever it
exposed, and erase the Capture's body. The incident evidence contract
`security.file-erasable-v1` declares `erasure: authorized_by_rule`, so
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
  Until then the host has no current inventory: the respond Line enumerates
  every asset (`security.deployments`), so an erased scan leaves the host
  unknown in RQ1, with a gap naming the inventory pull, never silent. Re-acquire
  the scan and re-bind its Claims straight away.
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

| Contract / logical source | Acquired by | Body (a workspace file, at most 1 MiB) | Read by |
|---|---|---|---|
| `security.file-erasable-v1` / `security.inventory` | `security.inventory-acquire` | the kit body `{"scope", "looked_for": ["php", "debian/php8.2"] or ["*"], "coverage": "full" or "partial", "assets": [{"hostname", "runs": ["pkg:generic/php@8.3.10"]}]}`, no timestamps; or a CycloneDX JSON SBOM of one asset (Syft, Trivy) with metadata properties `cruxible.scope` and `cruxible.asset` | `security.inventory-import.<scope>` (parameter `scope`) |
| `security.file-erasable-v1` / `security.log-read` | `security.log-acquire` | `{"audit": {"incident", "service"}, "source", "query", "from", "to", "complete", "records_scanned", "matches": [{"at", "summary"}]}`; `complete` = every record in [from, to] searched (no sampling, no result cap, retention reaching `from`); redact match summaries | `security.log-import.<incident>` (parameter `incident`) |
| `security.file-erasable-v1` / `security.credential-state` | `security.credential-acquire` | `{"issuer", "name", "read": "receipt" or "state_read", "keys": [{"key_id", "state": "active" / "inactive" / "revoked" / "deleted", "created_at", "revoked_at", "last_used_at", "created_by"}]}` and nothing else, plus `"complete": true` when a `state_read` lists every key the issuer holds for it (every page read) | `security.credential-import` |

What each import proposes:

- **Inventory.** Each asset by key and `asset.scanned_in` the scope's coverage;
  each release it runs (`product_name` the purl's whole namespace and name, so
  `pkg:deb/debian/php8.2@8.2.20-1~deb12u1` is `debian/php8.2` and
  `pkg:golang/github.com/cli/cli/v2@v2.86.0` is `github.com/cli/cli/v2`, never a
  last segment; `version` from the purl; the purl as `release.component`, so OSV
  decides a distro build) as `asset.runs`, observed
  beside the declared `installs`. Two ecosystems' packages of one name and
  version (`pkg:npm/foo@1.0`, `pkg:pypi/foo@1.0`) are one release with both
  purls as components: neither is dropped. A **full** kit scan restates the coverage
  revision (the digest of its `looked_for` and (asset, runs) set: an unchanged
  fleet, in any order, is a re-observation and proposes nothing, while freshness
  moves), retires runs it no longer sees of the products it looked for (a new
  version of a product revises the run it replaces), and
  proposes `verification` `verified` on an open patch whose asset no longer runs
  the affected release; a scan that still shows it on a patch claimed `completed`
  proposes `failed`. A **partial** scan only adds.
  A complete read also states each asset's **nones**: an `asset.runs` inverse
  keyed by the release's `product_name` ("app-1 runs no php"), cited to the scan.
  It states one for every product `looked_for` names that the asset doesn't run,
  and under `*` for a product the asset ran before and no longer runs (the run
  retires and the none lands in one change set: a flip) or declares installing
  (`installs`) and doesn't run; never for a product the scan didn't look for, and
  `*` alone states none for a product the asset never had. A held none is
  restated by each full scan (a none goes stale on the coverage's 12 h horizon),
  and retired when any scan sees the product running again (the other flip) or a
  full scan stops looking for it. `looked_for` stays the record of the question
  the scan asked: it bounds the nones, and says a looked-for product's runs (which
  versions) are complete. A CycloneDX SBOM is one asset's
  complete run set: it adds, retires and verifies for that asset, never states the
  scope's coverage (its own timestamp makes every scan new content), and proposes
  only when the run set changed. It is complete only while every component is
  identified: a component without a purl with a version (missing, malformed,
  unversioned; an operating-system component without a purl included) could be
  any product, the one a patch moved off included (an OS patch too), so such an SBOM only adds, never retires or
  verifies, and the summary counts it (`unidentified`). A complete SBOM flips a
  vanished product to none for its asset; none answers for the scope need a full
  kit scan.
- **Log read.** One `security.audit.read` (`SOURCE FROM/TO`) for a complete read of
  a stated audit. An incomplete read is posted (`read_incomplete`, with why in
  words): a finding about your logs, not about the attacker. Say what wasn't
  searched in the read itself, `"missing": [{"from", "to", "reason": "expired"
  (retention, an HTTP 410) / "unavailable" (an error status) / "not_searched",
  "status": 410}]`, and anything else in `incomplete_reason`; the item reads
  "records 2026-01-21T00:00:00Z to 2026-07-24T08:06:00Z expired (HTTP 410)". A read
  that says `complete` and also names `missing` spans or an `incomplete_reason`
  contradicts itself and is refused, never recorded. A read for an audit nobody
  stated is posted (`audit_not_stated`). Never a `result`.
- **Credential state.** From either kind of read, the current key's `key_id`,
  `issued_at` and `issued_by`. Only from a `state_read`: `revoked_key`, and a
  rotation's `verification`: `verified` when `revokes_key` is listed revoked or
  deleted, or is absent from a listing that says `"complete": true` (every key,
  every page), and an active key issued after the incident's `window_start` exists;
  `failed` when the rotation is claimed `completed` and `revokes_key` is still
  listed. Absence from a listing that doesn't say it is complete proves nothing
  (the summary counts it `unproven`): a receipt relabelled `state_read`, or one
  page, verifies nothing. A receipt (what the issuer returned to the rotating
  agent) never verifies. That the state read is later, separate and acquired by
  someone other than the rotator is **your convention**: a Procedure can't see who
  acquired a Capture, so the kit can't check it. Each acquiring run's `actor` is on
  its ProcedureRun (`cruxible get ProcedureRun:RUN-...`): check it when you
  review the verification.

### Declare the incident

An incident (`security.incident`, keyed by `name`) groups the CVEs of one
response, so each service gets one audit however many CVEs. Declaring it is an
approved act in two parts: one write with the incident's Claims, and one
ChangeSet with its respond Line and log import Line and their Triggers (Lines are
authored disabled: enable both after approval). Rename `php2shell` and the
window for yours. The Claims, which also create the incident by its key:

```python
incident = cx.changes(because="One response to PHP2Shell (CVE-2026-109618, CVE-2026-109619).",
                      subject="security.incident/PHP2Shell")
incident.set("window_start", "2026-09-01T00:00:00Z")
incident.set("rotation_policy", "on_found_or_unknown")
incident.set("status", "open")
for cve in ("CVE-2026-109618", "CVE-2026-109619"):
    incident.add("vulnerability", f"security.vulnerability/{cve}")
outcome = incident.write()
outcome.status   # 'accepted' ('awaiting_approval' when your policy wants a reviewer)
```

For an MCP-only client, the same write is `cruxible_write` with these arguments
(on the CLI, `cruxible write FILE` takes them as a file):

```json
{
  "because": "One response to PHP2Shell (CVE-2026-109618, CVE-2026-109619).",
  "subject": "security.incident/PHP2Shell",
  "changes": [
    {"op": "set", "field": "window_start", "value": "2026-09-01T00:00:00Z"},
    {"op": "set", "field": "rotation_policy", "value": "on_found_or_unknown"},
    {"op": "set", "field": "status", "value": "open"},
    {
      "op": "add",
      "field": "vulnerability",
      "value": "security.vulnerability/CVE-2026-109618"
    },
    {
      "op": "add",
      "field": "vulnerability",
      "value": "security.vulnerability/CVE-2026-109619"
    }
  ]
}
```

The Lines and Triggers:

```python
from cruxible_client.contracts.authoring.models import (
    CaptureEventByNameWindow,
    CaptureLandingByNameSchedule,
    WindowCloseAuthoringSchedule,
)
from cruxible_client.contracts.triggers import CronSchedule

respond, log_import = "security.respond.php2shell", "security.log-import.php2shell"
draft = cx.changes(rationale="PHP2Shell's respond and log import Lines.")
draft.line(name=respond, procedure="security.respond", max_authority="observe",
           parameters={"incident": "PHP2Shell", "inventory_pull": "security.inventory-acquire",
                       "log_pull": "security.log-acquire",
                       "credential_pull": "security.credential-acquire",
                       "record_pull": "security.fetch"})
draft.line(name=log_import, procedure="security.log-import", max_authority="propose",
           trigger_input="log", parameters={"incident": "PHP2Shell"})
draft.trigger(name="security.log-landed.php2shell", line=log_import,
              schedule=CaptureLandingByNameSchedule(
                  capture_contract="security.file-erasable-v1",
                  logical_sources=("security.log-read",)))
draft.trigger(name="security.respond-daily.php2shell", line=respond,
              schedule=CronSchedule(expression="50 7 * * *"))
# Re-ask a day after a key-state read or an inventory scan lands.
for after, source in (("rotation", "security.credential-state"), ("scan", "security.inventory")):
    draft.trigger(
        name=f"security.respond-after-{after}.php2shell", line=respond,
        schedule=WindowCloseAuthoringSchedule(window=CaptureEventByNameWindow(
            capture_contract="security.file-erasable-v1", logical_sources=(source,),
            duration_seconds=86400)))
intent = draft.submit()
intent.outcome.status   # 'landed'
```

The window-close Triggers re-ask a day after a landing: an unverified patch or
rotation is sighted again (an item you acknowledged keeps your decision and counts
the recurrence, `recurred_since_disposition` in `cruxible inbox get`), and an answer
that changed is a new item. A gap that closed is simply not posted again: the
inbox never resolves an item on its own (dispositions are yours), so after a
respond run acknowledge each of its items whose latest sighting (`inbox list`,
`LAST_POSTED`) is older than that run. The log import's propose Mandate
(`security.log-import-propose`), `security.inventory-import.prod` (one Line per
inventory scope) and `security.credential-import` are authored with the incident
response: the kit's [automation template](automation.json) carries the dependency
loop only. No Mandate covers `audit.result`, `audit.window_end`,
`audit.log_source`, `work.verification`, `remediation.*`, `credential.*` or any
incident field.

### The five questions, in three states

`security.respond` answers each question **found** (posted), **none** (the run
summary) or **unknown** (posted as a gap `{subject, pull, input}` naming the pull or
statement that answers it). Unknown is never none: RQ1 enumerates every
deployment from the inventory, never through assessments: every asset
(`security.deployments`, with its inventory coverage and each release it declares
installing) and every release a scan observed on one (`security.scanned_runs`),
each paired with every incident CVE. So a release nobody assessed (Homebrew's
`gh`, an upstream binary as `pkg:generic`), a declared release no scan has read,
and an asset whose scan is missing, stale or erased stay unknown and posted until
a source or an analyst answers them, and the Line never halts `nothing_to_post`
while such a pair is open (an incident with no deployment known at all posts that
gap too). Absence is read from **nones**, never derived from a scan's coverage:
a declared or patched release is not running when the asset holds a current none
of its product (or a current full scan that looked for the product shows another
version running), and an asset runs nothing the incident affects only when it
holds a current none of each product the incident affects (the products each
CVE's record names, `vulnerability.affected_product`; the releases assessed
affected or inconclusive; the packages OSV names), established only once the
record is read: one observed package is never the whole list. A release the
asset runs is none from its own none (an assessment, or OSV's complete answer)
under a current full scan that looked for its product. An incident's CVEs are
watched (KEV, EPSS and OSV read them) from the moment it names them.

The Line posts at most 200 items per run. A run with more refuses (`overflow`,
naming how many of each kind it would post) rather than post the first 200 every
time and never the rest: answer gaps in bulk (a scope's full scan, a judgment
covering many releases: one gap per CVE lists them, *Many releases at once* in [Analyst judgments](in-depth.md#analyst-judgments)),
then run it again.

| # | found | none | unknown |
|---|---|---|---|
| RQ1 | `exposed`: a scan observed the asset running a release assessed affected | a declared or patched release the asset holds a current none of (cited), or a current full scan that looked for the product shows another version of; an asset holding a current none of every product the incident affects (cited); under a current full scan of the asset that looked for the product, a release it observed that is assessed `not_affected` (a negative naming the components it rests on holds while the release has them as they were), or that nobody assessed while OSV answered every component of the exact current set (the coverage's `set` digest) and none is a package OSV says the CVE affects (the answer `cites` those Claims) | an asset with no current inventory (never scanned by a full scan, stale, or its evidence erased), or no current none of a product the incident affects (the gap names the inventory pull, with `looking_for`: name it in the scan's `looked_for`); a CVE whose record isn't read (`record_pull`); an inconclusive assessment (an analyst's judgment answers it); a release nobody assessed for the CVE otherwise, with the next step in order: the CVE's record, a contended unidentified-component count (a statement), a negative whose components moved (`osv_line`), "OSV doesn't index N components of this release" or "its SBOM lists N components without a purl" (a judgment, a product alias, or a re-scan with a purl type OSV indexes), the OSV Line (`osv_line`, when OSV hasn't answered its current components), an analyst's judgment (one gap per CVE listing its releases) |
| RQ2 | `patch_missing`; `patch_overdue`; `patch_disputed` (verification `failed`, or claimed `completed` while still running); `patch_regressed` (verified, then seen running again) | `verification` `verified` and no affected run, under current coverage | a claimed patch no scan has read since; an approved one on schedule is *pending*, and a missing or overdue one under an accepted risk is *excepted* (both summary only) |
| RQ3 | `exploited`: the result `exploited` | `not_exploited`, `window_end` stated, and for every `log_source` the union of its complete reads covers [`incident.window_start`, `window_end`] | no audit (the gap names the service's `log_source` list as `sources`); otherwise one gap per service listing every missing piece in `input.missing`: no log source, a source the service lists that the audit does not state, window open, no result, `inconclusive`, `conflict`, and each uncovered interval (named per source, "A to B") |
| RQ4 | `rotate {credential, services: {audit, patch}, key_id, because}` for each credential a warranted, audited service uses (`on_found_or_unknown`: its audit's RQ3 found or unknown; `all_exposed`: every exposed service with an audit); RQ4 reads credentials through the incident's audits, so state each service's audit first: a service with no audit has no RQ4 answer yet (its RQ3 gap asks for the audit); `rotation_disputed` | a rotation a state read verified, the current key issued after `window_start`; a credential no warranted service uses | claimed rotated, and no state read has verified it yet (none landed, or the one that did lists neither the old key retired nor says it is complete) |
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

Coverage goes stale 12 h after a scope's last full scan, and so do the nones it
stated: every RQ1 and RQ2 none resting on them turns unknown (the respond Line
reads the scope's revision and the nones through every tap,
`security.scanned_runs` and `security.deployments` included), as `cruxible next`
(`claim_stale_evidence`) says.

**Owners and teams.** A patch or rotation names its `owner` (a `security.team`).
Create the team once, in its own approved write (or name one that exists), before
raising remediations: a team created inline in two pending proposals makes the
second stale the moment the first is approved (it then needs `proposal readmit`).

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

`security.incident_status` (parameter `incident`) is one row per CVE, exposure
(affected first), host a scan observed running it (`exposed_host`), patch raised
for an exposed asset or exception accepting its risk, and audit of the incident
with each credential its service uses, with every state as held: `exposure` (the
assessment), `exposed_host`, `host` (the patch's or exception's asset), `patch`
(progress) and `patch_verified`, `excepted_until` (an approved exception's
expiry, until it passes), `audit_service` and `audit` (the result;
`(conflicted)` while disputed), `credential`, `rotation` (progress: an approved
rotation shows `planned` until it starts) and `rotation_verified`. Pending actions are
their own state: a patch or rotation `planned` or `in_progress`, beside its
verification. An exposure nobody has raised a patch or an exception for is a row
with no host (no action yet: the respond Line posts `patch_missing`); a change
still awaiting approval isn't accepted state, so `cruxible proposal list --status
open` shows it. An empty cell is unknown, never none; none is the respond Line's
answer. An exception's expiry moves no state, so re-render the page after it
(`block sync`). Render it into a page with a projection block, which `next` flags
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
