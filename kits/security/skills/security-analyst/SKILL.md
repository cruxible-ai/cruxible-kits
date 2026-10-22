---
name: security-analyst
description: Work as a security analyst on an instance with the Cruxible security kit - answer exposure questions, work the KEV triage backlog, review applicability proposals, record analyst judgments with their evidence, act on hardening answers (found, none, unknown), triage code findings without a finder confirming its own report, and carry an incident through patch, audit and rotate on evidence, never on self-report.
---

# Security Analyst

Use this skill when the security kit is installed and the user wants security
questions answered or security work done: what is exposed, what is untriaged,
whether a finding is real, what to fix first, and how to respond when a
vulnerability is exploited in the wild.

The kit's [README](../../README.md) is the source for every name below, and
its [reference](../../reference.md) lists every kind, field and query. The
core guides are at https://docs.cruxible.ai. If the kit isn't installed yet,
use the `adopt-kit` skill and the README's **Install and first answers**. If
the instance doesn't yet hold what you ship and run, or an answer is unknown,
use the [security intake skill](../security-intake/SKILL.md) first: it pulls
in SBOMs, inventory, services, credentials and log sources, and fetches what
each unknown names.

## Ground rules

- **Found, none, or unknown.** An answer is **none** only when a current
  coverage says the source was read and nothing matched. When nobody has read
  it, the answer is **unknown**, and the job is to run the pull that answers
  it. Never report "none" for something nobody read.
- **Observations versus judgments.** Procedures record what a source said
  (role `observation`, citing the Capture they read). Your decisions are
  normative (role `normative`), with your reasoning as the write's `because`.
  Reads show each Claim's role; the worklists carry a `status_role` column.
- **Nobody confirms their own finding.** Under
  `independent_approval_required`, a change waits for someone other than its
  author, so a finder's confirmation waits for a reviewer. Under
  `self_approval_allowed` it lands alone, and no query shows who wrote it; say
  so when it matters ([Review and
  governance](https://docs.cruxible.ai/review-and-governance/#the-approval-policy)).
- **Judgments never go in a mandate.** Automation may settle verbatim facts
  (KEV and EPSS fields, parsed workflow facts) once it has earned it. Verdicts,
  justifications, verification, `affects`, `explained_by` and publish gates
  stay with people and agents.

## 1. Orient

```bash
cruxible orient
cruxible next                                            # what is wrong or waiting
cruxible inbox list --status unread                      # what the Lines posted for judgment
cruxible proposal list --status open
```

These Lines post for judgment: `security.harden` (hardening answers),
`security.kev-attention` (possible exposures), the SARIF attention Line of
each repository (`security.sarif-attention.<repo>` in the example automation;
regressions and location gaps), and during an incident its respond Line
(`security.respond.<incident>`) and log import (`security.log-import.<incident>`:
incomplete reads). Use `--line NAME` to read one.

Open proposals from the kit's Lines are its proposed observations; review them
before anything else rests on them.

## 2. Answer exposure questions

Each question in the README's [What it answers](../../README.md#what-it-answers)
table is a saved query:

```bash
cruxible query --name security.urgent_exposures      # exposed releases, KEV-listed first, then EPSS
cruxible query --name security.triage --param vulnerability=security.vulnerability/CVE-…
cruxible query --name security.kev_exposure          # internet-facing hosts running an affected release
```

Read the flags and `status_role` with each row: a value flagged `stale` or
`contested`, or a status that is an observation nobody has reviewed, is part
of the answer. In `urgent_exposures`, `asset` is a host that declares
installing the release (declared and observed when `asset_observed` is set)
and `observed` a host only a scan sees running it; a release with both kinds
pairs each declaring host with each scan-only one, so count hosts per column,
not rows. `triage` lists declaring hosts only. An SBOM release with no assessment for a CVE
means nothing decided it, not that someone judged it safe: read its
`osv_coverage` (`security.release_inventory`). Under `complete` coverage OSV
answered every component, so a CVE OSV knows (`security.vulnerability.package`)
that none of them is a package of is none; under `partial` coverage (a
`pkg:brew` or `pkg:generic` component OSV never indexes) it is unknown.

## 3. Work the triage backlog

```bash
cruxible query --name security.kev_triage_backlog    # KEV-listed, no status or inconclusive
cruxible query --name security.assessment_index      # every assessment, with its status role
cruxible query --name security.coverage_gaps --param vulnerability=security.vulnerability/CVE-…
```

- **Review applicability proposals.** `security.osv-applicability` and
  `security.cve-applicability` never settle; every `affected`,
  `not_affected` and `inconclusive` they propose is reviewed
  (`cruxible proposal review ID`). Check the cited Capture before approving.
- **Record a judgment** where the source can't decide or is wrong for your
  deployment: retain what you read (`security.evidence-acquire` on the file),
  then set `status` and `justification` (and, for `affected`, the `component`
  that brings it in) with role `normative`, citing that Capture, in one write
  with your reasoning as `because`. A judgment cites your own words or a
  workspace file under **`security.workspace-evidence-v1`**: a source's Capture
  (the OSV query, a CVE record) is refused for a normative Claim
  (`existing_capture_not_admitted`), so retain the record or note you read as a
  workspace file instead. The README's
  [Analyst judgments](../../README.md#analyst-judgments) shows the exact write.
- **Name a product the records name differently.** When a CVE record's affected
  entry names your release another way (GitHub's CNA writes `cli/cli` for
  Homebrew's `gh`), state `security.release.product_alias` on the release
  (`cli/cli`, a purl without version, a repository URL or a CPE prefix), citing
  a retained workspace file that shows it (the formula's JSON), then re-acquire
  the record: the matcher reads aliases like the release's own name. A partial
  name match is never a match.
  A retained file is kept for good (that contract can't be erased): never
  retain one holding a secret, such as a config as deployed; cut the
  credentials out first.
- **Hand an assessment back** to the Procedures by retiring your normative
  status and justification; they never revise a normative one.
- **Keep a CVE watched** after a `not_affected` judgment by stating a
  `watch_reason`.

A `security.kev-attention` item is a possible exposure nobody has looked at.
Close it by assessing the release or stating a `watch_reason`; acknowledging
the item doesn't close the gap.

## 4. Act on hardening answers

`security.harden` answers HQ1–HQ6 per gated target
([the hardening questions](../../README.md#your-systems-the-hardening-questions)):

- **found** is an inbox item. Decide it: a `security.remediation` naming the
  job (`security.work.job`) with its rationale, or a `security.exception` if
  the risk is accepted, then `inbox link` the item to it.
- **unknown** is one gap item per source, `{source, pull, input}`. Run that
  pull with that input, review the parse proposal, and run harden again.
- **none** appears only in the run summary, naming the revision it read.

A question is asked only of a target whose `publish_gate` someone has stated.
To investigate a signal (an HQ5 mismatch), follow the README's hop table: one
pull per hop, each cited, competing explanations recorded with `--contend`
and resolved by retiring the wrong one `was-wrong`.

## 5. Triage code findings

The README's [Your code's findings](../../README.md#your-codes-findings) and
[A code finding, end to end](../../README.md#a-code-finding-end-to-end) are the
source.

```bash
cruxible query --name security.open_findings --param repo_ref=github.com/OWNER/REPO
cruxible query --name security.finder_record --param repo_ref=github.com/OWNER/REPO   # each finder's record
```

1. **Review the report.** A SARIF import proposes the finding by key
   (weakness and locus, never a line number) with `rule`, `reported_by` and
   `severity`. A dependency advisory is routed to the SBOM path, not a finding.
   SARIF and reproduction reports are kept for good: never acquire a secret
   scanner's SARIF (its snippets are the secrets) or a PoC report with tokens
   or an environment dump in it.
2. **Locate it.** Add `location` as a file citation of the sink line, so
   `next` reports `citation_drifted` when that code changes.
3. **Decide.** A `verdict` needs a retained Capture: the code read
   (`security.evidence-acquire`) for `false_positive` or `not_exploitable`,
   with a `justification`, or a reproduction (`security.reproduction-acquire`
   of a failing PoC) for `confirmed`. Your own words are refused. Write the
   reasoning as a section in `findings/<id>.md` in the same write.
4. **Disagree by contending.** When a verdict you think is wrong stands, write
   yours with `contend: true`. The verdict reads `conflict` and `next` shows
   `claim_conflicted` until the wrong call is retired `was-wrong`
   ([Keeping knowledge
   current](https://docs.cruxible.ai/keeping-knowledge-current/#disagreement-competing-values-and-contradictions)).
5. **Don't confirm your own report.** If you (or the scanner principal you run
   as) reported the finding, leave the confirmation to an independent
   reviewer.
6. **Track the fix.** A remediation with `work.finding` while it's in
   progress; after the fix, a full re-scan proposes `verification` `fixed`
   (a partial scan never verifies), and `fixed_by` names the fixing change.
   A later report of the same finding is a regression.

## 6. Respond to an incident

The README's [Respond to an incident](../../README.md#respond-to-an-incident) is
the source. You govern the response; your own tools perform it. Cruxible runs no
command against any service.

```bash
cruxible inbox list --line security.respond.INCIDENT --status unread
cruxible query --name security.incident_exposure --param incident=INCIDENT    # RQ1 (assessed)
cruxible query --name security.scanned_runs                                    # RQ1 (every scanned release)
cruxible query --name security.open_patches --param incident=INCIDENT         # RQ2, internet-facing first
cruxible query --name security.audit_status --param incident=INCIDENT         # RQ3
cruxible query --name security.incident_credentials --param incident=INCIDENT # RQ4
```

- **Declare.** An incident groups the CVEs of one response: its window
  (`window_start`), rotation policy and status, plus its respond and log
  import Lines, in one approved ChangeSet. Enable both Lines after approval.
  Naming a CVE in an incident watches it.
- **Answer every pair.** RQ1 pairs each incident CVE with every release a scan
  observed. A pair nobody assessed is unknown until evidence answers it, and its
  gap names the next step: the CVE's record (`security.cve-record-acquire`,
  `input.url`) when none was read; "OSV doesn't index N components of this
  release" (a judgment, a product alias, or a re-scan naming the binary by a
  purl type OSV indexes, such as `go version -m` for a Go binary); the OSV Line
  when OSV hasn't answered the release; an analyst's judgment last. Never
  report "not affected" for a pair the respond Line reads unknown.
- **Act only on an accepted remediation.** A patch names `work.asset`,
  `work.assessment` and `target_release`; a rotation names `work.credential`,
  `work.audit` and `revokes_key` (the `key_id` held when you raise it). Approval
  is the authorization to act. Set `progress` `completed` when done: it never
  closes anything.
- **Accept a risk only with an expiry.** When an exposure can't be patched
  yet, raise a `security.exception` (`work.asset`, `work.assessment` for each
  of the incident's CVEs on that release, `expires_at`, `approval` `approved`
  citing a section of the incident's note that says why). While it holds, RQ2
  reads *excepted* instead of `patch_missing`; at `expires_at` the exposure is
  posted again. RQ1 still finds it, so it never closes the incident.
- **Prove with a read you did not make.** A full inventory scan verifies a
  patch, a separate state read of the credential verifies a rotation. Whoever
  acted does not acquire the Capture that verifies the action; `cruxible get
  ProcedureRun:RUN-...` shows each acquiring run's `actor`. A receipt from the
  issuer records the new key id; it never verifies.
- **Audit in three states.** State the audit's log sources first (stating them
  asks the question), starting from the service's `log_source` list: the
  respond Line's gap names it (`input.sources`), and a listed source the audit
  leaves out keeps the answer unknown. Once the audit exists, one gap per
  service lists every missing piece (`input.missing`: a source to state, the
  window end, the result, each uncovered interval to read). A source the service doesn't list yet:
  add it to the service too, with its doc section. `none` needs
  `not_exploited`, a `window_end`, and complete reads of every source covering
  the whole window. An incomplete read is a finding about
  the logs, not about the attacker: report it as such, with what was missing
  (`missing: [{from, to, reason: expired|unavailable|not_searched, status}]` in
  the read: the item says "records A to B expired (HTTP 410)"). The result cites
  the decisive read (or a workspace file, `security.workspace-evidence-v1`); your
  reasoning goes in a section of the incident's note. Disagree by contending.
- **Clear answered gaps yourself.** A gap that closed is simply not posted
  again; the inbox doesn't resolve items on its own (dispositions are yours).
  After a respond run, acknowledge each respond item whose latest sighting
  predates that run.
- **Rotate, usually after the patch.** Rotating after the patch is verified is
  the recommended order (rotating first lets an attacker still on the host read
  the new key), but it is your call: rotate at once when a key is known leaked or
  the patch cannot land soon. The respond Line posts `rotate` with the service's
  audit and patch state and never gates the rotation on the patch.
- **Never put a secret in a file.** Record only the allow-listed fields: key ids
  or `fp:` fingerprints, states, times, who. If a secret slips into a file you
  acquired, stop, rotate what it exposed and erase the Capture's body
  (`cruxible capture erase CAP-...`: the inventory, log-read and credential-state
  contracts authorize it), with a `--because` that never repeats the secret.
  The preview names the Claims it backed; `next` then lists each as
  `claim_evidence_erased`. Acquire a clean read and re-bind each onto it
  (`cruxible rebind CLM-... --capture CAP-... --because "..."`) before you
  report RQ1-RQ4 again: until then the respond Line doesn't answer for what
  that scan covered.
- **Close on the answer.** Close (`status` `closed`, with a Closure section)
  only after the respond Line posts `ready_to_close`, and name its residue
  (audits that stay unknown, and that their credentials were rotated).

Report per question RQ1-RQ5 in the README's flow table shape, with the exact
pull or statement for every unknown.

## 7. Report

Report in priority order, one row per item:

| Severity | Question or finding | Answer | Evidence | Next |
|---|---|---|---|---|

- **Answer** is found, none or unknown, or the verdict and its role.
- **Evidence** names exact references (`CLM-…`, `security.release/…`, a
  proposal ID, an inbox item) so anyone can `get` them.
- **Next** is the exact command, the pull that answers an unknown, or who
  must review.

Say which judgments are yours and wait for review, and what you didn't read.
