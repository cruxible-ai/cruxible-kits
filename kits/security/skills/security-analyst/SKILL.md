---
name: security-analyst
description: Work as a security analyst on an instance with the Cruxible security kit - read exposure answers for what they say and don't, judge applicability, hardening answers and code findings on cited evidence, and carry an incident through patch, audit and rotate on reads nobody self-reported.
---

# Security analyst

Use this skill when the user wants security questions answered or security work judged on an instance with
the security kit. The state says what is waiting: `cruxible next`, the inbox (what Lines posted for
judgment) and open proposals. This skill says what the answers mean and what a sound judgment rests on. The
kit's docs are the source for every name, query and exact write (its README and `walkthroughs.md`; an
analyst's judgment writes in `in-depth.md`), `reference.md` for every kind and field; the [security intake
skill](../security-intake/SKILL.md) says what each unknown is asking for.

## Ground rules

- **Found, none, or unknown.** None only when a current coverage says the source was read and nothing
  matched. Never report none, or "not affected", for anything nobody read or the respond Line reads unknown.
- **Observations are the source's word; judgments are yours.** A Procedure's Claim (role `observation`)
  says what a source said, citing its Capture. Your decision (role `normative`) is your belief on evidence
  you cite, with your reasoning as `because`. Read the role with every value.
- **Review what automation proposes.** Applicability never settles: check the cited Capture before you
  approve an `affected`, `not_affected` or `inconclusive`. An unreviewed observation is part of the answer;
  say it as one.
- **Nobody confirms their own finding**, and whoever acted doesn't acquire the read that verifies the
  action. The kit can't check either: read the acquiring run's actor. Under `self_approval_allowed` a change
  lands alone and no query shows who wrote it; say so when it matters.
- **Judgments never go in a mandate.** Automation may settle verbatim source fields once it has earned it;
  verdicts, justifications, verification, `affects`, `explained_by` and publish gates stay with people and
  agents.
- **Never retain a secret** (a secret scanner's SARIF, a PoC report with tokens, a config as deployed). If
  one lands, rotate what it exposed, erase the Capture, and re-bind what it backed onto a clean read.

## Reading the answers

- **Flags are part of the answer**: `stale`, `contested`, a status nobody reviewed.
- **No assessment is not safe**: nothing decided it. The release's OSV coverage says whether OSV could
  have: under `complete`, a CVE OSV knows that touches none of its components is none; under `partial` it is
  unknown. A coverage answers only for the component set its digest names.
- **Declared and observed hosts.** In exposure answers `asset` is a host that declares installing the
  release and `observed` one only a scan sees; rows pair them, so count hosts per column, not rows.
- **Advisories without a CVE alias** (a GHSA or PYSEC id alone) can't be tied to a CVE and aren't proposed;
  the component they hit still counts as answered.
- **An attention item is a possible exposure nobody has looked at.** Assessing the release or stating a
  `watch_reason` closes it; acknowledging it doesn't.
- **Hardening answers** (HQ1-HQ6, asked only of a target whose publish gate someone stated): found is an
  item to decide, a remediation or an exception; unknown is one gap per source; none appears only in the run
  summary, naming the revision it read.

## What a judgment rests on

| Judgment | Rests on |
|---|---|
| an assessment's status and justification | your words or a retained workspace file; a source's own Capture is refused for a normative Claim |
| a finding's `false_positive` or `not_exploitable` | the code read, retained, with a justification |
| a finding's `confirmed` | a failing reproduction, retained |
| an audit's result | the decisive log read, or a workspace file; never a note section |
| a patch verified | a full inventory scan the patcher didn't acquire |
| a rotation verified | a state read of the credential: the old key revoked or deleted, or absent from a complete listing; an issuer's receipt never verifies |

Write the reasoning once, as a section of the incident's or finding's note, cited in the same write.
Disagree by contending; resolve by retiring the wrong value `was-wrong`. Retiring your normative status
hands an assessment back to the Procedures, which never revise one. A `not_affected` you still want watched
needs a `watch_reason`. When a record names your release another way (GitHub's `cli/cli` for Homebrew's
`gh`), state a product alias citing a file that shows it; a partial name match is never a match.

## Code findings

A finding is keyed by weakness and locus, never a line number; a dependency advisory belongs to the SBOM
path. Its `location` is a file citation of the sink line, so a code change shows as drift. Only a full
re-scan verifies a fix; a later report of the same finding is a regression.

## Incidents

You govern the response; your own tools perform it. Cruxible runs nothing against any service.

- **RQ1 pairs every incident CVE with every deployment**: each asset and what it declares, and each release
  a scan observed. A host is none only when it holds a current none of every product the incident affects
  (what the record names, the releases assessed affected, OSV's packages).
- **Act only on an accepted remediation**: approval is the authorization to act. `progress` `completed`
  closes nothing; only the verifying read does.
- **Accept a risk only with an expiry.** An exception holds an exposure off the patch list until
  `expires_at`; it never closes the incident.
- **An audit has three states.** None needs `not_exploited`, a window end, and complete reads of every
  source over the whole window; an incomplete read is a finding about the logs, not about the attacker.
  RQ4 reads each credential through its service's audit: no audit, no rotation answer yet.
- **Rotate, usually after the patch**: rotating first lets an attacker still on the host read the new key.
  Rotate at once when a key is known leaked or the patch can't land soon; the order is your call.
- **Close on the answer**, once the respond Line says ready to close, naming the residue: audits that stay
  unknown, and that their credentials were rotated.

## Report, in priority order

| Severity | Question or finding | Answer | Evidence | Next |
|---|---|---|---|---|

**Answer** is found, none or unknown, or the verdict and its role. **Evidence** names exact references
(`CLM-…`, a Subject, a proposal, an inbox item). **Next** is the fetch that answers an unknown, or who must
review. Say which judgments are yours and await review, and what you didn't read.
