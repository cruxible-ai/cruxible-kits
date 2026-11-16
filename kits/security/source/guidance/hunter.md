# Reporting a security finding

Guides: security.finding.reported_at, security.finding.rule, security.finding.reported_by,
security.finding.found_in, security.coverage_unit.status, security.finding.rests_on,
security.coverage_unit.rests_on, security.code_fact.category, security.code_fact.holds.
Adapted from cloudflare/security-audit-skill (MIT).

A `security.finding` you report says: at this place in this repository's code, a
lower-trust principal can get past a control it should not get past. Another agent will
judge it and try to refute it. Your Claims are what you saw and where; the verdict is
not yours.

## Safety (non-negotiable)

- Read source freely. Run target code only in a sandbox with no external network, an
  empty environment holding only allowlisted safe values, a read-only target and
  toolchain, writes confined to a scratch directory, and low CPU, memory, process, disk
  and time limits. If you can't enforce all of these, don't run target code.
- Don't install dependencies or let a build fetch them.
- Use dummy principals, fixtures and secrets only. Never probe deployed endpoints, shared
  services, production identities, real accounts or other users' data. Stop at the
  smallest local effect that shows the defect.
- What you record becomes shared state. Record the command, the exact input, the limits
  and only the allowlisted environment names and safe values. Never record the ambient
  environment, credentials, tokens or unrelated host paths.

## The bar for reporting

Report a finding only when the source shows all five:

1. the lower-trust principal and what it can already do;
2. the input or action it controls;
3. the control that should stop it, read at its strongest (validation, identity,
   authorization, normalization, framework defaults);
4. the source path from that input past the control;
5. the principal or resource affected.

The observed result is for whoever judges it. If you ran a bounded local check, record
it. If one fact outside source decides the outcome (a proxy setting, an IAM policy, a
deployment flag), still report the finding and name that fact under `## Blocker`. If you
can't name the five from source, it is a hunch: keep reading or mark the unit blocked.

Not a finding: a missing best practice with no affected principal, defense in depth when
another layer already stops the attack, an effect on the actor's own data, a crash called
code execution, a guess about deployment. Write those as hardening notes on the coverage
unit (below). A known-vulnerable dependency is not a finding by itself: it belongs to the
dependency loop (SBOM, OSV, `security.exposure`) unless you show the path and the
boundary it crosses.

## How to report

1. **Key it** so another run or a scanner lands on the same Subject: `repo`
   (`host/owner/repo`), `weakness` (the most specific CWE, else `RULE:audit/<concern>`),
   `locus` (`path#symbol`; never a line number). One root cause is one finding, keyed where
   the fix goes, however many entry points reach it. Independent missing controls are
   separate findings.
2. **Look before you write.** If the key already holds a verdict, read it. Report a
   refuted finding again only when the code or your evidence changed, and say what
   changed. Don't hunt by imitating earlier confirmed findings.
3. **Write the trace** in `security/findings/<repo>/<finding-key>.md` (a file in the
   workspace catalog): `## Trace`, entry point first and effect last, each step a
   `path#symbol`; `## Local check` if you ran one (command, input, limits, result);
   `## Blocker` if one outside fact decides it (the fact, and a safe way for an owner to
   check it). Write it in its own write first (a docs-only write, or the file catalogued and
   committed). A section appended in the same write as the Claims counts as your own words,
   and an observation needs observed evidence, so that write is refused.
4. **Then write what you saw**, in a second write citing the notes file, each Claim with role
   `observation`:
   - `reported_at` (`path:line`), citing the code there (file evidence
     `path#<quoted line>`);
   - `rule` (the concern you checked, e.g. `audit:injection`), citing the notes file's
     `Trace` section (`{kind: section, file: <notes file>, section: [<title>, Trace]}`);
   - `reported_by` = `audit`, citing the code.

   Cite the narrowest passage that decides the judgment: a whole file reopens it on every
   edit, and no citation never reopens it. A quoted code line is a pointer for reviewers,
   not a witness: it reopens the finding only when those bytes change. Where a check
   decides what you claim (a scanner's findings imported through `security.sarif-import`,
   a local check's output file), cite its result.
5. **Link it:** `found_in` → the coverage unit you were working; `rests_on` → each
   codebase fact the finding rests on (below).
6. **Leave `verdict`, `severity` and `justification` alone.**

## Coverage

Keep the unit you worked honest (see the coverage guidance): `checked` cites the passage
you examined, `blocked` names what stopped you, `deferred` if you didn't get to it. A
partial pass says it is partial. A boundary you notice outside your unit is a new unit:
create it with its key and no status, so the next plan picks it up, instead of following
it now.

Hardening notes and safe patterns you confirmed go in the unit's notes section, which its
`status` cites; they are never findings.

## Codebase facts

A `security.code_fact` holds one thing true of a repository's code that security judgments
rest on: a `control` (something enforces it), an `invariant` (true by construction), a
`boundary` (where untrusted input enters or trust changes) or a `hazard` (a dangerous helper
or sink whose callers need checking). It is keyed by `repo` and `topic`, a short slug in your
words (`authn-middleware`, `tenant-id-source`) spelled the same every run. `security.code_facts`
lists a repository's facts and whether each holds: read them before re-deriving how the code
does something.

Record a fact when a judgment rests on something true beyond the passage you are judging,
and establishing it took real reading or more than one judgment will rest on it. Leave out
what one search answers. Facts are not a file map or an architecture document: expect tens
per repository. In one write: append a section to the repository's facts notes file (a
catalogued workspace file) stating the fact, where it holds and its known exceptions;
`create` the fact; `set` its `category` citing that section; `set` `holds` (`yes`, `partly` or
`no`) citing the code passage that decides it. A change carries one piece of evidence, so
the code backs `holds` and the notes back `category`. Link each judgment that rests on a fact
with `rests_on`.

When a fact's cited code changes, `next` lists its `holds` as `citation_drifted`. Core does
not act on `rests_on`: the judgments resting on that fact do not come back with it. Look
them up with `security.findings_resting_on`, `security.coverage_units_resting_on` and
`security.app_exposures_resting_on` (`--param fact=security.code_fact/<id>`), and after
setting `holds` to `partly` or `no`, with the repository's `*_on_weakened_facts` Queries
(each judgment once; `security.weakened_causes_of_*` says which facts). A
judgment that cites the fact's code passage itself also comes back on its own when that
passage changes.
