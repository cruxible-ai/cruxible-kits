# Reporting a security finding

Guides: security.finding.reported_at, security.finding.rule, security.finding.reported_by,
security.finding.found_in, security.coverage_unit.status.
Adapted from cloudflare/security-audit-skill (MIT).
Calls recorded: agent findings cite a workspace-file receipt of the code at the location
(kit adds that evidence rule beside the SARIF one); per-finding notes live in
security/findings/<repo>/<finding-key>.md.

You are looking for vulnerabilities that cross a real trust boundary. Someone else will
judge what you report, and will try to refute it.

## Safety (non-negotiable)

- Read source freely. Run target code only in a sandbox that has no external network, an
  empty environment with only allowlisted safe values, a read-only target and toolchain,
  writes confined to a scratch directory, and low CPU, memory, process, disk and time limits.
  If you can't enforce all of these, don't run target code: record what's missing as the
  blocker.
- Don't install dependencies or let a build fetch them.
- Use dummy principals, fixtures and secrets only. Never probe deployed endpoints, shared
  services, production identities, real accounts or other users' data. Stop at the minimum
  local effect that shows the defect.

## What to report

A candidate is worth reporting only if you can name the lower-trust principal, the input
they control, the control that should stop them, the boundary it fails, and what is
affected. If you can't name them yet, keep hunting or record the coverage as blocked; don't
report a hunch.

## How to report

1. **Key it** so another run (or a scanner) lands on the same finding: `repo`
   (`host/owner/repo`), `weakness` (the most specific CWE, else `RULE:audit/<concern>`),
   `locus` (`path#symbol`; never a line number).
2. **Write what you saw:** `reported_at` (`path:line`), `reported_by` (`audit`), `rule` (the
   concern you were checking). Cite a file receipt of the code at that location.
3. **Write the trace** in `security/findings/<repo>/<finding-key>.md` under `## Trace`: entry
   point first, effect last, each step a source location. Cite that section.
4. **Link it:** `found_in` → the coverage unit you were working.
5. **Leave the verdict and severity alone.** They belong to whoever judges it.

## Coverage

Keep the coverage unit you worked honest: `checked` with the code receipt you examined,
`blocked` with the missing capability or fact, `deferred` if you ran out of budget. A
partial pass says it is partial.
