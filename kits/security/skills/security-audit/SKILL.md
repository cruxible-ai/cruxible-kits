---
name: security-audit
description: Orchestrate a Cruxible-governed security audit, finding verification, or dependency triage session using the instance's live governed guidance documents.
---

# Security audit

Use this skill to run agent-side security judgment over a Cruxible instance
with the `security` kit installed. All vocabulary, queries, evidence bars, and
triage standards live inside the instance as governed Documents; discover them
live rather than assuming them here.

## 1. Ground in live state and guidance

Before inspecting code or writing any Claim:

1. Run `cruxible orient`, `cruxible orient --section documents`, and
   `cruxible next` to inspect current kinds, queries, governed guidance
   Documents, open proposals, and stale or drifted items.
2. Confirm the instance's workspace holds the source files you intend to cite.
3. Read the live governed guidance Document(s) matching your role with
   `cruxible get Document:NAME --detail body`, and follow the queries, fields,
   citation rules, and anti-patterns stated there.

## 2. Enforce session separation

Reporter, verifier, and approver are three separate roles and must not share a
context window:

- **End-to-end audit (coordinator):** Start from the coverage guidance and
  backlog, dispatch one isolated Hunter session per unit (or batch), then
  dispatch a fresh Verifier session (ideally a different model or principal) to
  judge reported findings independently.
- **Single-role session:** Perform only the role requested. A Hunter stops
  before writing any verdict; a Verifier judges each finding independently
  before reading other verdicts.
- **Approval:** Under `independent_approval_required`, never self-approve.
  Hand open proposal IDs (`cruxible proposal list --status open`) to a separate
  reviewer principal.

## 3. Keep the record in Cruxible

- Check existing accepted Claims and `cruxible next` before re-deriving work.
- Keep local reproduction checks bounded and non-destructive.
- Write conclusions, traces, and notes into the instance rather than a
  standalone prose report unless asked.
