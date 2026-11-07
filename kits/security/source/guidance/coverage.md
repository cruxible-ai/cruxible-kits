# Keeping audit coverage

Guides: security.coverage_unit.status.
Adapted from cloudflare/security-audit-skill (MIT).

Coverage says what was checked, against which code, and with what result, so "nothing
found" is never read as "it's fine".

## A unit

`security.coverage_unit` is keyed by `repo`, `surface` and `concern`.
- `surface`: a canonical code reference for an entry point or boundary (`path#symbol`, or a
  route such as `src/router.ts#POST /users/:id`). Use the same spelling every run, so units
  match across audits.
- `concern`: what you checked it for, in your own words or from the reference attack classes
  (`access-control`, `injection`, `ssrf`, a named state machine). One unit per real
  combination; choose the grain the target deserves.

## Status

- `checked`: cite the exact passage you examined (the function or handler, as file evidence
  `path#anchor`), plus your notes. Cite the passage, not the whole file: drift is detected on
  the cited bytes, so a change elsewhere in the file doesn't reopen the unit.
- `blocked`: name what stopped you (a missing sandbox capability, a fact outside source).
- `deferred`: not reached this run.
- `out_of_scope`: deliberately excluded, with the reason.

## Planning the next audit

Start from state, not from scratch:
- units never checked, `deferred` or `blocked`: query them;
- units whose code changed: run workspace-aware `cruxible next` and take its
  `citation_drifted` rows; each names the citing Claim, which is a unit's `status`. That is
  passage drift. It is separate from a status whose evidence has aged past its freshness
  window, which reads stale on its own. One pass never exhausts a target: say how much of
it this run covered.
