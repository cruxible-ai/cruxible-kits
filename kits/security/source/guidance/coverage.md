# Keeping audit coverage

Guides: security.coverage_unit.status, security.coverage_unit.rests_on.
Adapted from cloudflare/security-audit-skill (MIT).

Coverage says what was checked, against which code, and with what result, so "nothing
found" is never read as "it's fine". The units are the coverage: a summary sentence, an
agent count or "auth reviewed" is not.

## A unit

`security.coverage_unit` is keyed by `repo`, `surface` and `concern`.
- `surface`: a canonical code reference for an entry point or boundary (`path#symbol`, or
  a route such as `src/router.ts#POST /users/:id`). Spell it the same every run, so units
  match across audits.
- `concern`: what you checked it for, in your own words or from the reference attack
  classes (`access-control`, `injection`, `ssrf`, a named state machine). One unit per
  real combination; choose the grain the target deserves. If a concern can't apply to a
  surface, don't create the unit.

## Status

| Status | Means | Cite |
|---|---|---|
| `checked` | examined, whatever the outcome | the exact passage you read (file evidence `path#<quoted passage>`, the function or handler, not the whole file) and a notes section: what you checked, hardening notes, safe patterns confirmed |
| `blocked` | partly examined, then stopped | what you read, and the blocker: a missing sandbox capability or a fact outside source |
| `deferred` | not reached this pass | the reason (ran out of time or budget) |
| `out_of_scope` | deliberately excluded | the reason |

A unit with findings is `checked` and its findings link to it with `found_in`. Cite the
passage, not the file: drift is detected on the cited bytes, so a change elsewhere in the
file doesn't reopen the unit. Re-checking a unit revises its status; the earlier one stays
in history. A status that rests on a codebase fact (the middleware every route passes
through) links it with `rests_on` and pins its `holds` on the status change (`"based_on":
["security.code_fact/<id>#holds"]` in the write file, or `--based-on
security.code_fact/<id>#holds` on `cruxible set`). When that fact's `holds` changes
(`partly` or `no`), `next` lists the unit's status as `claim_dependency_stale`: check it
again. For a unit linked without a pin, `security.coverage_units_resting_on` lists the units
to check again. A `checked` status that relied on a deployment fact (an admin surface
reachable only internally) pins it too: `it.asset/<slug>#exposure`.

## Breadth and partial passes

A quick or scoped pass covers less; it never lowers the bar for a finding or a verdict.
A scoped pass marks the surfaces it saw but excluded `out_of_scope`, never `checked`, and
says it is partial. One pass never exhausts a target.

Before calling a pass complete, look for what it missed: entry points with no unit,
parallel paths to the same effect (batch, import, legacy, admin, retry, error paths),
lifecycle modes (setup, migration, deletion, restore), exclusions without a reason, and
units marked `checked` without a cited passage. Add the missing ones as units with no
status.

## Planning the next audit

Start from state, not from scratch:
- units never checked, `deferred` or `blocked`: the `security.coverage_plan` query;
- units whose pinned facts changed: `cruxible next` lists their status as
  `claim_dependency_stale`, naming the fact;
- units whose code changed: workspace-aware `cruxible next` lists `citation_drifted` rows,
  each naming the citing Claim (a unit's `status`, or a finding's `reported_at`). That is
  passage drift. It is separate from a status whose evidence has aged past its freshness
  window, which reads stale on its own;
- findings blocked on an outside fact: their `unsure` attestations, and whether the fact
  has since arrived.

A unit checked against unchanged code may set priority, but isn't proof the next pass can
skip it.
