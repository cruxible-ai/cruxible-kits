---
name: project-state
description: Plan work from accepted project state, record agreed scope and decisions with citations and based_on pins, and reconcile completed work in one coherent checkpoint.
---

# Project state loop

Use this skill when working in a repository that uses the `project-state` kit
(`dev.roadmap_item`, `dev.decision`, `dev.batch`, `dev.track`, `dev.law`,
`dev.card`, `dev.recommendation`, `dev.product_feedback`).

Accepted state is the authority for what was agreed and what is done. Chat
history, compacted summaries, and agent memory drift; treat accepted state as
authoritative and keep it ahead of the work.

## 1. Plan from state before touching code

Before planning, starting, resuming, or reporting status:

1. Run `cruxible orient` and `cruxible next` to inspect open drift, stale
   dependencies (`claim_dependency_stale`), drifted citations
   (`citation_drifted`), and open proposals.
2. Query the active tracks, decisions, and open roadmap items:

   ```bash
   cruxible query dev.track --select slug,status
   cruxible query dev.roadmap_item --where implementation_state!=completed --select slug,adoption_state,implementation_state,task_title --limit 30
   cruxible query dev.decision --where standing=ratified --select slug,ruling --limit 30
   ```

3. Answer "what is left", "did we finish X", and "are we done" from accepted
   state, naming the exact Subject slugs rather than guessing from memory.
4. If code or conversation disagrees with accepted state, stop and surface the
   discrepancy before proceeding.

## 2. Record agreements when they are made

- When the user agrees a new scope, roadmap item, decision, or acceptance
  criterion, record it in Cruxible before starting implementation.
- Never silently narrow, split, or drop an agreed item. Record any scope
  change explicitly after user confirmation.
- Pin downstream roadmap items or decisions to the upstream Claims they rest
  on using `based_on=[...]`, and cite workspace files or Markdown sections via
  `FileEvidence(file="PATH#EXACT_TEXT")` or `cx.section(...)`. That way an
  upstream change wakes only the dependent items in `cruxible next`.

## 3. Author through the typed Python SDK

Use `cruxible python` with the generated `.cruxible/world.pyi` stub so kind
names, fields, and enum values are checked before hitting the ledger:

```bash
cruxible python --check - <<'PY'
from typing import TYPE_CHECKING, cast
from cruxible_client import Cruxible

if TYPE_CHECKING:
    from world import World

with Cruxible.connect() as cx:
    w = cast("World", cx.world())
    res = w.write(
        w.dev.roadmap_item["example-slug"].edit(
            implementation_state="completed",
            reconciliation_note="Implemented and verified in commit abc1234.",
        ),
        because="Reconcile completed roadmap item after verification.",
        dry_run=True,
    )
    print(res)
PY
```

Run `--check` and `dry_run=True` first, inspect the changeset, then submit with
`dry_run=False`. Under `independent_approval_required`, never self-approve;
hand the open proposal ID to the reviewer principal.

## 4. Reconcile once per coherent milestone

- Batch one coherent checkpoint at the end of a meaningful implementation,
  merge, release, or scope ruling. Do not write after every tool call or create
  telemetry-only churn.
- Keep `implemented`, `merged`, `pushed`, `deployed`, and `released` distinct
  in your notes and status updates.
- Verify readback at the accepted generation coordinate before reporting work
  as done.
