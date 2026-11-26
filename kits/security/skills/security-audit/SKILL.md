---
name: security-audit
description: Orchestrate a Cruxible-governed security audit, finding verification, or dependency triage session using the instance's live governed guidance documents.
---

# Security audit

Use this skill to run agent-side security judgment over a Cruxible instance
with the `security` kit installed. All vocabulary, queries, evidence bars, and
triage standards live inside the instance as governed Documents; discover them
live rather than assuming them here.

## 1. Pick the authoring surface

1. **Typed Python SDK** whenever you can run Python. `cruxible python` runs a
   script with the CLI's own interpreter and connection, in any repository,
   whatever that repository's own Python or venv. `.cruxible/world.pyi` types
   the instance's kinds, fields and enum members, so names come from the
   instance and a misspelling fails before the wire:

   ```bash
   cruxible python - <<'PY'
   from typing import TYPE_CHECKING, cast
   from cruxible_client import Cruxible
   if TYPE_CHECKING:
       from world import World
   with Cruxible.connect() as cx:
       w = cast("World", cx.world())
       print(w.describe())
   PY
   ```

   `cruxible python --check SCRIPT` type-checks a script against the live
   vocabulary before it writes. The typed path is
   `w.<kind>.define(...).set(...).write(because=...)` for new Subjects (and
   `w.<kind>["<id>"].set(..., because=...)` for existing ones); carry a notes
   section as evidence with `cx.section(...)`. Pass `based_on=` directly on
   `.set(...)` or `.add(...)` (on typed World drafts, edits, and Subjects, or on
   `cx.set(...)` and `cx.changes(because=...)` batches).
2. **MCP** when you have no code execution: the same verbs as tools.
3. **CLI** for quick inspection and as a backup: `cruxible orient`,
   `cruxible next`, `cruxible write --example`, `cruxible proposal ...`.

## 2. Ground in live state and guidance

Before inspecting code or writing any Claim:

1. Run `cruxible orient`, `cruxible orient --section documents`, and
   `cruxible next` to inspect current kinds, queries, governed guidance
   Documents, open proposals, and stale or drifted items.
2. Confirm the instance's workspace holds the source files you intend to cite.
3. Read the live governed guidance Document(s) matching your role with
   `cruxible get Document:NAME --detail body`, and follow the queries, fields,
   citation rules, roles, and anti-patterns stated there.

## 3. Enforce session separation

Reporter, verifier, and approver are three separate roles and must not share a
context window:

- **End-to-end audit (coordinator):** Start from the coverage guidance and
  backlog, dispatch one isolated Hunter session per unit (or batch), then
  dispatch a fresh Verifier session (ideally a different model or principal) to
  judge reported findings independently.
- **Parallel hunters:** before dispatch, partition the coverage units so each
  belongs to exactly one hunter (no two hunters create or revise the same unit
  at once), and give each hunter its own notes and facts files named for that
  hunter instead of one shared file. Units a hunter finds outside its partition
  come back to the coordinator to record.
- **Single-role session:** Perform only the role requested. A Hunter stops
  before writing any verdict; a Verifier judges each finding independently
  before reading other verdicts.
- **Approval:** Under `independent_approval_required`, never self-approve.
  Hand open proposal IDs (`cruxible proposal list --status open`) to a separate
  reviewer principal.

## 4. Coverage critic check

Before the coordinator closes an audit pass, compare the covered units against
the target's starting files and entry points (routes, handlers, CLI commands,
message consumers, jobs). Each one in scope is either checked or recorded as an
open coverage unit for the next pass, never silently skipped. Confirm every
symbol a unit names exists in the file it names before recording it.

## 5. Keep the record in Cruxible

- Check existing accepted Claims and `cruxible next` before re-deriving work.
- Keep local reproduction checks bounded and non-destructive.
- Write conclusions, traces, and notes into the instance rather than a
  standalone prose report unless asked.
