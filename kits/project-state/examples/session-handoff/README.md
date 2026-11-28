# Session handoff demo (project-state 2.0.0)

This 60-second demo shows what governed project state does across coding-agent
sessions that plain Markdown notes (`CLAUDE.md`, `TODO.md`, or chat memory)
cannot:

1. **Session 1 (`--seed`):** Writes `ARCHITECTURE.md`, records a ratified
   `dev.decision/primary-database` citing that exact line, and records two
   roadmap items:
   - `dev.roadmap_item/connection-pool-tuning`, pinned `based_on` the database
     decision's `standing` and `ruling`.
   - `dev.roadmap_item/dark-mode-toggle`, unrelated to the database decision.
2. **Doc edit (`--edit-doc`):** Changes the cited line in `ARCHITECTURE.md`.
   `cruxible next` immediately surfaces `citation_drifted` on the decision so
   no agent trusts a stale summary.
3. **Session 2 (`--supersede`):** Updates `dev.decision/primary-database` to
   `superseded` citing the new line. `cruxible next` immediately wakes
   `claim_dependency_stale` **only** on `connection-pool-tuning`, while
   `dark-mode-toggle` stays quiet and untouched.

## Run it

```bash
mkdir project-state-demo && cd project-state-demo
git init -q -b main
cruxible init --principal-id owner
cruxible kit add project-state --commit

# Download this script (or copy it from a local cruxible-kits checkout)
curl -fsSLO https://raw.githubusercontent.com/cruxible-ai/cruxible-kits/main/kits/project-state/examples/session-handoff/demo_handoff.py

# 1. Session 1: seed decision + 2 roadmap items (one pinned based_on the decision)
cruxible python demo_handoff.py --seed
cruxible query dev.roadmap_item --select slug,implementation_state,task_title
cruxible next

# 2. Edit the cited line in ARCHITECTURE.md -> citation_drifted wakes up
cruxible python demo_handoff.py --edit-doc
cruxible next

# 3. Session 2: supersede the decision -> ONLY connection-pool-tuning wakes up
cruxible python demo_handoff.py --supersede
cruxible next
```
