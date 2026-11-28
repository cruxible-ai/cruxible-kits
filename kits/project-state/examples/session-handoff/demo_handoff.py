"""60-second session-handoff demo for the project-state kit.

Demonstrates why governed typed state beats plain Markdown/CLAUDE.md across
multiple coding-agent sessions:

  1. `--seed` (Session 1): writes ARCHITECTURE.md, records a ratified decision
     citing that exact passage, and records two roadmap items:
       - `connection-pool-tuning`, pinned `based_on` the database decision
       - `dark-mode-toggle`, unrelated to the database decision
  2. `--edit-doc` (Between sessions): edits the cited line in ARCHITECTURE.md
     so `cruxible next` surfaces `citation_drifted` on the decision.
  3. `--supersede` (Session 2): updates the database decision to `superseded`
     citing the new line, so `cruxible next` surfaces `claim_dependency_stale`
     ONLY on `connection-pool-tuning`, leaving `dark-mode-toggle` untouched.

Run inside an initialized repository with `project-state` installed:
    cruxible python demo_handoff.py --seed
    cruxible python demo_handoff.py --edit-doc
    cruxible next
    cruxible python demo_handoff.py --supersede
    cruxible next
"""

from __future__ import annotations

import argparse
from pathlib import Path
from cruxible_client import Cruxible, SectionEvidence

ARCH_FILE = Path("ARCHITECTURE.md")

ARCH_V1 = """# Architecture

## Database

We chose PostgreSQL 16 over SQLite for the API service so multiple workers
can write concurrently with ACID transactions and native JSONB indexes.
"""

ARCH_V2 = """# Architecture

## Database

We migrated the API service to SQLite with Litestream to cut infrastructure cost.
"""

DB_SECTION = SectionEvidence(file="ARCHITECTURE.md", section=("Architecture", "Database"))


def seed() -> None:
    ARCH_FILE.write_text(ARCH_V1, encoding="utf-8")

    with Cruxible.connect() as cx:
        w = cx.world()
        track = w.dev.track.define(slug="core-v1").set(status="open")
        decision = w.dev.decision.define(slug="primary-database").set(
            standing="ratified",
            ruling="PostgreSQL 16 (concurrent multi-worker writes, JSONB)",
            evidence=DB_SECTION,
        )
        # Same-write `based_on` pins: if the database decision moves later,
        # `connection-pool-tuning` automatically reopens in `cruxible next`.
        pool_item = w.dev.roadmap_item.define(slug="connection-pool-tuning").set(
            task_title="Tune Postgres connection pool size and idle timeout",
            adoption_state="adopted",
            implementation_state="partial",
            completion_criterion="p99 query latency under 20ms at 500 concurrent connections.",
            based_on=[decision.pin("standing"), decision.pin("ruling")],
        )
        # Unrelated work item: stays silent when the database decision changes.
        ui_item = w.dev.roadmap_item.define(slug="dark-mode-toggle").set(
            task_title="Add dark mode toggle in user settings",
            adoption_state="adopted",
            implementation_state="not_started",
            completion_criterion="Setting persists across reloads.",
        )
        res = w.write(
            track,
            decision,
            pool_item,
            ui_item,
            because="Session 1: record primary database decision and two initial roadmap items.",
        )
        print(f"Seeded generation {res.coordinate.generation}: decision + 2 roadmap items.")


def edit_doc() -> None:
    ARCH_FILE.write_text(ARCH_V2, encoding="utf-8")
    print("Updated ARCHITECTURE.md#Database to SQLite with Litestream.")


def supersede() -> None:
    if not ARCH_FILE.exists() or "SQLite" not in ARCH_FILE.read_text(encoding="utf-8"):
        ARCH_FILE.write_text(ARCH_V2, encoding="utf-8")

    with Cruxible.connect() as cx:
        w = cx.world()
        res = w.dev.decision["primary-database"].set(
            standing="superseded",
            ruling="Migrated from PostgreSQL 16 to SQLite with Litestream.",
            evidence=DB_SECTION,
            because="Session 2: supersede PostgreSQL 16 decision after storage migration.",
        )
        print(
            f"Updated decision at generation {res.coordinate.generation}. "
            "Run `cruxible next` to see affected items."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Project-state 60-second session handoff demo.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--seed", action="store_true", help="Session 1: seed decision and two roadmap items")
    group.add_argument("--edit-doc", action="store_true", help="Edit the cited line in ARCHITECTURE.md")
    group.add_argument("--supersede", action="store_true", help="Session 2: supersede the database decision")
    args = parser.parse_args()

    if args.seed:
        seed()
    elif args.edit_doc:
        edit_doc()
    elif args.supersede:
        supersede()


if __name__ == "__main__":
    main()
