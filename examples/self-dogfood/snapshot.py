"""Append one daily metrics line for the persistent self-dogfood instance.

    python snapshot.py [--print]

One JSON object per run, appended to ``ROOT/metrics.jsonl``: when, the accepted
generation, counts (watched vulnerabilities, assessments by status and by role
of their status Claim, judged assessments, open proposals, unread inbox items,
``next`` rows), each kit Line's last run (status, elapsed seconds, started_at),
and the ``security.urgent_exposures`` top 5. Read-only against the instance.
Run it once a day (after the 15:30 UTC OSV run, say); it may become a Line later.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from persistent import KIT, ROOT, Instance

sys.path.insert(0, str(KIT / "gate"))
import recipe  # noqa: E402


def _cells(instance: Instance) -> list[dict[str, Any]]:
    out = instance.json("query", "security.assessment", "--select", "status,judgment",
                        "--claims", "--all")
    return list(out["rows"])


def snapshot(instance: Instance) -> dict[str, Any]:
    orient = instance.json("orient")
    watched = {row.get("cve_id") for row in instance.rows("security.watched_vulnerabilities")}
    by_status: Counter[str] = Counter()
    by_role: Counter[str] = Counter()
    judged = 0
    for row in _cells(instance):
        cells = (row.get("claims") or {}).get("status") or []
        if cells:
            by_status[str(cells[0].get("value"))] += 1
            by_role[str(cells[0].get("role"))] += 1
        else:
            by_status["none"] += 1
        judged += bool((row.get("claims") or {}).get("judgment"))
    unread = instance.json("inbox", "list", "--status", "unread", "--limit", "200")
    next_rows = instance.json("next")
    lines = {}
    for line in recipe.LINES:
        runs = instance.runs(line)
        if not runs:
            lines[line] = None
            continue
        card = instance.json("get", runs[0]["run"])["card"]
        lines[line] = {"status": runs[0]["status"], "started_at": runs[0].get("started_at"),
                       "elapsed_s": round((card.get("elapsed_us") or 0) / 1e6, 2)}
    urgent = [
        {k: row.get(k) for k in ("cve_id", "kev_listed", "kev_due_date", "epss_score",
                                  "product_name", "version", "judgment")}
        for row in instance.rows("security.urgent_exposures")[:5]
    ]
    attention = orient.get("attention") or {}
    return {
        "at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "generation": orient.get("generation"),
        "counts": {
            "watched": len(watched - {None}),
            "assessments_by_status": dict(sorted(by_status.items())),
            "assessment_status_by_role": dict(sorted(by_role.items())),
            "judged": judged,
            "open_proposals": attention.get("open_proposals"),
            "inbox_unread": len(unread.get("entries") or [])
            + (1 if unread.get("truncated") else 0),  # 201 means "more than 200"
            "next_rows": next_rows.get("total_items", len(next_rows.get("items") or [])),
        },
        "lines": lines,
        "urgent_top5": urgent,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--print", action="store_true", help="also print the line")
    args = parser.parse_args()
    record = snapshot(Instance(ROOT))
    line = json.dumps(record, sort_keys=True)
    with (ROOT / "metrics.jsonl").open("a") as metrics:
        metrics.write(line + "\n")
    if args.print:
        print(line)


if __name__ == "__main__":
    main()
