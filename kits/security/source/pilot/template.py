"""The security kit's automation template (D-R48): ``automation.json`` at the kit root.

One change set the adopter tailors and submits as their own reviewed change: the
dependency loop's Lines (one SBOM import, OSV, KEV and EPSS) and their Mandates,
the attention Lines, two Runbooks, one daily Trigger, and the Trigger that runs
the OSV unkeyed Line.

``security.start`` seeds a fresh instance in the order the Lines' reads and
writes imply:

1. ``security.sbom-import.app``: writes each occurrence's ``scope`` (and creates
   the inventory and its components); it reads no state;
2. ``security.osv-query``: reads the inventoried components (the occurrences
   holding a scope) and writes ``component.affected_by``;
3. ``security.kev-triage``: reads ``security.watched_vulnerabilities`` (the
   affected_by join over the occurrences) and writes the KEV fields;
4. ``security.epss-triage``: reads the same watch list and writes the EPSS fields;
5. ``security.exposure-attention.unjudged`` and ``.contested``: read the worklist
   (the judgments, which agents write and no Line does) and post one Line inbox
   item per pair nobody has judged whose vulnerability is KEV-listed, has an
   EPSS score at or above the unjudged Line's ``min_epss`` (``0.1`` as shipped)
   or has no EPSS score yet,
   and one per pair whose judgment does not count (no threshold). The whole
   worklist stays in ``security.urgent_exposures``.

``security.osv-unkeyed`` is no step: it binds its triggering Capture, which a
Runbook step cannot supply. Its own Trigger, ``security.osv-matches-landed``,
runs it on each landing of step 2's derived match document, so it posts one
inbox item per advisory with no CVE alias (no Claim can key one) right after
the OSV step, under its own enablement.

``security.maintain`` is the daily refresh: steps 2-5 without the SBOM import
(the SBOM changes when the repository changes, not on a clock). The one Trigger,
``security.maintain-daily``, fires it at 14:00 UTC; each step runs under its
Line's own enablement, so a Line nobody enabled stops the run. Each Line fetches
its own source; the one landing Trigger is the unkeyed Line's, which fetches
nothing. Nothing here is installed by ``kit add``.

    python template.py           # rewrite ../../automation.json
    python template.py --check   # fail when it is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import definitions as kit  # noqa: E402
import inventory  # noqa: E402
import osv  # noqa: E402
import triage  # noqa: E402

KIT = HERE.parents[1]
TEMPLATE = KIT / "automation.json"
START = "security.start"
MAINTAIN = "security.maintain"
MAINTAIN_TRIGGER = "security.maintain-daily"
#: 14:00 UTC daily. KEV has no fixed publication time (CISA adds entries as it
#: confirms them), so no hour catches every same-day addition: a daily read is at
#: most a day behind whatever hour runs it.
MAINTAIN_CRON = "0 14 * * *"
#: The example SBOM import: Line suffix and workspace path (tailor both).
SBOM = ("app", "sbom.cdx.json")
#: Mandates start the day before this and expire 90 days after (tailor both).
DATED = datetime(2026, 11, 7, tzinfo=UTC)
#: The seeding order (see the module docstring).
START_LINES = (
    inventory.sbom_line_name(SBOM[0]),
    osv.OSV_LINE,
    kit.KEV_LINE,
    kit.EPSS_LINE,
    *(triage.ATTENTION[state] for state in triage.ATTENTION_STATES),
)
#: The daily refresh: the seeding order without the SBOM import.
MAINTAIN_LINES = START_LINES[1:]
#: Both Runbooks: where OSV's advisories with no CVE id go (no step of either).
UNKEYED_NOTE = (
    f"OSV advisories with no CVE id are posted to the inbox by {osv.UNKEYED_LINE}, which "
    f"its Trigger {osv.UNKEYED_TRIGGER} runs on each OSV result once the Line is enabled."
)


def template() -> dict[str, Any]:
    value = kit.automation((), now=DATED, sboms=(SBOM,))
    members = list(value["members"])
    members += [
        {
            "kind": "runbook",
            "name": START,
            "description": (
                "Seed a fresh instance: import the SBOM, ask OSV what affects it, read KEV "
                "and EPSS for what it found, then post to the inbox the pairs nobody has "
                "judged that are KEV-listed, have an EPSS score at or above the attention "
                "Line's min_epss or have no EPSS score yet, and the pairs whose judgment "
                "does not count. The whole worklist stays in security.urgent_exposures. "
                + UNKEYED_NOTE
            ),
            "steps": [{"line": line} for line in START_LINES],
        },
        {
            "kind": "runbook",
            "name": MAINTAIN,
            "description": (
                "Daily refresh: ask OSV what affects the inventory, read KEV and EPSS for "
                "what it found, then post to the inbox the pairs nobody has judged that are "
                "KEV-listed, have an EPSS score at or above the attention Line's min_epss or "
                "have no EPSS score yet, and the pairs whose judgment does not count. The "
                "whole worklist stays in security.urgent_exposures. " + UNKEYED_NOTE
            ),
            "steps": [{"line": line} for line in MAINTAIN_LINES],
        },
        # After the Runbook it names: a Runbook Trigger needs its Runbook live.
        {
            "kind": "trigger",
            "name": MAINTAIN_TRIGGER,
            "runbook_name": MAINTAIN,
            "schedule": {"kind": "cron", "expression": MAINTAIN_CRON},
        },
    ]
    return {
        "kind": "change_set",
        "rationale": (
            "Adopt the security kit's dependency loop: the SBOM import, OSV, KEV and EPSS "
            "Lines and their Mandates, and the two observe-only attention Lines that post "
            "exposures to the inbox (unjudged pairs KEV-listed, with an EPSS score at or "
            "above min_epss, 0.1 as shipped, or not yet scored; contested pairs); the "
            "observe-only OSV unkeyed Line and its Trigger security.osv-matches-landed, "
            "which post each OSV advisory with no CVE alias to the inbox whenever the OSV "
            "Line's match document lands; the "
            "security.start Runbook that seeds a fresh instance; and the security.maintain "
            "Runbook that the one daily Trigger security.maintain-daily runs (OSV, KEV, "
            "EPSS, attention; the SBOM import runs when the SBOM changes). Tailor the Line "
            "names, the SBOM path, the cron time, the attention threshold and the Mandate "
            "dates before submitting."
        ),
        "members": members,
    }


def render() -> str:
    return json.dumps(template(), indent=1) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.check:
        if not TEMPLATE.is_file() or TEMPLATE.read_text() != content:
            print(f"{TEMPLATE} is out of date: run source/pilot/template.py", file=sys.stderr)
            return 1
        return 0
    TEMPLATE.write_text(content)
    print(f"wrote {TEMPLATE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
