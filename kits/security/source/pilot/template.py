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
runs it on each landing of step 2's derived match document, so when OSV lists
advisories with no CVE alias (no Claim can key one) it posts one summary inbox
item pointing at that document right after the OSV step, under its own
enablement.

``security.maintain`` is the daily refresh: steps 2-5 without the SBOM import
(the SBOM changes when the repository changes, not on a clock). The one Trigger,
``security.maintain-daily``, fires it at 14:00 UTC; each step runs under its
Line's own enablement, so a Line nobody enabled stops the run. Each Line fetches
its own source; the one landing Trigger is the unkeyed Line's, which fetches
nothing. Nothing here is installed by ``kit add``.

Built for Cruxible 0.6: every Mandate is valid for ``expires: 90d`` from the moment
the change set is submitted (no ``valid_from``, no dates to edit), and the KEV and
EPSS Lines and the SBOM import each take ONE ``scope: observations`` settle grant,
which core lowers to the exact per-ClaimType scope their Procedures write (the
SBOM's ``scope`` and ``osv_package``; its ``subject_creation`` names the
occurrence and its nested inventory and component ends). The OSV Line keeps an
explicit one-ClaimType scope: ``affected_by`` also carries agents' package-level
judgments (it permits ``normative``), which an observation grant refuses. Every Line either Runbook names, plus the unkeyed Line, is enabled with
one command: ``cruxible line enable security.osv-unkeyed --runbook security.start``.

The SARIF intake is a second, smaller change set beside the example it reads,
``examples/sarif/automation-sarif.json`` (``sarif_template``): the import Line
for one scanner's SARIF file, its Mandates (``expires: 90d``) and the attention
Line with its landing Trigger. It lives under ``examples/`` so it travels in the
kit bundle (``kit pull``) with ``examples/sarif/semgrep-demo.sarif``.

**Recipes (Cruxible 0.6, ``kit adopt``).** The same members, split so an adopter
names values instead of editing JSON. Each is a change set under ``recipes/`` with
``{{param}}`` placeholders, declared in ``source/recipes.json`` (written here too):

- ``default`` (``kit adopt security``): KEV, EPSS, OSV, the unkeyed Line and its
  Trigger, both attention Lines, and the two Runbooks. ``security.start`` runs the
  SBOM imports as one fan-out step, ``{"procedure": "security.sbom-import"}``: every
  live Line of that Procedure, in Line-name order, so a second SBOM joins the
  Runbook with no edit (and with none yet the step is skipped).
- ``sbom`` (``kit adopt security:sbom --param name=app --param relative_path=sbom.cdx.json``):
  one SBOM import Line and its Mandates; adopt it again under another ``name`` for
  each further SBOM.
- ``sarif`` (``kit adopt security:sarif --param name=semgrep --param relative_path=...
  --param repo=host/owner/repo``): one scanner's SARIF intake (the members of
  ``examples/sarif/automation-sarif.json``).
- ``schedule`` (``kit adopt security:schedule``): the daily Trigger aimed at
  ``security.maintain``, apart so a CI-driven adopter takes no local cron.

``automation.json`` stays the one-file template (D-R48) for adopters on the
authoring path.

    python template.py           # rewrite automation.json, the SARIF template and the recipes
    python template.py --check   # fail when any is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import definitions as kit  # noqa: E402
import findings  # noqa: E402
import inventory  # noqa: E402
import osv  # noqa: E402
import triage  # noqa: E402

KIT = HERE.parents[1]
TEMPLATE = KIT / "automation.json"
SARIF_TEMPLATE = KIT / "examples" / "sarif" / "automation-sarif.json"
#: The example scan: Line suffix, repository (host/owner/repo) and workspace path of
#: the SARIF file (tailor all three; the example file is examples/sarif/semgrep-demo.sarif).
SARIF_SCAN = ("semgrep", "github.com/example/demo-app", "scans/semgrep.sarif")
START = "security.start"
MAINTAIN = "security.maintain"
MAINTAIN_TRIGGER = "security.maintain-daily"
#: 14:00 UTC daily. KEV has no fixed publication time (CISA adds entries as it
#: confirms them), so no hour catches every same-day addition: a daily read is at
#: most a day behind whatever hour runs it.
MAINTAIN_CRON = "0 14 * * *"
#: The example SBOM import: Line suffix and workspace path (tailor both).
SBOM = ("app", "sbom.cdx.json")
#: The Line no Runbook step can name (it binds its triggering Capture): the one
#: command that enables every Line names it beside the start Runbook.
ENABLE_ALL = f"cruxible line enable {osv.UNKEYED_LINE} --runbook {START}"
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
    f"OSV advisories with no CVE id get one summary inbox item from {osv.UNKEYED_LINE}, "
    f"which its Trigger {osv.UNKEYED_TRIGGER} runs on each OSV result once the Line is "
    f"enabled. Enable every Line at once: {ENABLE_ALL}."
)


def template() -> dict[str, Any]:
    value = kit.automation((), sboms=(SBOM,))
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
            "which posts one summary item (count, sample, the match document) when the OSV "
            "Line's match document lists advisories with no CVE alias; the "
            "security.start Runbook that seeds a fresh instance; and the security.maintain "
            "Runbook that the one daily Trigger security.maintain-daily runs (OSV, KEV, "
            "EPSS, attention; the SBOM import runs when the SBOM changes). The SBOM, KEV and "
            "EPSS Lines each take one scope: observations settle grant; OSV's names "
            "affected_by by hand (that field also carries agents' judgments). Every "
            "Mandate is valid for 90 days from submission. Tailor the Line names, the SBOM "
            "path, the cron time and the attention threshold before submitting."
        ),
        "members": members,
    }


def sarif_template() -> dict[str, Any]:
    value = findings.automation([SARIF_SCAN])
    return {
        "kind": "change_set",
        "rationale": (
            "Adopt the security kit's SARIF intake for one scanner: the import Line, which "
            "reads the SARIF file under its own logical source and writes code findings by "
            "key (settling the scanner's observations: rule, reported_by, severity, "
            "reported_at, verification; never a verdict), its Mandates, valid for 90 days "
            "from submission, and the observe-only attention Line its landing Trigger runs, "
            "which posts regressions and location gaps to the inbox. The import's settle "
            "grant names its ClaimTypes by hand: severity also permits normative (the "
            "verifier's own severity), so scope: observations refuses it. Tailor the Line "
            "suffix, the repository and the SARIF path before submitting."
        ),
        "members": value["members"],
    }


#: Where the recipes and their declarations live.
RECIPES = KIT / "recipes"
RECIPE_SPECS = HERE.parent / "recipes.json"
#: The recipe parameters every recipe with Mandates takes.
EXPIRES = "{{expires}}"
_EXPIRES_SPEC = {
    "type": "string",
    "default": kit.MANDATE_SPAN,
    "pattern": "^[1-9][0-9]{0,4}[hdwy]$",
    "description": "How long each Mandate stays valid from submission: hours, days, weeks "
    "or years (36h, 90d, 12w, 1y).",
}
#: A recipe's ``name`` is the Line suffix: short, lowercase, unique per kind of input.
_NAME_PATTERN = "^[a-z][a-z0-9_-]{0,48}$"
#: A recipe's ``relative_path``: a normalized workspace-relative POSIX path, as
#: ``workspace.file`` reads it. Segments of letters, digits, ``_``, ``.`` and ``-``
#: joined by ``/``; a segment may start with ``.`` (``.github/sbom.json``) but is
#: never ``.`` or ``..``, so no leading ``/``, no ``..``, no backslash, no whitespace
#: and no empty segment. Unbounded repeats keep the NFA small (core matches recipe
#: patterns in linear time); the import Procedures' params cap the length at 256.
_SEGMENT = r"(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\.[A-Za-z0-9_-][A-Za-z0-9._-]*)"
_PATH_PATTERN = f"^{_SEGMENT}(?:/{_SEGMENT})*$"


def _with_expires(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each Mandate's span as the ``expires`` parameter."""

    out = []
    for member in members:
        if member.get("kind") == "procedure_mandate" and member.get("expires") == kit.MANDATE_SPAN:
            member = {**member, "expires": EXPIRES}
        out.append(member)
    return out


def default_recipe() -> dict[str, Any]:
    members = _with_expires(kit.automation((), sboms=())["members"])
    unjudged = triage.ATTENTION["unjudged"]
    for member in members:
        if member.get("kind") == "line" and member.get("name") == unjudged:
            member["parameters"] = {**member["parameters"], "min_epss": "{{min_epss}}"}
    start_steps = [{"procedure": inventory.SBOM_PROCEDURE}] + [
        {"line": line} for line in MAINTAIN_LINES
    ]
    members += [
        {
            "kind": "runbook",
            "name": START,
            "description": (
                f"Seed a fresh instance: import every SBOM (each live Line of "
                f"{inventory.SBOM_PROCEDURE}, in Line-name order; add one with cruxible kit "
                "adopt security:sbom), ask OSV what affects them, read KEV and EPSS for what "
                "it found, then post to the inbox the pairs nobody has judged that are "
                "KEV-listed, have an EPSS score at or above the attention Line's min_epss or "
                "have no EPSS score yet, and the pairs whose judgment does not count. The "
                "whole worklist stays in security.urgent_exposures. " + UNKEYED_NOTE
            ),
            "steps": start_steps,
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
    ]
    return {
        "kind": "change_set",
        "rationale": (
            "kit adopt security: the dependency loop's shared Lines (OSV, KEV, EPSS) and "
            "their Mandates (valid for {{expires}} from submission), the two observe-only "
            "attention Lines (unjudged pairs KEV-listed, with an EPSS score at or above "
            "{{min_epss}}, or not yet scored; contested pairs), the OSV unkeyed Line and its "
            "Trigger security.osv-matches-landed, the security.start Runbook (every SBOM "
            "import Line, then OSV, KEV, EPSS and attention) and the security.maintain "
            "Runbook. SBOM imports come from kit adopt security:sbom; the daily Trigger "
            "from kit adopt security:schedule."
        ),
        "members": members,
    }


def sbom_recipe() -> dict[str, Any]:
    return {
        "kind": "change_set",
        "rationale": (
            "kit adopt security:sbom: the SBOM import Line security.sbom-import.{{name}}, "
            "reading {{relative_path}} (CycloneDX or SPDX 2.2/2.3 JSON) under the logical source "
            "cyclonedx.sbom.{{name}}, and its propose and scope: observations settle "
            "Mandates, valid for {{expires}} from submission. security.start runs it with "
            "every other SBOM import Line."
        ),
        "members": _with_expires(inventory.sbom_automation((("{{name}}", "{{relative_path}}"),))),
    }


def sarif_recipe() -> dict[str, Any]:
    return {
        "kind": "change_set",
        "rationale": (
            "kit adopt security:sarif: the SARIF import Line security.sarif-import.{{name}}, "
            "reading {{relative_path}} for the repository {{repo}} under the logical source "
            "sarif.{{name}}, its Mandates (valid for {{expires}} from submission; the "
            "settle grant names the scanner's observation ClaimTypes, never a verdict), and "
            "the observe-only attention Line security.sarif-attention.{{name}} with the "
            "landing Trigger that runs it."
        ),
        "members": _with_expires(
            findings.automation([("{{name}}", "{{repo}}", "{{relative_path}}")])["members"]
        ),
    }


def schedule_recipe() -> dict[str, Any]:
    return {
        "kind": "change_set",
        "rationale": (
            "kit adopt security:schedule: the Trigger security.maintain-daily, which runs "
            "the security.maintain Runbook at the cron time {{cron}} (UTC)."
        ),
        "members": [
            {
                "kind": "trigger",
                "name": MAINTAIN_TRIGGER,
                "runbook_name": MAINTAIN,
                "schedule": {"kind": "cron", "expression": "{{cron}}"},
            }
        ],
    }


def recipe_specs() -> list[dict[str, Any]]:
    """The manifest's ``recipes`` declarations (``kit build --recipes``)."""

    name = {
        "type": "string",
        "required": True,
        "pattern": _NAME_PATTERN,
        "description": "Short identifier for this input: the Line suffix and logical "
        "source suffix; unique per input of this kind.",
    }
    return [
        {
            "name": "default",
            "path": "recipes/default.json",
            "description": (
                "The dependency loop's shared backbone: OSV, KEV and EPSS Lines and Mandates, "
                "the attention and OSV unkeyed Lines, and the security.start (fans out to "
                "every SBOM import Line) and security.maintain Runbooks."
            ),
            "params": {
                "expires": _EXPIRES_SPEC,
                "min_epss": {
                    "type": "string",
                    "default": "0.1",
                    "pattern": "^(0(\\.[0-9]{1,6})?|1(\\.0{1,6})?)$",
                    "description": "EPSS score (0 to 1) at or above which an unjudged pair "
                    "goes to the inbox (KEV-listed and unscored pairs always do).",
                },
            },
        },
        {
            "name": "sarif",
            "path": "recipes/sarif.json",
            "description": (
                "One scanner's SARIF intake: the import Line, its Mandates, and the attention "
                "Line with its landing Trigger. Adopt again under another name per scanner."
            ),
            "params": {
                "expires": _EXPIRES_SPEC,
                "name": {**name, "example": SARIF_SCAN[0]},
                "relative_path": {
                    "type": "string",
                    "required": True,
                    "pattern": _PATH_PATTERN,
                    "example": SARIF_SCAN[2],
                    "description": "Workspace-relative path of the scanner's SARIF 2.1.0 file.",
                },
                "repo": {
                    "type": "string",
                    "required": True,
                    "pattern": findings._REPO_PATTERN,
                    "example": SARIF_SCAN[1],
                    "description": "The scanned repository as host/owner/repo, lowercase; a "
                    "SARIF run naming another repository writes nothing.",
                },
            },
        },
        {
            "name": "sbom",
            "path": "recipes/sbom.json",
            "description": (
                "One SBOM import Line (CycloneDX or SPDX 2.2/2.3 JSON) and its Mandates. "
                "Adopt again under another name per SBOM; security.start runs them all."
            ),
            "params": {
                "expires": _EXPIRES_SPEC,
                "name": {**name, "example": SBOM[0]},
                "relative_path": {
                    "type": "string",
                    "required": True,
                    "pattern": _PATH_PATTERN,
                    "example": SBOM[1],
                    "description": "Workspace-relative path of the SBOM JSON file.",
                },
            },
        },
        {
            "name": "schedule",
            "path": "recipes/schedule.json",
            "description": (
                "The daily Trigger security.maintain-daily, which runs security.maintain. "
                "Skip it when CI runs the Runbooks."
            ),
            "params": {
                "cron": {
                    "type": "string",
                    "default": MAINTAIN_CRON,
                    "description": "Five-field cron expression, read in UTC.",
                },
            },
            "depends_on": ["default"],
        },
    ]


RECIPE_BUILDERS = {
    "default": default_recipe,
    "sarif": sarif_recipe,
    "sbom": sbom_recipe,
    "schedule": schedule_recipe,
}


def render() -> str:
    return json.dumps(template(), indent=1) + "\n"


def rendered_recipes() -> dict[Path, str]:
    """Every recipe file and the declarations, by target path."""

    out = {
        KIT / spec["path"]: json.dumps(RECIPE_BUILDERS[spec["name"]](), indent=1) + "\n"
        for spec in recipe_specs()
    }
    out[RECIPE_SPECS] = json.dumps(recipe_specs(), indent=1) + "\n"
    return out


def render_sarif() -> str:
    return json.dumps(sarif_template(), indent=1) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = 0
    targets = [(TEMPLATE, render()), (SARIF_TEMPLATE, render_sarif())]
    targets += list(rendered_recipes().items())
    for target, content in targets:
        if args.check:
            if not target.is_file() or target.read_text() != content:
                print(f"{target} is out of date: run source/pilot/template.py", file=sys.stderr)
                stale = 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        print(f"wrote {target}")
    return stale


if __name__ == "__main__":
    raise SystemExit(main())
