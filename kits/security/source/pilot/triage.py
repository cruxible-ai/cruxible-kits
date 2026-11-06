"""Triage worklists and the judgment track record, as Queries (K-B2-1, K-B2-TR).

No Procedure writes any of this: an agent reads the worklists, judges, and its
judgment is ordinary state.

- ``security.urgent_exposures``: every (inventory, component, vulnerability)
  exposure, KEV-listed first (``kev_date_added`` present), then by EPSS score.
- ``security.kev_triage_backlog``: the KEV-listed exposures nobody has judged
  (a judged pair holds "none of V", so it is no exposure any more).
- ``security.not_affected_judgments``: the track record. Every component with a
  not_affected judgment, its VEX reason (qualified by the CVE) and, beside it,
  the affected_by nones (run it with ``claims``/``nones``: each names its
  Claim; ``get`` on the Claim gives who stated it and when). A source that
  later disagrees surfaces as a ``held_disagrees`` finding in the OSV Line's
  inbox.

A not_affected judgment is two writes an agent makes together
(:func:`judgment`): the ``write`` that retires OSV's observation of V and
adds "affected_by none of V" (normative, own words, K-B2-J1), and the Claim of
its VEX reason (K-B2-J1b, qualified by the CVE, which the write verbs cannot
carry).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from definitions import VULN
from inventory import COMPONENT, INVENTORY, VEX_JUSTIFICATIONS

URGENT = "security.urgent_exposures"
BACKLOG = "security.kev_triage_backlog"
JUDGMENTS = "security.not_affected_judgments"
EXPOSURE_ROW = "security.exposure"
JUDGMENT_ROW = "security.judgment"

_HOPS = (
    {"c": f"<v.{COMPONENT}.affected_by!"},
    {"i": f"c.{COMPONENT}.in_inventory!: {INVENTORY}"},
)
_FIELDS = (
    {"inventory": "i.inventory_id"},
    {"component": "c.purl"},
    "v.cve_id",
    "v.kev_date_added",
    "v.kev_due_date",
    "v.kev_ransomware_use",
    "v.epss_score",
    "v.epss_percentile",
)

URGENT_SPEC: dict[str, Any] = {
    "query": URGENT,
    "description": "Every component of an imported inventory that a vulnerability affects, "
    "KEV-listed first, then by EPSS score; a pair an agent judged not_affected is no "
    "exposure.",
    "from": {"v": VULN},
    "hops": list(_HOPS),
    "row": f"{EXPOSURE_ROW}@1",
    "fields": list(_FIELDS),
    "order": ["-v.kev_date_added", "-v.epss_score"],
}
BACKLOG_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": BACKLOG,
    "description": "The KEV-listed exposures nobody has judged yet, by EPSS score.",
    "where": "exists v.kev_date_added",
    "order": ["-v.epss_score"],
}
JUDGMENTS_SPEC: dict[str, Any] = {
    "query": JUDGMENTS,
    "description": "Every component with a not_affected judgment: its VEX reasons (each "
    "qualified by its CVE) and its affected_by nones; each names its Claim.",
    "from": {"c": COMPONENT},
    "where": "exists c.not_affected_reason",
    "row": f"{JUDGMENT_ROW}@1",
    "fields": [{"component": "c.purl"}, "c.not_affected_reason", "c.affected_by"],
}


def vocabulary_members() -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": EXPOSURE_ROW,
            "version": 1,
            "description": "One exposure: an inventory's component a vulnerability affects, "
            "with the vulnerability's KEV and EPSS facts.",
            "fields": {
                "inventory": "string",
                "component": "string",
                "cve_id": "string",
                "kev_date_added": "date?",
                "kev_due_date": "date?",
                "kev_ransomware_use": f"enum_of {VULN}.kev_ransomware_use?",
                "epss_score": "decimal{0..1}?",
                "epss_percentile": "decimal{0..1}?",
            },
        },
        {
            "kind": "contract",
            "name": JUDGMENT_ROW,
            "version": 1,
            "description": "One judged component: its VEX reasons and affected_by values.",
            "fields": {
                "component": "string",
                "not_affected_reason": (
                    f"list<enum_of {COMPONENT}.not_affected_reason>{{max_items: 64}}?"
                ),
                "affected_by": "list<string>{max_items: 256}?",
            },
        },
    ]
    for spec in (URGENT_SPEC, BACKLOG_SPEC, JUDGMENTS_SPEC):
        members.append({"kind": "query_definition", "query_definition": spec})
    return members


def judgment(
    purl: str,
    cve_id: str,
    *,
    reason: str,
    because: str,
    retire: Sequence[str] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A not_affected judgment: (the ``write`` request, the reason's change set).

    ``purl`` is the component's key (its purl@version); ``retire`` names the OSV
    observation Claims of this unit the judgment supersedes (a none beside the live
    value of its unit is refused).
    """

    if reason not in VEX_JUSTIFICATIONS:
        raise ValueError(f"reason must be one of {VEX_JUSTIFICATIONS}")
    vulnerability = f"{VULN}/{cve_id.lower()}"
    component = f"{COMPONENT}/{purl}"
    write = {
        "because": because,
        "changes": [
            *({"op": "retire", "target": claim, "reason": "superseded"} for claim in retire),
            {
                "op": "add",
                "subject": component,
                "field": "affected_by",
                "value": {"none": vulnerability},
                "role": "normative",
            },
        ],
    }
    stated = {
        "kind": "change_set",
        "rationale": f"VEX reason for not_affected {cve_id}.",
        "members": [
            {
                "kind": "claim",
                "subject": {"subject_kind": COMPONENT, "key": {COMPONENT + ".purl": purl}},
                "predicate": COMPONENT + ".not_affected_reason",
                "qualifier": cve_id,
                "object": {"kind": "literal", "value": reason},
                "role": "normative",
                "rationale": because,
                "source": {"kind": "self_source", "body": because + "\n"},
            }
        ],
    }
    return write, stated
