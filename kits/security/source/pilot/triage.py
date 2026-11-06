"""Triage worklists and the judgment track record, as Queries (K-B2-1, K-B2-TR).

No Procedure writes any of this: an agent reads the worklists, judges, and its
judgment is ordinary state.

- ``security.urgent_exposures``: every (inventory, component, vulnerability)
  exposure, KEV-listed first (``kev_date_added`` present), then by EPSS score.
- ``security.kev_triage_backlog``: the KEV-listed exposures nobody has judged
  (a judged pair holds "none of V", so it is no exposure any more).
- ``security.not_affected_judgments``: the candidates for the track record:
  every component with a not_affected reason. Which of its pairs are judged is
  :func:`judgment_status` over the compact query
  (``query security.component --select purl,not_affected_reason,affected_by
  --claims``): a pair is ``judged`` only when the none of V exists, and
  ``judgment incomplete`` when only its reason does. Each entry names its
  Claims; ``get --detail history`` on a Claim gives who stated it and when. A
  source that later disagrees surfaces as a ``held_disagrees`` finding in the
  OSV Line's inbox.

A not_affected judgment is two writes (:func:`judgment`), in this order:

1. the Claim of its VEX reason (K-B2-J1b, qualified by the CVE; the write verbs
   cannot carry a qualifier, so it is an ``authoring submit``);
2. the ``write`` that retires OSV's observation of V and adds "affected_by none
   of V" (normative, own words, K-B2-J1).

Everything that hides a pair keys on the none: the exposure, the backlog and
the watch list. So if the second write fails, is refused or never happens, the
pair stays exposed and reads ``judgment incomplete``: visible, and recovered by
making the second write. (A single atomic change set needs core: surface gap
G4.)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

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
    "description": "Every component with a not_affected reason (each qualified by its "
    "CVE) and its affected_by values; a pair is judged only when its none of V exists "
    "(see triage.judgment_status).",
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


class Judgment(NamedTuple):
    """A not_affected judgment's two writes, in the order they must land."""

    #: FIRST: ``authoring submit`` this change set (the VEX reason, qualified).
    reason: dict[str, Any]
    #: SECOND: ``write`` this request (retire OSV's observation, add the none).
    verdict: dict[str, Any]


def judgment(
    purl: str,
    cve_id: str,
    *,
    reason: str,
    because: str,
    retire: Sequence[str] = (),
) -> Judgment:
    """A not_affected judgment: the reason's change set, then the ``write`` request.

    Submit ``reason`` first and ``verdict`` second. Only the none of V (the
    second write) hides the pair from the exposure, the backlog and the watch
    list, so a judgment that stops between the two leaves the pair exposed and
    :func:`judgment_status` reports it ``judgment incomplete``; make the second
    write to finish it.

    ``purl`` is the component's key (its purl@version); ``retire`` names the OSV
    observation Claims of this unit the judgment supersedes (a none beside the live
    value of its unit is refused).
    """

    if reason not in VEX_JUSTIFICATIONS:
        raise ValueError(f"reason must be one of {VEX_JUSTIFICATIONS}")
    vulnerability = f"{VULN}/{cve_id.lower()}"
    component = f"{COMPONENT}/{purl}"
    verdict = {
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
    return Judgment(reason=stated, verdict=verdict)


JUDGED = "judged"
INCOMPLETE = "judgment incomplete"


def judgment_status(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The judgments of one component, from its compact query row.

    ``row`` is one row of ``query security.component --select
    purl,not_affected_reason,affected_by --claims`` (its ``claims`` and
    ``nones`` cells). One entry per CVE that has a not_affected reason or an
    affected_by none: ``judged`` when both exist, ``judgment incomplete`` when
    only the reason does (the second write is missing: the pair is still
    exposed), and a none without a reason is ``judged`` with no reason (J1 alone).
    """

    def text(value: Any) -> str:
        return str(getattr(value, "value", value))

    def cell(name: str, part: str) -> list[Any]:
        found = (row.get(part) or {}).get(name) or []
        return list(found)

    def field(item: Any, name: str) -> Any:
        return item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)

    reasons = {
        str(field(c, "qualifier")).upper(): c
        for c in cell("not_affected_reason", "claims")
        if field(c, "qualifier")
    }
    nones = {
        text(field(n, "of")).rsplit("/", 1)[-1].upper(): n for n in cell("affected_by", "nones")
    }
    out = []
    for cve in sorted(set(reasons) | set(nones)):
        stated, none = reasons.get(cve), nones.get(cve)
        out.append(
            {
                "cve_id": cve,
                "status": JUDGED if none is not None else INCOMPLETE,
                "reason": None if stated is None else text(field(stated, "value")),
                "reason_claim": None if stated is None else field(stated, "claim"),
                "none_claim": None if none is None else field(none, "claim"),
            }
        )
    return out
