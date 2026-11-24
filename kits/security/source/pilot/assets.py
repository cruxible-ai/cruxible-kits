"""The deployment anchor: ``it.asset``, one lean kind, and its link from an inventory.

A worklist row says a vulnerable release is in an inventory. Whether it matters
there depends on where that software runs: an internet-facing production service
and an isolated dev box differ, and dependency judgments rely on that every day
("internal-only service"). ``it.asset`` records the deployment facts those
judgments rest on, so a judgment can pin them (``--based-on
it.asset/<slug>#exposure``) and come back in ``next`` as ``claim_dependency_stale``
when they change.

- ``it.asset`` is keyed by ``slug`` (a short stable id, as a code fact's
  ``topic``) and holds five fields an agent or an operator states: ``title``,
  ``owner`` (the team or service owner), ``environment`` (``prod``, ``staging``,
  ``dev``), ``exposure`` (``internet``, ``internal``, ``isolated``) and
  ``criticality`` (``critical``, ``high``, ``medium``, ``low``). Each is
  normative, own words or a cited workspace file (the deployment config that
  shows it), and never settled by a Mandate.
- ``security.inventory.asset`` (one, Subject-valued) links an SBOM inventory to the
  asset it runs as. It lives on the security side, so the asset kind names
  nothing of the security kit. An inventory with no link is unchanged: every
  worklist still lists it, and ``security.asset_urgent_exposures`` lists its rows
  with the asset columns empty (an optional hop). When one build runs as several
  assets, link the most exposed one: a judgment that relies on exposure relies on
  the worst case.

The ``it.`` prefix is reserved for a future IT asset kit (inbound discovery Lines
and the inventory kinds that need them); this kit holds only the anchor its own
judgments rest on, and adds no host, cluster, network or vendor kinds.
"""

from __future__ import annotations

from typing import Any

from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input

ASSET = "it.asset"
#: The link from an SBOM inventory to the asset it runs as.
INVENTORY_ASSET = "security.inventory.asset"
INVENTORY = "security.inventory"
ENVIRONMENTS = ("prod", "staging", "dev")
EXPOSURES = ("internet", "internal", "isolated")
CRITICALITIES = ("critical", "high", "medium", "low")
_SLUG_PATTERN = "^[a-z0-9]+(-[a-z0-9]+)*$"


def _stated(field: str, value: dict[str, Any], description: str, **more: Any) -> dict[str, Any]:
    """An asset field an agent or operator states: normative, own words or a cited
    workspace file (the core default admits both), never a Mandate's."""

    return {
        "predicate": f"{ASSET}.{field}",
        "allowed_subject_kinds": [ASSET],
        "cardinality": "one",
        "value": value,
        "description": description,
        **more,
        "permitted_roles": ["normative"],
        "default_role": "normative",
        "evidence_requirement": "self",
        "revision_evidence": "replace",
    }


def claim_type_records() -> list[dict[str, Any]]:
    return [
        {
            "predicate": f"{ASSET}.slug",
            "allowed_subject_kinds": [ASSET],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 64, "pattern": _SLUG_PATTERN},
            "description": "The asset's short stable id (payments-api, build-runner-eu), spelled "
            "the same every time; the asset's key.",
        },
        _stated(
            "title",
            {"kind": "string", "max_len": 120},
            "The asset's display name (Payments API).",
        ),
        _stated(
            "owner",
            {"kind": "string", "max_len": 128},
            "The team or service owner who answers for the asset (payments-team).",
        ),
        _stated(
            "environment",
            {"kind": "enum", "members": list(ENVIRONMENTS)},
            "Which environment the asset is.",
        ),
        _stated(
            "exposure",
            {"kind": "enum", "members": list(EXPOSURES)},
            "Who can reach the asset over the network. A dependency judgment that relies on "
            "it pins it (--based-on it.asset/<slug>#exposure), so a change brings the judgment "
            "back in next as claim_dependency_stale.",
            member_descriptions=[
                {"member": "internet", "description": "Reachable from the public internet."},
                {
                    "member": "internal",
                    "description": "Reachable only from the organization's own networks.",
                },
                {"member": "isolated", "description": "No inbound network path."},
            ],
        ),
        _stated(
            "criticality",
            {"kind": "enum", "members": list(CRITICALITIES)},
            "How much harm a compromise of the asset does.",
        ),
        {
            "predicate": INVENTORY_ASSET,
            "allowed_subject_kinds": [INVENTORY],
            "cardinality": "one",
            "value": {"kind": "subject", "subject_kinds": [ASSET]},
            "description": "The IT asset this inventory's software runs as. When one build runs "
            "as several, link the most exposed. Optional: an inventory with no asset is triaged "
            "as before. Never settled by a Mandate.",
            "permitted_roles": ["normative"],
            "default_role": "normative",
            "evidence_requirement": "self",
            "revision_evidence": "replace",
        },
    ]


def claim_types() -> list[Any]:
    return [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]


def subject_kind_members() -> list[dict[str, Any]]:
    return [
        {
            "kind": "subject_kind",
            "name": ASSET,
            "description": "One deployed system security judgments rest on (a service, an "
            "appliance, a host), named by its slug: where it runs, who can reach it, who owns "
            "it and how much it matters.",
            "keys": [f"{ASSET}.slug"],
        }
    ]


def vocabulary_members() -> list[dict[str, Any]]:
    """The asset kind, its ClaimTypes and the inventory's link (the triage Query that
    reads them is ``triage.ASSET_URGENT``)."""

    return [
        *(
            {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
            for t in claim_types()
        ),
        *subject_kind_members(),
    ]
