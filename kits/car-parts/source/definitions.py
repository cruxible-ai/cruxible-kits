"""The car-parts kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/car-parts SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default. A rule that admitted a named workspace file (``quotes``, ``catalog``,
``fitment``, ``decisions``) admits any catalogued workspace file
(``capture_contract_families: [workspace_file]``): a kit cannot ship an
adopter's per-file source contracts. A string field that 1.1.0 left unbounded is
bounded at 256 characters, the most the current core admits for a string.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "car-parts"
VERSION = "1.2.0"
OWNS = ("catalog.",)

PART = "catalog.part"
VEHICLE = "catalog.vehicle"
NOTE = "catalog.note"
DECISION = "catalog.decision"
SELF = "playbill.coordinator-self-source-v1"


def _rule(rule_id: str, role: str, *, file: bool = False) -> dict[str, Any]:
    """An own-words rule; ``file`` also admits any catalogued workspace file."""

    rule: dict[str, Any] = {
        "rule_id": rule_id,
        "claim_roles": [role],
        "capture_contracts": [SELF],
        "admission": "direct",
        "attestation_requirement": "none",
        "subject_binding": "exact_claim_subject",
    }
    if file:
        rule["capture_contract_families"] = ["workspace_file"]
    return rule


def _key(kind: str, description: str) -> dict[str, Any]:
    """A kind's key: the slug or number that names it; no evidence rules."""

    return {
        "predicate": f"{kind}.name",
        "cardinality": "one",
        "value": _text(),
        "default_role": "normative",
        "permitted_roles": ["normative"],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": []},
        "description": description,
    }


def _field(
    predicate: str,
    value: dict[str, Any],
    description: str,
    *,
    role: str = "observation",
    cardinality: str = "one",
    rule: str = "own-words-or-file",
    file: bool = False,
    default_role: bool = True,
    **more: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "predicate": predicate,
        "cardinality": cardinality,
        "value": value,
        "permitted_roles": [role],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": [_rule(rule, role, file=file)]},
        "description": description,
        **more,
    }
    if default_role:
        record["default_role"] = role
    return record


def _text(maximum: int = 256) -> dict[str, Any]:
    """Non-empty text; a string ClaimType is bounded at 256 characters at most."""

    return {"kind": "string", "min_len": 1, "max_len": maximum}


def _subjects(*kinds: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kinds": list(kinds)}


#: The fitment and decision links, as 1.1.0's own-words-or-catalog/fitment/decisions rule.
_LINK = "own-words-catalog-or-fitment-notes"


def claim_type_records() -> list[dict[str, Any]]:
    return [
        _key(PART, "The part number; its key."),
        _field(f"{PART}.title", _text(), "The part name as the supplier lists it."),
        _field(
            f"{PART}.category",
            {"kind": "enum", "members": ["brakes", "filters", "wipers", "lighting"]},
            "The kind of part.",
        ),
        _field(
            f"{PART}.price",
            {"kind": "int", "min": 0},
            "The supplier's list price, in USD.",
            file=True,
            evidence_requirement="captured",
            evidence_freshness={"stale_after": "PT2M"},
        ),
        _field(
            f"{PART}.fits",
            _subjects(VEHICLE),
            "A vehicle this part fits.",
            cardinality="many",
            rule=_LINK,
            file=True,
        ),
        _field(
            f"{PART}.replaces",
            _subjects(PART),
            "An older part this part replaces.",
            cardinality="many",
        ),
        _field(
            f"{PART}.weight_grams",
            {"kind": "int", "min": 0},
            "The part's shipping weight, in grams.",
            rule="self",
            default_role=False,
        ),
        _key(VEHICLE, "The vehicle's slug (make-model-year); its key."),
        _field(f"{VEHICLE}.make", _text(), "The manufacturer."),
        _field(f"{VEHICLE}.model", _text(), "The model."),
        _field(f"{VEHICLE}.year", {"kind": "int", "min": 1900}, "The model year."),
        _key(NOTE, "The slug; its key."),
        _field(f"{NOTE}.title", _text(120), "A one-line title."),
        _field(
            f"{NOTE}.about",
            _subjects(PART, VEHICLE),
            "What the note is about.",
            cardinality="many",
            rule=_LINK,
            file=True,
        ),
        _key(DECISION, "The slug; its key."),
        _field(
            f"{DECISION}.status",
            {"kind": "enum", "members": ["proposed", "accepted", "superseded"]},
            "Where the decision stands.",
            role="normative",
        ),
        _field(f"{DECISION}.summary", _text(200), "The decision in one line.", role="normative"),
        _field(
            f"{DECISION}.governs",
            _subjects(PART, VEHICLE),
            "What the decision governs.",
            role="normative",
            cardinality="many",
            rule=_LINK,
            file=True,
        ),
        _field(
            f"{DECISION}.amends",
            _subjects(DECISION),
            "An earlier decision this one amends.",
            role="normative",
            cardinality="many",
            rule=_LINK,
            file=True,
        ),
    ]


SUBJECT_KINDS = (
    (PART, "A part in the catalog, named by its part number."),
    (VEHICLE, "A vehicle, named make-model-year."),
    (NOTE, "A note: a finding, checkpoint or report, named by its slug."),
    (DECISION, "A decision the team made, named by its slug."),
)

PARTS_FOR_VEHICLE = {
    "query": "catalog.parts_for_vehicle",
    "description": "The parts that fit one vehicle.",
    "params": {"vehicle": "string"},
    "from": {"part": PART},
    "hops": [{"vehicle": f"part.{PART}.fits!: {VEHICLE}"}],
    "where": "vehicle.name == $vehicle",
    "fields": ["part.category", "part.title"],
    "limit": 100,
    "max": {"results": 1000},
}


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"car-parts {VERSION}: the 1.1.0 definitions in the current formats.",
        "members": [
            *(
                {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
                for t in claim_types
            ),
            *(
                {
                    "kind": "subject_kind",
                    "name": name,
                    "description": description,
                    "keys": [f"{name}.name"],
                }
                for name, description in SUBJECT_KINDS
            ),
            {"kind": "query_definition", "query_definition": PARTS_FOR_VEHICLE},
        ],
    }
