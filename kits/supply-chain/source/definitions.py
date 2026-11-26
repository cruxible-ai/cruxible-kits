"""The supply-chain kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/supply-chain SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

Facts read from documents (a certificate's dates, a part's supplier, a BOM line)
are ``observation``; reviews and approvals are ``normative``. Both admit own words or
a passage of any catalogued workspace file, so an approval can cite the audit report
or certificate it rests on. Two relationships carry their own state and so are pair
kinds keyed by their ends: a product's use of a component (``supply.usage``) and a
supplier's attestation to a standard (``supply.attestation``). Renewing an
attestation revises that one pair, so every component review pinned to it
(``based_on``) is flagged for a re-check and nothing else is.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "supply-chain"
VERSION = "1.0.0"
OWNS = ("supply.",)

SUPPLIER = "supply.supplier"
COMPONENT = "supply.component"
PRODUCT = "supply.product"
USAGE = "supply.usage"
ATTESTATION = "supply.attestation"
SELF = "playbill.coordinator-self-source-v1"

OBSERVED = "observation"
DECIDED = "normative"


def _rule(role: str) -> dict[str, Any]:
    """Own words, or a passage of any catalogued workspace file."""

    return {
        "rule_id": "own-words-or-file",
        "claim_roles": [role],
        "capture_contracts": [SELF],
        "capture_contract_families": ["workspace_file"],
        "admission": "direct",
        "attestation_requirement": "none",
        "subject_binding": "exact_claim_subject",
    }


def _key(predicate: str, value: dict[str, Any], description: str) -> dict[str, Any]:
    """A key part: the slug, value or Subject that names the Subject."""

    return {
        "predicate": predicate,
        "cardinality": "one",
        "value": value,
        "default_role": DECIDED,
        "permitted_roles": [DECIDED],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": []},
        "description": description,
    }


def _field(
    predicate: str,
    value: dict[str, Any],
    description: str,
    *,
    role: str = OBSERVED,
    cardinality: str = "one",
    **more: Any,
) -> dict[str, Any]:
    return {
        "predicate": predicate,
        "cardinality": cardinality,
        "value": value,
        "default_role": role,
        "permitted_roles": [role],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": [_rule(role)]},
        "description": description,
        **more,
    }


def _text(maximum: int = 120) -> dict[str, Any]:
    return {"kind": "string", "min_len": 1, "max_len": maximum}


def _enum(*members: str) -> dict[str, Any]:
    return {"kind": "enum", "members": list(members)}


def _ranked(*members: str) -> dict[str, Any]:
    """An ordered enum: members lowest first, so queries can compare rank."""

    return {"kind": "enum", "members": list(members), "ordered": True}


def _subjects(*kinds: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kinds": list(kinds)}


def _meanings(**members: str) -> list[dict[str, str]]:
    return [{"member": member, "description": text} for member, text in members.items()]


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Suppliers.
        _key(f"{SUPPLIER}.name", _text(256), "The supplier's slug (acme-sensors); its key."),
        _field(f"{SUPPLIER}.title", _text(), "The supplier's legal or trading name."),
        _field(f"{SUPPLIER}.country", _text(64), "The country the supplier manufactures in."),
        _field(
            f"{SUPPLIER}.risk_tier",
            _ranked("low", "medium", "high", "critical"),
            "The supplier's assessed risk, lowest first; cite the risk assessment.",
            role=DECIDED,
        ),
        _field(
            f"{SUPPLIER}.status",
            _enum("approved", "conditional", "suspended", "disqualified"),
            "Whether the supplier may be sourced from.",
            role=DECIDED,
        ),
        # Components.
        _key(f"{COMPONENT}.name", _text(256), "The component's part number (fw-crypto-2.4); its key."),
        _field(f"{COMPONENT}.title", _text(), "The component's name, as the supplier lists it."),
        _field(f"{COMPONENT}.supplier", _subjects(SUPPLIER), "The supplier that makes it."),
        _field(
            f"{COMPONENT}.category",
            _enum("electronic", "firmware", "software", "mechanical", "material", "packaging"),
            "What kind of component it is.",
        ),
        _field(
            f"{COMPONENT}.criticality",
            _ranked("low", "medium", "high", "critical"),
            "How much a defect or shortage of this component would hurt, lowest first.",
            role=DECIDED,
        ),
        _field(
            f"{COMPONENT}.review_status",
            _enum(
                "pending_review",
                "approved_for_prototype",
                "approved_for_production",
                "approved_with_conditions",
                "rejected",
            ),
            "The outcome of the component's supplier review. Pin it (based_on) to the "
            "attestations it relied on, so a renewed or lapsed attestation reopens it.",
            role=DECIDED,
            member_descriptions=_meanings(
                pending_review="Not yet reviewed.",
                approved_for_prototype="Cleared for prototype builds only.",
                approved_for_production="Cleared for production builds.",
                approved_with_conditions="Cleared, with conditions the review states.",
                rejected="Not to be used.",
            ),
        ),
        # Products.
        _key(f"{PRODUCT}.name", _text(256), "The product's SKU or slug (edge-gateway-v3); its key."),
        _field(f"{PRODUCT}.title", _text(), "The product's name."),
        _field(
            f"{PRODUCT}.lifecycle",
            _enum("development", "production", "end_of_life"),
            "Where the product is in its lifecycle.",
            role=DECIDED,
        ),
        # A product's use of a component: one per (product, component).
        _key(f"{USAGE}.product", _subjects(PRODUCT), "The product; a key part."),
        _key(f"{USAGE}.component", _subjects(COMPONENT), "The component it uses; a key part."),
        _field(
            f"{USAGE}.quantity",
            {"kind": "int", "min": 1},
            "How many of the component one unit of the product uses, from its BOM.",
        ),
        _field(
            f"{USAGE}.sourcing",
            _enum("sole_source", "primary", "alternate"),
            "The component's sourcing role in this product.",
            role=DECIDED,
        ),
        # A supplier's attestation to a standard: one per (supplier, standard).
        _key(f"{ATTESTATION}.supplier", _subjects(SUPPLIER), "The attesting supplier; a key part."),
        _key(
            f"{ATTESTATION}.standard",
            _enum(
                "soc2_type2", "iso_27001", "iso_9001", "iatf_16949", "rohs", "reach",
                "conflict_minerals",
            ),
            "The standard attested to; a key part.",
        ),
        _field(
            f"{ATTESTATION}.issued_at",
            {"kind": "datetime"},
            "When the current certificate or report was issued; cite it.",
        ),
        _field(
            f"{ATTESTATION}.valid_until",
            {"kind": "datetime"},
            "When the current certificate or report lapses; cite it.",
        ),
        _field(
            f"{ATTESTATION}.verdict",
            _enum("accepted", "accepted_with_exceptions", "rejected"),
            "The reviewer's verdict on the current certificate or report; cite the "
            "passage that supports it.",
            role=DECIDED,
        ),
    ]


SUBJECT_KINDS = (
    (SUPPLIER, "A supplier or vendor, named by its slug.", [f"{SUPPLIER}.name"]),
    (COMPONENT, "A purchased component, named by its part number.", [f"{COMPONENT}.name"]),
    (PRODUCT, "A product you build and ship, named by its SKU.", [f"{PRODUCT}.name"]),
    (
        USAGE,
        "A product's use of a component (a BOM line), keyed by the product and component.",
        [f"{USAGE}.product", f"{USAGE}.component"],
    ),
    (
        ATTESTATION,
        "A supplier's attestation to one standard, keyed by the supplier and standard; "
        "a renewal revises it in place.",
        [f"{ATTESTATION}.supplier", f"{ATTESTATION}.standard"],
    ),
)

AFFECTED_PRODUCTS = {
    "query": "supply.affected_products",
    "description": "Every product that uses a component from one supplier, with the "
    "component's review status.",
    "params": {"supplier": "string"},
    "from": {"use": USAGE},
    "hops": [
        {"component": f"use.{USAGE}.component!: {COMPONENT}"},
        {"supplier": f"component.{COMPONENT}.supplier!: {SUPPLIER}"},
    ],
    "where": "supplier.name == $supplier",
    "fields": [
        "use.product",
        "use.component",
        "use.sourcing",
        {"review_status": "component.review_status"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

EXPIRING_ATTESTATIONS = {
    "query": "supply.expiring_attestations",
    "description": "Attestations that have lapsed or lapse within 30 days.",
    "from": {"attestation": ATTESTATION},
    "where": "attestation.valid_until < now + 30d",
    "fields": [
        "attestation.supplier",
        "attestation.standard",
        "attestation.valid_until",
        "attestation.verdict",
    ],
    "limit": 200,
    "max": {"results": 2000},
}

UNAPPROVED_CRITICAL = {
    "query": "supply.unapproved_critical_components",
    "description": "High or critical components not approved for production, reviewed "
    "or not.",
    "from": {"component": COMPONENT},
    "where": 'component.criticality >= "high" and (not exists component.review_status or '
    'component.review_status != "approved_for_production")',
    "fields": ["component.supplier", "component.criticality", "component.review_status"],
    "limit": 200,
    "max": {"results": 2000},
}

QUERIES = (AFFECTED_PRODUCTS, EXPIRING_ATTESTATIONS, UNAPPROVED_CRITICAL)


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"supply-chain {VERSION}: suppliers, components, products, BOM usage "
        "and attestations.",
        "members": [
            *(
                {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
                for t in claim_types
            ),
            *(
                {"kind": "subject_kind", "name": name, "description": description, "keys": keys}
                for name, description, keys in SUBJECT_KINDS
            ),
            *({"kind": "query_definition", "query_definition": q} for q in QUERIES),
        ],
    }
