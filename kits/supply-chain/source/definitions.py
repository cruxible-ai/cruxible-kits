"""The supply-chain kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/supply-chain SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

Facts read from BOMs, facility records, and certificates are ``observation``; risk
ratings, approvals, verdicts, and incident dispositions are ``normative``. Both admit
own words or a passage of any catalogued workspace file. Two relationships carry their
own state and are pair kinds keyed by their ends: a product's use of a component
(``supply.usage``) and a supplier's compliance certificate for a standard
(``supply.certificate``). Renewing a certificate revises that one pair in place, so
every component review pinned to it (``based_on``) reopens selectively.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "supply-chain"
VERSION = "2.0.0"
OWNS = ("supply.",)

SUPPLIER = "supply.supplier"
FACILITY = "supply.facility"
COMPONENT = "supply.component"
PRODUCT = "supply.product"
USAGE = "supply.usage"
CERTIFICATE = "supply.certificate"
INCIDENT = "supply.incident"
SELF = "playbill.coordinator-self-source-v1"

OBSERVED = "observation"
DECIDED = "normative"

SOURCE_DIR = Path(__file__).resolve().parent


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


RISK_TIER = _ranked("low", "medium", "high", "critical")
RISK_MEANINGS = _meanings(
    low="Routine vendor with strong compliance posture and low disruption risk.",
    medium="Moderate exposure; standard periodic review applies.",
    high="Elevated geopolitical, financial, quality, or security risk.",
    critical="Severe risk requiring executive sign-off or active replacement.",
)

APPROVAL_STATUS = _ranked("approved", "conditional", "suspended", "disqualified")
APPROVAL_MEANINGS = _meanings(
    approved="Cleared for production sourcing.",
    conditional="Cleared with documented conditions or pending remediation.",
    suspended="New orders paused pending investigation or re-audit.",
    disqualified="Do not source from this vendor or facility.",
)


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Suppliers.
        _key(f"{SUPPLIER}.name", _text(256), "The supplier's slug (acme-sensors); its key."),
        _field(f"{SUPPLIER}.title", _text(), "The supplier's legal or trading name."),
        _field(f"{SUPPLIER}.country", _text(64), "The supplier's headquarters or primary country."),
        _field(
            f"{SUPPLIER}.risk_tier",
            RISK_TIER,
            "The supplier's assessed risk, lowest first; cite the risk assessment.",
            role=DECIDED,
            member_descriptions=RISK_MEANINGS,
        ),
        _field(
            f"{SUPPLIER}.status",
            APPROVAL_STATUS,
            "Whether the supplier may be sourced from, ordered from approved to disqualified.",
            role=DECIDED,
            member_descriptions=APPROVAL_MEANINGS,
        ),
        # Supplier facilities (factories, assembly plants, test labs, warehouses).
        _key(
            f"{FACILITY}.name",
            _text(256),
            "The facility's slug (acme-penang-fab-2); its key.",
        ),
        _field(f"{FACILITY}.supplier", _subjects(SUPPLIER), "The supplier operating this facility."),
        _field(f"{FACILITY}.title", _text(), "The facility's display name or site label."),
        _field(f"{FACILITY}.country", _text(64), "The country where the facility operates."),
        _field(
            f"{FACILITY}.role",
            _enum("manufacturing", "assembly", "testing", "warehouse"),
            "The operational role of the facility in the supply chain.",
            role=DECIDED,
        ),
        _field(
            f"{FACILITY}.status",
            APPROVAL_STATUS,
            "Qualification standing of this specific facility, ordered from approved to disqualified.",
            role=DECIDED,
            member_descriptions=APPROVAL_MEANINGS,
        ),
        # Components (supplier-specific MPN; alternate suppliers get their own Component Subject).
        _key(
            f"{COMPONENT}.name",
            _text(256),
            "The supplier's manufacturer part number (MPN, e.g. fw-crypto-2.4); its key. "
            "Alternate suppliers get their own component Subject and appear as alternate rows in supply.usage.",
        ),
        _field(f"{COMPONENT}.title", _text(), "The component's name, as the supplier lists it."),
        _field(f"{COMPONENT}.supplier", _subjects(SUPPLIER), "The supplier that makes it."),
        _field(
            f"{COMPONENT}.facility",
            _subjects(FACILITY),
            "The primary manufacturing or assembly facility for this part, when known.",
        ),
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
            member_descriptions=_meanings(
                low="Commodity part with trivial substitution.",
                medium="Shortage slows builds or requires minor re-qualification.",
                high="Shortage halts production or requires engineering redesign.",
                critical="Safety, security, or regulatory critical; outage halts shipments.",
            ),
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
            "The outcome of the component's qualification review. Pin it (based_on) to the "
            "certificates and supplier status it relied on, so any renewal or lapse reopens it.",
            role=DECIDED,
            member_descriptions=_meanings(
                pending_review="Not yet reviewed.",
                approved_for_prototype="Cleared for prototype builds only.",
                approved_for_production="Cleared for production builds.",
                approved_with_conditions="Cleared, with conditions stated in the review.",
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
        # A supplier's compliance certificate: one per (supplier, standard).
        _key(f"{CERTIFICATE}.supplier", _subjects(SUPPLIER), "The certified supplier; a key part."),
        _key(
            f"{CERTIFICATE}.standard",
            _text(64),
            "Normalized standard slug (soc2-type2, iso-27001, iso-9001, iatf-16949, "
            "as9100, iso-13485, rohs, reach, conflict-minerals, cmmc); a key part.",
        ),
        _field(
            f"{CERTIFICATE}.facility",
            _subjects(FACILITY),
            "Specific facility covered by the certificate, when site-scoped.",
        ),
        _field(
            f"{CERTIFICATE}.issued_at",
            {"kind": "datetime"},
            "When the current certificate or audit report was issued; cite it.",
        ),
        _field(
            f"{CERTIFICATE}.valid_until",
            {"kind": "datetime"},
            "When the current certificate or audit report lapses; cite it.",
        ),
        _field(
            f"{CERTIFICATE}.verdict",
            _enum("accepted", "accepted_with_exceptions", "rejected"),
            "The reviewer's verdict on the current certificate or report; cite the "
            "passage that supports it.",
            role=DECIDED,
            member_descriptions=_meanings(
                accepted="Certificate meets requirements with no blocking exceptions.",
                accepted_with_exceptions="Accepted with documented compensating controls or exceptions.",
                rejected="Certificate does not satisfy qualification requirements.",
            ),
        ),
        # Supply chain incidents and disruptions.
        _key(f"{INCIDENT}.name", _text(256), "The incident's slug (penang-power-outage-2026); its key."),
        _field(
            f"{INCIDENT}.affects",
            _subjects(SUPPLIER, FACILITY, COMPONENT),
            "The supplier, facility, or component affected by the incident.",
            cardinality="many",
        ),
        _field(
            f"{INCIDENT}.category",
            _enum(
                "quality_defect",
                "shortage",
                "compliance_lapse",
                "security_advisory",
                "geopolitical",
            ),
            "Primary category of the supply disruption or issue.",
        ),
        _field(
            f"{INCIDENT}.severity",
            _ranked("info", "low", "medium", "high", "critical"),
            "How severe the operational or compliance impact is, lowest first.",
        ),
        _field(
            f"{INCIDENT}.disposition",
            _enum("open", "mitigated", "resolved", "accepted"),
            "Current handling status of the incident.",
            role=DECIDED,
            member_descriptions=_meanings(
                open="Active and under investigation or response.",
                mitigated="Workaround or alternate sourcing in place; root issue remains.",
                resolved="Root issue closed and normal supply restored.",
                accepted="Residual risk explicitly accepted with cited rationale.",
            ),
        ),
    ]


SUBJECT_KINDS = (
    (SUPPLIER, "A supplier or vendor, named by its slug.", [f"{SUPPLIER}.name"]),
    (
        FACILITY,
        "A specific manufacturing, assembly, testing, or warehouse site operated by a supplier.",
        [f"{FACILITY}.name"],
    ),
    (
        COMPONENT,
        "A purchased component (supplier MPN), named by its part number.",
        [f"{COMPONENT}.name"],
    ),
    (PRODUCT, "A product you build and ship, named by its SKU.", [f"{PRODUCT}.name"]),
    (
        USAGE,
        "A product's use of a component (a BOM line), keyed by the product and component.",
        [f"{USAGE}.product", f"{USAGE}.component"],
    ),
    (
        CERTIFICATE,
        "A supplier's compliance certificate for one standard, keyed by the supplier and standard; "
        "a renewal revises it in place.",
        [f"{CERTIFICATE}.supplier", f"{CERTIFICATE}.standard"],
    ),
    (
        INCIDENT,
        "A supply disruption, quality defect, compliance lapse, or security advisory.",
        [f"{INCIDENT}.name"],
    ),
)

AFFECTED_PRODUCTS = {
    "query": "supply.affected_products",
    "description": "Every product that uses a component from one supplier, with sourcing "
    "and review status.",
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

EXPIRING_CERTIFICATES = {
    "query": "supply.expiring_certificates",
    "description": "Certificates that have lapsed or lapse within 30 days.",
    "from": {"cert": CERTIFICATE},
    "where": "cert.valid_until < now + 30d",
    "fields": [
        "cert.supplier",
        "cert.standard",
        "cert.valid_until",
        "cert.verdict",
    ],
    "limit": 200,
    "max": {"results": 2000},
}

UNAPPROVED_CRITICAL = {
    "query": "supply.unapproved_critical_components",
    "description": "High or critical components not approved for production, reviewed or not.",
    "from": {"component": COMPONENT},
    "where": 'component.criticality >= "high" and (not exists component.review_status or '
    'component.review_status != "approved_for_production")',
    "fields": ["component.supplier", "component.criticality", "component.review_status"],
    "limit": 200,
    "max": {"results": 2000},
}

SOLE_SOURCE_CRITICAL = {
    "query": "supply.sole_source_critical",
    "description": "Production products relying on a sole-source component with high/critical "
    "criticality or a high-risk/suspended supplier.",
    "from": {"use": USAGE},
    "hops": [
        {"product": f'use.{USAGE}.product!: {PRODUCT} where product.lifecycle == "production"'},
        {"component": f"use.{USAGE}.component!: {COMPONENT}"},
        {"supplier": f"component.{COMPONENT}.supplier!: {SUPPLIER}"},
    ],
    "where": 'use.sourcing == "sole_source" and (component.criticality >= "high" or '
    'supplier.risk_tier >= "high" or supplier.status >= "suspended")',
    "fields": [
        "use.product",
        "use.component",
        {"criticality": "component.criticality"},
        {"supplier": "component.supplier"},
        {"supplier_risk": "supplier.risk_tier"},
        {"supplier_status": "supplier.status"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

OPEN_INCIDENTS = {
    "query": "supply.open_incidents",
    "description": "Open supply incidents of medium severity or worse.",
    "from": {"incident": INCIDENT},
    "where": 'incident.disposition == "open" and incident.severity >= "medium"',
    "fields": ["incident.affects", "incident.category", "incident.severity"],
    "limit": 200,
    "max": {"results": 2000},
}

QUERIES = (
    AFFECTED_PRODUCTS,
    EXPIRING_CERTIFICATES,
    UNAPPROVED_CRITICAL,
    SOLE_SOURCE_CRITICAL,
    OPEN_INCIDENTS,
)


def guidance_documents(store_body: Callable[[Path], str]) -> list[dict[str, Any]]:
    path = SOURCE_DIR / "guidance" / "review-guidance.md"
    title = path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
    guided = (
        f"ClaimType:{SUPPLIER}.risk_tier",
        f"ClaimType:{SUPPLIER}.status",
        f"ClaimType:{COMPONENT}.review_status",
        f"ClaimType:{CERTIFICATE}.verdict",
        f"ClaimType:{INCIDENT}.disposition",
    )
    return [
        {
            "kind": "document",
            "identity": "document:supply.guidance.review-guidance",
            "document_kind": "supply.guidance",
            "title": title,
            "media_type": "text/markdown",
            "body_digest": store_body(path),
            "links": [
                {"relation": "guides", "target_identity": target}
                for target in sorted(guided, key=lambda item: item.encode("utf-8"))
            ],
            "governance_scope": ["supply"],
            "lifecycle": {"revision": 1},
        }
    ]


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"supply-chain {VERSION}: suppliers, facilities, components, products, "
        "BOM usage, certificates and incidents.",
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
