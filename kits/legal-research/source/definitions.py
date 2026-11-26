"""The legal-research kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/legal-research SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

Facts about an opinion (its citation, court, date, how later courts treated it) are
``observation`` and cite the opinion or citator report. What a researcher concludes
(a holding's rule and whether it still supports an argument, an argument's
readiness) is ``normative`` and cites the opinion passage or the memo section it rests
on. Prose stays in memos and briefs; Claims hold the short rule, the pin cite and the
status, and an argument pins (``based_on``) the holdings it relies on, so a changed
holding flags exactly the arguments built on it. Treatment is an ordered enum from
good law to overruled, so a query can ask for anything worse than good law.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "legal-research"
VERSION = "1.0.0"
OWNS = ("legal.",)

COURT = "legal.court"
CASE = "legal.case"
HOLDING = "legal.holding"
MATTER = "legal.matter"
ARGUMENT = "legal.argument"
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
    """A key part: the slug or Subject that names the Subject."""

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


#: Precedential treatment, from fully good law to no longer law.
TREATMENT = _ranked("good_law", "distinguished", "criticized", "limited", "overruled")
TREATMENT_MEANINGS = _meanings(
    good_law="No negative treatment.",
    distinguished="A later court declined to apply it on different facts.",
    criticized="A later court questioned its reasoning without departing from it.",
    limited="A later court narrowed it.",
    overruled="Overruled, reversed or vacated: no longer law.",
)


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Courts.
        _key(f"{COURT}.name", _text(256), "The court's slug (9th-cir, sdny); its key."),
        _field(f"{COURT}.title", _text(), "The court's full name."),
        _field(f"{COURT}.jurisdiction", _text(64), "The jurisdiction (federal, california)."),
        _field(
            f"{COURT}.level",
            _ranked("trial", "intermediate_appellate", "supreme"),
            "Where the court sits in its hierarchy, lowest first.",
        ),
        # Cases.
        _key(f"{CASE}.name", _text(256), "The case's slug (smith-v-acme); its key."),
        _field(f"{CASE}.caption", _text(), "The case caption (Smith v. Acme Corp.)."),
        _field(f"{CASE}.citation", _text(64), "The reporter citation (123 F.4th 456)."),
        _field(f"{CASE}.court", _subjects(COURT), "The court that decided it."),
        _field(f"{CASE}.decided_on", {"kind": "date"}, "The decision date."),
        _field(
            f"{CASE}.status",
            TREATMENT,
            "How later courts have treated the case, lowest first; cite the later opinion "
            "or citator report.",
            member_descriptions=TREATMENT_MEANINGS,
        ),
        # Holdings: one per (case, issue).
        _key(f"{HOLDING}.case", _subjects(CASE), "The case the holding comes from; a key part."),
        _key(
            f"{HOLDING}.issue",
            _text(64),
            "The issue the holding decides, as a short slug (duty-of-care); a key part.",
        ),
        _field(
            f"{HOLDING}.rule",
            _text(200),
            "The rule the holding states, in one sentence; the full analysis lives in the "
            "memo section the Claim cites.",
            role=DECIDED,
        ),
        _field(
            f"{HOLDING}.pin_cite",
            _text(64),
            "Where in the opinion the holding is stated (slip op. at 14).",
        ),
        _field(
            f"{HOLDING}.status",
            TREATMENT,
            "The researcher's verdict on whether this holding is still good law, lowest "
            "first. Pin it (based_on) to the case's status it was judged from.",
            role=DECIDED,
            member_descriptions=TREATMENT_MEANINGS,
        ),
        # Matters.
        _key(f"{MATTER}.name", _text(256), "The matter's slug; its key."),
        _field(f"{MATTER}.title", _text(), "The matter's short title.", role=DECIDED),
        _field(f"{MATTER}.forum", _subjects(COURT), "The court the matter is before.", role=DECIDED),
        _field(
            f"{MATTER}.stage",
            _ranked("intake", "pleadings", "discovery", "motions", "trial", "appeal", "closed"),
            "How far the matter has progressed, earliest first.",
            role=DECIDED,
        ),
        # Arguments.
        _key(
            f"{ARGUMENT}.name",
            _text(256),
            "The argument's slug, usually its brief section (motion-section-3b); its key.",
        ),
        _field(f"{ARGUMENT}.matter", _subjects(MATTER), "The matter it is made in.", role=DECIDED),
        _field(f"{ARGUMENT}.title", _text(), "The argument's heading.", role=DECIDED),
        _field(
            f"{ARGUMENT}.relies_on",
            _subjects(HOLDING),
            "A holding the argument relies on.",
            role=DECIDED,
            cardinality="many",
        ),
        _field(
            f"{ARGUMENT}.status",
            _enum("draft", "verified", "filed", "withdrawn"),
            "Where the argument stands. Pin a verified status (based_on) to the holdings "
            "it relies on, so a change to any of them flags it for re-verification.",
            role=DECIDED,
            member_descriptions=_meanings(
                draft="Still being written.",
                verified="Every authority checked at the pinned versions.",
                filed="Filed with the court.",
                withdrawn="No longer pressed.",
            ),
        ),
    ]


SUBJECT_KINDS = (
    (COURT, "A court, named by its slug.", [f"{COURT}.name"]),
    (CASE, "A decided case, named by its slug.", [f"{CASE}.name"]),
    (
        HOLDING,
        "One holding of a case on one issue, keyed by the case and issue.",
        [f"{HOLDING}.case", f"{HOLDING}.issue"],
    ),
    (MATTER, "A client matter or litigation, named by its slug.", [f"{MATTER}.name"]),
    (ARGUMENT, "An argument in a brief or memo, named by its slug.", [f"{ARGUMENT}.name"]),
)

AFFECTED_ARGUMENTS = {
    "query": "legal.affected_arguments",
    "description": "Arguments relying on a holding that is no longer fully good law.",
    "from": {"argument": ARGUMENT},
    "hops": [{"holding": f'argument.{ARGUMENT}.relies_on!: {HOLDING} where holding.status > "good_law"'}],
    "fields": [
        "argument.matter",
        "argument.status",
        "holding",
        {"holding_status": "holding.status"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

HOLDINGS_BY_CASE = {
    "query": "legal.holdings_by_case",
    "description": "The holdings recorded for one case, with their rule and status.",
    "params": {"case": "string"},
    "from": {"holding": HOLDING},
    "hops": [{"case": f"holding.{HOLDING}.case!: {CASE}"}],
    "where": "case.name == $case",
    "fields": ["holding.issue", "holding.rule", "holding.pin_cite", "holding.status"],
    "limit": 200,
    "max": {"results": 2000},
}

ARGUMENTS_BY_MATTER = {
    "query": "legal.arguments_by_matter",
    "description": "The arguments in one matter, with their status.",
    "params": {"matter": "string"},
    "from": {"argument": ARGUMENT},
    "hops": [{"matter": f"argument.{ARGUMENT}.matter!: {MATTER}"}],
    "where": "matter.name == $matter",
    "fields": ["argument.title", "argument.status"],
    "limit": 200,
    "max": {"results": 2000},
}

QUERIES = (AFFECTED_ARGUMENTS, HOLDINGS_BY_CASE, ARGUMENTS_BY_MATTER)


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"legal-research {VERSION}: courts, cases, holdings, matters and "
        "arguments.",
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
