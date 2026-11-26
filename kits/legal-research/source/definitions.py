"""The legal-research kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/legal-research SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

Facts about an opinion or statute (its citation, court, date, how later courts or
legislatures treated it) are ``observation`` and cite the opinion, statute, or citator
report. What a researcher concludes (a holding's rule, weight, and treatment verdict;
an argument's readiness) is ``normative`` and cites the opinion passage or memo section
it rests on. Prose stays in memos and briefs; Claims hold the verifiable structure, and
arguments pin (``based_on``) every relied-on and distinguished authority so any change
cascades directly to the arguments affected.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "legal-research"
VERSION = "2.0.0"
OWNS = ("legal.",)

CLIENT = "legal.client"
MATTER = "legal.matter"
COURT = "legal.court"
CASE = "legal.case"
HOLDING = "legal.holding"
STATUTE = "legal.statute"
ARGUMENT = "legal.argument"
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
    overruled="Overruled, reversed, or vacated: no longer law.",
)


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Clients.
        _key(f"{CLIENT}.name", _text(256), "The client's slug (acme-corp); its key."),
        _field(f"{CLIENT}.title", _text(), "The client's legal or display name.", role=DECIDED),
        _field(
            f"{CLIENT}.entity_type",
            _enum("individual", "corporation", "government", "nonprofit"),
            "What kind of legal entity the client is.",
            role=DECIDED,
        ),
        _field(
            f"{CLIENT}.status",
            _enum("prospective", "active", "former"),
            "Current engagement status of the client.",
            role=DECIDED,
        ),
        _field(
            f"{CLIENT}.conflict_status",
            _enum("pending", "cleared", "waived", "conflicted"),
            "Conflicts check standing for this client.",
            role=DECIDED,
            member_descriptions=_meanings(
                pending="Conflict check not yet completed.",
                cleared="No conflicts found.",
                waived="Conflict disclosed and waived in writing; cite the waiver.",
                conflicted="Representation barred by conflict.",
            ),
        ),
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
            "or citator report. Expires after 30 days so pre-filing citator checks stay current.",
            evidence_freshness={"stale_after": "P30D"},
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
            f"{HOLDING}.weight",
            _enum("holding", "dicta", "concurrence", "dissent"),
            "Intrinsic precedential role of the cited proposition within the opinion.",
            role=DECIDED,
            member_descriptions=_meanings(
                holding="Necessary to the court's judgment.",
                dicta="Non-binding remark in the majority opinion.",
                concurrence="Separate concurring opinion; note if controlling under Marks.",
                dissent="Dissenting opinion; persuasive only.",
            ),
        ),
        _field(
            f"{HOLDING}.status",
            TREATMENT,
            "The researcher's verdict on whether this holding is still good law, lowest "
            "first. Pin it (based_on) to the case's status it was judged from.",
            role=DECIDED,
            member_descriptions=TREATMENT_MEANINGS,
        ),
        # Statutes and regulations.
        _key(f"{STATUTE}.name", _text(256), "The statute's slug (15-usc-78j-b); its key."),
        _field(f"{STATUTE}.title", _text(), "Short title or section heading."),
        _field(f"{STATUTE}.citation", _text(64), "Official statutory or regulatory citation."),
        _field(f"{STATUTE}.jurisdiction", _text(64), "The enacting jurisdiction (federal, delaware)."),
        _field(
            f"{STATUTE}.status",
            _ranked("in_force", "amended", "enjoined", "repealed"),
            "Current force of the statute or regulation, ordered from in_force to repealed.",
            member_descriptions=_meanings(
                in_force="Currently enacted and in effect.",
                amended="Amended since last check; verify current statutory text.",
                enjoined="Enforcement enjoined or held unconstitutional in part or whole.",
                repealed="Repealed or superseded.",
            ),
        ),
        # Matters.
        _key(f"{MATTER}.name", _text(256), "The matter's slug; its key."),
        _field(f"{MATTER}.client", _subjects(CLIENT), "The client this matter is for.", role=DECIDED),
        _field(f"{MATTER}.title", _text(), "The matter's short title.", role=DECIDED),
        _field(f"{MATTER}.forum", _subjects(COURT), "The court the matter is before.", role=DECIDED),
        _field(
            f"{MATTER}.stage",
            _ranked("intake", "pleadings", "discovery", "motions", "trial", "appeal", "closed"),
            "How far the matter has progressed, earliest first.",
            role=DECIDED,
        ),
        # Arguments: scoped per (matter, name) so brief section slugs never collide across matters.
        _key(f"{ARGUMENT}.matter", _subjects(MATTER), "The matter the argument belongs to; a key part."),
        _key(
            f"{ARGUMENT}.name",
            _text(128),
            "The argument's slug within the matter (motion-section-3b); a key part.",
        ),
        _field(f"{ARGUMENT}.title", _text(), "The argument's heading.", role=DECIDED),
        _field(
            f"{ARGUMENT}.relies_on",
            _subjects(HOLDING, STATUTE),
            "A supporting holding or statute the argument relies on.",
            role=DECIDED,
            cardinality="many",
        ),
        _field(
            f"{ARGUMENT}.distinguishes",
            _subjects(HOLDING, STATUTE),
            "An adverse holding or statute that the argument distinguishes or addresses.",
            role=DECIDED,
            cardinality="many",
        ),
        _field(
            f"{ARGUMENT}.status",
            _enum("draft", "verified", "filed", "withdrawn"),
            "Where the argument stands. Pin a verified or filed status (based_on) to every "
            "relied-on and distinguished holding or statute status so any change flags it.",
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
    (CLIENT, "A client or represented entity, named by its slug.", [f"{CLIENT}.name"]),
    (COURT, "A court, named by its slug.", [f"{COURT}.name"]),
    (CASE, "A decided case, named by its slug.", [f"{CASE}.name"]),
    (
        HOLDING,
        "One holding of a case on one issue, keyed by the case and issue.",
        [f"{HOLDING}.case", f"{HOLDING}.issue"],
    ),
    (STATUTE, "A statute or regulation, named by its slug.", [f"{STATUTE}.name"]),
    (MATTER, "A client matter or litigation, named by its slug.", [f"{MATTER}.name"]),
    (
        ARGUMENT,
        "An argument in a brief or memo, keyed by its matter and section slug.",
        [f"{ARGUMENT}.matter", f"{ARGUMENT}.name"],
    ),
)

AFFECTED_ARGUMENTS = {
    "query": "legal.affected_arguments",
    "description": "Arguments relying on a holding that is no longer fully good law.",
    "from": {"argument": ARGUMENT},
    "hops": [
        {"holding": f'argument.{ARGUMENT}.relies_on!: {HOLDING} where holding.status > "good_law"'}
    ],
    "fields": [
        "argument.matter",
        "argument.title",
        "argument.status",
        "holding",
        {"holding_status": "holding.status"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

ARGUMENTS_TO_VERIFY = {
    "query": "legal.arguments_to_verify",
    "description": "Draft arguments in active matters (stage before closed) not yet verified.",
    "from": {"argument": ARGUMENT},
    "hops": [{"matter": f'argument.{ARGUMENT}.matter!: {MATTER} where matter.stage < "closed"'}],
    "where": 'argument.status == "draft"',
    "fields": [
        "argument.matter",
        "argument.title",
        "argument.status",
        {"matter_stage": "matter.stage"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

HOLDINGS_BY_CASE = {
    "query": "legal.holdings_by_case",
    "description": "The holdings recorded for one case, with their rule, weight and status.",
    "params": {"case": "string"},
    "from": {"holding": HOLDING},
    "hops": [{"case": f"holding.{HOLDING}.case!: {CASE}"}],
    "where": "case.name == $case",
    "fields": [
        "holding.issue",
        "holding.rule",
        "holding.pin_cite",
        "holding.weight",
        "holding.status",
    ],
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

MATTERS_BY_CLIENT = {
    "query": "legal.matters_by_client",
    "description": "The matters opened for one client, with their forum and stage.",
    "params": {"client": "string"},
    "from": {"matter": MATTER},
    "hops": [{"client": f"matter.{MATTER}.client!: {CLIENT}"}],
    "where": "client.name == $client",
    "fields": ["matter.title", "matter.forum", "matter.stage"],
    "limit": 200,
    "max": {"results": 2000},
}

QUERIES = (
    AFFECTED_ARGUMENTS,
    ARGUMENTS_TO_VERIFY,
    HOLDINGS_BY_CASE,
    ARGUMENTS_BY_MATTER,
    MATTERS_BY_CLIENT,
)


def guidance_documents(store_body: Callable[[Path], str]) -> list[dict[str, Any]]:
    path = SOURCE_DIR / "guidance" / "review-guidance.md"
    title = path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
    guided = (
        f"ClaimType:{HOLDING}.rule",
        f"ClaimType:{HOLDING}.weight",
        f"ClaimType:{HOLDING}.status",
        f"ClaimType:{ARGUMENT}.status",
    )
    return [
        {
            "kind": "document",
            "identity": "document:legal.guidance.review-guidance",
            "document_kind": "legal.guidance",
            "title": title,
            "media_type": "text/markdown",
            "body_digest": store_body(path),
            "links": [
                {"relation": "guides", "target_identity": target}
                for target in sorted(guided, key=lambda item: item.encode("utf-8"))
            ],
            "governance_scope": ["legal"],
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
        "rationale": f"legal-research {VERSION}: clients, courts, cases, holdings, statutes, "
        "matters and arguments.",
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
