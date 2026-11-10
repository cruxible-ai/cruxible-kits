"""Codebase facts (``security.code_fact``) and the judgments that rest on them.

A codebase fact is one thing true of a repository's code that security
judgments rest on ("every /api route passes through the auth middleware"). An
agent records one when a judgment rests on something true beyond the passage it
judges, and establishing it took real reading or more than one judgment rests
on it, so the next session reads it instead of re-deriving it. It is not a file
map or an architecture document: expect tens per repository.

The design rule, here as everywhere in the kit: a short label that identifies a
thing is a typed key; anything compared is an enum, a reference or a number;
anything that argues goes in a notes document a Claim cites. No Claim value is
free prose.

- ``security.code_fact`` is keyed by ``repo`` (host/owner/repo, as a finding's)
  and ``topic`` (a short stable slug in the agent's words, such as
  ``authn-middleware``, spelled the same every run), as a coverage unit is.
- ``category``: ``control``, ``invariant``, ``boundary`` or ``hazard`` (not
  ``kind``: core's read verbs reserve that field name). It cites the
  notes section that states the fact, where it holds and its known exceptions
  (a section the same write appends counts as the agent's own words).
- ``holds``: ``yes``, ``partly`` or ``no``, citing the code passage that decides
  it (a catalogued workspace file; own words are refused). It drifts when that
  passage changes. Never settled by a Mandate. One write cannot cite two files
  on one Claim (a write change carries one ``evidence``), so the notes section
  is cited by ``category`` in the same write.
- ``rests_on`` (many, on a finding, an app exposure and a coverage unit): this
  judgment was made in light of that fact, shaped like ``found_in``.

Core does not act on ``rests_on``. When a fact comes back in ``next`` because
its cited code changed, the judgments resting on it do not come back with it:
an agent runs ``security.*_resting_on`` for that fact. The engine has no union,
so there is one Query per judging kind. ``security.*_on_weakened_facts`` lists,
for one repository, each judgment resting on at least one fact whose resolved
``holds`` is ``no`` or ``partly`` (a contested ``holds`` is no resolved value),
once however many such facts it rests on; ``security.weakened_causes_of_*``
lists the (judgment, weakened fact) pairs, the causes.

The fact kind, its ClaimTypes and ``app_exposure.rests_on`` install with the
dependency vocabulary (:func:`dependency_members`); ``finding.rests_on`` and
``coverage_unit.rests_on`` install with the audit vocabulary
(:func:`audit_members`), after the kinds they name.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input

CODE_FACT = "security.code_fact"
FINDING = "security.finding"
APP_EXPOSURE = "security.app_exposure"
UNIT = "security.coverage_unit"
SELF_SOURCE = "cruxible.coordinator-self-source-v1"

FACT_KINDS = ["control", "invariant", "boundary", "hazard"]
HOLDS = ["yes", "partly", "no"]
#: A fact whose resolved ``holds`` is one of these is weakened.
WEAKENED = ("no", "partly")
#: The kinds whose judgments may rest on a fact.
JUDGING_KINDS = (FINDING, APP_EXPOSURE, UNIT)

FACTS_QUERY = "security.code_facts"
FACT_ROW = "security.code-fact-row"
RESTING_ROW = "security.resting-judgment"
DEPENDENT_ROW = "security.weakened-dependent"
#: Per judging kind: the Query of judgments resting on one fact; of the judgments
#: resting on a weakened fact of one repository, once each; and of each (judgment,
#: weakened fact) pair, the causes.
RESTING_ON = {
    FINDING: "security.findings_resting_on",
    APP_EXPOSURE: "security.app_exposures_resting_on",
    UNIT: "security.coverage_units_resting_on",
}
ON_WEAKENED = {
    FINDING: "security.findings_on_weakened_facts",
    APP_EXPOSURE: "security.app_exposures_on_weakened_facts",
    UNIT: "security.coverage_units_on_weakened_facts",
}
WEAKENED_CAUSES = {
    FINDING: "security.weakened_causes_of_findings",
    APP_EXPOSURE: "security.weakened_causes_of_app_exposures",
    UNIT: "security.weakened_causes_of_coverage_units",
}

_REPO_PATTERN = "^[a-z0-9.-]+/[^/\\s]+/[^/\\s]+$"
_TOPIC_PATTERN = "^[a-z0-9]+(-[a-z0-9]+)*$"
_MANY = {"cardinality": "many", "eligible_verdicts": ["supported"], "selector": "all"}


def _rule(rule_id: str, roles: Sequence[str], kind: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "claim_roles": list(roles),
        "capture_contracts": [kind],
        "admission": "direct",
        "subject_binding": "exact_claim_subject",
    }


def _file_rule() -> dict[str, Any]:
    """Any catalogued workspace file (the ``workspace_file`` family, D1)."""

    return {
        "rule_id": "file",
        "claim_roles": ["normative"],
        "capture_contract_families": ["workspace_file"],
        "admission": "direct",
        "subject_binding": "exact_claim_subject",
    }


def fact_claim_type_records() -> list[dict[str, Any]]:
    """The fact's keys, its category and whether it holds."""

    return [
        {
            "predicate": CODE_FACT + ".repo",
            "allowed_subject_kinds": [CODE_FACT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256, "pattern": _REPO_PATTERN},
            "description": "The repository as host/owner/repo, casefolded (as a finding's "
            "repo); with topic, the fact's key.",
        },
        {
            "predicate": CODE_FACT + ".topic",
            "allowed_subject_kinds": [CODE_FACT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 64, "pattern": _TOPIC_PATTERN},
            "description": "What the fact is about, as a short stable slug in the agent's "
            "words (authn-middleware, sql-parameterisation, tenant-id-source), spelled the "
            "same every run; with repo, the fact's key.",
        },
        {
            "predicate": CODE_FACT + ".category",
            "allowed_subject_kinds": [CODE_FACT],
            "cardinality": "one",
            "value": {"kind": "enum", "members": FACT_KINDS},
            "description": "What sort of fact it is. Cites the notes section stating the "
            "fact, where it holds and its known exceptions. Never settled by a Mandate.",
            "member_descriptions": [
                {"member": "control", "description": "Something enforces it."},
                {"member": "invariant", "description": "True by construction."},
                {
                    "member": "boundary",
                    "description": "Where untrusted input enters or trust changes.",
                },
                {
                    "member": "hazard",
                    "description": "A dangerous helper or sink whose callers need checking.",
                },
            ],
            "permitted_roles": ["normative"],
            "default_role": "normative",
            "evidence_requirement": "self",
            "revision_evidence": "replace",
            # Rules sorted by rule_id: a notes section (file), or own words (self).
            "evidence_admission_policy": {
                "rules": [_file_rule(), _rule("self", ["normative"], SELF_SOURCE)]
            },
        },
        {
            "predicate": CODE_FACT + ".holds",
            "allowed_subject_kinds": [CODE_FACT],
            "cardinality": "one",
            "value": {"kind": "enum", "members": HOLDS},
            "description": "Whether the fact holds in the code, citing the passage that "
            "decides it (path#anchor); it drifts when that passage changes. Never settled by "
            "a Mandate.",
            "member_descriptions": [
                {"member": "yes", "description": "Holds wherever the notes say it applies."},
                {"member": "partly", "description": "Holds, with exceptions the notes name."},
                {"member": "no", "description": "Does not hold: the code contradicts it."},
            ],
            "permitted_roles": ["normative"],
            "default_role": "normative",
            # Evidence required: the code passage, a catalogued workspace file.
            "evidence_requirement": "captured",
            "revision_evidence": "replace",
            "evidence_admission_policy": {"rules": [_file_rule()]},
        },
    ]


def rests_on_record(kind: str) -> dict[str, Any]:
    """``<kind>.rests_on``: a judgment made in light of a fact (shaped like found_in)."""

    return {
        "predicate": f"{kind}.rests_on",
        "allowed_subject_kinds": [kind],
        "cardinality": "many",
        "value": {"kind": "subject", "subject_kinds": [CODE_FACT]},
        "description": "A codebase fact this judgment was made in light of. Core does not "
        "act on it: when the fact changes, run the resting_on Query for it. Never settled "
        "by a Mandate.",
        "permitted_roles": ["normative"],
        "default_role": "normative",
        "evidence_requirement": "self",
        "revision_evidence": "replace",
        "evidence_admission_policy": {"rules": [_rule("self", ["normative"], SELF_SOURCE)]},
        "resolution_policy": _MANY,
    }


def claim_type_records() -> list[dict[str, Any]]:
    """Every ClaimType this module declares (both vocabularies)."""

    return [*fact_claim_type_records(), *(rests_on_record(kind) for kind in JUDGING_KINDS)]


def _claim_type_members(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "kind": "claim_type",
            "claim_type": lower_claim_type_input(
                ClaimTypeInputRecord.model_validate(record), tree={}
            ).model_dump(mode="json", by_alias=True),
        }
        for record in records
    ]


def _resting_fields() -> list[Any]:
    return [
        {"judgment_kind": "j.subject_kind"},
        {"judgment": "j.subject_id"},
        {"fact": "x.subject_id"},
        "x.topic",
        "x.holds",
    ]


def resting_on_spec(kind: str) -> dict[str, Any]:
    """The judgments of ``kind`` resting on one fact: its reverse ``rests_on`` links."""

    return {
        "query": RESTING_ON[kind],
        "description": f"The {kind} judgments resting on one codebase fact (rests_on): "
        "read them again when the fact changes or stops holding.",
        "params": {"fact": "subject"},
        "from": {"x": f"{CODE_FACT} = $fact"},
        "hops": [{"j": f"<x.{kind}.rests_on!: {kind}"}],
        "row": f"{RESTING_ROW}@1",
        "fields": _resting_fields(),
        "order": ["j.subject_id"],
    }


def _weakened(kind: str) -> dict[str, Any]:
    """The walk both weakened views share: the facts of one repository whose resolved
    ``holds`` is no or partly (a contested or absent ``holds`` is no resolved
    value), then the ``kind`` judgments resting on each."""

    weakened = ", ".join(json.dumps(value) for value in WEAKENED)
    return {
        "params": {"repo": "string"},
        "from": {"x": CODE_FACT},
        "where": f"x.repo == $repo and x.holds in ({weakened})",
        "hops": [{"j": f"<x.{kind}.rests_on!: {kind}"}],
    }


def weakened_causes_spec(kind: str) -> dict[str, Any]:
    """Each (``kind`` judgment, weakened fact) pair of one repository: the causes."""

    return {
        "query": WEAKENED_CAUSES[kind],
        "description": f"Each {kind} judgment and a codebase fact of one repository it rests "
        "on that holds only partly or not at all: one row per (judgment, fact), the causes "
        f"behind {ON_WEAKENED[kind]}.",
        **_weakened(kind),
        "row": f"{RESTING_ROW}@1",
        "fields": _resting_fields(),
        "order": ["j.subject_id", "x.topic"],
    }


def on_weakened_spec(kind: str) -> dict[str, Any]:
    """The ``kind`` judgments resting on at least one weakened fact of one repository,
    once each: the same walk, deduplicated by the judgment (the result binding)."""

    return {
        "query": ON_WEAKENED[kind],
        "description": f"Each {kind} judgment resting on at least one codebase fact of one "
        "repository that holds only partly or not at all, once however many: read it again. "
        f"The facts behind each are in {WEAKENED_CAUSES[kind]}.",
        **_weakened(kind),
        "row": f"{DEPENDENT_ROW}@1",
        "fields": [{"judgment_kind": "j.subject_kind"}, {"judgment": "j.subject_id"}],
    }


def on_weakened_definition(kind: str) -> dict[str, Any]:
    """:func:`on_weakened_spec` lowered and made Subject-shaped on the judgment: Subject
    dedupe keyed on ``j``, so a judgment resting on two weakened facts is one row."""

    import inventory
    from definitions import subject_shaped

    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    kinds = [
        {
            "kind": "subject_kind",
            "name": CODE_FACT,
            "keys": [CODE_FACT + ".repo", CODE_FACT + ".topic"],
        },
        {
            "kind": "subject_kind",
            "name": FINDING,
            "keys": [f"{FINDING}.{part}" for part in ("repo", "weakness", "locus")],
        },
        {
            "kind": "subject_kind",
            "name": UNIT,
            "keys": [f"{UNIT}.{part}" for part in ("repo", "surface", "concern")],
        },
        *(m for m in inventory.subject_kind_members() if m["name"] == APP_EXPOSURE),
    ]
    return subject_shaped(
        on_weakened_spec(kind), claim_types, result_binding="j", subject_kinds=kinds
    )


FACTS_SPEC: dict[str, Any] = {
    "query": FACTS_QUERY,
    "description": "The codebase facts of one repository: topic, category and whether each "
    "holds. Read them before re-deriving how the code does something.",
    "params": {"repo": "string"},
    "from": {"f": CODE_FACT},
    "where": "f.repo == $repo",
    "row": f"{FACT_ROW}@1",
    "fields": [{"fact": "f.subject_id"}, "f.topic", "f.category", "f.holds"],
    "order": ["f.topic"],
}


def _query(spec: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "query_definition", "query_definition": spec}


def dependency_members() -> list[dict[str, Any]]:
    """With the dependency vocabulary: the fact kind and its ClaimTypes,
    ``app_exposure.rests_on``, the row Contracts and the fact and app-exposure Queries."""

    return [
        {
            "kind": "contract",
            "name": FACT_ROW,
            "version": 1,
            "description": "One codebase fact: its Subject id, topic, category and whether it "
            "holds.",
            "fields": {
                "fact": "string",
                "topic": "string",
                "category": f"enum_of {CODE_FACT}.category?",
                "holds": f"enum_of {CODE_FACT}.holds?",
            },
        },
        {
            "kind": "contract",
            "name": DEPENDENT_ROW,
            "version": 1,
            "description": "One judgment resting on at least one weakened codebase fact: its "
            "Subject (kind and id).",
            "fields": {"judgment_kind": "string", "judgment": "string"},
        },
        {
            "kind": "contract",
            "name": RESTING_ROW,
            "version": 1,
            "description": "One judgment resting on a codebase fact: the judgment's Subject "
            "(kind and id) and the fact (id, topic, holds).",
            "fields": {
                "judgment_kind": "string",
                "judgment": "string",
                "fact": "string",
                "topic": "string",
                "holds": f"enum_of {CODE_FACT}.holds?",
            },
        },
        *_claim_type_members(fact_claim_type_records()),
        {
            "kind": "subject_kind",
            "name": CODE_FACT,
            "description": "One thing true of a repository's code that security judgments rest on.",
            "keys": [CODE_FACT + ".repo", CODE_FACT + ".topic"],
        },
        *_claim_type_members([rests_on_record(APP_EXPOSURE)]),
        _query(FACTS_SPEC),
        _query(resting_on_spec(APP_EXPOSURE)),
        _query(on_weakened_definition(APP_EXPOSURE)),
        _query(weakened_causes_spec(APP_EXPOSURE)),
    ]


def audit_members() -> list[dict[str, Any]]:
    """With the audit vocabulary: ``rests_on`` on findings and coverage units, and
    their Queries."""

    return [
        *_claim_type_members([rests_on_record(FINDING), rests_on_record(UNIT)]),
        *(_query(resting_on_spec(kind)) for kind in (FINDING, UNIT)),
        *(_query(on_weakened_definition(kind)) for kind in (FINDING, UNIT)),
        *(_query(weakened_causes_spec(kind)) for kind in (FINDING, UNIT)),
    ]
