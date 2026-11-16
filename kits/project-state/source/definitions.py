"""The project-state kit's definitions, as authored inputs.

Rebuild the kit from here with
``python scripts/build_kit.py kits/project-state SCRATCH`` (see that script).
Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the client's
``lower_claim_type_input``. 1.0.0 declared no SubjectKinds, defaults or
descriptions; this keeps it so, stating ``evidence_requirement: self`` (the rules
decide, as 1.0.0's types had no requirement of their own).

Where the current core cannot say what 1.0.0 said:

- 1.0.0's rules each named one workspace file's own source contract
  (``agent-reports``, ``program-register``, ``feedback-*``, ``program-*`` ...).
  A kit cannot ship an adopter's per-file contracts, so those rules become one
  ``file`` rule admitting any catalogued workspace file
  (``capture_contract_families: [workspace_file]``).
- ``exact_content`` values are retired (prose lives in Documents), and a string
  ClaimType holds at most 256 characters. ``dev.decision.ruling``,
  ``dev.law.text`` and ``dev.program.prose`` become strings of at most 256
  characters that keep their file rule, so the full prose is the passage a Claim
  cites; every other free-text string 1.0.0 left unbounded is bounded at 256.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "project-state"
VERSION = "1.1.0"
OWNS = ("dev.", "project.")

SELF = "playbill.coordinator-self-source-v1"
SHA = "^[0-9a-f]{40}$"


def _self(rule_id: str, roles: list[str]) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "claim_roles": roles,
        "capture_contracts": [SELF],
        "admission": "direct",
        "attestation_requirement": "none",
        "subject_binding": "exact_claim_subject",
    }


def _file(roles: list[str]) -> dict[str, Any]:
    return {
        "rule_id": "file",
        "claim_roles": roles,
        "capture_contract_families": ["workspace_file"],
        "admission": "direct",
        "attestation_requirement": "none",
        "subject_binding": "exact_claim_subject",
    }


def _type(
    predicate: str,
    value: dict[str, Any],
    roles: list[str],
    rules: list[dict[str, Any]],
    *,
    cardinality: str = "one",
    **more: Any,
) -> dict[str, Any]:
    return {
        "predicate": predicate,
        "cardinality": cardinality,
        "value": value,
        "permitted_roles": roles,
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": rules},
        **more,
    }


def _text(**more: Any) -> dict[str, Any]:
    """Non-empty text; a string ClaimType is bounded at 256 characters at most."""

    return {"kind": "string", "min_len": 1, "max_len": 256, **more}


def _enum(*members: str) -> dict[str, Any]:
    return {"kind": "enum", "members": list(members)}


def _subjects(*kinds: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kinds": list(kinds)}


OBSERVED = ["observation"]
NORMATIVE = ["normative"]


def _reported(predicate: str, value: dict[str, Any], **more: Any) -> dict[str, Any]:
    """An observation read from the project's own files (1.0.0: agent reports,
    dispatch contracts, friction logs, the program register)."""

    return _type(predicate, value, OBSERVED, [_file(OBSERVED)], **more)


def _recorded(predicate: str, **more: Any) -> dict[str, Any]:
    """Normative prose a project file states (1.0.0: exact_content from those files)."""

    return _type(predicate, _text(), NORMATIVE, [_file(NORMATIVE)], **more)


def _recommended(predicate: str, value: dict[str, Any] | None = None) -> dict[str, Any]:
    """A roadmap item's authored recommendation field, in the author's own words."""

    return _type(
        predicate, value or _text(), NORMATIVE, [_self("author-recommendation", NORMATIVE)]
    )


def _attributed(
    predicate: str, value: dict[str, Any], roles: list[str], **more: Any
) -> dict[str, Any]:
    return _type(predicate, value, roles, [_self("attributed-author-account", roles)], **more)


def claim_type_records() -> list[dict[str, Any]]:
    both = ["normative", "observation"]
    return [
        _reported("dev.batch.belongs_to_track", _subjects("dev.track")),
        _reported("dev.batch.blocked_by", _subjects("dev.batch"), cardinality="many"),
        _reported("dev.batch.landed_at", {"kind": "string", "pattern": SHA, "max_len": 40}),
        _reported(
            "dev.batch.state",
            _enum(
                "planned",
                "dispatched",
                "returned",
                "reviewed",
                "landed",
                "certified",
                "abandoned",
            ),
        ),
        _reported(
            "dev.batch.tip", {"kind": "string", "pattern": SHA, "max_len": 40}, cardinality="many"
        ),
        _reported(
            "dev.batch.verdict", _enum("accept", "accept_with_fixes", "reject"), cardinality="many"
        ),
        _reported("dev.card.closed_by", _subjects("dev.batch")),
        _reported("dev.card.disposition", _enum("open", "closed", "deferred")),
        _reported("dev.card.lane", {"kind": "string", "min_len": 1, "max_len": 64}),
        _reported("dev.decision.decided_in", _subjects("dev.batch")),
        _recorded("dev.decision.ruling"),
        _reported(
            "dev.decision.standing",
            _enum("proposed", "deferred", "ratified", "retracted", "superseded"),
        ),
        _reported("dev.law.origin", _subjects("dev.batch", "dev.card")),
        _recorded("dev.law.text"),
        _type(
            "dev.product_feedback.finding_text",
            _text(),
            both,
            [_self("attributed-author-account", both), _file(both)],
        ),
        _attributed(
            "dev.product_feedback.follow_up",
            _subjects("dev.roadmap_item"),
            NORMATIVE,
            cardinality="many",
        ),
        _recorded("dev.program.prose", cardinality="many", allowed_subject_kinds=["dev.track"]),
        _type(
            "dev.recommendation.rationale",
            _text(),
            NORMATIVE,
            [_self("authored-recommendation", NORMATIVE)],
        ),
        _type(
            "dev.recommendation.rule",
            _text(),
            NORMATIVE,
            [_self("authored-recommendation", NORMATIVE)],
        ),
        _recommended(
            "dev.roadmap_item.adoption_state", _enum("proposed", "adopted", "deferred", "rejected")
        ),
        _recommended("dev.roadmap_item.audit_baseline"),
        _recommended("dev.roadmap_item.completion_criterion"),
        _recommended("dev.roadmap_item.historical_audit_class"),
        _attributed(
            "dev.roadmap_item.implementation_state",
            _enum("not_started", "partial", "completed", "blocked"),
            OBSERVED,
        ),
        _recommended("dev.roadmap_item.justification"),
        _recommended("dev.roadmap_item.original_recommendation"),
        _recommended("dev.roadmap_item.proposed_release", _enum("OSS v1", "Managed v1", "Post-v1")),
        _recommended("dev.roadmap_item.reconciliation_note"),
        _attributed(
            "dev.roadmap_item.refines",
            _subjects("dev.roadmap_item"),
            NORMATIVE,
            cardinality="many",
        ),
        _recommended("dev.roadmap_item.strategic_bucket"),
        _recommended("dev.roadmap_item.task_title"),
        _reported("dev.track.status", _enum("open", "blocked", "done", "parked")),
    ]


ROADMAP_MEMBERSHIP = {
    "query": "project.roadmap-membership",
    "description": "All retained project roadmap Subjects; watch membership so newly added "
    "work cannot silently disappear from repo views.",
    "from": {"item": "dev.roadmap_item"},
    "fields": [],
    "limit": 1000,
    "max": {"results": 1000},
}


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"project-state {VERSION}: the 1.0.0 definitions in the current formats.",
        "members": [
            *(
                {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
                for t in claim_types
            ),
            {"kind": "query_definition", "query_definition": ROADMAP_MEMBERSHIP},
        ],
    }
