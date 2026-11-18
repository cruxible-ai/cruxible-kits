"""The project-state kit's definitions, as authored inputs.

Rebuild the kit from here with
``python scripts/build_kit.py kits/project-state SCRATCH`` (see that script).
Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the client's
``lower_claim_type_input``. 1.0.0's fields keep its lack of defaults and
descriptions, stating ``evidence_requirement: self`` (the rules decide, as 1.0.0's
types had no requirement of their own).

1.0.0 declared no SubjectKinds; Cruxible 0.5 creates a Subject only of a declared
kind. 2.0.0 declares each kind, keyed by a new ``slug`` key ClaimType: every kind
is named by a short slug in the project's own files (batch, card and decision
ids, roadmap item names), so none is minted.

Where the current core cannot say what 1.0.0 said:

- 1.0.0's rules each named one workspace file's own source contract
  (``agent-reports``, ``program-register``, ``feedback-*``, ``program-*`` ...).
  A kit cannot ship an adopter's per-file contracts, and since core PR #32 it
  authors no family-only rule either (``cruxible.claim_type.family_rule_not_authored``):
  those fields state no rules and take the core's default, which admits own
  words and any catalogued workspace file or section. 1.0.0 admitted only the
  files; own words are now admitted too, as on every field that does not require
  captured evidence.
- 1.0.0's authored fields (the roadmap item's recommendation fields, a
  recommendation's rationale and rule, feedback follow-ups, ``refines`` and
  ``implementation_state``) admitted only the author's own words. Under the
  current core a file or section citation is admitted wherever own words are, so
  they too state no rules and take the core's default. No field of this kit
  requires captured evidence.
- ``exact_content`` values are retired (prose lives in Documents), and a string
  ClaimType holds at most 256 characters. ``dev.decision.ruling``,
  ``dev.law.text`` and ``dev.program.prose`` become strings of at most 256
  characters that cite a file, so the full prose is the passage a Claim
  cites, as a short summary citing a Document section; every other free-text
  string 1.0.0 left unbounded is bounded at 256.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "project-state"
VERSION = "2.0.0"
OWNS = ("dev.", "project.")

SHA = "^[0-9a-f]{40}$"


def _type(
    predicate: str,
    value: dict[str, Any],
    roles: list[str],
    rules: list[dict[str, Any]] | None,
    *,
    cardinality: str = "one",
    **more: Any,
) -> dict[str, Any]:
    """``rules=None`` states none: the core's default admits own words and
    workspace file and section citations."""

    return {
        "predicate": predicate,
        "cardinality": cardinality,
        "value": value,
        "permitted_roles": roles,
        "evidence_requirement": "self",
        **({} if rules is None else {"evidence_admission_policy": {"rules": rules}}),
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

    return _type(predicate, value, OBSERVED, None, **more)


def _recorded(predicate: str, **more: Any) -> dict[str, Any]:
    """Normative prose a project file states (1.0.0: exact_content from those files)."""

    return _type(predicate, _text(), NORMATIVE, None, **more)


def _recommended(predicate: str, value: dict[str, Any] | None = None) -> dict[str, Any]:
    """A roadmap item's authored recommendation field (1.0.0: the author's own words
    only)."""

    return _type(predicate, value or _text(), NORMATIVE, None)


def _attributed(
    predicate: str, value: dict[str, Any], roles: list[str], **more: Any
) -> dict[str, Any]:
    """An authored account (1.0.0: the author's own words only)."""

    return _type(predicate, value, roles, None, **more)


#: Each kind and what one is; each is keyed by its ``slug``.
KINDS = (
    ("dev.batch", "A batch of work dispatched, reviewed and landed, named by its slug."),
    ("dev.card", "A review card, named by its slug."),
    ("dev.decision", "A decision, named by its slug."),
    ("dev.law", "A standing project law, named by its slug."),
    ("dev.product_feedback", "A product feedback finding, named by its slug."),
    ("dev.recommendation", "A recommendation, named by its slug."),
    ("dev.roadmap_item", "A roadmap item, named by its slug."),
    ("dev.track", "A track of work batches belong to, named by its slug."),
)


def _slug(kind: str) -> dict[str, Any]:
    """A kind's key: the slug that names it; a key needs no evidence rules."""

    return {
        "predicate": f"{kind}.slug",
        "cardinality": "one",
        "value": _text(),
        "default_role": "normative",
        "permitted_roles": NORMATIVE,
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": []},
        "description": "The slug; its key.",
    }


def claim_type_records() -> list[dict[str, Any]]:
    both = ["normative", "observation"]
    return [
        *(_slug(kind) for kind, _ in KINDS),
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
            None,
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
            None,
        ),
        _type(
            "dev.recommendation.rule",
            _text(),
            NORMATIVE,
            None,
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
        "rationale": f"project-state {VERSION}: the 1.0.0 definitions in the current formats, "
        "with a SubjectKind per kind keyed by its slug.",
        "members": [
            *(
                {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
                for t in claim_types
            ),
            *(
                {
                    "kind": "subject_kind",
                    "name": kind,
                    "description": description,
                    "keys": [f"{kind}.slug"],
                }
                for kind, description in KINDS
            ),
            {"kind": "query_definition", "query_definition": ROADMAP_MEMBERSHIP},
        ],
    }
