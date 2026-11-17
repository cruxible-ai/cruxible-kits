"""The security kit's code-findings loop (kit batch 2): SARIF -> findings -> agents judge.

Everything is in the Procedure template form (D-R37). Two Procedures, one
terminal each:

- ``security.sarif-import``: read (the findings held for the Line's repository)
  -> fetch (core's builtin ``workspace.file`` reads the SARIF file) -> derive
  (``sarif.findings``, pure, ``security-sarif-provider``) -> extract
  ``/findings/*`` -> claims on ``security.finding`` (``create: if_absent``).
  ``expect`` is the derived header's ``covered``: the held findings whose rule
  set a FULL scan ran. A covered finding the scan no longer reports is a
  ``fixed`` record (a declared derive rule over typed facts, M1(2));
  ``verification`` lists ``fixed`` in ``requires_complete_input``, so an
  incomplete read never writes it; ``reported_at`` mirrors, so a fixed
  finding's last location retires with the complete read as witness. A
  partial scan covers nothing and never marks anything fixed.
- ``security.sarif-attention``: the same derived document, on its landing
  (a ``capture_landing`` Trigger on ``security.sarif-findings``; the derive is
  substituted, never re-run) -> extract ``/attention/*`` -> inbox. Regressions
  (a held ``fixed`` finding reported again) and location gaps (a result with
  no repository path or no stable locator) reach the Line inbox as typed
  ``security.sarif-attention@1`` items. This is the template-correct route: a
  Procedure has one terminal, so claims and inbox egress are two Procedures
  composed through the derived Capture (Q3), and neither a regression nor a
  gap is a core finding kind.

Agents judge findings with normative Claims in their own words: ``verdict``,
``justification`` and ``fixed_by``. ``severity`` is the scan's observation or an
agent's normative judgment; a later scan that disagrees records
``held_disagrees`` (routed to the import Line's inbox) and never overrides it.

    python findings.py OUT_DIR --repo NAME=host/owner/repo=RELATIVE_PATH ...
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cruxible_client.contracts.authoring.inputs import ChangeSetInput, ProcedureInput
from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input

from capabilities import HELD_ROW, SARIF_FINDINGS as SARIF_FINDINGS_CAPABILITY
from capabilities import WORKSPACE_FILE as WORKSPACE_FILE_CAPABILITY
from capabilities import capability, pinned_layout
from definitions import FINDINGS, params_contract, params_contract_members, refs

FINDING = "security.finding"
#: The SARIF file as read (core's builtin workspace.file), decoded as JSON.
SARIF_KIND = "security.sarif-log"
#: The derived document sarif.findings emits (D-R37 derive; c5: the kit declares it).
FINDINGS_KIND = "security.sarif-findings"
FINDING_ROW = "security.sarif-finding"
ATTENTION_ROW = "security.sarif-attention-record"
ATTENTION_ITEM = "security.sarif-attention"
#: The item Contract version the attention Lines post: version 2 types the finding
#: key parts as references and describes each field; version 1 stays accepted as its
#: predecessor. Item identity is the Line, posting step and ``ref``, so it holds.
ATTENTION_ITEM_VERSION = 2
HELD_QUERY = "security.sarif_held_findings"
VERDICTS_QUERY = "security.finding_verdicts"
VERDICT_ROW = "security.finding-verdict"
IMPORT_PROCEDURE = "security.sarif-import"
ATTENTION_PROCEDURE = "security.sarif-attention"
IMPORT_LINE = "security.sarif-import"
ATTENTION_LINE = "security.sarif-attention"
SARIF_SOURCE = "sarif"
WORKSPACE_FILE = "cruxible-builtin#workspace.file"
SARIF_FINDINGS = "security-sarif-provider#sarif.findings"
PROVIDER_PACKAGE = "security-sarif-provider"
SELF_SOURCE = "cruxible.coordinator-self-source-v1"
PROVIDER_ROOT = (
    Path(__file__).resolve().parents[1]
    / "providers"
    / PROVIDER_PACKAGE
    / "src"
    / "security_sarif_provider"
)

#: Security audits (K-CA1..K-CA4): what was checked, and where agents' findings were found.
UNIT = "security.coverage_unit"
COVERAGE_STATUSES = ["checked", "deferred", "blocked", "out_of_scope"]
#: The statuses an audit plan re-opens (K-CA3): a unit never checked, deferred or blocked.
OPEN_STATUSES = ("deferred", "blocked")
COVERAGE_PLAN_QUERY = "security.coverage_plan"
FINDINGS_BY_UNIT_QUERY = "security.findings_by_unit"
PLAN_ROW = "security.coverage-plan-row"
UNIT_FINDING_ROW = "security.unit-finding"
#: ``reported_by`` for a finding an audit agent reports (hunter guidance).
AUDIT_REPORTER = "audit"

SEVERITIES = ["low", "medium", "high", "critical"]
VERIFICATIONS = ["present", "fixed"]
VERDICTS = ["confirmed", "false_positive", "not_exploitable"]
JUSTIFICATIONS = [
    "no_boundary_crossed",
    "not_attacker_controlled",
    "not_reachable",
    "rule_misfire",
    "sanitized",
    "test_or_dead_code",
]

#: ``min_len: 1``: sent as workspace.file@1's ``relative_path``, which is never empty.
_PATH = 'string{min_len: 1, max_len: 256, pattern: "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_REPO_PATTERN = "^[a-z0-9.-]+/[^/\\s]+/[^/\\s]+$"
_REPO = f'string{{max_len: 256, pattern: "{_REPO_PATTERN.replace(chr(92), chr(92) * 2)}"}}'
_ATTENTION_KINDS = 'enum["location_gap", "regression"]'
_ATTENTION_ITEM_DESCRIPTION = (
    "A code-findings item for an agent: a regression (a finding verified fixed that a "
    "scan reports again) or a location gap (a result with no repository path or no "
    "stable locator, so it is no finding yet)."
)
_WEAKNESS_PATTERN = "^(CWE-[0-9]{1,6}|RULE:\\S{1,240})$"
_TOOL_PATTERN = "^[0-9a-z][0-9a-z._-]{0,63}$"
_TOOL = f'string{{max_len: 64, pattern: "{_TOOL_PATTERN}"}}'
#: A canonical code reference: ``path#symbol`` or ``path#<route>`` (one line).
_SURFACE_PATTERN = "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}#[^\\r\\n]{1,240}$"
_CONCERN_PATTERN = "^[^\\r\\n]{1,128}$"


# -- 1. CaptureKinds ------------------------------------------------------------------


def _json_decoding(max_bytes: int, records: int, depth: int) -> dict[str, Any]:
    return {
        "format": "json",
        "encoding": "identity",
        "limits": {"decoded_bytes": max_bytes, "depth": depth, "records": records},
    }


def capture_kinds() -> dict[str, dict[str, Any]]:
    """The SARIF file's kind (the file's bytes verbatim) and the derived document's."""

    return {
        SARIF_KIND: {
            "name": SARIF_KIND,
            "shape": "http_response",
            "grade": "observed",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": 16 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": _json_decoding(16 * 1024 * 1024, 100_000, 64),
        },
        FINDINGS_KIND: {
            "name": FINDINGS_KIND,
            "shape": "http_response",
            "grade": "derived",
            "replay": "attested",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": 8 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": _json_decoding(8 * 1024 * 1024, 100_000, 16),
            "layout": pinned_layout(FINDINGS_LAYOUT),
        },
    }


def _key(part: str) -> dict[str, Any]:
    return {"at": part, "type": f"key_part<{FINDING}:{part}>"}


#: The derived findings document sarif.findings emits (security.sarif.findings@1's
#: result): ``covered`` (the held findings a full run's rules cover), the findings by
#: (repo, weakness, locus) counted by ``/count``, and the attention records.
FINDINGS_LAYOUT: dict[str, Any] = {
    "header": {
        "covered": {"at": "/covered", "type": "list<string{max_len: 256}>{max_items: 20000}"}
    },
    "records": {
        "findings": {
            "at": "/findings/*",
            "key": {"repo": _key("repo"), "weakness": _key("weakness"), "locus": _key("locus")},
            "row": f"{FINDING_ROW}@1",
            "fields": {
                "verification": {"at": "verification"},
                "rule": {"at": "rule", "presence": "optional"},
                "tool": {"at": "tool", "presence": "optional"},
                "severity": {"at": "severity", "presence": "optional"},
                "reported_at": {"at": "reported_at", "presence": "optional"},
            },
            "count_at": "/count",
        },
        "attention": {
            "at": "/attention/*",
            "row": f"{ATTENTION_ROW}@1",
            "fields": {
                "kind": {"at": "kind"},
                "ref": {"at": "ref"},
                "repo": {"at": "repo"},
                "rule": {"at": "rule"},
                "path": {"at": "path"},
                "weakness": {"at": "weakness", "presence": "optional"},
                "locus": {"at": "locus", "presence": "optional"},
                "finding": {"at": "finding", "presence": "optional"},
                "reason": {"at": "reason", "presence": "optional"},
            },
        },
    },
}


# -- 2. Vocabulary ----------------------------------------------------------------------


def _rule(rule_id: str, roles: Sequence[str], kind: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "claim_roles": list(roles),
        "capture_contracts": [kind],
        "admission": "direct",
        "subject_binding": "exact_claim_subject",
    }


_MANY = {"cardinality": "many", "eligible_verdicts": ["supported"], "selector": "all"}


def _rules(*rules: Any) -> dict[str, Any]:
    flat = [rule for item in rules for rule in (item if isinstance(item, list) else [item])]
    return {"rules": sorted(flat, key=lambda rule: rule["rule_id"].encode("utf-8"))}


def _scanned(
    predicate: str,
    value: dict[str, Any],
    description: str,
    *,
    agent: bool = False,
    **more: Any,
) -> dict:
    """A scanner's observation, cited by the derived findings document.

    With ``agent`` an audit agent's observation is admitted too: a workspace file
    or section citation of the code at the location (hunter guidance). A workspace
    citation is not captured evidence (a shaped payload), so such a field requires
    only ``self`` and lists the SARIF contract in ``evidence``; the core's default
    rule admits the citation.
    """

    if agent:
        evidence: dict[str, Any] = {
            "evidence_requirement": "self",
            "evidence": [FINDINGS_KIND],
        }
    else:
        evidence = {
            "evidence_requirement": "captured",
            "evidence_admission_policy": _rules(_rule("sarif", ["observation"], FINDINGS_KIND)),
        }
    return {
        "predicate": FINDING + "." + predicate,
        "allowed_subject_kinds": [FINDING],
        "cardinality": "one",
        "value": value,
        "description": description,
        "permitted_roles": ["observation"],
        "default_role": "observation",
        "revision_evidence": "replace",
        **evidence,
        **more,
    }


def _default_rules(record: dict[str, Any]) -> dict[str, Any]:
    """The record with no rules stated: the core's default admits own words and
    workspace file and section citations (a confirmed verdict's observed run output)."""

    return {key: value for key, value in record.items() if key != "evidence_admission_policy"}


def _judged(predicate: str, value: dict[str, Any], description: str) -> dict:
    """An agent's normative judgment, in its own words (self-source)."""

    return {
        "predicate": FINDING + "." + predicate,
        "allowed_subject_kinds": [FINDING],
        "cardinality": "one",
        "value": value,
        "description": description,
        "permitted_roles": ["normative"],
        "default_role": "normative",
        "evidence_requirement": "self",
        "revision_evidence": "replace",
        "evidence_admission_policy": {"rules": [_rule("self", ["normative"], SELF_SOURCE)]},
    }


def claim_type_records() -> list[dict[str, Any]]:
    """Every code-findings ClaimType; an agent's findings and coverage cite any
    catalogued workspace file (``_file_rule``)."""

    bounded = {"kind": "string", "max_len": 256}
    audit = {"agent": True}
    return [
        {
            "predicate": FINDING + ".repo",
            "allowed_subject_kinds": [FINDING],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256, "pattern": _REPO_PATTERN},
            "description": "The repository as host/owner/repo, casefolded; with weakness and "
            "locus, the finding's key.",
        },
        {
            "predicate": FINDING + ".weakness",
            "allowed_subject_kinds": [FINDING],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256, "pattern": _WEAKNESS_PATTERN},
            "description": "CWE-<n>, the smallest CWE the reporting rule names, else "
            "RULE:<tool>/<ruleId>; with repo and locus, the finding's key.",
        },
        {
            "predicate": FINDING + ".locus",
            "allowed_subject_kinds": [FINDING],
            "cardinality": "one",
            "value": bounded,
            "description": "Where in the code: <path>#<locator>, the first tier that applies "
            "(symbol, snippet:<12 hex>, line-hash:<the tool's>). Never a line number; with "
            "repo and weakness, the finding's key.",
        },
        _scanned(
            "rule",
            bounded,
            "A rule that reported the finding: tool:ruleId from a SARIF scan, or the concern "
            "an audit agent was checking.",
            cardinality="many",
            resolution_policy=_MANY,
            **audit,
        ),
        _scanned(
            "reported_by",
            {"kind": "string", "max_len": 64, "pattern": _TOOL_PATTERN},
            "A finder that reported the finding: a tool (semgrep, codeql) from a SARIF scan, "
            "or audit for an audit agent citing the code.",
            cardinality="many",
            resolution_policy=_MANY,
            **audit,
        ),
        _scanned(
            "reported_at",
            bounded,
            "Where the finding was reported, as path:line: by the latest scan, or by an "
            "audit agent citing the code there. A moved finding keeps its key and this "
            "revises; a full scan that no longer reports it retires the scan's.",
            **audit,
        ),
        _scanned(
            "verification",
            {"kind": "enum", "members": VERIFICATIONS},
            "present when a scan reports the finding; fixed when a full scan of the rules "
            "that reported it no longer does. fixed needs complete input.",
            requires_complete_input=["fixed"],
        ),
        {
            **_scanned(
                "severity",
                {"kind": "enum", "members": SEVERITIES},
                "How severe the finding is: a scan's severity (security-severity, else the "
                "level), or an agent's normative judgment, which a later scan never overrides.",
            ),
            "permitted_roles": ["normative", "observation"],
            "evidence_requirement": "self",
            "evidence_admission_policy": {
                "rules": [
                    _rule("sarif", ["observation"], FINDINGS_KIND),
                    _rule("self", ["normative"], SELF_SOURCE),
                ]
            },
        },
        _default_rules(
            _judged(
                "verdict",
                {"kind": "enum", "members": VERDICTS},
                "An agent's verdict: confirmed (real and exploitable), false_positive (no "
                "such weakness here) or not_exploitable (real, but not exploitable here). A "
                "confirmed verdict cites the observed run output (a catalogued test log or "
                "output file); a refutation cites the agent's own words. Never settled by a "
                "Mandate.",
            )
        ),
        {
            **_judged(
                "justification",
                {"kind": "enum", "members": JUSTIFICATIONS},
                "Why a finding is false_positive or not_exploitable, as an agent judged it.",
            ),
            "member_descriptions": [
                {
                    "member": "no_boundary_crossed",
                    "description": "The effect stays within the attacker's own authority.",
                },
            ],
        },
        _judged(
            "fixed_by",
            {"kind": "string", "max_len": 40, "pattern": "^[0-9a-f]{40}$"},
            "The commit (40-hex SHA) that fixes the finding, as an agent states it.",
        ),
        {
            **_judged(
                "found_in",
                {"kind": "subject", "subject_kinds": [UNIT]},
                "The coverage unit an audit agent was working when it found the finding. "
                "Never settled by a Mandate.",
            ),
            "cardinality": "many",
            "resolution_policy": _MANY,
        },
        *coverage_claim_type_records(),
    ]


def coverage_claim_type_records() -> list[dict[str, Any]]:
    """The coverage unit's key parts and its status (K-CA3)."""

    return [
        {
            "predicate": UNIT + ".repo",
            "allowed_subject_kinds": [UNIT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256, "pattern": _REPO_PATTERN},
            "description": "The repository as host/owner/repo, casefolded (as a finding's "
            "repo); with surface and concern, the unit's key.",
        },
        {
            "predicate": UNIT + ".surface",
            "allowed_subject_kinds": [UNIT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256, "pattern": _SURFACE_PATTERN},
            "description": "The entry point or boundary checked, as a canonical code "
            "reference: path#symbol, or a route (src/router.ts#POST /users/:id). Spelled the "
            "same every run; with repo and concern, the unit's key.",
        },
        {
            "predicate": UNIT + ".concern",
            "allowed_subject_kinds": [UNIT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 128, "pattern": _CONCERN_PATTERN},
            "description": "What the surface was checked for, in the auditor's words or a "
            "reference attack class (access-control, injection, ssrf, a named state "
            "machine); with repo and surface, the unit's key.",
        },
        {
            "predicate": UNIT + ".status",
            "allowed_subject_kinds": [UNIT],
            "cardinality": "one",
            "value": {"kind": "enum", "members": COVERAGE_STATUSES},
            "description": "What an audit agent did with the unit, in its own words or citing "
            "the examined passage. Never settled by a Mandate.",
            "member_descriptions": [
                {
                    "member": "checked",
                    "description": "Examined; the Claim cites the exact passage (path#anchor).",
                },
                {"member": "deferred", "description": "Not reached this run."},
                {
                    "member": "blocked",
                    "description": "Stopped: a missing sandbox capability or a fact outside "
                    "source, named in the rationale.",
                },
                {
                    "member": "out_of_scope",
                    "description": "Deliberately excluded, with the reason.",
                },
            ],
            "permitted_roles": ["normative"],
            "default_role": "normative",
            "evidence_requirement": "self",
            "revision_evidence": "replace",
            # No rules stated: the core's default admits own words and workspace file
            # and section citations (the passage examined).
        },
    ]


def claim_types() -> list[Any]:
    return [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]


def vocabulary() -> dict[str, Any]:
    """Row and inbox Contracts, the ClaimTypes, the finding and coverage-unit
    SubjectKinds and their Queries."""

    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": FINDING_ROW,
            "version": 1,
            "description": "One finding a SARIF findings document lists: its verification and, "
            "when the scan gives them, the rule, tool, severity and location that reported it.",
            "fields": {
                "verification": f"enum_of {FINDING}.verification",
                "rule": "string{max_len: 256}?",
                "tool": _TOOL + "?",
                "severity": f"enum_of {FINDING}.severity?",
                "reported_at": "string{max_len: 256}?",
            },
        },
        {
            "kind": "contract",
            "name": ATTENTION_ROW,
            "version": 1,
            "description": "One attention record: a regression or a location gap.",
            "fields": {
                "kind": _ATTENTION_KINDS,
                "ref": "string{max_len: 512}",
                "repo": "string{max_len: 256}",
                "rule": "string{max_len: 256}",
                "path": "string{max_len: 256}",
                "weakness": "string{max_len: 256}?",
                "locus": "string{max_len: 256}?",
                "finding": "string{max_len: 256}?",
                "reason": "string{max_len: 64}?",
            },
        },
        {
            "kind": "contract",
            "name": ATTENTION_ITEM,
            "version": 1,
            "description": _ATTENTION_ITEM_DESCRIPTION,
            "fields": {
                "kind": _ATTENTION_KINDS,
                "ref": "string{max_len: 512}",
                "repo": "string{max_len: 256}",
                "rule": "string{max_len: 256}",
                "path": "string{max_len: 256}",
                "weakness": "string{max_len: 256}?",
                "locus": "string{max_len: 256}?",
                "finding": "string{max_len: 256}?",
                "reason": "string{max_len: 64}?",
            },
        },
        {
            "kind": "contract",
            "name": ATTENTION_ITEM,
            "version": ATTENTION_ITEM_VERSION,
            "description": _ATTENTION_ITEM_DESCRIPTION,
            "fields": {
                "kind": {
                    "type": _ATTENTION_KINDS,
                    "description": "regression (a finding verified fixed that a scan reports "
                    "again) or location_gap (a result the scan could not place).",
                },
                "ref": {
                    "type": "string{max_len: 512}",
                    "description": "The item's identity: the kind, then the finding and scan "
                    "revision, or the rule and path.",
                },
                "repo": {
                    "type": f"key_part<{FINDING}:repo>",
                    "description": "The repository (host/owner/repo): the finding key's repo.",
                },
                "rule": {
                    "type": "string{max_len: 256}",
                    "description": "The rule that reported it, as tool:ruleId.",
                },
                "path": {
                    "type": "string{max_len: 256}",
                    "description": "The repository-relative path the result names, or (none).",
                },
                "weakness": {
                    "type": f"key_part<{FINDING}:weakness>?",
                    "description": "A regression's weakness (CWE-n or RULE:tool/ruleId): the "
                    "finding key's weakness.",
                },
                "locus": {
                    "type": f"key_part<{FINDING}:locus>?",
                    "description": "A regression's locus (path#locator): the finding key's "
                    "locus.",
                },
                # The held row's subject_id, without its kind: subject<security.finding>
                # takes kind/id only, so typing it would change the posted value.
                "finding": {
                    "type": "string{max_len: 256}?",
                    "description": "A regression's finding Subject id: get "
                    "security.finding/<finding>.",
                },
                "reason": {
                    "type": "string{max_len: 64}?",
                    "description": "Why a location gap is no finding (for example "
                    "no_repository_path or no_stable_location).",
                },
            },
        },
        {
            "kind": "contract",
            "name": VERDICT_ROW,
            "version": 1,
            "description": "One finding with the judgments agents hold on it.",
            "fields": {
                "subject_kind": "string",
                "subject_id": "string",
                "weakness": "string",
                "locus": "string",
                "verdict": "string?",
                "justification": "string?",
                "severity": "string?",
                "verification": "string?",
                "reported_by": "list<string{max_len: 64}>{max_items: 64}?",
            },
        },
        {
            "kind": "contract",
            "name": PLAN_ROW,
            "version": 1,
            "description": "One coverage unit an audit should take up: never checked, "
            "deferred or blocked.",
            "fields": {
                "subject_kind": "string",
                "subject_id": "string",
                "surface": "string",
                "concern": "string",
                "status": "string?",
            },
        },
        {
            "kind": "contract",
            "name": UNIT_FINDING_ROW,
            "version": 1,
            "description": "One finding found in a coverage unit (finding: its Subject id), "
            "with its judgments.",
            "fields": {
                "finding": "string",
                "weakness": "string",
                "locus": "string",
                "verdict": "string?",
                "severity": "string?",
                "reported_by": "list<string{max_len: 64}>{max_items: 64}?",
            },
        },
        *(
            {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
            for t in claim_types()
        ),
        {
            "kind": "subject_kind",
            "name": FINDING,
            "description": "One weakness of one kind at one place in one repository's code.",
            "keys": [FINDING + ".repo", FINDING + ".weakness", FINDING + ".locus"],
        },
        {
            "kind": "subject_kind",
            "name": UNIT,
            "description": "One audit coverage unit: one surface of one repository checked "
            "for one concern.",
            "keys": [UNIT + ".repo", UNIT + ".surface", UNIT + ".concern"],
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": HELD_QUERY,
                "description": "Every finding the instance holds for one repository: the held "
                "rows the SARIF import receives.",
                "params": {"repo": "string"},
                "from": {"f": FINDING},
                "where": "f.repo == $repo",
                "row": f"{HELD_ROW}@1",
                "fields": [
                    "f.subject_kind",
                    "f.subject_id",
                    "f.weakness",
                    "f.locus",
                    {"rules": "f.rule"},
                    "f.verification",
                ],
            },
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": VERDICTS_QUERY,
                "description": "Every finding of one repository with the agents' verdicts and "
                "the scans' verification.",
                "params": {"repo": "string"},
                "from": {"f": FINDING},
                "where": "f.repo == $repo",
                "row": f"{VERDICT_ROW}@1",
                "fields": [
                    "f.subject_kind",
                    "f.subject_id",
                    "f.weakness",
                    "f.locus",
                    "f.verdict",
                    "f.justification",
                    "f.severity",
                    "f.verification",
                    "f.reported_by",
                ],
            },
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": COVERAGE_PLAN_QUERY,
                "description": "The coverage units of one repository an audit should take "
                "up: never checked (no status), deferred or blocked. A checked unit whose "
                "passage changed is not here: next lists it as citation_drifted.",
                "params": {"repo": "string"},
                "from": {"u": UNIT},
                "where": "u.repo == $repo and (not exists u.status or u.status in ("
                + ", ".join(f'"{status}"' for status in OPEN_STATUSES)
                + "))",
                "row": f"{PLAN_ROW}@1",
                "fields": [
                    "u.subject_kind",
                    "u.subject_id",
                    "u.surface",
                    "u.concern",
                    "u.status",
                ],
            },
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": FINDINGS_BY_UNIT_QUERY,
                "description": "The findings found in one coverage unit (found_in), with "
                "their verdicts.",
                "params": {"unit": "subject"},
                "from": {"u": f"{UNIT} = $unit"},
                "hops": [{"f": f"<u.{FINDING}.found_in!: {FINDING}"}],
                "row": f"{UNIT_FINDING_ROW}@1",
                # A row's subject and subject_id name the entry (the unit), so
                # the finding's id is its own column.
                "fields": [
                    {"finding": "f.subject_id"},
                    "f.weakness",
                    "f.locus",
                    "f.verdict",
                    "f.severity",
                    "f.reported_by",
                ],
            },
        },
    ]
    members += params_contract_members(IMPORT_PROCEDURE, *IMPORT_PARAMS)
    # Codebase facts: rests_on on findings and coverage units, and their Queries.
    import facts

    members += facts.audit_members()
    return {
        "kind": "change_set",
        "rationale": "Security kit code findings: the finding and coverage-unit Subjects, "
        "scan and audit observations, agent judgments, the held-findings Query the import "
        "reads, the audit Queries, and the judgments that rest on codebase facts.",
        "members": members,
    }


# -- 3. Procedures ----------------------------------------------------------------------


_SLOTS = {
    "read": {"capability": capability(WORKSPACE_FILE_CAPABILITY)},
    "derive": {"capability": capability(SARIF_FINDINGS_CAPABILITY)},
}
_CAPS = {
    "wall_clock": "PT5M",
    "provider_calls": 2,
    "capture_bytes": 32 * 1024 * 1024,
    "items": 100_000,
    "read_rows": 20_000,
    "repeat_attempts": 1,
}
#: What a Line on security.sarif-import supplies, as its params Contract says it.
IMPORT_PARAMS = (
    "What a Line on security.sarif-import reads: one SARIF file in the workspace, the "
    "repository whose results it imports, and the source label it is recorded under; one "
    "Line per scanner and repository.",
    {
        "relative_path": (
            _PATH,
            "Workspace-relative path of one SARIF 2.1.0 JSON log, at most 1 MiB and 20000 "
            "results. Only runs whose versionControlProvenance[0].repositoryUri names the "
            "Line's repo are read. A result needs a repository-relative path and a symbol, "
            "snippet or primaryLocationLineHash, or it is a location gap, not a finding; a "
            "CVE or GHSA result in a manifest is left to the SBOM loop. Only a run with "
            "properties cruxible.coverage full, every invocation successful, marks findings "
            "fixed. The scanner writes the file; Cruxible does not.",
        ),
        "logical_source": (
            _SOURCE,
            "Source label the SARIF Capture and the derived findings document are recorded "
            "under, lowercase: sarif.<scanner> (for example sarif.semgrep). The attention "
            "Line's landing Trigger names it, so give each scanner's import its own.",
        ),
        "repo": (
            _REPO,
            "The repository the findings belong to, as host/owner/repo in lowercase (for "
            "example github.com/acme/shop). It is part of every finding's key and picks "
            "which runs of the log are read: a log with no run of this repository imports "
            "nothing.",
        ),
    },
)


def import_spec() -> dict[str, Any]:
    """``security.sarif-import``: one SARIF file's findings for the Line's repository."""

    claims: list[dict[str, Any]] = [
        {
            "type": FINDING + ".rule",
            "value": "$item.fields.rule",
            "when_absent": "keep",
            "rationale": "{$item.fields.rule} reports {$item.key.weakness} here.",
        },
        {
            "type": FINDING + ".reported_by",
            "value": "$item.fields.tool",
            "when_absent": "keep",
            "rationale": "{$item.fields.tool} reports {$item.key.weakness} here.",
        },
        {
            "type": FINDING + ".severity",
            "value": "$item.fields.severity",
            "when_absent": "keep",
            "rationale": "{$item.fields.rule} rates it {$item.fields.severity}.",
        },
        {
            "type": FINDING + ".reported_at",
            "value": "$item.fields.reported_at",
            "when_absent": "mirror",
            "rationale": "The scan reports it at {$item.fields.reported_at}.",
        },
        {
            "type": FINDING + ".verification",
            "value": "$item.fields.verification",
            "when_absent": "keep",
            "rationale": "The scan of {$params.relative_path} reads it "
            "{$item.fields.verification}.",
        },
    ]
    return refs(
        {
            "procedure": IMPORT_PROCEDURE,
            "description": "Read one SARIF file from the workspace and write the findings it "
            "reports for the Line's repository; only a full scan marks a held finding fixed.",
            "input": {},
            "output": {},
            "parameter_contract": params_contract(IMPORT_PROCEDURE),
            "slots": _SLOTS,
            "hard_caps": _CAPS,
            "steps": [
                {"read": "held", "query": HELD_QUERY, "params": {"repo": "$params.repo"}},
                {
                    "call": "sarif",
                    "slot": "read",
                    "captures": {"capture": SARIF_KIND},
                    "input": {
                        "logical_source": "$params.logical_source",
                        "relative_path": "$params.relative_path",
                    },
                },
                {
                    "call": "findings",
                    "slot": "derive",
                    "captures": {"document": FINDINGS_KIND},
                    "input": {
                        "logs": ["$steps.sarif.capture"],
                        "held": "$steps.held.rows",
                        "repo": "$params.repo",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "extract": "found",
                    "capture": "$steps.findings.document",
                    "records": "findings",
                    "header": ["covered"],
                },
                {
                    "id": "write",
                    "for_each": "$steps.found.records",
                    "subject": {
                        "kind": FINDING,
                        "key": {
                            "repo": "$item.key.repo",
                            "weakness": "$item.key.weakness",
                            "locus": "$item.key.locus",
                        },
                        "create": "if_absent",
                    },
                    "expect": "$steps.found.header.covered",
                    "claims": claims,
                },
            ],
        }
    )


def attention_spec() -> dict[str, Any]:
    """``security.sarif-attention``: regressions and location gaps to the Line inbox.

    It runs on the landing of the import's derived document: the Trigger
    substitutes that Capture for the derive call, so nothing is read or
    re-derived (the call's input is never evaluated).
    """

    return refs(
        {
            "procedure": ATTENTION_PROCEDURE,
            "description": "Post each regression and location gap in one derived SARIF "
            "findings document to the Line's inbox.",
            "input": {},
            "output": {},
            "params": {"logical_source": _SOURCE, "repo": _REPO},
            # Inbox egress is the terminal; the run's own value is empty.
            "returns": {"fields": {}},
            "slots": {"derive": _SLOTS["derive"]},
            "hard_caps": {**_CAPS, "provider_calls": 1},
            "steps": [
                {
                    "call": "findings",
                    "slot": "derive",
                    "captures": {"document": FINDINGS_KIND},
                    "input": {
                        "logs": [],
                        "held": [],
                        "repo": "$params.repo",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "extract": "attention",
                    "capture": "$steps.findings.document",
                    "records": "attention",
                },
                {
                    "id": "post",
                    "inbox": f"{ATTENTION_ITEM}@{ATTENTION_ITEM_VERSION}",
                    "for_each": "$steps.attention.records",
                    "fields": {
                        name: f"$item.fields.{name}"
                        for name in (
                            "kind",
                            "ref",
                            "repo",
                            "rule",
                            "path",
                            "weakness",
                            "locus",
                            "finding",
                            "reason",
                        )
                    },
                    "dedupe_key": ["ref"],
                },
            ],
        }
    )


def procedures() -> dict[str, Any]:
    members = [{"kind": "procedure", "spec": spec} for spec in (import_spec(), attention_spec())]
    for member in members:
        ProcedureInput.model_validate(member)
    return {
        "kind": "change_set",
        "rationale": "Security kit code findings: SARIF import and its attention items.",
        "members": members,
    }


# -- 4. Automation ----------------------------------------------------------------------

#: The import settles scan observations on the extracted record and retires the
#: last location on absence (K-B2-G4: a full rescan that no longer finds a finding
#: is a source-driven negative). Agents' judgments are never in scope.
IMPORT_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    FINDING + ".rule": {"create": {"basis": ["extracted"]}},
    FINDING + ".reported_by": {"create": {"basis": ["extracted"]}},
    FINDING + ".severity": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
    },
    FINDING + ".reported_at": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
    FINDING + ".verification": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
    },
}


def import_line_name(suffix: str) -> str:
    return f"{IMPORT_LINE}.{suffix}"


def attention_line_name(suffix: str) -> str:
    return f"{ATTENTION_LINE}.{suffix}"


def logical_source(suffix: str) -> str:
    return f"{SARIF_SOURCE}.{suffix}"


def automation(
    scans: Sequence[tuple[str, str, str]], *, now: datetime, settle: bool = True
) -> dict[str, Any]:
    """Two Lines per scan, (line suffix, repository, workspace path) each.

    The import Line reads the SARIF file under its own logical source
    (``sarif.<suffix>``), so absence only retires what the same scanner's file
    wrote (D-R18). The attention Line runs on the landing of the import's
    derived document (a capture_landing Trigger on that logical source).
    """

    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    members: list[dict[str, Any]] = []
    for suffix, repo, path in scans:
        line, attention, source = (
            import_line_name(suffix),
            attention_line_name(suffix),
            logical_source(suffix),
        )
        members += [
            {
                "kind": "line",
                "name": line,
                "procedure_name": IMPORT_PROCEDURE,
                "bindings": {"read": WORKSPACE_FILE, "derive": SARIF_FINDINGS},
                "parameters": {"relative_path": path, "logical_source": source, "repo": repo},
                "acquisition": {},
                "findings": {"inbox": list(FINDINGS)},
                "max_authority": "settle" if settle else "propose",
            },
            {
                "kind": "procedure_mandate",
                "name": line + "-propose",
                "line_name": line,
                "grants": "propose",
                "namespace": ["claims", "subjects"],
                "valid_from": valid_from,
                "expires_at": expires_at,
            },
        ]
        if settle:
            members.append(
                {
                    "kind": "procedure_mandate",
                    "name": line + "-settle",
                    "line_name": line,
                    "grants": "settle",
                    "namespace": ["claims"],
                    "valid_from": valid_from,
                    "expires_at": expires_at,
                    "subject_creation": [FINDING],
                    "scope": [
                        {"claim_type": claim_type, "changes": changes}
                        for claim_type, changes in IMPORT_SETTLE_SCOPE.items()
                    ],
                }
            )
        members += [
            {
                "kind": "line",
                "name": attention,
                "procedure_name": ATTENTION_PROCEDURE,
                "bindings": {"derive": SARIF_FINDINGS},
                "parameters": {"logical_source": source, "repo": repo},
                "trigger_input": "findings.document",
                "acquisition": {"findings.document": {}},
                # Inbox egress only: posting feeds agents, it changes no state.
                "max_authority": "observe",
            },
            {
                "kind": "trigger",
                "name": f"security.sarif-findings-landed.{suffix}",
                "line_name": attention,
                "schedule": {
                    "kind": "capture_landing",
                    "capture_contract": FINDINGS_KIND,
                    "logical_sources": [source],
                },
            },
        ]
    return {
        "kind": "change_set",
        "rationale": "Adopt the SARIF import and attention Lines.",
        "members": members,
    }


# -- 5. Agent judgments (state an agent writes) -----------------------------------------


def judgment(
    key: dict[str, str],
    *,
    predicate: str,
    value: str,
    rationale: str,
    revises: str | None = None,
) -> dict[str, Any]:
    """One normative Claim on a finding in the agent's own words (self-source).

    ``revises`` names the scan's Claim an agent's judgment replaces (severity):
    the slot's holder becomes normative, and a later scan that disagrees is
    recorded as ``held_disagrees`` instead of applied.
    """

    return {
        **({"revises": revises} if revises else {}),
        "kind": "claim",
        "subject": {
            "subject_kind": FINDING,
            "key": {f"{FINDING}.{part}": text for part, text in key.items()},
        },
        "predicate": f"{FINDING}.{predicate}",
        "object": {"kind": "literal", "value": value},
        "role": "normative",
        "rationale": rationale,
        "source": {"kind": "self_source", "body": f"{predicate} = {value}: {rationale}\n"},
    }


# -- payloads ---------------------------------------------------------------------------


def write_all(
    out: Path,
    *,
    scans: Sequence[tuple[str, str, str]],
    now: datetime,
) -> list[Path]:
    from definitions import staged_capture_kinds

    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    # The kinds themselves are in definitions.write_all's payloads; their layouts
    # follow the findings vocabulary, which holds their rows.
    _, layouts = staged_capture_kinds(capture_kinds())
    for name, record in layouts.items():
        path = out / f"capture-layout.{name}.json"
        path.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
        written.append(path)
    for name, payload in (
        ("findings-vocabulary", vocabulary()),
        ("findings-procedures", procedures()),
        ("findings-automation", automation(scans, now=now)),
    ):
        ChangeSetInput.model_validate(payload)
        path = out / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument(
        "--scan",
        nargs="*",
        default=[],
        help="NAME=host/owner/repo=RELATIVE_PATH: two Lines per SARIF file",
    )
    parser.add_argument("--now", default=None, help="ISO-8601 instant Mandates start from")
    args = parser.parse_args()
    now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    scans = [tuple(item.split("=", 2)) for item in args.scan]
    for path in write_all(
        args.out,
        scans=scans,  # type: ignore[arg-type]
        now=now.replace(microsecond=0),
    ):
        print(path)


if __name__ == "__main__":
    main()
