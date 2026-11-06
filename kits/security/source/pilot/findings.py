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

from definitions import FINDINGS, refs

FINDING = "security.finding"
#: The SARIF file as read (core's builtin workspace.file), decoded as JSON.
SARIF_KIND = "security.sarif-log"
#: The derived document sarif.findings emits (D-R37 derive; c5: the kit declares it).
FINDINGS_KIND = "security.sarif-findings"
FINDING_ROW = "security.sarif-finding"
ATTENTION_ROW = "security.sarif-attention-record"
ATTENTION_ITEM = "security.sarif-attention"
HELD_ROW = "sarif.held-finding"
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

SEVERITIES = ["low", "medium", "high", "critical"]
VERIFICATIONS = ["present", "fixed"]
VERDICTS = ["confirmed", "false_positive", "not_exploitable"]
JUSTIFICATIONS = [
    "not_attacker_controlled",
    "not_reachable",
    "rule_misfire",
    "sanitized",
    "test_or_dead_code",
]

_PATH = 'string{max_len: 256, pattern: "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_REPO_PATTERN = "^[a-z0-9.-]+/[^/\\s]+/[^/\\s]+$"
_REPO = f'string{{max_len: 256, pattern: "{_REPO_PATTERN.replace(chr(92), chr(92) * 2)}"}}'
_ATTENTION_KINDS = 'enum["location_gap", "regression"]'
_WEAKNESS_PATTERN = "^(CWE-[0-9]{1,6}|RULE:\\S{1,240})$"
_TOOL_PATTERN = "^[0-9a-z][0-9a-z._-]{0,63}$"
_TOOL = f'string{{max_len: 64, pattern: "{_TOOL_PATTERN}"}}'


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


def _scanned(predicate: str, value: dict[str, Any], description: str, **more: Any) -> dict:
    """A scanner's observation, cited by the derived findings document."""

    return {
        "predicate": FINDING + "." + predicate,
        "allowed_subject_kinds": [FINDING],
        "cardinality": "one",
        "value": value,
        "description": description,
        "permitted_roles": ["observation"],
        "default_role": "observation",
        "evidence_requirement": "captured",
        "revision_evidence": "replace",
        "evidence_admission_policy": {"rules": [_rule("sarif", ["observation"], FINDINGS_KIND)]},
        **more,
    }


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
    bounded = {"kind": "string", "max_len": 256}
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
            "A tool rule that reported the finding, as tool:ruleId, from a SARIF scan.",
            cardinality="many",
            resolution_policy=_MANY,
        ),
        _scanned(
            "reported_by",
            {"kind": "string", "max_len": 64, "pattern": _TOOL_PATTERN},
            "A finder that reported the finding: a tool (semgrep, codeql) or an agent's "
            "principal, from a SARIF scan.",
            cardinality="many",
            resolution_policy=_MANY,
        ),
        _scanned(
            "reported_at",
            bounded,
            "Where the latest scan reported the finding, as path:line. A moved finding keeps "
            "its key and this revises; a full scan that no longer reports it retires it.",
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
        _judged(
            "verdict",
            {"kind": "enum", "members": VERDICTS},
            "An agent's verdict: confirmed (real and exploitable), false_positive (no such "
            "weakness here) or not_exploitable (real, but not exploitable here). Never settled "
            "by a Mandate.",
        ),
        _judged(
            "justification",
            {"kind": "enum", "members": JUSTIFICATIONS},
            "Why a finding is false_positive or not_exploitable, as an agent judged it.",
        ),
        _judged(
            "fixed_by",
            {"kind": "string", "max_len": 40, "pattern": "^[0-9a-f]{40}$"},
            "The commit (40-hex SHA) that fixes the finding, as an agent states it.",
        ),
    ]


def claim_types() -> list[Any]:
    return [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]


def provider_contract_members(root: Path = PROVIDER_ROOT) -> list[dict[str, Any]]:
    """The Contracts security-sarif-provider ships, as authoring members (nested last)."""

    from cruxible_client.contracts.shapes import parse_contract, render_type

    out = []
    for path in sorted((root / "contracts").rglob("*.json")):
        member = "contracts/" + path.relative_to(root / "contracts").as_posix()
        contract = parse_contract(path.read_bytes(), path=member)
        item: dict[str, Any] = {
            "kind": "contract",
            "name": contract.name,
            "version": contract.version,
            "fields": {
                name: render_type(field.type) + ("?" if field.optional else "")  # type: ignore[arg-type]
                for name, field in contract.fields.items()
            },
        }
        if contract.description:
            item["description"] = contract.description
        out.append(item)
    return sorted(out, key=lambda item: 1 if "@" in json.dumps(item["fields"]) else 0)


def vocabulary() -> dict[str, Any]:
    """Row and inbox Contracts, the ClaimTypes, the finding SubjectKind and its Queries."""

    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": FINDING_ROW,
            "version": 1,
            "description": "One finding the derived document lists, typed in the extract.",
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
            "description": "A code-findings item for an agent: a regression (a finding verified "
            "fixed that a scan reports again) or a location gap (a result with no repository "
            "path or no stable locator, so it is no finding yet).",
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
            "kind": "query_definition",
            "query_definition": {
                "query": HELD_QUERY,
                "description": "Every finding held for one repository: the import's held rows.",
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
                "description": "Every finding of one repository with its agents' verdicts and "
                "the scans' verification: the code-findings judgment record.",
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
    ]
    return {
        "kind": "change_set",
        "rationale": "Security kit code findings: the finding Subject, scan observations, "
        "agent judgments and the held-findings Query the import reads.",
        "members": members,
    }


# -- 3. Procedures ----------------------------------------------------------------------


_SLOTS = {
    "read": {"in": "workspace.file.request@1", "out": "workspace.file.result@1", "effect": "pure"},
    "derive": {
        "in": "sarif.findings.request@1",
        "out": "sarif.findings.result@1",
        "effect": "pure",
    },
}
_CAPS = {
    "wall_clock": "PT5M",
    "provider_calls": 2,
    "capture_bytes": 32 * 1024 * 1024,
    "items": 100_000,
    "read_rows": 20_000,
    "repeat_attempts": 1,
}
_PARAMS = {"relative_path": _PATH, "logical_source": _SOURCE, "repo": _REPO}


def _key(part: str) -> dict[str, Any]:
    return {"at": part, "type": f"key_part<{FINDING}:{part}>"}


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
            "reports for the Line's repository; a full scan verifies fixes.",
            "input": {},
            "output": {},
            "params": _PARAMS,
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
                    "records": "/findings/*",
                    "row": f"{FINDING_ROW}@1",
                    "key": {
                        "repo": _key("repo"),
                        "weakness": _key("weakness"),
                        "locus": _key("locus"),
                    },
                    "fields": {
                        "verification": {"at": "verification"},
                        "rule": {"at": "rule", "presence": "optional"},
                        "tool": {"at": "tool", "presence": "optional"},
                        "severity": {"at": "severity", "presence": "optional"},
                        "reported_at": {"at": "reported_at", "presence": "optional"},
                    },
                    "header": {
                        "covered": {
                            "at": "/covered",
                            "type": "list<string{max_len: 256}>{max_items: 20000}",
                        },
                    },
                    "complete_when": {"count_at": "/count"},
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
            "description": "Post the regressions and location gaps of one derived SARIF "
            "findings document to the Line inbox.",
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
                    "records": "/attention/*",
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
                {
                    "id": "post",
                    "inbox": f"{ATTENTION_ITEM}@1",
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


def write_all(out: Path, *, scans: Sequence[tuple[str, str, str]], now: datetime) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    contracts = out / "sarif-contracts.json"
    contracts.write_text(
        json.dumps(
            {
                "kind": "change_set",
                "rationale": "The Contracts security-sarif-provider's operation pins, as shipped.",
                "members": provider_contract_members(),
            },
            indent=1,
        )
        + "\n"
    )
    written.append(contracts)
    for name, record in capture_kinds().items():
        path = out / f"capture-kind.{name}.json"
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
    for path in write_all(args.out, scans=scans, now=now.replace(microsecond=0)):  # type: ignore[arg-type]
        print(path)


if __name__ == "__main__":
    main()
