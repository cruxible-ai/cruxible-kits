"""Audit gate: coverage units and agents' findings (K-CA1..K-CA4).

An audit agent writes through the ordinary write verbs (``service_playbill_write``,
the daemon side of ``cruxible write``), citing catalogued workspace files as the
CLI's ``--evidence-file PATH#ANCHOR`` does: the client observes the bytes, the
daemon captures them under the file's foreign-source contract. The kit's
``file`` rule admits any catalogued workspace file (the ``workspace_file``
family, D1): a Capture under an accepted foreign-source contract.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$RUNTIME/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_audit_gate.py
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from test_findings_gate import (
    REPO,
    SEMGREP,
    _result,
    changed,
    counts,
    findings_world,
    query_rows,
    run,
    sarif,
    scan,
)
from test_pilot_gate import submit, workspace, write_file

import findings  # noqa: E402

FINDING = findings.FINDING
UNIT = findings.UNIT
DB = "app/db.py"
NOTES = "security/findings/gate-app/sqli.md"
SOURCES = ("gate-app.db", "gate-app.notes")
DB_CODE = b'''import sqlite3


def find_by_name(conn, name):
    """Look a user up by name."""
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


def find_by_id(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
'''
TRACE = b"""# SQL injection in find_by_name

## Trace

1. `app/routes.py#search`: the `q` query parameter, unauthenticated.
2. `app/db.py#find_by_name`: `name` is formatted into the SQL text.
3. Effect: any row of `users` is readable.
"""
SINK = "def find_by_name(conn, name):"
SQLI_LOCUS = "app/db.py#find_by_name"
CATALOG = f"""\
tag: playbill-source-catalog-v1
catalog_kind: portable
entries:
  - name: gate-app.db
    locator: {DB}
  - name: gate-app.notes
    locator: {NOTES}
"""


def audit_world(tmp_path: Path, *, cited_before: Sequence[str] = SOURCES) -> Any:
    """The findings world, the gate app's files catalogued, and ``cited_before``
    already cited once (their foreign-source contracts accepted).

    ``cited_before`` stands in for an earlier citation through the write path:
    core admits a family rule's Capture only under a contract accepted at the
    write's base, so the write that first cites a file (and installs its
    contract) is not admitted (``test_core_d1_a_first_citation_is_admitted``).
    """

    from cruxible_client.contracts.captures import (
        capture_contract_path,
        foreign_source_capture_contract,
        render_capture_contract,
    )
    from tests.core_support._identity_support import accept_tree

    instance = findings_world(tmp_path)
    write_file(tmp_path, ".cruxible/files.yaml", CATALOG.encode())
    write_file(tmp_path, DB, DB_CODE)
    write_file(tmp_path, NOTES, TRACE)
    if cited_before:
        contracts = [foreign_source_capture_contract(source) for source in cited_before]
        tree = {
            capture_contract_path(c.identity.name): render_capture_contract(c) for c in contracts
        }
        accept_tree(instance, tree, name="cited-before")
    return instance


def write(
    instance: Any, tmp_path: Path, changes: Sequence[Mapping[str, Any]], *, because: str
) -> Any:
    """One write, its file evidence observed from the workspace as the CLI does."""

    from cruxible_client.authoring.write_evidence import observe_changes
    from cruxible_client.contracts.write import WriteRequest
    from cruxible_core.service.authoring.write_verbs import service_playbill_write
    from tests.core_support._write_support import caller

    request = WriteRequest.model_validate({"because": because, "changes": list(changes)})
    observed = request.model_copy(
        update={"changes": observe_changes(request.changes, workspace=workspace(tmp_path))}
    )
    return service_playbill_write(instance, request=observed, caller=caller())


def accepted_write(instance: Any, tmp_path: Path, changes: Sequence[Mapping[str, Any]], **kw: Any):
    outcome = write(instance, tmp_path, changes, **kw)
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    return outcome


def code(anchor: str = SINK) -> dict[str, str]:
    return {"kind": "file", "file": f"{DB}#{anchor}"}


def _key(kind: str, **parts: str) -> list[dict[str, str]]:
    return [{"predicate": f"{kind}.{name}", "value": value} for name, value in parts.items()]


def unit_changes(
    label: str, surface: str, concern: str, status: str | None, *, evidence: Any = None
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = [
        {
            "op": "create",
            "label": label,
            "subject_kind": UNIT,
            "key": _key(UNIT, repo=REPO, surface=surface, concern=concern),
        }
    ]
    if status is not None:
        changes.append(
            {
                "op": "set",
                "subject": {"created": label},
                "field": "status",
                "value": status,
                **({"evidence": evidence} if evidence is not None else {}),
            }
        )
    return changes


def agent_finding(label: str, *, unit: Any, locus: str = SQLI_LOCUS) -> list[dict[str, Any]]:
    """The hunter's writes: key it, what it saw (citing the code), link the unit."""

    target = {"created": label}
    return [
        {
            "op": "create",
            "label": label,
            "subject_kind": FINDING,
            "key": _key(FINDING, repo=REPO, weakness="CWE-89", locus=locus),
        },
        {
            "op": "set",
            "subject": target,
            "field": "reported_at",
            "value": "app/db.py:6",
            "role": "observation",
            "evidence": code('conn.execute(f"SELECT'),
        },
        {
            "op": "add",
            "subject": target,
            "field": "reported_by",
            "value": findings.AUDIT_REPORTER,
            "role": "observation",
            "evidence": code(),
        },
        {
            "op": "add",
            "subject": target,
            "field": "rule",
            "value": "audit:injection",
            "role": "observation",
            "evidence": code(),
        },
        {"op": "add", "subject": target, "field": "found_in", "value": unit},
    ]


def symbol_scan(*symbols: tuple[str, str, str]) -> dict[str, Any]:
    """A full Semgrep run whose results name a symbol: (rule, path, symbol) each."""

    document = sarif("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["results"] = [
        _result(rule, path, symbol=symbol) for rule, path, symbol in symbols
    ]
    return document


def plan(instance: Any, *, repo: str = REPO) -> list[tuple[str, str, Any]]:
    rows = query_rows(instance, findings.COVERAGE_PLAN_QUERY, repo=repo)
    return sorted((r["surface"], r["concern"], r["status"]) for r in rows)


def created(outcome: Any, kind: str) -> list[str]:
    """The Subjects (kind/id) a write's create changes landed on, in change order."""

    return [
        c.subject
        for c in outcome.changes
        if c.op == "create" and c.subject and c.subject.startswith(kind + "/")
    ]


# -- convergence ------------------------------------------------------------------------


def test_an_agent_finding_and_a_sarif_result_converge_on_one_subject(tmp_path: Path) -> None:
    instance = audit_world(tmp_path)
    unit = unit_changes("u", "app/db.py#find_by_name", "injection", "checked", evidence=code())
    outcome = accepted_write(
        instance,
        tmp_path,
        [*unit, *agent_finding("f", unit={"created": "u"})],
        because="find_by_name formats name into the SQL text",
    )
    verdicts = {c.field: c.verdict for c in outcome.changes if c.field is not None}
    assert verdicts == dict.fromkeys(
        ("status", "reported_at", "reported_by", "rule", "found_in"), "supported"
    ), outcome.warnings
    (agent,) = query_rows(instance, findings.HELD_QUERY, repo=REPO)
    assert agent["locus"] == SQLI_LOCUS and agent["rules"] == ["audit:injection"], agent
    state = scan(instance, tmp_path, symbol_scan(("sqli-fstring-execute", DB, "find_by_name")))
    # The scan lands on the agent's Subject (none created): its rule, reporter,
    # severity and verification are new; its location revises the agent's
    # (reported_at is one-valued: the latest report says where).
    assert counts(state) == (4, 1, 0, 0, 0), counts(state)
    (row,) = query_rows(instance, findings.VERDICTS_QUERY, repo=REPO)
    assert row["subject_id"] == agent["subject_id"], row
    assert sorted(row["reported_by"]) == ["audit", "semgrep"], row
    (scanned,) = query_rows(instance, findings.HELD_QUERY, repo=REPO)
    assert sorted(scanned["rules"]) == ["audit:injection", "semgrep:sqli-fstring-execute"]


def test_the_file_rule_admits_the_workspace_file_family() -> None:
    """reported_at, rule, reported_by and coverage_unit.status admit any
    catalogued workspace file (D1); no ClaimType names a file."""

    file_rules = {
        record["predicate"]: rule
        for record in findings.claim_type_records()
        for rule in record.get("evidence_admission_policy", {}).get("rules", [])
        if rule["rule_id"] == "file"
    }
    assert sorted(file_rules) == sorted(
        [f"{FINDING}.{name}" for name in ("reported_at", "reported_by", "rule")]
        + [f"{UNIT}.status"]
    )
    for rule in file_rules.values():
        assert rule["capture_contract_families"] == ["workspace_file"]
        assert "capture_contracts" not in rule
    for claim_type in findings.claim_types():
        for rule in claim_type.evidence_admission_policy.rules:
            assert not any(
                "foreign-source" in item.target.qualified for item in rule.capture_contracts
            ), claim_type.predicate


# -- coverage units ---------------------------------------------------------------------


def test_a_unit_checked_with_a_file_receipt_and_found_in_resolve(tmp_path: Path) -> None:
    instance = audit_world(tmp_path)
    outcome = accepted_write(
        instance,
        tmp_path,
        [
            *unit_changes("u", "app/db.py#find_by_name", "injection", "checked", evidence=code()),
            *agent_finding("f", unit={"created": "u"}),
            *unit_changes("d", "app/db.py#find_by_id", "injection", "deferred"),
            *unit_changes("b", "app/routes.py#POST /users/:id", "access-control", "blocked"),
            *unit_changes("o", "app/admin.py#export", "ssrf", "out_of_scope"),
            *unit_changes("n", "app/routes.py#search", "injection", None),
        ],
        because="first pass over the gate app",
    )
    (status,) = [
        c
        for c in changed_claims(instance, outcome)
        if c.statement.predicate == UNIT + ".status" and c.statement.object.value == "checked"
    ]
    # The checked status cites the examined passage of the catalogued file.
    assert _cited_sources(instance, status) == {"gate-app.db"}
    (unit, *_rest) = created(outcome, UNIT)
    (finding,) = created(outcome, FINDING)
    rows = query_rows(instance, findings.FINDINGS_BY_UNIT_QUERY, unit=unit)
    assert [(f"{FINDING}/{r['finding']}", r["locus"]) for r in rows] == [(finding, SQLI_LOCUS)], (
        rows
    )
    # The plan re-opens never checked, deferred and blocked; never checked or out_of_scope.
    assert plan(instance) == [
        ("app/db.py#find_by_id", "injection", "deferred"),
        ("app/routes.py#POST /users/:id", "access-control", "blocked"),
        ("app/routes.py#search", "injection", None),
    ]
    assert (
        query_rows(instance, findings.FINDINGS_BY_UNIT_QUERY, unit=created(outcome, UNIT)[1]) == []
    )


# -- fail closed -------------------------------------------------------------------------


def test_a_status_outside_the_enum_refuses(tmp_path: Path) -> None:
    instance = audit_world(tmp_path)
    head = instance.accepted_coordinate()
    outcome = write(
        instance,
        tmp_path,
        unit_changes("u", "app/db.py#find_by_name", "injection", "done"),
        because="done with it",
    )
    assert outcome.status == "refused"
    assert outcome.refusal.code == "cruxible.write.value_not_member", outcome.refusal
    assert instance.accepted_coordinate() == head


def _never_cited_capture(instance: Any, source: str, text: bytes) -> str:
    """A foreign-source Capture of a catalogued file, built outside the write path:
    its contract was never accepted."""

    from datetime import UTC, datetime

    from cruxible_client.contracts.captures import (
        DirectForeignSourceSelection,
        build_foreign_source_capture,
    )
    from cruxible_client.contracts.semantic import ContentSpan
    from cruxible_core.indexes.projection import AcceptedCoordinate

    store = instance.body_store()
    stored = store.store(text)
    built = build_foreign_source_capture(
        store=store,
        actor_id="owner",
        claim_id="CLM-" + "a" * 32,
        rationale=f"read {source} outside the write path",
        observed_at=datetime(2026, 8, 20, 12, tzinfo=UTC),
        accepted_coordinate=AcceptedCoordinate.from_internal(instance.accepted_coordinate()),
        selection=DirectForeignSourceSelection(
            logical_source_identity=source,
            span=ContentSpan(content_digest=stored.digest, start_byte=0, end_byte=len(text)),
        ),
    )
    return built.capture_digest


@pytest.mark.parametrize("field", ["reported_at", "status"])
def test_a_file_never_cited_through_the_write_path_refuses(tmp_path: Path, field: str) -> None:
    """The family admits a catalogued file's Capture only under an accepted
    contract: a Capture of a file never cited through the workspace write path
    (no accepted contract) refuses, and nothing is written."""

    instance = audit_world(tmp_path, cited_before=())
    head = instance.accepted_coordinate()
    evidence = {
        "kind": "capture",
        "capture": _never_cited_capture(instance, "gate-app.db", DB_CODE),
    }
    if field == "status":
        changes = unit_changes("u", "app/db.py#find_by_name", "injection", "checked")
        changes[-1]["evidence"] = evidence
    else:
        changes = agent_finding("f", unit=None)[:2]
        changes[-1]["evidence"] = evidence
    outcome = write(instance, tmp_path, changes, because="read it elsewhere")
    assert outcome.status == "refused"
    assert outcome.refusal.code == "cruxible.authoring.capture_contract_unresolved", outcome.refusal
    assert instance.accepted_coordinate() == head


def test_an_uncatalogued_file_is_never_observed(tmp_path: Path) -> None:
    """The workspace catalog is the boundary: the writer's side refuses a path
    no catalog entry names before anything reaches the daemon."""

    from cruxible_client.authoring.sdk_types import SourceSelectionError

    instance = audit_world(tmp_path)
    write_file(tmp_path, "app/other.py", DB_CODE)
    head = instance.accepted_coordinate()
    changes = agent_finding("f", unit=None, locus="app/other.py#find_by_name")[:2]
    changes[-1]["evidence"] = {"kind": "file", "file": f"app/other.py#{SINK}"}
    with pytest.raises(SourceSelectionError, match="0 catalogued files"):
        write(instance, tmp_path, changes, because="formats name into SQL")
    assert instance.accepted_coordinate() == head


@pytest.mark.xfail(
    strict=True,
    reason="core (owner: core D1, evidence admission): a family rule verifies a "
    "Capture's foreign-source contract against accepted state at the write's base "
    "(historical_capture_contract), so the write that first cites a catalogued file "
    "and installs its contract in the same change is not admitted: reported_at refuses "
    "with cruxible.claim.captured_evidence_required, a checked status lands uncovered. "
    "Expected: the contract the write itself installs counts.",
)
def test_core_d1_a_first_citation_is_admitted(tmp_path: Path) -> None:
    instance = audit_world(tmp_path, cited_before=())
    outcome = write(
        instance,
        tmp_path,
        [
            *unit_changes("u", "app/db.py#find_by_name", "injection", "checked", evidence=code()),
            *agent_finding("f", unit={"created": "u"}),
        ],
        because="find_by_name formats name into the SQL text",
    )
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    verdicts = {c.field: c.verdict for c in outcome.changes if c.field is not None}
    assert verdicts == dict.fromkeys(
        ("status", "reported_at", "reported_by", "rule", "found_in"), "supported"
    )


PROBE = "security.probe-judgment"


def _probe_line(instance: Any, predicate: str) -> str:
    """A Procedure that writes a judgment from the scan, under a settle Mandate naming it."""

    from cruxible_client.contracts.authoring.inputs import ProcedureInput
    from tests.support.operation_world import NOW, author

    from definitions import refs

    spec = copy.deepcopy(findings.import_spec())
    spec["procedure"] = PROBE
    write_step = spec["steps"][-1]
    if predicate == UNIT + ".status":
        # Each scanned finding read as a unit: its locus the surface, its weakness the concern.
        write_step.pop("expect")
        (extract,) = [step for step in spec["steps"] if step.get("extract") == "found"]
        extract["key"] = {
            part: {"at": at, "type": f"key_part<{UNIT}:{part}>"}
            for part, at in (("repo", "repo"), ("surface", "locus"), ("concern", "weakness"))
        }
        write_step["subject"] = refs(
            {
                "kind": UNIT,
                "key": {part: f"$item.key.{part}" for part in ("repo", "surface", "concern")},
                "create": "if_absent",
            }
        )
        value, creates = "checked", UNIT
    else:
        value, creates = "confirmed", FINDING
    write_step["claims"] = [{"type": predicate, "value": value, "rationale": "the scan says"}]
    author(instance, ProcedureInput.model_validate({"kind": "procedure", "spec": spec}), name="p")
    automation = findings.automation([("probe", REPO, SEMGREP)], now=NOW)
    members = []
    for member in automation["members"]:
        if member["kind"] == "line" and member["procedure_name"] == findings.IMPORT_PROCEDURE:
            member["procedure_name"] = PROBE
        elif member["kind"] in ("line", "trigger"):
            continue  # the attention Line is not under test
        if member.get("grants") == "settle":
            member["subject_creation"] = [creates]
            member["scope"] = [
                {"claim_type": predicate, "changes": {"create": {"basis": ["extracted"]}}}
            ]
        members.append(member)
    submit(instance, {**automation, "members": members}, name="probe-automation")
    return findings.import_line_name("probe")


@pytest.mark.parametrize(
    "predicate", [UNIT + ".status", FINDING + ".verdict"], ids=["status", "verdict"]
)
def test_a_mandate_cannot_settle_a_judgment(tmp_path: Path, predicate: str) -> None:
    instance = audit_world(tmp_path)
    line = _probe_line(instance, predicate)
    head = instance.accepted_coordinate()
    write_file(tmp_path, SEMGREP, json.dumps(sarif("semgrep-gate-app-vulnerable.sarif")).encode())
    state = run(instance, line)
    # A scan's Capture backs no judgment: the claims refuse, nothing is written.
    assert state.status != "succeeded"
    details = state.terminal.model_dump(mode="json")
    assert details["code"] == "proposal_lowering_refused", details
    assert details["details"]["code"] == "cruxible.authoring.existing_capture_not_admitted"
    assert instance.accepted_coordinate() == head
    assert plan(instance) == []
    assert all(
        r["verdict"] is None for r in query_rows(instance, findings.VERDICTS_QUERY, repo=REPO)
    )


def test_a_sarif_only_run_never_writes_coverage(tmp_path: Path) -> None:
    instance = audit_world(tmp_path)
    assert not any(
        claim["type"].startswith(UNIT + ".")
        for claim in findings.import_spec()["steps"][-1]["claims"]
    )
    first = scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    fixed = scan(instance, tmp_path, sarif("semgrep-gate-app-fixed.sarif"), minute=1)
    for state in (first, fixed):
        assert not [
            c for c in changed(instance, state).values() if c.statement.predicate.startswith(UNIT)
        ]
    assert plan(instance) == []
    with instance.bind_accepted_projection(instance.accepted_coordinate()) as projection:
        (units,) = projection.typed.connection.execute(
            "SELECT count(*) FROM subjects WHERE subject_kind=?", (UNIT,)
        ).fetchone()
    assert units == 0


# -- work counts at two sizes ------------------------------------------------------------

_SIZES = (10, 40)
_SLOPE_RATIO = 1.15
_SLOPE_SLACK = 2.0
_COUNTERS = (
    "sql_statements",
    "sql_vm_steps",
    "claim_parses",
    "canonical_digests",
    "projection_binds",
    "cas_body_reads",
    "git_blob_reads",
)
OTHER = "github.com/acme/other-app"
HUB = ("app/hub.py#dispatch", "injection")


def _units(repo: str, size: int, prefix: str, status: str | None = None) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for index in range(size):
        label = f"{prefix}{index}"
        changes.append(
            {
                "op": "create",
                "label": label,
                "subject_kind": UNIT,
                "key": _key(UNIT, repo=repo, surface=f"app/m{index}.py#{label}", concern="xss"),
            }
        )
        if status is not None:
            changes.append(
                {"op": "set", "subject": {"created": label}, "field": "status", "value": status}
            )
    return changes


def _findings_in(unit: Any, repo: str, size: int, prefix: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for index in range(size):
        label = f"{prefix}{index}"
        changes += [
            {
                "op": "create",
                "label": label,
                "subject_kind": FINDING,
                "key": _key(
                    FINDING, repo=repo, weakness="CWE-79", locus=f"app/m{index}.py#{label}"
                ),
            },
            {"op": "add", "subject": {"created": label}, "field": "found_in", "value": unit},
        ]
    return changes


def _audit_state(tmp_path: Path, *, output: int, unrelated: int) -> tuple[Any, str]:
    """``output`` open units and findings in the hub unit, beside ``unrelated``
    checked units, other-repository units and findings in other units."""

    instance = audit_world(tmp_path)
    hub = accepted_write(
        instance,
        tmp_path,
        [
            *unit_changes("hub", *HUB, "checked"),
            *_findings_in({"created": "hub"}, REPO, output, "f"),
            *_units(REPO, output, "a"),
        ],
        because="the measured audit",
    )
    (hub_unit,) = created(hub, UNIT)[:1]
    accepted_write(
        instance,
        tmp_path,
        [
            *_units(REPO, unrelated, "c", "checked"),
            *_units(OTHER, unrelated, "o"),
            *unit_changes("side", "app/side.py#side", "ssrf", "checked"),
            *_findings_in({"created": "side"}, REPO, unrelated, "g"),
        ],
        because="unrelated coverage",
    )
    return instance, hub_unit


def _measured(tmp_path: Path, *, output: int, unrelated: int) -> dict[str, dict[str, float]]:
    from tests.test_scale._counters import counting, trace_sqlite

    out: dict[str, dict[str, float]] = {}
    with trace_sqlite(tmp_path):
        instance, hub = _audit_state(tmp_path, output=output, unrelated=unrelated)
        reads = {
            "coverage_plan": lambda: query_rows(instance, findings.COVERAGE_PLAN_QUERY, repo=REPO),
            "findings_by_unit": lambda: query_rows(
                instance, findings.FINDINGS_BY_UNIT_QUERY, unit=hub
            ),
        }
        for read in reads.values():
            read()  # warm: the measured read is a steady-state read
        for name, read in reads.items():
            with counting(tmp_path) as window:
                rows = read()
            assert not window.unexplained, window.unexplained
            out[name] = {"rows": len(rows), **{c: window.counts[c] for c in _COUNTERS}}
    return out


def _sized(tmp_path: Path, sizes: Sequence[tuple[int, int]]) -> list[dict[str, dict[str, float]]]:
    measured = []
    for output, unrelated in sizes:
        root = tmp_path / f"o{output}-u{unrelated}"
        root.mkdir()
        measured.append(_measured(root, output=output, unrelated=unrelated))
    return measured


def test_audit_reads_are_linear_in_their_output(tmp_path: Path) -> None:
    small, large = _sized(tmp_path, [(size, _SIZES[0]) for size in _SIZES])
    for found, size in ((small, _SIZES[0]), (large, _SIZES[1])):
        assert found["coverage_plan"]["rows"] == size
        assert found["findings_by_unit"]["rows"] == size
    for read in ("coverage_plan", "findings_by_unit"):
        for counter in _COUNTERS:
            marginal = (large[read][counter] - small[read][counter]) / (_SIZES[1] - _SIZES[0])
            average = small[read][counter] / _SIZES[0]
            assert marginal <= average * _SLOPE_RATIO + _SLOPE_SLACK, (read, counter, small, large)
    report = os.environ.get("AUDIT_WORK_COUNTS")
    if report:
        Path(report).write_text(json.dumps({"small": small, "large": large}, indent=1) + "\n")


@pytest.mark.xfail(
    strict=True,
    reason="core (owner: core, query pushdown): both audit reads load every coverage unit "
    "and finding. service/discovery/query_pushdown.py returns the full load for a "
    "conjunction with any unsupported conjunct (coverage_plan's `not exists u.status`; "
    "its seekable `u.repo == $repo` could narrow alone, the selection being a superset), "
    "for any traversal (findings_by_unit's reverse found_in hop) and for a Subject-valued "
    "value (`f.found_in == $unit`). Expected: constant work as unrelated units grow.",
)
def test_core_audit_reads_are_constant_in_unrelated_units(tmp_path: Path) -> None:
    few, many = _sized(tmp_path, [(_SIZES[0], size) for size in _SIZES])
    for read in ("coverage_plan", "findings_by_unit"):
        assert few[read]["rows"] == many[read]["rows"] == _SIZES[0]
        for counter in ("sql_statements", "sql_vm_steps", "claim_parses"):
            assert many[read][counter] <= few[read][counter] * 1.05 + 2, (read, counter, few, many)


# -- guidance (K-CA4) --------------------------------------------------------------------


def test_guidance_guides_only_kit_claim_types() -> None:
    import install

    declared = {record["predicate"] for record in findings.claim_type_records()}
    members = install.guidance_members()
    assert [m["document_id"] for m in members[:3]] == [
        "security.guidance.hunter",
        "security.guidance.verifier",
        "security.guidance.coverage",
    ]
    for member in members:
        targets = {link["target_identity"].removeprefix("ClaimType:") for link in member["links"]}
        assert targets <= declared, (member["document_id"], targets - declared)
        assert bool(targets) is (member["document_kind"] == "security.guidance"), member
    assert len(members) == 3 + 12


@pytest.mark.xfail(
    strict=True,
    reason="core-surface item 11 (owner: core-surface item 11): kits ship Documents. Until "
    "then a change set has no Document member, so the guidance and reference Documents "
    "(install.guidance_members, a TODO) cannot be installed.",
)
def test_core_surface_item_11_guidance_installs_as_governed_documents() -> None:
    from cruxible_client.contracts.authoring.inputs import ChangeSetInput

    import install

    ChangeSetInput.model_validate(
        {
            "kind": "change_set",
            "rationale": "Security audit guidance",
            "members": install.guidance_members(),
        }
    )


# -- helpers on accepted state -------------------------------------------------------------


def changed_claims(instance: Any, outcome: Any) -> list[Any]:
    """The accepted Claims a write's changes name."""

    from cruxible_client.contracts.claims import parse_claim

    tree = instance.tree_at(instance.accepted_coordinate().git_oid)
    out = []
    for change in outcome.changes:
        if change.claim is None:
            continue
        name = change.claim.removeprefix("Claim:")
        path = f"claims/{name[4:6]}/{name}.json"
        out.append(parse_claim(tree[path], path=path))
    return out


def _cited_sources(instance: Any, claim: Any) -> set[str]:
    """The logical sources of the Captures a Claim cites (a file: its catalog name)."""

    from cruxible_client.contracts.captures import parse_capture_envelope
    from cruxible_client.contracts.cas_contracts import BodyAccessContext

    access = BodyAccessContext(principal_id="kit-audit-gate", can_read_body=True)
    names = set()
    for citation in claim.backing.citations:
        envelope = parse_capture_envelope(
            instance.body_store().read(citation.capture_digest, access=access)
        )
        names.add(envelope.source.source_identity)
    return names
