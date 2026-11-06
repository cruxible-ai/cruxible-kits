"""Batch-2 gate: code findings (SARIF -> findings -> agents judge -> fix verified).

The kit's own payloads (``definitions.py`` + ``findings.py``) are authored into
a fresh in-process instance, as ``test_pilot_gate.py`` does; the SARIF files
are read through core's builtin ``workspace.file`` from a temporary workspace,
and the real ``sarif.findings`` derive (``security-sarif-provider``) answers
the derive call in-process. The SARIF files are the provider's test data:
Semgrep's are recorded, CodeQL's are hand-built in CodeQL's shape.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$RUNTIME/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_findings_gate.py
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from test_pilot_gate import accepted, changed, kit_world, submit, summary, write_file

import findings  # noqa: E402

PROVIDER = findings.PROVIDER_ROOT.parents[1]
sys.path.insert(0, str(PROVIDER / "src"))

from security_sarif_provider import sarif as derive  # noqa: E402

DATA = PROVIDER / "tests" / "data"
REPO = "github.com/cruxible-ai/gate-app"
SEMGREP = "scans/semgrep.sarif"
CODEQL = "scans/codeql.sarif"
FINDING = findings.FINDING
SQLI = ("CWE-89", "app/db.py")
TRAVERSAL = ("CWE-22", "app/files.py")


def sarif(name: str) -> dict[str, Any]:
    return json.loads((DATA / name).read_bytes())


def encode(document: Mapping[str, Any] | bytes) -> bytes:
    return document if isinstance(document, bytes) else json.dumps(document, indent=2).encode()


# -- the world ---------------------------------------------------------------------------


def _sarif_build(instance: Any) -> Any:
    from cruxible_client.contracts.providers import (
        ProviderLocalDistributionPin,
        ProviderLocalEnvBackendPin,
    )
    from cruxible_core.providers.package_metadata import read_package_registration
    from cruxible_core.service.procedures.provider_installation import tree_contract_digests

    digests = tree_contract_digests(instance.tree_at(instance.accepted_coordinate().git_oid))
    registration = read_package_registration(findings.PROVIDER_ROOT)
    return registration.provider_definition(
        distribution=ProviderLocalDistributionPin(
            name=registration.manifest.distribution.name,
            version=registration.manifest.distribution.version,
            filename="security_sarif_provider-0.1.0.dev0-py3-none-any.whl",
            sha256="sha256:" + "5a" * 32,
        ),
        local_env=ProviderLocalEnvBackendPin(
            lock_sha256="sha256:" + "b" * 64,
            materialization_digests={"linux-cp311": "sha256:" + "c" * 64},
        ),
        control_domain=findings.PROVIDER_PACKAGE,
        operations=registration.pinned_operations(digests),
    )


def findings_world(
    tmp_path: Path, *, scans: tuple[tuple[str, str, str], ...] = (("semgrep", REPO, SEMGREP),)
) -> Any:
    """The whole kit plus the code-findings vocabulary, provider, Procedures and Lines."""

    from cruxible_client.contracts.authoring.inputs import ProcedureInput
    from cruxible_client.contracts.capture_contract_inputs import (
        CaptureContractInputRecord,
        lower_capture_contract_input,
    )
    from cruxible_client.contracts.captures import capture_contract_path, render_capture_contract
    from tests.core_support._identity_support import accept_tree
    from tests.support.operation_world import NOW, author, build_files

    instance = kit_world(tmp_path)
    submit(
        instance,
        {"kind": "change_set", "members": findings.provider_contract_members()},
        name="sarif-contracts",
    )
    accept_tree(instance, build_files(_sarif_build(instance)), name="sarif-build")
    kinds = {
        capture_contract_path(name): render_capture_contract(
            lower_capture_contract_input(
                CaptureContractInputRecord.model_validate(record), named=True
            )
        )
        for name, record in findings.capture_kinds().items()
    }
    accept_tree(instance, kinds, name="sarif-kinds")
    submit(instance, findings.vocabulary(), name="findings-vocabulary")
    for index, member in enumerate(findings.procedures()["members"]):
        author(instance, ProcedureInput.model_validate(member), name=f"findings-procedure-{index}")
    submit(instance, findings.automation(scans, now=NOW), name="findings-automation")
    return instance


# -- running a Line ----------------------------------------------------------------------


class Scanner:
    """Answers the Line's two calls: the workspace read (core's builtin) and the
    derive (the real ``sarif.findings``). ``doctor`` edits the derived document
    (fail-closed cases a correct derive never produces)."""

    def __init__(self, doctor: Callable[[dict[str, Any]], dict[str, Any]] | None = None):
        self.doctor = doctor
        self.calls: list[str] = []

    def operator(self) -> Any:
        from cruxible_provider_runtime.acquisition import external_capture_result
        from cruxible_provider_runtime.egress import EgressRecorder
        from cruxible_provider_runtime.protocol import Budgets
        from cruxible_provider_runtime.provider_api import ProviderRunContext
        from tests.support.operation_world import Invoker, Operator

        def output(context: Any) -> dict[str, Any]:
            if "commitment_digest" in context.input:
                from cruxible_core.providers.builtin_workspace_file import WorkspaceFile

                self.calls.append("read")
                envelope = WorkspaceFile()(context)
                assert envelope.status == "ok", envelope
                return dict(envelope.output or {})
            self.calls.append("derive")
            result = derive.SarifFindings()(
                ProviderRunContext(
                    run_id=context.run_id,
                    input=dict(context.input),
                    operation=derive.OPERATION,
                    operation_signature_digest="sha256:" + "9" * 64,
                    build_digest="sha256:" + "b" * 64,
                    implementation_digest="sha256:" + "a" * 64,
                    declared_endpoints=(),
                    budgets=Budgets(wall_clock_seconds=30, output_bytes=8_000_000),
                    coordinates={},
                    capture_contract=None,
                    secrets={},
                    egress=EgressRecorder(),
                )
            )
            if result.status == "refused":
                raise _Refused(result.refusal.code if result.refusal else "provider_declined")
            assert result.status == "ok", result
            out = dict(result.output)
            if self.doctor is not None:
                wire = out["document"]
                document = self.doctor(json.loads(_content(wire)))
                out["document"] = external_capture_result(
                    derive.document_bytes(document),
                    source_identity=wire["source_identity"],
                    coordinate_type=wire["coordinate_type"],
                    coordinate=wire["coordinate"],
                    observed_at=_observed(wire),
                    selector_type=wire["selector_type"],
                )
            return out

        class Refusing(Invoker):
            """Answers a derive's declared refusal as the runtime does: a refused envelope."""

            def invoke_provider(self, **kwargs: Any) -> Any:  # type: ignore[override]
                try:
                    return super().invoke_provider(**kwargs)
                except _Refused as refused:
                    self.refusal = (refused.code, {})
                    try:
                        return super().invoke_provider(**kwargs)
                    finally:
                        self.refusal = None

        return Operator(Refusing(output=output))


class _Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _content(wire: Mapping[str, Any]) -> bytes:
    import base64

    return base64.b64decode(wire["content_base64"])


def _observed(wire: Mapping[str, Any]) -> Any:
    from datetime import datetime

    return datetime.fromisoformat(str(wire["observed_at"]).replace("Z", "+00:00"))


def run(instance: Any, line: str, *, scanner: Scanner | None = None, minute: int = 0) -> Any:
    from cruxible_core.documents.workspace_file import WorkspaceFileReader
    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        service_run_playbill_line,
    )
    from tests.support.operation_world import NOW, actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    state = service_run_playbill_line(
        instance,
        path_identity_digest=line,
        request=LineRunRequest(line=line),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(NOW + timedelta(minutes=minute)),
        provider_runtime_operator=(scanner or Scanner()).operator(),  # type: ignore[arg-type]
        workspace_file_reader=WorkspaceFileReader(
            instance_id=instance.descriptor.instance_id,
            operating_profile="local",
            attached_roots=(instance.root.parent / "workspace",),
            managed_roots=(instance.root,),
        ),
    )
    return state


def scan(
    instance: Any,
    tmp_path: Path,
    document: Mapping[str, Any] | bytes,
    *,
    path: str = SEMGREP,
    line: str = "semgrep",
    minute: int = 0,
    scanner: Scanner | None = None,
) -> Any:
    """Write the SARIF file into the workspace and run its import Line."""

    write_file(tmp_path, path, encode(document))
    state = run(instance, findings.import_line_name(line), scanner=scanner, minute=minute)
    assert state.status == "succeeded", json.dumps(state.terminal.model_dump(mode="json"))[:4000]
    return state


def held(instance: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """Every finding of the repository, by (weakness, path), from the judgment Query."""

    rows = query_rows(instance, findings.VERDICTS_QUERY, repo=REPO)
    return {(r["weakness"], r["locus"].split("#", 1)[0]): r for r in rows}


def query_rows(instance: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    from cruxible_client.contracts.compact_query import QueryRequest
    from cruxible_core.service.discovery.compact_query import service_playbill_query

    page = service_playbill_query(instance, request=QueryRequest(name=query, params=params or None))
    return [dict(row) for row in page.rows]


def counts(state: Any) -> tuple[int, int, int, int, int]:
    claims = summary(state, "claims")
    return (
        claims.written,
        claims.revised,
        claims.re_observed,
        claims.retired,
        claims.subjects_created,
    )


# -- inbox, attention and edits ---------------------------------------------------------


def inbox(instance: Any, line: str) -> list[Any]:
    """The payloads of every item one Line posted (findings or attention items)."""

    from cruxible_core.exhaust.line_inbox import LineInboxStore

    store = LineInboxStore(instance)
    entries, _cursor = store.page(line=None, status=None, limit=200, cursor=None)
    return [
        store.get(e.envelope.item_id).payload
        for e in entries
        if e.envelope.line.endswith(line) or line in json.dumps(e.envelope.model_dump(mode="json"))
    ]


def attention(instance: Any, upstream: Any, *, suffix: str = "semgrep", minute: int = 0) -> Any:
    """Run the attention Line as its Trigger does: on the import's derived Capture."""

    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        TriggerFire,
        service_run_playbill_line,
    )
    from tests.support.operation_world import NOW, actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    (call,) = (node for node in upstream.nodes if node.node == "findings")
    (event,) = [
        o.capture_event
        for o in upstream.outcomes
        if o.event_kind == "produced_capture" and o.node_id == call.node
    ]
    line = findings.attention_line_name(suffix)
    state = service_run_playbill_line(
        instance,
        path_identity_digest=line,
        request=LineRunRequest(line=line),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(NOW + timedelta(minutes=minute)),
        trigger_fire=TriggerFire(trigger=f"security.sarif-findings-landed.{suffix}", event=event),
    )
    assert state.status == "succeeded", json.dumps(state.terminal.model_dump(mode="json"))[:4000]
    return state


def moved(document: dict[str, Any], *, by: int) -> dict[str, Any]:
    """The same scan with every result ``by`` lines lower (an edit above the sinks)."""

    out = copy.deepcopy(document)
    for run_ in out["runs"]:
        for result in run_["results"]:
            for location in result["locations"]:
                region = location["physicalLocation"].get("region") or {}
                for name in ("startLine", "endLine"):
                    if name in region:
                        region[name] += by
    return out


def partial(document: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(document)
    for run_ in out["runs"]:
        run_["properties"] = {**run_.get("properties", {}), "cruxible.coverage": "partial"}
    return out


def other_repo(document: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(document)
    for run_ in out["runs"]:
        run_["versionControlProvenance"][0]["repositoryUri"] = "https://github.com/acme/other"
    return out


def judge(
    instance: Any,
    key: tuple[str, str],
    *,
    predicate: str,
    value: str,
    why: str,
    revises: str | None = None,
) -> None:
    """An agent's normative Claim on the held finding ``key`` (weakness, path)."""

    row = held(instance)[key]
    submit(
        instance,
        {
            "kind": "change_set",
            "rationale": why,
            "members": [
                findings.judgment(
                    {"repo": REPO, "weakness": row["weakness"], "locus": row["locus"]},
                    predicate=predicate,
                    value=value,
                    rationale=why,
                    revises=revises,
                )
            ],
        },
        name=f"judge-{predicate}",
    )


def kinds(state: Any) -> list[str]:
    return sorted(f.kind for f in state.findings)


# -- the gate ---------------------------------------------------------------------------


def test_semgrep_import_writes_findings_by_key(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    state = scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    assert state.terminal_egress[0].settle_outcome == "settled", state.terminal_egress
    # Two findings: rule, reported_by, severity, reported_at, verification each.
    assert counts(state) == (10, 0, 0, 0, 2)
    rows = held(instance)
    assert set(rows) == {SQLI, TRAVERSAL}, rows
    sqli = rows[SQLI]
    assert sqli["locus"].startswith("app/db.py#snippet:"), sqli  # Semgrep has no symbols
    assert sqli["reported_by"] == ["semgrep"] and sqli["verification"] == "present", sqli
    # Every Claim cites the one derived document, extracted from its records.
    scanned = {
        FINDING + p for p in (".rule", ".reported_by", ".severity", ".reported_at", ".verification")
    }
    claims = [c for c in changed(instance, state).values() if c.statement.predicate in scanned]
    assert len(claims) == 10
    (root,) = {c.backing.capture_digests for c in claims}
    assert len(root) == 1
    for claim in claims:
        assert accepted(instance, claim).backing.procedure_evidence.value.basis == "extracted"
    values = {
        (c.statement.subject.artifact_path, c.statement.predicate): c.statement.object
        for c in claims
    }
    severities = sorted(v.value for (_s, p), v in values.items() if p == FINDING + ".severity")
    assert severities == ["high", "medium"]  # security-severity 8.8; level warning
    at = sorted(v.value for (_s, p), v in values.items() if p == FINDING + ".reported_at")
    assert at == ["app/db.py:12", "app/files.py:12"]


def test_an_identical_rerun_writes_nothing(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    document = sarif("semgrep-gate-app-vulnerable.sarif")
    scan(instance, tmp_path, document)
    head = instance.accepted_coordinate()
    again = scan(instance, tmp_path, document, minute=1)
    assert again.terminal_egress[0].proposal_id is None
    assert counts(again) == (0, 0, 10, 0, 0)
    assert instance.accepted_coordinate() == head
    assert kinds(again) == []


def test_codeql_import_has_its_own_key(tmp_path: Path) -> None:
    scans = (("semgrep", REPO, SEMGREP), ("codeql", REPO, CODEQL))
    instance = findings_world(tmp_path, scans=scans)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    state = scan(
        instance, tmp_path, sarif("codeql-gate-app-vulnerable.sarif"), path=CODEQL, line="codeql"
    )
    assert state.terminal_egress[0].settle_outcome == "settled"
    assert counts(state) == (5, 0, 0, 0, 1)
    rows = query_rows(instance, findings.VERDICTS_QUERY, repo=REPO)
    sqli = sorted((r["locus"], r["reported_by"]) for r in rows if r["weakness"] == "CWE-89")
    assert len(sqli) == 2, rows  # CodeQL names no snippet or symbol: its line hash
    (codeql,) = [locus for locus, by in sqli if by == ["codeql"]]
    assert codeql == "app/db.py#line-hash:3d1c6f0a9e2b7745:1"
    # CodeQL's full rescan of the fix verifies its own finding only: Semgrep's
    # SQLi was found by a rule CodeQL's rule set does not have.
    fixed = scan(
        instance,
        tmp_path,
        sarif("codeql-gate-app-fixed.sarif"),
        path=CODEQL,
        line="codeql",
        minute=1,
    )
    assert counts(fixed)[1] == 1
    verification = {
        r["locus"]: r["verification"]
        for r in query_rows(instance, findings.VERDICTS_QUERY, repo=REPO)
        if r["weakness"] == "CWE-89"
    }
    assert verification[codeql] == "fixed"
    assert [v for locus, v in verification.items() if locus != codeql] == ["present"]


def test_a_finding_that_moved_lines_relocates(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    document = sarif("semgrep-gate-app-vulnerable.sarif")
    scan(instance, tmp_path, document)
    before = {k: r["subject_id"] for k, r in held(instance).items()}
    state = scan(instance, tmp_path, moved(document, by=7), minute=1)
    # The same two Subjects; only where they are revises (no duplicate finding).
    assert counts(state) == (0, 2, 8, 0, 0)
    assert {k: r["subject_id"] for k, r in held(instance).items()} == before
    at = sorted(
        c.statement.object.value
        for c in changed(instance, state).values()
        if c.statement.predicate == FINDING + ".reported_at"
    )
    assert at == ["app/db.py:19", "app/files.py:19"]


def test_a_full_rescan_verifies_the_fix(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    state = scan(instance, tmp_path, sarif("semgrep-gate-app-fixed.sarif"), minute=1)
    assert state.terminal_egress[0].settle_outcome == "settled", state.terminal_egress
    # SQLi: verification revised to fixed, its last location retired on absence.
    assert counts(state) == (0, 1, 5, 1, 0)
    rows = held(instance)
    assert rows[SQLI]["verification"] == "fixed"
    assert rows[TRAVERSAL]["verification"] == "present"
    (retired,) = [c for c in changed(instance, state).values() if c.lifecycle.state == "retired"]
    assert retired.statement.predicate == FINDING + ".reported_at"
    assert retired.retirement.absence.logical_source == findings.logical_source("semgrep")


def test_a_partial_scan_never_marks_fixed(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    fixed = sarif("semgrep-gate-app-fixed.sarif")
    for minute, document in enumerate((partial(fixed), _failed(fixed)), start=1):
        state = scan(instance, tmp_path, document, minute=minute)
        # The traversal is still reported (re-observed); the SQLi is not judged.
        assert counts(state) == (0, 0, 5, 0, 0), minute
        assert held(instance)[SQLI]["verification"] == "present"


def _failed(document: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(document)
    out["runs"][0]["invocations"][0]["executionSuccessful"] = False
    return out


def test_a_fixed_finding_reappearing_is_a_regression_in_the_inbox(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    vulnerable = sarif("semgrep-gate-app-vulnerable.sarif")
    scan(instance, tmp_path, vulnerable)
    scan(instance, tmp_path, sarif("semgrep-gate-app-fixed.sarif"), minute=1)
    state = scan(instance, tmp_path, vulnerable, minute=2)
    # verification fixed -> present, and its location again.
    assert counts(state) == (1, 1, 8, 0, 0)
    assert held(instance)[SQLI]["verification"] == "present"
    posted = attention(instance, state, minute=3)
    assert summary(posted, "post_inbox").emitted == 1
    (item,) = inbox(instance, findings.attention_line_name("semgrep"))
    assert item["kind"] == "regression" and item["weakness"] == "CWE-89", item
    assert item["finding"] == held(instance)[SQLI]["subject_id"]


def test_a_location_gap_reaches_the_inbox_and_is_no_finding(tmp_path: Path) -> None:
    scans = (("auditor", REPO, "scans/auditor.sarif"),)
    instance = findings_world(tmp_path, scans=scans)
    state = scan(
        instance,
        tmp_path,
        sarif("auditor-gate-app.sarif"),
        path="scans/auditor.sarif",
        line="auditor",
    )
    assert counts(state)[4] == 1  # the located CWE-89 only
    posted = attention(instance, state, suffix="auditor")
    assert summary(posted, "post_inbox").emitted == 1
    (item,) = inbox(instance, findings.attention_line_name("auditor"))
    assert (item["kind"], item["rule"], item["reason"]) == (
        "location_gap",
        "auditor:CWE-79",
        "no_stable_location",
    )


def test_the_wrong_repository_writes_nothing(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    document = sarif("semgrep-gate-app-vulnerable.sarif")
    scan(instance, tmp_path, document)
    head = instance.accepted_coordinate()
    state = scan(instance, tmp_path, other_repo(sarif("semgrep-gate-app-fixed.sarif")), minute=1)
    assert counts(state) == (0, 0, 0, 0, 0)
    assert summary(state, "extract").records == 0
    assert instance.accepted_coordinate() == head
    assert held(instance)[SQLI]["verification"] == "present"


def test_an_agent_judgment_holds_when_the_scanner_disagrees(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    document = sarif("semgrep-gate-app-vulnerable.sarif")
    first = scan(instance, tmp_path, document)
    sqli = held(instance)[SQLI]["subject_id"]
    (scanned,) = [
        c.identity.name
        for c in changed(instance, first).values()
        if c.statement.predicate == FINDING + ".severity"
        and c.statement.subject.artifact_path.endswith(sqli.rsplit("/", 1)[-1] + ".json")
    ]
    judge(
        instance,
        SQLI,
        predicate="severity",
        value="low",
        why="Only admins reach find_by_name.",
        revises=scanned,
    )
    judge(
        instance,
        TRAVERSAL,
        predicate="verdict",
        value="false_positive",
        why="realpath and the BASE prefix check keep every path under the root.",
    )
    judge(instance, TRAVERSAL, predicate="justification", value="sanitized", why="See verdict.")
    state = scan(instance, tmp_path, document, minute=1)
    # The scanner still says high: recorded, routed to the Line's inbox, never applied.
    (disagrees,) = [f for f in state.findings if f.kind == "held_disagrees"]
    assert (disagrees.held_value["value"], disagrees.incoming_value["value"]) == ("low", "high")
    assert counts(state) == (0, 0, 9, 0, 0)
    rows = held(instance)
    assert rows[SQLI]["severity"] == "low"  # the agent's, not the scan's high
    assert rows[TRAVERSAL]["verdict"] == "false_positive"
    assert rows[TRAVERSAL]["justification"] == "sanitized"
    posted = inbox(instance, findings.import_line_name("semgrep"))
    assert any("held_disagrees" in json.dumps(p) for p in posted), posted


# -- fail closed -------------------------------------------------------------------------


def _with_result(document: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(document)
    out["runs"][0]["results"].append(result)
    return out


def _result(rule: str, path: str, *, snippet: str | None = None, symbol: str | None = None):
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": 3}}
    }
    if snippet is not None:
        location["physicalLocation"]["region"]["snippet"] = {"text": snippet}
    if symbol is not None:
        location["logicalLocations"] = [{"fullyQualifiedName": symbol}]
    return {"ruleId": rule, "locations": [location], "message": {"text": "x"}}


def _garbled(document: dict[str, Any]) -> dict[str, Any]:
    """The traversal's record replaced by one that is no record (a corrupt document)."""

    records: list[Any] = [r for r in document["findings"] if r["weakness"] != "CWE-22"]
    return {**document, "findings": [*records, "garbled"]}


def _long_key(document: dict[str, Any]) -> dict[str, Any]:
    """The traversal's locus over its key ClaimType's 256 code points."""

    records = [dict(r) for r in document["findings"]]
    (target,) = [r for r in records if r["weakness"] == "CWE-22"]
    target["locus"] = "app/files.py#" + "x" * 300
    return {**document, "findings": records}


@pytest.mark.parametrize("doctor", [_garbled, _long_key], ids=["garbled", "long_key"])
def test_an_unparseable_record_fails_closed(tmp_path: Path, doctor: Any) -> None:
    """Today an unparseable record fails the whole run: nothing is written, fixed or retired."""

    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    head = instance.accepted_coordinate()
    write_file(tmp_path, SEMGREP, encode(sarif("semgrep-gate-app-fixed.sarif")))
    state = run(
        instance, findings.import_line_name("semgrep"), scanner=Scanner(doctor=doctor), minute=1
    )
    assert state.status != "succeeded"
    assert instance.accepted_coordinate() == head
    assert held(instance)[SQLI]["verification"] == "present"


@pytest.mark.xfail(
    strict=True,
    reason="core (owner: core): an unparseable record fails the run instead of being "
    "inadmissible. A record that is no object, or a key part outside its key ClaimType "
    "under a plain type, reaches the claims terminal, which resolves $item.key.<part> on "
    "it and fails internal_failed (claims_terminal.expand_claims: the subject key is "
    "resolved before any invalid-record check); under key_part<K:p> an over-long part "
    "passes the extract and the whole run refuses at publication (value_invalid). "
    "Expected: that record refused (extract_refused), the read incomplete, siblings "
    "written.",
)
@pytest.mark.parametrize("doctor", [_garbled, _long_key], ids=["garbled", "long_key"])
def test_core_an_unparseable_record_is_inadmissible_per_record(tmp_path: Path, doctor: Any) -> None:
    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    state = scan(
        instance,
        tmp_path,
        sarif("semgrep-gate-app-fixed.sarif"),
        minute=1,
        scanner=Scanner(doctor=doctor),
    )
    assert summary(state, "extract").invalid_records == 1
    assert counts(state) == (0, 0, 0, 0, 0)  # incomplete: the SQLi is not fixed
    assert held(instance)[SQLI]["verification"] == "present"
    assert "incomplete_source" in kinds(state)


def test_an_invalid_value_is_inadmissible_while_its_record_writes(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)

    def garbled(document: dict[str, Any]) -> dict[str, Any]:
        records = [dict(r) for r in document["findings"]]
        (target,) = [r for r in records if r["weakness"] == "CWE-22"]
        target["severity"] = "severe"  # not a member
        return {**document, "findings": records}

    state = scan(
        instance,
        tmp_path,
        sarif("semgrep-gate-app-vulnerable.sarif"),
        scanner=Scanner(doctor=garbled),
    )
    assert summary(state, "extract").invalid_fields == 1
    assert counts(state) == (9, 0, 0, 0, 2)  # every value but that severity
    (refused,) = [f for f in state.findings if f.kind == "extract_refused"]
    assert refused.lexeme == "severe"


def test_an_unkeyable_result_is_a_location_gap_and_its_siblings_write(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    document = _with_result(
        sarif("semgrep-gate-app-vulnerable.sarif"),
        _result("open-joined-path", "app/long.py", symbol="pkg." + "x" * 300),
    )
    state = scan(instance, tmp_path, document)
    assert counts(state) == (10, 0, 0, 0, 2)  # the two located findings
    posted = attention(instance, state, minute=1)
    (item,) = inbox(instance, findings.attention_line_name("semgrep"))
    assert (item["kind"], item["reason"], item["path"]) == (
        "location_gap",
        "unkeyable_location",
        "app/long.py",
    )
    assert summary(posted, "post_inbox").emitted == 1


def _lost_location(document: dict[str, Any]) -> dict[str, Any]:
    """The SQLi's result, still reported, has lost its snippet (and has no fingerprint)."""

    out = copy.deepcopy(document)
    (result,) = [r for r in out["runs"][0]["results"] if r["ruleId"] == "sqli-fstring-execute"]
    del result["locations"][0]["physicalLocation"]["region"]["snippet"]
    result.pop("partialFingerprints", None)
    return out


def _scalar_result(document: dict[str, Any]) -> dict[str, Any]:
    """The SQLi's result replaced by a malformed scalar."""

    out = copy.deepcopy(document)
    results = out["runs"][0]["results"]
    (index,) = [i for i, r in enumerate(results) if r["ruleId"] == "sqli-fstring-execute"]
    results[index] = 42
    return out


@pytest.mark.parametrize(
    ("edit", "reason"),
    [(_lost_location, "no_stable_location"), (_scalar_result, "malformed_result")],
    ids=["lost_snippet", "malformed_scalar"],
)
def test_a_held_finding_the_rescan_cannot_place_is_never_fixed(
    tmp_path: Path, edit: Any, reason: str
) -> None:
    instance = findings_world(tmp_path)
    vulnerable = sarif("semgrep-gate-app-vulnerable.sarif")
    scan(instance, tmp_path, vulnerable)
    # A full rescan that still reports the SQLi, but in a form the derive cannot
    # place: its rule is tainted, so it covers nothing; no fixed, no retirement.
    state = scan(instance, tmp_path, edit(vulnerable), minute=1)
    assert counts(state) == (0, 0, 5, 0, 0)  # the traversal, re-observed
    assert held(instance)[SQLI]["verification"] == "present"
    assert summary(state, "extract").complete is True  # the document is honest
    posted = attention(instance, state, minute=2)
    assert summary(posted, "post_inbox").emitted == 1
    (item,) = inbox(instance, findings.attention_line_name("semgrep"))
    assert (item["kind"], item["reason"]) == ("location_gap", reason)


@pytest.mark.parametrize(
    "catalog",
    [[], [{"id": "open-joined-path"}]],
    ids=["empty_catalog", "catalog_omits_the_rule"],
)
def test_an_unknown_rule_in_one_run_never_lets_another_run_of_its_tool_fix(
    tmp_path: Path, catalog: list[dict[str, Any]]
) -> None:
    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))
    # The clean full rescan (no SQLi) beside a Semgrep run whose one result is a
    # malformed scalar and whose rule catalog cannot say which rule it was.
    document = sarif("semgrep-gate-app-fixed.sarif")
    malformed = copy.deepcopy(document["runs"][0])
    malformed["tool"]["driver"]["rules"] = catalog
    malformed["results"] = [42]
    document["runs"].insert(0, malformed)
    state = scan(instance, tmp_path, document, minute=1)
    assert counts(state) == (0, 0, 5, 0, 0)  # the traversal, re-observed
    assert held(instance)[SQLI]["verification"] == "present"
    posted = attention(instance, state, minute=2)
    assert summary(posted, "post_inbox").emitted == 1
    (item,) = inbox(instance, findings.attention_line_name("semgrep"))
    assert (item["kind"], item["reason"]) == ("location_gap", "malformed_result")


def test_a_count_mismatch_never_retires_or_fixes(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    scan(instance, tmp_path, sarif("semgrep-gate-app-vulnerable.sarif"))

    def short(document: dict[str, Any]) -> dict[str, Any]:
        return {**document, "count": document["count"] + 1}

    state = scan(
        instance,
        tmp_path,
        sarif("semgrep-gate-app-fixed.sarif"),
        minute=1,
        scanner=Scanner(doctor=short),
    )
    assert summary(state, "extract").complete is False
    assert counts(state)[1:4:2] == (0, 0)  # nothing revised to fixed, nothing retired
    assert held(instance)[SQLI]["verification"] == "present"
    assert "incomplete_source" in kinds(state)


def test_a_duplicate_record_writes_nothing_for_its_key(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)

    def doubled(document: dict[str, Any]) -> dict[str, Any]:
        records = document["findings"]
        twin = {**records[0], "severity": "low"}
        return {**document, "findings": [*records, twin], "count": len(records) + 1}

    state = scan(
        instance,
        tmp_path,
        sarif("semgrep-gate-app-vulnerable.sarif"),
        scanner=Scanner(doctor=doubled),
    )
    assert summary(state, "extract").duplicates == 2
    assert counts(state) == (5, 0, 0, 0, 1)  # only the other finding
    assert "duplicate_key" in kinds(state)


def test_an_unreadable_sarif_file_writes_nothing(tmp_path: Path) -> None:
    instance = findings_world(tmp_path)
    head = instance.accepted_coordinate()
    write_file(tmp_path, SEMGREP, b"{not json")
    state = run(instance, findings.import_line_name("semgrep"))
    assert state.status != "succeeded"
    assert "provider_declined" in json.dumps(state.terminal.model_dump(mode="json"))
    assert instance.accepted_coordinate() == head


# -- work counts at two sizes ------------------------------------------------------------

#: Findings per measured scan: the marginal cost of a finding must not grow with N.
_SIZES = (10, 40)
_SLOPE_RATIO = 1.15
_SLOPE_SLACK = 2.0
_COUNTERS = (
    "sql_statements",
    "claim_parses",
    "canonical_digests",
    "projection_binds",
    "cas_body_reads",
    "git_blob_reads",
)


def synthetic(size: int, *, gaps: int = 0, revision: str = "a" * 40) -> dict[str, Any]:
    """One full Semgrep run: ``size`` located findings and ``gaps`` unlocated ones."""

    results = [
        _result("sqli-fstring-execute", f"app/m{index}.py", snippet=f"execute(q{index})")
        for index in range(size)
    ] + [_result("open-joined-path", f"app/g{index}.py") for index in range(gaps)]
    document = sarif("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["results"] = results
    document["runs"][0]["versionControlProvenance"][0]["revisionId"] = revision
    return document


def _measured(tmp_path: Path, size: int) -> dict[str, dict[str, float]]:
    from tests.test_scale._counters import counting, trace_sqlite

    out: dict[str, dict[str, float]] = {}
    with trace_sqlite(tmp_path):
        instance = findings_world(tmp_path)
        document = synthetic(size, gaps=size)
        for phase, minute in (("import", 0), ("rerun", 1)):
            write_file(tmp_path, SEMGREP, encode(document))
            scanner = Scanner()
            with counting(tmp_path) as window:
                state = run(
                    instance, findings.import_line_name("semgrep"), scanner=scanner, minute=minute
                )
            assert state.status == "succeeded", state.terminal
            assert not window.unexplained, window.unexplained
            assert scanner.calls == ["read", "derive"]  # two provider calls at any size
            claims = summary(state, "claims")
            out[phase] = {
                "written": claims.written,
                "re_observed": claims.re_observed,
                "created": claims.subjects_created,
                "held_rows": summary(state, "read").rows,
                **{c: window.counts[c] for c in _COUNTERS},
            }
            if phase == "import":
                with counting(tmp_path) as window:
                    posted = attention(instance, state, minute=minute)
                assert not window.unexplained, window.unexplained
                out["attention"] = {
                    "emitted": summary(posted, "post_inbox").emitted,
                    **{c: window.counts[c] for c in _COUNTERS},
                }
    return out


def test_work_is_linear_and_flat_per_finding(tmp_path: Path) -> None:
    measured = {}
    for size in _SIZES:
        root = tmp_path / f"n{size}"
        root.mkdir()
        found = _measured(root, size)
        # Exact item counts: five Claims and one Subject per finding, read back
        # as N held rows and re-observed, one inbox item per gap.
        assert (found["import"]["written"], found["import"]["created"]) == (5 * size, size)
        assert found["import"]["held_rows"] == 0
        assert (found["rerun"]["written"], found["rerun"]["re_observed"]) == (0, 5 * size)
        assert found["rerun"]["held_rows"] == size
        assert found["attention"]["emitted"] == size
        measured[size] = found
    small, large = (measured[size] for size in _SIZES)
    for phase in ("import", "rerun", "attention"):
        for counter in _COUNTERS:
            # Constant per-item cost: the marginal cost of a finding between the
            # sizes is no more than the per-finding average at the small size
            # (which carries the fixed cost too).
            marginal = (large[phase][counter] - small[phase][counter]) / (_SIZES[1] - _SIZES[0])
            average = small[phase][counter] / _SIZES[0]
            assert marginal <= average * _SLOPE_RATIO + _SLOPE_SLACK, (phase, counter, measured)
    report = __import__("os").environ.get("FINDINGS_WORK_COUNTS")
    if report:
        Path(report).write_text(json.dumps(measured, indent=1) + "\n")
