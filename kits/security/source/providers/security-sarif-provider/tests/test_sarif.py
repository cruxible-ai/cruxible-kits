"""Offline tests for ``sarif.findings`` (pure derive) on the kit's SARIF test data.

``data/`` holds the gate app's scans: Semgrep's are recorded, CodeQL's are
hand-built in CodeQL's shape, and the auditor's is an agent's SARIF. No test
opens a socket; the conformance tests block the network outright.
"""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from security_sarif_provider import sarif  # noqa: E402

DATA = HERE / "data"
REPO = "github.com/cruxible-ai/gate-app"
OBSERVED = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def log(name: str) -> dict[str, Any]:
    return json.loads((DATA / name).read_bytes())


def encode(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode()


def derive(*documents: Mapping[str, Any], held: list[dict[str, Any]] | None = None) -> dict:
    return sarif.findings([encode(d) for d in documents], held or [], REPO)


def held_row(record: Mapping[str, Any], *, verification: str = "present", sid: str = "f1"):
    return {
        "subject_kind": "security.finding",
        "subject_id": sid,
        "weakness": record["weakness"],
        "locus": record["locus"],
        "rules": [record["rule"]],
        "verification": verification,
    }


def context(payload: Mapping[str, Any]) -> Any:
    from cruxible_provider_runtime.egress import EgressRecorder
    from cruxible_provider_runtime.protocol import Budgets
    from cruxible_provider_runtime.provider_api import ProviderRunContext

    return ProviderRunContext(
        run_id="run-test",
        input=dict(payload),
        operation=sarif.OPERATION,
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


def wire(document: Mapping[str, Any]) -> dict[str, Any]:
    from cruxible_provider_runtime.acquisition import external_capture_result

    return external_capture_result(
        encode(document),
        source_identity="sarif.semgrep",
        coordinate_type="http-response-v1",
        coordinate={"revision": "working"},
        observed_at=OBSERVED,
        selector_type="whole-response-v1",
    )


def call(*documents: Mapping[str, Any], held: list[dict[str, Any]] | None = None) -> Any:
    return sarif.sarif_findings(
        context(
            {
                "logs": [wire(d) for d in documents],
                "held": held or [],
                "repo": REPO,
                "logical_source": "sarif.semgrep",
            }
        )
    )


# -- the key -------------------------------------------------------------------------


def test_semgrep_findings_are_keyed_by_cwe_and_snippet() -> None:
    document = derive(log("semgrep-gate-app-vulnerable.sarif"))
    found = {(r["weakness"], r["locus"].split("#")[0]): r for r in document["findings"]}
    assert set(found) == {("CWE-89", "app/db.py"), ("CWE-22", "app/files.py")}
    sqli = found[("CWE-89", "app/db.py")]
    assert sqli["locus"].startswith("app/db.py#snippet:") and sqli["tier"] == "snippet"
    assert (sqli["rule"], sqli["tool"], sqli["severity"]) == (
        "semgrep:sqli-fstring-execute",
        "semgrep",
        "high",  # security-severity 8.8
    )
    assert sqli["reported_at"] == "app/db.py:12" and sqli["verification"] == "present"
    # The smallest CWE a rule names (CWE-22 and CWE-73 on the traversal rule).
    assert found[("CWE-22", "app/files.py")]["severity"] == "medium"  # level warning
    assert (document["full"], document["count"]) == (True, 2)
    assert document["queried"] == ["semgrep:open-joined-path", "semgrep:sqli-fstring-execute"]


def test_codeql_names_its_cwe_by_tag_and_is_located_by_its_line_hash() -> None:
    document = derive(log("codeql-gate-app-vulnerable.sarif"))
    (sqli,) = document["findings"]
    assert sqli["weakness"] == "CWE-89"  # external/cwe/cwe-089
    assert sqli["locus"] == "app/db.py#line-hash:3d1c6f0a9e2b7745:1"
    assert sqli["tier"] == "line_hash" and sqli["tool"] == "codeql"


def test_locator_tiers_prefer_symbol_then_snippet_then_line_hash() -> None:
    result: dict[str, Any] = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"snippet": {"text": "  run(  x )"}},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": "abc:1"},
    }
    assert sarif.locator(result, {})[0] == "snippet"
    # Indentation and spacing never move a snippet locator.
    moved = copy.deepcopy(result)
    moved["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] = "run( x )"
    assert sarif.locator(moved, {}) == sarif.locator(result, {})
    result["locations"][0]["logicalLocations"] = [{"fullyQualifiedName": "pkg.mod.fn"}]
    assert sarif.locator(result, {}) == ("symbol", "pkg.mod.fn")
    del result["locations"][0]["logicalLocations"]
    del result["locations"][0]["physicalLocation"]["region"]["snippet"]
    assert sarif.locator(result, {}) == ("line_hash", "line-hash:abc:1")


@pytest.mark.parametrize(
    ("score", "level", "expected"),
    [
        ("9.1", None, "critical"),
        ("7.0", None, "high"),
        ("4.0", None, "medium"),
        ("0.1", None, "low"),
        (None, "error", "high"),
        (None, "warning", "medium"),
        (None, "note", "low"),
        (None, None, None),
    ],
)
def test_severity_map(score: str | None, level: str | None, expected: str | None) -> None:
    rule: dict[str, Any] = {"properties": {"security-severity": score}} if score else {}
    result: dict[str, Any] = {"level": level} if level else {}
    assert sarif.severity(result, rule) == expected


def test_a_rule_naming_no_cwe_is_keyed_by_the_rule() -> None:
    assert sarif.weakness("semgrep", "custom-rule", {}) == "RULE:semgrep/custom-rule"
    assert sarif.weakness("x", "r", {"properties": {"tags": ["cwe-079", "CWE-20"]}}) == "CWE-20"


# -- routing, repositories, gaps -------------------------------------------------------


def _result(rule: str, path: str, **extra: Any) -> dict[str, Any]:
    region = {
        "startLine": 3,
        **({"snippet": {"text": extra.pop("snippet")}} if "snippet" in extra else {}),
    }
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": path}, "region": region}
    }
    if "symbol" in extra:
        location["logicalLocations"] = [{"fullyQualifiedName": extra.pop("symbol")}]
    return {"ruleId": rule, "locations": [location], "message": {"text": "x"}, **extra}


def test_a_dependency_advisory_in_a_manifest_is_routed_out() -> None:
    document = log("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["results"].append(
        _result("CVE-2021-44228", "pom.xml", snippet="<version>2.14.1</version>")
    )
    out = derive(document)
    assert out["routed"] == [{"rule": "semgrep:CVE-2021-44228", "path": "pom.xml"}]
    assert out["count"] == 2  # no finding for it


def test_another_repositorys_runs_give_no_records() -> None:
    document = log("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["versionControlProvenance"][0]["repositoryUri"] = (
        "git@github.com:acme/other.git"
    )
    vulnerable = derive(log("semgrep-gate-app-vulnerable.sarif"))
    held = [held_row(vulnerable["findings"][0])]
    out = derive(document, held=held)
    assert (out["findings"], out["covered"], out["full"], out["queried"]) == ([], [], False, [])
    assert out["other_repo_runs"] == 1


def test_unlocated_and_unkeyable_results_are_gaps_not_findings() -> None:
    out = derive(log("auditor-gate-app.sarif"))
    (gap,) = out["attention"]
    assert (gap["kind"], gap["rule"], gap["reason"]) == (
        "location_gap",
        "auditor:CWE-79",
        "no_stable_location",
    )
    document = log("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["results"] += [
        _result("open-joined-path", "app/long.py", symbol="pkg." + "x" * 300),
        _result("open-joined-path", "app/nl.py", symbol="a\nb"),
        _result("open-joined-path", "/etc/abs.py", snippet="x"),
    ]
    reasons = sorted((g["path"], g["reason"]) for g in derive(document)["attention"])
    assert reasons == [
        ("(none)", "no_repository_path"),
        ("app/long.py", "unkeyable_location"),
        ("app/nl.py", "unkeyable_location"),
    ]


# -- coverage, fixed and regressions -----------------------------------------------------


def test_a_full_rescan_marks_a_covered_finding_fixed() -> None:
    vulnerable = derive(log("semgrep-gate-app-vulnerable.sarif"))
    held = [held_row(r, sid=f"f{i}") for i, r in enumerate(vulnerable["findings"])]
    out = derive(log("semgrep-gate-app-fixed.sarif"), held=held)
    assert sorted(out["covered"]) == ["f0", "f1"]
    by = {r["weakness"]: r for r in out["findings"]}
    assert by["CWE-89"] == {
        "repo": REPO,
        "weakness": "CWE-89",
        "locus": by["CWE-89"]["locus"],
        "verification": "fixed",
    }
    assert by["CWE-22"]["verification"] == "present"


@pytest.mark.parametrize("how", ["declared_partial", "invocation_failed", "no_invocations"])
def test_a_partial_scan_covers_nothing(how: str) -> None:
    vulnerable = derive(log("semgrep-gate-app-vulnerable.sarif"))
    held = [held_row(r, sid=f"f{i}") for i, r in enumerate(vulnerable["findings"])]
    document = log("semgrep-gate-app-fixed.sarif")
    run_ = document["runs"][0]
    if how == "declared_partial":
        run_["properties"]["cruxible.coverage"] = "partial"
    elif how == "invocation_failed":
        run_["invocations"][0]["executionSuccessful"] = False
    else:
        run_["invocations"] = []
    out = derive(document, held=held)
    assert (out["full"], out["covered"]) == (False, [])
    assert [r["verification"] for r in out["findings"]] == ["present"]


def test_a_rule_set_that_did_not_find_it_never_covers_it() -> None:
    semgrep = derive(log("semgrep-gate-app-vulnerable.sarif"))
    held = [held_row(r, sid=f"f{i}") for i, r in enumerate(semgrep["findings"])]
    out = derive(log("codeql-gate-app-fixed.sarif"), held=held)
    assert out["covered"] == [] and all(r["verification"] == "present" for r in out["findings"])


def test_a_fixed_finding_reported_again_is_a_regression() -> None:
    vulnerable = derive(log("semgrep-gate-app-vulnerable.sarif"))
    sqli = next(r for r in vulnerable["findings"] if r["weakness"] == "CWE-89")
    out = derive(
        log("semgrep-gate-app-vulnerable.sarif"),
        held=[held_row(sqli, verification="fixed", sid="sqli")],
    )
    (regression,) = out["attention"]
    assert regression["kind"] == "regression" and regression["finding"] == "sqli"
    assert regression["ref"] == "regression:sqli:a382bce444533bfc4622e7f822b3d6c11cbd7510"
    assert next(r for r in out["findings"] if r["weakness"] == "CWE-89")["verification"] == (
        "present"
    )


# -- the operation: refusals, wire, purity -------------------------------------------------


@pytest.mark.parametrize(
    ("content", "held"),
    [
        (b"{not json", []),
        (json.dumps({"version": "1.0", "runs": []}).encode(), []),
        (json.dumps({"version": "2.1.0"}).encode(), []),
        (encode(log("semgrep-gate-app-vulnerable.sarif")), [{"subject_id": "x"}]),
    ],
    ids=["not_json", "not_sarif_2_1", "no_runs", "held_row_without_key"],
)
def test_unreadable_input_is_declined(content: bytes, held: list[dict[str, Any]]) -> None:
    from cruxible_provider_runtime.acquisition import external_capture_result

    log_wire = external_capture_result(
        content,
        source_identity="sarif.semgrep",
        coordinate_type="http-response-v1",
        coordinate={},
        observed_at=OBSERVED,
        selector_type="whole-response-v1",
    )
    result = sarif.sarif_findings(
        context({"logs": [log_wire], "held": held, "repo": REPO, "logical_source": "sarif.x"})
    )
    assert result.status == "refused" and result.refusal.code == sarif.PROVIDER_DECLINED


def test_the_document_is_the_capture_verbatim_stamped_with_its_input_time() -> None:
    import base64

    result = call(log("semgrep-gate-app-vulnerable.sarif"))
    assert result.status == "ok", result
    document = result.output["document"]
    content = base64.b64decode(document["content_base64"])
    assert content == sarif.document_bytes(derive(log("semgrep-gate-app-vulnerable.sarif")))
    assert document["bytes_digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert document["observed_at"] == "2026-11-05T12:00:00Z"  # the input's, never the clock
    assert document["source_identity"] == "sarif.semgrep"


def test_the_derive_is_pure_byte_identical_and_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    first = call(log("semgrep-gate-app-vulnerable.sarif"), log("codeql-gate-app-vulnerable.sarif"))

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("sarif.findings opened a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    second = call(log("semgrep-gate-app-vulnerable.sarif"), log("codeql-gate-app-vulnerable.sarif"))
    assert first.status == second.status == "ok"
    assert first.output == second.output


# -- work counts at two sizes ----------------------------------------------------------------


def synthetic(size: int) -> dict[str, Any]:
    document = log("semgrep-gate-app-vulnerable.sarif")
    document["runs"][0]["results"] = [
        _result("sqli-fstring-execute", f"app/m{i}.py", snippet=f"execute(q{i})")
        for i in range(size)
    ]
    return document


def _counted(monkeypatch: pytest.MonkeyPatch, *names: str) -> dict[str, int]:
    calls: dict[str, int] = {}
    for name in names:
        original = getattr(sarif, name)

        def counted(*args: Any, _name: str = name, _original: Any = original, **kw: Any) -> Any:
            calls[_name] = calls.get(_name, 0) + 1
            return _original(*args, **kw)

        monkeypatch.setattr(sarif, name, counted)
    return calls


@pytest.mark.parametrize("held_fraction", [0, 1])
def test_derive_work_is_linear_in_results_and_held_rows(
    monkeypatch: pytest.MonkeyPatch, held_fraction: int
) -> None:
    calls = _counted(monkeypatch, "locator", "weakness", "severity", "is_covered", "coverage_index")
    measured = {}
    for size in (10, 40):
        document = synthetic(size)
        held = (
            [held_row(r, sid=f"f{i}") for i, r in enumerate(derive(document)["findings"])]
            if held_fraction
            else []
        )
        calls.clear()
        out = derive(document, held=held)
        assert out["count"] == size
        measured[size] = dict(calls)
        # Constant per item: one locator, weakness and severity read per result,
        # one coverage index per scan and one index check per held finding.
        assert calls["locator"] == calls["weakness"] == calls["severity"] == size
        assert calls["coverage_index"] == 1
        assert calls.get("is_covered", 0) == len(held)
    assert measured[40]["locator"] == 4 * measured[10]["locator"]


def multi_run(runs: int) -> dict[str, Any]:
    """One log of ``runs`` full runs, each its own tool's rule and one result."""

    document = log("semgrep-gate-app-vulnerable.sarif")
    template = document["runs"][0]
    out = []
    for index in range(runs):
        run_ = copy.deepcopy(template)
        run_["tool"]["driver"]["name"] = f"tool{index}"
        run_["tool"]["driver"]["rules"] = [{"id": f"rule{index}"}]
        run_["results"] = [_result(f"rule{index}", f"app/r{index}.py", snippet=f"call(x{index})")]
        out.append(run_)
    document["runs"] = out
    return document


def test_coverage_work_is_linear_over_many_runs_and_held_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """10 runs / 10 held vs 40 / 40: one index, one O(rules) check per held finding."""

    rule_checks = 0
    original = sarif.is_covered

    def counted(finding: Any, index: Any) -> bool:
        nonlocal rule_checks
        rule_checks += len(finding.rules)  # the frozenset intersections it does
        return original(finding, index)

    monkeypatch.setattr(sarif, "is_covered", counted)
    measured = {}
    for size in (10, 40):
        document = multi_run(size)
        held = [held_row(r, sid=f"f{i}") for i, r in enumerate(derive(document)["findings"])]
        rule_checks = 0
        # The rescan reports nothing: every held finding is covered and fixed.
        for run_ in document["runs"]:
            run_["results"] = []
        out = derive(document, held=held)
        assert len(out["covered"]) == size
        assert [r["verification"] for r in out["findings"]] == ["fixed"] * size
        measured[size] = rule_checks
    assert measured == {10: 10, 40: 40}  # linear: never held x runs


# -- taint: a result the scan cannot place never lets its rule fix anything -----------------


def _sqli_held() -> list[dict[str, Any]]:
    vulnerable = derive(log("semgrep-gate-app-vulnerable.sarif"))
    return [held_row(r, sid=f"f-{r['weakness']}") for r in vulnerable["findings"]]


def _sqli(document: dict[str, Any]) -> dict[str, Any]:
    return next(r for r in document["runs"][0]["results"] if r["ruleId"] == "sqli-fstring-execute")


def _unlocated(document: dict[str, Any]) -> None:
    del _sqli(document)["locations"][0]["physicalLocation"]["region"]["snippet"]


def _scalar(document: dict[str, Any]) -> None:
    results = document["runs"][0]["results"]
    results[results.index(_sqli(document))] = 42


def _no_rule(document: dict[str, Any]) -> None:
    del _sqli(document)["ruleId"]


def _bad_locations(document: dict[str, Any]) -> None:
    _sqli(document)["locations"] = "app/db.py"


@pytest.mark.parametrize(
    ("edit", "reason", "tainted"),
    [
        (_unlocated, "no_stable_location", ["semgrep:sqli-fstring-execute"]),
        (_bad_locations, "malformed_location", ["semgrep:sqli-fstring-execute"]),
        (_scalar, "malformed_result", ["semgrep:open-joined-path", "semgrep:sqli-fstring-execute"]),
        (_no_rule, "no_rule", ["semgrep:open-joined-path", "semgrep:sqli-fstring-execute"]),
    ],
    ids=["lost_snippet", "malformed_locations", "malformed_scalar", "no_rule"],
)
def test_a_held_finding_whose_result_cannot_be_placed_is_never_fixed(
    edit: Any, reason: str, tainted: list[str]
) -> None:
    document = log("semgrep-gate-app-vulnerable.sarif")
    edit(document)
    out = derive(document, held=_sqli_held())
    assert "f-CWE-89" not in out["covered"]
    assert all(r["verification"] == "present" for r in out["findings"])
    assert out["tainted"] == tainted
    (gap,) = out["attention"]
    assert (gap["kind"], gap["reason"]) == ("location_gap", reason)
    # The admissible sibling still writes, and is still covered unless its run is tainted.
    (traversal,) = [r for r in out["findings"] if r["weakness"] == "CWE-22"]
    assert traversal["verification"] == "present"
    assert ("f-CWE-22" in out["covered"]) == ("semgrep:open-joined-path" not in tainted)


def _malformed_run(catalog: list[dict[str, Any]]) -> dict[str, Any]:
    """A Semgrep run whose one result is a scalar, with the given rule catalog."""

    run_ = copy.deepcopy(log("semgrep-gate-app-vulnerable.sarif")["runs"][0])
    run_["tool"]["driver"]["rules"] = catalog
    run_["results"] = [42]
    return run_


@pytest.mark.parametrize(
    "catalog",
    [[], [{"id": "open-joined-path"}]],
    ids=["empty_catalog", "catalog_omits_the_rule"],
)
def test_an_unknown_rule_taints_its_tool_across_runs(catalog: list[dict[str, Any]]) -> None:
    """A clean full run of the same tool never re-authorizes the malformed run's negatives."""

    document = log("semgrep-gate-app-fixed.sarif")  # the clean full rescan: no SQLi
    document["runs"].insert(0, _malformed_run(catalog))
    out = derive(document, held=_sqli_held())
    assert out["tainted_tools"] == ["semgrep"]
    assert out["covered"] == []
    assert not [r for r in out["findings"] if r["verification"] == "fixed"]
    (gap,) = out["attention"]
    assert (gap["kind"], gap["reason"]) == ("location_gap", "malformed_result")
    # The admissible positive still writes.
    assert [(r["weakness"], r["verification"]) for r in out["findings"]] == [("CWE-22", "present")]


def test_an_unknown_rule_of_one_tool_leaves_another_tool_covered() -> None:
    document = log("codeql-gate-app-fixed.sarif")
    document["runs"].insert(0, _malformed_run([]))
    codeql = derive(log("codeql-gate-app-vulnerable.sarif"))["findings"][0]
    out = derive(document, held=[held_row(codeql, sid="codeql-sqli")])
    assert out["tainted_tools"] == ["semgrep"]
    assert out["covered"] == ["codeql-sqli"]
    assert [r["verification"] for r in out["findings"]] == ["fixed"]


def test_a_taint_in_one_run_holds_across_the_scan() -> None:
    """A clean full run of the same rule does not override another run's taint."""

    clean = log("semgrep-gate-app-fixed.sarif")["runs"][0]
    document = log("semgrep-gate-app-vulnerable.sarif")
    _unlocated(document)
    document["runs"].append(clean)
    out = derive(document, held=_sqli_held())
    assert "f-CWE-89" not in out["covered"]
    assert not [r for r in out["findings"] if r["verification"] == "fixed"]


# -- the package -------------------------------------------------------------------------------


def test_registration_names_the_operation_and_its_manifest_digest() -> None:
    root = HERE.parent / "src" / "security_sarif_provider"
    registration = json.loads((root / "registration.json").read_text())
    (entry,) = registration["operations"]
    assert (entry["name"], entry["effect"], entry["entrypoint"]) == (
        "sarif.findings",
        "pure",
        "security_sarif_provider.sarif:sarif_findings",
    )
    # A @derive function: pure, no endpoint, its declaration the registration's.
    from cruxible_provider_runtime import DeriveOperation

    assert isinstance(sarif.sarif_findings, DeriveOperation)
    assert sarif.sarif_findings.effect == "pure" and sarif.sarif_findings.declared_endpoints == ()
    assert sarif.sarif_findings.serves == tuple(entry["serves"])
    manifest = (root / "manifest.yaml").read_bytes()
    assert registration["manifest"]["digest"] == "sha256:" + hashlib.sha256(manifest).hexdigest()


def test_the_registration_carries_exactly_what_the_kit_renders() -> None:
    """The carried Contracts and kinds are the kit's own (``build_registrations.py``)."""

    pytest.importorskip("cruxible_core")
    pytest.importorskip("cruxible_provider_runtime")
    sys.path.insert(0, str(HERE.parents[1]))
    import build_registrations

    assert build_registrations.write("security-sarif-provider", check=True)
