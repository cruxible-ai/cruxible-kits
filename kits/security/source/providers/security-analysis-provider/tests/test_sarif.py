"""First-party code findings from SARIF: keyed so every finder meets, diffed against held state.

Fixtures (``data/sarif``): ``semgrep-gate-app-*.sarif`` are real Semgrep OSS 1.182.0
output (``semgrep scan --config semgrep-rules.yaml --sarif``) over the gate-app
fixture before and after its SQL injection fix, with the scanner's two annotations
added (``versionControlProvenance`` and ``properties["cruxible.coverage"]``;
Semgrep emits neither). ``codeql-gate-app-*.sarif`` follow CodeQL's
``sarif-latest`` shape (``external/cwe/cwe-NNN`` tags, ``security-severity``,
``partialFingerprints``, no snippets, no logical locations); they are hand-built
in that shape, not recorded. ``auditor-gate-app.sarif`` is an agent finder's
minimal SARIF.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_analysis_provider.common import parse_rows
from security_analysis_provider.harden import harden
from security_analysis_provider.sarif import (
    findings,
    locator,
    repo_ref,
    snippet_locator,
    weakness,
)

DATA = Path(__file__).parent / "data" / "sarif"
REPO = "github.com/cruxible-ai/gate-app"
SINK = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
SQLI = ("CWE-89", "app/db.py#" + str(snippet_locator(SINK)))
TRAVERSAL = ("CWE-22", "app/files.py#" + str(snippet_locator('with open(path, "rb") as handle:')))
CODEQL_SQLI = ("CWE-89", "app/db.py#line-hash:3d1c6f0a9e2b7745:1")


def _text(name: str) -> str:
    return (DATA / name).read_text()


def _held(subject_id: str, key: tuple[str, str], **fields: Any) -> dict[str, Any]:
    path = f"subjects/security.finding/{subject_id}.json"
    values = {"weakness": key[0], "locus": key[1], "repo_ref": REPO, **fields}
    claims = []
    if "verification" in fields:
        claims.append({"claim_path": f"claims/ab/CLM-{subject_id}-verification.json",
                       "subject_identity": f"security.finding/{subject_id}",
                       "predicate": "security.finding.verification"})
    return {
        "bindings": [{"binding": "finding", "subject_kind": "security.finding",
                      "subject_id": subject_id, "subject_path": path,
                      "subject_identity": f"security.finding/{subject_id}"}],
        "fields": [{"name": k, "state": "absent" if v is None else "present", "value": v}
                   for k, v in values.items()],
        "read_claims": claims,
    }


def _run(name: str, *held: dict[str, Any], repo: str = REPO) -> dict[str, Any]:
    return findings(_text(name), parse_rows(list(held)), repo)


def _claims(result: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    """(subject key or path, predicate, value) per Claim item."""

    found = []
    for item in result["items"]:
        statement = item.get("statement")
        if statement is None:
            continue
        subject = statement["subject"]
        who = (tuple(sorted(subject["key"].items())) if "key" in subject
               else subject["artifact_path"])
        obj = statement["object"]
        found.append((who, statement["predicate"], obj.get("value", obj.get("subject"))))
    return found


# --- reading -------------------------------------------------------------------


def test_keys_name_the_repository_the_smallest_cwe_and_a_stable_locus() -> None:
    assert repo_ref("https://github.com/Cruxible-AI/gate-app.git") == REPO
    assert repo_ref("git@github.com:cruxible-ai/gate-app.git") == REPO
    assert repo_ref("github.com/cruxible-ai") is None
    rule = {"properties": {"tags": ["CWE-73: External Control", "CWE-22: Path Traversal"]}}
    assert weakness("semgrep", "open-joined-path", rule) == "CWE-22"
    assert weakness("codeql", "py/x", {"properties": {"tags": ["external/cwe/cwe-089"]}}) == (
        "CWE-89")
    assert weakness("auditor", "CWE-79", {}) == "CWE-79"
    taxonomy = {"relationships": [{"target": {"id": "352", "toolComponent": {"name": "CWE"}}}]}
    assert weakness("x", "r", taxonomy) == "CWE-352"
    assert weakness("semgrep", "style.nit", {}) == "RULE:semgrep/style.nit"
    # Tiers: the symbol, then the snippet (whitespace does not matter), then the line hash.
    result: dict[str, Any] = {"locations": [{"physicalLocation": {"region": {
        "snippet": {"text": "   " + SINK + "\n"}}}}],
        "partialFingerprints": {"primaryLocationLineHash": "abc:1"}}
    assert locator(result, {}) == ("snippet", str(snippet_locator(SINK)))
    result["properties"] = {"cruxible.symbol": "UserRepo.find_by_name"}
    assert locator(result, {}) == ("symbol", "UserRepo.find_by_name")
    indexed = {"locations": [{"logicalLocations": [{"index": 0}]}]}
    assert locator(indexed, {"logicalLocations": [{"fullyQualifiedName": "a.b"}]}) == (
        "symbol", "a.b")
    assert locator({"partialFingerprints": {"primaryLocationLineHash": "abc:1"}}, {}) == (
        "line_hash", "line-hash:abc:1")
    assert locator({}, {}) is None


# --- the import ----------------------------------------------------------------


def test_a_first_scan_proposes_each_finding_by_key_with_its_report() -> None:
    result = _run("semgrep-gate-app-vulnerable.sarif")
    assert (result["mine"], result["new"], result["findings"], result["changed"]) == (1, 2, 2, 8)
    subjects = [i["key"] for i in result["items"] if i.get("subject_kind") == "security.finding"]
    assert result["items"][0]["subject_kind"] == "security.repo"  # created by key, or named
    assert subjects == [
        {"repo_ref": REPO, "weakness": SQLI[0], "locus": SQLI[1]},
        {"repo_ref": REPO, "weakness": TRAVERSAL[0], "locus": TRAVERSAL[1]},
    ] or subjects == [
        {"repo_ref": REPO, "weakness": TRAVERSAL[0], "locus": TRAVERSAL[1]},
        {"repo_ref": REPO, "weakness": SQLI[0], "locus": SQLI[1]},
    ]
    claims = _claims(result)
    sqli = tuple(sorted({"repo_ref": REPO, "weakness": SQLI[0], "locus": SQLI[1]}.items()))
    mine = {(p, v if not isinstance(v, dict) else json.dumps(v, sort_keys=True))
            for who, p, v in claims if who == sqli}
    assert mine == {
        ("security.finding.rule", "semgrep:sqli-fstring-execute"),
        ("security.finding.reported_by", "semgrep"),
        ("security.finding.severity", "high"),  # security-severity 8.8
        ("security.finding.repo", json.dumps(
            {"key": {"forge_host": "github.com", "full_name": "cruxible-ai/gate-app"},
             "subject_kind": "security.repo"}, sort_keys=True)),
    }
    traversal = [v for who, p, v in claims
                 if p == "security.finding.severity" and who != sqli]
    assert traversal == ["medium"]  # no security-severity: the warning level
    assert result["inbox"] == [] and result["revisions"] == [
        "a382bce444533bfc4622e7f822b3d6c11cbd7510"]


def test_a_rescan_of_held_findings_proposes_nothing() -> None:
    held = [_held("one", SQLI, rules=["semgrep:sqli-fstring-execute"], reported_by=["semgrep"],
                  severity="high"),
            _held("two", TRAVERSAL, rules=["semgrep:open-joined-path"], reported_by=["semgrep"],
                  severity="medium")]
    result = _run("semgrep-gate-app-vulnerable.sarif", *held)
    assert (result["changed"], result["items"], result["new"]) == (0, [], 0)


def test_another_finder_of_the_same_key_adds_only_its_report() -> None:
    held = _held("one", SQLI, rules=["semgrep:sqli-fstring-execute"], reported_by=["semgrep"],
                 severity="high")
    result = _run("auditor-gate-app.sarif", held)
    assert result["new"] == 0 and result["added"] == 2
    assert sorted((p, v) for _who, p, v in _claims(result)) == [
        ("security.finding.reported_by", "auditor"), ("security.finding.rule", "auditor:CWE-89")]
    # Its unlocated result is a gap, never a finding.
    (gap,) = result["inbox"]
    assert (gap["kind"], gap["tool"], gap["rule"], gap["path"]) == (
        "location_gap", "auditor", "auditor:CWE-79", "app/templates/user.html")
    # A partial scan says nothing about what it did not report.
    assert result["fixed"] == 0


def test_a_line_hash_tool_is_its_own_key() -> None:
    held = _held("one", SQLI, rules=["semgrep:sqli-fstring-execute"], reported_by=["semgrep"])
    result = _run("codeql-gate-app-vulnerable.sarif", held)
    (subject,) = [i["key"] for i in result["items"] if i.get("subject_kind") == "security.finding"]
    assert (subject["weakness"], subject["locus"]) == CODEQL_SQLI
    assert ("security.finding.severity", "high") in [(p, v) for _w, p, v in _claims(result)]


def test_another_repository_or_none_halts() -> None:
    result = _run("semgrep-gate-app-vulnerable.sarif", repo="github.com/cruxible-ai/cruxible")
    assert (result["mine"], result["items"], result["changed"]) == (0, [], 0)
    unannotated = json.loads(_text("semgrep-gate-app-vulnerable.sarif"))
    del unannotated["runs"][0]["versionControlProvenance"]
    assert findings(json.dumps(unannotated), [], REPO)["mine"] == 0


def test_dependency_advisories_route_to_assessment() -> None:
    log = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": "GHSA-9wx4-h78v-vm56"}]}},
        "versionControlProvenance": [{"repositoryUri": f"https://{REPO}", "revisionId": "x"}],
        "results": [{"ruleId": "GHSA-9wx4-h78v-vm56", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "uv.lock"}, "region": {"snippet": {"text": "x"}}}}]}]}]}
    result = findings(json.dumps(log), [], REPO)
    assert (result["routed_to_assessment"], result["findings"], result["items"]) == (1, 0, [])


# --- verification ------------------------------------------------------------------


def test_a_full_rescan_without_the_key_verifies_the_fix() -> None:
    held = [_held("one", SQLI, rules=["semgrep:sqli-fstring-execute"], reported_by=["semgrep"],
                  severity="high", verdict="confirmed"),
            _held("two", TRAVERSAL, rules=["semgrep:open-joined-path"], reported_by=["semgrep"],
                  severity="medium", verdict="false_positive"),
            _held("three", CODEQL_SQLI, rules=["codeql:py/sql-injection"],
                  reported_by=["codeql"], severity="high")]
    result = _run("semgrep-gate-app-fixed.sarif", *held)
    assert result["fixed"] == 1 and result["regressed"] == 0
    assert _claims(result) == [("subjects/security.finding/one.json",
                                "security.finding.verification", "fixed")]
    # CodeQL's finding is not covered by a Semgrep scan; its own full rescan verifies it.
    codeql = _run("codeql-gate-app-fixed.sarif", *held)
    assert _claims(codeql) == [("subjects/security.finding/three.json",
                                "security.finding.verification", "fixed")]
    # A partial scan never verifies.
    assert _run("auditor-gate-app.sarif", *held)["fixed"] == 0


def test_a_fixed_finding_reported_again_regresses() -> None:
    held = _held("one", SQLI, rules=["semgrep:sqli-fstring-execute"], reported_by=["semgrep"],
                 severity="high", verification="fixed")
    result = _run("semgrep-gate-app-vulnerable.sarif", held)
    assert result["regressed"] == 1
    (item,) = [i for i in result["items"] if "statement" in i
               and i["statement"]["predicate"] == "security.finding.verification"]
    assert item["statement"]["object"]["value"] == "present"
    assert item["revises"] == "CLM-one-verification"
    (regression,) = [i for i in result["inbox"] if i["kind"] == "regression"]
    assert regression["finding"] == "security.finding/one"
    # Already fixed and still absent: nothing to say about it.
    again = _run("semgrep-gate-app-fixed.sarif", held)
    assert (again["fixed"], again["regressed"]) == (0, 0)


# --- HQ6 -------------------------------------------------------------------------


def test_hq6_finds_an_open_confirmed_finding_in_what_a_gated_target_serves() -> None:
    def row(verdict: str | None, verification: str | None) -> dict[str, Any]:
        def bind(name: str, kind: str, subject_id: str) -> dict[str, Any]:
            return {"binding": name, "subject_kind": kind, "subject_id": subject_id,
                    "subject_path": f"subjects/{kind}/{subject_id}.json",
                    "subject_identity": f"{kind}/{subject_id}"}

        fields = {"target_registry": "pypi", "target_name": "gate-app", "verdict": verdict,
                  "verification": verification, "weakness": SQLI[0], "locus": SQLI[1],
                  "severity": "high", "artifact_name": "gate_app-1.0.0-py3-none-any.whl"}
        return {"bindings": [bind("target", "security.target", "pypi--gate-app"),
                             bind("artifact", "security.artifact", "wheel"),
                             bind("release", "security.release", "gate-app--1.0.0"),
                             bind("finding", "security.finding", "sqli")],
                "fields": [{"name": k, "state": "absent" if v is None else "present", "value": v}
                           for k, v in fields.items()]}

    empty: dict[str, Any] = {name: [] for name in ("hq1", "hq2", "hq3", "hq4", "hq5")}
    found = harden({**empty, "hq6": [row("confirmed", None)], "params": {}})
    (item,) = [i for i in found["items"] if i["question"] == "HQ6"]
    assert item["finding"] == "security.finding/sqli" and item["releases"] == [
        "security.release/gate-app--1.0.0"]
    for verdict, verification in (("confirmed", "fixed"), (None, None)):
        quiet = harden({**empty, "hq6": [row(verdict, verification)], "params": {}})
        assert not [i for i in quiet["items"] if i.get("question") == "HQ6"]
