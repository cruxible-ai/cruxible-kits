"""The system model: what a repository declares, what a registry serves, and the questions."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from security_analysis_provider.harden import harden
from security_analysis_provider.registry import certificate_commit, publisher
from security_analysis_provider.common import parse_rows
from security_analysis_provider.registry import _facts as _registry_facts
from security_analysis_provider.workflows import _facts as _workflow_facts
from security_analysis_provider.workflows import manifest_digests, parse_workflow

DATA = Path(__file__).parent / "data"
WORKFLOWS = DATA / "workflows"
OLD, NEW = "52509a27514eb9b081ede8a91fbd7539026bb322", "4e9b5db950bc66145fc72252be82b40a7826077c"
REPO_PATH = "subjects/security.repo/github.com--cruxible-ai-cruxible.json"
PYPI_TARGET = "subjects/security.target/pypi--cruxible.json"
CLIENT_TARGET = "subjects/security.target/pypi--cruxible-client.json"
GHCR_TARGET = "subjects/security.target/ghcr--cruxible-ai-cruxible-runtime.json"


def _claim(seed: str) -> str:
    return "CLM-" + hashlib.sha256(seed.encode()).hexdigest()[:32]


def _bind(binding: str, kind: str, path: str) -> dict[str, Any]:
    subject_id = path.rsplit("/", 1)[-1].removesuffix(".json")
    return {"binding": binding, "subject_kind": kind, "subject_id": subject_id,
            "subject_path": path, "subject_identity": f"{kind}/{subject_id}"}


def _row(bindings: list[dict[str, Any]], fields: dict[str, Any],
         claims: dict[tuple[str, str], str] | None = None,
         includes: dict[str, list[tuple[Any, str | None, str]]] | None = None) -> dict[str, Any]:
    return {
        "bindings": bindings,
        "fields": [{"name": k, "state": "absent" if v is None else "present", "value": v}
                   for k, v in fields.items()],
        "read_claims": [{"claim_path": f"claims/{c[4:6]}/{c}.json", "subject_identity": who,
                         "predicate": predicate} for (who, predicate), c in (claims or {}).items()],
        "includes": [{"name": name, "items": [
            {"claim_object": {"kind": "subject", "address": {"artifact_path": path}}
             if path else {"kind": "literal", "value": value},
             "visibility": {"claim_path": f"claims/{c[4:6]}/{c}.json"}}
            for value, path, c in items]} for name, items in (includes or {}).items()],
    }


def _snapshot(revision: str, names: list[str], ref: str = "main") -> dict[str, Any]:
    files = []
    for name in names:
        data = (WORKFLOWS / name).read_bytes()
        files.append({"path": f".github/workflows/{name}", "sha256": "x", "size": len(data),
                      "git_blob": "x", "content_base64": base64.b64encode(data).decode()})
    return {"input_bucket": "scope=ci.workflows", "source": "test", "forge_host": "github.com",
            "full_name": "cruxible-ai/cruxible", "ref": ref, "scope": "ci.workflows",
            "path": ".github/workflows/",
            "locator": f"github.com/cruxible-ai/cruxible@{ref}:.github/workflows/",
            "revision": revision, "files": files}


def _targets() -> list[dict[str, Any]]:
    repo = _bind("repo", "security.repo", REPO_PATH)
    return [_row([repo, _bind("target", "security.target", path)],
                 {"registry": registry, "name": name})
            for path, registry, name in ((PYPI_TARGET, "pypi", "cruxible"),
                                         (CLIENT_TARGET, "pypi", "cruxible-client"),
                                         (GHCR_TARGET, "ghcr", "cruxible-ai/cruxible-runtime"))]


def _claims(items: list[dict[str, Any]], tag: str = "claim") -> list[tuple[str, Any]]:
    """(predicate, object) of each Claim item, in order."""

    found = []
    for item in items:
        statement = item.get("statement")
        if statement is None:
            continue
        obj = statement["object"]
        value = obj.get("value", obj.get("subject", obj.get("address")))
        found.append((statement["predicate"], value))
    return found


def workflow_facts(snapshot: dict[str, Any], *rows: list[dict[str, Any]]) -> Any:
    return _workflow_facts(snapshot, *(parse_rows(r) for r in rows))


def registry_facts(release: dict[str, Any], *rows: list[dict[str, Any]]) -> Any:
    return _registry_facts(release, *(parse_rows(r) for r in rows))


# --- parsing ---------------------------------------------------------------------


def test_publish_yml_reads_triggers_effective_permissions_and_publish_credentials() -> None:
    workflow = parse_workflow(".github/workflows/publish.yml",
                              (WORKFLOWS / "publish.yml").read_text())
    assert workflow.error is None
    assert workflow.triggers == {"push:tags:v*"}  # YAML 1.1 reads `on:` as True
    client = workflow.jobs["publish-client"]
    assert client.permissions == {"contents:read", "id-token:write"}
    assert client.environment == "pypi-cruxible-client"
    assert "pkg:githubactions/pypa/gh-action-pypi-publish@release/v1" in client.uses
    assert client.registries == {"pypi"} and client.needs == {"verify-versions"}
    verify = workflow.jobs["verify-versions"]
    assert verify.permissions == {"contents:read"}  # the workflow default applies
    assert verify.registries == set() and verify.environment == "none"
    bundles = workflow.jobs["publish-kit-bundles"]
    assert bundles.registries == {"github_release"} and "GITHUB_TOKEN" in bundles.secrets


def test_runtime_image_workflow_is_dispatchable_with_packages_write() -> None:
    workflow = parse_workflow(".github/workflows/publish-runtime-image.yml",
                              (WORKFLOWS / "publish-runtime-image.yml").read_text())
    assert workflow.triggers == {"workflow_dispatch", "push:tags:v*"}
    build = workflow.jobs["build"]
    assert "packages:write" in build.permissions and build.environment == "none"
    assert "ghcr" in build.registries


def test_trigger_and_permission_forms() -> None:
    text = """
"on": [push, workflow_dispatch]
permissions: write-all
jobs:
  a: {runs-on: x, steps: [{uses: actions/checkout@v4}]}
  b: {runs-on: x, permissions: {}, environment: {name: prod}}
"""
    workflow = parse_workflow("w.yml", text)
    assert workflow.triggers == {"push", "workflow_dispatch"}
    assert workflow.jobs["a"].permissions == {"*:write"}
    assert workflow.jobs["a"].registries == {"ghcr", "github_release", "github_pages"}
    assert workflow.jobs["b"].permissions == {"*:none"} and workflow.jobs["b"].environment == "prod"
    plain = parse_workflow("w.yml", "on:\n  schedule:\n    - cron: '0 6 * * *'\njobs:\n  c: {}\n")
    assert plain.triggers == {"schedule:cron:0 6 * * *"}
    assert plain.jobs["c"].permissions == {"token:repository-default"}
    assert parse_workflow("w.yml", "on: [").error is not None


def test_manifest_digests_read_json_and_sha256sums() -> None:
    manifest = {"kits": {"a": {"asset": "a-1.tar.gz", "tarball_sha256": "AB" * 32}}}
    assert manifest_digests(json.dumps(manifest)) == {"a-1.tar.gz": "sha256:" + "ab" * 32}
    assert manifest_digests(f"{'cd' * 32}  b.whl\n") == {"b.whl": "sha256:" + "cd" * 32}


# --- workflow facts ----------------------------------------------------------------


def test_a_first_snapshot_creates_the_source_model_and_restates_its_coverage() -> None:
    output, _ = workflow_facts(_snapshot(OLD, ["publish.yml"]), [], [], _targets(), [])
    subjects = [(i["subject_kind"], i["key"]) for i in output["items"] if "subject_kind" in i]
    assert ("security.coverage", {"source": "github.com/cruxible-ai/cruxible@main:"
            ".github/workflows/", "scope": "ci.workflows"}) in subjects
    assert ("security.workflow", {"source": "github.com/cruxible-ai/cruxible@main",
            "path": ".github/workflows/publish.yml"}) in subjects
    assert ("security.job", {"workflow_ref": "github.com/cruxible-ai/cruxible@main:"
            ".github/workflows/publish.yml", "job_key": "publish-client"}) in subjects
    claims = _claims(output["items"])
    assert ("security.coverage.revision", OLD) in claims
    publishes = [v for p, v in claims if p == "security.job.publishes_to"]
    # Both PyPI jobs hold the PyPI credential: each can publish either PyPI target.
    assert sorted(v["artifact_path"] for v in publishes if "pypi" in v["artifact_path"]) == sorted(
        [PYPI_TARGET, CLIENT_TARGET, PYPI_TARGET, CLIENT_TARGET])
    assert ("security.workflow.trigger", "push:tags:v*") in claims
    assert output["restated"] == 2 and output["changed"] == len(claims) - 2


def _held_rows(output: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """What acceptance of ``output`` would hold: coverage rows and source_facts rows."""

    source = "github.com/cruxible-ai/cruxible@main"
    coverage_path = "subjects/security.coverage/main-workflows.json"
    revision = next(v for p, v in _claims(output["items"]) if p == "security.coverage.revision")
    cover = _bind("coverage", "security.coverage", coverage_path)
    coverage_rows = [_row([cover], {"source": f"{source}:.github/workflows/",
                                    "scope": "ci.workflows", "revision": revision},
                          {("security.coverage/main-workflows", "security.coverage.revision"):
                           _claim("rev")})]
    by_subject: dict[str, dict[str, list[Any]]] = {}
    for item in output["items"]:
        statement = item.get("statement")
        if statement is None or not isinstance(statement["subject"], dict):
            continue
        key = statement["subject"].get("key")
        if not key or "job_key" not in key and "path" not in key:
            continue
        name = key.get("job_key") or key["path"]
        by_subject.setdefault(name, {}).setdefault(statement["predicate"], []).append(
            statement["object"])
    rows = []
    workflow_path = ".github/workflows/publish.yml"
    wf = _bind("workflow", "security.workflow", "subjects/security.workflow/publish.json")
    triggers = [(o["value"], None, _claim("t" + o["value"]))
                for o in by_subject[workflow_path]["security.workflow.trigger"]]
    jobs = {name: facts for name, facts in by_subject.items() if name != workflow_path}
    for name, facts in sorted(jobs.items()):
        job = _bind("job", "security.job", f"subjects/security.job/{name}.json")
        includes: dict[str, list[tuple[Any, str | None, str]]] = {"trigger": triggers}
        for include, predicate in (("permission", "permission"), ("secret", "secret"),
                                   ("uses", "uses"), ("needs", "needs"),
                                   ("publishes_to", "publishes_to")):
            values = facts.get(f"security.job.{predicate}", [])
            includes[include] = [
                (o.get("value"),
                 o.get("address", {}).get("artifact_path") if o["kind"] == "subject"
                 else (f"subjects/security.job/{o['subject']['key']['job_key']}.json"
                       if o["kind"] == "subject_key" else None),
                 _claim(name + predicate + json.dumps(o, sort_keys=True))) for o in values]
        environment = facts["security.job.environment"][0]["value"]
        rows.append(_row(
            [wf, job], {"path": workflow_path, "job_key": name, "environment": environment},
            {("security.workflow/publish", "security.workflow.repo"): _claim("wr"),
             ("security.workflow/publish", "security.workflow.coverage"): _claim("wc"),
             (f"security.job/{name}", "security.job.workflow"): _claim(name + "w"),
             (f"security.job/{name}", "security.job.environment"): _claim(name + "e")},
            includes))
    return coverage_rows, rows


def test_an_unchanged_snapshot_restates_only_its_coverage() -> None:
    snapshot = _snapshot(OLD, ["publish.yml"])
    first, _ = workflow_facts(snapshot, [], [], _targets(), [])
    coverage, held = _held_rows(first)
    again, _ = workflow_facts(snapshot, coverage, held, _targets(), [])
    assert again["changed"] == 0 and again["restated"] == 2
    assert sorted(p for p, _ in _claims(again["items"])) == [
        "security.coverage.of", "security.coverage.revision"]


def test_a_moved_source_revises_its_one_coverage_claim_and_only_what_changed() -> None:
    first, _ = workflow_facts(_snapshot(OLD, ["publish.yml"]), [], [], _targets(), [])
    coverage, held = _held_rows(first)
    moved, _ = workflow_facts(_snapshot(NEW, ["publish.yml", "publish-runtime-image.yml"]),
                              coverage, held, _targets(), [])
    revision = [i for i in moved["items"] if i.get("statement", {}).get("predicate")
                == "security.coverage.revision"]
    assert len(revision) == 1 and revision[0]["revises"] == _claim("rev")
    assert revision[0]["statement"]["object"]["value"] == NEW
    for item in moved["items"]:
        predicate = item.get("statement", {}).get("predicate")
        if predicate in {"security.coverage.revision", "security.coverage.of"}:
            continue
        assert "publish-runtime-image" in json.dumps(item), item  # nothing else changed
    assert moved["retired"] == 0 and moved["revised"] == 1


def test_a_dropped_value_is_retired_by_its_claim() -> None:
    first, _ = workflow_facts(_snapshot(OLD, ["publish.yml"]), [], [], _targets(), [])
    coverage, held = _held_rows(first)
    text = (WORKFLOWS / "publish.yml").read_text().replace(
        'tags: ["v*"]', 'tags: ["v*"]\n  workflow_dispatch:')
    snapshot = _snapshot(NEW, ["publish.yml"])
    snapshot["files"][0]["content_base64"] = base64.b64encode(text.encode()).decode()
    moved, _ = workflow_facts(snapshot, coverage, held, _targets()[:1], [])
    claims = _claims(moved["items"])
    assert ("security.workflow.trigger", "workflow_dispatch") in claims
    retired = [i for i in moved["items"] if i.get("tag", "").endswith("retirement-item-v1")]
    # The client target is no longer among the repository's targets: its edges go.
    assert len(retired) == 2 and all(i["reason"] == "superseded" for i in retired)


def test_a_manifest_snapshot_declares_each_asset_digest() -> None:
    manifest = {"base_url": "x", "kits": {"agent-release": {
        "asset": "agent-release-0.3.2.tar.gz", "tarball_sha256": "b2" * 32}}}
    snapshot = _snapshot(NEW, [], ref="v0.3.2")
    snapshot.update(scope="release.manifest", path="src/manifest.json",
                    locator="github.com/cruxible-ai/cruxible@v0.3.2:src/manifest.json",
                    files=[{"path": "src/manifest.json", "content_base64": base64.b64encode(
                        json.dumps(manifest).encode()).decode()}])
    output, _ = workflow_facts(snapshot, [], [], _targets(), [])
    claims = _claims(output["items"])
    assert ("security.artifact.declared_sha256", "sha256:" + "b2" * 32) in claims
    keys = [i["key"] for i in output["items"] if i.get("subject_kind") == "security.artifact"]
    assert keys == [{"target_ref": "github_release/cruxible-ai/cruxible",
                     "name": "v0.3.2/agent-release-0.3.2.tar.gz"}]


# --- registry facts ----------------------------------------------------------------


def test_provenance_names_the_publishing_workflow_environment_and_commit() -> None:
    provenance = json.loads((DATA / "provenance-cruxible_client-0.3.2.json").read_text())
    certificate = provenance["attestation_bundles"][0]["attestations"][0][
        "verification_material"]["certificate"]
    assert certificate_commit(certificate) == "e848cbb6787262db349912c48d9c008d8068ede8"
    assert publisher(provenance) == {
        "repository": "cruxible-ai/cruxible", "workflow": "publish.yml",
        "environment": "pypi-cruxible-client",
        "commit": "e848cbb6787262db349912c48d9c008d8068ede8"}


def _release() -> dict[str, Any]:
    provenance = json.loads((DATA / "provenance-cruxible_client-0.3.2.json").read_text())
    return {"project": "cruxible-client", "versions": [{"version": "0.3.2", "files": [
        {"filename": "cruxible_client-0.3.2-py3-none-any.whl", "sha256": "ef" * 32,
         "provenance_status": 200, "provenance": provenance, "yanked": False},
        {"filename": "cruxible_client-0.3.2.tar.gz", "sha256": "01" * 32,
         "provenance_status": 404, "provenance": None, "yanked": False}]}]}


def test_registry_facts_state_what_pypi_serves_and_who_published_it() -> None:
    output, _ = registry_facts(_release(), [], [])
    claims = dict(_claims(output["items"]))
    assert claims["security.artifact.publish_environment"] == "pypi-cruxible-client"
    assert claims["security.artifact.published_by"]["key"] == {
        "source": "github.com/cruxible-ai/cruxible@e848cbb6787262db349912c48d9c008d8068ede8",
        "path": ".github/workflows/publish.yml"}
    assert claims["security.target.source_repo"]["key"] == {
        "forge_host": "github.com", "full_name": "cruxible-ai/cruxible"}
    digests = [v for p, v in _claims(output["items"]) if p == "security.artifact.sha256"]
    assert sorted(digests) == ["sha256:" + "01" * 32, "sha256:" + "ef" * 32]
    # The sdist has no provenance: nothing states a publisher for it.
    assert len([p for p, _ in _claims(output["items"])
                if p == "security.artifact.published_by"]) == 1
    assert output["revision"].startswith("sha256:") and output["restated"] == 2


# --- the questions -----------------------------------------------------------------


def _hq_row(target: tuple[str, str, str], gate: list[str], repo: bool = True,
            coverage: tuple[str, str] | None = None, **extra: Any) -> dict[str, Any]:
    path, registry, name = target
    bindings = [_bind("target", "security.target", path)]
    fields: dict[str, Any] = {"target_registry": registry, "target_name": name, "gate": gate,
                              "repo_host": None, "repo_name": None,
                              "coverage_source": None, "coverage_revision": None}
    if repo:
        bindings.append(_bind("repo", "security.repo", REPO_PATH))
        fields.update(repo_host="github.com", repo_name="cruxible-ai/cruxible")
    if coverage:
        bindings.append(_bind("coverage", "security.coverage", coverage[0]))
        fields.update(coverage_source=coverage[1], coverage_revision=NEW)
    for binding, (kind, value) in extra.pop("_bind", {}).items():
        bindings.append(_bind(binding, kind, value))
    fields.update(extra)
    return _row(bindings, fields)


PYPI = (PYPI_TARGET, "pypi", "cruxible")
GHCR = (GHCR_TARGET, "ghcr", "cruxible-ai/cruxible-runtime")
MAIN = ("subjects/security.coverage/main.json",
        "github.com/cruxible-ai/cruxible@main:.github/workflows/")


def _job(name: str, path: str, triggers: list[str], **facts: Any) -> dict[str, Any]:
    return {"_bind": {"job": ("security.job", f"subjects/security.job/{name}.json"),
                      "job_coverage": ("security.coverage", MAIN[0])},
            "job_key": name, "workflow_path": path, "triggers": triggers, **facts}


def test_every_answer_starts_unknown_and_gaps_group_by_source() -> None:
    rows = {"hq1": [_hq_row(PYPI, ["push:tags:v*"], repo=False),
                    _hq_row(GHCR, ["push:tags:v*"])],
            "hq2": [], "hq3": [], "hq4": [], "hq5": [], "params": {}}
    result = harden(rows)
    assert {a["state"] for a in result["answers"]} == {"unknown"}
    gaps = [i for i in result["items"] if i["kind"] == "gap"]
    assert sorted(g["source"] for g in gaps) == [
        "github.com/cruxible-ai/cruxible@main:.github/workflows/", "pypi/cruxible"]
    assert gaps[1]["pull"] == "security.registry-acquire"
    assert gaps[0]["input"] == {"forge_host": "github.com", "full_name": "cruxible-ai/cruxible",
                                "ref": "main", "scope": "ci.workflows",
                                "path": ".github/workflows/"}
    # Many questions wait on each source: still one item per source.
    assert result["gaps"] == 2 and result["unknown"] > 2


def test_covered_answers_are_found_or_none_and_name_their_coverage() -> None:
    rows = {
        "hq1": [_hq_row(PYPI, ["push:tags:v*"], coverage=MAIN,
                        **_job("publish-cruxible", "publish.yml", ["push:tags:v*"])),
                _hq_row(GHCR, ["push:tags:v*"], coverage=MAIN,
                        **_job("build", "publish-runtime-image.yml",
                               ["push:tags:v*", "workflow_dispatch"]))],
        "hq2": [], "hq3": [], "hq4": [], "hq5": [], "params": {},
    }
    result = harden(rows)
    by = {(a["question"], a["subject"].split(" @ ")[0]): a for a in result["answers"]}
    assert by[("HQ1", "pypi/cruxible")]["state"] == "none"
    assert by[("HQ1", "pypi/cruxible")]["revision"] == NEW
    found = by[("HQ1", "ghcr/cruxible-ai/cruxible-runtime")]
    assert found["state"] == "found"
    (finding,) = [i for i in result["items"] if i["kind"] == "finding"]
    assert finding["bypass"] == [{"job": "publish-runtime-image.yml#build",
                                  "triggers": ["workflow_dispatch"]}]
    # HQ5 still waits on PyPI: what the target serves was never pulled.
    assert [i["source"] for i in result["items"] if i["kind"] == "gap"] == ["pypi/cruxible"]


def test_hq2_hq3_hq4_judge_credentials_triggers_and_pins() -> None:
    build = _job("build", "publish-runtime-image.yml", ["push:tags:v*", "workflow_dispatch"],
                 permissions=["contents:read", "packages:write"], secrets=["GITHUB_TOKEN"],
                 environment="none", uses=["pkg:githubactions/docker/login-action@" + "a" * 40])
    build["_bind"]["coverage"] = build["_bind"].pop("job_coverage")
    client = _job("publish-client", "publish.yml", ["push:tags:v*"],
                  permissions=["id-token:write"], environment="pypi-cruxible-client",
                  uses=["pkg:githubactions/actions/checkout@v4"])
    cruxible = _job("publish-cruxible", "publish.yml", ["push:tags:v*"],
                    permissions=["id-token:write"], uses=["pkg:githubactions/actions/checkout@v4"])
    hq3_client = dict(client, _bind=dict(client["_bind"]))
    hq3_client["_bind"]["coverage"] = hq3_client["_bind"].pop("job_coverage")
    result = harden({
        "hq1": [_hq_row(PYPI, ["push:tags:v*"], coverage=MAIN)],
        "hq2": [_hq_row(PYPI, ["push:tags:v*"], **build)],
        "hq3": [_hq_row(PYPI, ["push:tags:v*"], **hq3_client)],
        "hq4": [_hq_row(PYPI, ["push:tags:v*"], coverage=MAIN, **client),
                _hq_row(PYPI, ["push:tags:v*"], coverage=MAIN, **cruxible)],
        "hq5": [], "params": {}})
    findings = {i["question"]: i for i in result["items"] if i["kind"] == "finding"}
    assert findings["HQ2"]["jobs"][0]["triggers"] == ["workflow_dispatch"]
    assert findings["HQ3"]["jobs"][0]["mutable"] == ["pkg:githubactions/actions/checkout@v4"]
    assert findings["HQ4"]["shared"] == ["pkg:githubactions/actions/checkout@v4"]


def test_hq5_posts_a_digest_disagreement_citing_both_claims() -> None:
    release = ("subjects/security.target/github_release--cruxible.json", "github_release",
               "cruxible-ai/cruxible")
    artifact = "subjects/security.artifact/v0.3.2-agent-release.json"
    row = _hq_row(release, ["push:tags:v*"], coverage=MAIN,
                  _bind={"artifact": ("security.artifact", artifact)},
                  artifact_name="v0.3.2/agent-release-0.3.2.tar.gz",
                  declared_sha256="sha256:" + "b2" * 32, sha256="sha256:" + "ff" * 32)
    row["read_claims"] = [
        {"claim_path": f"claims/aa/{_claim('d')}.json", "predicate":
         "security.artifact.declared_sha256", "subject_identity": "security.artifact/x"},
        {"claim_path": f"claims/bb/{_claim('s')}.json", "predicate": "security.artifact.sha256",
         "subject_identity": "security.artifact/x"}]
    row["bindings"][-1]["subject_identity"] = "security.artifact/x"
    result = harden({"hq1": [], "hq2": [], "hq3": [], "hq4": [], "hq5": [row], "params": {}})
    (finding,) = [i for i in result["items"] if i["kind"] == "finding"]
    assert finding["disagreement"] == "digest"
    assert finding["declared"] == {"value": "sha256:" + "b2" * 32, "claim": _claim("d")}
    assert finding["served"] == {"value": "sha256:" + "ff" * 32, "claim": _claim("s")}


def test_hq5_unknown_until_the_publishing_commit_is_covered() -> None:
    sha = "e848cbb6787262db349912c48d9c008d8068ede8"
    row = _hq_row(PYPI, ["push:tags:v*"],
                  _bind={"artifact": ("security.artifact", "subjects/security.artifact/w.json"),
                         "registry_coverage": ("security.coverage",
                                               "subjects/security.coverage/pypi.json")},
                  registry_coverage_source="pypi/cruxible", registry_coverage_revision="sha256:1",
                  artifact_name="cruxible-0.3.2-py3-none-any.whl", sha256="sha256:2",
                  workflow_source=f"github.com/cruxible-ai/cruxible@{sha}",
                  workflow_path=".github/workflows/publish.yml", publish_environment="none")
    result = harden({"hq1": [], "hq2": [], "hq3": [], "hq4": [], "hq5": [row], "params": {}})
    gaps = {i["source"]: i for i in result["items"] if i["kind"] == "gap"}
    # HQ5 waits on the workflows at the commit PyPI says it was built from; HQ1-4 on main.
    gap = gaps[f"github.com/cruxible-ai/cruxible@{sha}:.github/workflows/"]
    assert gap["input"]["ref"] == sha and len(gaps) == 2
    (hq5,) = [a for a in result["answers"] if a["question"] == "HQ5"]
    assert hq5["state"] == "unknown" and hq5["source"] == gap["source"]
    assert parse_rows([row])[0].value("artifact_name").endswith(".whl")
