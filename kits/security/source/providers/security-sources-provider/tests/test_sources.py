"""The Sources retain exactly the exchanges they had, as Core's acquisition wire."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

import httpx
import security_sources_provider
from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_runtime.protocol import Budgets
from cruxible_provider_runtime.provider_api import ProviderRunContext
from cruxible_provider_runtime.registration import load_registration
from security_sources_provider.sources import (
    EpssDaily,
    OsvQuery,
    PypiRelease,
    RepoSnapshot,
    git_blob_id,
    static_transport,
)


def _context(interface: str, payload: dict[str, Any]) -> ProviderRunContext:
    return ProviderRunContext(
        run_id="test",
        input=payload,
        interface_id=interface,
        interface_digest="sha256:" + "0" * 64,
        implementation_digest="sha256:" + "1" * 64,
        declared_endpoints=(),
        input_bucket="test",
        budgets=Budgets(wall_clock_seconds=30, output_bytes=50_000_000),
        coordinates={},
        capture_contract=None,
        secrets={},
        egress=EgressRecorder(),
    )


def _material(result: Any) -> dict[str, Any]:
    assert result.status == "ok", result
    wire = result.output
    assert wire["tag"] == "playbill-provider-result-to-external-capture-v1"
    assert wire["replayability"] == "attested_only"
    return json.loads(base64.b64decode(wire["content_base64"]))


def _rows(name: str, *values: object) -> list[dict[str, Any]]:
    return [
        {"bindings": [], "fields": [{"name": name, "state": "present", "value": v}]} for v in values
    ]


def test_osv_query_batches_components_then_fetches_hits_watched_and_their_aliases() -> None:
    records = {
        "GHSA-h75v-3vvj-5mfj": {"id": "GHSA-h75v-3vvj-5mfj", "aliases": ["CVE-2024-34064"]},
        "CVE-2021-44228": {"id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"]},
        "GHSA-jfh8-c2jp-5v3q": {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]},
    }

    def batch(purls: list[str]) -> bytes:
        results = [
            {"vulns": [{"id": "GHSA-h75v-3vvj-5mfj"}]} if "jinja2" in p else {} for p in purls
        ]
        return json.dumps({"results": results}).encode()

    routes = {
        ("GET", f"/v1/vulns/{k}"): (200, json.dumps(v).encode(), {}) for k, v in records.items()
    }
    provider = OsvQuery(lambda: static_transport(routes, batch))
    context = _context(
        "security.osv-query",
        {
            "releases": _rows(
                "components", ["pkg:pypi/jinja2@3.1.3", "pkg:pypi/httpx@0.28.1", "x"]
            ),
            "watched": _rows("cve_id", "CVE-2021-44228", "CVE-2099-0001"),
        },
    )
    material = _material(provider(context))
    paths = [(e["method"], e["path"], e["status"]) for e in material["exchanges"]]
    assert paths == [
        ("POST", "/v1/querybatch", 200),
        ("GET", "/v1/vulns/CVE-2021-44228", 200),
        ("GET", "/v1/vulns/CVE-2099-0001", 404),
        ("GET", "/v1/vulns/GHSA-h75v-3vvj-5mfj", 200),
        ("GET", "/v1/vulns/GHSA-jfh8-c2jp-5v3q", 200),
    ]
    assert material["exchanges"][0]["request"] == {
        "purls": ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"]
    }
    assert material["source"] == "packaged-recording"
    assert context.egress.observed() == ["https://api.osv.dev"]


def test_epss_daily_follows_the_dated_redirect_and_keeps_the_exact_bytes() -> None:
    body = gzip.compress(
        b"#model_version:v1,score_date:2026-10-10T00:00:00Z\ncve,epss,percentile\n", mtime=0
    )
    routes = {
        ("GET", "/epss_scores-current.csv.gz"): (
            302,
            b"",
            {"location": "epss_scores-2026-10-10.csv.gz"},
        ),
        ("GET", "/epss_scores-2026-10-10.csv.gz"): (
            200,
            body,
            {"content-type": "application/gzip"},
        ),
    }
    context = _context("security.epss-daily", {})
    material = _material(EpssDaily(lambda: static_transport(routes))(context))
    retrieved = material["retrieved"]
    assert (
        retrieved["final_url"] == "https://epss.empiricalsecurity.com/epss_scores-2026-10-10.csv.gz"
    )
    assert base64.b64decode(retrieved["body_base64"]) == body
    assert context.egress.observed() == ["https://epss.empiricalsecurity.com"]


def test_epss_refuses_another_origin() -> None:
    result = EpssDaily(lambda: httpx.MockTransport(lambda r: httpx.Response(500)))(
        _context("security.epss-daily", {"url": "https://example.org/x.csv.gz"})
    )
    assert result.status == "refused"


SHA = "e848cbb6787262db349912c48d9c008d8068ede8"
PUBLISH = b"on:\n  push:\n    tags: ['v*']\njobs: {}\n"


def _repo_routes(publish: bytes = PUBLISH, blob: str | None = None) -> dict[Any, Any]:
    listing = [
        {"type": "file", "name": "publish.yml", "path": ".github/workflows/publish.yml",
         "sha": blob or git_blob_id(publish)},
        {"type": "file", "name": "README.md", "path": ".github/workflows/README.md",
         "sha": git_blob_id(b"x")},
    ]
    return {
        ("GET", "/repos/cruxible-ai/cruxible/commits"): (
            200, json.dumps([{"sha": SHA}]).encode(), {}),
        ("GET", "/repos/cruxible-ai/cruxible/contents/.github/workflows"): (
            200, json.dumps(listing).encode(), {}),
        ("GET", f"/cruxible-ai/cruxible/{SHA}/.github/workflows/publish.yml"): (200, publish, {}),
    }


REPO_INPUT = {"forge_host": "GitHub.com", "full_name": "Cruxible-AI/cruxible", "ref": "main",
              "scope": "ci.workflows", "path": ".github/workflows/"}


def test_repo_snapshot_reads_the_workflows_at_the_revision_as_deterministic_bytes() -> None:
    wires = []
    for _ in range(2):
        context = _context("security.repo-snapshot", REPO_INPUT)
        result = RepoSnapshot(lambda: static_transport(_repo_routes()))(context)
        material = _material(result)
        wires.append(result.output["content_base64"])
    assert wires[0] == wires[1]  # an unchanged source is the same bytes: a re-observation
    assert material["locator"] == "github.com/cruxible-ai/cruxible@main:.github/workflows/"
    assert material["revision"] == SHA
    (only,) = material["files"]  # README.md is not a workflow file
    assert only["path"] == ".github/workflows/publish.yml"
    assert base64.b64decode(only["content_base64"]) == PUBLISH
    assert context.egress.observed() == [
        "https://api.github.com", "https://raw.githubusercontent.com"]


def test_repo_snapshot_fails_on_a_file_that_is_not_its_listed_blob() -> None:
    routes = _repo_routes(blob="0" * 40)
    result = RepoSnapshot(lambda: static_transport(routes))(
        _context("security.repo-snapshot", REPO_INPUT))
    assert result.status == "error"


def test_repo_snapshot_of_a_missing_path_is_an_empty_answer_at_the_ref_head() -> None:
    routes = {
        ("GET", "/repos/cruxible-ai/cruxible/commits"): (200, b"[]", {}),
        ("GET", "/repos/cruxible-ai/cruxible/commits/main"): (
            200, json.dumps({"sha": SHA}).encode(), {}),
    }
    material = _material(RepoSnapshot(lambda: static_transport(routes))(
        _context("security.repo-snapshot", REPO_INPUT)))
    assert (material["revision"], material["files"]) == (SHA, [])


def test_repo_snapshot_refuses_what_it_does_not_read() -> None:
    for change in ({"forge_host": "gitlab.com"}, {"path": ".github/workflows"},
                   {"scope": "release.manifest"}, {"ref": "../x"}):
        result = RepoSnapshot(lambda: static_transport({}))(
            _context("security.repo-snapshot", {**REPO_INPUT, **change}))
        assert result.status == "refused", change


def test_pypi_release_keeps_the_newest_versions_files_and_their_provenance() -> None:
    def file(name: str, at: str) -> dict[str, Any]:
        return {"filename": name, "packagetype": "bdist_wheel", "size": 3,
                "digests": {"sha256": "ab" * 32}, "upload_time_iso_8601": at,
                "yanked": False, "downloads": -1}

    project = {"info": {"name": "Cruxible"}, "last_serial": 1, "releases": {
        "0.3.1": [file("cruxible-0.3.1-py3-none-any.whl", "2026-07-01T00:00:00Z")],
        "0.3.2": [file("cruxible-0.3.2-py3-none-any.whl", "2026-08-07T00:22:34Z"),
                  file("cruxible-0.3.2.tar.gz", "2026-08-07T00:22:36Z")],
        "0.1.0": [],
    }}
    provenance = {"version": 1, "attestation_bundles": [{"publisher": {
        "kind": "GitHub", "repository": "cruxible-ai/cruxible", "workflow": "publish.yml",
        "environment": None}, "attestations": []}]}
    routes = {
        ("GET", "/pypi/cruxible/json"): (200, json.dumps(project).encode(), {}),
        ("GET", "/integrity/cruxible/0.3.2/cruxible-0.3.2-py3-none-any.whl/provenance"): (
            200, json.dumps(provenance).encode(), {}),
    }
    context = _context("security.pypi-release", {"project": "Cruxible", "versions": 2})
    material = _material(PypiRelease(lambda: static_transport(routes))(context))
    assert material["project"] == "cruxible"
    assert [v["version"] for v in material["versions"]] == ["0.3.2", "0.3.1"]
    wheel, sdist = material["versions"][0]["files"]
    assert (wheel["provenance_status"], wheel["provenance"]) == (200, provenance)
    assert (sdist["provenance_status"], sdist["provenance"]) == (404, None)
    assert "downloads" not in wheel and wheel["sha256"] == "ab" * 32
    assert context.egress.observed() == ["https://pypi.org"]


def test_the_registration_verifies() -> None:
    load_registration(Path(security_sources_provider.__file__).parent)
