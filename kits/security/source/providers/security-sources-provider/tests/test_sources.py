"""The Sources retain exactly the exchanges they had, as Core's acquisition wire."""

from __future__ import annotations

import base64
import hashlib
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
    OSV_ECOSYSTEMS_URL,
    OsvEcosystems,
    OsvQuery,
    PypiRelease,
    ReleaseAsset,
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


#: The kit data the osv-applicability Procedure carries (purl type -> OSV ecosystem).
PURL_TYPES = json.loads(
    (Path(__file__).resolve().parents[3] / "authoring" / "data" / "purl_osv_ecosystems.json")
    .read_text())
ECOSYSTEMS_TXT = b"Debian\nDebian:12\nGo\nMaven\nnpm\nPyPI\n"


def _ecosystems(body: bytes = ECOSYSTEMS_TXT) -> dict[str, Any]:
    """The security.osv-ecosystems material the osv Source reads."""

    return _material(OsvEcosystems(lambda: static_transport(
        {("GET", "/ecosystems.txt"): (200, body, {"content-type": "text/plain"})}))(
            _context("security.osv-ecosystems", {})))


def test_osv_ecosystems_retains_the_published_list_exactly() -> None:
    context = _context("security.osv-ecosystems", {})
    material = _material(OsvEcosystems(lambda: static_transport(
        {("GET", "/ecosystems.txt"): (200, ECOSYSTEMS_TXT, {"content-type": "text/plain"})}))(
            context))
    retrieved = material["retrieved"]
    assert base64.b64decode(retrieved["body_base64"]) == ECOSYSTEMS_TXT
    assert retrieved["url"] == OSV_ECOSYSTEMS_URL and retrieved["status_code"] == 200
    assert context.egress.observed() == ["https://osv-vulnerabilities.storage.googleapis.com"]
    refused = OsvEcosystems(lambda: static_transport({}))(
        _context("security.osv-ecosystems", {"url": "https://example.com/ecosystems.txt"}))
    assert refused.status == "refused"


def test_osv_query_never_asks_about_a_component_osv_does_not_index() -> None:
    asked: list[list[str]] = []

    def batch(purls: list[str]) -> bytes:
        asked.append(list(purls))
        return json.dumps({"results": [{} for _ in purls]}).encode()

    provider = OsvQuery(lambda: static_transport({}, batch))
    payload = {
        "releases": _rows("components", ["pkg:brew/gh@2.86.0", "pkg:generic/php@8.3.10",
                                         "pkg:golang/github.com/cli/cli/v2@v2.86.0",
                                         "pkg:deb/debian/libc6@2.36-9", "pkg:apk/alpine/musl@1.2"]),
        "watched": [], "ecosystems": _ecosystems(), "purl_types": PURL_TYPES}
    material = _material(provider(_context("security.osv-query", payload)))
    assert asked == [["pkg:deb/debian/libc6@2.36-9", "pkg:golang/github.com/cli/cli/v2@v2.86.0"]]
    reasons = {item["purl"]: (item["type"], item["reason"]) for item in material["not_indexed"]}
    assert reasons == {
        "pkg:apk/alpine/musl@1.2": ("apk", "OSV does not list the Alpine ecosystem"),
        "pkg:brew/gh@2.86.0": ("brew", "no OSV ecosystem for purl type brew"),
        "pkg:generic/php@8.3.10": ("generic", "no OSV ecosystem for purl type generic")}
    assert material["osv_ecosystems"]["listed"] == ["Debian", "Go", "Maven", "PyPI", "npm"]
    assert material["purl_types"]["osv_ecosystems"]["golang"] == "Go"
    # Without the captured list (or the map) a missing answer would read as none: refused.
    for missing in ("ecosystems", "purl_types"):
        refused = provider(_context("security.osv-query", {**payload, missing: None}))
        assert refused.status == "refused"
        assert "would read as no advisories" in refused.refusal.message


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
            "ecosystems": _ecosystems(),
            "purl_types": PURL_TYPES,
        },
    )
    material = _material(provider(context))
    assert material["not_indexed"] == []
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


def test_release_asset_follows_github_redirect_and_keeps_the_served_bytes() -> None:
    url = "https://github.com/cruxible-ai/cruxible/releases/download/v0.3.2/a.tar.gz"
    routes = {
        ("GET", "/cruxible-ai/cruxible/releases/download/v0.3.2/a.tar.gz"): (
            302, b"", {"location": "https://release-assets.githubusercontent.com/x/a?sig=1"}),
        ("GET", "/x/a"): (200, b"bytes", {"content-type": "application/octet-stream"}),
    }
    context = _context("security.release-asset", {"url": url})
    retrieved = _material(ReleaseAsset(lambda: static_transport(routes))(context))["retrieved"]
    assert retrieved["body_sha256"] == "sha256:" + hashlib.sha256(b"bytes").hexdigest()
    assert retrieved["final_url"] == "https://release-assets.githubusercontent.com/x/a"
    refused = ReleaseAsset(lambda: static_transport(routes))(
        _context("security.release-asset", {"url": "https://example.org/a.tar.gz"}))
    assert refused.status == "refused"


def test_the_registration_verifies() -> None:
    load_registration(Path(security_sources_provider.__file__).parent)


# --- retries: a slow origin answers or fails, never half-answers ------------------


def test_a_timed_out_or_throttled_exchange_is_retried_with_backoff(monkeypatch: Any) -> None:
    from security_sources_provider import sources

    ecosystems = _ecosystems()  # read before the network is made slow

    waits: list[float] = []
    monkeypatch.setattr(sources, "_sleep", waits.append)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadTimeout("slow", request=request)
        if calls["n"] == 2:
            return httpx.Response(503, content=b"busy", request=request)
        return httpx.Response(200, content=json.dumps({"results": [{}]}).encode(),
                              request=request)

    provider = OsvQuery(lambda: httpx.MockTransport(handler))
    result = provider(_context("security.osv-query", {
        "releases": _rows("components", ["pkg:pypi/requests@2.32.3"]), "watched": [],
        "ecosystems": ecosystems, "purl_types": PURL_TYPES}))
    material = _material(result)
    assert calls["n"] == 3 and waits == [1.0, 2.0]
    assert [e["status"] for e in material["exchanges"]] == [200]


def test_a_timeout_on_every_attempt_fails_the_run(monkeypatch: Any) -> None:
    from security_sources_provider import sources

    ecosystems = _ecosystems()  # read before the network is made slow

    monkeypatch.setattr(sources, "_sleep", lambda _s: None)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("down", request=request)

    provider = OsvQuery(lambda: httpx.MockTransport(handler))
    result = provider(_context("security.osv-query", {
        "releases": _rows("components", ["pkg:pypi/requests@2.32.3"]), "watched": [],
        "ecosystems": ecosystems, "purl_types": PURL_TYPES}))
    assert result.status == "error" and "Timeout" in result.error.message


def test_each_source_stamps_only_the_logical_sources_its_interface_produces() -> None:
    """The source_identity each Source writes is what its interface declares it produces."""

    import ast

    package = Path(security_sources_provider.__file__).parent
    module = ast.parse((package / "sources.py").read_text())
    constants = {
        target.id: node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    classes = {node.name: node for node in module.body if isinstance(node, ast.ClassDef)}
    manifest = json.loads((package / "manifest.json").read_text())
    assert len(manifest["implementations"]) == 5
    for implementation in manifest["implementations"]:
        interface = implementation["interface_id"]
        _module, _, name = implementation["entrypoint"].partition(":")
        stamped = {
            constants[keyword.value.id]
            for call in ast.walk(classes[name])
            if isinstance(call, ast.Call)
            for keyword in call.keywords
            if keyword.arg == "source_identity" and isinstance(keyword.value, ast.Name)
        }
        definition = json.loads((package / "contracts" / f"{interface}.json").read_text())
        assert stamped, interface
        assert stamped <= set(definition["produces"]), (interface, stamped)
        assert definition["produces"] == sorted(set(definition["produces"])), interface
