"""Offline tests for osv.query and osv.match on recorded real OSV exchanges.

``recordings/`` holds real api.osv.dev exchanges (recorded 2026-11-04 for the
kit's two demo SBOMs, plus a distro binary-name miss, its source-name hit and an
advisory OSV does not know). No test opens a socket. Core wiring (list Captures,
derive inputs, derived Captures) is not exercised here: it waits for core lanes
A + B.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from security_osv_provider import osv  # noqa: E402

RECORDINGS = HERE / "recordings"
INDEX = json.loads((RECORDINGS / "index.json").read_text())["exchanges"]
SBOMS = HERE.parents[3] / "examples" / "sboms"


def sbom_purls(name: str) -> list[str]:
    return [c["purl"] for c in json.loads((SBOMS / name).read_text())["components"]]


class Recorded:
    """An OSV origin answering from recordings, by method + URL + request body."""

    def __init__(self, overrides: Mapping[str, tuple[int, bytes]] | None = None) -> None:
        self.answers: dict[tuple[str, str, str], tuple[int, bytes]] = {}
        for item in INDEX:
            body = "" if item["request"] is None else json.dumps(item["request"], sort_keys=True)
            self.answers[(item["method"], item["url"], body)] = (
                item["status"],
                (RECORDINGS / item["body"]).read_bytes(),
            )
        self.overrides = dict(overrides or {})
        self.requests: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requests.append(f"{request.method} {url}")
            if url in self.overrides:
                status, content = self.overrides[url]
                return httpx.Response(status, content=content)
            body = request.content.decode() if request.content else ""
            if body:
                body = json.dumps(json.loads(body), sort_keys=True)
            status, content = self.answers[(request.method, url, body)]
            return httpx.Response(
                status, headers={"content-type": "application/json"}, content=content
            )

        return httpx.MockTransport(handle)


def context(payload: Mapping[str, Any], operation: str) -> Any:
    from cruxible_provider_runtime.egress import EgressRecorder
    from cruxible_provider_runtime.protocol import Budgets
    from cruxible_provider_runtime.provider_api import ProviderRunContext

    return ProviderRunContext(
        run_id="run-test",
        input=dict(payload),
        operation=operation,
        operation_signature_digest="sha256:" + "9" * 64,
        build_digest="sha256:" + "b" * 64,
        implementation_digest="sha256:" + "a" * 64,
        declared_endpoints=(osv.OSV_API,),
        budgets=Budgets(wall_clock_seconds=30, output_bytes=8_000_000),
        coordinates={},
        capture_contract=None,
        secrets={},
        egress=EgressRecorder(),
    )


def query(components: list[str], origin: Recorded) -> list[dict[str, Any]]:
    result = osv.OsvQuery(transport_factory=origin.transport)(
        context({"components": components, "logical_source": "osv.dev.query"}, osv.QUERY)
    )
    assert result.status == "ok", result
    return list(result.output["responses"])


def derive(responses: list[dict[str, Any]], components: list[str]) -> tuple[bytes, dict]:
    result = osv.OsvMatch()(
        context(
            {"responses": responses, "components": components, "logical_source": "osv.dev.query"},
            osv.MATCH,
        )
    )
    assert result.status == "ok", result
    import base64

    content = base64.b64decode(result.output["document"]["content_base64"])
    return content, json.loads(content)


def test_each_response_is_one_member_verbatim() -> None:
    origin = Recorded()
    components = sbom_purls("log4j-demo-app.cdx.json")
    responses = query(components, origin)
    # One batch, then one record per advisory the batch names.
    assert [r["coordinate"]["method"] for r in responses].count("POST") == 1
    batch = next(r for r in responses if r["coordinate"]["method"] == "POST")
    import base64

    assert (
        base64.b64decode(batch["content_base64"])
        == (RECORDINGS / "batch-log4j-demo-app.body").read_bytes()
    )
    assert batch["coordinate"]["purls"] == sorted(components)
    assert len(responses) == 1 + 9


def test_log4j_demo_app_reaches_log4shell_and_its_siblings() -> None:
    components = sbom_purls("log4j-demo-app.cdx.json")
    _content, document = derive(query(components, Recorded()), components)
    pairs = {(r["purl"].split("/")[-1], r["cve_id"]) for r in document["affected"]}
    assert ("log4j-core@2.14.1", "CVE-2021-44228") in pairs
    assert ("log4j-core@2.14.1", "CVE-2021-45046") in pairs
    assert ("log4j-api@2.14.1", "CVE-2026-49844") in pairs
    assert document["queried"] == sorted(components)
    assert document["not_checked"] == []


def test_cruxible_env_names_mcp_cves_and_reports_unkeyed_advisories() -> None:
    components = sbom_purls("cruxible-env.cdx.json")
    _content, document = derive(query(components, Recorded()), components)
    assert {r["cve_id"] for r in document["affected"]} == {
        "CVE-2026-116684",
        "CVE-2026-116685",
        "CVE-2026-116686",
        "CVE-2026-59951",
    }
    # certifi's and uv's advisories alias only each other (GHSA <-> PYSEC): no CVE.
    assert {r["purl"].split("@")[0] for r in document["unkeyed"]} == {
        "pkg:pypi/certifi",
        "pkg:pypi/uv",
    }
    assert len(document["queried"]) == 55


def test_distro_packages_are_never_asked_and_read_not_checked() -> None:
    origin = Recorded()
    libc6 = "pkg:deb/debian/libc6@2.36-9+deb12u7"
    responses = query([libc6], origin)
    assert responses == [] and origin.requests == []
    _content, document = derive(responses, [libc6])
    assert document["queried"] == []
    assert document["not_checked"] == [{"purl": libc6, "reason": "distro_source_name_unknown"}]
    # Why (recorded): OSV's Debian data answers the source name, not the binary one.
    assert json.loads((RECORDINGS / "distro-miss-binary-libc6.body").read_bytes()) == {
        "results": [{}]
    }
    glibc = json.loads((RECORDINGS / "distro-source-glibc.body").read_bytes())
    assert len(glibc["results"][0]["vulns"]) > 0


def test_an_unreadable_advisory_leaves_its_component_unanswered() -> None:
    components = sbom_purls("log4j-demo-app.cdx.json")
    missing = (RECORDINGS / "vuln-missing.body").read_bytes()
    origin = Recorded(overrides={f"{osv.OSV_API}/v1/vulns/GHSA-jfh8-c2jp-5v3q": (404, missing)})
    _content, document = derive(query(components, origin), components)
    core = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert core not in document["queried"]
    assert {"purl": core, "reason": "advisory_unreadable"} in document["not_checked"]
    assert all(r["purl"] != core for r in document["affected"])
    # Its siblings still answer.
    assert "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1" in document["queried"]


def test_a_failed_batch_leaves_every_component_in_it_unanswered() -> None:
    components = sbom_purls("log4j-demo-app.cdx.json")
    origin = Recorded(overrides={f"{osv.OSV_API}/v1/querybatch": (503, b"unavailable")})
    _content, document = derive(query(components, origin), components)
    assert document["queried"] == [] and document["affected"] == []
    assert {r["reason"] for r in document["not_checked"]} == {"batch_failed"}


def test_match_is_byte_identical_across_runs() -> None:
    components = sbom_purls("log4j-demo-app.cdx.json")
    responses = query(components, Recorded())
    first, _ = derive(responses, components)
    second, _ = derive(responses, components)
    assert first == second


@pytest.mark.parametrize("operation", [osv.QUERY, osv.MATCH])
def test_registration_names_each_operation_and_its_entrypoint(operation: str) -> None:
    root = HERE.parent / "src" / "security_osv_provider"
    registration = json.loads((root / "registration.json").read_text())
    (entry,) = [op for op in registration["operations"] if op["name"] == operation]
    module, _, name = entry["entrypoint"].partition(":")
    assert operation in getattr(osv, name).operations
    assert entry["effect"] == ("pure" if operation == osv.MATCH else "external_read")
    import hashlib

    manifest = (root / "manifest.yaml").read_bytes()
    assert registration["manifest"]["digest"] == "sha256:" + hashlib.sha256(manifest).hexdigest()
