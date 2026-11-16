"""Offline tests for osv.query and osv.match on recorded real OSV exchanges.

``recordings/`` holds real api.osv.dev exchanges (recorded 2026-11-04 for the
kit's two demo SBOMs, plus a distro binary-name miss, its source-name hit and an
advisory OSV does not know). No test opens a socket. The core wiring (list
Captures, derive inputs, derived Captures) is exercised by the kit gate
(``source/pilot/test_dependency_gate.py``).
"""

from __future__ import annotations

import base64
import json
import socket
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
    """An OSV origin answering from recordings, by method + URL + request body.

    ``overrides`` answer a URL with (status, bytes); ``drop`` URLs raise a
    transport error (no response at all).
    """

    def __init__(
        self,
        overrides: Mapping[str, tuple[int, bytes]] | None = None,
        *,
        drop: tuple[str, ...] = (),
    ) -> None:
        self.answers: dict[tuple[str, str, str], tuple[int, bytes]] = {}
        for item in INDEX:
            body = "" if item["request"] is None else json.dumps(item["request"], sort_keys=True)
            self.answers[(item["method"], item["url"], body)] = (
                item["status"],
                (RECORDINGS / item["body"]).read_bytes(),
            )
        self.overrides = dict(overrides or {})
        self.drop = drop
        self.requests: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requests.append(f"{request.method} {url}")
            if url in self.drop:
                raise httpx.ConnectError("dropped", request=request)
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


def query_result(components: list[str], origin: Recorded) -> Any:
    result = osv.OsvQuery(transport_factory=origin.transport)(
        context({"components": components, "logical_source": "osv.dev.query"}, osv.QUERY)
    )
    assert result.status == "ok", result
    return result


def query(components: list[str], origin: Recorded) -> list[dict[str, Any]]:
    result = query_result(components, origin)
    assert result.incomplete_captures == []
    return list(result.output["responses"])


def derive(responses: list[dict[str, Any]], components: list[str]) -> tuple[bytes, dict]:
    result = osv.OsvMatch()(
        context(
            {"responses": responses, "components": components, "logical_source": "osv.dev.query"},
            osv.MATCH,
        )
    )
    assert result.status == "ok", result
    content = base64.b64decode(result.output["document"]["content_base64"])
    return content, json.loads(content)


def test_each_response_is_one_member_verbatim() -> None:
    origin = Recorded()
    components = sbom_purls("log4j-demo-app.cdx.json")
    responses = query(components, origin)
    # One batch, then one record per advisory the batch names.
    assert [r["coordinate"]["method"] for r in responses].count("POST") == 1
    batch = next(r for r in responses if r["coordinate"]["method"] == "POST")
    assert (
        base64.b64decode(batch["content_base64"])
        == (RECORDINGS / "batch-log4j-demo-app.body").read_bytes()
    )
    assert batch["coordinate"]["purls"] == sorted(components)
    assert len(responses) == 1 + 9


class SlowRecorded(Recorded):
    """Recorded, with advisory GETs answered in reverse order of arrival.

    Each advisory GET waits until ``FETCH_CONCURRENCY`` of them are in flight
    (or a short timeout), so the test sees the concurrency, and the later ones
    answer first.
    """

    def __init__(self, overrides: Mapping[str, tuple[int, bytes]] | None = None) -> None:
        super().__init__(overrides)
        import threading

        self.lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0
        self.gate = threading.Barrier(osv.FETCH_CONCURRENCY)

    def transport(self) -> httpx.MockTransport:
        import threading
        import time

        inner = super().transport()

        def handle(request: httpx.Request) -> httpx.Response:
            if "/v1/vulns/" not in str(request.url):
                return inner.handle_request(request)
            with self.lock:
                self.in_flight += 1
                self.peak = max(self.peak, self.in_flight)
                order = self.in_flight
            try:
                self.gate.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
            # Later arrivals answer first.
            time.sleep(0.01 * (osv.FETCH_CONCURRENCY - order % osv.FETCH_CONCURRENCY))
            try:
                return inner.handle_request(request)
            finally:
                with self.lock:
                    self.in_flight -= 1

        return httpx.MockTransport(handle)


def test_advisories_are_fetched_concurrently_and_returned_in_sorted_order() -> None:
    """Concurrent GETs change only the wait: the members, their order and the
    recorded egress are what one-at-a-time fetching returns."""

    purls, sequential = _synthetic(20)
    expected = query(purls, sequential)
    _purls, slow = _synthetic(20)
    concurrent = SlowRecorded(slow.overrides)
    ctx = context({"components": purls, "logical_source": "osv.dev.query"}, osv.QUERY)
    result = osv.OsvQuery(transport_factory=concurrent.transport)(ctx)
    assert result.status == "ok" and result.incomplete_captures == []
    responses = list(result.output["responses"])
    assert concurrent.peak == osv.FETCH_CONCURRENCY
    strip = lambda members: [  # noqa: E731
        {k: v for k, v in m.items() if k != "observed_at"} for m in members
    ]
    assert strip(responses) == strip(expected)
    advisories = [r["coordinate"]["url"].rsplit("/", 1)[-1] for r in responses[1:]]
    assert advisories == sorted(advisories) and len(advisories) == 20
    assert ctx.egress.observed() == [osv.OSV_API]


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


def test_match_is_byte_identical_across_runs_with_the_network_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Purity conformance (b5): two runs, byte-identical output, no socket."""

    components = sbom_purls("log4j-demo-app.cdx.json")
    responses = query(components, Recorded())

    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("osv.match opened a socket")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    first = osv.OsvMatch()(
        context({"responses": responses, "components": components}, osv.MATCH)
    ).output
    second = osv.OsvMatch()(
        context({"responses": responses, "components": components}, osv.MATCH)
    ).output
    assert first == second
    # Stamped with its inputs' observation time, never the clock.
    assert first["document"]["observed_at"] == max(r["observed_at"] for r in responses)


def test_fixed_versions_are_the_packages_own_fixed_events_sorted_as_text() -> None:
    components = sbom_purls("log4j-demo-app.cdx.json")
    _content, document = derive(query(components, Recorded()), components)
    rows = {(r["purl"].split("/")[-1], r["cve_id"]): r for r in document["affected"]}
    # Log4Shell's advisory lists three log4j-core release lines (and other
    # packages' fixes, which are not this component's).
    assert rows[("log4j-core@2.14.1", "CVE-2021-44228")]["fixed"] == ["2.12.2", "2.15.0", "2.3.1"]
    assert rows[("log4j-api@2.14.1", "CVE-2026-49844")]["fixed"] == ["2.25.5", "2.26.1"]
    # An advisory with no fixed event for the package carries no list.
    assert all("fixed" not in r or r["fixed"] for r in document["affected"])
    assert document["count"] == len(document["affected"])


def test_pypi_names_match_under_pep503() -> None:
    record = {
        "affected": [
            {
                "package": {"purl": "pkg:pypi/Foo_Bar"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2"}]}],
            },
            {"package": {"purl": "pkg:pypi/other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
        ]
    }
    assert osv.fixed_versions(record, "pkg:pypi/foo-bar@1.0") == ["1.2"]


def test_a_request_with_no_response_is_missing_and_named_incomplete() -> None:
    """R-ON2: a transport failure leaves the member out and names the list field."""

    components = sbom_purls("log4j-demo-app.cdx.json")
    advisory = f"{osv.OSV_API}/v1/vulns/GHSA-jfh8-c2jp-5v3q"
    result = query_result(components, Recorded(drop=(advisory,)))
    assert result.incomplete_captures == [osv.RESPONSES]
    responses = result.output["responses"]
    assert len(responses) == 1 + 8
    _content, document = derive(responses, components)
    core = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert {"purl": core, "reason": "advisory_unreadable"} in document["not_checked"]
    # A dropped batch: its purls were never answered.
    batch = query_result(components, Recorded(drop=(f"{osv.OSV_API}/v1/querybatch",)))
    assert batch.incomplete_captures == [osv.RESPONSES] and batch.output["responses"] == []
    _content, document = derive([], components)
    assert document["queried"] == [] and {r["reason"] for r in document["not_checked"]} == {
        "not_asked"
    }


def _synthetic(n: int) -> tuple[list[str], Recorded]:
    """n components, each with one advisory naming one CVE, answered by a fake OSV."""

    purls = [f"pkg:pypi/pkg{i}@1.0" for i in range(n)]
    batch = {"results": [{"vulns": [{"id": f"GHSA-{i:04d}"}]} for i in range(n)]}
    overrides = {f"{osv.OSV_API}/v1/querybatch": (200, json.dumps(batch).encode())}
    for i in range(n):
        record = {
            "id": f"GHSA-{i:04d}",
            "aliases": [f"CVE-2026-{1000 + i}"],
            "affected": [
                {
                    "package": {"purl": f"pkg:pypi/pkg{i}"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
                }
            ],
        }
        overrides[f"{osv.OSV_API}/v1/vulns/GHSA-{i:04d}"] = (200, json.dumps(record).encode())
    return purls, Recorded(overrides=overrides)


@pytest.mark.parametrize("n", [10, 40])
def test_work_grows_linearly_with_components(n: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Work counts at two sizes: one request and one decode per member, one
    fixed-version scan per pair; constant per component."""

    purls, origin = _synthetic(n)
    responses = query(purls, origin)
    assert len(origin.requests) == 1 + n
    counts = {"decode": 0, "index": 0}
    real_input, real_index = osv.capture_input, osv.fixed_index

    def counted_input(view: Any) -> Any:
        counts["decode"] += 1
        return real_input(view)

    def counted_index(record: Any) -> Any:
        counts["index"] += 1
        return real_index(record)

    monkeypatch.setattr(osv, "capture_input", counted_input)
    monkeypatch.setattr(osv, "fixed_index", counted_index)
    _content, document = derive(responses, purls)
    assert len(document["affected"]) == n
    assert counts == {"decode": 1 + n, "index": n}


def _shared(n: int) -> tuple[list[str], Recorded]:
    """n components and ONE advisory affecting all n packages (with aliases)."""

    purls = [f"pkg:pypi/pkg{i}@1.0" for i in range(n)]
    batch = {"results": [{"vulns": [{"id": "GHSA-0000"}]} for _ in sorted(purls)]}
    record = {
        "id": "GHSA-0000",
        "aliases": ["CVE-2026-0001", "CVE-2026-0002"],
        "affected": [
            {
                "package": {"purl": f"pkg:pypi/pkg{i}"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
            }
            for i in range(n)
        ],
    }
    overrides = {
        f"{osv.OSV_API}/v1/querybatch": (200, json.dumps(batch).encode()),
        f"{osv.OSV_API}/v1/vulns/GHSA-0000": (200, json.dumps(record).encode()),
    }
    return purls, Recorded(overrides=overrides)


@pytest.mark.parametrize("n", [10, 40])
def test_one_shared_advisory_costs_linear_work(n: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """F4: one advisory affecting n packages is indexed once; package
    normalizations grow linearly (n entries + n components), never n x n."""

    purls, origin = _shared(n)
    responses = query(purls, origin)
    calls = {"base": 0, "index": 0}
    real_base, real_index = osv.package_base, osv.fixed_index

    def counted_base(purl: str) -> str:
        calls["base"] += 1
        return real_base(purl)

    def counted_index(record: Any) -> Any:
        calls["index"] += 1
        return real_index(record)

    monkeypatch.setattr(osv, "package_base", counted_base)
    monkeypatch.setattr(osv, "fixed_index", counted_index)
    _content, document = derive(responses, purls)
    assert len(document["affected"]) == 2 * n  # two CVE aliases per component
    assert {tuple(r["fixed"]) for r in document["affected"]} == {("1.1",)}
    assert calls == {"base": 2 * n, "index": 1}


def _one_package(n: int) -> tuple[list[str], Recorded]:
    """n versions of ONE package, one advisory listing n fixed events for it."""

    purls = [f"pkg:pypi/shared@0.{i}" for i in range(n)]
    batch = {"results": [{"vulns": [{"id": "GHSA-0001"}]} for _ in sorted(purls)]}
    record = {
        "id": "GHSA-0001",
        "aliases": ["CVE-2026-0003"],
        "affected": [
            {
                "package": {"purl": "pkg:pypi/shared"},
                "ranges": [
                    {"events": [{"introduced": "0"}, *({"fixed": f"1.{i:04d}"} for i in range(n))]}
                ],
            }
        ],
    }
    overrides = {
        f"{osv.OSV_API}/v1/querybatch": (200, json.dumps(batch).encode()),
        f"{osv.OSV_API}/v1/vulns/GHSA-0001": (200, json.dumps(record).encode()),
    }
    return purls, Recorded(overrides=overrides)


@pytest.mark.parametrize("n", [40, 160])
def test_many_versions_of_one_package_copy_bounded_fixes(
    n: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F4 r2: n component versions share a package whose advisory lists n > MAX_FIXED
    fixes. The index keeps MAX_FIXED per package, so each pair copies a bounded
    list: total copied entries are n x MAX_FIXED, never n x n."""

    purls, origin = _one_package(n)
    responses = query(purls, origin)
    sizes: list[int] = []
    real_index = osv.fixed_index

    def measured_index(record: Any) -> Any:
        index = real_index(record)
        sizes.extend(len(v) for v in index.values())
        return index

    monkeypatch.setattr(osv, "fixed_index", measured_index)
    _content, document = derive(responses, purls)
    assert sizes == [osv.MAX_FIXED]
    expected = tuple(sorted(f"1.{i:04d}" for i in range(n))[: osv.MAX_FIXED])
    assert len(document["affected"]) == n
    assert {tuple(r["fixed"]) for r in document["affected"]} == {expected}


@pytest.mark.parametrize("operation", [osv.QUERY, osv.MATCH, "sbom.components"])
def test_registration_names_each_operation_and_its_entrypoint(operation: str) -> None:
    import importlib

    root = HERE.parent / "src" / "security_osv_provider"
    registration = json.loads((root / "registration.json").read_text())
    (entry,) = [op for op in registration["operations"] if op["name"] == operation]
    module, _, name = entry["entrypoint"].partition(":")
    assert operation in getattr(importlib.import_module(module), name).operations
    assert entry["effect"] == ("external_read" if operation == osv.QUERY else "pure")
    carried = {(item["name"], item["version"]) for item in registration["declares"]["contracts"]}
    for contract in (entry["in"], entry["out"]):
        cname, _, version = contract.partition("@")
        assert (cname, int(version)) in carried
    assert entry["serves"] == [entry["in"].removesuffix(".request@1")]
    import hashlib

    manifest = (root / "manifest.yaml").read_bytes()
    assert registration["manifest"]["digest"] == "sha256:" + hashlib.sha256(manifest).hexdigest()


def test_the_registration_carries_exactly_what_the_kit_renders() -> None:
    """The carried Contracts and kinds are the kit's own (``build_registrations.py``)."""

    import sys

    pytest.importorskip("cruxible_core")
    sys.path.insert(0, str(HERE.parents[1]))
    import build_registrations

    assert build_registrations.write("security-osv-provider", check=True)
