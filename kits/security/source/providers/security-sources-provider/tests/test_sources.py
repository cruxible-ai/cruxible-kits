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
from security_sources_provider.sources import EpssDaily, OsvQuery, static_transport


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


def test_the_registration_verifies() -> None:
    load_registration(Path(security_sources_provider.__file__).parent)
