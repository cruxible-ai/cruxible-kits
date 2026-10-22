"""web.fetch over vendored responses: the real adapter, a fixed transport.

The gate needs KEV catalog, CVE record and GitHub Captures without contacting
cisa.gov, cveawg.mitre.org or GitHub. This reuses cruxible-provider-web's
``WebFetch`` unchanged (request validation, byte cap, material shape, Capture
result) and swaps only the client factory: the KEV feed URL, the CVE record URLs
of ``responses/cve/`` and the recorded GitHub release, runs and commits answers
(``responses/github/api/``, and gate-app's release, built in that shape) are
answered from ``responses/``; anything else is a
404. Every run is labelled ``packaged-recording``, never ``network``.

The KEV feed URL answers the vendored catalog, unless a ``security-gate-fixture.json``
beside the gate's state root (found by walking up from this installed package) says
``{"kev": "<file under responses/>"}``: that is how the gate lists a new KEV entry (the
incident's) without touching the daemon.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_web.fetch import WebFetch
from cruxible_provider_web.http import RecordingClient

RESPONSES = Path(__file__).resolve().parent / "responses"
MARKER = "security-gate-fixture.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _kev() -> str:
    for parent in Path(__file__).resolve().parents:
        marker = parent / MARKER
        if marker.is_file():
            return str(json.loads(marker.read_text()).get("kev") or
                       "known_exploited_vulnerabilities.json")
    return "known_exploited_vulnerabilities.json"
GITHUB = "https://api.github.com/repos/cruxible-ai/cruxible"
ROUTES = {
    f"{GITHUB}/releases/tags/v0.3.2": "github/api/release-v0.3.2.json",
    f"{GITHUB}/actions/workflows/publish.yml/runs?branch=v0.3.2&per_page=5": (
        "github/api/runs-publish-v0.3.2.json"),
    f"{GITHUB}/commits?path=scripts/build_kit_bundles.py&sha=v0.3.2&per_page=5": (
        "github/api/commits-build_kit_bundles-v0.3.2.json"),
    # gate-app's release (the code findings' HQ6): hand-built in the API's shape.
    "https://api.github.com/repos/cruxible-ai/gate-app/releases/tags/v1.0.0": (
        "github/api/gate-app-release-v1.0.0.json"),

    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json": (
        "known_exploited_vulnerabilities.json"
    ),
    **{
        f"https://cveawg.mitre.org/api/cve/{path.stem}": f"cve/{path.name}"
        for path in sorted((RESPONSES / "cve").glob("*.json"))
    },
}


def gate_client_factory(
    recorder: EgressRecorder, *, url: str, timeout_seconds: float
) -> RecordingClient:
    name = _kev() if url == KEV_URL else ROUTES.get(url)

    def handler(request: httpx.Request) -> httpx.Response:
        if name is None:
            return httpx.Response(404, content=b"not a gate fixture", request=request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=(RESPONSES / name).read_bytes(),
            request=request,
        )

    return RecordingClient(
        recorder,
        timeout_seconds=timeout_seconds,
        transport=httpx.MockTransport(handler),
        recording_id=f"security-gate:{name or 'missing'}",
    )


class GateWebFetch(WebFetch):
    """``web.fetch`` answering the gate's KEV and CVE record URLs from vendored bytes."""

    def __init__(self) -> None:
        super().__init__(client_factory=gate_client_factory)
