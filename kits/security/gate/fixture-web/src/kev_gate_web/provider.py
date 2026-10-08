"""web.fetch over vendored responses: the real adapter, a fixed transport.

The gate needs a KEV catalog Capture without contacting cisa.gov. This reuses
cruxible-provider-web's ``WebFetch`` unchanged (request validation, byte cap,
material shape, Capture result) and swaps only the client factory: the KEV feed
URL and one CVE record URL are answered from ``responses/``; anything else is a
404. Every run is labelled ``packaged-recording``, never ``network``.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_web.fetch import WebFetch
from cruxible_provider_web.http import RecordingClient

RESPONSES = Path(__file__).resolve().parent / "responses"
ROUTES = {
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json": (
        "known_exploited_vulnerabilities.json"
    ),
    "https://cveawg.mitre.org/api/cve/CVE-2021-44228": "CVE-2021-44228.json",
}


def gate_client_factory(
    recorder: EgressRecorder, *, url: str, timeout_seconds: float
) -> RecordingClient:
    name = ROUTES.get(url)

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
        recording_id=f"kev-gate:{name or 'missing'}",
    )


class GateWebFetch(WebFetch):
    """``web.fetch`` answering the gate's two URLs from vendored bytes."""

    def __init__(self) -> None:
        super().__init__(client_factory=gate_client_factory)
