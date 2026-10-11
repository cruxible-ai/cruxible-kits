"""security.osv-query and security.epss-daily over vendored responses: the kit's adapters, fixed transport.

``_sources.py`` is security-sources-provider's ``sources.py``, copied byte for byte
by ``build_registration.py``; only the transport differs. OSV answers the gate
SBOM's purls from ``responses/osv/querybatch.json`` and serves the records in
``responses/osv/vulns/`` (404 for anything else); EPSS serves
``responses/epss_scores.csv.gz``. Every Capture says ``packaged-recording``.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from ._sources import EpssDaily, OsvQuery, static_transport

RESPONSES = Path(__file__).resolve().parent / "responses"


def _osv_transport() -> httpx.BaseTransport:
    answers = json.loads((RESPONSES / "osv" / "querybatch.json").read_text())
    routes = {
        ("GET", f"/v1/vulns/{path.stem}"): (200, path.read_bytes(), {})
        for path in sorted((RESPONSES / "osv" / "vulns").glob("*.json"))
    }

    def batch(purls: list[str]) -> bytes:
        return json.dumps({"results": [answers.get(purl, {}) for purl in purls]}).encode()

    return static_transport(routes, batch)


def _epss_transport() -> httpx.BaseTransport:
    body = (RESPONSES / "epss_scores.csv.gz").read_bytes()
    routes = {
        ("GET", "/epss_scores-current.csv.gz"): (200, body, {"content-type": "application/gzip"})
    }
    return static_transport(routes)


class GateOsvQuery(OsvQuery):
    """``security.osv-query`` answering from the gate's vendored OSV responses."""

    def __init__(self) -> None:
        super().__init__(_osv_transport)


class GateEpssDaily(EpssDaily):
    """``security.epss-daily`` serving the gate's vendored EPSS file."""

    def __init__(self) -> None:
        super().__init__(_epss_transport)
