"""The kit's Sources over vendored responses: the kit's adapters, a fixed transport.

``_sources.py`` is security-sources-provider's ``sources.py``, copied byte for byte
by ``build_registration.py``; only the transport differs. OSV answers the gate
SBOM's purls from ``responses/osv/querybatch.json`` and serves the records in
``responses/osv/vulns/`` (404 for anything else) and its ecosystem list from
``responses/osv/ecosystems.txt`` (OSV's names; no Homebrew, no generic); EPSS serves
``responses/epss_scores.csv.gz``. ``security.repo-snapshot`` answers GitHub's
commits, contents and raw-file requests from ``responses/github/`` (recorded by
``record_system_model.py``), and ``security.pypi-release`` PyPI's project JSON and
provenance from ``responses/pypi/``, and ``security.release-asset`` the recorded
asset of ``responses/github/assets/`` ALTERED: its bytes plus ``ALTERED_SUFFIX``.
That is the gate's injected mismatch: what the release serves no longer matches
the digest the manifest declares. Every Capture says ``packaged-recording``.

A recorded ref can name several heads (``refs.json``: ``main`` before and after the
runtime-image workflow landed). It names the first, unless a
``security-gate-fixture.json`` beside the gate's state root (found by walking up
from this installed package) says ``{"heads": {"owner/repo": {"ref": index}}}``:
that is how the gate moves ``main`` without touching the daemon.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from ._sources import (
    EpssDaily,
    OsvEcosystems,
    OsvQuery,
    PypiRelease,
    ReleaseAsset,
    RepoSnapshot,
    static_transport,
)

RESPONSES = Path(__file__).resolve().parent / "responses"
MARKER = "security-gate-fixture.json"
ALTERED_SUFFIX = b"\nreplaced after release\n"


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


def _ecosystems_transport() -> httpx.BaseTransport:
    body = (RESPONSES / "osv" / "ecosystems.txt").read_bytes()
    return static_transport({("GET", "/ecosystems.txt"): (200, body,
                                                          {"content-type": "text/plain"})})


class GateOsvEcosystems(OsvEcosystems):
    """``security.osv-ecosystems`` serving the gate's vendored ecosystem list."""

    def __init__(self) -> None:
        super().__init__(_ecosystems_transport)


class GateEpssDaily(EpssDaily):
    """``security.epss-daily`` serving the gate's vendored EPSS file."""

    def __init__(self) -> None:
        super().__init__(_epss_transport)


def _moved(repo: str) -> dict[str, int]:
    for parent in Path(__file__).resolve().parents:
        marker = parent / MARKER
        if marker.is_file():
            heads = json.loads(marker.read_text()).get("heads") or {}
            return {str(k): int(v) for k, v in (heads.get(repo) or {}).items()}
    return {}


def _github_transport() -> httpx.BaseTransport:
    github = RESPONSES / "github"
    refs = json.loads((github / "refs.json").read_text())
    recorded = json.loads((github / "repo.json").read_text())
    known = {head for heads in refs.values() for value in heads.values()
             for head in (value if isinstance(value, list) else [value])}

    def head(repo: str, ref: str) -> str | None:
        value = (refs.get(repo) or {}).get(ref)
        if isinstance(value, list):
            return value[min(_moved(repo).get(ref, 0), len(value) - 1)]
        if isinstance(value, str):
            return value
        return ref if ref in known else None

    def answer(status: int, body: object) -> tuple[int, bytes]:
        return status, json.dumps(body).encode()

    def route(request: httpx.Request) -> tuple[int, bytes]:
        path = request.url.path
        params = dict(request.url.params)
        if request.url.host == "raw.githubusercontent.com":
            owner, repo, revision, rest = path.lstrip("/").split("/", 3)
            file = github / "raw" / revision / rest
            return (200, file.read_bytes()) if file.is_file() else (404, b"404: Not Found")
        parts = path.strip("/").split("/")
        if len(parts) < 4 or parts[0] != "repos":
            return answer(404, {"message": "Not Found"})
        repo = f"{parts[1]}/{parts[2]}"
        if parts[3] == "commits" and len(parts) == 4:
            resolved = head(repo, params.get("sha", ""))
            found = recorded["commits"].get(f"{resolved}|{params.get('path', '')}")
            return answer(200, found) if found is not None else answer(200, [])
        if parts[3] == "commits" and len(parts) == 5:
            resolved = head(repo, parts[4])
            return answer(200, {"sha": resolved}) if resolved else answer(
                404, {"message": "No commit found"})
        if parts[3] == "contents":
            found = recorded["contents"].get(f"{params.get('ref')}|{'/'.join(parts[4:])}")
            return answer(200, found) if found is not None else answer(
                404, {"message": "Not Found"})
        return answer(404, {"message": "Not Found"})

    def handler(request: httpx.Request) -> httpx.Response:
        status, body = route(request)
        return httpx.Response(status, content=body, request=request)

    return httpx.MockTransport(handler)


def _pypi_transport() -> httpx.BaseTransport:
    pypi = RESPONSES / "pypi"

    def handler(request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        file = None
        if len(parts) == 3 and parts[0] == "pypi" and parts[2] == "json":
            file = pypi / f"{parts[1]}.json"
        elif len(parts) == 5 and parts[0] == "integrity" and parts[4] == "provenance":
            file = pypi / "provenance" / f"{parts[3]}.json"
        if file is None or not file.is_file():
            return httpx.Response(404, content=b'{"message": "Not Found"}', request=request)
        return httpx.Response(200, content=file.read_bytes(), request=request)

    return httpx.MockTransport(handler)


class GateRepoSnapshot(RepoSnapshot):
    """``security.repo-snapshot`` answering from the gate's recorded GitHub responses."""

    def __init__(self) -> None:
        super().__init__(_github_transport)


class GatePypiRelease(PypiRelease):
    """``security.pypi-release`` answering from the gate's recorded PyPI responses."""

    def __init__(self) -> None:
        super().__init__(_pypi_transport)


def _asset_transport() -> httpx.BaseTransport:
    assets = RESPONSES / "github" / "assets"

    def handler(request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        file = assets / parts[-1] if len(parts) == 6 and parts[2:4] == [
            "releases", "download"] else None
        if file is None or not file.is_file():
            return httpx.Response(404, content=b"Not Found", request=request)
        return httpx.Response(200, headers={"content-type": "application/octet-stream"},
                              content=file.read_bytes() + ALTERED_SUFFIX, request=request)

    return httpx.MockTransport(handler)


class GateReleaseAsset(ReleaseAsset):
    """``security.release-asset`` serving the gate's recorded asset, altered."""

    def __init__(self) -> None:
        super().__init__(_asset_transport)
