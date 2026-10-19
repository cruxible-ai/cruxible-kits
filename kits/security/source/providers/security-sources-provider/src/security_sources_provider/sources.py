"""The security kit's network Sources: OSV.dev, FIRST's EPSS daily file, GitHub and PyPI.

Each returns Core's shared acquisition wire (``external_capture_result``): the
exact exchanges it had with the origin, bodies base64 inside one canonical JSON
bundle, and mints no Capture itself -- the CaptureContract decides the grade.
Every request goes through one httpx client whose request hook records the
endpoint on the run's egress recorder; the endpoints are declared in the
manifest (``https://api.osv.dev``, ``https://epss.empiricalsecurity.com``).

``security.osv-query`` asks OSV, for every component purl@version of every
release in the request (rows of ``security.release_inventory``), which
advisories affect it (``POST /v1/querybatch``, up to 1000 queries a batch), then
fetches the full record of every advisory it found and of every watched CVE
(rows of ``security.watched_vulnerabilities``) and their aliases
(``GET /v1/vulns/{id}``). A 404 is retained as an exchange like any other: OSV
not knowing an id is an answer.

``security.epss-daily`` fetches the current EPSS daily scores file (gzip CSV,
following the redirect to the dated file) and retains its exact bytes.

``security.repo-snapshot`` reads what one GitHub repository declares at one ref
for one scope (``ci.workflows``: every workflow file under a directory;
``release.manifest``: one file). It resolves the revision R (the latest commit
reachable from the ref that touched the path, ``GET /repos/{repo}/commits``),
lists the path at R (``GET /repos/{repo}/contents/{path}?ref=R``) and reads each
file at R from ``raw.githubusercontent.com``, checking every file against the
git blob id the listing names. The bundle is canonical JSON of (locator, R,
files): the same R yields the same bytes, so a re-pull of an unchanged source
is a re-observation. No credential is sent.

``security.pypi-release`` reads what PyPI serves for one project: the project
JSON (``GET /pypi/{project}/json``) and, for each file of the newest N
versions, its provenance (``GET /integrity/{project}/{version}/{file}/provenance``;
a 404 is retained as an answer). The bundle keeps each file's name, digest,
size, upload time and provenance, not the volatile counters around them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from cruxible_provider_runtime.acquisition import external_capture_result
from cruxible_provider_runtime.canonical import canonical_json
from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

OSV_API = "https://api.osv.dev"
OSV_SOURCE = "osv.dev.query"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_SOURCE = "first.epss.daily"
USER_AGENT = "security-sources-provider/1.0 (cruxible security kit)"
BATCH = 1000
MAX_EPSS_BYTES = 16_777_216
MAX_RECORDS = 5000
WATCH_LIMIT = 1000
GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
REPO_SOURCE = "github.repo.snapshot"
PYPI = "https://pypi.org"
PYPI_SOURCE = "pypi.release"
#: scope -> what a path names: a directory of workflow files, or one manifest file.
SCOPES = ("ci.workflows", "release.manifest")
WORKFLOW_SUFFIXES = (".yml", ".yaml")
MAX_REPO_FILES = 200
MAX_FILE_BYTES = 1_048_576
MAX_SNAPSHOT_BYTES = 16_777_216
MAX_VERSIONS = 10
_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REF = re.compile(r"^[A-Za-z0-9_./-]{1,255}$")
_PROJECT = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

#: Builds the client a run uses. Tests and the release gate pass a transport.
TransportFactory = Callable[[], httpx.BaseTransport | None]


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _client(
    recorder: EgressRecorder,
    *,
    base_url: str,
    timeout: float,
    transport: httpx.BaseTransport | None,
) -> httpx.Client:
    def record(request: httpx.Request) -> None:
        recorder.record(str(request.url))

    return httpx.Client(
        base_url=base_url,
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
        headers={"user-agent": USER_AGENT},
        event_hooks={"request": [record]},
    )


def _rows_values(rows: object, name: str) -> list[Any]:
    values: list[Any] = []
    if not isinstance(rows, list):
        return values
    for row in rows:
        for field in (row.get("fields") or ()) if isinstance(row, Mapping) else ():
            if field.get("name") == name and field.get("state") == "present":
                values.append(field.get("value"))
    return values


def osv_request(payload: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """(component purls with a version, watched CVE ids), sorted and unique."""

    purls: set[str] = set()
    for value in _rows_values(payload.get("releases"), "components"):
        for purl in value if isinstance(value, list) else [value]:
            if isinstance(purl, str) and purl.startswith("pkg:") and "@" in purl.split("/", 1)[-1]:
                purls.add(purl.strip())
    cves = {
        value.strip().upper()
        for value in _rows_values(payload.get("watched"), "cve_id")
        if isinstance(value, str) and value.strip()
    }
    return sorted(purls), sorted(cves)


def classify_osv(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not isinstance(payload.get("releases"), list) or not isinstance(
        payload.get("watched"), list
    ):
        return None
    purls, cves = osv_request(payload)
    return {
        "components": "none" if not purls else "small" if len(purls) <= BATCH else "large",
        "watchlist": "small" if len(cves) <= WATCH_LIMIT else "large",
    }


def classify_epss(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    url = payload.get("url", EPSS_URL)
    if not isinstance(url, str) or not url.startswith("https://"):
        return None
    return {"file": "daily"}


@dataclass(frozen=True)
class _Exchange:
    method: str
    path: str
    request: Any
    status: int
    body: bytes

    def wire(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "request": self.request,
            "status": self.status,
            "body_sha256": _sha256(self.body),
            "body_base64": base64.b64encode(self.body).decode("ascii"),
        }


def _json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


class OsvQuery:
    """The ``security.osv-query`` implementation (external read, Source)."""

    interface_id = "security.osv-query"

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (lambda: None)
        self._source = "network" if transport_factory is None else "packaged-recording"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        purls, cves = osv_request(context.input)
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.4)
        exchanges: list[_Exchange] = []
        try:
            with _client(
                context.egress,
                base_url=OSV_API,
                timeout=timeout,
                transport=self._transport_factory(),
            ) as client:
                found: set[str] = set()
                for start in range(0, len(purls), BATCH):
                    chunk = purls[start : start + BATCH]
                    body = {"queries": [{"package": {"purl": purl}} for purl in chunk]}
                    response = client.post("/v1/querybatch", json=body)
                    exchanges.append(
                        _Exchange(
                            "POST",
                            "/v1/querybatch",
                            {"purls": chunk},
                            response.status_code,
                            response.content,
                        )
                    )
                    if response.status_code != 200:
                        return ProviderResult.failed(
                            "HttpStatus", f"OSV querybatch answered {response.status_code}"
                        )
                    for result in (_json(response.content) or {}).get("results") or ():
                        for vuln in (result or {}).get("vulns") or ():
                            if isinstance(vuln, Mapping) and vuln.get("id"):
                                found.add(str(vuln["id"]))
                fetched: dict[str, Any] = {}
                wanted = sorted(found | set(cves))
                while wanted:
                    if len(fetched) + len(wanted) > MAX_RECORDS:
                        return ProviderResult.refused(
                            RefusalCode.PROVIDER_DECLINED,
                            f"more than {MAX_RECORDS} OSV records would be fetched",
                        )
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        answers = list(
                            pool.map(lambda item: (item, client.get(f"/v1/vulns/{item}")), wanted)
                        )
                    follow: set[str] = set()
                    for item, response in answers:
                        exchanges.append(
                            _Exchange(
                                "GET",
                                f"/v1/vulns/{item}",
                                None,
                                response.status_code,
                                response.content,
                            )
                        )
                        record = _json(response.content) if response.status_code == 200 else None
                        fetched[item] = record
                        if item in cves and isinstance(record, Mapping):
                            follow.update(str(alias) for alias in record.get("aliases") or ())
                    wanted = sorted(follow - set(fetched))
        except httpx.HTTPError as error:
            return ProviderResult.failed("HttpError", f"{type(error).__name__}: {error}")
        material = {
            "input_bucket": context.input_bucket,
            "service": OSV_API,
            "source": self._source,
            "exchanges": [exchange.wire() for exchange in exchanges],
        }
        return ProviderResult.ok(
            external_capture_result(
                canonical_json(material),
                source_identity=OSV_SOURCE,
                coordinate_type="http-response-v1",
                selector_type="whole-response-v1",
                coordinate={
                    "request_digest": _sha256(canonical_json({"purls": purls, "cves": cves})),
                    "exchanges": len(exchanges),
                    "source": self._source,
                },
                observed_at=datetime.now(UTC),
            ),
            metrics={"exchanges": float(len(exchanges)), "purls": float(len(purls))},
        )


class EpssDaily:
    """The ``security.epss-daily`` implementation (external read, Source)."""

    interface_id = "security.epss-daily"

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (lambda: None)
        self._source = "network" if transport_factory is None else "packaged-recording"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        url = str(context.input.get("url") or EPSS_URL)
        if not url.startswith("https://epss.empiricalsecurity.com/"):
            return ProviderResult.refused(
                RefusalCode.PROVIDER_DECLINED,
                "the EPSS file is read from epss.empiricalsecurity.com",
            )
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.8)
        try:
            with _client(
                context.egress,
                base_url="https://epss.empiricalsecurity.com",
                timeout=timeout,
                transport=self._transport_factory(),
            ) as client:
                final = url
                response = client.get(url)
                for _ in range(3):
                    if response.status_code not in {301, 302, 303, 307, 308}:
                        break
                    final = str(httpx.URL(final).join(response.headers.get("location", "")))
                    if not final.startswith("https://epss.empiricalsecurity.com/"):
                        return ProviderResult.refused(
                            RefusalCode.PROVIDER_DECLINED, "the EPSS redirect left the origin"
                        )
                    response = client.get(final)
        except httpx.HTTPError as error:
            return ProviderResult.failed("HttpError", f"{type(error).__name__}: {error}")
        if response.status_code != 200:
            return ProviderResult.failed("HttpStatus", f"EPSS answered {response.status_code}")
        body = response.content
        if len(body) > MAX_EPSS_BYTES:
            return ProviderResult.refused(
                RefusalCode.PROVIDER_DECLINED, "the EPSS file is too large"
            )
        source = self._source
        material = {
            "input_bucket": context.input_bucket,
            "retrieved": {
                "url": url,
                "final_url": final,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "byte_count": len(body),
                "body_sha256": _sha256(body),
                "body_base64": base64.b64encode(body).decode("ascii"),
                "source": source,
            },
        }
        return ProviderResult.ok(
            external_capture_result(
                canonical_json(material),
                source_identity=EPSS_SOURCE,
                coordinate_type="http-response-v1",
                selector_type="whole-response-v1",
                coordinate={
                    "request_digest": _sha256(url.encode()),
                    "status": response.status_code,
                    "body_sha256": _sha256(body),
                    "source": source,
                },
                observed_at=datetime.now(UTC),
            ),
            metrics={"byte_count": float(len(body))},
        )


class SourceInputError(ValueError):
    """The request does not name a source this interface reads."""


def repo_request(payload: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    """(forge_host, full_name, ref, scope, path), checked and in canonical form.

    Host and repository name are lowercased (GitHub names are case-insensitive);
    the ref and path are kept as given (both are case-sensitive). A ``ci.workflows``
    path names a directory and ends in ``/``; a ``release.manifest`` path names a file.
    """

    host = str(payload.get("forge_host") or "").strip().lower()
    name = str(payload.get("full_name") or "").strip().lower()
    ref = str(payload.get("ref") or "").strip()
    scope = str(payload.get("scope") or "").strip()
    path = str(payload.get("path") or "").strip()
    if host != "github.com":
        raise SourceInputError("only github.com repositories are read")
    if not _NAME.fullmatch(name):
        raise SourceInputError("full_name must be owner/repository")
    if not _REF.fullmatch(ref) or ".." in ref:
        raise SourceInputError("ref must be a branch, tag or commit SHA")
    if scope not in SCOPES:
        raise SourceInputError(f"scope must be one of {', '.join(SCOPES)}")
    if not path or path.startswith("/") or ".." in path.split("/"):
        raise SourceInputError("path must be relative to the repository root")
    if (scope == "ci.workflows") != path.endswith("/"):
        raise SourceInputError("a ci.workflows path is a directory (ends in /); a manifest is a file")
    return host, name, ref, scope, path


def repo_locator(host: str, name: str, ref: str, path: str) -> str:
    """The coverage source a snapshot answers for: ``host/owner/repo@ref:path``."""

    return f"{host}/{name}@{ref}:{path}"


def classify_repo(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    try:
        _host, _name, _ref, scope, _path = repo_request(payload)
    except SourceInputError:
        return None
    return {"scope": scope}


def git_blob_id(data: bytes) -> str:
    """The git blob id GitHub lists for a file's bytes."""

    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _segments(path: str) -> str:
    return "/".join(quote(part, safe="") for part in path.split("/") if part)


class RepoSnapshot:
    """The ``security.repo-snapshot`` implementation (external read, Source)."""

    interface_id = "security.repo-snapshot"

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (lambda: None)
        self._source = "network" if transport_factory is None else "packaged-recording"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            host, name, ref, scope, path = repo_request(context.input)
        except SourceInputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.4)
        bare = path.rstrip("/")
        files: list[dict[str, Any]] = []
        total = 0
        try:
            transport = self._transport_factory()
            with (
                _client(context.egress, base_url=GITHUB_API, timeout=timeout,
                        transport=transport) as api,
                _client(context.egress, base_url=GITHUB_RAW, timeout=timeout,
                        transport=transport) as raw,
            ):
                response = api.get(f"/repos/{name}/commits",
                                   params={"sha": ref, "path": bare, "per_page": 1})
                if response.status_code != 200:
                    return ProviderResult.failed(
                        "HttpStatus", f"GitHub commits answered {response.status_code}")
                commits = _json(response.content)
                if not isinstance(commits, list):
                    return ProviderResult.failed("BadResponse", "GitHub commits is not a list")
                listing: list[Mapping[str, Any]] = []
                if commits:
                    revision = str(commits[0].get("sha") or "")
                    response = api.get(f"/repos/{name}/contents/{_segments(bare)}",
                                       params={"ref": revision})
                    if response.status_code == 200:
                        body = _json(response.content)
                        entries = body if isinstance(body, list) else [body]
                        listing = [e for e in entries if isinstance(e, Mapping)
                                   and e.get("type") == "file"]
                    elif response.status_code != 404:
                        return ProviderResult.failed(
                            "HttpStatus", f"GitHub contents answered {response.status_code}")
                else:
                    # The path never existed at the ref: the answer is "nothing there",
                    # at the ref's own head.
                    response = api.get(f"/repos/{name}/commits/{quote(ref, safe='')}")
                    if response.status_code != 200:
                        return ProviderResult.failed(
                            "HttpStatus", f"GitHub commit answered {response.status_code}")
                    revision = str((_json(response.content) or {}).get("sha") or "")
                if not re.fullmatch(r"[0-9a-f]{40}", revision):
                    return ProviderResult.failed("BadResponse", "no commit SHA for the ref")
                if scope == "ci.workflows":
                    listing = [e for e in listing
                               if str(e.get("name", "")).endswith(WORKFLOW_SUFFIXES)]
                if len(listing) > MAX_REPO_FILES:
                    return ProviderResult.refused(
                        RefusalCode.PROVIDER_DECLINED, f"more than {MAX_REPO_FILES} files")
                for entry in sorted(listing, key=lambda e: str(e.get("path"))):
                    file_path = str(entry.get("path"))
                    response = raw.get(f"/{name}/{revision}/{_segments(file_path)}")
                    if response.status_code != 200:
                        return ProviderResult.failed(
                            "HttpStatus", f"raw {file_path} answered {response.status_code}")
                    data = response.content
                    if len(data) > MAX_FILE_BYTES:
                        return ProviderResult.refused(
                            RefusalCode.PROVIDER_DECLINED, f"{file_path} is too large")
                    total += len(data)
                    if total > MAX_SNAPSHOT_BYTES:
                        return ProviderResult.refused(
                            RefusalCode.PROVIDER_DECLINED, "the snapshot is too large")
                    if entry.get("sha") and git_blob_id(data) != entry.get("sha"):
                        return ProviderResult.failed(
                            "BadResponse", f"{file_path} does not match its listed blob")
                    files.append({
                        "path": file_path,
                        "git_blob": git_blob_id(data),
                        "sha256": _sha256(data),
                        "size": len(data),
                        "content_base64": base64.b64encode(data).decode("ascii"),
                    })
        except httpx.HTTPError as error:
            return ProviderResult.failed("HttpError", f"{type(error).__name__}: {error}")
        locator = repo_locator(host, name, ref, path)
        material = {
            "input_bucket": context.input_bucket,
            "source": self._source,
            "forge_host": host,
            "full_name": name,
            "ref": ref,
            "scope": scope,
            "path": path,
            "locator": locator,
            "revision": revision,
            "files": files,
        }
        return ProviderResult.ok(
            external_capture_result(
                canonical_json(material),
                source_identity=REPO_SOURCE,
                coordinate_type="http-response-v1",
                selector_type="whole-response-v1",
                coordinate={
                    "request_digest": _sha256(locator.encode()),
                    "revision": revision,
                    "source": self._source,
                },
                observed_at=datetime.now(UTC),
            ),
            metrics={"files": float(len(files)), "bytes": float(total)},
        )


def normalize_project(value: object) -> str:
    """A PyPI project name in PEP 503 normal form."""

    return re.sub(r"[-_.]+", "-", str(value or "").strip()).lower()


def pypi_request(payload: Mapping[str, Any]) -> tuple[str, int]:
    project = str(payload.get("project") or "").strip()
    versions = payload.get("versions", 3)
    if not _PROJECT.fullmatch(project):
        raise SourceInputError("project must be a PyPI project name")
    if not isinstance(versions, int) or isinstance(versions, bool) or not (
        1 <= versions <= MAX_VERSIONS
    ):
        raise SourceInputError(f"versions must be between 1 and {MAX_VERSIONS}")
    return normalize_project(project), versions


def classify_pypi(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    try:
        _project, versions = pypi_request(payload)
    except SourceInputError:
        return None
    return {"versions": "few" if versions <= 3 else "many"}


def _newest(releases: Mapping[str, Any], count: int) -> list[tuple[str, list[Mapping[str, Any]]]]:
    """The ``count`` newest versions that have files, by their latest upload time."""

    dated = []
    for version, files in releases.items():
        kept = [f for f in files or () if isinstance(f, Mapping) and f.get("filename")]
        if kept:
            latest = max(str(f.get("upload_time_iso_8601") or "") for f in kept)
            dated.append((latest, str(version), kept))
    dated.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [(version, files) for _latest, version, files in dated[:count]]


class PypiRelease:
    """The ``security.pypi-release`` implementation (external read, Source)."""

    interface_id = "security.pypi-release"

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (lambda: None)
        self._source = "network" if transport_factory is None else "packaged-recording"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            project, count = pypi_request(context.input)
        except SourceInputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.4)
        versions: list[dict[str, Any]] = []
        try:
            with _client(context.egress, base_url=PYPI, timeout=timeout,
                         transport=self._transport_factory()) as client:
                response = client.get(f"/pypi/{project}/json")
                if response.status_code != 200:
                    return ProviderResult.failed(
                        "HttpStatus", f"PyPI project JSON answered {response.status_code}")
                body = _json(response.content)
                if not isinstance(body, Mapping) or not isinstance(body.get("releases"), Mapping):
                    return ProviderResult.failed("BadResponse", "not a PyPI project JSON")
                for version, files in _newest(body["releases"], count):
                    held = []
                    for item in sorted(files, key=lambda f: str(f["filename"])):
                        filename = str(item["filename"])
                        answer = client.get(
                            f"/integrity/{project}/{quote(version, safe='')}/"
                            f"{quote(filename, safe='')}/provenance")
                        if answer.status_code not in {200, 404}:
                            return ProviderResult.failed(
                                "HttpStatus", f"PyPI provenance answered {answer.status_code}")
                        digests = item.get("digests") or {}
                        held.append({
                            "filename": filename,
                            "packagetype": str(item.get("packagetype") or ""),
                            "sha256": str(digests.get("sha256") or ""),
                            "size": int(item.get("size") or 0),
                            "upload_time": str(item.get("upload_time_iso_8601") or ""),
                            "yanked": bool(item.get("yanked")),
                            "provenance_status": answer.status_code,
                            "provenance": _json(answer.content)
                            if answer.status_code == 200 else None,
                        })
                    versions.append({"version": version, "files": held})
        except httpx.HTTPError as error:
            return ProviderResult.failed("HttpError", f"{type(error).__name__}: {error}")
        material = {
            "input_bucket": context.input_bucket,
            "source": self._source,
            "project": project,
            "versions": versions,
        }
        return ProviderResult.ok(
            external_capture_result(
                canonical_json(material),
                source_identity=PYPI_SOURCE,
                coordinate_type="http-response-v1",
                selector_type="whole-response-v1",
                coordinate={
                    "request_digest": _sha256(f"{project}:{count}".encode()),
                    "versions": [item["version"] for item in versions],
                    "source": self._source,
                },
                observed_at=datetime.now(UTC),
            ),
            metrics={"versions": float(len(versions))},
        )


def static_transport(
    routes: Mapping[tuple[str, str], tuple[int, bytes, Mapping[str, str]]],
    batch: Callable[[Sequence[str]], bytes] | None = None,
) -> httpx.MockTransport:
    """A fixed transport for tests and the release gate: (method, path) -> (status, body, headers).

    ``batch`` answers ``POST /v1/querybatch`` from the requested purls.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/querybatch" and batch is not None:
            purls = [q["package"]["purl"] for q in json.loads(request.content)["queries"]]
            return httpx.Response(200, content=batch(purls), request=request)
        status, body, headers = routes.get(
            (request.method, request.url.path), (404, b'{"code":5,"message":"Bug not found."}', {})
        )
        return httpx.Response(status, content=body, headers=dict(headers), request=request)

    return httpx.MockTransport(handler)
