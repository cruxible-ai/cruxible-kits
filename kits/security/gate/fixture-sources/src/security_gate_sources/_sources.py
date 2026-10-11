# Vendored from security-sources-provider by build_registration.py: do not edit.
"""The security kit's two network Sources: OSV.dev and FIRST's EPSS daily file.

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
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

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
