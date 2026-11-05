"""OSV.dev for the security kit, in the Procedure template's fetch + derive form (D-R37).

``osv.query`` (fetch, ``external_read``) asks OSV which advisories affect each
component purl@version it is given: ``POST /v1/querybatch`` (at most
``BATCH`` components a request), then ``GET /v1/vulns/{id}`` for every advisory
a batch names (OSV's batch answer carries ids only; the record carries the CVE
aliases). It returns every response VERBATIM, one member of the output's
Capture list each; how a response was obtained (method, URL, status, content
type, the request's digest and the purls a batch asked about) is the member's
coordinate, never inside the bytes (D-R25/D-R26). Version matching is OSV's
own (K-B1-3): the kit has no version-range code.

``osv.match`` (derive, ``pure``) reads those responses (their bytes, passed by
core) and the components the run asked about, and emits ONE derived JSON
document::

    {"queried":      [purl, ...],       # components OSV answered in full
     "not_checked":  [{"purl", "reason"}],
     "affected":     [{"purl", "cve_id", "osv_id"}],
     "unkeyed":      [{"purl", "osv_id"}]}   # advisories with no CVE alias

Distro coverage (K-B1-6): OSV's distro ecosystems (Debian, Ubuntu, Alpine, the
RPM distributions) are keyed by SOURCE package name, while an SBOM lists binary
packages (``pkg:deb/debian/libc6`` is ``glibc`` to OSV). v1 cannot map binary to
source names, so every distro component (purl type ``deb``, ``rpm`` or ``apk``)
is left out of the query and out of ``queried``: it reads "not checked", never
clean, and absence never retires its Claims. A component whose answer is
incomplete -- its batch failed or truncated (``next_page_token``), or an
advisory it names could not be read -- is also left out of ``queried``
("unanswered"). Post-v1: map binary to source packages from SBOM source-name
metadata (syft ``sourceName``) or a distro name table.

PREPARED, NOT WIRED: the output list of Captures (lane A, a1-a8) and the derive
input/derived Capture (lane B, b1-b8, c1-c6) are being added to core. The wire
shapes below follow those decisions; the TODO(core lane A/B) markers name what
changes when they land.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import httpx
from cruxible_provider_runtime.acquisition import external_capture_result
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

OSV_API = "https://api.osv.dev"
QUERY = "osv.query"
MATCH = "osv.match"
BATCH = 1000
#: The most advisory records one run reads (each is one Capture).
MAX_RECORDS = 1000
#: Purl types whose OSV ecosystem is keyed by source package name (K-B1-6).
DISTRO_TYPES = frozenset({"deb", "rpm", "apk"})
COORDINATE_TYPE = "osv-exchange-v1"
SELECTOR_TYPE = "whole-response-v1"
PROVIDER_DECLINED = "provider_declined"
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
USER_AGENT = "security-osv-provider/0.1 (cruxible security kit)"

TransportFactory = Callable[[], httpx.BaseTransport | None]


def purl_type(purl: str) -> str:
    return purl[4:].split("/", 1)[0].lower() if purl.startswith("pkg:") else ""


def partition(components: Iterable[str]) -> tuple[list[str], list[dict[str, str]]]:
    """(the purls osv.query asks about, the ones it leaves "not checked" and why)."""

    asked: list[str] = []
    skipped: list[dict[str, str]] = []
    for purl in sorted(set(components)):
        kind = purl_type(purl)
        if kind in DISTRO_TYPES:
            skipped.append({"purl": purl, "reason": "distro_source_name_unknown"})
        elif "@" not in purl.rsplit("/", 1)[-1]:
            skipped.append({"purl": purl, "reason": "no_version"})
        else:
            asked.append(purl)
    return asked, skipped


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _member(
    content: bytes,
    *,
    logical_source: str,
    method: str,
    url: str,
    status: int,
    content_type: str,
    request_body: bytes | None,
    purls: Sequence[str] = (),
    advisory: str | None = None,
) -> dict[str, Any]:
    """One response as one Capture-list member: the body verbatim, the rest coordinate.

    TODO(core lane A, a1-a2): the member wire is the existing Capture wire; a
    member's identity is its request digest (from the coordinate).
    """

    coordinate: dict[str, Any] = {
        "method": method,
        "url": url,
        "status": status,
        "content_type": content_type,
        "request_digest": _digest(
            method.encode() + b" " + url.encode() + b"\n" + (request_body or b"")
        ),
    }
    if purls:
        coordinate["purls"] = list(purls)
    if advisory is not None:
        coordinate["advisory"] = advisory
    return external_capture_result(
        content,
        source_identity=logical_source,
        coordinate_type=COORDINATE_TYPE,
        coordinate=coordinate,
        observed_at=datetime.now(UTC),
        selector_type=SELECTOR_TYPE,
    )


class OsvQuery:
    """``osv.query``: OSV's raw answers for a list of component purls."""

    operations = (QUERY,)

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (lambda: None)

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        source = str(context.input.get("logical_source") or "osv.dev.query")
        components = [str(p) for p in context.input.get("components") or ()]
        asked, _skipped = partition(components)
        responses: list[dict[str, Any]] = []
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.4)

        def record(request: httpx.Request) -> None:
            context.egress.record(str(request.url))

        try:
            with httpx.Client(
                base_url=OSV_API,
                timeout=timeout,
                headers={"user-agent": USER_AGENT},
                transport=self._transport_factory(),
                event_hooks={"request": [record]},
            ) as client:
                found: set[str] = set()
                for start in range(0, len(asked), BATCH):
                    chunk = asked[start : start + BATCH]
                    body = json.dumps(
                        {"queries": [{"package": {"purl": p}} for p in chunk]}, sort_keys=True
                    ).encode()
                    response = client.post(
                        "/v1/querybatch", content=body, headers={"content-type": "application/json"}
                    )
                    responses.append(
                        _member(
                            response.content,
                            logical_source=source,
                            method="POST",
                            url=f"{OSV_API}/v1/querybatch",
                            status=response.status_code,
                            content_type=response.headers.get("content-type", ""),
                            request_body=body,
                            purls=chunk,
                        )
                    )
                    answer = _json(response.content) if response.status_code == 200 else None
                    for result in (answer or {}).get("results") or ():
                        for vuln in (result or {}).get("vulns") or ():
                            if isinstance(vuln, Mapping) and isinstance(vuln.get("id"), str):
                                found.add(vuln["id"])
                if len(found) > MAX_RECORDS:
                    return ProviderResult.refused(
                        PROVIDER_DECLINED,
                        f"OSV names {len(found)} advisories; one run reads at most {MAX_RECORDS}",
                    )
                for advisory in sorted(found):
                    response = client.get(f"/v1/vulns/{advisory}")
                    responses.append(
                        _member(
                            response.content,
                            logical_source=source,
                            method="GET",
                            url=f"{OSV_API}/v1/vulns/{advisory}",
                            status=response.status_code,
                            content_type=response.headers.get("content-type", ""),
                            request_body=None,
                            advisory=advisory,
                        )
                    )
        except httpx.HTTPError as error:
            return ProviderResult.failed("HttpError", f"{type(error).__name__}: {error}")
        # TODO(core lane A): `responses` is the out Contract's list<capture<*>> field.
        return ProviderResult.ok(
            {"responses": responses},
            metrics={"responses": float(len(responses)), "asked": float(len(asked))},
        )


def _json(content: bytes) -> Any:
    try:
        return json.loads(content)
    except ValueError:
        return None


def _bytes(member: Mapping[str, Any]) -> bytes:
    """A member's bytes. TODO(core lane B, b1): the runtime helper returning
    (bytes, coordinate) replaces this."""

    return base64.b64decode(str(member.get("content_base64") or ""), validate=True)


def cve_ids(record: Mapping[str, Any]) -> list[str]:
    """The CVE ids an OSV record is: its id, aliases and (distro records) upstream."""

    ids = [record.get("id"), *(record.get("aliases") or ()), *(record.get("upstream") or ())]
    return sorted({str(i) for i in ids if isinstance(i, str) and _CVE.fullmatch(i)})


def match(responses: Sequence[Mapping[str, Any]], components: Sequence[str]) -> dict[str, Any]:
    """The derived document osv.match emits (pure: same inputs, same bytes)."""

    asked, skipped = partition(components)
    hits: dict[str, list[str]] = {}
    unanswered: dict[str, str] = {}
    records: dict[str, Mapping[str, Any]] = {}
    seen: set[str] = set()
    for member in responses:
        coordinate = member.get("coordinate") or {}
        status = coordinate.get("status")
        answer = _json(_bytes(member)) if status == 200 else None
        if coordinate.get("method") == "POST":
            purls = [str(p) for p in coordinate.get("purls") or ()]
            seen.update(purls)
            results = (answer or {}).get("results") if isinstance(answer, Mapping) else None
            if not isinstance(results, list) or len(results) != len(purls):
                unanswered.update(dict.fromkeys(purls, "batch_failed"))
                continue
            for purl, result in zip(purls, results, strict=True):
                result = result if isinstance(result, Mapping) else {}
                hits[purl] = sorted(
                    str(v["id"])
                    for v in result.get("vulns") or ()
                    if isinstance(v, Mapping) and isinstance(v.get("id"), str)
                )
                if result.get("next_page_token"):
                    unanswered[purl] = "truncated"
        else:
            advisory = str(coordinate.get("advisory") or "")
            if (
                isinstance(answer, Mapping)
                and answer.get("id") == advisory
                and isinstance(answer.get("affected"), list)
            ):
                records[advisory] = answer
    for purl in asked:
        if purl not in seen:
            unanswered.setdefault(purl, "not_asked")
        for advisory in hits.get(purl, ()):
            if advisory not in records:
                # Its aliases are unknown: it could be any CVE, so the answer is
                # incomplete, never "none" for the CVEs it might be.
                unanswered.setdefault(purl, "advisory_unreadable")
    affected: list[dict[str, str]] = []
    unkeyed: list[dict[str, str]] = []
    for purl in asked:
        if purl in unanswered:
            continue
        for advisory in hits.get(purl, ()):
            ids = cve_ids(records[advisory])
            if not ids:
                unkeyed.append({"purl": purl, "osv_id": advisory})
            for cve in ids:
                affected.append({"purl": purl, "cve_id": cve, "osv_id": advisory})
    # One (purl, CVE) pair is one fact, whichever advisories state it: keep the
    # lowest advisory id as the record's locator.
    pairs: dict[tuple[str, str], dict[str, str]] = {}
    for row in sorted(affected, key=lambda r: (r["purl"], r["cve_id"], r["osv_id"])):
        pairs.setdefault((row["purl"], row["cve_id"]), row)
    return {
        "queried": [p for p in asked if p not in unanswered],
        "not_checked": [
            *skipped,
            *({"purl": p, "reason": r} for p, r in sorted(unanswered.items())),
        ],
        "affected": list(pairs.values()),
        "unkeyed": unkeyed,
    }


class OsvMatch:
    """``osv.match``: OSV's responses -> one derived JSON document (pure)."""

    operations = (MATCH,)

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        responses = context.input.get("responses")
        components = context.input.get("components")
        if not isinstance(responses, list) or not isinstance(components, list):
            return ProviderResult.refused(
                PROVIDER_DECLINED, "osv.match needs this run's OSV responses and components"
            )
        try:
            document = match(responses, [str(p) for p in components])
        except (ValueError, TypeError) as error:
            return ProviderResult.refused(PROVIDER_DECLINED, f"unreadable OSV response: {error}")
        content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        # TODO(core lane B, c1-c5): the derived Capture's manifest (sources,
        # reads, reducer) is core's; the provider returns only the document.
        return ProviderResult.ok(
            {
                "document": external_capture_result(
                    content,
                    source_identity=str(context.input.get("logical_source") or "osv.dev.query"),
                    coordinate_type="osv-match-v1",
                    coordinate={"responses": len(responses), "components": len(components)},
                    observed_at=datetime(1970, 1, 1, tzinfo=UTC),
                    selector_type=SELECTOR_TYPE,
                )
            },
            metrics={"affected": float(len(document["affected"]))},
        )
