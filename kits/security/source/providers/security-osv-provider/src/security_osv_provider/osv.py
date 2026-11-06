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
     "affected":     [{"purl", "cve_id", "osv_id", "fixed"?: [version, ...]}],
     "count":        len(affected),
     "unkeyed":      [{"purl", "osv_id"}]}   # advisories with no CVE alias

``fixed`` is every version OSV's advisories for that CVE list as a ``fixed``
range event of the component's own package (matched by the advisory's
``package.purl``, version and qualifiers dropped), sorted as text: one per
release line OSV knows. The kit compares no versions (K-B1-3), so it does not
pick the one above the component's version; agents read the list.

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

A request that fails in transport (no response at all) is left out of the
list, and the result names ``responses`` in ``incomplete_captures`` (R-ON2):
core then marks the call incomplete, positives from the delivered members still
write, and absence never retires. A response that arrives with an error status
is still a member, verbatim; the derive reads its status and leaves the
components it concerns unanswered.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import httpx
from cruxible_provider_runtime.acquisition import (
    CaptureInputError,
    capture_input,
    capture_observed_at,
    external_capture_result,
)
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

OSV_API = "https://api.osv.dev"
QUERY = "osv.query"
MATCH = "osv.match"
BATCH = 1000
#: The most advisory records one run reads (each is one Capture).
MAX_RECORDS = 1000
#: The most fixed versions one (component, CVE) pair carries, and their length.
MAX_FIXED = 32
MAX_VERSION_LEN = 64
#: The out Contract's list<capture> field (named in incomplete_captures).
RESPONSES = "responses"
#: Purl types whose OSV ecosystem is keyed by source package name (K-B1-6).
DISTRO_TYPES = frozenset({"deb", "rpm", "apk"})
#: Core's HTTP coordinate schema (the http_response shape admits only it).
COORDINATE_TYPE = "http-response-v1"
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
    observed_at: datetime,
    purls: Sequence[str] = (),
    advisory: str | None = None,
) -> dict[str, Any]:
    """One response as one Capture-list member: the body verbatim, the rest coordinate.

    A member's identity is its request digest (core, a2), so every request
    names a distinct one.
    """

    coordinate: dict[str, Any] = {
        "method": method,
        "url": url,
        "final_url": url,
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
        observed_at=observed_at,
        selector_type=SELECTOR_TYPE,
    )


class OsvQuery:
    """``osv.query``: OSV's raw answers for a list of component purls."""

    operations = (QUERY,)

    def __init__(
        self,
        transport_factory: TransportFactory | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport_factory = transport_factory or (lambda: None)
        self._clock = clock or (lambda: datetime.now(UTC))

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        source = str(context.input.get("logical_source") or "osv.dev.query")
        components = [str(p) for p in context.input.get("components") or ()]
        asked, _skipped = partition(components)
        responses: list[dict[str, Any]] = []
        missing = 0
        timeout = max(5.0, context.budgets.wall_clock_seconds * 0.4)

        def record(request: httpx.Request) -> None:
            context.egress.record(str(request.url))

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
                try:
                    response = client.post(
                        "/v1/querybatch", content=body, headers={"content-type": "application/json"}
                    )
                except httpx.HTTPError:
                    # No response at all: the member is missing (R-ON2). The
                    # derive reads these purls as never asked (not_asked).
                    missing += 1
                    continue
                responses.append(
                    _member(
                        response.content,
                        logical_source=source,
                        method="POST",
                        url=f"{OSV_API}/v1/querybatch",
                        status=response.status_code,
                        content_type=response.headers.get("content-type", ""),
                        request_body=body,
                        observed_at=self._clock(),
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
                try:
                    response = client.get(f"/v1/vulns/{advisory}")
                except httpx.HTTPError:
                    # The derive reads the components naming it as advisory_unreadable.
                    missing += 1
                    continue
                responses.append(
                    _member(
                        response.content,
                        logical_source=source,
                        method="GET",
                        url=f"{OSV_API}/v1/vulns/{advisory}",
                        status=response.status_code,
                        content_type=response.headers.get("content-type", ""),
                        request_body=None,
                        observed_at=self._clock(),
                        advisory=advisory,
                    )
                )
        return ProviderResult.ok(
            {RESPONSES: responses},
            incomplete_captures=[RESPONSES] if missing else None,
            metrics={
                "responses": float(len(responses)),
                "asked": float(len(asked)),
                "missing": float(missing),
            },
        )


def _json(content: bytes) -> Any:
    try:
        return json.loads(content)
    except ValueError:
        return None


def cve_ids(record: Mapping[str, Any]) -> list[str]:
    """The CVE ids an OSV record is: its id, aliases and (distro records) upstream."""

    ids = [record.get("id"), *(record.get("aliases") or ()), *(record.get("upstream") or ())]
    return sorted({str(i) for i in ids if isinstance(i, str) and _CVE.fullmatch(i)})


_PEP503 = re.compile(r"[-_.]+")


def package_base(purl: str) -> str:
    """A purl without version, qualifiers or subpath, compared case-insensitively.

    PyPI names compare under PEP 503 (runs of ``-_.`` are one ``-``), the form
    core's purl normalizer keys pypi components by.
    """

    base = purl.split("#", 1)[0].split("?", 1)[0]
    if "@" in base.rsplit("/", 1)[-1]:
        base = base.rsplit("@", 1)[0]
    base = base.lower()
    if purl_type(base) == "pypi":
        head, _, name = base.rpartition("/")
        base = f"{head}/{_PEP503.sub('-', name)}"
    return base


def fixed_index(record: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """The ``fixed`` range events an advisory lists, by package (``package_base``).

    Built once per advisory record and looked up per component: one shared
    advisory affecting N packages costs N entries, never N x N comparisons.
    Each package keeps only its lexically smallest ``MAX_FIXED`` versions, the
    only ones a pair can list, so a lookup copies a bounded list.
    """

    index: dict[str, set[str]] = {}
    for affected in record.get("affected") or ():
        if not isinstance(affected, Mapping):
            continue
        package = affected.get("package")
        candidate = package.get("purl") if isinstance(package, Mapping) else None
        if not isinstance(candidate, str):
            continue
        found = index.setdefault(package_base(candidate), set())
        for range_ in affected.get("ranges") or ():
            events = range_.get("events") if isinstance(range_, Mapping) else None
            for event in events or ():
                version = event.get("fixed") if isinstance(event, Mapping) else None
                if isinstance(version, str) and 0 < len(version) <= MAX_VERSION_LEN:
                    found.add(version)
    return {package: tuple(sorted(found)[:MAX_FIXED]) for package, found in index.items()}


def fixed_versions(record: Mapping[str, Any], purl: str) -> list[str]:
    """Every ``fixed`` range event the advisory lists for the component's own package."""

    return list(fixed_index(record).get(package_base(purl), ()))


def match(responses: Sequence[Mapping[str, Any]], components: Sequence[str]) -> dict[str, Any]:
    """The derived document osv.match emits (pure: same inputs, same bytes).

    ``responses`` is core's Capture wire, one per osv.query member (b1).
    """

    asked, skipped = partition(components)
    hits: dict[str, list[str]] = {}
    unanswered: dict[str, str] = {}
    records: dict[str, Mapping[str, Any]] = {}
    seen: set[str] = set()
    for member in responses:
        view = capture_input(member)
        coordinate = view.coordinate if isinstance(view.coordinate, Mapping) else {}
        status = coordinate.get("status")
        answer = _json(view.content) if status == 200 else None
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
    # One (purl, CVE) pair is one fact, whichever advisories state it: the
    # lowest advisory id is the record's locator, and the fixed versions are
    # every one those advisories list.
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    fixed: dict[tuple[str, str], set[str]] = {}
    # One fixed-event index per advisory, shared by every component and alias.
    indexes: dict[str, dict[str, tuple[str, ...]]] = {}
    unkeyed: list[dict[str, str]] = []
    for purl in asked:
        if purl in unanswered:
            continue
        base = package_base(purl)
        for advisory in hits.get(purl, ()):
            record = records[advisory]
            if advisory not in indexes:
                indexes[advisory] = fixed_index(record)
            versions = indexes[advisory].get(base, ())
            ids = cve_ids(record)
            if not ids:
                unkeyed.append({"purl": purl, "osv_id": advisory})
            for cve in ids:
                pair = (purl, cve)
                held = pairs.get(pair)
                if held is None or advisory < held["osv_id"]:
                    pairs[pair] = {"purl": purl, "cve_id": cve, "osv_id": advisory}
                fixed.setdefault(pair, set()).update(versions)
    affected: list[dict[str, Any]] = []
    for pair in sorted(pairs):
        row = dict(pairs[pair])
        listed = sorted(fixed[pair])[:MAX_FIXED]
        if listed:
            row["fixed"] = listed
        affected.append(row)
    return {
        "queried": [p for p in asked if p not in unanswered],
        "not_checked": [
            *skipped,
            *({"purl": p, "reason": r} for p, r in sorted(unanswered.items())),
        ],
        "affected": affected,
        "count": len(affected),
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
            # Pure: stamped with the latest input's observation time, never the clock.
            observed = [capture_observed_at(member) for member in responses]
        except (CaptureInputError, ValueError, TypeError) as error:
            return ProviderResult.refused(PROVIDER_DECLINED, f"unreadable OSV response: {error}")
        content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return ProviderResult.ok(
            {
                "document": external_capture_result(
                    content,
                    source_identity=str(context.input.get("logical_source") or "osv.dev.query"),
                    coordinate_type=COORDINATE_TYPE,
                    coordinate={"responses": len(responses), "components": len(components)},
                    observed_at=max(observed, default=EPOCH),
                    selector_type=SELECTOR_TYPE,
                )
            },
            metrics={"affected": float(len(document["affected"]))},
        )


#: osv.match's observation time when no response was read (every component
#: was a distro package, or none was given): a constant, so the derive stays pure.
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
