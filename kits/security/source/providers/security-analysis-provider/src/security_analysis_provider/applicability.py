"""Applicability of watched vulnerabilities to releases in inventory, from OSV and CVE records.

Both analyses decide, per (release, CVE), ``affected``, ``not_affected`` (with a
VEX justification) or ``inconclusive``, and return proposal items that create or
reuse the assessment Subject by its composite key (release id + CVE id) and
state its ``status``, its ``justification`` (``not_affected`` only) and a
per-item rationale. They never settle: a person or agent reviews the proposal.
A pair whose held assessment already says the same is left alone, so a re-run
proposes nothing; a pair whose answer changed revises the held Claims (and
retires a justification an ``affected`` answer no longer has). A pair an analyst
judged (its assessment carries ``security.assessment.judgment``) is never
revised: the run counts it under ``judged``.

``OsvApplicability`` (``security.osv-applicability``) reads the
``security.osv-query`` Capture: OSV's answer for every component purl@version
of every release with an SBOM, plus the OSV records of every hit and of every
watched CVE (and their aliases). For a release with components:

- a component OSV lists as affected by a CVE -> ``affected`` (the CVE is watched
  by the same proposal when it is not yet);
- a watched CVE OSV knows package data for, not listed for any component:
  a component of one of its packages is present at a version OSV does not list
  -> ``not_affected`` / ``vulnerable_code_not_present``;
- a component of one of its packages whose OSV query failed -> ``inconclusive``;
- a watched CVE none of whose packages is a component -> no assessment. Writing
  ``component_not_present`` for every such pair is releases x watched CVEs of
  answers nobody asked for (the self-dogfood run's second day: 509 of them, 2,545
  proposal items); an unassessed pair with an SBOM means exactly that;
- a watched CVE OSV has no package data for -> no answer here (vendor products
  are the CVE record analysis's).
An OSV advisory with no CVE alias cannot be keyed and is reported in
``unkeyed``, not proposed.

``CveApplicability`` (``security.cve-applicability``) reads one CVE record
Capture (CVE JSON 5) and the releases in inventory. A release whose product name
equals an ``affected`` entry's product (letters and digits, case-insensitive),
with a supplier that matches the entry's vendor or no supplier, is decided by
the entry's version ranges (``version``, ``lessThan``/``lessThanOrEqual``,
``changes``; a ``lessThan`` ending in ``*`` is open-ended) and ``defaultStatus``.
Conservatively: a version the ranges cannot order, a product that only
partially matches, or a vendor that contradicts the supplier -> ``inconclusive``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    Bound,
    InputError,
    Row,
    claim_item,
    cve_token,
    key_ref,
    match_token,
    parse_rows,
    sorted_items,
    subject_item,
)

ASSESSMENT = "security.assessment"
VULNERABILITY = "security.vulnerability"
STATUS = "security.assessment.status"
JUSTIFICATION = "security.assessment.justification"
RETIREMENT_ITEM = "playbill-procedure-claim-retirement-item-v1"
LIMIT = 1000


def classify_osv(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not isinstance(payload.get("osv"), Mapping) or not isinstance(payload.get("releases"), list):
        return None
    return {
        "osv": "present",
        "inventory": "small" if len(payload["releases"]) <= LIMIT else "large",
    }


def classify_cve(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not isinstance(payload.get("record_base64"), str) or not isinstance(
        payload.get("releases"), list
    ):
        return None
    return {
        "record": "present",
        "inventory": "small" if len(payload["releases"]) <= LIMIT else "large",
    }


@dataclass(frozen=True)
class Decision:
    release: Bound
    cve: str
    status: str
    justification: str | None
    rationale: str


@dataclass(frozen=True)
class Held:
    """What inventory already says about one (release, CVE) assessment."""

    assessment: Bound
    status: str | None
    justification: str | None
    status_claim: str | None
    justification_claim: str | None
    judged: bool = False


def _held(rows: Iterable[Row]) -> dict[tuple[str, str], Held]:
    held: dict[tuple[str, str], Held] = {}
    for row in rows:
        assessment = row.subject("assessment")
        release_id = row.value("release_id")
        cve = cve_token(row.value("cve_id"))
        if assessment is None or not isinstance(release_id, str) or cve is None:
            continue
        held[(release_id, cve)] = Held(
            assessment=assessment,
            status=row.value("status"),
            justification=row.value("justification"),
            status_claim=row.claim_id(assessment, STATUS),
            justification_claim=row.claim_id(assessment, JUSTIFICATION),
            judged=row.value("judgment") is not None,
        )
    return held


def decisions_to_items(
    decisions: Iterable[Decision], held: Mapping[tuple[str, str], Held], watched: set[str]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Proposal items for every decision that changes what inventory holds."""

    subjects: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    counts = {"affected": 0, "not_affected": 0, "inconclusive": 0, "unchanged": 0, "judged": 0}
    new_vulnerabilities: set[str] = set()
    for decision in decisions:
        prior = held.get((decision.release.subject_id, decision.cve))
        if prior is not None and prior.judged:
            # An analyst's judgment (security.assessment.judgment) is never revised by a source.
            counts["judged"] += 1
            continue
        if (
            prior is not None
            and prior.status == decision.status
            and prior.justification == decision.justification
        ):
            counts["unchanged"] += 1
            continue
        counts[decision.status] += 1
        vulnerability = key_ref(VULNERABILITY, cve_id=decision.cve)
        if prior is None:
            assessment: Bound | dict[str, Any] = key_ref(
                ASSESSMENT, release_id=decision.release.subject_id, cve_id=decision.cve
            )
            if decision.cve not in watched and decision.cve not in new_vulnerabilities:
                new_vulnerabilities.add(decision.cve)
                subjects.append(
                    subject_item(
                        VULNERABILITY,
                        {"cve_id": decision.cve},
                        f"{decision.cve} applies to inventory ({decision.release.subject_id}): "
                        "watch it.",
                    )
                )
            subjects.append(
                subject_item(
                    ASSESSMENT,
                    {"release_id": decision.release.subject_id, "cve_id": decision.cve},
                    f"Assess {decision.release.subject_id} for {decision.cve}.",
                )
            )
            claims.append(
                claim_item(
                    assessment,
                    "security.assessment.release",
                    decision.release,
                    f"The assessment is about release {decision.release.subject_id}.",
                    role="normative",
                )
            )
            claims.append(
                claim_item(
                    assessment,
                    "security.assessment.vulnerability",
                    vulnerability,
                    f"The assessment is about {decision.cve}.",
                    role="normative",
                )
            )
        else:
            assessment = prior.assessment
        claims.append(
            claim_item(
                assessment,
                STATUS,
                decision.status,
                decision.rationale,
                revises=prior.status_claim if prior is not None and prior.status else None,
            )
        )
        if decision.justification is not None:
            claims.append(
                claim_item(
                    assessment,
                    JUSTIFICATION,
                    decision.justification,
                    decision.rationale,
                    revises=(
                        prior.justification_claim
                        if prior is not None and prior.justification
                        else None
                    ),
                )
            )
        elif prior is not None and prior.justification_claim is not None:
            claims.append(
                {
                    "tag": RETIREMENT_ITEM,
                    "retires": prior.justification_claim,
                    "reason": "superseded",
                    "rationale": f"{decision.status}: the assessment no longer has a "
                    f"not_affected justification. {decision.rationale}",
                    "effective_until": None,
                }
            )
    return subjects + sorted_items(claims), counts


def _releases(rows: Iterable[Row]) -> list[tuple[Bound, Row]]:
    found = []
    for row in rows:
        release = row.subject("release")
        if release is not None:
            found.append((release, row))
    return sorted(found, key=lambda item: item[0].path)


# --- OSV ------------------------------------------------------------------------

_ECOSYSTEM_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "golang",
    "crates.io": "cargo",
    "rubygems": "gem",
    "nuget": "nuget",
    "packagist": "composer",
    "pub": "pub",
    "hex": "hex",
}


def _package_name(purl_type: str, name: str) -> str:
    lowered = name.strip().lower()
    if purl_type == "pypi":
        return re.sub(r"[-_.]+", "-", lowered)
    return lowered


def purl_package(purl: str) -> tuple[str, str] | None:
    """(type, name) of a package URL, version and qualifiers dropped."""

    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    body = body.rsplit("@", 1)[0] if "@" in body else body
    purl_type, _, rest = body.partition("/")
    if not rest:
        return None
    return purl_type.lower(), _package_name(purl_type.lower(), rest.replace("%40", "@"))


def _record_packages(record: Mapping[str, Any]) -> set[tuple[str, str]]:
    packages: set[tuple[str, str]] = set()
    for affected in record.get("affected") or ():
        package = affected.get("package") if isinstance(affected, Mapping) else None
        if not isinstance(package, Mapping):
            continue
        purl = package.get("purl")
        if isinstance(purl, str) and (parsed := purl_package(purl)):
            packages.add(parsed)
            continue
        ecosystem = str(package.get("ecosystem") or "").split(":", 1)[0].lower()
        name = package.get("name")
        if ecosystem in _ECOSYSTEM_TYPES and isinstance(name, str) and name:
            purl_type = _ECOSYSTEM_TYPES[ecosystem]
            packages.add((purl_type, _package_name(purl_type, name)))
    return packages


def _cves(record_id: str, record: Mapping[str, Any] | None) -> set[str]:
    ids = {record_id, *((record or {}).get("aliases") or ())}
    return {cve for item in ids if (cve := cve_token(item))}


def _fixed(record: Mapping[str, Any], package: tuple[str, str]) -> list[str]:
    fixed: list[str] = []
    for affected in record.get("affected") or ():
        if _record_packages({"affected": [affected]}) != {package}:
            continue
        for span in affected.get("ranges") or ():
            for event in span.get("events") or ():
                if isinstance(event, Mapping) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return sorted(set(fixed))


def osv_view(
    material: Mapping[str, Any],
) -> tuple[dict[str, list[str]], set[str], dict[str, Any]]:
    """(purl -> advisory ids, purls whose query failed, id -> record) from the OSV Capture."""

    hits: dict[str, list[str]] = {}
    failed: set[str] = set()
    records: dict[str, Any] = {}
    for exchange in material.get("exchanges") or ():
        if not isinstance(exchange, Mapping):
            raise InputError("an OSV exchange must be an object")
        try:
            body = base64.b64decode(str(exchange.get("body_base64")), validate=True)
        except (binascii.Error, ValueError) as error:
            raise InputError("an OSV exchange body is not base64") from error
        status = exchange.get("status")
        answer = json.loads(body) if status == 200 and body else None
        if exchange.get("method") == "POST":
            purls = list((exchange.get("request") or {}).get("purls") or ())
            results = (answer or {}).get("results") if isinstance(answer, Mapping) else None
            if not isinstance(results, list) or len(results) != len(purls):
                failed.update(purls)
                continue
            for purl, result in zip(purls, results, strict=True):
                vulns = (result or {}).get("vulns") or ()
                hits[purl] = sorted(
                    str(v["id"]) for v in vulns if isinstance(v, Mapping) and v.get("id")
                )
                if (result or {}).get("next_page_token"):
                    failed.add(purl)  # more advisories than one page: not a complete answer
        else:
            record_id = str(exchange.get("path") or "").rsplit("/", 1)[-1]
            if isinstance(answer, Mapping):
                records[record_id] = answer
    return hits, failed, records


class OsvApplicability:
    """The ``security.osv-applicability`` implementation."""

    interface_id = "security.osv-applicability"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            osv = context.input.get("osv")
            if not isinstance(osv, Mapping) or not isinstance(osv.get("exchanges"), list):
                raise InputError("the OSV Capture body has no exchanges")
            releases = _releases(parse_rows(context.input.get("releases")))
            watched_rows = parse_rows(context.input.get("watched"))
            held = _held(parse_rows(context.input.get("assessments")))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        try:
            hits, failed, records = osv_view(osv)
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        cve_packages: dict[str, set[tuple[str, str]]] = {}
        cve_records: dict[str, set[str]] = {}
        unkeyed: set[str] = set()
        for record_id, record in records.items():
            cves = _cves(record_id, record)
            for cve in cves:
                cve_packages.setdefault(cve, set()).update(_record_packages(record))
                cve_records.setdefault(cve, set()).add(record_id)
        watched = {cve for row in watched_rows if (cve := cve_token(row.value("cve_id")))}
        decisions: list[Decision] = []
        for release, row in releases:
            components = sorted(str(item) for item in row.value("components") or ())
            if not components:
                continue
            affected: dict[str, list[str]] = {}
            for purl in components:
                for record_id in hits.get(purl, ()):
                    cves = _cves(record_id, records.get(record_id))
                    if not cves:
                        unkeyed.add(record_id)
                    for cve in cves:
                        package = purl_package(purl)
                        fixed = (
                            _fixed(records[record_id], package)
                            if package and record_id in records
                            else []
                        )
                        affected.setdefault(cve, []).append(
                            f"{purl} ({record_id}"
                            + (f", fixed in {', '.join(fixed)}" if fixed else "")
                            + ")"
                        )
            for cve, reasons in sorted(affected.items()):
                decisions.append(
                    Decision(
                        release,
                        cve,
                        "affected",
                        None,
                        f"OSV lists {cve} as affecting {'; '.join(sorted(set(reasons)))}.",
                    )
                )
            by_package: dict[tuple[str, str], list[str]] = {}
            for purl in components:
                package = purl_package(purl)
                if package is not None:
                    by_package.setdefault(package, []).append(purl)
            for cve in sorted(watched - set(affected)):
                packages = cve_packages.get(cve, set())
                if not packages:
                    continue
                present = sorted(p for package in packages for p in by_package.get(package, ()))
                advisories = ", ".join(sorted(cve_records.get(cve, ())))
                if any(purl in failed for purl in present):
                    decisions.append(
                        Decision(
                            release,
                            cve,
                            "inconclusive",
                            None,
                            "OSV could not be queried for "
                            f"{', '.join(p for p in present if p in failed)}"
                            f", a package {cve} affects ({advisories}).",
                        )
                    )
                elif present:
                    decisions.append(
                        Decision(
                            release,
                            cve,
                            "not_affected",
                            "vulnerable_code_not_present",
                            f"{', '.join(present)} is a package {cve} affects ({advisories}), at a "
                            "version OSV does not list as affected.",
                        )
                    )
        items, counts = decisions_to_items(decisions, held, watched)
        return ProviderResult.ok(
            {
                "items": items,
                "changed": len(items),
                "affected": counts["affected"],
                "not_affected": counts["not_affected"],
                "inconclusive": counts["inconclusive"],
                "unchanged": counts["unchanged"],
                "judged": counts["judged"],
                "unkeyed": sorted(unkeyed),
            },
            metrics={"items": float(len(items))},
        )


# --- CVE record ---------------------------------------------------------------

_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-.+_]?([A-Za-z]+)\.?(\d*))?$")
_PRE = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "rc": 3, "c": 3}


def version_key(value: object) -> tuple[Any, ...] | None:
    """An orderable key for a dotted numeric version with an optional pre-release tag."""

    if not isinstance(value, str):
        return None
    match = _VERSION.match(value.strip())
    if match is None:
        return None
    numbers = [int(part) for part in match.group(1).split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    tag = (match.group(2) or "").lower()
    if tag and tag not in _PRE:
        if tag in {"final", "ga", "release"}:
            tag = ""
        else:
            return None
    pre = (_PRE[tag], int(match.group(3) or 0)) if tag else (9, 0)
    return (tuple(numbers), pre)


def _entry_status(entry: Mapping[str, Any], version: tuple[Any, ...]) -> str | None:
    """'affected'/'unaffected' when this versions[] entry decides, None when it does not
    cover the version, 'unknown' when it cannot be ordered."""

    status = str(entry.get("status") or "")
    if status not in {"affected", "unaffected", "unknown"}:
        return "unknown"
    start_raw = entry.get("version")
    upper_raw = entry.get("lessThan") or entry.get("lessThanOrEqual")
    inclusive = "lessThanOrEqual" in entry and "lessThan" not in entry
    if upper_raw is None:
        exact = version_key(start_raw)
        if exact is None:
            return "unknown"
        return status if exact == version else None
    start = ((0,), (0, 0)) if str(start_raw).strip() in {"0", "*", ""} else version_key(start_raw)
    upper_text = str(upper_raw).strip()
    upper = None if upper_text.endswith("*") else version_key(upper_text)
    if start is None or (upper is None and not upper_text.endswith("*")):
        return "unknown"
    if version < start:
        return None
    if upper is not None and (version > upper or (version == upper and not inclusive)):
        return None
    current = status
    changes = []
    for change in entry.get("changes") or ():
        at = version_key(change.get("at")) if isinstance(change, Mapping) else None
        if at is None:
            return "unknown"
        changes.append((at, str(change.get("status") or "")))
    for at, changed in sorted(changes):
        if at <= version:
            current = changed
    return current if current in {"affected", "unaffected"} else "unknown"


def _product_decision(affected: Mapping[str, Any], version_text: str) -> tuple[str, str]:
    """(status, why) for one release version under one CVE affected[] entry."""

    version = version_key(version_text)
    if version is None:
        return "inconclusive", f"its version {version_text!r} cannot be ordered"
    verdicts = set()
    for entry in affected.get("versions") or ():
        if isinstance(entry, Mapping):
            verdict = _entry_status(entry, version)
            if verdict is not None:
                verdicts.add(verdict)
    if "unknown" in verdicts or len(verdicts) > 1:
        return "inconclusive", "the record's version ranges do not order it unambiguously"
    if verdicts:
        status = verdicts.pop()
        return (
            ("affected", "the record's version ranges include it")
            if status == "affected"
            else ("not_affected", "the record's version ranges exclude it")
        )
    default = str(affected.get("defaultStatus") or "unknown")
    if default == "affected":
        return "affected", "no range covers it and the record's defaultStatus is affected"
    if default == "unaffected":
        return "not_affected", "no range covers it and the record's defaultStatus is unaffected"
    return "inconclusive", "no range covers it and the record states no default"


class CveApplicability:
    """The ``security.cve-applicability`` implementation."""

    interface_id = "security.cve-applicability"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            raw = context.input.get("record_base64")
            try:
                record = json.loads(base64.b64decode(str(raw), validate=True))
            except (binascii.Error, ValueError) as error:
                raise InputError("the CVE record Capture body is not JSON") from error
            cve = cve_token((record.get("cveMetadata") or {}).get("cveId"))
            cna = (record.get("containers") or {}).get("cna") or {}
            if cve is None or not isinstance(cna, Mapping):
                raise InputError("the Capture body is not a CVE JSON 5 record")
            releases = _releases(parse_rows(context.input.get("releases")))
            watched_rows = parse_rows(context.input.get("watched"))
            held = _held(parse_rows(context.input.get("assessments")))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        watched = {c for row in watched_rows if (c := cve_token(row.value("cve_id")))}
        decisions: list[Decision] = []
        for release, row in releases:
            product = match_token(row.value("product_name"))
            supplier = match_token(row.value("supplier_name"))
            version = str(row.value("version") or "")
            if not product:
                continue
            for affected in cna.get("affected") or ():
                if not isinstance(affected, Mapping):
                    continue
                named = match_token(affected.get("product"))
                vendor = match_token(affected.get("vendor"))
                label = f"{affected.get('vendor')} {affected.get('product')}"
                if not named:
                    continue
                if named != product:
                    if len(product) >= 3 and (product in named or named in product):
                        decisions.append(
                            Decision(
                                release,
                                cve,
                                "inconclusive",
                                None,
                                f"{cve}'s record names {label}, which only partly matches the "
                                f"release's product {row.value('product_name')!r}.",
                            )
                        )
                    continue
                if (
                    supplier
                    and vendor
                    and vendor not in {"na", ""}
                    and not (supplier in vendor or vendor in supplier)
                ):
                    decisions.append(
                        Decision(
                            release,
                            cve,
                            "inconclusive",
                            None,
                            f"{cve}'s record names {label}; the release's supplier "
                            f"{row.value('supplier_name')!r} is a different vendor.",
                        )
                    )
                    continue
                status, why = _product_decision(affected, version)
                decisions.append(
                    Decision(
                        release,
                        cve,
                        status,
                        "vulnerable_code_not_present" if status == "not_affected" else None,
                        f"{cve}'s CVE record lists {label}: for version {version} {why}.",
                    )
                )
        # One answer per release: an inconclusive one never stands beside a decided one.
        merged: dict[str, Decision] = {}
        for decision in decisions:
            prior = merged.get(decision.release.path)
            if prior is None or (
                prior.status == "inconclusive" and decision.status != "inconclusive"
            ):
                merged[decision.release.path] = decision
            elif prior.status != decision.status and decision.status != "inconclusive":
                merged[decision.release.path] = Decision(
                    decision.release,
                    cve,
                    "inconclusive",
                    None,
                    f"{cve}'s record gives conflicting answers for this release: "
                    f"{prior.rationale} / {decision.rationale}",
                )
        items, counts = decisions_to_items(merged.values(), held, watched)
        return ProviderResult.ok(
            {
                "items": items,
                "changed": len(items),
                "cve_id": cve,
                "affected": counts["affected"],
                "not_affected": counts["not_affected"],
                "inconclusive": counts["inconclusive"],
                "unchanged": counts["unchanged"],
                "judged": counts["judged"],
            },
            metrics={"items": float(len(items))},
        )
