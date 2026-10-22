"""Applicability of watched vulnerabilities to releases in inventory, from OSV and CVE records.

Both analyses decide, per (release, CVE), ``affected``, ``not_affected`` (with a
VEX justification) or ``inconclusive``, and return proposal items that create or
reuse the assessment Subject by its composite key (release id + CVE id) and
state its ``status``, its ``justification`` (``not_affected`` only) and a
per-item rationale. They never settle: a person or agent reviews the proposal.
A pair whose held assessment already says the same is left alone, so a re-run
proposes nothing; a pair whose answer changed revises the held Claims (and
retires a justification an ``affected`` answer no longer has). A pair an analyst
judged (its status Claim is normative: the state tap's ``status_role``) is never
revised: the run counts it under ``judged``.

``OsvApplicability`` (``security.osv-applicability``) reads the
``security.osv-query`` Capture: OSV's answer for every component purl@version
of every release with an SBOM whose ecosystem OSV indexes (the Capture lists the
rest as ``not_indexed``, with the ecosystem list and purl type map it applied),
plus the OSV records of every hit and of every watched CVE (and their aliases).
For each release with components it states one ``security.release.osv_coverage``
(``complete: N of N components answered``, or ``partial`` with how many OSV
answered, the purl types not indexed and how many went unanswered): OSV's
coverage is the provider's own word, never a per-CVE inconclusive. For each
watched CVE (and each this proposal starts watching) it states the packages OSV's
records say it affects (``security.vulnerability.package``, a purl without
version): OSV knows the CVE. For a release with components:

- a component OSV lists as affected by a CVE -> ``affected`` (the proposal creates
  the CVE's vulnerability by key when it does not exist; the affected assessment
  is what makes it watched);
- a watched CVE OSV knows package data for, not listed for any component:
  a component of one of its packages is present at a version OSV does not list
  -> ``not_affected`` / ``vulnerable_code_not_present``;
- a component of one of its packages whose OSV query failed -> ``inconclusive``;
- a component of one of its packages OSV was never asked about (not indexed) ->
  no answer here (the coverage Claim says partial);
- a watched CVE none of whose packages is a component -> no assessment. Writing
  ``component_not_present`` for every such pair is releases x watched CVEs of
  answers nobody asked for (the self-dogfood run's second day: 509 of them, 2,545
  proposal items); an unassessed pair with an SBOM means exactly that;
- a watched CVE OSV has no package data for -> no answer here (vendor products
  are the CVE record analysis's).
An OSV advisory with no CVE alias cannot be keyed and is reported in
``unkeyed``, not proposed.

``CveApplicability`` (``security.cve-applicability``) reads one CVE record
Capture (CVE JSON 5) and the releases in inventory, and matches each ``affected``
entry to a release by data, never by a partial or substring name:

- its ``collectionURL`` + ``packageName`` (read through the kit's collectionURL
  map, ``collections``: kit data citing the CVE schema and the purl spec) against
  each component purl's full namespace and name (decided by that component's
  version, which the assessment names as its component);
- its ``repo`` against the release's source repository where the system model
  knows it (``security.release_sources``: the repository a target serving the
  release is published from, or a forge purl such as ``pkg:github/cli/cli``);
- its ``cpes``, its ``packageName`` and its vendor/product against the release's
  product aliases (``security.release.product_alias``: an analyst's statement,
  citing evidence, that e.g. a Homebrew ``gh`` release is ``cli/cli``);
- its product against the release's product name (letters and digits,
  case-insensitive), with a supplier that matches the entry's vendor or no
  supplier.

A matched release is decided by the entry's version ranges (``version``,
``lessThan``/``lessThanOrEqual``, ``changes``; a ``lessThan`` ending in ``*`` is
open-ended; a ``version`` written as comparisons, ``< 2.97.0``, is read as
written) and ``defaultStatus``. Conservatively: a version the ranges cannot order,
or a vendor that contradicts the supplier -> ``inconclusive``. A release the
record does not name gets no assessment (an incident's RQ1 reads that pair
unknown, never none). The CNA's ``affected`` entries are read with every ADP
container's (CISA's vulnrichment adds them where the CNA states none); a null or
absent container, list or field is no data, never an answer. The record's title
(``security.vulnerability.title``) is stated for the CVE it is about: a record of
it was read.

The record may also be an NVD API 2.0 answer for one CVE (``vulnerabilities[0].cve``):
its ``configurations[].nodes[].cpeMatch[]`` (each null or absent tolerated: no CPE
data is no answer) become affected entries by CPE vendor and product (and the CPE
itself), with ``versionStart*``/``versionEnd*`` as the range (a start-excluding
bound is read as inclusive: toward affected) and versions outside every range not
affected. The answer must be complete: ``totalResults`` zero (NVD does not know
the CVE) or more results than the page holds is refused, so a truncated or empty
page reads as unknown, never as none.

OSV decides a release through a purl OSV answered for (the release's
``osv_coverage``, the provider's own word) when OSV knows the CVE (its records
name a package for it, ``security.vulnerability.package``): the record analysis
then leaves it, so the two Procedures never flip one assessment between them (a
distro build's version does not order against upstream ranges, and its backports
are in the distro advisory).
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
    once_per,
    parse_rows,
    replacing,
    sorted_items,
    subject_item,
)

ASSESSMENT = "security.assessment"
VULNERABILITY = "security.vulnerability"
STATUS = "security.assessment.status"
JUSTIFICATION = "security.assessment.justification"
COMPONENT = "security.assessment.component"
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
    #: The release's components OSV lists as affected (``assessment.component``).
    components: tuple[str, ...] = ()


@dataclass(frozen=True)
class Held:
    """What inventory already says about one (release, CVE) assessment."""

    assessment: Bound
    status: str | None
    justification: str | None
    status_claim: str | None
    justification_claim: str | None
    judged: bool = False
    #: component purl -> its Claim ID
    components: tuple[tuple[str, str], ...] = ()


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
            judged=row.value("status_role") == "normative",
            components=tuple(sorted((str(item.value), item.claim_id)
                                    for item in row.included("component")
                                    if isinstance(item.value, str))),
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
            # An analyst's judgment (a normative status) is never revised by a source.
            counts["judged"] += 1
            continue
        held_components = dict(prior.components) if prior is not None else {}
        wanted = set(decision.components) if decision.status == "affected" else set()
        if (
            prior is not None
            and prior.status == decision.status
            and prior.justification == decision.justification
            and (decision.status != "affected" or not decision.components
                 or wanted == set(held_components))
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
                        f"{decision.cve} applies to inventory ({decision.release.subject_id}); "
                        "its assessment tracks it.",
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
        if prior is None or prior.status != decision.status:
            claims.append(
                claim_item(
                    assessment,
                    STATUS,
                    decision.status,
                    decision.rationale,
                    revises=prior.status_claim if prior is not None and prior.status else None,
                )
            )
        pairs, adds, stale = replacing(held_components, wanted)
        for purl, revises in [*pairs, *((purl, None) for purl in adds)]:
            claims.append(claim_item(assessment, COMPONENT, purl,
                                     f"OSV lists {decision.cve} for the component {purl}.",
                                     revises=revises))
        for purl in stale:
            claims.append({"tag": RETIREMENT_ITEM, "retires": held_components[purl],
                           "reason": "superseded", "effective_until": None,
                           "rationale": f"{decision.status}: OSV no longer lists {purl} for "
                                        f"{decision.cve}. {decision.rationale}"})
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

RELEASE_COVERAGE = "security.release.osv_coverage"
TITLE = "security.vulnerability.title"
VULNERABILITY_PACKAGE = "security.vulnerability.package"


def ecosystem_purls(purl_types: object) -> dict[str, tuple[str, str | None]]:
    """OSV ecosystem name (casefolded) -> (purl type, namespace or None), from the kit's
    purl type map the OSV query applied (its Capture records it): how an OSV record
    that names a package by ecosystem and name, without a purl, is read."""

    table = purl_types.get("osv_ecosystems") if isinstance(purl_types, Mapping) else None
    found: dict[str, tuple[str, str | None]] = {}
    for key, ecosystem in sorted((table or {}).items()):
        purl_type, _, namespace = str(key).lower().partition("/")
        found.setdefault(str(ecosystem).casefold(), (purl_type, namespace or None))
    return found


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


def _record_packages(record: Mapping[str, Any],
                     ecosystems: Mapping[str, tuple[str, str | None]] | None = None,
                     ) -> set[tuple[str, str]]:
    """(type, name) of every package an OSV record's affected[] names: its purl, else its
    ecosystem and name through the kit's purl type map (``ecosystem_purls``)."""

    packages: set[tuple[str, str]] = set()
    for affected in record.get("affected") or ():
        package = affected.get("package") if isinstance(affected, Mapping) else None
        if not isinstance(package, Mapping):
            continue
        purl = package.get("purl")
        if isinstance(purl, str) and (parsed := purl_package(purl)):
            packages.add(parsed)
            continue
        ecosystem = str(package.get("ecosystem") or "").split(":", 1)[0].strip().casefold()
        name = package.get("name")
        mapped = (ecosystems or {}).get(ecosystem)
        if mapped is not None and isinstance(name, str) and name.strip():
            purl_type, namespace = mapped
            full = f"{namespace}/{name.strip()}" if namespace else name.strip()
            packages.add((purl_type, _package_name(purl_type, full)))
    return packages


def package_purl(package: tuple[str, str]) -> str:
    """A package as a purl without version (``pkg:deb/debian/php8.2``)."""

    return f"pkg:{package[0]}/{package[1]}"


def coverage_text(total: int, answered: int, not_indexed: Mapping[str, int],
                  unanswered: int) -> str:
    """The release's OSV coverage, one value: ``complete: N of N components answered``, or
    ``partial: A of N components answered; not indexed: brew 1, generic 2; unanswered K``."""

    state = "complete" if answered == total and total else "partial"
    text = f"{state}: {answered} of {total} components answered"
    if not_indexed:
        text += "; not indexed: " + ", ".join(f"{t} {n}" for t, n in sorted(not_indexed.items()))
    if unanswered:
        text += f"; unanswered {unanswered}"
    return text


def _cves(record_id: str, record: Mapping[str, Any] | None) -> set[str]:
    """The CVE ids an OSV record is: its id, aliases, and the upstream ids a distro record
    (DEBIAN-CVE-..., UBUNTU-CVE-...) names."""

    ids = {record_id, *((record or {}).get("aliases") or ()),
           *((record or {}).get("upstream") or ())}
    return {cve for item in ids if (cve := cve_token(item))}


def _fixed(record: Mapping[str, Any], package: tuple[str, str],
           ecosystems: Mapping[str, tuple[str, str | None]] | None = None) -> list[str]:
    fixed: list[str] = []
    for affected in record.get("affected") or ():
        if _record_packages({"affected": [affected]}, ecosystems) != {package}:
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
        ecosystems = ecosystem_purls(osv.get("purl_types"))
        # Components the query never asked OSV about (their ecosystem is not OSV's).
        not_indexed = {str(item["purl"]): str(item.get("type") or "")
                       for item in osv.get("not_indexed") or ()
                       if isinstance(item, Mapping) and isinstance(item.get("purl"), str)}
        cve_packages: dict[str, set[tuple[str, str]]] = {}
        cve_records: dict[str, set[str]] = {}
        unkeyed: set[str] = set()
        for record_id, record in records.items():
            cves = _cves(record_id, record)
            for cve in cves:
                cve_packages.setdefault(cve, set()).update(_record_packages(record, ecosystems))
                cve_records.setdefault(cve, set()).add(record_id)
        watched_once = once_per(watched_rows, "vulnerability")
        watched = {cve for row in watched_once if (cve := cve_token(row.value("cve_id")))}
        decisions: list[Decision] = []
        coverage_items: list[dict[str, Any]] = []
        for release, row in releases:
            components = sorted(str(item) for item in row.value("components") or ())
            if not components:
                continue
            # One coverage Claim per release: did OSV answer every component?
            answered = [c for c in components if c in hits and c not in failed]
            skipped: dict[str, int] = {}
            for purl in components:
                if purl in not_indexed:
                    skipped[not_indexed[purl]] = skipped.get(not_indexed[purl], 0) + 1
            unanswered = len(components) - len(answered) - sum(skipped.values())
            coverage = coverage_text(len(components), len(answered), skipped, unanswered)
            if row.value("osv_coverage") != coverage:
                held_claim = row.claim_id(release, RELEASE_COVERAGE)
                coverage_items.append(claim_item(
                    release, RELEASE_COVERAGE, coverage,
                    f"OSV's answer for {release.subject_id}'s {len(components)} components: "
                    f"{coverage}." + (" The query did not ask about a component whose purl type "
                                      "OSV does not index (its ecosystem list and the kit's "
                                      "purl type map), so no advisory there reads as none."
                                      if skipped else ""),
                    revises=held_claim if row.value("osv_coverage") else None))
            affected: dict[str, list[str]] = {}
            affected_purls: dict[str, set[str]] = {}
            for purl in components:
                for record_id in hits.get(purl, ()):
                    cves = _cves(record_id, records.get(record_id))
                    if not cves:
                        unkeyed.add(record_id)
                    for cve in cves:
                        package = purl_package(purl)
                        fixed = (
                            _fixed(records[record_id], package, ecosystems)
                            if package and record_id in records
                            else []
                        )
                        affected.setdefault(cve, []).append(
                            f"{purl} ({record_id}"
                            + (f", fixed in {', '.join(fixed)}" if fixed else "")
                            + ")"
                        )
                        affected_purls.setdefault(cve, set()).add(purl)
            for cve, reasons in sorted(affected.items()):
                decisions.append(
                    Decision(
                        release,
                        cve,
                        "affected",
                        None,
                        f"OSV lists {cve} as affecting {'; '.join(sorted(set(reasons)))}.",
                        tuple(sorted(affected_purls.get(cve, ()))),
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
                if any(purl not in hits and purl not in failed for purl in present):
                    # Never asked (not indexed) or no answer in the Capture: OSV's silence
                    # decides nothing; the release's coverage Claim says partial.
                    continue
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
        # What OSV says each watched CVE affects (OSV knows the CVE), and each CVE this
        # proposal starts watching: what respond and the CVE record matcher read.
        created = {str(item["key"]["cve_id"]) for item in items
                   if item.get("subject_kind") == VULNERABILITY}
        package_items: list[dict[str, Any]] = []
        targets: dict[str, Any] = {}
        held_packages: dict[str, set[str]] = {}
        for row in watched_once:
            cve, bound = cve_token(row.value("cve_id")), row.subject("vulnerability")
            if cve is not None and bound is not None:
                targets.setdefault(cve, bound)
                held_packages.setdefault(cve, set()).update(
                    str(item.value) for item in row.included("package")
                    if isinstance(item.value, str))
        for cve in sorted(created):
            targets.setdefault(cve, key_ref(VULNERABILITY, cve_id=cve))
        for cve, subject in sorted(targets.items()):
            advisories = ", ".join(sorted(cve_records.get(cve, ())))
            for purl in sorted(package_purl(p) for p in cve_packages.get(cve, set())):
                if purl not in held_packages.get(cve, set()):
                    package_items.append(claim_item(
                        subject, VULNERABILITY_PACKAGE, purl,
                        f"OSV's {advisories} name {purl} as affected by {cve}."))
        subjects = [item for item in items if item.get("subject_kind")]
        claims = [item for item in items if not item.get("subject_kind")]
        items = subjects + sorted_items(claims + coverage_items + package_items)
        return ProviderResult.ok(
            {
                "items": items,
                "changed": len(items),
                "affected": counts["affected"],
                "not_affected": counts["not_affected"],
                "inconclusive": counts["inconclusive"],
                "unchanged": counts["unchanged"],
                "judged": counts["judged"],
                "coverage": len(coverage_items),
                "packages": len(package_items),
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


_CONSTRAINT = re.compile(r"^(>=|<=|>|<|=)\s*(\S+)$")


def _constraints(value: object) -> list[tuple[str, tuple[Any, ...]]] | None:
    """A ``version`` written as comparisons (``< 2.97.0``, ``>= 2.40.0, < 2.97.0``, as
    GitHub's CNA writes them), or None when it is a plain version."""

    if not isinstance(value, str) or not value.strip()[:1] in {"<", ">", "="}:
        return None
    bounds = []
    for part in value.split(","):
        match = _CONSTRAINT.match(part.strip())
        key = version_key(match.group(2)) if match else None
        if match is None or key is None:
            return None
        bounds.append((match.group(1), key))
    return bounds


def _holds(version: tuple[Any, ...], op: str, at: tuple[Any, ...]) -> bool:
    return {"<": version < at, "<=": version <= at, ">": version > at, ">=": version >= at,
            "=": version == at}[op]


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
        bounds = _constraints(start_raw)
        if bounds is not None:  # "< 2.97.0", ">= 2.40.0, < 2.97.0": the record's own words
            return status if all(_holds(version, op, at) for op, at in bounds) else None
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


# --- matching a record's affected entries to releases, by data ------------------


@dataclass(frozen=True)
class Collections:
    """The kit's collectionURL map (``cve_collections.json``): prefix -> package naming."""

    table: tuple[tuple[str, Mapping[str, Any]], ...]

    @classmethod
    def read(cls, value: object) -> Collections:
        table = value.get("collections") if isinstance(value, Mapping) else None
        if not isinstance(table, Mapping):
            raise InputError("no collectionURL map (collections.collections)")
        rows = [(str(url).strip().rstrip("/").lower(), spec) for url, spec in table.items()
                if isinstance(spec, Mapping) and spec.get("type")]
        return cls(tuple(sorted(rows, key=lambda row: -len(row[0]))))

    def package(self, url: object, name: object) -> tuple[str, str] | None:
        """(purl type, full name) a collectionURL + packageName names, or None."""

        if not isinstance(url, str) or not isinstance(name, str) or not name.strip():
            return None
        text = url.strip().rstrip("/").lower()
        for prefix, spec in self.table:
            if text == prefix or text.startswith(prefix + "/"):
                full = name.strip()
                if spec.get("name_separator"):
                    full = full.replace(str(spec["name_separator"]), "/")
                if spec.get("namespace"):
                    full = f"{spec['namespace']}/{full}"
                purl_type = str(spec["type"]).lower()
                return purl_type, _package_name(purl_type, full)
        return None

    def forge(self, purl_type: str) -> str | None:
        """The host a forge purl type's names are repositories on (github -> github.com)."""

        for prefix, spec in self.table:
            if spec.get("repository") and str(spec["type"]).lower() == purl_type:
                return prefix.split("://", 1)[-1].split("/", 1)[0]
        return None


def repo_identity(value: object) -> str | None:
    """A repository as host/owner/name, casefolded (``https://github.com/cli/cli.git`` ->
    ``github.com/cli/cli``)."""

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0].rstrip("/")
    text = text.removesuffix(".git").removeprefix("www.").casefold()
    return text if text.count("/") >= 2 else None


def cpe_identity(value: object) -> tuple[str, str, str] | None:
    """(part, vendor, product) of a CPE 2.3 name or prefix, compared by match_token."""

    if not isinstance(value, str):
        return None
    parts = value.strip().split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3" or parts[2] not in {"a", "h", "o"}:
        return None
    vendor, product = (match_token(unquote_cpe(part)) for part in parts[3:5])
    return (parts[2], vendor, product) if vendor and product and product != "" else None


def alias_identity(value: object) -> tuple[Any, ...] | None:
    """An analyst's product alias (``security.release.product_alias``) as an identity:
    a purl without version, a CPE prefix, a repository URL, or vendor/product as a
    CVE record's affected entry names it."""

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.startswith("pkg:"):
        package = purl_package(text)
        return ("package", *package) if package else None
    if text.startswith("cpe:"):
        cpe = cpe_identity(text)
        return ("cpe", *cpe) if cpe else None
    if text.startswith(("https://", "http://")):
        repo = repo_identity(text)
        return ("repo", repo) if repo else None
    vendor, _, product = text.rpartition("/")
    if vendor.strip() and product.strip():
        return ("vendor_product", match_token(vendor), match_token(product))
    return None


@dataclass
class Candidate:
    """What one release is known as: its key, components, source repositories, aliases."""

    release: Bound
    row: Row
    product: str
    supplier: str
    version: str
    #: (type, name) -> [(component purl, its version)]
    packages: dict[tuple[str, str], list[tuple[str, str]]]
    repos: set[str]
    aliases: set[tuple[Any, ...]]
    #: purl types OSV did not index for this release; None when OSV never answered it
    osv_skipped: set[str] | None
    own: str | None


def coverage_skipped(text: object) -> set[str] | None:
    """The purl types a release's OSV coverage says OSV did not index, or None when there
    is no coverage (OSV never answered it)."""

    if not isinstance(text, str) or ":" not in text:
        return None
    state, _, rest = text.partition(":")
    if state not in {"complete", "partial"}:
        return None
    skipped: set[str] = set()
    for clause in rest.split(";"):
        clause = clause.strip()
        if clause.startswith("not indexed:"):
            for item in clause.removeprefix("not indexed:").split(","):
                skipped.add(item.strip().split(" ", 1)[0])
    return skipped


def _candidates(releases: Iterable[tuple[Bound, Row]], sources: Iterable[Row],
                collections: Collections) -> list[Candidate]:
    repos: dict[str, set[str]] = {}
    for row in sources:
        release, host, name = row.subject("release"), row.value("forge_host"), row.value(
            "full_name")
        if release is not None and isinstance(host, str) and isinstance(name, str):
            repos.setdefault(release.path, set()).add(f"{host}/{name}".casefold())
    found = []
    for release, row in releases:
        product = str(row.value("product_name") or "")
        version = str(row.value("version") or "").strip()
        packages: dict[tuple[str, str], list[tuple[str, str]]] = {}
        held_repos = set(repos.get(release.path, ()))
        own = None
        for purl in row.value("components") or ():
            if not isinstance(purl, str) or "@" not in purl:
                continue
            package = purl_package(purl)
            if package is None:
                continue
            at = purl.split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[1]
            packages.setdefault(package, []).append((purl, at))
            if match_token(package[1]) == match_token(product) and at == version:
                own = purl
            host = collections.forge(package[0])
            if host is not None:
                held_repos.add(f"{host}/{package[1]}")
        aliases = {identity for value in _list(row.value("product_alias"))
                   if (identity := alias_identity(value)) is not None}
        found.append(Candidate(
            release=release, row=row, product=match_token(product),
            supplier=match_token(row.value("supplier_name")), version=version,
            packages=packages, repos=held_repos, aliases=aliases,
            osv_skipped=coverage_skipped(row.value("osv_coverage")), own=own))
    return found


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _osv_decides(candidate: Candidate, purl: str | None, osv_knows: bool) -> bool:
    """Whether OSV, not the record, decides this release through ``purl``: OSV answered for
    it (the release's coverage, the provider's own word) and OSV knows the CVE (its
    records name a package for it). Then the two Procedures never flip one assessment."""

    if purl is None or not osv_knows or candidate.osv_skipped is None:
        return False
    package = purl_package(purl)
    return package is not None and package[0] not in candidate.osv_skipped


def entry_matches(entry: Mapping[str, Any], candidate: Candidate, collections: Collections,
                  osv_knows: bool) -> list[tuple[str, tuple[str, ...], str]]:
    """(version to decide, components, how it matched) for each way the record's affected
    ``entry`` names the release: its packageName (a component's full namespace and name),
    its repo (the release's source repository), its CPEs, its vendor/product (the release's
    product name, or an analyst's alias). No partial or substring match."""

    found: list[tuple[str, tuple[str, ...], str]] = []
    package = collections.package(entry.get("collectionURL"), entry.get("packageName"))
    if package is not None:
        for purl, at in candidate.packages.get(package, ()):
            if not _osv_decides(candidate, purl, osv_knows):
                found.append((at, (purl,), f"its packageName names {purl}"))
    if _osv_decides(candidate, candidate.own, osv_knows):
        return found  # the release is itself a package OSV answered for
    vendor, product = match_token(entry.get("vendor")), match_token(entry.get("product"))
    repo = repo_identity(entry.get("repo"))
    cpes = {cpe for value in _list(entry.get("cpes")) if (cpe := cpe_identity(value))}
    how = None
    if package is not None and ("package", *package) in candidate.aliases:
        how = f"its packageName is an alias of the release ({package_purl(package)})"
    elif repo is not None and (repo in candidate.repos or ("repo", repo) in candidate.aliases):
        how = f"its repo {repo} is the release's source repository"
    elif any(("cpe", *cpe) in candidate.aliases for cpe in cpes):
        how = "a CPE it lists is an alias of the release"
    elif product and ("vendor_product", vendor, product) in candidate.aliases:
        how = f"{entry.get('vendor')}/{entry.get('product')} is an alias of the release"
    elif product and product == candidate.product:
        if (candidate.supplier and vendor and vendor not in {"na", ""}
                and not (candidate.supplier in vendor or vendor in candidate.supplier)):
            return found + [("", (), "vendor_mismatch")]
        how = "its product is the release's product name"
    if how is not None:
        found.append((candidate.version, (), how))
    return found


def _record_title(record: Mapping[str, Any]) -> str | None:
    """The record's title (CVE 5: cna.title, else its first English description; NVD: the
    first English description), at most 300 characters."""

    if "cveMetadata" in record:
        cna = (record.get("containers") or {}).get("cna") or {}
        texts = [cna.get("title")] + [d.get("value") for d in cna.get("descriptions") or ()
                                      if isinstance(d, Mapping) and str(d.get("lang") or "")
                                      .lower().startswith("en")]
    else:
        body = ((record.get("vulnerabilities") or [{}])[0] or {}).get("cve") or {}
        texts = [d.get("value") for d in body.get("descriptions") or ()
                 if isinstance(d, Mapping) and str(d.get("lang") or "").lower().startswith("en")]
    for text in texts:
        if isinstance(text, str) and " ".join(text.split()):
            return " ".join(text.split())[:300]
    return None


_CPE = re.compile(r"^cpe:2\.3:([aho]):([^:]*):([^:]*):([^:]*):")


def _nvd_affected(record: Mapping[str, Any]) -> tuple[str, list[Mapping[str, Any]]]:
    """(CVE id, CVE 5-shaped affected entries) of an NVD API 2.0 answer for one CVE."""

    total, start = record.get("totalResults"), record.get("startIndex") or 0
    items = record.get("vulnerabilities") or []
    if not isinstance(total, int) or not isinstance(items, list) or not isinstance(start, int):
        raise InputError("the NVD answer states no totalResults: completeness unknown")
    if total == 0:
        raise InputError("NVD does not know the CVE (totalResults 0): no answer, not a "
                         "not_affected")
    if start + len(items) < total or len(items) != 1:
        raise InputError(f"the NVD answer is incomplete or not one CVE ({len(items)} of "
                         f"{total} from {start}): it would read a missing range as none")
    cve_body = (items[0] or {}).get("cve") or {}
    cve = cve_token(cve_body.get("id"))
    if cve is None:
        raise InputError("the NVD answer names no CVE id")
    entries: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for configuration in cve_body.get("configurations") or ():
        for node in (configuration or {}).get("nodes") or ():
            for match in (node or {}).get("cpeMatch") or ():
                if not isinstance(match, Mapping) or match.get("vulnerable") is not True:
                    continue
                parsed = _CPE.match(str(match.get("criteria") or ""))
                if parsed is None:
                    continue
                part = parsed.group(1)
                vendor, product, version = (unquote_cpe(text) for text in parsed.groups()[1:])
                low = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                if version not in ("*", "-", ""):
                    entry: dict[str, Any] = {"version": version, "status": "affected"}
                elif match.get("versionEndExcluding"):
                    entry = {"version": low or "0", "lessThan": match["versionEndExcluding"],
                             "status": "affected"}
                elif match.get("versionEndIncluding"):
                    entry = {"version": low or "0",
                             "lessThanOrEqual": match["versionEndIncluding"],
                             "status": "affected"}
                else:
                    entry = {"version": low or "0", "lessThan": "*", "status": "affected"}
                entries.setdefault((part, vendor, product), []).append(entry)
    return cve, [{"vendor": vendor, "product": product, "versions": versions,
                  "cpes": [f"cpe:2.3:{part}:{vendor}:{product}"],
                  "defaultStatus": "unaffected"}
                 for (part, vendor, product), versions in sorted(entries.items())]


def unquote_cpe(part: str) -> str:
    """A CPE 2.3 formatted-string component with its backslash escapes removed."""

    return re.sub(r"\\(.)", r"\1", part)


def _record_affected(record: Mapping[str, Any]) -> tuple[str, list[Mapping[str, Any]]]:
    """(CVE id, affected entries) of a CVE JSON 5 record or an NVD API 2.0 answer."""

    if "vulnerabilities" in record and "cveMetadata" not in record:
        return _nvd_affected(record)
    cve = cve_token((record.get("cveMetadata") or {}).get("cveId"))
    containers = record.get("containers") or {}
    if cve is None or not isinstance(containers, Mapping):
        raise InputError("the Capture body is not a CVE JSON 5 record")
    cna = containers.get("cna") or {}
    if not isinstance(cna, Mapping):
        raise InputError("the Capture body is not a CVE JSON 5 record")
    affected = [entry for entry in cna.get("affected") or () if isinstance(entry, Mapping)]
    for adp in containers.get("adp") or ():
        if isinstance(adp, Mapping):
            affected += [e for e in adp.get("affected") or () if isinstance(e, Mapping)]
    return cve, affected


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
            if not isinstance(record, Mapping):
                raise InputError("the Capture body is not a CVE record")
            cve, affected_entries = _record_affected(record)
            releases = _releases(parse_rows(context.input.get("releases")))
            sources = parse_rows(context.input.get("sources") or [])
            watched_rows = once_per(parse_rows(context.input.get("watched")), "vulnerability")
            held = _held(parse_rows(context.input.get("assessments")))
            collections = Collections.read(context.input.get("collections"))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        watched = {c for row in watched_rows if (c := cve_token(row.value("cve_id")))}
        mine = next((row for row in watched_rows if cve_token(row.value("cve_id")) == cve), None)
        # OSV knows the CVE when its records name a package for it: then a release OSV
        # answered for is OSV's to decide.
        osv_knows = mine is not None and any(
            isinstance(item.value, str) for item in mine.included("package"))
        decisions: list[Decision] = []
        for candidate in _candidates(releases, sources, collections):
            if not candidate.product and not candidate.packages:
                continue
            for affected in affected_entries:
                label = f"{affected.get('vendor')} {affected.get('product')}"
                for version, components, how in entry_matches(
                        affected, candidate, collections, osv_knows):
                    if how == "vendor_mismatch":
                        decisions.append(Decision(
                            candidate.release, cve, "inconclusive", None,
                            f"{cve}'s record names {label}; the release's supplier "
                            f"{candidate.row.value('supplier_name')!r} is a different vendor."))
                        continue
                    status, why = _product_decision(affected, version)
                    decisions.append(Decision(
                        candidate.release, cve, status,
                        "vulnerable_code_not_present" if status == "not_affected" else None,
                        f"{cve}'s CVE record lists {label} ({how}): for version {version} "
                        f"{why}.", components if status == "affected" else ()))
        # One answer per release: an inconclusive one never stands beside a decided one.
        merged: dict[str, Decision] = {}
        for decision in decisions:
            prior = merged.get(decision.release.path)
            if prior is None or (
                prior.status == "inconclusive" and decision.status != "inconclusive"
            ):
                merged[decision.release.path] = decision
            elif prior.status == decision.status and decision.components:
                merged[decision.release.path] = Decision(
                    decision.release, cve, decision.status, decision.justification,
                    prior.rationale, tuple(sorted(set(prior.components)
                                                  | set(decision.components))))
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
        # The record's title: that a record of the CVE was read (an incident's RQ1 asks
        # for one until then).
        title = _record_title(record)
        created = any(item.get("subject_kind") == VULNERABILITY for item in items)
        bound = mine.subject("vulnerability") if mine is not None else None
        held_title = mine.value("title") if mine is not None else None
        if title is not None and held_title != title and (bound is not None or created):
            claims = [item for item in items if not item.get("subject_kind")]
            claims.append(claim_item(
                bound or key_ref(VULNERABILITY, cve_id=cve), TITLE, title,
                f"{cve}'s CVE record states its title.",
                revises=mine.claim_id(bound, TITLE) if mine is not None and bound is not None
                and held_title else None))
            items = [item for item in items if item.get("subject_kind")] + sorted_items(claims)
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
