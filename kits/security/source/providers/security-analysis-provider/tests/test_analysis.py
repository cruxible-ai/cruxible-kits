"""Each analysis proposes exactly what changed, names Subjects by path or key, and is idempotent."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_runtime.protocol import Budgets
from cruxible_provider_runtime.provider_api import ProviderRunContext
from cruxible_provider_runtime.registration import load_registration

import security_analysis_provider
from security_analysis_provider.applicability import (
    CveApplicability,
    OsvApplicability,
    cpe_identity,
    package_purl,
    purl_package,
    version_key,
)
from security_analysis_provider.common import component_set
from security_analysis_provider.epss import EpssTriage
from security_analysis_provider.kev import KevAttention, KevTriage
from security_analysis_provider.sbom import CycloneDxComponents

DATA = Path(__file__).parent / "data"
CATALOG = {
    "catalogVersion": "2026.10.04",
    "dateReleased": "2026-10-04T18:00:00Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Example Corp",
            "product": "Widget Server",
            "vulnerabilityName": "Widget Server auth bypass",
            "dateAdded": "2026-10-03",
            "dueDate": "2026-10-24",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def _run(provider: Any, payload: dict[str, Any]) -> dict[str, Any]:
    result = provider(
        ProviderRunContext(
            run_id="test",
            input=payload,
            interface_id=provider.interface_id,
            interface_digest="sha256:" + "0" * 64,
            implementation_digest="sha256:" + "1" * 64,
            declared_endpoints=(),
            input_bucket="test",
            budgets=Budgets(wall_clock_seconds=30, output_bytes=10_000_000),
            coordinates={},
            capture_contract=None,
            secrets={},
            egress=EgressRecorder(),
        )
    )
    assert result.status == "ok", result
    assert result.output is not None
    return result.output


def _row(
    bindings: dict[str, tuple[str, str]],
    claims: dict[tuple[str, str], str] | None = None,
    **fields: object,
) -> dict[str, Any]:
    """A state-tap row: binding -> (kind, id); (binding, predicate) -> claim id."""

    def bound(kind: str, subject_id: str) -> dict[str, str]:
        return {
            "subject_kind": kind,
            "subject_id": subject_id,
            "subject_path": f"subjects/{kind}/{subject_id}.json",
            "subject_identity": f"Subject:{kind}/{subject_id}",
        }

    return {
        "bindings": [{"binding": name, **bound(*spec)} for name, spec in bindings.items()],
        "fields": [
            {"name": name, "state": "present", "value": value}
            for name, value in sorted(fields.items())
        ],
        "read_claims": [
            {
                "claim_path": f"claims/00/{claim}.json",
                "predicate": predicate,
                "subject_identity": f"Subject:{bindings[binding][0]}/{bindings[binding][1]}",
            }
            for (binding, predicate), claim in (claims or {}).items()
        ],
    }


def _includes(**named: list[str]) -> list[dict[str, Any]]:
    """A row's includes: name -> literal values (each its own Claim)."""

    return [{"name": name, "items": [
        {"claim_object": {"kind": "literal", "value": value},
         "visibility": {"claim_path": f"claims/00/CLM-{name}-{index}.json"}}
        for index, value in enumerate(values)]} for name, values in named.items()]


def _vuln(cve: str, claims: dict[str, str] | None = None, *, packages: list[str] | None = None,
          **fields: object) -> dict[str, Any]:
    subject = ("security.vulnerability", cve.lower())
    row = _row(
        {"vulnerability": subject},
        {("vulnerability", f"security.vulnerability.{k}"): v for k, v in (claims or {}).items()},
        cve_id=cve,
        **fields,
    )
    if packages:
        row["includes"] = _includes(package=packages)
    return row


def _release(
    product: str, version: str, components: list[str] | None = None, supplier: str | None = None,
    *, coverage: str | None = None, aliases: list[str] | None = None,
) -> dict[str, Any]:
    rid = f"{product}--{version}"
    bindings = {"release": ("security.release", rid), "product": ("security.product", product)}
    fields: dict[str, Any] = {"product_name": product, "version": version}
    if supplier:
        bindings["supplier"] = ("security.supplier", supplier.lower().replace(" ", "-"))
        fields["supplier_name"] = supplier.lower()
    if components:
        fields["components"] = components
    claims = {}
    if coverage:
        fields["osv_coverage"] = coverage
        claims[("release", "security.release.osv_coverage")] = f"CLM-coverage-{rid}"
    if aliases:
        fields["product_alias"] = aliases
    return _row(bindings, claims, **fields)


def _catalog_b64() -> str:
    return base64.b64encode(json.dumps(CATALOG).encode()).decode()


def _statements(items: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    found = []
    for item in items:
        if "statement" not in item:
            continue
        statement = item["statement"]
        subject = statement["subject"]
        subject = subject.get("artifact_path") or json.dumps(subject["key"], sort_keys=True)
        obj = statement["object"]
        found.append(
            (
                subject,
                statement["predicate"].rsplit(".", 1)[-1],
                obj.get("value", obj.get("subject", obj.get("address"))),
            )
        )
    return sorted(found, key=json.dumps)


# --- KEV ------------------------------------------------------------------------


def test_kev_triage_proposes_changed_fields_by_path_and_nothing_for_a_held_catalog() -> None:
    output = _run(
        KevTriage(),
        {
            "catalog_base64": _catalog_b64(),
            "watched": [_vuln("CVE-2021-44228"), _vuln("CVE-2021-44832")],
        },
    )
    assert _statements(output["items"]) == [
        ("subjects/security.vulnerability/cve-2021-44228.json", "kev_date_added", "2021-12-10"),
        ("subjects/security.vulnerability/cve-2021-44228.json", "kev_due_date", "2021-12-24"),
        ("subjects/security.vulnerability/cve-2021-44228.json", "kev_listed", True),
        ("subjects/security.vulnerability/cve-2021-44228.json", "kev_ransomware_use", "known"),
        ("subjects/security.vulnerability/cve-2021-44832.json", "kev_listed", False),
    ]
    assert (output["changed"], output["listed"], output["watched"]) == (5, 1, 2)
    held = _run(
        KevTriage(),
        {
            "catalog_base64": _catalog_b64(),
            "watched": [
                _vuln(
                    "CVE-2021-44228",
                    kev_listed=True,
                    kev_date_added="2021-12-10",
                    kev_due_date="2021-12-24",
                    kev_ransomware_use="known",
                ),
                _vuln("CVE-2021-44832", kev_listed=False),
            ],
        },
    )
    assert held["items"] == [] and held["changed"] == 0
    revised = _run(
        KevTriage(),
        {
            "catalog_base64": _catalog_b64(),
            "watched": [
                _vuln("CVE-2021-44228", {"kev_listed": "CLM-" + "a" * 32}, kev_listed=False)
            ],
        },
    )
    listed = [i for i in revised["items"] if i["statement"]["predicate"].endswith("kev_listed")]
    assert listed[0]["revises"] == "CLM-" + "a" * 32


def test_kev_attention_posts_new_listings_matching_unwatched_or_unassessed_inventory() -> None:
    widget = _release("widget server", "4.2", supplier="Example Corp")
    log4j = _release("log4j2", "2.14.1", supplier="Apache")
    payload = {
        "catalog_base64": _catalog_b64(),
        "releases": [widget, log4j],
        "watched": [],
        "assessments": [],
    }
    output = _run(KevAttention(), payload)
    # Log4Shell was added years before the catalog's release date: not new.
    assert [(p["cve_id"], p["gap"], p["release"]) for p in output["items"]] == [
        ("CVE-2026-0001", "not_watched", "subjects/security.release/widget server--4.2.json")
    ]
    assert output["newly_listed"] == 1
    watched = _run(KevAttention(), {**payload, "watched": [_vuln("CVE-2026-0001")]})
    assert [p["gap"] for p in watched["items"]] == ["no_assessment"]
    assessed = _row(
        {"assessment": ("security.assessment", "a")},
        cve_id="CVE-2026-0001",
        release_id="widget server--4.2",
        status="not_affected",
    )
    done = _run(
        KevAttention(), {**payload, "watched": [_vuln("CVE-2026-0001")], "assessments": [assessed]}
    )
    assert done["items"] == []
    # The same situation posts the same bytes, so core's inbox dedupe counts a sighting.
    assert _run(KevAttention(), payload)["items"] == output["items"]


# --- EPSS -----------------------------------------------------------------------


def _epss(rows: str) -> str:
    text = (
        "#model_version:v2026.06.15,score_date:2026-10-10T12:00:23Z\ncve,epss,percentile\n" + rows
    )
    return base64.b64encode(gzip.compress(text.encode(), mtime=0)).decode()


def test_epss_triage_states_scores_verbatim_and_revises_only_changes() -> None:
    daily = _epss("CVE-2021-44228,0.99999,1.00000\nCVE-2024-34064,0.00979,0.61101\n")
    output = _run(
        EpssTriage(),
        {
            "daily_base64": daily,
            "watched": [
                _vuln("CVE-2021-44228"),
                _vuln(
                    "CVE-2024-34064",
                    {"epss_score": "CLM-" + "b" * 32},
                    epss_score="0.00900",
                    epss_percentile="0.61101",
                ),
                _vuln("CVE-2099-0001"),
            ],
        },
    )
    assert _statements(output["items"]) == [
        ("subjects/security.vulnerability/cve-2021-44228.json", "epss_percentile", "1.00000"),
        ("subjects/security.vulnerability/cve-2021-44228.json", "epss_score", "0.99999"),
        ("subjects/security.vulnerability/cve-2024-34064.json", "epss_score", "0.00979"),
    ]
    revising = [i for i in output["items"] if i["revises"]]
    assert [i["revises"] for i in revising] == ["CLM-" + "b" * 32]
    assert (output["watched"], output["scored"], output["model_version"]) == (3, 2, "v2026.06.15")


# --- SBOM -----------------------------------------------------------------------

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "component": {
            "type": "application",
            "name": "Cruxible-Core",
            "version": "0.3.2",
            "supplier": {"name": "Cruxible"},
        }
    },
    "components": [
        {"type": "library", "name": "jinja2", "version": "3.1.3", "purl": "pkg:pypi/jinja2@3.1.3"},
        {"type": "library", "name": "httpx", "version": "0.28.1", "purl": "pkg:pypi/httpx@0.28.1"},
        {"type": "library", "name": "nopurl", "version": "1"},
    ],
}


def test_sbom_import_creates_by_key_and_reimports_nothing() -> None:
    output = _run(CycloneDxComponents(), {"sbom_text": json.dumps(SBOM), "releases": []})
    subjects = [(i["subject_kind"], i["key"]) for i in output["items"] if "key" in i]
    assert subjects == [
        ("security.product", {"name": "Cruxible-Core"}),
        ("security.release", {"product_name": "Cruxible-Core", "version": "0.3.2"}),
        ("security.supplier", {"name": "Cruxible"}),
    ]
    components = [s[2] for s in _statements(output["items"]) if s[1] == "component"]
    assert components == ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"]
    assert (output["components"], output["added"], output["skipped"]) == (2, 2, 1)
    held = _release(
        "cruxible-core",
        "0.3.2",
        ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"],
        supplier="Cruxible",
    )
    # The component without a purl is counted on the release (OSV can't be asked about it).
    assert [s[2] for s in _statements(output["items"]) if s[1] == "unidentified_components"] == [1]
    held["fields"].append({"name": "unidentified", "state": "present", "value": 1})
    again = _run(CycloneDxComponents(), {"sbom_text": json.dumps(SBOM), "releases": [held]})
    assert again["items"] == [] and again["changed"] == 0
    # A later SBOM of the release with every component identified revises the count to 0.
    held["read_claims"].append({"claim_path": "claims/00/CLM-unidentified.json",
                                "predicate": "security.release.unidentified_components",
                                "subject_identity":
                                    "Subject:security.release/cruxible-core--0.3.2"})
    named = json.loads(json.dumps(SBOM))
    named["components"] = named["components"][:2]
    (item,) = _run(CycloneDxComponents(), {"sbom_text": json.dumps(named),
                                           "releases": [held]})["items"]
    assert item["statement"]["object"]["value"] == 0 and item["revises"] == "CLM-unidentified"


def _held_release(version: str, components: list[str], supplier: str = "Cruxible") -> dict:
    return _row(
        {
            "release": ("security.release", f"cruxible-core--{version}"),
            "product": ("security.product", "cruxible-core"),
            "supplier": ("security.supplier", supplier.lower()),
        },
        {("product", "security.product.supplied_by"): "CLM-" + "5" * 32},
        product_name="cruxible-core",
        version=version,
        supplier_name=supplier.lower(),
        components=components,
        unidentified=1,
    )


def test_a_new_version_reuses_the_product_and_restates_nothing_it_holds() -> None:
    held = _held_release("0.3.1", ["pkg:pypi/httpx@0.28.1"])
    sbom = json.loads(json.dumps(SBOM))
    sbom["metadata"]["component"]["name"] = "cruxible-core"
    output = _run(CycloneDxComponents(), {"sbom_text": json.dumps(sbom), "releases": [held]})
    subjects = [(i["subject_kind"], i["key"]) for i in output["items"] if "key" in i]
    assert subjects == [("security.release", {"product_name": "cruxible-core", "version": "0.3.2"})]
    predicates = sorted(s[1] for s in _statements(output["items"]))
    assert predicates == ["component", "component", "product",
                          "unidentified_components"]  # no supplied_by restated


def test_a_changed_sbom_for_a_held_release_adds_only_its_new_components() -> None:
    held = _held_release("0.3.2", ["pkg:pypi/httpx@0.28.1"])
    sbom = json.loads(json.dumps(SBOM))
    sbom["metadata"]["component"]["name"] = "cruxible-core"
    output = _run(CycloneDxComponents(), {"sbom_text": json.dumps(sbom), "releases": [held]})
    assert [i for i in output["items"] if "key" in i] == []
    assert [s[2] for s in _statements(output["items"])] == ["pkg:pypi/jinja2@3.1.3"]


def test_a_changed_supplier_revises_the_held_one() -> None:
    held = _held_release(
        "0.3.2", ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"], supplier="Someone Else"
    )
    sbom = json.loads(json.dumps(SBOM))
    sbom["metadata"]["component"]["name"] = "cruxible-core"
    output = _run(CycloneDxComponents(), {"sbom_text": json.dumps(sbom), "releases": [held]})
    revising = [
        i
        for i in output["items"]
        if i.get("statement", {}).get("predicate") == "security.product.supplied_by"
    ]
    assert [i["revises"] for i in revising] == ["CLM-" + "5" * 32]


# --- OSV applicability ---------------------------------------------------------


def _exchange(
    method: str, path: str, body: object, request: object = None, status: int = 200
) -> dict:
    raw = json.dumps(body).encode()
    return {
        "method": method,
        "path": path,
        "request": request,
        "status": status,
        "body_sha256": "sha256:" + "0" * 64,
        "body_base64": base64.b64encode(raw).decode(),
    }


JINJA_GHSA = {
    "id": "GHSA-h75v-3vvj-5mfj",
    "aliases": ["CVE-2024-34064"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "jinja2", "purl": "pkg:pypi/jinja2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4"}]}],
        }
    ],
}
GHSA_ONLY = {"id": "GHSA-xxxx-only", "aliases": [], "affected": []}
OSV = {
    "exchanges": [
        _exchange(
            "POST",
            "/v1/querybatch",
            {"results": [{}, {"vulns": [{"id": "GHSA-h75v-3vvj-5mfj"}, {"id": "GHSA-xxxx-only"}]},
                         {}]},
            {"purls": ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3",
                       "pkg:pypi/jinja2@3.1.4"]},
        ),
        _exchange("GET", "/v1/vulns/GHSA-h75v-3vvj-5mfj", JINJA_GHSA),
        _exchange("GET", "/v1/vulns/GHSA-xxxx-only", GHSA_ONLY),
        _exchange(
            "GET",
            "/v1/vulns/CVE-2024-34064",
            {"id": "CVE-2024-34064", "aliases": ["GHSA-h75v-3vvj-5mfj"]},
        ),
    ]
}


def _covered(text: str, *components: str) -> str:
    """A coverage value bound to its exact component set."""

    return f"{text}; set {component_set(components)}"


COMPLETE = {1: "complete: 1 of 1 components answered", 2: "complete: 2 of 2 components answered"}
HTTPX, JINJA, JINJA_FIXED = ("pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3",
                             "pkg:pypi/jinja2@3.1.4")


def test_osv_applicability_decides_each_release_and_watches_what_it_finds() -> None:
    first = [_release("cruxible-core", "0.3.2", ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"]),
             _release("cruxible-client", "0.3.2", ["pkg:pypi/httpx@0.28.1"]),
             _release("other", "1.0", ["pkg:pypi/jinja2@3.1.4"])]
    output = _run(
        OsvApplicability(),
        {"osv": OSV, "releases": first, "watched": [], "assessments": []},
    )
    assert output["unkeyed"] == ["GHSA-xxxx-only"]
    # One coverage Claim per release: OSV answered every component of each.
    assert {s[0]: s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"} == {
        "subjects/security.release/cruxible-client--0.3.2.json": _covered(COMPLETE[1], HTTPX),
        "subjects/security.release/cruxible-core--0.3.2.json": _covered(COMPLETE[2], HTTPX,
                                                                         JINJA),
        "subjects/security.release/other--1.0.json": _covered(COMPLETE[1], JINJA_FIXED)}
    # What OSV says the CVE it starts watching affects (OSV knows the CVE).
    assert [(json.loads(s[0]), s[2]) for s in _statements(output["items"])
            if s[1] == "package"] == [({"cve_id": "CVE-2024-34064"}, "pkg:pypi/jinja2")]
    assert (output["coverage"], output["packages"]) == (3, 1)
    core = _release("cruxible-core", "0.3.2", ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"],
                    coverage=_covered(COMPLETE[2], HTTPX, JINJA))
    client = _release("cruxible-client", "0.3.2", ["pkg:pypi/httpx@0.28.1"],
                      coverage=_covered(COMPLETE[1], HTTPX))
    fixed = _release("other", "1.0", ["pkg:pypi/jinja2@3.1.4"],
                     coverage=_covered(COMPLETE[1], JINJA_FIXED))
    # Not watched yet: only the affected release is assessed, and the CVE is watched by key.
    keys = [(i["subject_kind"], i["key"]) for i in output["items"] if i.get("subject_kind")]
    assert keys == [
        ("security.vulnerability", {"cve_id": "CVE-2024-34064"}),
        ("security.assessment", {"cve_id": "CVE-2024-34064", "release_id": "cruxible-core--0.3.2"}),
    ]
    status = [s for s in _statements(output["items"]) if s[1] == "status"]
    assert [s[2] for s in status] == ["affected"]
    # The component that brings it in (urgent_exposures and triage show it).
    assert [s[2] for s in _statements(output["items"]) if s[1] == "component"] == [
        "pkg:pypi/jinja2@3.1.3"]
    # Watched: every release with a component of the CVE's packages gets an answer; a
    # release with none of them (client: no jinja2) is not assessed.
    watched = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core, client, fixed],
            "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])],
            "assessments": [],
        },
    )
    assert (watched["coverage"], watched["packages"]) == (0, 0)
    decided = {
        json.loads(s[0])["release_id"]: s[2]
        for s in _statements(watched["items"])
        if s[1] in {"status", "justification"} and s[2] not in {"affected", "not_affected"}
    }
    assert decided == {"other--1.0": "vulnerable_code_not_present"}
    assert (watched["affected"], watched["not_affected"]) == (1, 1)
    held = [
        _row(
            {"assessment": ("security.assessment", f"a{n}")},
            cve_id="CVE-2024-34064",
            release_id=rid,
            status=status,
            **({"justification": j} if j else {}),
        )
        for n, (rid, status, j) in enumerate(
            [
                ("cruxible-core--0.3.2", "affected", None),
                ("other--1.0", "not_affected", "vulnerable_code_not_present"),
            ]
        )
    ]
    # An assessment held without its component gains it, and nothing else: the affected
    # one what brings the CVE in, the not_affected one what its negative rests on.
    gains = _run(
        OsvApplicability(),
        {"osv": OSV, "releases": [core, client, fixed],
         "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])],
         "assessments": held},
    )
    assert [(s[1], s[2]) for s in _statements(gains["items"])] == [
        ("component", "pkg:pypi/jinja2@3.1.3"), ("component", "pkg:pypi/jinja2@3.1.4")]
    for row, purl in zip(held, ("pkg:pypi/jinja2@3.1.3", "pkg:pypi/jinja2@3.1.4"), strict=True):
        row["includes"] = [{"name": "component", "items": [{
            "claim_object": {"kind": "literal", "value": purl},
            "visibility": {"claim_path": f"claims/00/CLM-component-{purl[-5:]}.json"}}]}]
    again = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core, client, fixed],
            "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])],
            "assessments": held,
        },
    )
    assert again["items"] == [] and again["unchanged"] == 2


def test_a_flipped_answer_revises_status_and_retires_the_stale_justification() -> None:
    core = _release("cruxible-core", "0.3.2", ["pkg:pypi/jinja2@3.1.3"])
    held = _row(
        {"assessment": ("security.assessment", "a1")},
        {
            ("assessment", "security.assessment.status"): "CLM-" + "1" * 32,
            ("assessment", "security.assessment.justification"): "CLM-" + "2" * 32,
        },
        cve_id="CVE-2024-34064",
        release_id="cruxible-core--0.3.2",
        status="not_affected",
        justification="vulnerable_code_not_present",
        status_role="observation",
    )
    output = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core],
            "watched": [_vuln("CVE-2024-34064")],
            "assessments": [held],
        },
    )
    retire = [i for i in output["items"] if i["tag"].endswith("retirement-item-v1")]
    assert [i["retires"] for i in retire] == ["CLM-" + "2" * 32]
    status = [
        i for i in output["items"] if i.get("statement", {}).get("predicate", "").endswith("status")
    ]
    assert status[0]["revises"] == "CLM-" + "1" * 32
    assert status[0]["statement"]["object"]["value"] == "affected"


def test_an_analyst_judgment_is_never_revised_by_a_source() -> None:
    core = _release("cruxible-core", "0.3.2", ["pkg:pypi/jinja2@3.1.3"], coverage=(
        "partial: 0 of 1 components answered; unanswered 1"))
    judged = _row(
        {"assessment": ("security.assessment", "a1")},
        cve_id="CVE-2024-34064",
        release_id="cruxible-core--0.3.2",
        status="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        status_role="normative",
    )
    output = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core],
            "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])],
            "assessments": [judged],
        },
    )
    # (jinja2 3.1.3 is in the batch: its held partial coverage is revised to complete.)
    assert [(s[1], s[2]) for s in _statements(output["items"])] == [
        ("osv_coverage", _covered(COMPLETE[1], JINJA))]
    assert output["items"][0]["revises"] == "CLM-coverage-cruxible-core--0.3.2"
    assert output["judged"] == 1 and output["affected"] == 0


def test_osv_coverage_is_partial_where_osv_never_answered_and_decides_nothing_there() -> None:
    """A component OSV does not index is never asked: its release's coverage is partial (with
    the purl types), and no CVE is decided from OSV's silence about it (never none)."""

    osv = {**OSV, "not_indexed": [
        {"purl": "pkg:brew/gh@2.86.0", "type": "brew", "reason": "no OSV ecosystem for brew"},
        {"purl": "pkg:generic/php@8.3.10", "type": "generic", "reason": "no OSV ecosystem"},
        {"purl": "pkg:pypi/jinja2@3.1.5", "type": "pypi", "reason": "not listed"}]}
    mixed = _release("tooling", "1.0", ["pkg:brew/gh@2.86.0", "pkg:generic/php@8.3.10",
                                        "pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.5"],
                     coverage=COMPLETE[2])
    output = _run(OsvApplicability(), {
        "osv": osv, "releases": [mixed],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    (item,) = output["items"]
    assert item["statement"]["predicate"] == "security.release.osv_coverage"
    assert item["statement"]["object"]["value"] == _covered(
        "partial: 1 of 4 components answered; not indexed: brew 1, generic 1, pypi 1",
        *mixed["fields"][0]["value"])
    assert item["revises"] == "CLM-coverage-tooling--1.0"
    assert (output["inconclusive"], output["not_affected"]) == (0, 0)


def test_purls_and_versions_compare_conservatively() -> None:
    assert purl_package("pkg:pypi/Jinja_2@3.1.3?x=1") == ("pypi", "jinja-2")
    assert version_key("2.14.1") > version_key("2.13.0") > version_key("2.0-beta9")
    assert version_key("2.0") == version_key("2.0.0")
    assert version_key("not-a-version") is None


# --- CVE applicability ---------------------------------------------------------


def test_cve_record_decides_matching_products_by_range_and_flags_ambiguity() -> None:
    record = base64.b64encode((DATA / "CVE-2021-44228.json").read_bytes()).decode()
    releases = [
        _release("apache log4j2", "2.14.1", supplier="Apache Software Foundation"),
        _release("apache log4j2", "2.12.2"),
        _release("apache log4j2", "2.17.1"),
        _release("log4j2", "2.14.1"),
        _release("apache log4j2", "2.14.0", supplier="Other Vendor"),
        _release("nginx", "1.25.0"),
    ]
    output = _run(
        CveApplicability(),
        {"record_base64": record, "releases": releases, "watched": [], "assessments": [],
         "sources": [], "collections": COLLECTIONS},
    )
    status = {
        json.loads(s[0])["release_id"]: s[2]
        for s in _statements(output["items"])
        if s[1] == "status"
    }
    # "log4j2" only partly matches "Apache Log4j2": no match, no assessment (never a guess).
    assert status == {
        "apache log4j2--2.14.1": "affected",
        "apache log4j2--2.12.2": "not_affected",
        "apache log4j2--2.17.1": "not_affected",
        "apache log4j2--2.14.0": "inconclusive",
    }
    assert output["cve_id"] == "CVE-2021-44228"
    # The record's title marks the CVE read (stated with the vulnerability it creates).
    (title,) = [s for s in _statements(output["items"]) if s[1] == "title"]
    assert title[0] == json.dumps({"cve_id": "CVE-2021-44228"}) and "Log4j2" in title[2]


#: The kit data cve-applicability carries.
COLLECTIONS = json.loads((Path(__file__).resolve().parents[3] / "authoring" / "data" /
                          "cve_collections.json").read_text())
GH_CVE = "CVE-2026-110311"


def _gh_record(**entry: object) -> str:
    affected = {"vendor": "cli", "product": "cli", "defaultStatus": "unaffected",
                "versions": [{"version": "2.40.0", "lessThan": "2.97.0", "status": "affected",
                              "versionType": "semver"}], **entry}
    record = {"cveMetadata": {"cveId": GH_CVE},
              "containers": {"cna": {"title": "gh auth status prints a token suffix",
                                     "descriptions": [{"lang": "en", "value": "..."}],
                                     "affected": [affected]}}}
    return base64.b64encode(json.dumps(record).encode()).decode()


def _decide(record: str, releases: list[dict[str, Any]], *, sources: list[Any] | None = None,
            watched: list[dict[str, Any]] | None = None) -> dict[str, str]:
    output = _run(CveApplicability(), {
        "record_base64": record, "releases": releases, "watched": watched or [],
        "assessments": [], "sources": sources or [], "collections": COLLECTIONS})
    return {json.loads(s[0])["release_id"]: s[2] for s in _statements(output["items"])
            if s[1] == "status"}


def test_a_record_matches_a_go_module_by_collection_url_and_package_name() -> None:
    go = _release("github.com/cli/cli/v2", "v2.86.0",
                  ["pkg:golang/github.com/cli/cli/v2@v2.86.0"])
    fixed = _release("github.com/cli/cli/v2", "v2.97.0",
                     ["pkg:golang/github.com/cli/cli/v2@v2.97.0"])
    app = _release("tooling", "1.0", ["pkg:golang/github.com/cli/cli/v2@v2.90.1",
                                      "pkg:pypi/httpx@0.28.1"])
    brew = _release("gh", "2.86.0", ["pkg:brew/gh@2.86.0"])
    record = _gh_record(collectionURL="https://pkg.go.dev",
                        packageName="github.com/cli/cli/v2")
    output = _run(CveApplicability(), {
        "record_base64": record, "releases": [go, fixed, app, brew], "watched": [],
        "assessments": [], "sources": [], "collections": COLLECTIONS})
    found = {}
    for s_ in _statements(output["items"]):
        if s_[1] in {"status", "component"}:
            found.setdefault(json.loads(s_[0])["release_id"], []).append(s_[2])
    # Decided by the component's own version; Homebrew's gh is not named (no assessment).
    assert {release: sorted(values) for release, values in found.items()} == {
        "github.com/cli/cli/v2--v2.86.0": ["affected",
                                           "pkg:golang/github.com/cli/cli/v2@v2.86.0"],
        # A negative decided through a component names it: it rests on that component.
        "github.com/cli/cli/v2--v2.97.0": ["not_affected",
                                           "pkg:golang/github.com/cli/cli/v2@v2.97.0"],
        "tooling--1.0": ["affected", "pkg:golang/github.com/cli/cli/v2@v2.90.1"]}


def test_an_analysts_alias_and_a_source_repository_name_a_release() -> None:
    record = _gh_record(repo="https://github.com/cli/cli")
    # Homebrew's gh is named only once an analyst states what it is.
    plain = _release("gh", "2.86.0", ["pkg:brew/gh@2.86.0"])
    assert _decide(record, [plain]) == {}
    aliased = _release("gh", "2.86.0", ["pkg:brew/gh@2.86.0"], aliases=["cli/cli"])
    assert _decide(record, [aliased]) == {"gh--2.86.0": "affected"}
    for alias in ("https://github.com/cli/cli", "cpe:2.3:a:github:cli"):
        record_cpe = _gh_record(cpes=["cpe:2.3:a:github:cli:*:*:*:*:*:*:*:*"], vendor="x",
                                product="y")
        release = _release("gh", "2.86.0", ["pkg:brew/gh@2.86.0"], aliases=[alias])
        expected = {"gh--2.86.0": "affected"}
        assert _decide(record_cpe if alias.startswith("cpe") else record, [release]) == (
            expected), alias
    # A release the system model knows is published from the repository.
    built = _release("cli-build", "2.80.0")
    sources = [_row({"release": ("security.release", "cli-build--2.80.0"),
                     "repo": ("security.repo", "github.com--cli-cli")},
                    forge_host="github.com", full_name="cli/cli")]
    assert _decide(record, [built], sources=sources) == {"cli-build--2.80.0": "affected"}


def test_github_style_version_constraints_are_read_as_written() -> None:
    record = _gh_record(versions=[{"version": ">= 2.40.0, < 2.97.0", "status": "affected"}])
    releases = [_release("gh", v, ["pkg:brew/gh@" + v], aliases=["cli/cli"])
                for v in ("2.39.0", "2.86.0", "2.97.0")]
    assert _decide(record, releases) == {"gh--2.39.0": "not_affected",
                                         "gh--2.86.0": "affected", "gh--2.97.0": "not_affected"}


def test_a_release_osv_answered_for_is_osvs_once_osv_knows_the_cve() -> None:
    record = _gh_record(collectionURL="https://pkg.go.dev", packageName="github.com/cli/cli/v2")
    go = _release("github.com/cli/cli/v2", "v2.86.0",
                  ["pkg:golang/github.com/cli/cli/v2@v2.86.0"],
                  coverage=_covered(COMPLETE[1], "pkg:golang/github.com/cli/cli/v2@v2.86.0"))
    known = [_vuln(GH_CVE, packages=["pkg:golang/github.com/cli/cli/v2"])]
    assert _decide(record, [go], watched=known) == {}
    # OSV does not know the CVE (no package): the record decides, whatever OSV answered.
    assert _decide(record, [go], watched=[_vuln(GH_CVE)]) == {
        "github.com/cli/cli/v2--v2.86.0": "affected"}
    # A held title is not restated; a changed one revises it.
    watched = [_vuln(GH_CVE, {"title": "CLM-title"},
                     title="gh auth status prints a token suffix")]
    # (the products it names held as the record states them)
    watched[0]["includes"] = _includes(affected_product=["cli", "github.com/cli/cli/v2"])
    output = _run(CveApplicability(), {
        "record_base64": record, "releases": [], "watched": watched, "assessments": [],
        "sources": [], "collections": COLLECTIONS})
    assert output["items"] == []
    watched[0]["fields"] = [f for f in watched[0]["fields"] if f["name"] != "title"] + [
        {"name": "title", "state": "present", "value": "old title"}]
    (item,) = _run(CveApplicability(), {
        "record_base64": record, "releases": [], "watched": watched, "assessments": [],
        "sources": [], "collections": COLLECTIONS})["items"]
    assert item["revises"] == "CLM-title"


def test_the_registration_verifies() -> None:
    load_registration(Path(security_analysis_provider.__file__).parent)


def test_a_vulnerability_on_several_watched_paths_is_triaged_once() -> None:
    row = _vuln("CVE-2021-44228")
    output = _run(KevTriage(), {"catalog_base64": _catalog_b64(), "watched": [row, row]})
    assert output["watched"] == 1 and output["changed"] == 4


# --- K1 review regressions: negatives need complete, exact, bound evidence -------------


def test_any_affected_component_makes_the_release_affected_whatever_the_order() -> None:
    """F-001: three copies of one module; the first disagreement never gets overwritten."""

    record = _gh_record(collectionURL="https://pkg.go.dev", packageName="github.com/cli/cli/v2")
    copies = ["pkg:golang/github.com/cli/cli/v2@v2.86.0",
              "pkg:golang/github.com/cli/cli/v2@v2.97.0",
              "pkg:golang/github.com/cli/cli/v2@v2.98.0"]
    for order in (copies, copies[::-1], copies[1:] + copies[:1]):
        assert _decide(record, [_release("tooling", "1.0", order)]) == {
            "tooling--1.0": "affected"}, order
    # Unknown beside fixed: never not_affected.
    unordered = ["pkg:golang/github.com/cli/cli/v2@not-a-version",
                 "pkg:golang/github.com/cli/cli/v2@v2.97.0"]
    assert _decide(record, [_release("tooling", "1.0", unordered)]) == {
        "tooling--1.0": "inconclusive"}
    # Every copy fixed: not_affected, resting on every copy.
    output = _run(CveApplicability(), {
        "record_base64": record, "releases": [_release("tooling", "1.0", copies[1:])],
        "watched": [], "assessments": [], "sources": [], "collections": COLLECTIONS})
    found = sorted((s[1], s[2]) for s in _statements(output["items"])
                   if s[1] in ("status", "component"))
    assert found == [("component", copies[1]), ("component", copies[2]),
                     ("status", "not_affected")]


def test_a_fixed_package_beside_an_unanswered_component_is_never_not_affected() -> None:
    """F-002: OSV answered jinja2 3.1.4 (fixed) but never the Homebrew component."""

    osv = {**OSV, "not_indexed": [{"purl": "pkg:brew/wget@1.24", "type": "brew",
                                   "reason": "no OSV ecosystem for brew"}]}
    mixed = _release("tooling", "1.0", ["pkg:brew/wget@1.24", JINJA_FIXED])
    output = _run(OsvApplicability(), {
        "osv": osv, "releases": [mixed],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    status = [s[2] for s in _statements(output["items"]) if s[1] == "status"]
    assert status == ["inconclusive"] and output["not_affected"] == 0
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage.startswith("partial: 1 of 2 components answered; not indexed: brew 1")
    # An SBOM component without a purl keeps the coverage partial too.
    unidentified = _release("other", "1.0", [JINJA_FIXED])
    unidentified["fields"].append({"name": "unidentified", "state": "present", "value": 1})
    output = _run(OsvApplicability(), {
        "osv": OSV, "releases": [unidentified],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    assert [s[2] for s in _statements(output["items"]) if s[1] == "status"] == ["inconclusive"]
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage.startswith("partial: 1 of 1 components answered; unidentified 1; set ")


def test_coverage_is_bound_to_the_exact_component_set() -> None:
    """F-006: one component replaced by another keeps the count, never the coverage."""

    before = _covered(COMPLETE[1], HTTPX)
    replaced = _release("cruxible-client", "0.3.2", [JINJA_FIXED], coverage=before)
    output = _run(OsvApplicability(), {"osv": OSV, "releases": [replaced], "watched": [],
                                       "assessments": []})
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage == _covered(COMPLETE[1], JINJA_FIXED) != before


def test_an_unreadable_advisory_record_leaves_its_component_unanswered() -> None:
    """F-007: a batch hit whose GHSA record fetch failed (HTTP 500) is not complete."""

    osv = {"exchanges": [
        _exchange("POST", "/v1/querybatch", {"results": [{"vulns": [{"id": "GHSA-gone"}]}]},
                  {"purls": [JINJA_FIXED]}),
        _exchange("GET", "/v1/vulns/GHSA-gone", {"message": "internal"}, status=500),
        _exchange("GET", "/v1/vulns/GHSA-h75v-3vvj-5mfj", JINJA_GHSA)]}
    release = _release("other", "1.0", [JINJA_FIXED])
    output = _run(OsvApplicability(), {
        "osv": osv, "releases": [release],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage.startswith("partial: 0 of 1 components answered; unanswered 1")
    assert [s[2] for s in _statements(output["items"]) if s[1] == "status"] == ["inconclusive"]


def test_scoped_npm_packages_round_trip() -> None:
    """F-012: the kit reads back the package claims it writes."""

    for purl in ("pkg:npm/@angular/core", "pkg:npm/%40angular/core@17.0.0",
                 "pkg:npm/%40angular/core"):
        assert purl_package(purl) == ("npm", "@angular/core"), purl
    assert package_purl(("npm", "@angular/core")) == "pkg:npm/%40angular/core"
    assert purl_package(package_purl(("npm", "@angular/core"))) == ("npm", "@angular/core")
    assert purl_package(package_purl(("golang", "github.com/cli/cli/v2"))) == (
        "golang", "github.com/cli/cli/v2")
    record = _gh_record(collectionURL="https://registry.npmjs.org", packageName="@angular/core",
                        versions=[{"version": "0", "lessThan": "17.0.1", "status": "affected"}])
    app = _release("web", "1.0", ["pkg:npm/%40angular/core@17.0.0"])
    assert _decide(record, [app]) == {"web--1.0": "affected"}


def test_cpe_and_supplier_identity_is_exact() -> None:
    """F-013: punctuation is identity; a vendor that merely contains the supplier is
    another vendor."""

    assert cpe_identity("cpe:2.3:a:foo-bar:widget:1.0:*:*:*:*:*:*:*") == (
        "a", "foo-bar", "widget")
    assert cpe_identity("cpe:2.3:a:foo\\:bar:widget") == ("a", "foo:bar", "widget")
    assert cpe_identity("cpe:2.3:a:*:widget") is None
    record = _gh_record(cpes=["cpe:2.3:a:foobar:widget:*:*:*:*:*:*:*:*"], vendor="x",
                        product="y")
    aliased = _release("widget", "1.0", aliases=["cpe:2.3:a:foo-bar:widget"])
    assert _decide(record, [aliased]) == {}
    # Product name: the whole name (its name form), never letters and digits only.
    named = _gh_record(vendor="Example", product="foo-bar")
    assert _decide(named, [_release("foobar", "2.50.0")]) == {}
    assert _decide(named, [_release("Foo-Bar", "2.50.0")]) == {"Foo-Bar--2.50.0": "affected"}
    # Supplier: compared whole, never by substring.
    assert _decide(named, [_release("foo-bar", "2.50.0", supplier="Example Corp")]) == {
        "foo-bar--2.50.0": "inconclusive"}
    assert _decide(named, [_release("foo-bar", "2.50.0", supplier="example")]) == {
        "foo-bar--2.50.0": "affected"}


def test_a_forge_collection_names_the_source_repository() -> None:
    """F-015: collectionURL https://github.com + packageName cli/cli is github.com/cli/cli."""

    record = _gh_record(collectionURL="https://github.com", packageName="cli/cli")
    built = _release("cli-build", "2.80.0")
    sources = [_row({"release": ("security.release", "cli-build--2.80.0"),
                     "repo": ("security.repo", "github.com--cli-cli")},
                    forge_host="github.com", full_name="cli/cli")]
    assert _decide(record, [built], sources=sources) == {"cli-build--2.80.0": "affected"}
    assert _decide(record, [built]) == {}


def test_a_200_body_that_is_no_record_leaves_its_component_unanswered() -> None:
    """R-006: an HTTP 200 that doesn't establish which advisory it is is no record."""

    osv = {"exchanges": [
        _exchange("POST", "/v1/querybatch", {"results": [{"vulns": [{"id": "GHSA-unknown"}]}]},
                  {"purls": [JINJA_FIXED]}),
        _exchange("GET", "/v1/vulns/GHSA-unknown", {"message": "not a record"}),
        _exchange("GET", "/v1/vulns/GHSA-h75v-3vvj-5mfj", JINJA_GHSA)]}
    output = _run(OsvApplicability(), {
        "osv": osv, "releases": [_release("other", "1.0", [JINJA_FIXED])],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage.startswith("partial: 0 of 1 components answered; unanswered 1")
    assert [s[2] for s in _statements(output["items"]) if s[1] == "status"] == ["inconclusive"]


# --- K2: K1 recheck 2 (R2-001..R2-005) ---------------------------------------------------


def test_r2_001_a_record_states_the_products_it_names_whether_or_not_inventory_holds_them(
) -> None:
    """The record's affected entries are the roster RQ1 rules out per asset: a matched
    entry is its release's product, an unmatched one its own product or packageName."""

    record = _gh_record(collectionURL="https://pkg.go.dev",
                        packageName="github.com/cli/cli/v2")
    watched = [_vuln(GH_CVE)]
    output = _run(CveApplicability(), {
        "record_base64": record, "releases": [], "watched": watched, "assessments": [],
        "sources": [], "collections": COLLECTIONS})
    named = sorted(s[2] for s in _statements(output["items"]) if s[1] == "affected_product")
    assert named == ["cli", "github.com/cli/cli/v2"]
    # Through an analyst's alias, the entry is the aliased release's product.
    aliased = _release("gh", "2.86.0", ["pkg:brew/gh@2.86.0"], aliases=["cli/cli"])
    output = _run(CveApplicability(), {
        "record_base64": _gh_record(), "releases": [aliased], "watched": watched,
        "assessments": [], "sources": [], "collections": COLLECTIONS})
    assert sorted(s[2] for s in _statements(output["items"]) if s[1] == "affected_product") == [
        "gh"]
    # Held as stated: nothing to propose for it; a name the record dropped retires.
    held = _vuln(GH_CVE, title="gh auth status prints a token suffix")
    held["includes"] = _includes(affected_product=["gh", "old-name"])
    output = _run(CveApplicability(), {
        "record_base64": _gh_record(), "releases": [aliased], "watched": [held],
        "assessments": [], "sources": [], "collections": COLLECTIONS})
    assert not [s for s in _statements(output["items"]) if s[1] == "affected_product"]
    assert [i["retires"] for i in output["items"] if "retires" in i] == [
        "CLM-affected_product-1"]


def test_r2_002_a_contended_unidentified_count_never_makes_coverage_complete() -> None:
    release = _release("other", "1.0", [JINJA_FIXED])
    release["fields"].append({"name": "unidentified", "state": "conflict", "value": None})
    output = _run(OsvApplicability(), {
        "osv": OSV, "releases": [release],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    assert not [s for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert "not_affected" not in [s[2] for s in _statements(output["items"]) if s[1] == "status"]


def test_r2_003_a_record_names_its_advisory_by_id_or_a_whole_alias() -> None:
    from security_analysis_provider.applicability import osv_record_names

    assert osv_record_names(JINJA_GHSA, "GHSA-h75v-3vvj-5mfj")
    assert osv_record_names({**JINJA_GHSA, "id": "PYSEC-1", "aliases": ["GHSA-x"]}, "GHSA-x")
    for body in ({"id": "OTHER", "aliases": "not-GHSA-unknown-suffix", "affected": []},
                 {"id": "OTHER", "aliases": ["not-GHSA-unknown-suffix"], "affected": []},
                 {"id": "GHSA-unknown"}, {"id": "GHSA-unknown", "aliases": [1], "affected": []},
                 {"message": "not a record"}):
        assert not osv_record_names(body, "GHSA-unknown"), body
    osv = {"exchanges": [
        _exchange("POST", "/v1/querybatch", {"results": [{"vulns": [{"id": "GHSA-unknown"}]}]},
                  {"purls": [JINJA_FIXED]}),
        _exchange("GET", "/v1/vulns/GHSA-unknown",
                  {"id": "OTHER", "aliases": "not-GHSA-unknown-suffix", "affected": []})]}
    output = _run(OsvApplicability(), {
        "osv": osv, "releases": [_release("other", "1.0", [JINJA_FIXED])],
        "watched": [_vuln("CVE-2024-34064", packages=["pkg:pypi/jinja2"])], "assessments": []})
    (coverage,) = [s[2] for s in _statements(output["items"]) if s[1] == "osv_coverage"]
    assert coverage.startswith("partial: 0 of 1 components answered; unanswered 1")


def test_r2_005_nested_release_sbom_components_are_read_or_counted() -> None:
    from security_analysis_provider.sbom import read_sbom

    document = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                "metadata": {"component": {"name": "app", "version": "1.0"}},
                "components": [{"name": "httpx", "purl": "pkg:pypi/httpx@0.28.1",
                                "components": [
                                    {"name": "jinja2", "purl": "pkg:pypi/jinja2@3.1.3"},
                                    {"name": "vendored", "version": "?"},
                                    {"type": "operating-system", "name": "debian",
                                     "version": "12"}]}]}
    _, _, _, purls, unidentified = read_sbom(json.dumps(document))
    assert purls == ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"] and unidentified == 2
