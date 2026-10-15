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
    purl_package,
    version_key,
)
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


def _vuln(cve: str, claims: dict[str, str] | None = None, **fields: object) -> dict[str, Any]:
    subject = ("security.vulnerability", cve.lower())
    return _row(
        {"vulnerability": subject},
        {("vulnerability", f"security.vulnerability.{k}"): v for k, v in (claims or {}).items()},
        cve_id=cve,
        **fields,
    )


def _release(
    product: str, version: str, components: list[str] | None = None, supplier: str | None = None
) -> dict[str, Any]:
    rid = f"{product}--{version}"
    bindings = {"release": ("security.release", rid), "product": ("security.product", product)}
    fields: dict[str, Any] = {"product_name": product, "version": version}
    if supplier:
        bindings["supplier"] = ("security.supplier", supplier.lower().replace(" ", "-"))
        fields["supplier_name"] = supplier.lower()
    if components:
        fields["components"] = components
    return _row(bindings, **fields)


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
    again = _run(CycloneDxComponents(), {"sbom_text": json.dumps(SBOM), "releases": [held]})
    assert again["items"] == [] and again["changed"] == 0


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
    )


def test_a_new_version_reuses_the_product_and_restates_nothing_it_holds() -> None:
    held = _held_release("0.3.1", ["pkg:pypi/httpx@0.28.1"])
    sbom = json.loads(json.dumps(SBOM))
    sbom["metadata"]["component"]["name"] = "cruxible-core"
    output = _run(CycloneDxComponents(), {"sbom_text": json.dumps(sbom), "releases": [held]})
    subjects = [(i["subject_kind"], i["key"]) for i in output["items"] if "key" in i]
    assert subjects == [("security.release", {"product_name": "cruxible-core", "version": "0.3.2"})]
    predicates = sorted(s[1] for s in _statements(output["items"]))
    assert predicates == ["component", "component", "product"]  # no supplied_by restated


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
            {"results": [{}, {"vulns": [{"id": "GHSA-h75v-3vvj-5mfj"}, {"id": "GHSA-xxxx-only"}]}]},
            {"purls": ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"]},
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


def test_osv_applicability_decides_each_release_and_watches_what_it_finds() -> None:
    core = _release("cruxible-core", "0.3.2", ["pkg:pypi/httpx@0.28.1", "pkg:pypi/jinja2@3.1.3"])
    client = _release("cruxible-client", "0.3.2", ["pkg:pypi/httpx@0.28.1"])
    fixed = _release("other", "1.0", ["pkg:pypi/jinja2@3.1.4"])
    output = _run(
        OsvApplicability(),
        {"osv": OSV, "releases": [core, client, fixed], "watched": [], "assessments": []},
    )
    assert output["unkeyed"] == ["GHSA-xxxx-only"]
    # Not watched yet: only the affected release is assessed, and the CVE is watched by key.
    keys = [(i["subject_kind"], i["key"]) for i in output["items"] if i.get("subject_kind")]
    assert keys == [
        ("security.vulnerability", {"cve_id": "CVE-2024-34064"}),
        ("security.assessment", {"cve_id": "CVE-2024-34064", "release_id": "cruxible-core--0.3.2"}),
    ]
    status = [s for s in _statements(output["items"]) if s[1] == "status"]
    assert [s[2] for s in status] == ["affected"]
    # Watched: every release with a component of the CVE's packages gets an answer; a
    # release with none of them (client: no jinja2) is not assessed.
    watched = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core, client, fixed],
            "watched": [_vuln("CVE-2024-34064")],
            "assessments": [],
        },
    )
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
    again = _run(
        OsvApplicability(),
        {
            "osv": OSV,
            "releases": [core, client, fixed],
            "watched": [_vuln("CVE-2024-34064")],
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
    core = _release("cruxible-core", "0.3.2", ["pkg:pypi/jinja2@3.1.3"])
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
            "watched": [_vuln("CVE-2024-34064")],
            "assessments": [judged],
        },
    )
    assert output["items"] == [] and output["judged"] == 1 and output["affected"] == 0


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
        {"record_base64": record, "releases": releases, "watched": [], "assessments": []},
    )
    status = {
        json.loads(s[0])["release_id"]: s[2]
        for s in _statements(output["items"])
        if s[1] == "status"
    }
    assert status == {
        "apache log4j2--2.14.1": "affected",
        "apache log4j2--2.12.2": "not_affected",
        "apache log4j2--2.17.1": "not_affected",
        "log4j2--2.14.1": "inconclusive",
        "apache log4j2--2.14.0": "inconclusive",
    }
    assert output["cve_id"] == "CVE-2021-44228"


def test_the_registration_verifies() -> None:
    load_registration(Path(security_analysis_provider.__file__).parent)


def test_a_vulnerability_on_several_watched_paths_is_triaged_once() -> None:
    row = _vuln("CVE-2021-44228")
    output = _run(KevTriage(), {"catalog_base64": _catalog_b64(), "watched": [row, row]})
    assert output["watched"] == 1 and output["changed"] == 4
