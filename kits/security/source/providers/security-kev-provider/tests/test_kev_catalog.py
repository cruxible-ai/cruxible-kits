"""The KEV catalog provider proposes exactly the changed fields, and nothing for an identical catalog."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_runtime.protocol import Budgets
from cruxible_provider_runtime.provider_api import ProviderRunContext
from cruxible_provider_runtime.registration import load_registration

import security_kev_provider
from security_kev_provider.provider import KevCatalog, classify

CATALOG = {
    "catalogVersion": "2026.10.04",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    ],
}


def _row(subject_id: str, **fields: object) -> dict[str, object]:
    claims = []
    projected = []
    for index, (name, value) in enumerate(sorted(fields.items())):
        projected.append({"name": name, "state": "present", "value": value})
        claims.append(
            {
                "claim_path": f"claims/0{index}/CLM-{index:032x}.json",
                "predicate": f"security.vulnerability.{name}",
                "subject_identity": f"Subject:security.vulnerability/{subject_id}",
            }
        )
    return {
        "bindings": [
            {"binding": "vulnerability", "subject_kind": "security.vulnerability", "subject_id": subject_id}
        ],
        "fields": projected,
        "read_claims": claims,
    }


def _run(rows: list[dict[str, object]]) -> dict[str, object]:
    payload = {
        "catalog_base64": base64.b64encode(json.dumps(CATALOG).encode()).decode(),
        "watched": rows,
    }
    bucket = classify(payload)
    assert bucket == {"catalog": "present", "watchlist": "small"}
    result = KevCatalog()(
        ProviderRunContext(
            run_id="test",
            input=payload,
            interface_id="security.kev-catalog",
            interface_digest="sha256:" + "0" * 64,
            implementation_digest="sha256:" + "1" * 64,
            declared_endpoints=(),
            input_bucket="catalog=present;watchlist=small",
            budgets=Budgets(wall_clock_seconds=30, output_bytes=1_000_000),
            coordinates={},
            capture_contract=None,
            secrets={},
            egress=EgressRecorder(),
        )
    )
    assert result.status == "ok", result
    assert result.output is not None
    return result.output


def test_a_listed_and_an_absent_cve_propose_their_fields() -> None:
    output = _run([_row("cve-2021-44228"), _row("cve-2021-44832")])
    stated = sorted(
        (item["statement"]["subject"]["artifact_path"], item["statement"]["predicate"], item["statement"]["object"]["value"])
        for item in output["items"]
    )
    assert stated == [
        ("subjects/security.vulnerability/cve-2021-44228.json", "security.vulnerability.kev_date_added", "2021-12-10"),
        ("subjects/security.vulnerability/cve-2021-44228.json", "security.vulnerability.kev_due_date", "2021-12-24"),
        ("subjects/security.vulnerability/cve-2021-44228.json", "security.vulnerability.kev_listed", True),
        ("subjects/security.vulnerability/cve-2021-44228.json", "security.vulnerability.kev_ransomware_use", "known"),
        ("subjects/security.vulnerability/cve-2021-44832.json", "security.vulnerability.kev_listed", False),
    ]
    assert output["changed"] == 5 and output["listed"] == 1 and output["watched"] == 2
    assert all(item["revises"] is None for item in output["items"])


def test_an_identical_catalog_proposes_nothing_and_a_change_revises_the_held_claim() -> None:
    same = _run(
        [
            _row(
                "cve-2021-44228",
                kev_listed=True,
                kev_date_added="2021-12-10",
                kev_due_date="2021-12-24",
                kev_ransomware_use="known",
            ),
            _row("cve-2021-44832", kev_listed=False),
        ]
    )
    assert same["items"] == [] and same["changed"] == 0
    changed = _run([_row("cve-2021-44228", kev_listed=False)])
    revising = [i for i in changed["items"] if i["statement"]["predicate"].endswith("kev_listed")]
    assert revising[0]["revises"] == "CLM-" + "0" * 32


def test_the_registration_verifies() -> None:
    load_registration(Path(security_kev_provider.__file__).parent)
