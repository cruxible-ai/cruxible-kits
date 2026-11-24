"""SPDX JSON SBOMs and container distro packages, through the real Procedures.

An SPDX 2.3 SBOM imports through the same Line as a CycloneDX one: occurrences
with scopes from its relationships. A container SBOM's distro packages carry the
OSV package their SBOM states (``security.occurrence.osv_package``); the OSV Line
asks OSV by that source package (``Debian:12`` ``glibc``, not the binary
``libc6``), writes ``affected_by`` on the binary component, and leaves a distro
package whose release or source the SBOM does not state "not checked", never
clean. The provider runs in-process on a recorded-shape OSV answer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import dependency_replay
import inventory
import osv
import triage
from test_dependency_gate import affected_claim, get, query_rows
from test_inventory_gate import derived_document
from test_pilot_gate import Replay, import_sbom, kit_world, service_run, write_file

DATA = Path(__file__).resolve().parents[1] / "providers/security-osv-provider/tests/data"
IMAGE_PATH = "sboms/image.spdx.json"
REPO_PATH = "sboms/repo.spdx.json"
LIBC6 = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u7"
LIBSSL3 = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"
#: The component key core gives the zlib1g purl (qualifiers dropped).
ZLIB = "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1"
CVE = "CVE-2025-4802"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"


def test_an_spdx_sbom_imports_its_packages_with_the_scopes_its_relationships_give(
    tmp_path: Path,
) -> None:
    instance = kit_world(tmp_path, sboms=(("repo", REPO_PATH),))
    write_file(tmp_path, REPO_PATH, (DATA / "github-dependency-graph.spdx.json").read_bytes())
    state = import_sbom(instance, "repo", minute=-10)
    assert state.terminal_egress[0].settle_outcome == "settled", state.terminal_egress
    rows = query_rows(
        instance,
        inventory.INVENTORY_COMPONENTS,
        params={"inventory": f"{inventory.INVENTORY}/pkg:github/example/demo-app@main"},
    )
    assert {r["purl"]: r["scope"] for r in rows} == {
        "pkg:npm/%40babel/core@7.23.0": "excluded",
        "pkg:npm/express@4.17.1": "required",
        "pkg:npm/fsevents@2.3.3": "optional",
        "pkg:npm/lodash@4.17.20": "required",
    }
    # The SBOM lists a package with no purl: the read is incomplete, nothing retired.
    assert state.completeness is not None


def osv_answer(sent: list[dict[str, Any]]) -> dependency_replay.RecordedOsv:
    """OSV answering each batch query by what it asks: the Debian:12 glibc query with one
    DEBIAN- advisory (shaped as OSV serves them), anything else with nothing."""

    advisory = {
        "id": "DEBIAN-CVE-2025-4802",
        "upstream": [CVE],
        "modified": "2026-11-01T00:00:00Z",
        "affected": [
            {
                "package": {
                    "ecosystem": "Debian:12",
                    "name": "glibc",
                    "purl": "pkg:deb/debian/glibc?arch=source&distro=bookworm",
                },
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.36-9+deb12u11"}]}
                ],
            }
        ],
    }

    def batch(request: Any) -> tuple[int, bytes]:
        body = json.loads(request.content)
        sent.append(body)
        results = [
            {"vulns": [{"id": advisory["id"]}]}
            if query.get("package") == {"ecosystem": "Debian:12", "name": "glibc"}
            and query.get("version") == "2.36-9+deb12u7"
            else {}
            for query in body["queries"]
        ]
        return 200, json.dumps({"results": results}).encode()

    return dependency_replay.RecordedOsv(
        overrides={
            QUERYBATCH: batch,
            f"https://api.osv.dev/v1/vulns/{advisory['id']}": (200, json.dumps(advisory).encode()),
        }
    )


def test_a_container_sboms_distro_packages_are_asked_by_source_package_and_land_on_the_binary(
    tmp_path: Path,
) -> None:
    doc = json.loads((DATA / "syft-debian-image.spdx.json").read_bytes())
    # One package whose SBOM states no release: never asked, never clean.
    doc["packages"].append(
        {
            "SPDXID": "SPDXRef-Package-deb-zlib1g-9",
            "name": "zlib1g",
            "versionInfo": "1:1.2.13.dfsg-1",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=amd64&upstream=zlib",
                }
            ],
        }
    )
    instance = kit_world(tmp_path, sboms=(("image", IMAGE_PATH),))
    write_file(tmp_path, IMAGE_PATH, json.dumps(doc).encode())
    imported = import_sbom(instance, "image", minute=-10)
    # The SBOM grant is ONE scope: observations grant: core lowered it to every
    # ClaimType the import writes (osv_package included) and it creates the occurrence
    # and its nested inventory and component ends, so the first import settles.
    card = get(instance, f"Mandate:{inventory.sbom_line_name('image')}-settle").card
    assert {item.claim_type for item in card.scope} == {
        f"ClaimType:{inventory.SCOPE}", f"ClaimType:{inventory.OSV_PACKAGE}"
    }, card.scope
    assert imported.terminal_egress[0].settle_outcome == "settled", imported.terminal_egress

    # The import records the OSV package each distro occurrence is asked as.
    packages = {r["purl"]: r["osv_package"] for r in query_rows(instance, osv.OSV_DISTRO_PACKAGES)}
    assert packages == {
        "pkg:deb/debian/bash@5.2.15-2%2Bb2": "Debian:12|bash|5.2.15-2",
        LIBC6: "Debian:12|glibc|2.36-9+deb12u7",
        "pkg:deb/debian/libgcc-s1@12.2.0-14": "Debian:12|gcc-12|12.2.0-14",
        LIBSSL3: "Debian:12|openssl|3.0.11-1~deb12u2",
    }

    sent: list[dict[str, Any]] = []
    state = service_run(instance, Replay({}, osv=osv_answer(sent)), line=osv.OSV_LINE)
    assert state.status == "succeeded", state.terminal
    (body,) = sent
    assert {"package": {"ecosystem": "Debian:12", "name": "glibc"}, "version": "2.36-9+deb12u7"} in body["queries"]
    assert {"package": {"purl": "pkg:pypi/requests@2.31.0"}} in body["queries"]
    # No binary name and no unmapped package is ever asked.
    asked = json.dumps(body)
    assert "libc6" not in asked and "zlib" not in asked

    # OSV's answer for glibc lands on the binary component, with Debian:12's fix.
    claim = affected_claim(instance, LIBC6, CVE)
    rationale = get(instance, claim, detail="evidence").evidence.rationale
    assert rationale == (
        f"OSV DEBIAN-CVE-2025-4802 lists {CVE} for {LIBC6} (fixed in: 2.36-9+deb12u11)."
    ), rationale
    worklist = {(r["component"], r["cve_id"]) for r in query_rows(instance, triage.URGENT)}
    assert worklist == {(LIBC6, CVE)}

    # zlib1g states no release: not checked in the match document, never queried, and no
    # Claim says it is clean.
    document = derived_document(instance, state, node="matched")
    assert {"purl": ZLIB, "reason": "distro_source_name_unknown"} in document["not_checked"]
    assert ZLIB not in document["queried"] and LIBC6 in document["queried"]
    assert not [r for r in document["affected"] if r["purl"] == ZLIB]
