"""SPDX JSON input to ``sbom.components``, and distro packages asked by OSV source package.

The fixtures under ``data/`` are shaped as the tools write them: GitHub's
dependency-graph SPDX 2.3 export, a Syft SPDX 2.3 of a debian:12 image, a Trivy
CycloneDX 1.5 of Alpine / RHEL / Rocky / Alma packages, and a Syft CycloneDX 1.5
of Ubuntu / Wolfi / Chainguard packages with the cases that must stay unmapped.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from security_osv_provider import distro, osv, sbom  # noqa: E402
from test_osv import Recorded, context  # noqa: E402
from test_sbom import document, run  # noqa: E402

DATA = HERE / "data"
SBOMS = HERE.parents[3] / "examples" / "sboms"


def records(name: str) -> dict[str, dict[str, Any]]:
    out = document((DATA / name).read_bytes(), f"sboms/{name}")
    return {c["purl"].split("?", 1)[0]: c for c in out["components"]}


# -- CycloneDX stays byte for byte ----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "digest"),
    [
        ("log4j-demo-app.cdx.json", "4b7b4ceef42f2e8f8b04b77525ea5ad1ac0073de67399f4143b18f9c9b2462bd"),
        ("cruxible-env.cdx.json", "ca156a5316a0e9c464212e02b7cf06785db8707e6658b9601c4ca9bce2c1ec6c"),
    ],
)
def test_a_cyclonedx_sbom_with_no_distro_package_derives_the_same_bytes_as_before(
    name: str, digest: str
) -> None:
    """The digests are the 1.4.0 derive's output before SPDX and distro support."""

    result = run((SBOMS / name).read_bytes(), f"sboms/{name}")
    content = base64.b64decode(result.output["document"]["content_base64"])
    assert hashlib.sha256(content).hexdigest() == digest
    assert b"osv_package" not in content and b'"distro"' not in content


# -- SPDX JSON ------------------------------------------------------------------------------


def test_github_dependency_graph_spdx_names_its_inventory_and_scopes_each_package() -> None:
    out = document((DATA / "github-dependency-graph.spdx.json").read_bytes(), "sbom.spdx.json")
    assert (out["inventory"], out["named_by"]) == ("pkg:github/example/demo-app@main", "metadata_component")
    # The described package is the inventory, not a component; the package with no
    # purl is counted, never a record.
    assert (out["count"], out["unidentified"]) == (5, 1)
    found = {c["purl"]: c for c in out["components"]}
    assert {p: c["scope"] for p, c in found.items()} == {
        "pkg:npm/%40babel/core@7.23.0": "excluded",  # DEV_DEPENDENCY_OF
        "pkg:npm/express@4.17.1": "required",  # DEPENDS_ON from the root
        "pkg:npm/fsevents@2.3.3": "optional",  # OPTIONAL_DEPENDENCY_OF; versionInfo appended
        "pkg:npm/lodash@4.17.20": "required",  # DEPENDS_ON beats DEV_DEPENDENCY_OF
    }
    assert found["pkg:npm/lodash@4.17.20"]["supplier"] == "Organization: OpenJS Foundation"
    assert "supplier" not in found["pkg:npm/express@4.17.1"]  # NOASSERTION
    assert found["pkg:npm/express@4.17.1"]["name"] == "npm:express"
    assert "distro" not in out


def test_syft_spdx_of_a_debian_image_resolves_each_binary_to_its_source_package() -> None:
    out = document((DATA / "syft-debian-image.spdx.json").read_bytes(), "image.spdx.json")
    assert out["inventory"].startswith("pkg:oci/debian@sha256")
    assert out["distro"] == {"mapped": 4, "unmapped": {}}
    found = {c["name"]: c for c in out["components"]}
    assert {n: c.get("osv_package") for n, c in found.items()} == {
        "libc6": "Debian:12|glibc|2.36-9+deb12u7",
        "libssl3": "Debian:12|openssl|3.0.11-1~deb12u2",
        # Syft states a source only when it differs: bash is its own; binNMU +b2 dropped.
        "bash": "Debian:12|bash|5.2.15-2",
        "libgcc-s1": "Debian:12|gcc-12|12.2.0-14",  # upstream=gcc-12@12.2.0-14
        "requests": None,  # not a distro package: unchanged
    }
    assert "osv_unmapped" not in found["requests"]


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda d: d.update(spdxVersion="SPDX-3.0"), "neither"),
        (lambda d: d.update(packages={}), "no packages"),
        (lambda d: d["packages"].append("x"), "not an object"),
        (lambda d: d["packages"][1].pop("SPDXID"), "no SPDXID"),
        (lambda d: d.update(relationships=[1]), "relationship is not an object"),
        (lambda d: d.update(relationships={}), "relationships are not a list"),
    ],
)
def test_a_malformed_spdx_document_is_refused(edit: Any, message: str) -> None:
    doc = json.loads((DATA / "github-dependency-graph.spdx.json").read_bytes())
    edit(doc)
    with pytest.raises(sbom.SbomRefused, match=message):
        sbom.components_document(json.dumps(doc).encode(), "sbom.spdx.json")
    result = run(json.dumps(doc).encode())
    assert result.status == "refused" and result.refusal.code == sbom.PROVIDER_DECLINED


def test_an_spdx_document_describing_no_single_purl_is_named_by_its_path() -> None:
    doc = json.loads((DATA / "github-dependency-graph.spdx.json").read_bytes())
    doc["documentDescribes"] = []
    doc["relationships"] = [r for r in doc["relationships"] if r["relationshipType"] != "DESCRIBES"]
    out = sbom.components_document(json.dumps(doc).encode(), "sboms/repo.spdx.json")
    assert (out["inventory"], out["warning"]) == ("sboms/repo.spdx.json", "sbom_unnamed")
    assert "pkg:github/example/demo-app@main" in {c["purl"] for c in out["components"]}


# -- Distro packages: the OSV package each is asked as ---------------------------------------


@pytest.mark.parametrize(
    ("purl", "kwargs", "expected"),
    [
        ("pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&upstream=glibc&distro=debian-12", {},
         "Debian:12|glibc|2.36-9+deb12u7"),
        ("pkg:deb/debian/libc6@2.36-9?distro=bookworm&upstream=glibc", {}, "Debian:12|glibc|2.36-9"),
        ("pkg:deb/debian/libc6@2.36-9+deb12u4?distro=debian-12.4",
         {"properties": {"aquasecurity:trivy:SrcName": "glibc", "aquasecurity:trivy:SrcVersion": "2.36",
                         "aquasecurity:trivy:SrcRelease": "9+deb12u4"}},
         "Debian:12|glibc|2.36-9+deb12u4"),
        ("pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.15?distro=ubuntu-22.04",
         {"properties": {"syft:metadata:source": "openssl"}}, "Ubuntu:22.04|openssl|3.0.2-0ubuntu1.15"),
        ("pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19.1&upstream=openssl", {},
         "Alpine:v3.19|openssl|3.1.4-r5"),
        ("pkg:apk/alpine/musl@1.2.4-r2?distro=3.19.1", {"source_info": "built package from: musl 1.2.4-r2"},
         "Alpine:v3.19|musl|1.2.4-r2"),
        ("pkg:apk/wolfi/openssl@3.2.1-r0?arch=x86_64", {"binary_is_source": True}, "Wolfi|openssl|3.2.1-r0"),
        ("pkg:apk/chainguard/libcrypto3@3.2.1-r0?upstream=openssl", {}, "Chainguard|openssl|3.2.1-r0"),
        ("pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm", {},
         "Red Hat|openssl|1:3.0.7-25.el9_3"),
        ("pkg:rpm/rocky/glibc-common@2.34-83.el9.7?distro=rocky-9.3&upstream=glibc-2.34-83.el9.7.src.rpm",
         {}, "Rocky Linux:9|glibc|2.34-83.el9.7"),
        ("pkg:rpm/almalinux/curl-minimal@7.76.1-26.el9_3.2?distro=almalinux-9.3",
         {"properties": {"aquasecurity:trivy:SrcName": "curl", "aquasecurity:trivy:SrcVersion": "7.76.1",
                         "aquasecurity:trivy:SrcRelease": "26.el9_3.2"}},
         "AlmaLinux:9|curl|7.76.1-26.el9_3.2"),
    ],
)
def test_a_distro_package_is_asked_as_its_release_and_source_package(
    purl: str, kwargs: dict[str, Any], expected: str
) -> None:
    assert distro.osv_package(purl, **kwargs) == (expected, None)


@pytest.mark.parametrize(
    ("purl", "kwargs", "reason"),
    [
        # A release is never guessed: no distro qualifier, or one the table does not know.
        ("pkg:deb/debian/zlib1g@1.2.13?upstream=zlib", {}, "no_distro_qualifier"),
        ("pkg:deb/debian/libfoo@1.0-1?distro=debian-sid&upstream=foo", {}, "unknown_distro"),
        ("pkg:apk/alpine/busybox@1.36.1-r15?distro=edge", {"binary_is_source": True}, "unknown_distro"),
        ("pkg:rpm/centos/bash@5.1.8-9.el9?distro=centos-9&upstream=bash-5.1.8-9.el9.src.rpm", {},
         "unknown_distro"),
        ("pkg:rpm/rocky/bash@5.1.8?upstream=bash", {}, "no_distro_qualifier"),
        # A source is never guessed from the binary name, unless the generator's convention
        # says an unstated source is the binary's own (Syft, deb and apk only).
        ("pkg:deb/debian/libc6@2.36-9?distro=debian-12", {}, "no_source_package"),
        ("pkg:rpm/rocky/glibc-common@2.34?distro=rocky-9", {"binary_is_source": True}, "no_source_package"),
        ("pkg:deb/debian/libc6?distro=debian-12&upstream=glibc", {}, "no_version"),
    ],
)
def test_a_distro_package_osv_cannot_be_asked_about_says_why(
    purl: str, kwargs: dict[str, Any], reason: str
) -> None:
    assert distro.osv_package(purl, **kwargs) == (None, reason)


def test_trivy_cyclonedx_maps_alpine_rhel_rocky_and_alma_and_counts_the_rest() -> None:
    out = document((DATA / "trivy-os-packages.cdx.json").read_bytes(), "trivy.cdx.json")
    assert out["distro"] == {"mapped": 5, "unmapped": {"unknown_distro": 1}}
    found = records("trivy-os-packages.cdx.json")
    assert {p: c.get("osv_package") or c["osv_unmapped"] for p, c in found.items()} == {
        "pkg:apk/alpine/musl@1.2.4_git20230717-r4": "Alpine:v3.19|musl|1.2.4_git20230717-r4",
        "pkg:apk/alpine/libcrypto3@3.1.4-r5": "Alpine:v3.19|openssl|3.1.4-r5",
        "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3": "Red Hat|openssl|1:3.0.7-25.el9_3",
        "pkg:rpm/rocky/glibc-common@2.34-83.el9.7": "Rocky Linux:9|glibc|2.34-83.el9.7",
        "pkg:rpm/almalinux/curl-minimal@7.76.1-26.el9_3.2": "AlmaLinux:9|curl|7.76.1-26.el9_3.2",
        "pkg:rpm/centos/bash@5.1.8-9.el9": "unknown_distro",
    }


def test_syft_cyclonedx_maps_ubuntu_wolfi_and_chainguard_and_never_guesses_the_rest() -> None:
    out = document((DATA / "syft-distro-packages.cdx.json").read_bytes(), "syft.cdx.json")
    assert out["distro"] == {"mapped": 4, "unmapped": {"no_distro_qualifier": 1, "unknown_distro": 2}}
    found = records("syft-distro-packages.cdx.json")
    assert {p: c.get("osv_package") or c["osv_unmapped"] for p, c in found.items()} == {
        "pkg:deb/ubuntu/libc6@2.35-0ubuntu3.6": "Ubuntu:22.04|glibc|2.35-0ubuntu3.6",
        "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.15": "Ubuntu:22.04|openssl|3.0.2-0ubuntu1.15",
        "pkg:apk/wolfi/openssl@3.2.1-r0": "Wolfi|openssl|3.2.1-r0",
        "pkg:apk/chainguard/libcrypto3@3.2.1-r0": "Chainguard|openssl|3.2.1-r0",
        "pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1": "no_distro_qualifier",
        "pkg:deb/debian/libfoo@1.0-1": "unknown_distro",
        "pkg:apk/alpine/busybox@1.36.1-r15": "unknown_distro",
    }


def test_without_a_syft_generator_a_distro_package_with_no_stated_source_is_unmapped() -> None:
    doc = json.loads((DATA / "syft-distro-packages.cdx.json").read_bytes())
    doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "other-scanner"}]}
    found = {
        c["purl"].split("?", 1)[0]: c
        for c in sbom.components_document(json.dumps(doc).encode(), "x.cdx.json")["components"]
    }
    assert found["pkg:apk/wolfi/openssl@3.2.1-r0"]["osv_unmapped"] == "no_source_package"
    assert found["pkg:deb/ubuntu/libc6@2.35-0ubuntu3.6"]["osv_package"].startswith("Ubuntu:22.04|glibc|")


# -- osv.query and osv.match over distro packages ---------------------------------------------

LIBC6 = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u7"
LIBC6_PACKAGE = "Debian:12|glibc|2.36-9+deb12u7"
MUSL = "pkg:apk/alpine/musl@1.2.4-r2"
NPM = "pkg:npm/lodash@4.17.20"


def distro_origin() -> tuple[Recorded, list[dict[str, Any]]]:
    """A fake OSV: one batch answer (libc6, then npm: sorted purl order), one advisory each."""

    batch = {"results": [{"vulns": [{"id": "DEBIAN-CVE-2025-4802"}]}, {"vulns": [{"id": "GHSA-lodash"}]}]}
    debian = {
        "id": "DEBIAN-CVE-2025-4802",
        "upstream": ["CVE-2025-4802"],
        "affected": [
            {"package": {"ecosystem": "Debian:12", "name": "glibc",
                         "purl": "pkg:deb/debian/glibc?arch=source&distro=bookworm"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.36-9+deb12u11"}]}]},
            {"package": {"ecosystem": "Debian:11", "name": "glibc"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31-13+deb11u13"}]}]},
        ],
    }
    lodash = {
        "id": "GHSA-lodash",
        "aliases": ["CVE-2021-23337"],
        "affected": [{"package": {"purl": "pkg:npm/lodash"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }
    sent: list[dict[str, Any]] = []
    origin = Recorded(
        overrides={
            f"{osv.OSV_API}/v1/querybatch": (200, json.dumps(batch).encode()),
            f"{osv.OSV_API}/v1/vulns/DEBIAN-CVE-2025-4802": (200, json.dumps(debian).encode()),
            f"{osv.OSV_API}/v1/vulns/GHSA-lodash": (200, json.dumps(lodash).encode()),
        }
    )
    base = origin.transport

    def transport() -> Any:
        import httpx

        inner = base()

        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                sent.append(json.loads(request.content))
            return inner.handle_request(request)

        return httpx.MockTransport(handle)

    origin.transport = transport  # type: ignore[method-assign]
    return origin, sent


def distro_run(packages: dict[str, list[str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict]:
    origin, sent = distro_origin()
    purls = [p for p, values in packages.items() for _ in values]
    result = osv.OsvQuery(transport_factory=origin.transport)(
        context(
            {
                "components": [NPM, LIBC6, MUSL],
                "distro_purls": purls,
                "distro_packages": [v for values in packages.values() for v in values],
                "logical_source": "osv.dev.query",
            },
            osv.QUERY,
        )
    )
    assert result.status == "ok", result
    responses = list(result.output["responses"])
    match = osv.osv_match(
        context({"responses": responses, "components": [NPM, LIBC6, MUSL]}, osv.MATCH)
    )
    assert match.status == "ok", match
    return sent, responses, json.loads(base64.b64decode(match.output["document"]["content_base64"]))


def test_a_distro_component_is_asked_by_its_source_package_and_matched_back_to_its_purl() -> None:
    sent, responses, document = distro_run({LIBC6: [LIBC6_PACKAGE]})
    (body,) = sent
    assert body["queries"] == [
        {"package": {"ecosystem": "Debian:12", "name": "glibc"}, "version": "2.36-9+deb12u7"},
        {"package": {"purl": NPM}},
    ]
    (batch,) = [r for r in responses if r["coordinate"]["method"] == "POST"]
    assert batch["coordinate"]["purls"] == [LIBC6, NPM]
    assert batch["coordinate"]["packages"] == [LIBC6_PACKAGE, None]
    assert document["queried"] == [LIBC6, NPM]
    pairs = {(r["purl"], r["cve_id"]): r for r in document["affected"]}
    # The fixed versions are the advisory's for Debian:12 glibc only, not Debian:11's.
    assert pairs[(LIBC6, "CVE-2025-4802")]["fixed"] == ["2.36-9+deb12u11"]
    assert pairs[(LIBC6, "CVE-2025-4802")]["fixed_versions"] == "2.36-9+deb12u11"
    assert pairs[(NPM, "CVE-2021-23337")]["fixed"] == ["4.17.21"]
    # musl has no OSV package: never asked, never queried, not checked.
    assert {"purl": MUSL, "reason": "distro_source_name_unknown"} in document["not_checked"]


def test_a_purl_given_two_different_packages_is_never_asked() -> None:
    sent, _responses, document = distro_run({LIBC6: [LIBC6_PACKAGE, "Debian:12|eglibc|2.36-9"]})
    (body,) = sent
    assert body["queries"] == [{"package": {"purl": NPM}}]
    assert LIBC6 not in document["queried"]
    assert {"purl": LIBC6, "reason": "distro_source_name_unknown"} in document["not_checked"]


def test_a_batch_with_no_distro_package_keeps_its_coordinate_and_request_bytes() -> None:
    _sent, responses, _document = distro_run({})
    (batch,) = [r for r in responses if r["coordinate"]["method"] == "POST"]
    assert "packages" not in batch["coordinate"]


def test_mismatched_distro_lists_are_refused() -> None:
    origin, _sent = distro_origin()
    result = osv.OsvQuery(transport_factory=origin.transport)(
        context({"components": [LIBC6], "distro_purls": [LIBC6], "distro_packages": []}, osv.QUERY)
    )
    assert result.status == "refused" and result.refusal.code == osv.PROVIDER_DECLINED
