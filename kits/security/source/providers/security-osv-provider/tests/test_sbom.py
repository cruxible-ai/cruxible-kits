"""Offline tests for ``sbom.components`` on the kit's two demo SBOMs (K-B1-G1).

The derive reads one SBOM Capture's bytes (core's wire, built here with the
runtime's own helper) and emits one derived JSON document. Conformance: pure
(byte-identical across two runs with the network blocked), and work grows
linearly with the components it reads.
"""

from __future__ import annotations

import base64
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from security_osv_provider import sbom  # noqa: E402

SBOMS = HERE.parents[3] / "examples" / "sboms"
DEMO = SBOMS / "log4j-demo-app.cdx.json"
ENV = SBOMS / "cruxible-env.cdx.json"
OBSERVED = datetime(2026, 11, 5, 9, 30, tzinfo=UTC)


def wire(content: bytes) -> dict[str, Any]:
    from cruxible_provider_runtime.acquisition import external_capture_result

    return external_capture_result(
        content,
        source_identity="cyclonedx.sbom.demo",
        coordinate_type="workspace-file-v1",
        coordinate={"relative_path": "sboms/demo.cdx.json"},
        observed_at=OBSERVED,
        selector_type="whole-response-v1",
    )


def run(content: bytes, path: str = "sboms/demo.cdx.json") -> Any:
    from cruxible_provider_runtime.egress import EgressRecorder
    from cruxible_provider_runtime.protocol import Budgets
    from cruxible_provider_runtime.provider_api import ProviderRunContext

    return sbom.sbom_components(
        ProviderRunContext(
            run_id="run-test",
            input={
                "sbom": wire(content),
                "relative_path": path,
                "logical_source": "cyclonedx.sbom",
            },
            operation=sbom.COMPONENTS,
            operation_signature_digest="sha256:" + "9" * 64,
            build_digest="sha256:" + "b" * 64,
            implementation_digest="sha256:" + "a" * 64,
            declared_endpoints=(),
            budgets=Budgets(wall_clock_seconds=30, output_bytes=8_000_000),
            coordinates={},
            capture_contract=None,
            secrets={},
            egress=EgressRecorder(),
        )
    )


def document(content: bytes, path: str = "sboms/demo.cdx.json") -> dict[str, Any]:
    result = run(content, path)
    assert result.status == "ok", result
    return json.loads(base64.b64decode(result.output["document"]["content_base64"]))


def test_the_inventory_is_named_by_metadata_component() -> None:
    out = document(DEMO.read_bytes())
    assert out["inventory"] == "pkg:maven/com.example/log4j-demo-app@1.0.0"
    assert out["named_by"] == "metadata_component" and "warning" not in out
    assert out["count"] == 3 and out["unidentified"] == 0
    assert {c["inventory"] for c in out["components"]} == {out["inventory"]}
    assert [c["purl"] for c in out["components"]] == sorted(c["purl"] for c in out["components"])
    assert document(ENV.read_bytes())["count"] == 55


def test_without_metadata_component_the_path_names_it_with_a_warning() -> None:
    bare = json.loads(DEMO.read_bytes())
    del bare["metadata"]["component"]
    out = document(json.dumps(bare).encode(), "sboms/unnamed.cdx.json")
    assert (out["inventory"], out["named_by"], out["warning"]) == (
        "sboms/unnamed.cdx.json",
        "file_path",
        "sbom_unnamed",
    )
    assert all(c["warning"] == "sbom_unnamed" for c in out["components"])


def test_nested_components_flatten_and_a_repeated_purl_is_one_record() -> None:
    doc = json.loads(DEMO.read_bytes())
    first = doc["components"][0]
    first["components"] = [
        {"type": "library", "name": "inner", "purl": "pkg:maven/x/inner@1"},
        {"type": "library", "name": "again", "purl": first["purl"]},
        {"type": "file", "name": "no-purl"},
    ]
    out = document(json.dumps(doc).encode())
    assert len(out["components"]) == 4 and out["unidentified"] == 1
    # count is every component listed: one above the records, so core's
    # complete_when check reads the SBOM as incomplete (F1).
    assert out["count"] == 5
    assert "pkg:maven/x/inner@1" in {c["purl"] for c in out["components"]}


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        json.dumps({"bomFormat": "SPDX"}).encode(),
        b'{"bomFormat":"CycloneDX","components":{}}',
    ],
)
def test_a_document_that_is_not_a_cyclonedx_sbom_is_refused(content: bytes) -> None:
    result = run(content)
    assert result.status == "refused" and result.refusal.code == sbom.PROVIDER_DECLINED


def test_each_record_carries_its_scope_and_required_when_unstated() -> None:
    """The occurrence's membership fact (D-R46 R3): CycloneDX's scope, default required."""

    doc = json.loads(DEMO.read_bytes())
    doc["components"][0]["scope"] = "optional"
    doc["components"][1]["scope"] = "excluded"
    out = document(json.dumps(doc).encode())
    assert [c["scope"] for c in out["components"]] == ["optional", "excluded", "required"]
    assert {c["scope"] for c in document(DEMO.read_bytes())["components"]} == {"required"}
    assert "held" not in out


def test_an_unknown_scope_is_passed_through_for_the_extract_to_refuse() -> None:
    doc = json.loads(DEMO.read_bytes())
    doc["components"][0]["scope"] = "sometimes"
    out = document(json.dumps(doc).encode())
    assert out["components"][0]["scope"] == "sometimes" and out["count"] == 3


def test_one_purl_listed_with_two_scopes_stays_two_records() -> None:
    """Fail closed: core's refuse_key writes nothing for a key whose scope is ambiguous."""

    doc = json.loads(DEMO.read_bytes())
    twin = dict(doc["components"][0], scope="optional")
    doc["components"].append(twin)
    doc["components"].append(dict(doc["components"][1]))  # same purl, same scope: one record
    out = document(json.dumps(doc).encode())
    purls = [c["purl"] for c in out["components"]]
    assert purls.count(twin["purl"]) == 2 and len(purls) == 4
    assert out["count"] == 4


def test_pure_byte_identical_twice_with_the_network_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("sbom.components opened a socket")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    first, second = run(DEMO.read_bytes()).output, run(DEMO.read_bytes()).output
    assert first == second
    assert first["document"]["observed_at"] == "2026-11-05T09:30:00Z"


def _sbom(n: int) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"name": "app", "purl": "pkg:generic/app@1"}},
            "components": [
                {"type": "library", "name": f"p{i}", "purl": f"pkg:pypi/p{i}@1.0"} for i in range(n)
            ],
        }
    ).encode()


@pytest.mark.parametrize("n", [50, 200])
def test_work_grows_linearly_with_components(n: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Work counts at two sizes: one visit per component, constant per component."""

    visits = {"walk": 0}
    real = sbom._walk

    def counted(components: object, depth: int = 0) -> Any:
        for item in real(components, depth):
            if depth == 0:
                visits["walk"] += 1
            yield item

    monkeypatch.setattr(sbom, "_walk", counted)
    out = document(_sbom(n))
    assert out["count"] == n
    assert visits["walk"] == n
