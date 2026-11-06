"""Inventory gate: the one SBOM import Procedure (K-B1-G1) on the kit's demo SBOMs.

The kit's own payloads (``definitions.py`` + ``inventory.py``) are authored into
a fresh in-process instance, exactly as ``test_pilot_gate.py`` does; the SBOMs
are the kit's two demo SBOMs (``examples/sboms``), read through core's builtin
``workspace.file`` from a temporary workspace, and the ``sbom.components``
derive is the real security-osv-provider code (``dependency_replay``).

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_inventory_gate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import inventory  # noqa: E402
import pytest
from test_pilot_gate import (
    accepted,
    changed,
    import_sbom,
    kit_world,
    summary,
    write_file,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "sboms"
ENV_SBOM = EXAMPLES / "cruxible-env.cdx.json"
DEMO_SBOM = EXAMPLES / "log4j-demo-app.cdx.json"
DEMO_PATH = "sboms/log4j-demo-app.cdx.json"
ENV_PATH = "sboms/cruxible-env.cdx.json"
DEMO_APP = "pkg:maven/com.example/log4j-demo-app@1.0.0"
LOG4J_CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
IN_INVENTORY = inventory.COMPONENT + ".in_inventory"


def demo_world(tmp_path: Path, content: bytes | None = None, *, watch: tuple[str, ...] = ()) -> Any:
    instance = kit_world(tmp_path, watch=watch, sboms=(("demo", DEMO_PATH),))
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes() if content is None else content)
    return instance


def demo_document() -> dict[str, Any]:
    return json.loads(DEMO_SBOM.read_bytes())


def memberships(instance: Any, state: Any) -> dict[str, Any]:
    """Each in_inventory change the run settled, by component purl."""

    out = {}
    for claim in changed(instance, state).values():
        if claim.statement.predicate == IN_INVENTORY:
            out[claim.statement.subject.artifact_path] = claim
    return out


def query_rows(instance: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    from cruxible_client.contracts.compact_query import QueryRequest
    from cruxible_core.service.discovery.compact_query import service_playbill_query

    page = service_playbill_query(instance, request=QueryRequest(name=query, params=params or None))
    return [dict(row) for row in page.rows]


def inventory_of(instance: Any, inventory_id: str) -> list[str]:
    rows = query_rows(instance, inventory.INVENTORY_MEMBERSHIPS)
    return sorted(r["purl"] for r in rows if r["inventory_id"] == inventory_id)


def derived_document(instance: Any, state: Any, node: str = "derived") -> dict[str, Any]:
    """The derived JSON document a run's derive call emitted (its Capture's bytes)."""

    from cruxible_client.contracts.captures import parse_capture_envelope
    from cruxible_client.contracts.cas_contracts import BodyAccessContext

    (call,) = [n.summary for n in state.nodes if n.node == node]
    (capture,) = call.capture_digests
    access = BodyAccessContext(principal_id="kit-gate", can_read_body=True)
    envelope = parse_capture_envelope(instance.body_store().read(capture, access=access))
    return json.loads(instance.body_store().read(envelope.commitment.digest, access=access))


def test_one_line_names_the_inventory_from_the_sbom_and_a_rerun_writes_nothing(
    tmp_path: Path,
) -> None:
    instance = demo_world(tmp_path)
    imported = import_sbom(instance, "demo")
    written = summary(imported, "claims")
    # Three components plus the inventory, created by value (V1) from metadata.component.
    assert (written.written, written.subjects_created) == (3, 4)
    assert imported.terminal_egress[0].settle_outcome == "settled"
    for claim in memberships(instance, imported).values():
        membership = accepted(instance, claim)
        assert membership.backing.procedure_evidence.value.basis == "extracted"
    assert len(inventory_of(instance, DEMO_APP)) == 3
    before = instance.accepted_coordinate()
    again = import_sbom(instance, "demo", minute=1)
    (egress,) = again.terminal_egress
    assert egress.proposal_id is None
    claims = summary(again, "claims")
    assert (claims.written, claims.revised, claims.re_observed) == (0, 0, 3)
    assert instance.accepted_coordinate() == before


def test_a_component_removed_from_the_sbom_retires_with_a_witness(tmp_path: Path) -> None:
    instance = demo_world(tmp_path)
    import_sbom(instance, "demo")
    document = demo_document()
    document["components"] = [
        c for c in document["components"] if not c["name"].startswith("slf4j")
    ]
    write_file(tmp_path, DEMO_PATH, json.dumps(document, indent=2).encode())
    state = import_sbom(instance, "demo", minute=1)
    claims = summary(state, "claims")
    assert (claims.written, claims.retired, claims.re_observed) == (0, 1, 2)
    assert state.terminal_egress[0].settle_outcome == "settled"
    (retired,) = changed(instance, state).values()
    assert retired.statement.subject.artifact_path.endswith("slf4j-api-1.7.32.json")
    assert retired.lifecycle.state == "retired" and retired.retirement.absence is not None
    assert retired.retirement.absence.logical_source == "cyclonedx.sbom.demo"


def test_absence_never_crosses_inventories(tmp_path: Path) -> None:
    """A component two SBOMs list keeps its other membership when one SBOM drops it."""

    other = demo_document()
    other["metadata"]["component"]["purl"] = "pkg:maven/com.example/other-app@1.0.0"
    instance = kit_world(
        tmp_path, sboms=(("demo", DEMO_PATH), ("other", "sboms/other-app.cdx.json"))
    )
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
    write_file(tmp_path, "sboms/other-app.cdx.json", json.dumps(other, indent=2).encode())
    import_sbom(instance, "demo")
    import_sbom(instance, "other", minute=1)
    document = demo_document()
    document["components"] = [c for c in document["components"] if c["name"] != "log4j-core"]
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    state = import_sbom(instance, "demo", minute=2)
    (retired,) = changed(instance, state).values()
    assert retired.statement.object.address.artifact_path.endswith("log4j-demo-app-1.0.0.json")
    assert LOG4J_CORE in inventory_of(instance, "pkg:maven/com.example/other-app@1.0.0")
    assert LOG4J_CORE not in inventory_of(instance, DEMO_APP)
    # Each shared component's other membership is another logical source's Claim:
    # never retired, only surfaced in the run report (D-R18). The SBOM Lines do
    # not route claim_not_in_source to their inbox (it is every shared
    # component on every run; see inventory.SBOM_FINDINGS).
    surfaced = [f for f in state.findings if f.kind == "claim_not_in_source"]
    assert len(surfaced) == 3
    assert {f.claim_type for f in surfaced} == {IN_INVENTORY}
    assert not any(f.source_incomplete for f in surfaced)
    assert "claim_not_in_source" not in inventory.SBOM_FINDINGS


def test_an_sbom_without_metadata_component_imports_under_its_path(tmp_path: Path) -> None:
    bare = demo_document()
    del bare["metadata"]["component"]
    path = "sboms/unnamed.cdx.json"
    instance = kit_world(tmp_path, sboms=(("unnamed", path),))
    write_file(tmp_path, path, json.dumps(bare, indent=2).encode())
    imported = import_sbom(instance, "unnamed")
    assert summary(imported, "claims").written == 3
    assert inventory_of(instance, path) == sorted(c["purl"] for c in demo_document()["components"])
    # The fallback is on the derived document and every record (warning).
    document = derived_document(instance, imported)
    assert (document["named_by"], document["warning"]) == ("file_path", "sbom_unnamed")
    assert {c["warning"] for c in document["components"]} == {"sbom_unnamed"}


@pytest.mark.xfail(
    strict=True,
    reason="core bug (integ05 251753278): claims_absence.append_absence resolves the "
    "subject key template of an invalid extract arm; '$item.key.purl' does not resolve "
    "raises ExecutionError, which its except (ValueError, KeyError, TypeError) misses, "
    "so the run fails unexpected_exception instead of tainting the enumeration",
)
def test_an_unparseable_purl_is_inadmissible_its_siblings_write_and_nothing_retires(
    tmp_path: Path,
) -> None:
    instance = demo_world(tmp_path)
    import_sbom(instance, "demo")
    document = demo_document()
    document["components"][0]["purl"] = "not a purl"
    # slf4j is gone too, but the read is incomplete: its membership must not retire.
    document["components"] = [c for c in document["components"] if c["name"] != "slf4j-api"]
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    state = import_sbom(instance, "demo", minute=1)
    claims = summary(state, "claims")
    assert (claims.retired, claims.re_observed) == (0, 1)
    assert [f.kind for f in state.findings if f.kind == "extract_refused"] == ["extract_refused"]
    assert len(inventory_of(instance, DEMO_APP)) == 3


def test_a_lost_purl_beside_a_genuine_removal_retires_nothing(tmp_path: Path) -> None:
    """F1: a held component still listed but without its purl cannot be keyed, so
    the read is incomplete (count above records): nothing retires, not even the
    component genuinely removed beside it; the remaining and new members write."""

    instance = demo_world(tmp_path)
    import_sbom(instance, "demo")
    document = demo_document()
    by_name = {c["name"]: c for c in document["components"]}
    del by_name["log4j-api"]["purl"]  # still listed, purl lost
    document["components"] = [c for c in document["components"] if c["name"] != "slf4j-api"]
    document["components"].append(
        {"type": "library", "name": "new-lib", "purl": "pkg:maven/com.example/new-lib@1.0"}
    )
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    state = import_sbom(instance, "demo", minute=1)
    claims = summary(state, "claims")
    assert (claims.written, claims.re_observed, claims.retired) == (1, 1, 0)
    extract = summary(state, "extract")
    assert not extract.complete
    assert (extract.complete_when.expected, extract.complete_when.observed) == (3, 2)
    assert any(r.kind == "count_mismatch" for r in state.completeness.reasons)
    held = inventory_of(instance, DEMO_APP)
    assert "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1" in held
    assert "pkg:maven/org.slf4j/slf4j-api@1.7.32" in held
    assert "pkg:maven/com.example/new-lib@1.0" in held


def test_two_spellings_of_one_component_write_nothing_for_it(tmp_path: Path) -> None:
    """Two purls core's normalizer folds to one key: a duplicate, nothing written for
    that key, the siblings write, and the incomplete read retires nothing."""

    document = demo_document()
    twin = dict(document["components"][1])
    twin["purl"] = twin["purl"] + "?type=jar"
    document["components"].append(twin)
    instance = demo_world(tmp_path, json.dumps(document).encode())
    state = import_sbom(instance, "demo")
    claims = summary(state, "claims")
    assert claims.written == 2
    assert [f.kind for f in state.findings if f.kind == "duplicate_key"] == ["duplicate_key"]
    assert summary(state, "extract").duplicates == 2


# -- work counts --------------------------------------------------------------------

_SIZES = (10, 20, 40)


def _synthetic_sbom(size: int) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"name": "app", "purl": "pkg:generic/scale-app@1"}},
            "components": [
                {"type": "library", "name": f"p{i}", "purl": f"pkg:pypi/p{i}@1.0"}
                for i in range(size)
            ],
        }
    ).encode()


def _counted_import(tmp_path: Path, size: int) -> dict[str, float]:
    from tests.test_scale._counters import counting, trace_sqlite

    with trace_sqlite(tmp_path):
        instance = demo_world(tmp_path, _synthetic_sbom(size))
        with counting(tmp_path) as window:
            state = import_sbom(instance, "demo")
    assert not window.unexplained, window.unexplained
    assert summary(state, "claims").written == size
    return {
        "sql_statements": window.counts["sql_statements"],
        "projection_binds": window.counts["projection_binds"],
        "claim_parses": window.counts["claim_parses"],
    }


def test_import_work_is_linear_in_components(tmp_path: Path) -> None:
    """Work counts at three sizes: the marginal cost of a component stays flat."""

    measured = {}
    for size in _SIZES:
        root = tmp_path / f"n{size}"
        root.mkdir()
        measured[size] = _counted_import(root, size)
    small, middle, large = (measured[size] for size in _SIZES)
    steps = (_SIZES[1] - _SIZES[0], _SIZES[2] - _SIZES[1])
    for counter in ("sql_statements", "projection_binds", "claim_parses"):
        low = (middle[counter] - small[counter]) / steps[0]
        high = (large[counter] - middle[counter]) / steps[1]
        assert high <= low * 1.15 + 2.0, (counter, measured)


@pytest.mark.parametrize("name", ["cruxible-env", "log4j-demo-app"])
def test_both_demo_sboms_import(tmp_path: Path, name: str) -> None:
    content = (EXAMPLES / f"{name}.cdx.json").read_bytes()
    instance = demo_world(tmp_path, content)
    state = import_sbom(instance, "demo")
    count = len(json.loads(content)["components"])
    assert summary(state, "claims").written == count
    assert state.terminal_egress[0].settle_outcome == "settled"
