"""Batch-1 gate: SBOM import and the chain SBOM -> affected_by -> watch list -> KEV/EPSS.

The kit's own payloads (``definitions.py`` + ``inventory.py``) are authored into
a fresh in-process instance, exactly as ``test_pilot_gate.py`` does; the SBOMs
are the kit's two demo SBOMs (``examples/sboms``), read through core's builtin
``workspace.file`` from a temporary workspace. OSV is not wired yet (core lanes
A + B), so the chain test seeds ``affected_by`` with an agent's own-word
proposal, labelled as a seed.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_inventory_gate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from test_pilot_gate import (
    accepted,
    changed,
    fixture_bytes,
    import_sbom,
    kev,
    kit,
    kit_world,
    run,
    submit,
    summary,
    write_file,
)

import inventory  # noqa: E402

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "sboms"
ENV_SBOM = EXAMPLES / "cruxible-env.cdx.json"
DEMO_SBOM = EXAMPLES / "log4j-demo-app.cdx.json"
DEMO_PATH = "sboms/log4j-demo-app.cdx.json"
ENV_PATH = "sboms/cruxible-env.cdx.json"
LOG4J_CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4SHELL = "CVE-2021-44228"
IN_INVENTORY = inventory.COMPONENT + ".in_inventory"


def sboms(*names: tuple[str, str, bytes]) -> tuple[tuple[str, str, str], ...]:
    """Line inputs for (name, path, bytes): the inventory id each SBOM's lint names."""

    return tuple(
        (name, path, inventory.lint_sbom(content, path).inventory_id)
        for name, path, content in names
    )


def demo_world(tmp_path: Path, *, watch: tuple[str, ...] = ()) -> Any:
    content = DEMO_SBOM.read_bytes()
    instance = kit_world(tmp_path, watch=watch, sboms=sboms(("demo", DEMO_PATH, content)))
    write_file(tmp_path, DEMO_PATH, content)
    return instance


def components(instance: Any, state: Any) -> dict[str, Any]:
    """Each in_inventory change the run settled, by component purl."""

    out = {}
    for claim in changed(instance, state).values():
        if claim.statement.predicate == IN_INVENTORY:
            out[claim.statement.subject.artifact_path] = claim
    return out


def test_lint_names_the_inventory_by_metadata_component_and_falls_back_with_a_warning() -> None:
    named = inventory.lint_sbom(DEMO_SBOM.read_bytes(), DEMO_PATH)
    assert named == ("pkg:maven/com.example/log4j-demo-app@1.0.0", ())
    assert inventory.lint_sbom(ENV_SBOM.read_bytes(), ENV_PATH).inventory_id == (
        "pkg:generic/cruxible-env"
    )
    bare = json.loads(DEMO_SBOM.read_bytes())
    del bare["metadata"]["component"]
    fallback = inventory.lint_sbom(json.dumps(bare).encode(), "sboms/unnamed.cdx.json")
    assert fallback.inventory_id == "sboms/unnamed.cdx.json"
    (warning,) = fallback.warnings
    assert warning.startswith("cruxible.kit.security.sbom_unnamed:")


def test_import_settles_components_and_identical_rerun_writes_nothing(tmp_path: Path) -> None:
    instance = demo_world(tmp_path)
    named, imported = import_sbom(instance, "demo")
    assert summary(named, "claims").subjects_created == 1
    written = summary(imported, "claims")
    assert (written.written, written.subjects_created) == (3, 3)
    assert imported.terminal_egress[0].settle_outcome == "settled"
    held = components(instance, imported)
    assert len(held) == 3
    for claim in held.values():
        membership = accepted(instance, claim)
        assert membership.backing.procedure_evidence.value.basis == "extracted"
    before = instance.accepted_coordinate()
    again_named, again = import_sbom(instance, "demo", minute=1)
    for state, count in ((again_named, 1), (again, 3)):
        (egress,) = state.terminal_egress
        assert egress.proposal_id is None
        claims = summary(state, "claims")
        assert (claims.written, claims.revised, claims.re_observed) == (0, 0, count)
    assert instance.accepted_coordinate() == before


def test_a_component_removed_from_the_sbom_retires_with_a_witness(tmp_path: Path) -> None:
    instance = demo_world(tmp_path)
    import_sbom(instance, "demo")
    document = json.loads(DEMO_SBOM.read_bytes())
    document["components"] = [
        c for c in document["components"] if not c["name"].startswith("slf4j")
    ]
    write_file(tmp_path, DEMO_PATH, json.dumps(document, indent=2).encode())
    _named, state = import_sbom(instance, "demo", minute=1)
    claims = summary(state, "claims")
    assert (claims.written, claims.retired, claims.re_observed) == (0, 1, 2)
    assert state.terminal_egress[0].settle_outcome == "settled"
    (retired,) = changed(instance, state).values()
    assert retired.statement.subject.artifact_path.endswith("slf4j-api-1.7.32.json")
    assert retired.lifecycle.state == "retired" and retired.retirement.absence is not None
    witness = retired.retirement.absence
    assert witness.logical_source == "cyclonedx.sbom.demo"


def test_absence_never_crosses_inventories(tmp_path: Path) -> None:
    """A component two SBOMs list keeps its other membership when one SBOM drops it."""

    content = DEMO_SBOM.read_bytes()
    other = json.loads(content)
    other["metadata"]["component"]["purl"] = "pkg:maven/com.example/other-app@1.0.0"
    other_bytes = json.dumps(other, indent=2).encode()
    instance = kit_world(
        tmp_path,
        sboms=sboms(
            ("demo", DEMO_PATH, content), ("other", "sboms/other-app.cdx.json", other_bytes)
        ),
    )
    write_file(tmp_path, DEMO_PATH, content)
    write_file(tmp_path, "sboms/other-app.cdx.json", other_bytes)
    import_sbom(instance, "demo")
    import_sbom(instance, "other", minute=1)
    document = json.loads(content)
    document["components"] = [c for c in document["components"] if c["name"] != "log4j-core"]
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    _named, state = import_sbom(instance, "demo", minute=2)
    (retired,) = changed(instance, state).values()
    assert retired.statement.object.address.artifact_path.endswith("log4j-demo-app-1.0.0.json")
    rows = query_rows(instance, inventory.INVENTORY_COMPONENTS, path="sboms/other-app.cdx.json")
    assert any(r["purl"] == LOG4J_CORE for r in rows)


def test_an_sbom_without_metadata_component_imports_under_its_path(tmp_path: Path) -> None:
    bare = json.loads(DEMO_SBOM.read_bytes())
    del bare["metadata"]["component"]
    content = json.dumps(bare, indent=2).encode()
    path = "sboms/unnamed.cdx.json"
    instance = kit_world(tmp_path, sboms=sboms(("unnamed", path, content)))
    write_file(tmp_path, path, content)
    named, imported = import_sbom(instance, "unnamed")
    assert summary(named, "claims").subjects_created == 1
    assert summary(imported, "claims").written == 3
    rows = query_rows(instance, inventory.INVENTORY_COMPONENTS, path=path)
    assert len(rows) == 3


def query_rows(instance: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    from cruxible_client.contracts.compact_query import QueryRequest
    from cruxible_core.service.discovery.compact_query import service_playbill_query

    page = service_playbill_query(instance, request=QueryRequest(name=query, params=params or None))
    return [dict(row) for row in page.rows]


@pytest.mark.parametrize("seeded", [True, False])
def test_chain_sbom_to_seeded_affected_by_to_watch_list_to_kev_and_epss(
    tmp_path: Path, seeded: bool
) -> None:
    """SBOM -> affected_by (a labelled seed; OSV is not wired) -> watch list -> KEV/EPSS."""

    instance = demo_world(tmp_path, watch=(LOG4SHELL,))
    import_sbom(instance, "demo")
    if seeded:
        submit(
            instance,
            kit.seed_affected_by([(LOG4J_CORE, LOG4SHELL)], reason="chain gate"),
            name="seed",
        )
    rows = query_rows(instance, kit.WATCHED_QUERY)
    assert [r["cve_id"] for r in rows] == ([LOG4SHELL] if seeded else [])
    catalog = kev(instance, fixture_bytes("kev-catalog"), minute=1)
    scores = run(
        instance,
        {kit.epss_url((LOG4SHELL,)): fixture_bytes("epss-api")},
        line=kit.EPSS_LINE,
        minute=2,
    )
    assert scores.status == "succeeded", scores.terminal
    if not seeded:
        # Nothing is watched: neither Line writes (no applicability, no urgency).
        for state in (catalog, scores):
            assert summary(state, "claims").written == 0
        return
    written = {p for (_c, p) in changed(instance, catalog)}
    assert written == {
        kit.VULN + p
        for p in (".listed_in", ".kev_date_added", ".kev_due_date", ".kev_ransomware_use")
    }
    scored = changed(instance, scores)
    assert {p for (_c, p) in scored} == {
        kit.VULN + p for p in (".epss_score", ".epss_percentile", ".epss_score_date")
    }
    assert scores.terminal_egress[0].settle_outcome == "settled"
