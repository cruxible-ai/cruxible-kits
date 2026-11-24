"""The VEX exporter (``examples/export_vex.py``): CycloneDX 1.5 and OpenVEX v0.2.0.

Unit tests run it over a fake reader (the mapping, both formats' shape,
determinism, and the refusals that keep a contested judgment from ever reading
``not_affected``). The gate runs it on a real instance holding every judgment
state: an affected verdict, an app-level and a package-level not_affected
judgment, a contested judgment, unjudged pairs, and a judgment on a release the
SBOM upgraded away, all read at one pinned accepted coordinate.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

KIT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("export_vex", KIT / "examples" / "export_vex.py")
assert _spec is not None and _spec.loader is not None
vex = importlib.util.module_from_spec(_spec)
sys.modules["export_vex"] = vex  # its dataclasses resolve their module by name
_spec.loader.exec_module(vex)

APP = "pkg:maven/com.example/app@1.0.0"
LIB = "pkg:maven/org.example/lib@1.0"
COORD = {
    "instance_id": "inst_test",
    "generation": 42,
    "git_oid": "a" * 40,
    "state_digest": "sha256:" + "b" * 64,
    "proposed_at": "2026-11-20T10:00:00.123456+00:00",
}


def row(cve: str, *, inventory: str = APP, component: str = LIB, **more: Any) -> dict[str, Any]:
    return {"cve_id": cve, "inventory": inventory, "component": component, "occurrence": "occ-1", **more}


class FakeReader:
    """Query answers, cards and evidence held in memory, as one coordinate would answer."""

    def __init__(self, queries: Mapping[str, list[dict[str, Any]]], cards: Mapping[str, Any] | None = None,
                 evidence: Mapping[str, Any] | None = None) -> None:
        self.queries = {name: list(rows) for name, rows in queries.items()}
        self.cards = dict(cards or {})
        self.evidences = dict(evidence or {})

    def head(self) -> dict[str, Any]:
        return dict(COORD)

    def rows(self, name: str, params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        return list(self.queries.get(name, []))

    def card(self, ref: str) -> dict[str, Any] | None:
        return self.cards.get(ref)

    def evidence(self, claim: str) -> dict[str, Any]:
        return self.evidences.get(claim, {"captures": []})


def every_state() -> FakeReader:
    return FakeReader(
        {
            vex.CONFIRMED: [row("CVE-2026-0001", app_exposure="ae-1")],
            vex.COVERED_APP: [row("CVE-2026-0002")],
            vex.APP_JUDGMENTS: [row("CVE-2026-0002", app_exposure="ae-2",
                                    justification="vulnerable_code_not_in_execute_path")],
            vex.COVERED_PACKAGE: [row("CVE-2026-0003")],
            vex.JUDGMENTS: [{"cve_id": "CVE-2026-0003", "component": LIB, "exposure": "ex-3",
                             "justification": "vulnerable_code_not_present"}],
            vex.URGENT: [row("CVE-2026-0004"), row("CVE-2026-0005")],
            vex.CONTESTED: [row("CVE-2026-0005")],
        },
        cards={
            f"security.component/{LIB}": {
                "subject": "security.component/lib-id",
                "claims": [{"predicate": "affected_by",
                            "claim": ["CLM-osv1", "CLM-osv2"],
                            "value": ["security.vulnerability/cve-2026-0001",
                                      "security.vulnerability/cve-2026-0002"]}],
            },
            "security.app_exposure/ae-1": {"claims": [{"predicate": "verdict", "claim": "CLM-v1", "value": "affected"}]},
            "security.app_exposure/ae-2": {"claims": [{"predicate": "justification", "claim": "CLM-j2",
                                                       "value": "vulnerable_code_not_in_execute_path"}]},
            "security.exposure/ex-3": {"claims": [{"predicate": "justification", "claim": "CLM-j3",
                                                   "value": "vulnerable_code_not_present"}]},
            "security.occurrence/occ-1": {"claims": [{"predicate": "scope", "claim": "CLM-s", "value": "required"}]},
            "security.app_exposure/occ-1--cve-2026-0005": {"claims": [
                {"predicate": "justification", "claim": ["CLM-c1", "CLM-c2"],
                 "value": ["vulnerable_code_not_in_execute_path", "inline_mitigations_already_exist"]}]},
        },
        evidence={
            "CLM-osv1": {"rationale": "OSV GHSA-x lists CVE-2026-0001 for lib (fixed in: 1.1, 2.0.1).",
                         "captures": [{"capture": "CAP-osv", "contract": "CaptureContract:security.osv-matches",
                                       "source": "osv.dev.query"}]},
            "CLM-v1": {"rationale": "The app logs the header through the lookup.", "captures": []},
            "CLM-j2": {"rationale": "Never logs attacker input.",
                       "captures": [{"capture": "CAP-code", "contract": "CaptureContract:cruxible.foreign-source.app",
                                     "source": "app/log.py"}]},
            "CLM-j3": {"rationale": "The module is not built into this release."},
        },
    )


def by_cve(document: Mapping[str, Any], key: str) -> dict[str, Any]:
    if key == "vulnerabilities":
        return {v["id"]: v for v in document["vulnerabilities"]}
    return {s["vulnerability"]["name"]: s for s in document["statements"]}


def test_each_judgment_state_maps_faithfully_in_cyclonedx() -> None:
    document = json.loads(vex.export(every_state(), "cyclonedx"))
    assert (document["bomFormat"], document["specVersion"], document["version"]) == ("CycloneDX", "1.5", 1)
    assert document["serialNumber"].startswith("urn:uuid:")
    assert document["metadata"]["timestamp"] == "2026-11-20T10:00:00.123456Z"
    assert {p["name"]: p["value"] for p in document["metadata"]["properties"]} == {
        "cruxible:instance_id": "inst_test", "cruxible:generation": "42",
        "cruxible:git_oid": "a" * 40, "cruxible:state_digest": "sha256:" + "b" * 64,
    }
    vulns = by_cve(document, "vulnerabilities")
    assert vulns["CVE-2026-0001"]["analysis"]["state"] == "exploitable"
    assert vulns["CVE-2026-0001"]["analysis"]["response"] == ["update"]
    assert vulns["CVE-2026-0001"]["recommendation"].endswith("fixed: 1.1, 2.0.1.")
    assert vulns["CVE-2026-0002"]["analysis"] | {"detail": None} == {
        "state": "not_affected", "justification": "code_not_reachable", "detail": None}
    assert vulns["CVE-2026-0003"]["analysis"]["justification"] == "code_not_present"
    assert vulns["CVE-2026-0004"]["analysis"]["state"] == "in_triage"
    assert vulns["CVE-2026-0005"]["analysis"]["state"] == "in_triage"
    # Every affects ref names a nested component of its inventory.
    refs = {c["bom-ref"] for app in document["components"] for c in app["components"]}
    assert {a["ref"] for v in document["vulnerabilities"] for a in v["affects"]} <= refs
    # Provenance: the Claims and the Captures each statement rests on.
    props = [p["value"] for p in vulns["CVE-2026-0002"]["properties"]]
    assert "CLM-j2 security.app_exposure.justification" in props
    assert any(p.startswith("CLM-j2 CAP-code ") for p in props)
    assert "CLM-c1 security.app_exposure.justification" in [
        p["value"] for p in vulns["CVE-2026-0005"]["properties"]
    ]


def test_each_judgment_state_maps_faithfully_in_openvex() -> None:
    document = json.loads(vex.export(every_state(), "openvex"))
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["@id"].startswith("urn:cruxible:vex:") and document["version"] == 1
    statements = by_cve(document, "statements")
    assert statements["CVE-2026-0001"]["status"] == "affected"
    assert "1.1, 2.0.1" in statements["CVE-2026-0001"]["action_statement"]
    not_affected = statements["CVE-2026-0002"]
    assert (not_affected["status"], not_affected["justification"]) == (
        "not_affected", "vulnerable_code_not_in_execute_path")
    assert not_affected["impact_statement"] == "Never logs attacker input."
    assert statements["CVE-2026-0003"]["justification"] == "vulnerable_code_not_present"
    assert statements["CVE-2026-0004"]["status"] == "under_investigation"
    contested = statements["CVE-2026-0005"]
    assert contested["status"] == "under_investigation" and "justification" not in contested
    assert "contested" in contested["status_notes"] and "CLM-c2" in contested["status_notes"]
    assert statements["CVE-2026-0001"]["products"] == [{"@id": APP, "subcomponents": [{"@id": LIB}]}]
    assert "generation 42" in not_affected["status_notes"]


@pytest.mark.parametrize("fmt", vex.FORMATS)
def test_an_export_at_one_coordinate_is_byte_identical_whatever_the_read_order(fmt: str) -> None:
    first = vex.export(every_state(), fmt)
    shuffled = every_state()
    for rows in shuffled.queries.values():
        rows.reverse()
    assert vex.export(shuffled, fmt) == first
    # The timestamp and the serial are the caller's when named.
    named = json.loads(vex.export(every_state(), fmt, timestamp="2026-01-02T03:04:05Z", serial="urn:uuid:x"))
    assert (named.get("serialNumber") or named.get("@id")) == "urn:uuid:x"
    assert named.get("timestamp", named.get("metadata", {}).get("timestamp")) == "2026-01-02T03:04:05Z"


@pytest.mark.parametrize("covered", [vex.COVERED_APP, vex.COVERED_PACKAGE, vex.CONFIRMED])
def test_a_contested_pair_in_a_covered_or_confirmed_list_refuses_the_export(covered: str) -> None:
    """The invariant: a contested judgment is never exported as not_affected (or affected)."""

    reader = every_state()
    reader.queries[covered].append(row("CVE-2026-0005", app_exposure="ae-5"))
    with pytest.raises(vex.ExportRefused, match="contested"):
        vex.export(reader, "openvex")


def test_a_pair_in_two_states_refuses_the_export() -> None:
    reader = every_state()
    reader.queries[vex.URGENT].append(row("CVE-2026-0002"))
    with pytest.raises(vex.ExportRefused, match="two judgment states"):
        vex.export(reader, "cyclonedx")


def test_one_inventory_exports_alone() -> None:
    reader = every_state()
    reader.queries[vex.URGENT].append(row("CVE-2026-0009", inventory="pkg:maven/com.example/other@2"))
    document = json.loads(vex.export(reader, "openvex", inventory=APP))
    assert {s["vulnerability"]["name"] for s in document["statements"]} == {
        "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"}


@pytest.mark.parametrize(
    ("rationale", "expected"),
    [
        ("OSV G lists CVE-1 for x (fixed in: 2.12.2, 2.15.0, 2.3.1).", ("2.12.2", "2.15.0", "2.3.1")),
        ("OSV G lists CVE-1 for x (fixed in: none listed).", ()),
        ("OSV G lists CVE-1 for x (fixed in: 1.0, 1.1, ...).", ("1.0", "1.1")),
        ("OSV G lists CVE-1 for x.", ()),
        (None, ()),
    ],
)
def test_fixed_versions_come_from_the_affected_by_reason(rationale: str | None, expected: tuple[str, ...]) -> None:
    assert vex.fixed_from(rationale) == expected


# -- the gate: a real instance, every judgment state, one pinned coordinate -------------------


class InProcessReader:
    """The exporter's reads through core's own services, pinned to one git oid."""

    def __init__(self, instance: Any, at: str | None = None, state_digest: str | None = None) -> None:
        from cruxible_core.service.discovery.orient import service_playbill_orient

        self.instance = instance
        coordinate = instance.accepted_coordinate()
        self.at = at or coordinate.git_oid
        (newest,) = service_playbill_orient(
            instance, section="generations", limit=1, at=self.at
        ).generations
        self._head = {
            "instance_id": instance.descriptor.instance_id,
            "generation": newest.sequence,
            "git_oid": self.at,
            "state_digest": state_digest or coordinate.semantic_root,
            "proposed_at": newest.proposed_at.isoformat(),
        }

    def head(self) -> dict[str, Any]:
        return dict(self._head)

    def rows(self, name: str, params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        from cruxible_client.contracts.compact_query import QueryRequest
        from cruxible_core.service.discovery.compact_query import service_playbill_query

        page = service_playbill_query(
            self.instance,
            request=QueryRequest(name=name, params=dict(params or {}) or None, limit=500, at=self.at),
        )
        assert not page.truncated and not page.capped, (name, page.capped)
        return [dict(r) for r in page.rows]

    def card(self, ref: str) -> dict[str, Any] | None:
        from test_dependency_gate import get

        try:
            return get(self.instance, ref, at=self.at).card.model_dump(mode="json")
        except Exception as error:  # an absent Subject refuses
            if "not_found" in str(error) or "unknown" in str(error).lower():
                return None
            raise

    def evidence(self, claim: str) -> dict[str, Any]:
        from test_dependency_gate import get

        return get(self.instance, claim, detail="evidence", at=self.at).evidence.model_dump(mode="json")


def test_the_export_of_a_real_instance_states_every_judgment_faithfully_at_one_coordinate(
    tmp_path: Path,
) -> None:
    import test_dependency_gate as g

    instance = g.world(tmp_path, other=True)
    g.run_osv(instance)
    g.confirm(instance, g.DEMO_APP, g.CORE, g.LOG4SHELL)  # affected
    g.app_judge(instance, g.DEMO_APP, g.CORE, "CVE-2021-45046")  # app not_affected
    g.judge(instance, g.API, g.API_CVE)  # package not_affected, both inventories
    g._contested_justification_on(instance, g.DEMO_APP, g.CORE, "CVE-2021-44832")  # contested
    # A judgment on a release the other inventory then upgrades away: never exported.
    g.app_judge(instance, g.OTHER_APP, g.CORE, "CVE-2021-45105")
    document = json.loads(g.other_sbom())
    for item in document["components"]:
        if item.get("purl") == g.CORE:
            item["purl"], item["version"] = g.CORE.rpartition("@")[0] + "@2.17.1", "2.17.1"
    g.write_file(tmp_path, g.OTHER_PATH, json.dumps(document).encode())
    g.import_sbom(instance, "other", minute=3)

    reader = InProcessReader(instance)
    exports = {fmt: vex.export(reader, fmt) for fmt in vex.FORMATS}
    # Byte-identical on a second read at the same coordinate.
    assert {fmt: vex.export(InProcessReader(instance), fmt) for fmt in vex.FORMATS} == exports

    openvex = json.loads(exports["openvex"])
    statements = {
        (s["vulnerability"]["name"], s["products"][0]["@id"], s["products"][0]["subcomponents"][0]["@id"]): s
        for s in openvex["statements"]
    }
    affected = statements[(g.LOG4SHELL, g.DEMO_APP, g.CORE)]
    assert affected["status"] == "affected"
    assert "2.12.2, 2.15.0, 2.3.1" in affected["action_statement"]
    app = statements[("CVE-2021-45046", g.DEMO_APP, g.CORE)]
    assert (app["status"], app["justification"]) == ("not_affected", g.APP_REASON)
    for inventory_id in (g.DEMO_APP, g.OTHER_APP):
        package = statements[(g.API_CVE, inventory_id, g.API)]
        assert (package["status"], package["justification"]) == ("not_affected", g.PACKAGE_REASON)
    contested = statements[("CVE-2021-44832", g.DEMO_APP, g.CORE)]
    assert contested["status"] == "under_investigation", contested
    assert "Contested" in contested["status_notes"]
    # INVARIANT: nothing contested reads not_affected.
    contested_keys = {(r["cve_id"], r["inventory"], r["component"]) for r in reader.rows(vex.CONTESTED)}
    assert contested_keys and all(statements[k]["status"] == "under_investigation" for k in contested_keys)
    # The rest of the demo app's log4j-core CVEs are unjudged: under investigation.
    unjudged = {cve for (cve, inv, comp), s in statements.items()
                if inv == g.DEMO_APP and comp == g.CORE and s["status"] == "under_investigation"}
    assert unjudged == g.CORE_CVES - {g.LOG4SHELL, "CVE-2021-45046"}
    # The release the other inventory upgraded away is not exported at all.
    assert not [k for k in statements if k[1] == g.OTHER_APP and k[2] == g.CORE]
    assert ("CVE-2021-45105", g.OTHER_APP, g.CORE) not in statements

    # CycloneDX states the same, and both name the same coordinate.
    cyclonedx = json.loads(exports["cyclonedx"])
    states = {(v["id"], v["affects"][0]["ref"]): v["analysis"]["state"] for v in cyclonedx["vulnerabilities"]}
    assert states[(g.LOG4SHELL, f"{g.DEMO_APP}|{g.CORE}")] == "exploitable"
    assert states[("CVE-2021-45046", f"{g.DEMO_APP}|{g.CORE}")] == "not_affected"
    assert states[("CVE-2021-44832", f"{g.DEMO_APP}|{g.CORE}")] == "in_triage"
    assert len(states) == len(statements)
    coordinate = {p["name"]: p["value"] for p in cyclonedx["metadata"]["properties"]}
    assert coordinate["cruxible:git_oid"] == instance.accepted_coordinate().git_oid
    assert coordinate["cruxible:state_digest"] == instance.accepted_coordinate().semantic_root

    # Every Claim a statement cites resolves at that coordinate.
    cited = {claim for v in cyclonedx["vulnerabilities"] for p in v["properties"]
             if p["name"] == "cruxible:claim" for claim in [p["value"].split(" ", 1)[0]]}
    assert cited
    for claim in sorted(cited):
        assert reader.evidence(claim)

    # Later writes move the head; an export pinned to the first coordinate is unchanged.
    first_oid = reader.at
    g.app_judge(instance, g.DEMO_APP, g.CORE, "CVE-2021-45105")
    assert instance.accepted_coordinate().git_oid != first_oid
    pinned = InProcessReader(instance, at=first_oid, state_digest=reader.head()["state_digest"])
    assert vex.export(pinned, "openvex") == exports["openvex"]
    moved = json.loads(vex.export(InProcessReader(instance), "openvex"))
    assert moved["@id"] != openvex["@id"]
