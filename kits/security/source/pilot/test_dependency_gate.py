"""Dependency-loop gate: SBOM -> OSV -> KEV/EPSS -> agents judge -> track record.

The kit's own payloads in a fresh in-process instance (``test_pilot_gate``'s
world), the demo SBOM imported by its Line, and the OSV Line answered by the
REAL security-osv-provider code over OSV's recorded exchanges
(``security-osv-provider/tests/recordings``; ``dependency_replay``). No test
opens a socket.

The pair-Subject model (D-R43, D-R46): worklist rows are occurrences
(inventory, component); a package-level judgment is one write (retire OSV's
observation, "none of V", the exposure pair and its justification); an
app-level judgment (a not_affected justification, or an affected verdict) is
one write on the app_exposure pair of one occurrence.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_dependency_gate.py
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import dependency_replay  # noqa: E402
import facts  # noqa: E402
import inventory  # noqa: E402
import osv  # noqa: E402
import pytest
import triage  # noqa: E402
from test_inventory_gate import derived_document
from test_pilot_gate import (
    NOW,
    OWNERS,
    EpssOrigin,
    Replay,
    accepted,
    changed,
    fixture_bytes,
    import_sbom,
    epss,
    epss_answer,
    kev,
    kev_catalog,
    kit,
    kit_world,
    record,
    service_run,
    summary,
    write_file,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "sboms"
DEMO_SBOM = EXAMPLES / "log4j-demo-app.cdx.json"
DEMO_PATH = "sboms/log4j-demo-app.cdx.json"
OTHER_PATH = "sboms/other-app.cdx.json"
DEMO_APP = "pkg:maven/com.example/log4j-demo-app@1.0.0"
OTHER_APP = "pkg:maven/com.example/other-app@1.0.0"
CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
API = "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
SLF4J = "pkg:maven/org.slf4j/slf4j-api@1.7.32"
LOG4SHELL = "CVE-2021-44228"
API_CVE = "CVE-2026-49844"
OSV = dependency_replay.RecordedOsv
QUERYBATCH = "https://api.osv.dev/v1/querybatch"
LOG4SHELL_ADVISORY = "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q"
AFFECTED = osv.AFFECTED_BY
PACKAGE_REASON = "vulnerable_code_not_present"
APP_REASON = "vulnerable_code_not_in_execute_path"
CORE_CVES = {
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2021-44832",
    "CVE-2021-45105",
    "CVE-2025-68161",
    "CVE-2026-34477",
    "CVE-2026-34479",
    "CVE-2026-34480",
}


def recorded_batch() -> dict[str, Any]:
    index = json.loads((dependency_replay.RECORDINGS / "index.json").read_text())["exchanges"]
    (item,) = [i for i in index if i["id"] == "batch-log4j-demo-app"]
    return json.loads((dependency_replay.RECORDINGS / item["body"]).read_bytes())


def batch_with(edit: Any) -> tuple[int, bytes]:
    """The recorded demo-app batch answer, edited: ``edit(results)`` by purl order."""

    answer = recorded_batch()
    edit(answer["results"])
    return 200, json.dumps(answer).encode()


#: The recorded batch's purls, in the order OSV answered them (sorted).
BATCH_ORDER = (API, CORE, SLF4J)


def other_sbom() -> bytes:
    """A second inventory listing the same three components (the demo's twin)."""

    document = json.loads(DEMO_SBOM.read_bytes())
    document["metadata"]["component"]["purl"] = OTHER_APP
    return json.dumps(document, indent=2).encode()


def world(tmp_path: Path, *, other: bool = False) -> Any:
    """The demo SBOM imported, and with ``other`` a second inventory of the same
    components (one package release, two occurrences)."""

    sboms = (("demo", DEMO_PATH), ("other", OTHER_PATH)) if other else (("demo", DEMO_PATH),)
    instance = kit_world(tmp_path, sboms=sboms)
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
    import_sbom(instance, "demo", minute=-10)
    if other:
        write_file(tmp_path, OTHER_PATH, other_sbom())
        import_sbom(instance, "other", minute=-9)
    return instance


def run_osv(instance: Any, origin: Any = None, *, minute: int = 0) -> Any:
    origin = OSV() if origin is None else origin
    state = service_run(instance, Replay({}, osv=origin), line=osv.OSV_LINE, minute=minute)
    assert state.status == "succeeded", state.terminal
    return state


def query_rows(instance: Any, query: str | None, **request: Any) -> list[Any]:
    from cruxible_client.contracts.compact_query import QueryRequest
    from cruxible_core.service.discovery.compact_query import service_playbill_query

    page = service_playbill_query(
        instance, request=QueryRequest(**({"name": query} if query else {}), **request)
    )
    return list(page.rows)


def get(instance: Any, ref: str, **request: Any) -> Any:
    from cruxible_client.contracts.get_reads import GetRequest
    from cruxible_core.service.discovery.get import service_playbill_get
    from cruxible_core.storage.cas import BodyAccessContext

    return service_playbill_get(
        instance,
        request=GetRequest(ref=ref, **request),
        access=BodyAccessContext(principal_id="reader", can_read_body=True),
    )


def written_claims(instance: Any, state: Any) -> list[Any]:
    """Every affected_by Claim the run changed (``changed`` keys by Subject and predicate)."""

    from tests.test_procedures.test_claims_terminal import candidate_claims

    return [c for c in candidate_claims(instance, state) if c.statement.predicate == AFFECTED]


def component(purl: str) -> str:
    return f"{inventory.COMPONENT}/{purl}"


def affected(instance: Any) -> dict[str, set[str]]:
    """purl -> the CVE ids its live affected_by values name (nones excluded)."""

    out: dict[str, set[str]] = {}
    for purl in (CORE, API, SLF4J):
        card = get(instance, component(purl)).card
        rows = [r for r in card.claims if r.predicate == "affected_by"]
        values = rows[0].value if rows else []
        out[purl] = {str(v).rsplit("/", 1)[-1].upper() for v in values}
    return out


def affected_claim(instance: Any, purl: str, cve_id: str) -> str:
    card = get(instance, component(purl)).card
    (row,) = [r for r in card.claims if r.predicate == "affected_by"]
    for claim, value in zip(row.claim, row.value, strict=True):
        if str(value).lower().endswith(cve_id.lower()):
            return claim
    raise AssertionError(f"{purl} holds no affected_by {cve_id}")


def none_claim(instance: Any, purl: str, cve_id: str) -> str:
    (cells,) = query_rows(
        instance,
        None,
        kind=inventory.COMPONENT,
        where=[{"field": "purl", "eq": purl}],
        select=("affected_by",),
        claims=True,
    )
    (none,) = [n for n in cells["nones"]["affected_by"] if str(n.of).endswith(cve_id.lower())]
    return none.claim


def justification_claim(instance: Any, ref: str, field: str = "justification") -> str:
    card = get(instance, ref).card
    (row,) = [r for r in card.claims if r.predicate == field]
    claim = row.claim
    return claim[0] if isinstance(claim, list | tuple) else claim


def verdict_claim(instance: Any, ref: str) -> str:
    return justification_claim(instance, ref, "verdict")


def write(instance: Any, request: dict[str, Any]) -> Any:
    from cruxible_client.contracts.write import WriteRequest
    from cruxible_core.proposals.proposals import AuthenticatedActor
    from cruxible_core.service.authoring.write_verbs import WriteCaller, service_playbill_write

    return service_playbill_write(
        instance,
        request=WriteRequest.model_validate(request),
        caller=WriteCaller(
            actor=AuthenticatedActor(actor_id="owner"), may_activate=True, may_approve=True
        ),
    )


def package_judgment(instance: Any, purl: str, cve_id: str, **extra: Any) -> dict[str, Any]:
    return triage.judgment(
        purl,
        cve_id,
        reason=PACKAGE_REASON,
        because=f"{purl.split('/')[-1]} ships without the vulnerable JNDI lookup class.",
        retire=(affected_claim(instance, purl, cve_id),),
        accept="if_allowed",
        **extra,
    )


def judge(instance: Any, purl: str, cve_id: str) -> Any:
    """An agent's package-level not_affected judgment: one write."""

    outcome = write(instance, package_judgment(instance, purl, cve_id))
    assert outcome.status == "accepted", outcome
    return outcome


def exposures(instance: Any, query: str = triage.URGENT) -> set[tuple[str, str, str]]:
    """(inventory, component, CVE) of each worklist row."""

    return {(r["inventory"], r["component"], r["cve_id"]) for r in query_rows(instance, query)}


def occurrence_of(instance: Any, inventory_id: str, purl: str) -> str:
    """The occurrence id of ``purl`` in one inventory (its components Query)."""

    rows = query_rows(
        instance,
        inventory.INVENTORY_COMPONENTS,
        params={"inventory": f"{inventory.INVENTORY}/{inventory_id}"},
    )
    (row,) = [r for r in rows if r["purl"] == purl]
    return row["occurrence"]


def app_judge(instance: Any, inventory_id: str, purl: str, cve_id: str) -> Any:
    request = triage.app_judgment(
        occurrence_of(instance, inventory_id, purl),
        cve_id,
        reason=APP_REASON,
        because="This app never logs attacker-controlled input.",
        accept="if_allowed",
    )
    outcome = write(instance, request)
    assert outcome.status == "accepted", outcome
    return outcome


def confirm(instance: Any, inventory_id: str, purl: str, cve_id: str, **extra: Any) -> Any:
    """An agent's affected verdict for one occurrence (own words): one write."""

    request = triage.affected_judgment(
        occurrence_of(instance, inventory_id, purl),
        cve_id,
        because="The app logs the User-Agent header through log4j-core's message lookup.",
        accept="if_allowed",
        **extra,
    )
    outcome = write(instance, request)
    assert outcome.status == "accepted", outcome
    return outcome


def watched(instance: Any) -> set[str]:
    return {r["cve_id"] for r in query_rows(instance, kit.WATCHED_QUERY)}


def live_subjects(instance: Any, kind: str) -> list[str]:
    with instance.bind_accepted_projection(instance.accepted_coordinate()) as projection:
        return [
            str(row[0]).removeprefix("subjects/").removesuffix(".json")
            for row in projection.typed.connection.execute(
                "SELECT path FROM subjects WHERE path>=? AND path<? AND lifecycle='live' "
                "ORDER BY path",
                (f"subjects/{kind}/", f"subjects/{kind}0"),
            )
        ]


# -- OSV writes, re-observes and retires -------------------------------------------


def test_osv_writes_affected_by_creating_each_vulnerability(tmp_path: Path) -> None:
    instance = world(tmp_path)
    first = run_osv(instance)
    claims = summary(first, "claims")
    # 9 (component, CVE) pairs: one affected_by each; 9 vulnerabilities by value.
    assert (claims.written, claims.subjects_created) == (9, 9)
    assert first.terminal_egress[0].settle_outcome == "settled"
    assert affected(instance) == {CORE: CORE_CVES, API: {API_CVE}, SLF4J: set()}
    written = written_claims(instance, first)
    assert len(written) == 9
    roots = {c.backing.capture_digests for c in written}
    assert len(roots) == 1  # every Claim cites the one derived osv.match document
    assert {accepted(instance, c).backing.procedure_evidence.value.basis for c in written} == {
        "extracted"
    }
    # No fixed_in Claim: the fixed versions stay in the cited derived document.
    assert not any(p.endswith(".fixed_in") for (_s, p) in changed(instance, first))
    document = derived_document(instance, first, node="matched")
    (log4shell,) = [
        r for r in document["affected"] if (r["purl"], r["cve_id"]) == (CORE, LOG4SHELL)
    ]
    assert log4shell["fixed"] == ["2.12.2", "2.15.0", "2.3.1"]
    # The watch list (K-B1-2) now comes from OSV: Log4Shell is watched.
    assert LOG4SHELL in watched(instance) and len(watched(instance)) == 9


def test_an_identical_osv_run_writes_nothing(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    before = instance.accepted_coordinate()
    again = run_osv(instance, minute=1)
    claims = summary(again, "claims")
    assert (claims.written, claims.revised, claims.re_observed) == (0, 0, 9)
    assert again.terminal_egress[0].proposal_id is None
    assert instance.accepted_coordinate() == before


def test_a_cve_osv_no_longer_lists_retires_on_the_complete_read(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)

    def drop_api(results: list[Any]) -> None:
        results[BATCH_ORDER.index(API)] = {}

    state = run_osv(instance, OSV({QUERYBATCH: batch_with(drop_api)}), minute=1)
    claims = summary(state, "claims")
    assert (claims.retired, claims.re_observed) == (1, 8)
    assert state.terminal_egress[0].settle_outcome == "settled"
    (retired,) = written_claims(instance, state)
    assert retired.lifecycle.state == "retired"
    assert retired.retirement.absence.logical_source == inventory.OSV_SOURCE
    assert affected(instance)[API] == set()


def test_a_component_osv_did_not_answer_in_full_is_never_retired(tmp_path: Path) -> None:
    """K-B1-6 / incomplete answers: an unreadable advisory leaves log4j-core out of
    ``queried``; its eight CVEs stay, while log4j-api re-observes."""

    instance = world(tmp_path)
    run_osv(instance)
    missing = (dependency_replay.RECORDINGS / "vuln-missing.body").read_bytes()
    state = run_osv(instance, OSV({LOG4SHELL_ADVISORY: (404, missing)}), minute=1)
    claims = summary(state, "claims")
    assert (claims.retired, claims.written) == (0, 0)
    assert claims.re_observed == 1
    assert affected(instance)[CORE] == CORE_CVES


def test_a_request_with_no_response_marks_the_run_incomplete_and_retires_nothing(
    tmp_path: Path,
) -> None:
    """R-ON2: osv.query names ``responses`` incomplete; positives still write, the
    derive over the list is incomplete, and absence never retires."""

    instance = world(tmp_path)
    run_osv(instance)

    def drop_api(results: list[Any]) -> None:
        results[BATCH_ORDER.index(API)] = {}

    origin = OSV(
        {QUERYBATCH: batch_with(drop_api)},
        drop=("https://api.osv.dev/v1/vulns/GHSA-vc5p-v9hr-52mj",),
    )
    state = run_osv(instance, origin, minute=1)
    assert state.completeness is not None and not state.completeness.complete
    claims = summary(state, "claims")
    assert claims.retired == 0
    # log4j-api would have retired on a complete read: it is still there.
    assert affected(instance)[API] == {API_CVE}


def test_osv_asks_only_about_components_some_inventory_holds(tmp_path: Path) -> None:
    """A component whose every occurrence lost its scope is no longer asked about."""

    instance = world(tmp_path)
    document = json.loads(DEMO_SBOM.read_bytes())
    document["components"] = [c for c in document["components"] if c["name"] != "slf4j-api"]
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    import_sbom(instance, "demo", minute=-5)
    rows = query_rows(instance, osv.OSV_COMPONENTS)
    assert sorted(r["purl"] for r in rows) == [API, CORE]


# -- advisories with no CVE alias reach the inbox ------------------------------------------

#: log4j-api's one advisory (it names API_CVE).
API_ADVISORY_ID = "GHSA-qv9r-c865-cp47"
API_ADVISORY = f"https://api.osv.dev/v1/vulns/{API_ADVISORY_ID}"


def advisory_without_cve(request: Any) -> tuple[int, bytes]:
    """log4j-api's recorded advisory before a CVE was assigned: no CVE alias."""

    del request
    index = json.loads((dependency_replay.RECORDINGS / "index.json").read_text())["exchanges"]
    (item,) = [i for i in index if i["url"] == API_ADVISORY]
    record = json.loads((dependency_replay.RECORDINGS / item["body"]).read_bytes())
    record["aliases"] = []
    return 200, json.dumps(record).encode()


def run_unkeyed(instance: Any, upstream: Any, *, minute: int = 0) -> Any:
    """Run the unkeyed Line as its Trigger does: on the OSV run's derived match document."""

    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        TriggerFire,
        service_run_playbill_line,
    )
    from tests.support.operation_world import actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    (call,) = (node for node in upstream.nodes if node.node == "matched")
    (event,) = [
        o.capture_event
        for o in upstream.outcomes
        if o.event_kind == "produced_capture" and o.node_id == call.node
    ]
    state = service_run_playbill_line(
        instance,
        path_identity_digest=osv.UNKEYED_LINE,
        request=LineRunRequest(line=osv.UNKEYED_LINE),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(NOW + timedelta(minutes=minute)),
        trigger_fire=TriggerFire(trigger=osv.UNKEYED_TRIGGER, event=event),
    )
    assert state.status == "succeeded", state.terminal
    return state


def unkeyed_items(instance: Any) -> list[Any]:
    """Every item the unkeyed Line posted."""

    from cruxible_core.service.procedures.line_inbox import (
        service_get_inbox_item,
        service_list_inbox,
    )
    from cruxible_core.storage.cas import BodyAccessContext

    access = BodyAccessContext(principal_id="reader", can_read_body=True)
    listed = service_list_inbox(instance, line=osv.UNKEYED_LINE, limit=200, access=access)
    assert not listed.truncated
    return [
        service_get_inbox_item(instance, item=entry.item.item_id, access=access)
        for entry in listed.entries
    ]


def test_an_advisory_with_no_cve_reaches_the_inbox_until_osv_names_its_cve(
    tmp_path: Path,
) -> None:
    """An advisory with no CVE alias writes nothing (no vulnerability to key) and
    posts one inbox item; the same data again posts nothing new (the item is seen
    again); once the advisory names its CVE, the finding is an ordinary affected_by
    Claim and the item is no longer posted (it stays in the inbox as it was)."""

    instance = world(tmp_path)
    unkeyed = OSV({API_ADVISORY: advisory_without_cve})
    first = run_osv(instance, unkeyed)
    assert affected(instance) == {CORE: CORE_CVES, API: set(), SLF4J: set()}

    posted = run_unkeyed(instance, first, minute=1)
    assert (summary(posted, "extract").records, summary(posted, "extract").invalid_records) == (
        1,
        0,
    )
    assert summary(posted, "post_inbox").emitted == 1
    (item,) = unkeyed_items(instance)
    assert item.payload == {"osv_id": API_ADVISORY_ID, "purl": API}
    assert (item.item.status, item.item.occurrences) == ("unread", 1)

    # The same data again: the same item, seen again, nothing new.
    again = run_osv(instance, OSV({API_ADVISORY: advisory_without_cve}), minute=2)
    run_unkeyed(instance, again, minute=3)
    (seen,) = unkeyed_items(instance)
    assert (seen.item.item_id, seen.item.status, seen.item.occurrences) == (
        item.item.item_id,
        "unread",
        2,
    )

    # OSV names the CVE: an ordinary finding, and nothing posted.
    keyed = run_osv(instance, minute=4)
    assert affected(instance)[API] == {API_CVE}
    late = run_unkeyed(instance, keyed, minute=5)
    assert summary(late, "post_inbox").emitted == 0
    (kept,) = unkeyed_items(instance)
    assert (kept.item.item_id, kept.item.occurrences) == (item.item.item_id, 2)


def test_the_unkeyed_line_runs_on_the_osv_match_landing() -> None:
    """The unkeyed Line binds its triggering Capture (the match call is substituted,
    never re-run), observes only, and its Trigger names the OSV Line's source."""

    members = {
        (m["kind"], m["name"]): m for m in kit.automation([], now=NOW)["members"]
    }
    line = members[("line", osv.UNKEYED_LINE)]
    assert (line["trigger_input"], line["max_authority"]) == ("matched.document", "observe")
    assert not [
        m for m in members.values() if m.get("line_name") == osv.UNKEYED_LINE
        and m["kind"] == "procedure_mandate"
    ]
    trigger = members[("trigger", osv.UNKEYED_TRIGGER)]
    assert trigger["schedule"] == {
        "kind": "capture_landing",
        "capture_contract": inventory.OSV_MATCH_KIND,
        "logical_sources": [members[("line", osv.OSV_LINE)]["parameters"]["logical_source"]],
    }


# -- judgments (D-R46 R4, K-B2-J1) and the track record (K-B2-TR) ---------------------


def shared_log4shell(results: list[Any]) -> None:
    """log4j-api is also named by the Log4Shell advisory (a test edit), so one CVE
    affects two components."""

    results[BATCH_ORDER.index(API)].setdefault("vulns", []).append(
        {"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2026-01-01T00:00:00Z"}
    )


def test_the_worklists_list_one_row_per_occurrence(tmp_path: Path) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance)
    rows = exposures(instance)
    assert len(rows) == 18  # nine pairs, in each of two inventories
    assert {(DEMO_APP, CORE, LOG4SHELL), (OTHER_APP, CORE, LOG4SHELL)} <= rows
    (row,) = [
        r
        for r in query_rows(instance, triage.URGENT)
        if (r["inventory"], r["component"], r["cve_id"]) == (DEMO_APP, CORE, LOG4SHELL)
    ]
    assert row["scope"] == "required"
    assert row["occurrence"] == occurrence_of(instance, DEMO_APP, CORE)


def test_a_package_judgment_lands_in_one_write_and_silences_every_inventory(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance, OSV({QUERYBATCH: batch_with(shared_log4shell)}))
    before = exposures(instance)
    assert {(DEMO_APP, CORE, LOG4SHELL), (DEMO_APP, API, LOG4SHELL)} <= before
    outcome = judge(instance, CORE, LOG4SHELL)
    # One write: the retirement, the none, the exposure pair and its justification.
    assert outcome.changes[2].resolved == "created"
    assert live_subjects(instance, inventory.EXPOSURE) == [outcome.changes[2].subject]
    assert LOG4SHELL not in affected(instance)[CORE]
    assert none_claim(instance, CORE, LOG4SHELL)
    # The same package release everywhere: both inventories' rows go.
    assert before - exposures(instance) == {
        (DEMO_APP, CORE, LOG4SHELL),
        (OTHER_APP, CORE, LOG4SHELL),
    }
    # V still affects log4j-api, so it is still watched; judging that too drops it.
    assert LOG4SHELL in watched(instance)
    judge(instance, API, LOG4SHELL)
    assert LOG4SHELL not in watched(instance)
    assert CORE_CVES - {LOG4SHELL} <= watched(instance)


def test_a_package_judgment_refuses_as_a_whole(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    before = instance.accepted_coordinate().git_oid
    # Without retiring OSV's live value, the none beside it is refused: nothing lands.
    request = package_judgment(instance, CORE, LOG4SHELL)
    request["changes"] = [c for c in request["changes"] if c["op"] != "retire"]
    assert write(instance, request).status == "refused"
    # An app-level reason is no package-level justification (R4): refused by the enum.
    request = package_judgment(instance, CORE, LOG4SHELL)
    request["changes"][-1]["value"] = APP_REASON
    assert write(instance, request).status == "refused"
    assert instance.accepted_coordinate().git_oid == before
    assert live_subjects(instance, inventory.EXPOSURE) == []
    assert LOG4SHELL in affected(instance)[CORE]
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance)
    with pytest.raises(ValueError, match="app-level"):
        triage.judgment(CORE, LOG4SHELL, reason=APP_REASON, because="x")


def test_an_app_judgment_silences_only_its_own_inventory(tmp_path: Path) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance)
    outcome = app_judge(instance, DEMO_APP, CORE, LOG4SHELL)
    assert outcome.changes[0].resolved == "created"
    rows = exposures(instance)
    assert (DEMO_APP, CORE, LOG4SHELL) not in rows
    assert (OTHER_APP, CORE, LOG4SHELL) in rows
    # It never states the global none: OSV's observation and the watch list stay.
    assert LOG4SHELL in affected(instance)[CORE]
    assert LOG4SHELL in watched(instance)
    assert live_subjects(instance, inventory.EXPOSURE) == []
    # OSV's next run re-observes V, with nothing to disagree with.
    again = run_osv(instance, minute=1)
    assert not [f for f in again.findings if f.kind == "held_disagrees"]
    assert (DEMO_APP, CORE, LOG4SHELL) not in exposures(instance)


LOG4J_CONFIG = "app/src/main/resources/log4j2.xml"
LOG4J_CONFIG_V1 = b"""<Configuration>
  <Appenders><Console name="out"><PatternLayout pattern="%d %p %c - %m%n"/></Console></Appenders>
  <Loggers><Root level="info"><AppenderRef ref="out"/></Root></Loggers>
</Configuration>
"""
#: The passage the judgment cites: the only appender the configuration declares.
CITED = '<Console name="out">'
FILE_CATALOG = f"""\
tag: playbill-source-catalog-v1
catalog_kind: portable
entries:
  - name: demo-app.log4j-config
    locator: {LOG4J_CONFIG}
"""


def _next_rows(instance: Any, tmp_path: Path, reason: str) -> list[Any]:
    """``next``'s rows of one reason, with the workspace observed as the CLI does
    (the local catalog observation, enriched through the real coverage read)."""

    from cruxible_client.authoring.workspace import (
        observe_next_workspace,
        observe_next_workspace_with_coverage,
    )
    from cruxible_core.service.discovery.next import (
        NextRequest,
        NextWorkspaceObservation,
        service_playbill_next,
    )
    from cruxible_core.indexes.projection import AcceptedCoordinate
    from test_pilot_gate import workspace
    from tests.test_authoring.test_block_sync_service import ACCESS_PROFILE, _ServiceClient

    root = workspace(tmp_path)
    observation, _coordinate = observe_next_workspace_with_coverage(
        _ServiceClient(instance),  # type: ignore[arg-type]
        instance.descriptor.instance_id,
        root,
        observation=observe_next_workspace(root),
        access_profile=ACCESS_PROFILE.model_dump(mode="json"),
    )
    result = service_playbill_next(
        instance,
        request=NextRequest(
            at=AcceptedCoordinate.from_internal(instance.accepted_coordinate()),
            evaluation_time=NOW + timedelta(hours=1),
            access_profile=ACCESS_PROFILE,
            workspace_observation=NextWorkspaceObservation.model_validate(observation),
        ),
    )
    return [item for item in result.items if item.reason == reason]


def test_an_app_judgment_citing_code_is_supported_and_drifts_when_the_code_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dependency guidance says to cite the code read: the justification admits a
    catalogued workspace file (the ``file`` rule), so the judgment is supported and
    ``next`` reports ``citation_drifted`` once that code changes."""

    from cruxible_client.authoring.write_evidence import observe_changes
    from cruxible_client.contracts.write import WriteRequest
    from cruxible_core.service.authoring.write_verbs import service_playbill_write
    from test_pilot_gate import workspace
    from tests.core_support._write_support import caller

    # next reads the daemon registry under the state root: keep it in scratch.
    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = world(tmp_path)
    run_osv(instance)
    write_file(tmp_path, ".cruxible/files.yaml", FILE_CATALOG.encode())
    write_file(tmp_path, LOG4J_CONFIG, LOG4J_CONFIG_V1)
    request = triage.app_judgment(
        occurrence_of(instance, DEMO_APP, CORE),
        "CVE-2021-44832",
        reason=APP_REASON,
        because="The logging configuration is static and names no JDBC appender.",
        accept="if_allowed",
    )
    request["changes"][-1]["evidence"] = {"kind": "file", "file": f"{LOG4J_CONFIG}#{CITED}"}
    sent = WriteRequest.model_validate(request)
    sent = sent.model_copy(
        update={"changes": observe_changes(sent.changes, workspace=workspace(tmp_path))}
    )
    outcome = service_playbill_write(instance, request=sent, caller=caller())
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    (justification,) = [c for c in outcome.changes if c.field == "justification"]
    assert justification.verdict == "supported"
    assert (DEMO_APP, CORE, "CVE-2021-44832") not in exposures(instance)
    assert _next_rows(instance, tmp_path, "citation_drifted") == []

    write_file(
        tmp_path,
        LOG4J_CONFIG,
        # The cited passage itself changes: a JDBC appender replaces the console.
        LOG4J_CONFIG_V1.replace(CITED.encode(), b'<JDBC name="out">'),
    )
    drifted = _next_rows(instance, tmp_path, "citation_drifted")
    assert drifted, "editing the cited code must surface citation_drifted"
    claim = justification_claim(instance, justification.subject)
    assert any(claim in json.dumps(row.model_dump(mode="json")) for row in drifted), drifted


def test_an_app_judgment_refuses_as_a_whole(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    before = instance.accepted_coordinate().git_oid
    request = triage.app_judgment(
        occurrence_of(instance, DEMO_APP, CORE),
        LOG4SHELL,
        reason=APP_REASON,
        because="x",
        accept="if_allowed",
    )
    request["changes"][-1]["value"] = PACKAGE_REASON  # package-level only (R4)
    assert write(instance, request).status == "refused"
    assert instance.accepted_coordinate().git_oid == before
    assert live_subjects(instance, inventory.APP_EXPOSURE) == []
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance)
    with pytest.raises(ValueError, match="package-level"):
        triage.app_judgment("x", LOG4SHELL, reason=PACKAGE_REASON, because="x")


DEPENDENCY_GUIDANCE = "document:security.guidance.dependency"


def install_dependency_guidance(instance: Any) -> list[str]:
    """What ``install.main`` does for the dependency guidance (``body store``, then
    ``document propose``), landed."""

    from cruxible_client.contracts.documents import DocumentShell
    from cruxible_core.service.authoring.documents import service_propose_playbill_document
    from cruxible_core.service.authoring.landing import land_direct_proposal

    import install

    store = instance.body_store()
    landed = []
    for item in install.guidance_documents(
        lambda path: store.store(path.read_bytes()).digest,
        install.DEPENDENCY_GUIDANCE,
        references=False,
    ):
        shell = DocumentShell.model_validate(item)
        inspection = service_propose_playbill_document(
            instance,
            shell=shell,
            actor_id="owner",
            proposal_name=shell.identity.removeprefix("document:"),
            timestamp="2026-10-29T11:59:00.000000Z",
        )
        inspection = land_direct_proposal(
            instance, inspection, actor_id="owner", accept="if_allowed", may_activate=True
        )
        assert inspection.outcome is not None and inspection.outcome.status == "landed"
        landed.append(shell.identity)
    return landed


def guides(instance: Any, ref: str) -> list[str]:
    """The ``guides`` links ``get REF detail=backlinks`` serves."""

    result = get(instance, ref, detail="backlinks")
    return [link.source for link in result.backlinks.links if link.relation == "guides"]


def test_a_judgment_written_for_review_shows_the_guidance_and_changes_nothing(
    tmp_path: Path,
) -> None:
    """K-CF2a: the dependency guidance guides both justifications; the author writes
    with accept: never, and the proposal a reviewer reads carries the guidance."""

    from cruxible_core.service.proposals.review import service_review_playbill_proposal
    from cruxible_core.storage.cas import BodyAccessContext

    instance = world(tmp_path)
    assert install_dependency_guidance(instance) == [DEPENDENCY_GUIDANCE]
    for pair in (inventory.EXPOSURE, inventory.APP_EXPOSURE):
        assert guides(instance, f"ClaimType:{pair}.justification") == [DEPENDENCY_GUIDANCE]
    assert guides(instance, f"ClaimType:{inventory.APP_EXPOSURE}.verdict") == [DEPENDENCY_GUIDANCE]
    run_osv(instance)
    before = instance.accepted_coordinate().git_oid
    request = package_judgment(instance, CORE, LOG4SHELL)
    request["accept"] = "never"
    outcome = write(instance, request)
    assert outcome.status == "awaiting_approval", outcome
    assert instance.accepted_coordinate().git_oid == before
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance)
    review = service_review_playbill_proposal(
        instance,
        proposal_id=outcome.proposal.proposal_id,
        access=BodyAccessContext(principal_id="reviewer", can_read_body=True),
        detail=False,
    )
    assert [(g.definition, g.document) for g in review.guidance] == [
        (f"ClaimType:{inventory.EXPOSURE}.justification", DEPENDENCY_GUIDANCE)
    ]
    # An affected verdict goes to review the same way, and changes nothing until approved.
    request = triage.affected_judgment(
        occurrence_of(instance, DEMO_APP, CORE), LOG4SHELL, because="Reachable."
    )
    assert request["accept"] == "never"
    outcome = write(instance, request)
    assert outcome.status == "awaiting_approval", outcome
    assert instance.accepted_coordinate().git_oid == before
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance)
    assert query_rows(instance, triage.CONFIRMED) == []
    review = service_review_playbill_proposal(
        instance,
        proposal_id=outcome.proposal.proposal_id,
        access=BodyAccessContext(principal_id="reviewer", can_read_body=True),
        detail=False,
    )
    assert [(g.definition, g.document) for g in review.guidance] == [
        (f"ClaimType:{inventory.APP_EXPOSURE}.verdict", DEPENDENCY_GUIDANCE)
    ]


def test_osv_reobserving_a_judged_pair_records_held_disagrees_and_the_judgment_stays(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    judge(instance, CORE, LOG4SHELL)
    before = affected(instance)
    state = run_osv(instance, minute=1)
    (found,) = [f for f in state.findings if f.kind == "held_disagrees"]
    assert found.target.endswith(":" + AFFECTED) and found.role == "normative"
    assert found.held_value["kind"] == "none" and found.incoming_value["kind"] == "subject"
    assert "held_disagrees" in kit.FINDINGS  # the OSV Line routes it to its inbox
    assert affected(instance) == before and LOG4SHELL not in before[CORE]
    card = get(instance, component(CORE)).card
    (row,) = [r for r in card.claims if r.predicate == "affected_by"]
    assert [n.of for n in row.nones] == [f"{kit.VULN}/{LOG4SHELL.lower()}"]
    assert (DEMO_APP, CORE, LOG4SHELL) not in exposures(instance)


def test_the_track_record_lists_each_judgment_with_its_justification(tmp_path: Path) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance)
    judge(instance, CORE, LOG4SHELL)
    app_judge(instance, OTHER_APP, API, API_CVE)
    (row,) = query_rows(instance, triage.JUDGMENTS)
    assert (row["component"], row["cve_id"], row["justification"]) == (
        CORE,
        LOG4SHELL,
        PACKAGE_REASON,
    )
    (app,) = query_rows(instance, triage.APP_JUDGMENTS)
    assert (app["inventory"], app["component"], app["cve_id"], app["justification"]) == (
        OTHER_APP,
        API,
        API_CVE,
        APP_REASON,
    )
    # Who and when: each Claim's history.
    claims = (
        justification_claim(instance, f"{inventory.EXPOSURE}/{row['exposure']}"),
        none_claim(instance, CORE, LOG4SHELL),
        justification_claim(instance, f"{inventory.APP_EXPOSURE}/{app['app_exposure']}"),
    )
    for claim in claims:
        (revision,) = get(instance, claim, detail="history").history.revisions
        assert revision.actor == "owner" and revision.accepted


def test_reversing_a_judgment_retires_its_none_and_justification_together(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance)
    judge(instance, CORE, LOG4SHELL)
    app_judge(instance, DEMO_APP, API, API_CVE)
    (row,) = query_rows(instance, triage.JUDGMENTS)
    exposure = f"{inventory.EXPOSURE}/{row['exposure']}"
    reverse = triage.reverse_judgment(
        justification_claim(instance, exposure),
        none=none_claim(instance, CORE, LOG4SHELL),
        because="The JNDI lookup class is present after all.",
        accept="if_allowed",
    )
    assert write(instance, reverse).status == "accepted"
    (app,) = query_rows(instance, triage.APP_JUDGMENTS)
    reverse_app = triage.reverse_judgment(
        justification_claim(instance, f"{inventory.APP_EXPOSURE}/{app['app_exposure']}"),
        because="The app now logs request headers.",
        accept="if_allowed",
    )
    assert write(instance, reverse_app).status == "accepted"
    assert query_rows(instance, triage.JUDGMENTS) == []
    assert query_rows(instance, triage.APP_JUDGMENTS) == []
    # The pairs stay as history; OSV's next run restores the link.
    assert live_subjects(instance, inventory.EXPOSURE) == [exposure]
    run_osv(instance, minute=1)
    rows = exposures(instance)
    assert {(DEMO_APP, CORE, LOG4SHELL), (OTHER_APP, CORE, LOG4SHELL)} <= rows
    assert (DEMO_APP, API, API_CVE) in rows


# -- affected verdicts: confirmed, fix pending ------------------------------------------


def test_an_affected_verdict_moves_only_its_own_occurrence_to_confirmed(
    tmp_path: Path,
) -> None:
    """The worklists list pairs with no judgment; an affected verdict moves its one
    occurrence to ``confirmed_exposures`` and leaves every other inventory's row."""

    instance = world(tmp_path, other=True)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    pair_demo, pair_other = (DEMO_APP, CORE, LOG4SHELL), (OTHER_APP, CORE, LOG4SHELL)
    for query in (triage.URGENT, triage.BACKLOG):
        assert {pair_demo, pair_other} <= exposures(instance, query)
    assert query_rows(instance, triage.CONFIRMED) == []

    outcome = confirm(instance, DEMO_APP, CORE, LOG4SHELL)
    # One write: the pair and its verdict, nothing else (no justification, no none).
    assert [(c.op, c.field) for c in outcome.changes] == [("create", None), ("set", "verdict")]
    assert outcome.changes[1].verdict == "supported"
    for query in (triage.URGENT, triage.BACKLOG):
        rows = exposures(instance, query)
        assert pair_demo not in rows and pair_other in rows
    (row,) = query_rows(instance, triage.CONFIRMED)
    assert (row["inventory"], row["component"], row["cve_id"]) == pair_demo
    assert row["occurrence"] == occurrence_of(instance, DEMO_APP, CORE)
    assert row["app_exposure"] == outcome.changes[0].subject.rsplit("/", 1)[-1]
    assert row["scope"] == "required" and row["kev_date_added"] and row["kev_due_date"]
    # It is no not_affected judgment, and it never touches OSV's observation.
    assert query_rows(instance, triage.APP_JUDGMENTS) == []
    assert LOG4SHELL in affected(instance)[CORE] and LOG4SHELL in watched(instance)
    again = run_osv(instance, minute=2)
    assert not [f for f in again.findings if f.kind == "held_disagrees"]
    assert exposures(instance, triage.CONFIRMED) == {pair_demo}


JAVA_HANDLER = "app/src/main/java/com/example/RequestLogger.java"
JAVA_HANDLER_V1 = b"""package com.example;

final class RequestLogger {
    void log(Request request) {
        LOG.info("agent {}", request.header("User-Agent"));
    }
}
"""
#: The passage the verdict cites: the attacker-controlled header reaching log4j.
REACHES = 'LOG.info("agent {}", request.header("User-Agent"));'
HANDLER_CATALOG = f"""\
tag: playbill-source-catalog-v1
catalog_kind: portable
entries:
  - name: demo-app.request-logger
    locator: {JAVA_HANDLER}
"""


def test_an_affected_verdict_citing_code_is_supported_and_drifts_when_the_code_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The affected verdict admits the same evidence as a justification: the code
    that reaches the vulnerable function, cited by passage, so ``next`` reports
    ``citation_drifted`` once that code changes."""

    from cruxible_client.authoring.write_evidence import observe_changes
    from cruxible_client.contracts.write import WriteRequest
    from cruxible_core.service.authoring.write_verbs import service_playbill_write
    from test_pilot_gate import workspace
    from tests.core_support._write_support import caller

    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = world(tmp_path)
    run_osv(instance)
    write_file(tmp_path, ".cruxible/files.yaml", HANDLER_CATALOG.encode())
    write_file(tmp_path, JAVA_HANDLER, JAVA_HANDLER_V1)
    request = triage.affected_judgment(
        occurrence_of(instance, DEMO_APP, CORE),
        LOG4SHELL,
        because="The User-Agent header reaches LOG.info, which expands ${jndi:...} lookups.",
        evidence={"kind": "file", "file": f"{JAVA_HANDLER}#{REACHES}"},
        accept="if_allowed",
    )
    sent = WriteRequest.model_validate(request)
    sent = sent.model_copy(
        update={"changes": observe_changes(sent.changes, workspace=workspace(tmp_path))}
    )
    outcome = service_playbill_write(instance, request=sent, caller=caller())
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    (verdict,) = [c for c in outcome.changes if c.field == "verdict"]
    assert verdict.verdict == "supported"
    assert exposures(instance, triage.CONFIRMED) == {(DEMO_APP, CORE, LOG4SHELL)}
    assert _next_rows(instance, tmp_path, "citation_drifted") == []

    write_file(
        tmp_path,
        JAVA_HANDLER,
        # The cited passage changes: the header is no longer logged.
        JAVA_HANDLER_V1.replace(REACHES.encode(), b'LOG.info("request");'),
    )
    drifted = _next_rows(instance, tmp_path, "citation_drifted")
    assert drifted, "editing the cited code must surface citation_drifted"
    claim = verdict_claim(instance, verdict.subject)
    assert any(claim in json.dumps(row.model_dump(mode="json")) for row in drifted), drifted


def test_reversing_an_affected_verdict_to_not_affected_is_one_write(tmp_path: Path) -> None:
    """``app_judgment(verdict=True)`` revises the affected verdict to not_affected and
    states the justification in the same write; the pair moves to the track record."""

    instance = world(tmp_path)
    run_osv(instance)
    confirm(instance, DEMO_APP, CORE, LOG4SHELL)
    (row,) = query_rows(instance, triage.CONFIRMED)
    pair = f"{inventory.APP_EXPOSURE}/{row['app_exposure']}"
    first = verdict_claim(instance, pair)
    request = triage.app_judgment(
        row["occurrence"],
        LOG4SHELL,
        reason="inline_mitigations_already_exist",
        because="log4j2.formatMsgNoLookups=true is set in the launcher.",
        verdict=True,
        accept="if_allowed",
    )
    outcome = write(instance, request)
    assert outcome.status == "accepted", outcome
    assert outcome.changes[0].resolved == "existing"
    assert query_rows(instance, triage.CONFIRMED) == []
    (app,) = query_rows(instance, triage.APP_JUDGMENTS)
    assert (app["app_exposure"], app["justification"]) == (
        row["app_exposure"],
        "inline_mitigations_already_exist",
    )
    assert (DEMO_APP, CORE, LOG4SHELL) not in exposures(instance)
    # The same verdict Claim, revised: affected, then not_affected.
    assert verdict_claim(instance, pair) == first
    revisions = get(instance, first, detail="history").history.revisions
    assert len(revisions) == 2


def test_an_affected_verdict_beside_a_justification_is_no_judgment(tmp_path: Path) -> None:
    """Core has no cross-Claim refusal, so the rule is the read: affected beside a
    justification (in one write, or a justification later landing on an affected
    pair without revising the verdict) is no judgment. The pair stays in the
    worklists and in neither list, so a contradictory write never silences a row;
    the guidance tells the reviewer to reject it."""

    instance = world(tmp_path, other=True)
    run_osv(instance)
    both = triage.affected_judgment(
        occurrence_of(instance, DEMO_APP, CORE), LOG4SHELL, because="x", accept="if_allowed"
    )
    both["changes"].append(
        {
            "op": "set",
            "subject": {"created": "app_exposure"},
            "field": "justification",
            "value": APP_REASON,
            "role": "normative",
        }
    )
    assert write(instance, both).status == "accepted"
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance)
    assert query_rows(instance, triage.CONFIRMED) == []
    assert query_rows(instance, triage.APP_JUDGMENTS) == []

    # A reversal that forgets the verdict: the confirmed row goes back to the worklist.
    confirm(instance, OTHER_APP, CORE, LOG4SHELL)
    assert exposures(instance, triage.CONFIRMED) == {(OTHER_APP, CORE, LOG4SHELL)}
    app_judge(instance, OTHER_APP, CORE, LOG4SHELL)  # justification only
    assert query_rows(instance, triage.CONFIRMED) == []
    assert query_rows(instance, triage.APP_JUDGMENTS) == []
    assert (OTHER_APP, CORE, LOG4SHELL) in exposures(instance)

    # A bare not_affected verdict (no justification) is no judgment either.
    bare = triage.affected_judgment(
        occurrence_of(instance, DEMO_APP, API), API_CVE, because="x", accept="if_allowed"
    )
    bare["changes"][-1]["value"] = "not_affected"
    assert write(instance, bare).status == "accepted"
    assert (DEMO_APP, API, API_CVE) in exposures(instance)


def _contend(pair: str, field: str, value: str) -> dict[str, Any]:
    return {
        "op": "set",
        "subject": pair,
        "field": field,
        "value": value,
        "role": "normative",
        "contend": True,
    }


def _contested_verdict_with_justification(instance: Any) -> None:
    """affected, then not_affected written beside it (contend) with a justification."""

    pair = confirm(instance, DEMO_APP, CORE, LOG4SHELL).changes[1].subject
    outcome = write(
        instance,
        {
            "because": "A second assessment disagrees; both stand for review.",
            "changes": [
                _contend(pair, "verdict", "not_affected"),
                {
                    "op": "set",
                    "subject": pair,
                    "field": "justification",
                    "value": APP_REASON,
                    "role": "normative",
                },
            ],
        },
    )
    assert outcome.status == "accepted", outcome


def _contested_justification(instance: Any) -> None:
    """Two competing justification values, no verdict."""

    pair = app_judge(instance, DEMO_APP, CORE, LOG4SHELL).changes[0].subject
    outcome = write(
        instance,
        {
            "because": "A competing reason.",
            "changes": [_contend(pair, "justification", "inline_mitigations_already_exist")],
        },
    )
    assert outcome.status == "accepted", outcome


def _contested_affected_verdict(instance: Any) -> None:
    """affected, then not_affected written beside it (contend), no justification."""

    pair = confirm(instance, DEMO_APP, CORE, LOG4SHELL).changes[1].subject
    outcome = write(
        instance,
        {"because": "Disputed.", "changes": [_contend(pair, "verdict", "not_affected")]},
    )
    assert outcome.status == "accepted", outcome


@pytest.mark.parametrize(
    "contest",
    [_contested_verdict_with_justification, _contested_justification, _contested_affected_verdict],
    ids=["verdict-with-justification", "justification", "affected-verdict"],
)
def test_a_contested_judgment_is_no_judgment(tmp_path: Path, contest: Any) -> None:
    """A judgment counts only when its value is resolved: a contested verdict or
    justification (real ``contend`` writes) leaves the pair in both worklists and in
    neither the not_affected track record nor the confirmed list."""

    instance = world(tmp_path)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    contest(instance)
    pair = (DEMO_APP, CORE, LOG4SHELL)
    (ae,) = live_subjects(instance, inventory.APP_EXPOSURE)
    flags = [r.flags for r in get(instance, ae).card.claims if r.predicate != "occurrence"]
    assert any("contested" in f for f in flags), flags  # the write really contested
    assert pair in exposures(instance, triage.URGENT)
    assert pair in exposures(instance, triage.BACKLOG)
    assert query_rows(instance, triage.APP_JUDGMENTS) == []
    assert query_rows(instance, triage.CONFIRMED) == []


def test_a_confirmed_exposure_clears_when_the_sbom_drops_the_component_and_next_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An SBOM that no longer lists the component retires the occurrence's scope:
    the row leaves ``confirmed_exposures``, and core resurfaces the verdict on the
    now-unobserved occurrence as a ``claim_dependency_stale`` row in ``next``."""

    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = world(tmp_path)
    run_osv(instance)
    occurrence = occurrence_of(instance, DEMO_APP, CORE)
    outcome = confirm(instance, DEMO_APP, CORE, LOG4SHELL)
    claim = verdict_claim(instance, outcome.changes[1].subject)
    assert exposures(instance, triage.CONFIRMED) == {(DEMO_APP, CORE, LOG4SHELL)}
    assert _next_rows(instance, tmp_path, "claim_dependency_stale") == []

    document = json.loads(DEMO_SBOM.read_bytes())
    document["components"] = [c for c in document["components"] if c["name"] != "log4j-core"]
    write_file(tmp_path, DEMO_PATH, json.dumps(document).encode())
    import_sbom(instance, "demo", minute=2)
    assert query_rows(instance, triage.CONFIRMED) == []
    assert not {r for r in exposures(instance) if r[1] == CORE}
    stale = _next_rows(instance, tmp_path, "claim_dependency_stale")
    assert [row.subject_identity for row in stale] == [f"Claim:{claim}"], stale
    (entry,) = stale[0].detail["stale_inputs"]
    assert entry["subject_end"] == f"Subject:{inventory.OCCURRENCE}/{occurrence}"


# -- triage worklists ---------------------------------------------------------------


def test_urgent_exposures_put_kev_first_and_the_backlog_drops_judged_pairs(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path, other=True)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    rows = query_rows(instance, triage.URGENT)
    assert len(rows) == 18
    listed = [r["cve_id"] for r in rows if r.get("kev_date_added")]
    assert listed and rows[0]["cve_id"] in listed
    assert [r["cve_id"] for r in rows[: len(listed)]] == listed
    backlog = exposures(instance, triage.BACKLOG)
    assert {(DEMO_APP, CORE, LOG4SHELL), (OTHER_APP, CORE, LOG4SHELL)} <= backlog
    assert all(cve in listed for _i, _c, cve in backlog)
    app_judge(instance, DEMO_APP, CORE, LOG4SHELL)
    backlog = exposures(instance, triage.BACKLOG)
    assert (DEMO_APP, CORE, LOG4SHELL) not in backlog
    assert (OTHER_APP, CORE, LOG4SHELL) in backlog
    judge(instance, CORE, LOG4SHELL)
    assert not {(i, c, v) for i, c, v in exposures(instance, triage.BACKLOG) if v == LOG4SHELL}


def _attest_unsure(instance: Any, tmp_path: Path, claim: str, request: dict[str, Any]) -> None:
    """An agent's ``claim attest --unsure`` (examined), signed with the owner's key."""

    from cruxible_core.service.evidence.claim_attestations import (
        service_append_claim_attestation,
    )
    from tests.test_claims.test_claim_attestation_service import _request

    at = NOW + timedelta(minutes=2)
    name = get(instance, claim).card.claim
    service_append_claim_attestation(
        instance,
        request=_request(
            instance,
            OWNERS[instance.root],
            str(name).removeprefix("Claim:"),
            tmp_path,
            basis="examined_existing",
            stance=request["stance"],
            captures=(),
            attested_at=at,
            valid_until=request["valid_until"],
        ),
        actor_id="owner",
        recorded_at=at,
    )


def _kev_due_soon(instance: Any, due: Any) -> None:
    catalog = kev_catalog()
    record(catalog, LOG4SHELL)["dueDate"] = due.isoformat()
    kev(instance, catalog, minute=1)


def test_a_pair_under_investigation_stays_in_the_backlog_until_the_kev_due_date(
    tmp_path: Path,
) -> None:
    """K-CF1: an unsure attestation on OSV's affected_by, capped at a KEV due date
    sooner than 14 days; the pair stays in the backlog, and reading its one Claim
    marks it."""

    instance = world(tmp_path)
    run_osv(instance)
    due = (NOW + timedelta(days=10)).date()
    _kev_due_soon(instance, due)
    claim = affected_claim(instance, CORE, LOG4SHELL)
    request = triage.investigation(
        claim,
        because="Checking whether the demo app's log pattern reaches JNDI lookups.",
        until=NOW + timedelta(days=90),
        kev_due_date=due,
        now=NOW,
    )
    # A due date still ahead and sooner than 14 days ends the hold.
    assert request["valid_until"] == triage._end_of_day(due)
    assert triage.investigation_argv(request)[:4] == ["claim", "attest", claim, "--unsure"]
    _attest_unsure(instance, tmp_path, claim, request)
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance, triage.BACKLOG)

    def marked(at: Any) -> bool:
        evidence = get(instance, claim, detail="evidence", evaluation_time=at).evidence
        return triage.under_investigation(evidence.attestations)

    assert marked(NOW + timedelta(minutes=3))
    assert not marked(triage._end_of_day(due) + timedelta(minutes=1))
    assert not triage.under_investigation(
        get(
            instance, affected_claim(instance, API, API_CVE), detail="evidence"
        ).evidence.attestations
    )
    # An until already past is refused.
    with pytest.raises(ValueError, match="already past"):
        triage.investigation(claim, because="x", until=NOW - timedelta(minutes=1), now=NOW)


@pytest.mark.parametrize(
    "local",
    ["2026-10-25T12:00", "2027-03-07T12:00", "2026-07-01T12:00"],
    ids=["autumn-dst", "spring-dst", "no-change"],
)
def test_a_hold_is_336_hours_across_a_daylight_saving_change(local: str) -> None:
    """14 days are 336 elapsed hours whatever zone now is given in: America/New_York
    leaves DST on 2026-11-01 and enters it on 2027-03-14."""

    from datetime import UTC, datetime
    from zoneinfo import ZoneInfo

    now = datetime.fromisoformat(local).replace(tzinfo=ZoneInfo("America/New_York"))
    cap = triage.hold_until(now=now)
    assert cap.tzinfo == UTC
    assert cap - now.astimezone(UTC) == timedelta(hours=336)
    held = triage.investigation("CLM-x", because="checking", now=now)["valid_until"]
    assert held == cap
    # A sooner until in another zone is compared as an instant.
    until = now + timedelta(days=2)
    assert triage.investigation("CLM-x", because="x", until=until, now=now)[
        "valid_until"
    ] == until.astimezone(UTC)


def test_a_past_due_kev_pair_is_held_for_14_days(tmp_path: Path) -> None:
    """A KEV due date already past neither shortens nor cancels the hold: the real
    attestation lands with a 14-day valid_until and marks the row until then."""

    instance = world(tmp_path)
    run_osv(instance)
    past = (NOW - timedelta(days=30)).date()
    _kev_due_soon(instance, past)
    claim = affected_claim(instance, CORE, LOG4SHELL)
    request = triage.investigation(
        claim, because="Checking the log pattern.", kev_due_date=past, now=NOW
    )
    assert request["valid_until"] == NOW + timedelta(days=14)
    _attest_unsure(instance, tmp_path, claim, request)
    assert (DEMO_APP, CORE, LOG4SHELL) in exposures(instance, triage.BACKLOG)

    def marked(at: Any) -> bool:
        evidence = get(instance, claim, detail="evidence", evaluation_time=at).evidence
        return triage.under_investigation(evidence.attestations)

    assert marked(NOW + timedelta(days=13))
    assert not marked(NOW + timedelta(days=14, minutes=1))


@pytest.mark.parametrize(
    ("due_in_days", "held"),
    [
        (None, timedelta(days=14)),  # no KEV entry
        (5, None),  # KEV due in 5 days: the end of that day
        (30, timedelta(days=14)),  # KEV due in 30 days: 14 days is sooner
        (-1, timedelta(days=14)),  # KEV due in the past: neither shortens nor cancels
    ],
    ids=["no-kev", "kev-in-5-days", "kev-in-30-days", "kev-past-due"],
)
def test_a_hold_lasts_at_most_14_days_or_until_a_sooner_kev_due_date(
    due_in_days: int | None, held: timedelta | None
) -> None:
    due = None if due_in_days is None else (NOW + timedelta(days=due_in_days)).date()
    request = triage.investigation("CLM-x", because="checking", kev_due_date=due, now=NOW)
    expected = triage._end_of_day(due) if held is None else NOW + held
    assert request["valid_until"] == expected == triage.hold_until(now=NOW, kev_due_date=due)
    if due_in_days == 5:
        assert timedelta(days=5) <= expected - NOW < timedelta(days=6)
    # A sooner until shortens it; a later one never lengthens it.
    sooner = NOW + timedelta(days=2)
    assert (
        triage.investigation("CLM-x", because="x", until=sooner, kev_due_date=due, now=NOW)[
            "valid_until"
        ]
        == sooner
    )
    later = NOW + timedelta(days=90)
    assert (
        triage.investigation("CLM-x", because="x", until=later, kev_due_date=due, now=NOW)[
            "valid_until"
        ]
        == expected
    )


# -- exposure counts ----------------------------------------------------------------


def answer(instance: Any) -> Any:
    """``cruxible query --name NAME [--at OID] --json``, served."""

    from cruxible_client.contracts.compact_query import QueryRequest
    from cruxible_core.service.discovery.compact_query import service_playbill_query

    def read(name: str, at: str | None) -> Any:
        return service_playbill_query(instance, request=QueryRequest(name=name, limit=500, at=at))

    return read


def counts(instance: Any) -> dict[str, int]:
    """``triage.exposure_counts`` over the served named-query answers, at one head."""

    counted = triage.exposure_counts(answer(instance))
    assert counted.at == instance.accepted_coordinate().git_oid
    return counted.as_dict()


def test_exposure_counts_say_covered_new_confirmed_and_pair_without_judgment(
    tmp_path: Path,
) -> None:
    """How many exposures are covered (a resolved not_affected judgment, either level),
    new (unjudged), confirmed, and on the worklist with a judgment pair but no
    judgment (part of new: withdrawn, or created before judging), from the rows of
    named Queries."""

    instance = world(tmp_path, other=True)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    assert counts(instance) == {"covered": 0, "new": 18, "confirmed": 0, "pair_without_judgment": 0}
    app = app_judge(instance, DEMO_APP, CORE, LOG4SHELL)  # one occurrence
    judge(instance, CORE, "CVE-2021-45046")  # package level: both inventories
    confirm(instance, OTHER_APP, CORE, "CVE-2021-44832")
    assert counts(instance) == {"covered": 3, "new": 14, "confirmed": 1, "pair_without_judgment": 0}
    covered = exposures(instance, triage.COVERED_APP) | exposures(instance, triage.COVERED_PACKAGE)
    assert covered == {
        (DEMO_APP, CORE, LOG4SHELL),
        (DEMO_APP, CORE, "CVE-2021-45046"),
        (OTHER_APP, CORE, "CVE-2021-45046"),
    }
    # Withdrawn: the pair is back in the worklists, counted as a pair without judgment.
    reverse = triage.reverse_judgment(
        justification_claim(instance, app.changes[0].subject),
        because="The app now logs request headers.",
        accept="if_allowed",
    )
    assert write(instance, reverse).status == "accepted"
    assert counts(instance) == {"covered": 2, "new": 14, "confirmed": 1, "pair_without_judgment": 1}
    assert exposures(instance, triage.PAIR_WITHOUT_JUDGMENT) == {(DEMO_APP, CORE, LOG4SHELL)}
    assert exposures(instance, triage.PAIR_WITHOUT_JUDGMENT) <= exposures(instance)
    # A contested judgment holds a judgment Claim: new, not a pair without judgment.
    _contested_justification_on(instance, OTHER_APP, CORE, LOG4SHELL)
    assert counts(instance) == {"covered": 2, "new": 14, "confirmed": 1, "pair_without_judgment": 1}
    # A Query sees no history: a pair created before any judgment (here linked to a
    # codebase fact first, which the guidance says not to do) reads like a withdrawn one.
    fact = (
        write(
            instance,
            {
                "because": "How the app logs.",
                "changes": [
                    {
                        "op": "create",
                        "label": "fact",
                        "subject_kind": facts.CODE_FACT,
                        "key": [
                            {
                                "predicate": f"{facts.CODE_FACT}.repo",
                                "value": "github.com/acme/app",
                            },
                            {"predicate": f"{facts.CODE_FACT}.topic", "value": "log-helper"},
                        ],
                    }
                ],
            },
        )
        .changes[0]
        .subject
    )
    linked = write(
        instance,
        {
            "because": "Linked before judging.",
            "changes": [
                triage._app_pair(occurrence_of(instance, DEMO_APP, CORE), "CVE-2021-45105"),
                {
                    "op": "add",
                    "subject": {"created": "app_exposure"},
                    "field": "rests_on",
                    "value": fact,
                },
            ],
        },
    )
    assert linked.status == "accepted", linked
    assert counts(instance) == {"covered": 2, "new": 13, "confirmed": 1, "pair_without_judgment": 2}
    # A capped answer is refused rather than under-counted.
    capped = {"oid": "a" * 40}
    with pytest.raises(ValueError, match="capped"):
        triage.exposure_counts(
            lambda name, at: {
                "rows": [],
                "remaining": 0,
                "capped": ("max_results=200",),
                "receipt": {"coordinate": {"git_oid": capped["oid"]}},
            }
        )


def test_exposure_counts_read_every_query_at_one_coordinate(tmp_path: Path) -> None:
    """A judgment withdrawn between two of the reads: pinned reads still answer at
    the first read's coordinate, so the counts are that head's (never covered 9 /
    new -1); a surface that ignores the pin is refused, never combined."""

    instance = world(tmp_path)
    run_osv(instance)
    pair = app_judge(instance, DEMO_APP, CORE, LOG4SHELL).changes[0].subject
    before = counts(instance)
    assert before == {"covered": 1, "new": 8, "confirmed": 0, "pair_without_judgment": 0}
    head = instance.accepted_coordinate().git_oid
    served = answer(instance)

    def withdraw() -> None:
        reverse = triage.reverse_judgment(
            justification_claim(instance, pair), because="Withdrawn.", accept="if_allowed"
        )
        assert write(instance, reverse).status == "accepted"

    def moving(pinned: bool) -> Any:
        seen: list[str] = []

        def read(name: str, at: str | None) -> Any:
            if name == triage.PAIR_WITHOUT_JUDGMENT and not seen:
                seen.append(name)
                withdraw()  # the head moves between urgent_exposures and this read
            return served(name, at if pinned else None)

        return read

    counted = triage.exposure_counts(moving(pinned=True))
    assert (counted.as_dict(), counted.at) == (before, head)
    after = counts(instance)
    assert after == {"covered": 0, "new": 8, "confirmed": 0, "pair_without_judgment": 1}
    # The head moves again under a surface that ignores the pin: refused.
    pair = app_judge(instance, DEMO_APP, CORE, LOG4SHELL).changes[0].subject
    with pytest.raises(triage.MixedCoordinates):
        triage.exposure_counts(moving(pinned=False))
    # An explicit coordinate reads the past head whole.
    assert triage.exposure_counts(served, at=head[:12]).as_dict() == before


#: The package x app matrix: (CVE on log4j-core, package state, demo app state,
#: other app state). Package states: none, not_affected. App states: none,
#: not_affected, affected, contested (two justifications), both (affected beside a
#: justification), withdrawn (a justification retired).
_MATRIX = (
    ("CVE-2021-45046", None, None, "not_affected"),
    ("CVE-2021-44832", None, "affected", "contested"),
    ("CVE-2021-45105", None, "both", "withdrawn"),
    ("CVE-2025-68161", "not_affected", None, "not_affected"),
    ("CVE-2026-34477", "not_affected", "affected", "contested"),
    ("CVE-2026-34479", "not_affected", "both", "withdrawn"),
)


def _app_state(instance: Any, inventory_id: str, cve_id: str, state: str | None) -> None:
    if state is None:
        return
    if state == "not_affected":
        app_judge(instance, inventory_id, CORE, cve_id)
    elif state == "affected":
        confirm(instance, inventory_id, CORE, cve_id)
    elif state == "contested":
        _contested_justification_on(instance, inventory_id, CORE, cve_id)
    elif state == "both":
        pair = confirm(instance, inventory_id, CORE, cve_id).changes[0].subject
        both = {"op": "set", "subject": pair, "field": "justification", "value": APP_REASON}
        assert write(instance, {"because": "Both.", "changes": [both]}).status == "accepted"
    elif state == "withdrawn":
        pair = app_judge(instance, inventory_id, CORE, cve_id).changes[0].subject
        reverse = triage.reverse_judgment(
            justification_claim(instance, pair), because="Withdrawn.", accept="if_allowed"
        )
        assert write(instance, reverse).status == "accepted"
    else:
        raise AssertionError(state)


def test_the_four_counts_partition_every_package_and_app_judgment_state(tmp_path: Path) -> None:
    """Over every package x app state, each exposure is in exactly one of covered,
    confirmed, new and pair without judgment. A resolved app-level affected verdict
    beside a package-level not_affected judgment is confirmed, never covered: the
    package judgment neither covers it nor brings it back to the worklists."""

    instance = world(tmp_path, other=True)
    run_osv(instance)
    for cve_id, package, demo, other in _MATRIX:
        _app_state(instance, DEMO_APP, cve_id, demo)
        _app_state(instance, OTHER_APP, cve_id, other)
        if package == "not_affected":
            judge(instance, CORE, cve_id)
    pairs = {
        (app, purl, cve_id)
        for app in (DEMO_APP, OTHER_APP)
        for purl, cves in ((CORE, CORE_CVES), (API, {API_CVE}))
        for cve_id in cves
    }
    worklist = exposures(instance)
    without = exposures(instance, triage.PAIR_WITHOUT_JUDGMENT)
    sets = {
        "covered": exposures(instance, triage.COVERED_APP)
        | exposures(instance, triage.COVERED_PACKAGE),
        "confirmed": exposures(instance, triage.CONFIRMED),
        "new": worklist - without,
        "pair_without_judgment": without,
    }
    assert without <= worklist
    for one, two in ((a, b) for a in sets for b in sets if a < b):
        assert not sets[one] & sets[two], (one, two, sets[one] & sets[two])
    assert set().union(*sets.values()) == pairs, pairs - set().union(*sets.values())
    assert counts(instance) == {name: len(rows) for name, rows in sets.items()}
    expected = {
        "covered": {
            (OTHER_APP, CORE, "CVE-2021-45046"),
            (DEMO_APP, CORE, "CVE-2025-68161"),
            (OTHER_APP, CORE, "CVE-2025-68161"),
            (OTHER_APP, CORE, "CVE-2026-34477"),
            (DEMO_APP, CORE, "CVE-2026-34479"),
            (OTHER_APP, CORE, "CVE-2026-34479"),
        },
        "confirmed": {(DEMO_APP, CORE, "CVE-2021-44832"), (DEMO_APP, CORE, "CVE-2026-34477")},
        "pair_without_judgment": {(OTHER_APP, CORE, "CVE-2021-45105")},
    }
    expected["new"] = pairs - set().union(*expected.values())
    assert sets == expected
    # The cross-scope pair: confirmed only; the package track record still lists the
    # package judgment (a list of judgments, not of exposures).
    assert (DEMO_APP, CORE, "CVE-2026-34477") not in worklist
    assert "CVE-2026-34477" in {r["cve_id"] for r in query_rows(instance, triage.JUDGMENTS)}


def _contested_justification_on(instance: Any, inventory_id: str, purl: str, cve_id: str) -> None:
    pair = app_judge(instance, inventory_id, purl, cve_id).changes[0].subject
    outcome = write(
        instance,
        {
            "because": "A competing reason.",
            "changes": [_contend(pair, "justification", "inline_mitigations_already_exist")],
        },
    )
    assert outcome.status == "accepted", outcome


# -- work counts --------------------------------------------------------------------

_SIZES = (10, 20, 40)


def synthetic_sbom(size: int, app: str = "pkg:generic/scale-app@1", prefix: str = "p") -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"name": "app", "purl": app}},
            "components": [
                {"type": "library", "name": f"{prefix}{i}", "purl": f"pkg:pypi/{prefix}{i}@1.0"}
                for i in range(size)
            ],
        }
    ).encode()


def synthetic_osv(size: int) -> Any:
    """One advisory (one CVE, one fix) per component, answered by a fake OSV.

    osv.query asks in sorted purl order; the batch answers in that order.
    """

    order = sorted(range(size), key=lambda i: f"pkg:pypi/p{i}@1.0")
    batch = {"results": [{"vulns": [{"id": f"GHSA-{i:04d}"}]} for i in order]}
    overrides: dict[str, Any] = {QUERYBATCH: (200, json.dumps(batch).encode())}
    for i in range(size):
        record = {
            "id": f"GHSA-{i:04d}",
            "aliases": [f"CVE-2026-{1000 + i}"],
            "affected": [
                {
                    "package": {"purl": f"pkg:pypi/p{i}"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
                }
            ],
        }
        overrides[f"https://api.osv.dev/v1/vulns/GHSA-{i:04d}"] = (
            200,
            json.dumps(record).encode(),
        )
    return OSV(overrides)


def counted_osv_run(tmp_path: Path, size: int) -> dict[str, float]:
    from tests.test_scale._counters import counting, trace_sqlite

    with trace_sqlite(tmp_path):
        instance = kit_world(tmp_path, sboms=(("demo", DEMO_PATH),))
        write_file(tmp_path, DEMO_PATH, synthetic_sbom(size))
        import_sbom(instance, "demo", minute=-10)
        origin = synthetic_osv(size)
        with counting(tmp_path) as window:
            state = run_osv(instance, origin)
    assert not window.unexplained, window.unexplained
    assert summary(state, "claims").written == size
    assert len(origin.requests) == 1 + size
    return {
        "sql_statements": window.counts["sql_statements"],
        "projection_binds": window.counts["projection_binds"],
        "claim_parses": window.counts["claim_parses"],
    }


def test_osv_work_is_linear_in_components(tmp_path: Path) -> None:
    """Work counts at three sizes: the marginal cost of a component stays flat."""

    measured = {}
    for size in _SIZES:
        root = tmp_path / f"n{size}"
        root.mkdir()
        measured[size] = counted_osv_run(root, size)
    small, middle, large = (measured[size] for size in _SIZES)
    steps = (_SIZES[1] - _SIZES[0], _SIZES[2] - _SIZES[1])
    for counter in ("sql_statements", "projection_binds", "claim_parses"):
        low = (middle[counter] - small[counter]) / steps[0]
        high = (large[counter] - middle[counter]) / steps[1]
        assert high <= low * 1.15 + 2.0, (counter, measured)


_FLAT = ("sql_statements", "sql_vm_steps", "projection_binds", "claim_parses")


def counted_triage_reads(tmp_path: Path, unrelated: int) -> dict[str, dict[str, float]]:
    """The worklist reads of the demo app beside an unrelated inventory of
    ``unrelated`` components (imported after OSV ran: no vulnerability reaches them),
    and the one-Claim read that marks a pair under investigation."""

    from tests.test_scale._counters import counting, trace_sqlite

    out: dict[str, dict[str, float]] = {}
    with trace_sqlite(tmp_path):
        instance = kit_world(tmp_path, sboms=(("demo", DEMO_PATH), ("other", OTHER_PATH)))
        write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
        import_sbom(instance, "demo", minute=-10)
        run_osv(instance, minute=-8)
        due = (NOW + timedelta(days=10)).date()
        _kev_due_soon(instance, due)
        write_file(tmp_path, OTHER_PATH, synthetic_sbom(unrelated, "pkg:generic/other@1", "u"))
        import_sbom(instance, "other", minute=2)
        claim = affected_claim(instance, CORE, LOG4SHELL)
        request = triage.investigation(
            claim, because="checking", until=NOW + timedelta(days=5), now=NOW
        )
        _attest_unsure(instance, tmp_path, claim, request)
        confirm(instance, DEMO_APP, API, API_CVE)
        # One pair covered at package level, one at app level, one judgment withdrawn.
        judge(instance, CORE, "CVE-2021-45046")
        app_judge(instance, DEMO_APP, CORE, "CVE-2021-45105")
        withdrawn = app_judge(instance, DEMO_APP, CORE, "CVE-2021-44832").changes[0].subject
        reverse = triage.reverse_judgment(
            justification_claim(instance, withdrawn), because="withdrawn", accept="if_allowed"
        )
        assert write(instance, reverse).status == "accepted"
        for name, read in (
            ("urgent", lambda: query_rows(instance, triage.URGENT)),
            ("backlog", lambda: query_rows(instance, triage.BACKLOG)),
            ("confirmed", lambda: query_rows(instance, triage.CONFIRMED)),
            ("covered_app", lambda: query_rows(instance, triage.COVERED_APP)),
            ("covered_package", lambda: query_rows(instance, triage.COVERED_PACKAGE)),
            ("pair_without_judgment", lambda: query_rows(instance, triage.PAIR_WITHOUT_JUDGMENT)),
            # The attention reads: unfiltered, and over a threshold in every inventory
            # or in one. Nothing is scored, so every unjudged pair passes the filter: the
            # filter's own work, with no rows saved to pay for it.
            ("unjudged", lambda: query_rows(instance, triage.UNJUDGED)),
            (
                "unjudged_over",
                lambda: query_rows(instance, triage.UNJUDGED_OVER, params={"min_epss": "0.1"}),
            ),
            (
                "unjudged_over_in",
                lambda: query_rows(
                    instance,
                    triage.UNJUDGED_OVER_IN,
                    params={"inventory": DEMO_APP, "min_epss": "0.1"},
                ),
            ),
            (
                "investigation",
                lambda: (
                    get(
                        instance,
                        claim,
                        detail="evidence",
                        evaluation_time=NOW + timedelta(minutes=3),
                    ).evidence.attestations
                ),
            ),
        ):
            read()  # warm: the first read after a write folds that write's projections
            with counting(tmp_path) as window:
                result = read()
            assert not window.unexplained, window.unexplained
            if name == "urgent":
                # Nine pairs: one confirmed, one covered per level; the withdrawn one is back.
                assert len(result) == 6
            if name == "confirmed":
                assert [r["cve_id"] for r in result] == [API_CVE]
            if name in ("covered_app", "covered_package", "pair_without_judgment"):
                assert len(result) == 1, (name, result)
            if name == "investigation":
                assert triage.under_investigation(result)
            if name == "unjudged":
                unjudged = sorted(r["cve_id"] for r in result)
            if name in ("unjudged_over", "unjudged_over_in"):
                assert sorted(r["cve_id"] for r in result) == unjudged, (name, result)
            out[name] = {counter: window.counts[counter] for counter in _FLAT}
    return out


def test_triage_reads_are_flat_in_unrelated_inventories(tmp_path: Path) -> None:
    """The worklists (and the app-level covered and pair-without-judgment lists) start from the
    vulnerabilities' links and reach occurrences by the pair index, and the confirmed
    and package-level covered lists from the judgment pairs, so an unrelated inventory
    growing 10 -> 40 costs them nothing; the investigation mark is one Claim read per
    pair. The attention Lines' filtered reads (over a threshold, in every inventory
    or in one) cost no more than the unfiltered unjudged read."""

    # One warm-up world first: process-wide caches fill once, on whichever world
    # runs first in this worker, so neither measured size pays for them.
    (tmp_path / "warm").mkdir()
    counted_triage_reads(tmp_path / "warm", 10)
    measured = {}
    for unrelated in (10, 40):
        root = tmp_path / f"u{unrelated}"
        root.mkdir()
        measured[unrelated] = counted_triage_reads(root, unrelated)
    for read in (
        "urgent",
        "backlog",
        "confirmed",
        "covered_app",
        "covered_package",
        "pair_without_judgment",
        "unjudged",
        "unjudged_over",
        "unjudged_over_in",
        "investigation",
    ):
        small, large = measured[10][read], measured[40][read]
        for counter in ("sql_statements", "projection_binds", "claim_parses"):
            assert large[counter] == small[counter], (read, counter, measured)
        assert large["sql_vm_steps"] <= small["sql_vm_steps"] * 1.05, (read, measured)
    # The attention Lines' filtered reads cost no more than the unfiltered one.
    for size in (10, 40):
        for read in ("unjudged_over", "unjudged_over_in"):
            for counter in ("sql_statements", "projection_binds", "claim_parses", "sql_vm_steps"):
                assert measured[size][read][counter] <= measured[size]["unjudged"][counter], (
                    read,
                    counter,
                    measured[size],
                )


def test_chain_sbom_osv_kev_without_a_seed(tmp_path: Path) -> None:
    """The whole loop with no seed: SBOM -> OSV -> watch list -> KEV settles."""

    instance = world(tmp_path)
    run_osv(instance)
    catalog = kev(instance, fixture_bytes("kev-catalog"), minute=1)
    written = {p for (_c, p) in changed(instance, catalog)}
    assert kit.VULN + ".listed_in" in written
    assert catalog.terminal_egress[0].settle_outcome == "settled"


def test_a_cve_osv_adds_gets_an_epss_score_on_the_next_run_with_no_line_change(
    tmp_path: Path,
) -> None:
    """EPSS reads the watch list when it runs (D-R34): a CVE OSV newly lists for an
    inventoried component is asked for, and scored, on EPSS's next run; the Line
    is the same artifact before and after."""

    instance = world(tmp_path)

    def drop_api(results: list[Any]) -> None:
        results[BATCH_ORDER.index(API)] = {}

    run_osv(instance, OSV({QUERYBATCH: batch_with(drop_api)}))
    head = {k: v for k, v in epss_answer().items() if k != "data"}
    data = [
        {"cve": c, "epss": "0.100000000", "percentile": "0.900000000", "date": "2026-11-02"}
        for c in sorted({*CORE_CVES, API_CVE})
    ]
    answer = {**head, "total": len(data), "data": data}
    tree = instance.tree_at(instance.accepted_coordinate().git_oid)
    line = tree[f"lines/{kit.EPSS_LINE}.json"]

    before = EpssOrigin(answer)
    first = epss(instance, before, minute=1)
    (asked,) = before.pages
    assert sorted(asked) == sorted(CORE_CVES)
    assert {c for c, _ in changed(instance, first)} == {c.lower() for c in CORE_CVES}

    run_osv(instance, minute=2)  # OSV now lists API_CVE for log4j-api
    after = EpssOrigin(answer)
    second = epss(instance, after, minute=3)
    (asked,) = after.pages
    assert sorted(asked) == sorted({*CORE_CVES, API_CVE})
    assert set(changed(instance, second)) == {
        (API_CVE.lower(), kit.VULN + p)
        for p in (".epss_score", ".epss_percentile", ".epss_score_date")
    }
    assert second.terminal_egress[0].settle_outcome == "settled"
    assert (
        instance.tree_at(instance.accepted_coordinate().git_oid)[f"lines/{kit.EPSS_LINE}.json"]
        == line
    )


def test_judgments_never_settle_under_a_mandate() -> None:
    """Judgments are agents' alone: no Line's settle scope names the none's predicate
    for normative writes, a justification, a verdict, or a judgment pair."""

    automation = kit.automation([], now=NOW, sboms=(("demo", DEMO_PATH),))
    scoped = {
        entry["claim_type"]
        for member in automation["members"]
        if member["kind"] == "procedure_mandate"
        for entry in member.get("scope", ())
    }
    assert not {c for c in scoped if c.endswith((".justification", ".verdict"))}
    assert f"{inventory.APP_EXPOSURE}.verdict" in {
        r["predicate"] for r in inventory.claim_type_records()
    }
    created = {
        kind
        for member in automation["members"]
        if member["kind"] == "procedure_mandate"
        for kind in member.get("subject_creation", ())
    }
    assert not created & {inventory.EXPOSURE, inventory.APP_EXPOSURE}
    assert osv.OSV_SETTLE_SCOPE == {
        AFFECTED: {
            "create": {"basis": ["extracted"]},
            "revise": {"basis": ["extracted"]},
            "retire": {"basis": ["absence"]},
        }
    }
