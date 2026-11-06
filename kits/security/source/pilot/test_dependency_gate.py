"""Dependency-loop gate: SBOM -> OSV -> KEV/EPSS -> agents judge -> track record.

The kit's own payloads in a fresh in-process instance (``test_pilot_gate``'s
world), the demo SBOM imported by its Line, and the OSV Line answered by the
REAL security-osv-provider code over OSV's recorded exchanges
(``security-osv-provider/tests/recordings``; ``dependency_replay``). No test
opens a socket.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_dependency_gate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import dependency_replay  # noqa: E402
import inventory  # noqa: E402
import osv  # noqa: E402
import triage  # noqa: E402
from test_pilot_gate import (
    Replay,
    accepted,
    changed,
    fixture_bytes,
    import_sbom,
    kev,
    kit,
    kit_world,
    service_run,
    submit,
    summary,
    write_file,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "sboms"
DEMO_SBOM = EXAMPLES / "log4j-demo-app.cdx.json"
DEMO_PATH = "sboms/log4j-demo-app.cdx.json"
CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
API = "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
SLF4J = "pkg:maven/org.slf4j/slf4j-api@1.7.32"
LOG4SHELL = "CVE-2021-44228"
API_CVE = "CVE-2026-49844"
OSV = dependency_replay.RecordedOsv
QUERYBATCH = "https://api.osv.dev/v1/querybatch"
LOG4SHELL_ADVISORY = "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q"
AFFECTED = osv.AFFECTED_BY
FIXED = osv.FIXED_IN
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


def world(tmp_path: Path) -> Any:
    instance = kit_world(tmp_path, sboms=(("demo", DEMO_PATH),))
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
    import_sbom(instance, "demo", minute=-10)
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
    """Every Claim the run changed (``changed`` keys by Subject and predicate only)."""

    from tests.test_procedures.test_claims_terminal import candidate_claims

    return [
        c for c in candidate_claims(instance, state) if c.statement.predicate in {AFFECTED, FIXED}
    ]


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


def judgment(instance: Any, purl: str, cve_id: str, *, retire: bool = True) -> Any:
    return triage.judgment(
        purl,
        cve_id,
        reason="vulnerable_code_not_in_execute_path",
        because=f"The demo app never logs attacker input through {purl.split('/')[-1]}.",
        retire=(affected_claim(instance, purl, cve_id),) if retire else (),
    )


def judge(instance: Any, purl: str, cve_id: str) -> Any:
    """An agent's not_affected judgment: its VEX reason FIRST, then the none of V."""

    both = judgment(instance, purl, cve_id)
    submit(instance, both.reason, name=f"reason-{abs(hash((purl, cve_id))):x}")
    outcome = write(instance, both.verdict)
    assert outcome.status == "accepted", outcome
    return outcome


def status(instance: Any, purl: str) -> list[dict[str, Any]]:
    (row,) = query_rows(
        instance,
        None,
        kind=inventory.COMPONENT,
        where=[{"field": "purl", "eq": purl}],
        select=("purl", "not_affected_reason", "affected_by"),
        claims=True,
    )
    return triage.judgment_status(row)


# -- OSV writes, re-observes and retires -------------------------------------------


def test_osv_writes_affected_by_creating_each_vulnerability_and_its_fixed_versions(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path)
    first = run_osv(instance)
    claims = summary(first, "claims")
    # 9 (component, CVE) pairs: affected_by + fixed_in each; 9 vulnerabilities by value.
    assert (claims.written, claims.subjects_created) == (18, 9)
    assert first.terminal_egress[0].settle_outcome == "settled"
    assert affected(instance) == {CORE: CORE_CVES, API: {API_CVE}, SLF4J: set()}
    written = written_claims(instance, first)
    assert len(written) == 18
    roots = {c.backing.capture_digests for c in written}
    assert len(roots) == 1  # every Claim cites the one derived osv.match document
    fixed = [accepted(instance, c) for c in written if c.statement.predicate == FIXED]
    log4shell = next(c for c in fixed if c.statement.qualifier == LOG4SHELL)
    assert log4shell.statement.object.value == ["2.12.2", "2.15.0", "2.3.1"]
    assert {c.backing.procedure_evidence.value.basis for c in written} == {"extracted"}
    # The watch list (K-B1-2) now comes from OSV: Log4Shell is watched.
    watched = {r["cve_id"] for r in query_rows(instance, kit.WATCHED_QUERY)}
    assert LOG4SHELL in watched and len(watched) == 9


def test_an_identical_osv_run_writes_nothing(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    before = instance.accepted_coordinate()
    again = run_osv(instance, minute=1)
    claims = summary(again, "claims")
    assert (claims.written, claims.revised, claims.re_observed) == (0, 0, 18)
    assert again.terminal_egress[0].proposal_id is None
    assert instance.accepted_coordinate() == before


def test_a_cve_osv_no_longer_lists_retires_on_the_complete_read(tmp_path: Path) -> None:
    instance = world(tmp_path)
    run_osv(instance)

    def drop_api(results: list[Any]) -> None:
        results[BATCH_ORDER.index(API)] = {}

    state = run_osv(instance, OSV({QUERYBATCH: batch_with(drop_api)}), minute=1)
    claims = summary(state, "claims")
    assert (claims.retired, claims.re_observed) == (2, 16)  # affected_by + fixed_in
    assert state.terminal_egress[0].settle_outcome == "settled"
    retired = written_claims(instance, state)
    assert len(retired) == 2
    assert {c.lifecycle.state for c in retired} == {"retired"}
    assert {c.retirement.absence.logical_source for c in retired} == {inventory.OSV_SOURCE}
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
    assert claims.re_observed == 2
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


# -- judgments (K-B2-J1, J1b) and the track record (K-B2-TR) -------------------------


def shared_log4shell(results: list[Any]) -> None:
    """log4j-api is also named by the Log4Shell advisory (a test edit), so one CVE
    affects two components."""

    results[BATCH_ORDER.index(API)].setdefault("vulns", []).append(
        {"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2026-01-01T00:00:00Z"}
    )


def exposures(instance: Any, query: str = triage.URGENT) -> set[tuple[str, str]]:
    return {(r["component"], r["cve_id"]) for r in query_rows(instance, query)}


def test_a_judgment_removes_v_from_the_watch_list_for_that_component_only(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path)
    run_osv(instance, OSV({QUERYBATCH: batch_with(shared_log4shell)}))
    assert {(CORE, LOG4SHELL), (API, LOG4SHELL)} <= exposures(instance)
    outcome = judge(instance, CORE, LOG4SHELL)
    assert [s["status"] for s in status(instance, CORE)] == [triage.JUDGED]
    # A self-sourced normative "none of V" is admissible under the inverse's [self] rule.
    assert outcome.changes[-1].after.object == {"none": f"{kit.VULN}/{LOG4SHELL.lower()}"}
    assert (CORE, LOG4SHELL) not in exposures(instance)
    assert (API, LOG4SHELL) in exposures(instance)
    watched = {r["cve_id"] for r in query_rows(instance, kit.WATCHED_QUERY)}
    assert LOG4SHELL in watched  # still affects log4j-api
    judge(instance, API, LOG4SHELL)
    watched = {r["cve_id"] for r in query_rows(instance, kit.WATCHED_QUERY)}
    assert LOG4SHELL not in watched
    assert CORE_CVES - {LOG4SHELL} <= watched


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


def test_the_track_record_lists_each_judgment_with_its_reason_and_claim(
    tmp_path: Path,
) -> None:
    instance = world(tmp_path)
    run_osv(instance)
    judge(instance, CORE, LOG4SHELL)
    (row,) = query_rows(instance, triage.JUDGMENTS)
    assert (row["component"], row["not_affected_reason"]) == (
        CORE,
        "vulnerable_code_not_in_execute_path",
    )
    # The CVE each reason is qualified by, and its Claim: the compact query's cells.
    (cells,) = query_rows(
        instance,
        None,
        kind=inventory.COMPONENT,
        where=[{"field": "purl", "eq": CORE}],
        select=("not_affected_reason", "affected_by"),
        claims=True,
    )
    (reason,) = cells["claims"]["not_affected_reason"]
    assert (reason.qualifier, reason.role) == (LOG4SHELL, "normative")
    (none,) = cells["nones"]["affected_by"]
    assert none.of == f"{kit.VULN}/{LOG4SHELL.lower()}"
    # Who and when: each Claim's history.
    for claim in (reason.claim, none.claim):
        (revision,) = get(instance, claim, detail="history").history.revisions
        assert revision.actor == "owner" and revision.accepted


def test_a_judgment_stopped_between_its_writes_leaves_the_pair_exposed_and_pending(
    tmp_path: Path,
) -> None:
    """F3: the reason lands first; when the none of V fails, the pair stays in the
    exposure, the backlog and the watch list, and reads 'judgment incomplete'.
    Making the second write completes it."""

    instance = world(tmp_path)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    both = judgment(instance, CORE, LOG4SHELL, retire=False)
    submit(instance, both.reason, name="reason-first")
    # The second write fails: a none beside the live OSV value is refused.
    refused = write(instance, both.verdict)
    assert refused.status == "refused"
    assert (CORE, LOG4SHELL) in exposures(instance)
    assert (CORE, LOG4SHELL) in exposures(instance, triage.BACKLOG)
    assert LOG4SHELL in {r["cve_id"] for r in query_rows(instance, kit.WATCHED_QUERY)}
    (pending,) = status(instance, CORE)
    assert (pending["cve_id"], pending["status"], pending["none_claim"]) == (
        LOG4SHELL,
        triage.INCOMPLETE,
        None,
    )
    # Recovery: the second write, with OSV's observation retired.
    retry = write(instance, judgment(instance, CORE, LOG4SHELL).verdict)
    assert retry.status == "accepted", retry
    (done,) = status(instance, CORE)
    assert done["status"] == triage.JUDGED and done["none_claim"] and done["reason_claim"]
    assert (CORE, LOG4SHELL) not in exposures(instance)
    assert (CORE, LOG4SHELL) not in exposures(instance, triage.BACKLOG)


# -- triage worklists ---------------------------------------------------------------


def test_urgent_exposures_put_kev_first_and_the_backlog_drops_judged_pairs(
    tmp_path: Path,
) -> None:
    instance = kit_world(tmp_path, sboms=(("demo", DEMO_PATH),))
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
    import_sbom(instance, "demo", minute=-10)
    run_osv(instance)
    kev(instance, fixture_bytes("kev-catalog"), minute=1)
    rows = query_rows(instance, triage.URGENT)
    assert len(rows) == 9
    listed = [r["cve_id"] for r in rows if r.get("kev_date_added")]
    assert listed and rows[0]["cve_id"] in listed
    assert [r["cve_id"] for r in rows[: len(listed)]] == listed
    backlog = exposures(instance, triage.BACKLOG)
    assert (CORE, LOG4SHELL) in backlog
    assert all(cve in listed for _c, cve in backlog)
    judge(instance, CORE, LOG4SHELL)
    assert (CORE, LOG4SHELL) not in exposures(instance, triage.BACKLOG)


# -- work counts --------------------------------------------------------------------

_SIZES = (10, 20, 40)


def synthetic_sbom(size: int) -> bytes:
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
    assert summary(state, "claims").written == 2 * size
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


def test_chain_sbom_osv_kev_without_a_seed(tmp_path: Path) -> None:
    """The whole loop with no seed: SBOM -> OSV -> watch list -> KEV settles."""

    instance = world(tmp_path)
    run_osv(instance)
    catalog = kev(instance, fixture_bytes("kev-catalog"), minute=1)
    written = {p for (_c, p) in changed(instance, catalog)}
    assert kit.VULN + ".listed_in" in written
    assert catalog.terminal_egress[0].settle_outcome == "settled"
