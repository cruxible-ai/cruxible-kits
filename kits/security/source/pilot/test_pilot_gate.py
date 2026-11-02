"""Kit-pilot gate: the slice's own definitions on recorded real bytes.

The payloads ``definitions.py`` writes (the same files the scratch instance
installs) are authored into a fresh in-process instance; the real ``web.fetch``
adapter of the providers checkout answers each Line's call from recordings
(``fixtures/``: the CISA KEV catalog trimmed to 20 records, FIRST's EPSS API
answer verbatim), and each gate scenario edits those bytes. Nothing here is a
copy of a kit definition.

Runs against a core checkout's tests (core test support) and a providers
checkout::

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_pilot_gate.py
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import definitions as kit  # noqa: E402

pytest.importorskip("tests.support.operation_world")

from tests.support.operation_world import NOW, Operator, actor, author  # noqa: E402
from tests.support.provider_checkout import require_provider_checkout  # noqa: E402

FIXTURES = HERE / "fixtures"
EXCHANGES = {
    item["id"]: item for item in json.loads((FIXTURES / "exchanges.json").read_text())["exchanges"]
}
WATCH = kit.DEFAULT_WATCH
LISTED = WATCH[:8]
UNLISTED = WATCH[8:]
DELISTED = "CVE-2021-26855"
VULN = kit.VULN
LISTED_IN = VULN + ".listed_in"
DATE_ADDED = VULN + ".kev_date_added"
DUE_DATE = VULN + ".kev_due_date"
RANSOMWARE = VULN + ".kev_ransomware_use"
SCORE = VULN + ".epss_score"
PERCENTILE = VULN + ".epss_percentile"
SCORE_DATE = VULN + ".epss_score_date"


def kev_catalog() -> dict[str, Any]:
    return json.loads((FIXTURES / "kev-catalog.json").read_bytes())


def epss_answer() -> dict[str, Any]:
    return json.loads((FIXTURES / "epss-api.json").read_bytes())


def _bytes(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, indent=4).encode()


# -- the real web.fetch, answering from recordings ------------------------------------


def _web_fetch() -> Any:
    checkout = require_provider_checkout()
    package = checkout / "packages/cruxible-provider-web/src/cruxible_provider_web"
    if "cruxible_provider_web" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "cruxible_provider_web",
            package / "__init__.py",
            submodule_search_locations=[str(package)],
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["cruxible_provider_web"] = module
        spec.loader.exec_module(module)
    from cruxible_provider_web.fetch import WebFetch

    return WebFetch


class Replay:
    """web.fetch's real client, answered by URL from the bytes a scenario states."""

    def __init__(self, routes: Mapping[str, bytes]) -> None:
        self.routes = dict(routes)
        self.requests: list[str] = []

    def client_factory(self) -> Callable[..., Any]:
        import httpx
        from cruxible_provider_web.http import RecordingClient

        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(str(request.url))
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=self.routes[str(request.url)],
            )

        def factory(recorder: Any, *, url: str, timeout_seconds: float) -> Any:
            del url
            return RecordingClient(
                recorder, timeout_seconds=timeout_seconds, transport=httpx.MockTransport(handle)
            )

        return factory

    def operator(self) -> Operator:
        from cruxible_provider_runtime.egress import EgressRecorder
        from cruxible_provider_runtime.protocol import Budgets
        from cruxible_provider_runtime.provider_api import ProviderRunContext
        from tests.support.operation_world import Invoker

        web_fetch = _web_fetch()

        def output(context: Any) -> dict[str, Any]:
            result = web_fetch(client_factory=self.client_factory())(
                ProviderRunContext(
                    run_id=context.run_id,
                    input=dict(context.input),
                    operation="web.fetch",
                    operation_signature_digest="sha256:" + "9" * 64,
                    build_digest="sha256:" + "b" * 64,
                    implementation_digest="sha256:" + "a" * 64,
                    declared_endpoints=("dynamic:target-from-run-input",),
                    budgets=Budgets(wall_clock_seconds=30, output_bytes=8_000_000),
                    coordinates={},
                    capture_contract=None,
                    secrets={},
                    egress=EgressRecorder(),
                )
            )
            assert result.status == "ok", result
            return dict(result.output)

        return Operator(Invoker(output=output))


# -- the world: exactly the kit's payloads -------------------------------------------


def _web_build(instance: Any, checkout: Path, *, sha: str = "5e") -> Any:
    """A build of the web package as an install lowers it, pinned to the accepted Contracts."""

    from cruxible_client.contracts.providers import (
        ProviderLocalDistributionPin,
        ProviderLocalEnvBackendPin,
    )
    from cruxible_core.providers.package_metadata import read_package_registration
    from cruxible_core.service.procedures.provider_installation import tree_contract_digests

    root = checkout / "packages/cruxible-provider-web/src/cruxible_provider_web"
    digests = tree_contract_digests(instance.tree_at(instance.accepted_coordinate().git_oid))
    registration = read_package_registration(root)
    return registration.provider_definition(
        distribution=ProviderLocalDistributionPin(
            name=registration.manifest.distribution.name,
            version=registration.manifest.distribution.version,
            filename=f"cruxible_provider_web-{sha}-py3-none-any.whl",
            sha256="sha256:" + sha * 32,
        ),
        local_env=ProviderLocalEnvBackendPin(
            lock_sha256="sha256:" + "b" * 64,
            materialization_digests={"linux-cp311": "sha256:" + "c" * 64},
        ),
        control_domain="cruxible-provider-web",
        operations=registration.pinned_operations(digests),
    )


def _install_build(instance: Any, build: Any) -> None:
    from tests.core_support._identity_support import accept_tree
    from tests.support.operation_world import build_files

    accept_tree(instance, build_files(build), name="web-build-" + build.identity.name[-8:])


def submit(instance: Any, payload: Mapping[str, Any], *, name: str) -> None:
    from cruxible_client.contracts.authoring.inputs import ChangeSetInput

    author(instance, ChangeSetInput.model_validate(payload), name=name)


def pilot_world(tmp_path: Path, *, watch: tuple[str, ...] = WATCH) -> Any:
    from cruxible_client.contracts.capture_contract_inputs import (
        CaptureContractInputRecord,
        lower_capture_contract_input,
    )
    from cruxible_client.contracts.captures import capture_contract_path, render_capture_contract
    from tests.core_support._identity_support import accept_tree
    from tests.core_support._support import initialize_local
    from web_contracts import members as web_contract_members

    checkout = require_provider_checkout()
    instance, _owner = initialize_local(tmp_path)
    submit(
        instance,
        {"kind": "change_set", "members": web_contract_members(checkout)},
        name="web-contracts",
    )
    _install_build(instance, _web_build(instance, checkout))
    kinds = {
        capture_contract_path(name): render_capture_contract(
            lower_capture_contract_input(
                CaptureContractInputRecord.model_validate(record), named=True
            )
        )
        for name, record in kit.capture_kinds().items()
    }
    accept_tree(instance, kinds, name="capture-kinds")
    submit(instance, kit.vocabulary(), name="vocabulary")
    # One Procedure per authoring (the test helper accepts what one lowering
    # changed; the served daemon path takes kit.procedures() as one change set).
    from cruxible_client.contracts.authoring.inputs import ProcedureInput

    for index, member in enumerate(kit.procedures()["members"]):
        author(instance, ProcedureInput.model_validate(member), name=f"procedure-{index}")
    submit(instance, kit.watch_subjects(watch), name="watch")
    submit(instance, kit.automation(watch, now=NOW), name="automation")
    return instance


def run(instance: Any, routes: Mapping[str, bytes], *, line: str, minute: int = 0) -> Any:
    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        service_run_playbill_line,
    )
    from tests.test_procedures.test_completeness_transfer import _Clock

    return service_run_playbill_line(
        instance,
        path_identity_digest=line,
        request=LineRunRequest(line=line),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(NOW + timedelta(minutes=minute)),
        provider_runtime_operator=Replay(routes).operator(),  # type: ignore[arg-type]
    )


def kev(instance: Any, catalog: Mapping[str, Any], *, minute: int = 0, line: str = kit.KEV_LINE):
    state = run(instance, {kit.KEV_URL: _bytes(catalog)}, line=line, minute=minute)
    assert state.status == "succeeded", state.terminal
    return state


def epss(instance: Any, answer: Mapping[str, Any], *, minute: int = 0) -> Any:
    state = run(instance, {kit.epss_url(WATCH): _bytes(answer)}, line=kit.EPSS_LINE, minute=minute)
    assert state.status == "succeeded", state.terminal
    return state


def changed(instance: Any, state: Any) -> dict[tuple[str, str], Any]:
    from tests.test_procedures.test_claims_terminal import candidate_claims

    return {
        (
            c.statement.subject.artifact_path.rsplit("/", 1)[-1].removesuffix(".json"),
            c.statement.predicate,
        ): c
        for c in candidate_claims(instance, state)
    }


def summary(state: Any, kind: str) -> Any:
    (found,) = [n.summary for n in state.nodes if n.summary and n.summary.kind == kind]
    return found


def cve(value: str) -> str:
    return value.lower()


def delisted(catalog: Mapping[str, Any], *cves: str) -> dict[str, Any]:
    out = copy.deepcopy(dict(catalog))
    out["vulnerabilities"] = [v for v in out["vulnerabilities"] if v["cveID"] not in cves]
    out["count"] = len(out["vulnerabilities"])
    return out


def record(catalog: dict[str, Any], cve_id: str) -> dict[str, Any]:
    return next(v for v in catalog["vulnerabilities"] if v["cveID"] == cve_id)


# -- the gate ---------------------------------------------------------------------------


def test_g1_identical_runs_write_nothing_and_settle_by_basis(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    first = kev(instance, kev_catalog())
    claims = changed(instance, first)
    assert set(claims) == {
        *((cve(c), p) for c in LISTED for p in (LISTED_IN, DATE_ADDED, DUE_DATE, RANSOMWARE)),
        *((cve(c), LISTED_IN) for c in UNLISTED),
    }
    for c in UNLISTED:
        inverse = claims[(cve(c), LISTED_IN)]
        assert inverse.statement.object.kind == "none"
        assert inverse.backing.procedure_evidence.absence.logical_source == kit.KEV_SOURCE
    assert all(
        claims[(cve(c), p)].backing.procedure_evidence.value.basis == "extracted"
        for c in LISTED
        for p in (LISTED_IN, DATE_ADDED)
    )
    assert first.terminal_egress[0].settle_outcome == "settled"
    assert summary(first, "extract").complete
    assert (summary(first, "claims").written, summary(first, "claims").inverse_written) == (32, 2)
    scored = epss(instance, epss_answer(), minute=1)
    assert len(changed(instance, scored)) == 30
    assert scored.terminal_egress[0].settle_outcome == "settled"

    before = instance.accepted_coordinate()
    again = kev(instance, kev_catalog(), minute=2)
    rescored = epss(instance, epss_answer(), minute=3)
    for state, count in ((again, 34), (rescored, 30)):
        (egress,) = state.terminal_egress
        assert egress.proposal_id is None and all(c.unchanged for c in egress.children)
        written = summary(state, "claims")
        assert (written.written, written.revised, written.re_observed) == (0, 0, count)
    assert instance.accepted_coordinate() == before


def test_g4_g18_a_count_mismatch_never_writes_absence(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    short = kev_catalog()
    short["count"] += 1
    # A first run over an incomplete catalog: positives write; no inverse is
    # inferred for the unlisted CVEs (an absence conclusion over incomplete input).
    first = kev(instance, short)
    claims = changed(instance, first)
    assert not any(c in {cve(u) for u in UNLISTED} for c, _ in claims)
    assert len(claims) == 32
    assert first.completeness is not None
    assert any(r.kind == "count_mismatch" for r in first.completeness.reasons)
    # Over a complete history, the same mismatch on a delisting retires nothing.
    (tmp_path / "second").mkdir()
    instance = pilot_world(tmp_path / "second")
    kev(instance, kev_catalog())
    before = instance.accepted_coordinate()
    gone = delisted(kev_catalog(), DELISTED)
    gone["count"] += 1
    state = kev(instance, gone, minute=1)
    assert state.terminal_egress[0].proposal_id is None
    assert instance.accepted_coordinate() == before
    findings = [f for f in state.findings if f.kind == "claim_not_in_source"]
    assert {f.claim_type for f in findings} == {LISTED_IN, DATE_ADDED, DUE_DATE, RANSOMWARE}
    assert all(f.source_incomplete for f in findings)


def test_g5_delisting_inverts_membership_and_mirrors_dates_then_relisting(
    tmp_path: Path,
) -> None:
    instance = pilot_world(tmp_path)
    kev(instance, kev_catalog())
    state = kev(instance, delisted(kev_catalog(), DELISTED), minute=1)
    claims = changed(instance, state)
    assert set(claims) == {(cve(DELISTED), p) for p in (LISTED_IN, DATE_ADDED, DUE_DATE)}
    inverse = claims[(cve(DELISTED), LISTED_IN)]
    assert inverse.statement.object.kind == "none"
    witness = inverse.backing.procedure_evidence.absence
    assert witness.logical_source == kit.KEV_SOURCE and witness.complete_when.held
    for predicate in (DATE_ADDED, DUE_DATE):
        retired = claims[(cve(DELISTED), predicate)]
        assert retired.lifecycle.state == "retired" and retired.retirement.absence is not None
    # The ransomware field surfaces (when_absent: surface): a finding, no write.
    (surfaced,) = [f for f in state.findings if f.kind == "claim_not_in_source"]
    assert surfaced.claim_type == RANSOMWARE and not surfaced.source_incomplete
    # Every change is in the settle grant's scope: the whole run settles.
    assert state.terminal_egress[0].settle_outcome == "settled"
    assert (summary(state, "claims").retired, summary(state, "claims").inverse_written) == (2, 1)
    # Relisting revises the inverse back into the catalog Subject, on the record.
    back = kev(instance, kev_catalog(), minute=2)
    relisted = changed(instance, back)
    positive = relisted[(cve(DELISTED), LISTED_IN)]
    assert positive.statement.object.kind == "subject"
    assert positive.backing.procedure_evidence.value.basis == "extracted"
    assert back.terminal_egress[0].settle_outcome == "settled"


def test_g6_maybe_is_inadmissible_and_its_siblings_write(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    catalog = kev_catalog()
    record(catalog, LISTED[0])["knownRansomwareCampaignUse"] = "Maybe"
    state = kev(instance, catalog)
    claims = changed(instance, state)
    assert {p for c, p in claims if c == cve(LISTED[0])} == {LISTED_IN, DATE_ADDED, DUE_DATE}
    assert len(claims) == 33
    (refused,) = [f for f in state.findings if f.kind == "extract_refused"]
    assert refused.lexeme == "Maybe"


def test_g7_duplicate_records_write_nothing_for_that_key(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    catalog = kev_catalog()
    twice = copy.deepcopy(record(catalog, LISTED[2]))
    twice["dueDate"] = "2099-01-01"
    catalog["vulnerabilities"].append(twice)
    catalog["count"] += 1
    state = kev(instance, catalog)
    claims = changed(instance, state)
    assert not any(c == cve(LISTED[2]) for c, _ in claims)
    # The refused key makes the read incomplete (D-R19): no inverse is written
    # for the unlisted CVEs either, and the run says why.
    assert len(claims) == 28
    assert [f.kind for f in state.findings if f.kind == "duplicate_key"] == ["duplicate_key"]
    assert summary(state, "extract").duplicates == 2
    assert any(r.kind == "duplicate_key" for r in state.completeness.reasons)


def test_g8_a_read_ceiling_below_the_watch_list_refuses_before_writes(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    # A second Line on the kit's Procedure whose budget reads fewer rows than are watched.
    narrow = kit.automation(WATCH, now=NOW)
    line, propose = (copy.deepcopy(m) for m in narrow["members"][:2])
    line.update(name="security.kev-narrow", budgets={"max_read_rows": 5}, max_authority="propose")
    propose.update(name="security.kev-narrow-propose", line_name="security.kev-narrow")
    submit(instance, {**narrow, "members": [line, propose]}, name="narrow")
    before = instance.accepted_coordinate()
    state = run(instance, {kit.KEV_URL: _bytes(kev_catalog())}, line="security.kev-narrow")
    assert state.status == "admission_refused"
    assert state.terminal.code == "read_ceiling_exceeded"
    assert instance.accepted_coordinate() == before


def test_g9_a_new_web_build_changes_nothing_until_provider_move(tmp_path: Path) -> None:
    from cruxible_client.contracts.provider_installation import ProviderMoveRequest
    from cruxible_core.service.procedures.provider_builds import service_move_provider

    instance = pilot_world(tmp_path)
    kev(instance, kev_catalog())
    tree = instance.tree_at(instance.accepted_coordinate().git_oid)
    line_path = f"lines/{kit.KEV_LINE}.json"
    settle_path = f"procedure-mandates/{kit.KEV_LINE}-settle.json"
    pinned = (tree[line_path], tree[settle_path])
    newer = _web_build(instance, require_provider_checkout(), sha="6f")
    _install_build(instance, newer)
    tree = instance.tree_at(instance.accepted_coordinate().git_oid)
    assert (tree[line_path], tree[settle_path]) == pinned
    still = kev(instance, delisted(kev_catalog(), DELISTED), minute=1)
    assert still.terminal_egress[0].settle_outcome == "settled"
    moved = service_move_provider(
        instance,
        ProviderMoveRequest(
            provider="cruxible-provider-web", to=newer.identity.name, dry_run=False
        ),
        actor_id="owner",
        timestamp="2026-10-29T12:30:00.000000Z",
    )
    assert moved.status == "accepted", moved.detail
    carries = {item.identity: item for item in moved.automation_carries}
    assert carries[f"ProcedureMandate:{kit.KEV_LINE}-settle"].loses_settle
    before = instance.accepted_coordinate()
    after = kev(instance, kev_catalog(), minute=2)
    (egress,) = after.terminal_egress
    assert (egress.verdict, egress.settle_outcome, egress.capped_by) == (
        "delivered",
        "proposed",
        "mandate_grant",
    )
    assert instance.accepted_coordinate() == before


def test_g14_a_holder_from_another_source_is_surfaced_not_inverted(tmp_path: Path) -> None:
    """The same Procedure on a second logical source: the main Line's delisting
    never retires or inverts the other source's Claims; it surfaces them."""

    instance = pilot_world(tmp_path)
    mirror = kit.automation(WATCH, now=NOW)
    renamed = []
    for member in mirror["members"][:3]:
        member = copy.deepcopy(member)
        if member["kind"] == "line":
            member["name"] = "security.kev-mirror"
            member["parameters"]["logical_source"] = "cisa.kev.mirror"
        else:
            member["name"] = member["name"].replace(kit.KEV_LINE, "security.kev-mirror")
            member["line_name"] = "security.kev-mirror"
        renamed.append(member)
    submit(instance, {**mirror, "members": renamed}, name="mirror-line")
    kev(instance, kev_catalog(), line="security.kev-mirror")
    state = kev(instance, delisted(kev_catalog(), DELISTED), minute=1)
    writes = changed(instance, state) if state.terminal_egress[0].proposal_id else {}
    assert not any(c == cve(DELISTED) for c, _ in writes)
    found = [
        f
        for f in state.findings
        if f.kind == "claim_not_in_source" and cve(DELISTED) in (f.subject or "")
    ]
    surfaced = {f.claim_type for f in found}
    assert surfaced == {LISTED_IN, DATE_ADDED, DUE_DATE, RANSOMWARE}


def test_g11_epss_na_is_inadmissible_and_percentile_writes(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    answer = epss_answer()
    answer["data"][0]["epss"] = "n/a"
    target = answer["data"][0]["cve"]
    state = epss(instance, answer)
    claims = changed(instance, state)
    assert {p for c, p in claims if c == cve(target)} == {PERCENTILE, SCORE_DATE}
    assert len(claims) == 29
    (refused,) = [f for f in state.findings if f.kind == "extract_refused"]
    assert refused.lexeme == "n/a"
    receipt = claims[(cve(target), PERCENTILE)].backing.procedure_evidence.value
    # Typed in the extract (D-R23): the decimal is the parse, no transform between.
    assert receipt.basis == "extracted" and receipt.transform_node_ids == ()
