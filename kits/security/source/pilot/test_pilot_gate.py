"""Kit-pilot gate: the slice's own definitions on recorded real bytes.

The payloads ``definitions.py`` writes (the same files the scratch instance
installs) are authored into a fresh in-process instance; the real ``web.fetch``
adapter of the providers checkout answers each Line's call from recordings
(``fixtures/``: the CISA KEV catalog trimmed to 20 records, FIRST's EPSS API
answer verbatim), and each gate scenario edits those bytes. EPSS goes through
the real ``web.fetch.pages`` adapter: :class:`EpssOrigin` answers each page's
``cve=`` list from the recorded answer. Nothing here is a copy of a kit
definition.

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
from collections.abc import Callable, Iterable, Mapping
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


def _bytes(document: Mapping[str, Any] | bytes) -> bytes:
    """A baseline replays the fixture's own bytes; only a mutation re-serializes."""

    if isinstance(document, bytes):
        return document
    return json.dumps(document, indent=4).encode()


def fixture_bytes(exchange_id: str) -> bytes:
    """The recorded body exactly as the file holds it (no parse, no re-serialization)."""

    return (FIXTURES / EXCHANGES[exchange_id]["body"]).read_bytes()


# -- the real web.fetch, answering from recordings ------------------------------------


def _web_package() -> None:
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


def _web_fetch() -> Any:
    _web_package()
    from cruxible_provider_web.fetch import WebFetch

    return WebFetch


def _web_fetch_pages() -> Any:
    _web_package()
    from cruxible_provider_web.pages import WebFetchPages

    return WebFetchPages


class EpssOrigin:
    """FIRST's EPSS API: each page's ``cve=`` list answered from one recorded answer.

    A page asking for exactly the recorded CVEs gets the recorded bytes verbatim;
    any other page gets the records it asked for that ``answer`` holds, with
    ``total`` their count, as FIRST answers a ``cve=`` filter. A page asking for
    a CVE in ``fail``, or the ``fail_page``-th page (0-based, in request order),
    gets a 500. ``pages`` is every page's CVE list, in order.
    """

    def __init__(
        self,
        answer: Mapping[str, Any] | bytes | None = None,
        *,
        fail: Iterable[str] = (),
        fail_page: int | None = None,
    ) -> None:
        self.body = fixture_bytes("epss-api") if answer is None else _bytes(answer)
        self.records = {item["cve"]: item for item in json.loads(self.body)["data"]}
        self.recorded = set(EXCHANGES["epss-api"]["url"].split("cve=", 1)[1].split(","))
        self.fail = set(fail)
        self.fail_page = fail_page
        self.pages: list[list[str]] = []

    def respond(self, url: str) -> Any:
        import httpx
        from urllib.parse import parse_qs, urlsplit

        (cves,) = parse_qs(urlsplit(url).query)[kit.EPSS_PARAM]
        asked = cves.split(",")
        self.pages.append(asked)
        if self.fail & set(asked) or self.fail_page == len(self.pages) - 1:
            return httpx.Response(500, headers={"content-type": "text/plain"}, content=b"error")
        if set(asked) == self.recorded:
            body = self.body
        else:
            data = [self.records[c] for c in asked if c in self.records]
            head = {k: v for k, v in json.loads(self.body).items() if k != "data"}
            body = json.dumps({**head, "total": len(data), "data": data}).encode()
        return httpx.Response(
            200, headers={"content-type": "application/json; charset=utf-8"}, content=body
        )


class _Refused(Exception):
    """A provider's own typed refusal, answered as the refused envelope it is."""

    def __init__(self, code: str, detail: dict[str, Any]) -> None:
        super().__init__(code)
        self.code, self.detail = code, detail


def _answering_invoker() -> Any:
    from tests.support.operation_world import Invoker

    class Answering(Invoker):
        def invoke_provider(self, **kwargs: Any) -> Any:  # type: ignore[override]
            self.refusal = None
            try:
                return super().invoke_provider(**kwargs)
            except _Refused as refused:
                self.refusal = (refused.code, refused.detail)
                return super().invoke_provider(**kwargs)

    return Answering()


class Replay:
    """web.fetch's real client, answered by URL from the bytes a scenario states.

    The kit's dependency-plane operations (sbom.components, osv.query,
    osv.match) run the real security-osv-provider code (``dependency_replay``);
    ``osv`` is the recorded OSV origin osv.query talks to. ``epss`` answers
    every request to FIRST's EPSS API (each page of ``web.fetch.pages``).
    """

    def __init__(
        self, routes: Mapping[str, bytes], *, osv: Any = None, epss: EpssOrigin | None = None
    ) -> None:
        self.routes = dict(routes)
        self.osv = osv
        self.epss = epss
        self.now: Any = None  # the run's daemon clock (service_run sets it)
        self.requests: list[str] = []

    def client_factory(self) -> Callable[..., Any]:
        import httpx
        from cruxible_provider_web.http import RecordingClient

        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requests.append(url)
            if self.epss is not None and url.startswith(kit.EPSS_API + "?"):
                return self.epss.respond(url)
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=self.routes[url],
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

        web_fetch = _web_fetch()
        web_fetch_pages = _web_fetch_pages()
        invoker = _answering_invoker()

        def output(context: Any) -> dict[str, Any]:
            # -- Batch 2, dependency loop: the kit's own provider, in-process.
            import dependency_replay

            if context.operation in dependency_replay.OPERATIONS:
                answer = dependency_replay.run_operation(
                    context,
                    osv_transport=None if self.osv is None else self.osv.transport,
                    now=self.now,
                )
                assert answer.status == "ok", answer
                invoker.incomplete_captures = list(answer.incomplete_captures)
                return dict(answer.output)
            invoker.incomplete_captures = []
            if "commitment_digest" in context.input:
                # Core's builtin workspace.file (the SBOM import's read): the
                # daemon has already read the file; the builtin structures it.
                from cruxible_core.providers.builtin_workspace_file import WorkspaceFile

                envelope = WorkspaceFile()(context)
                assert envelope.status == "ok", envelope
                return dict(envelope.output or {})
            if context.operation == "web.fetch.pages":
                # The real adapter's own result: its pages, failed_pages and
                # incomplete_captures, never a hand-set flag.
                paged = web_fetch_pages(client_factory=self.client_factory())(
                    ProviderRunContext(
                        run_id=context.run_id,
                        input=dict(context.input),
                        operation="web.fetch.pages",
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
                if paged.status == "refused":
                    assert paged.refusal is not None
                    raise _Refused(paged.refusal.code, dict(paged.refusal.detail or {}))
                assert paged.status == "ok", paged
                invoker.incomplete_captures = list(paged.incomplete_captures)
                return dict(paged.output or {})
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

        invoker.output = output
        return Operator(invoker)


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


#: The pilot's watch list now comes from the chain (K-B1-2): one test SBOM lists a
#: stand-in component per watched CVE, and a SEED states each affected_by (OSV is
#: not wired yet). KEV and EPSS read the same watched rows as before.
PILOT_SBOM = "sboms/pilot-watch.cdx.json"
PILOT_SBOM_LINE = "pilot-watch"


def pilot_component(cve_id: str) -> str:
    return f"pkg:generic/pilot-watch/{cve_id.lower()}@1"


def pilot_sbom(watch: tuple[str, ...]) -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "pilot-watch",
                "purl": "pkg:generic/pilot-watch",
            }
        },
        "components": [
            {"type": "library", "name": c.lower(), "purl": pilot_component(c)} for c in watch
        ],
    }
    return json.dumps(document, indent=2).encode()


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir(exist_ok=True)
    return root


def write_file(tmp_path: Path, relative: str, content: bytes) -> None:
    path = workspace(tmp_path) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


#: Each world's owner key material, by instance root (an attestation signs with it).
OWNERS: dict[Path, Any] = {}


def kit_world(
    tmp_path: Path,
    *,
    watch: tuple[str, ...] = (),
    sboms: tuple[tuple[str, str], ...] = (),
    automation: bool = True,
) -> Any:
    """A fresh instance holding every kit definition, the catalog and ``watch``'s
    vulnerability Subjects, and (``automation``) the Lines (one SBOM import Line
    per ``sboms``)."""

    from cruxible_client.contracts.capture_contract_inputs import (
        CaptureContractInputRecord,
        lower_capture_contract_input,
    )
    from cruxible_client.contracts.captures import capture_contract_path, render_capture_contract
    from tests.core_support._identity_support import accept_tree
    from tests.core_support._support import initialize_local
    from web_contracts import members as web_contract_members

    checkout = require_provider_checkout()
    instance, owner = initialize_local(tmp_path)
    OWNERS[instance.root] = owner
    workspace(tmp_path)
    submit(
        instance,
        {"kind": "change_set", "members": web_contract_members(checkout)},
        name="web-contracts",
    )
    _install_build(instance, _web_build(instance, checkout))
    # -- Batch 2, dependency loop: security-osv-provider's Contracts and build.
    import dependency_replay
    import osv

    submit(instance, osv.provider_contracts(), name="osv-contracts")
    _install_build(instance, dependency_replay.provider_build(instance))
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
    if watch:
        submit(instance, kit.watch_subjects(watch), name="watch")
    if automation:
        submit(instance, kit.automation(watch, now=NOW, sboms=sboms), name="automation")
    return instance


def pilot_world(tmp_path: Path, *, watch: tuple[str, ...] = WATCH) -> Any:
    instance = kit_world(tmp_path, watch=watch, sboms=((PILOT_SBOM_LINE, PILOT_SBOM),))
    write_file(tmp_path, PILOT_SBOM, pilot_sbom(watch))
    import_sbom(instance, PILOT_SBOM_LINE, minute=-5)
    submit(
        instance,
        kit.seed_affected_by([(pilot_component(c), c) for c in watch], reason="pilot gate"),
        name="seed",
    )
    return instance


def import_sbom(instance: Any, name: str, *, minute: int = 0) -> Any:
    """Run one SBOM's import Line by hand: its components and their inventory."""

    from inventory import sbom_line_name

    state = run(instance, {}, line=sbom_line_name(name), minute=minute)
    assert state.status == "succeeded", (name, state.terminal)
    return state


def run(instance: Any, routes: Mapping[str, bytes], *, line: str, minute: int = 0) -> Any:
    return service_run(instance, Replay(routes), line=line, minute=minute)


def service_run(instance: Any, replay: Replay, *, line: str, minute: int = 0) -> Any:
    from cruxible_core.documents.workspace_file import WorkspaceFileReader
    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        service_run_playbill_line,
    )
    from tests.test_procedures.test_completeness_transfer import _Clock

    replay.now = NOW + timedelta(minutes=minute)
    return service_run_playbill_line(
        instance,
        path_identity_digest=line,
        request=LineRunRequest(line=line),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(NOW + timedelta(minutes=minute)),
        provider_runtime_operator=replay.operator(),  # type: ignore[arg-type]
        workspace_file_reader=WorkspaceFileReader(
            instance_id=instance.descriptor.instance_id,
            operating_profile="local",
            attached_roots=(instance.root.parent / "workspace",),
            managed_roots=(instance.root,),
        ),
    )


def kev(
    instance: Any, catalog: Mapping[str, Any] | bytes, *, minute: int = 0, line: str = kit.KEV_LINE
):
    state = run(instance, {kit.KEV_URL: _bytes(catalog)}, line=line, minute=minute)
    assert state.status == "succeeded", state.terminal
    return state


def epss(instance: Any, answer: Mapping[str, Any] | bytes | EpssOrigin, *, minute: int = 0) -> Any:
    origin = answer if isinstance(answer, EpssOrigin) else EpssOrigin(answer)
    state = service_run(instance, Replay({}, epss=origin), line=kit.EPSS_LINE, minute=minute)
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


def stored_capture(instance: Any, state: Any) -> tuple[str, bytes]:
    """The commitment digest and bytes of the one Capture the run's call admitted."""

    from cruxible_client.contracts.captures import parse_capture_envelope
    from cruxible_client.contracts.cas_contracts import BodyAccessContext

    (call,) = [n.summary for n in state.nodes if n.summary and n.summary.kind == "call"]
    (capture,) = call.capture_digests
    access = BodyAccessContext(principal_id="kit-pilot-gate", can_read_body=True)
    envelope = parse_capture_envelope(instance.body_store().read(capture, access=access))
    return envelope.commitment.digest, instance.body_store().read(
        envelope.commitment.digest, access=access
    )


def accepted(instance: Any, claim: Any) -> Any:
    """The Claim as the accepted head holds it (after a settle)."""

    from cruxible_client.contracts.claims import parse_claim

    name = claim.identity.name
    path = f"claims/{name[4:6]}/{name}.json"
    return parse_claim(instance.tree_at(instance.accepted_coordinate().git_oid)[path], path=path)


def utc(value: Any) -> str:
    """A datetime (or its wire text) as canonical UTC text."""

    from datetime import UTC, datetime

    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def listed_from(catalog: Mapping[str, Any], cve_id: str) -> str:
    """dateAdded at 00:00 UTC: the moment the listing takes effect (D-R29)."""

    added = next(v for v in catalog["vulnerabilities"] if v["cveID"] == cve_id)["dateAdded"]
    return f"{added}T00:00:00Z"


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


@pytest.mark.parametrize("exchange_id", ["kev-catalog", "epss-api"])
def test_baseline_replay_stores_the_fixture_bytes_verbatim(tmp_path: Path, exchange_id) -> None:
    """D-R25/D-R27: through the real web.fetch adapter, the admitted Capture's body
    is the origin's bytes exactly -- no wrapper, no re-serialization."""

    import hashlib

    instance = pilot_world(tmp_path)
    origin = fixture_bytes(exchange_id)
    url = EXCHANGES[exchange_id]["url"]
    if exchange_id == "kev-catalog":
        line, replay = kit.KEV_LINE, Replay({url: origin})
    else:
        # One page asks for exactly the ten watched CVEs, the recorded request.
        line, replay = kit.EPSS_LINE, Replay({}, epss=EpssOrigin())
    state = service_run(instance, replay, line=line)
    assert state.status == "succeeded", state.terminal
    if exchange_id == "kev-catalog":
        assert replay.requests == [url]
    else:
        (asked,) = replay.epss.pages
        assert sorted(asked) == sorted(WATCH) and replay.requests[0].startswith(kit.EPSS_API)
    digest, body = stored_capture(instance, state)
    assert body == origin
    assert digest == "sha256:" + hashlib.sha256(origin).hexdigest()
    # The downstream terminal reads those same bytes.
    extracted = summary(state, "extract")
    records = json.loads(origin)["vulnerabilities" if exchange_id == "kev-catalog" else "data"]
    assert extracted.records == len(records) and extracted.complete
    assert summary(state, "claims").written == (32 if exchange_id == "kev-catalog" else 30)
    assert state.terminal_egress[0].settle_outcome == "settled"


def test_g1_first_run_settles_by_basis_with_dated_membership(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    first = kev(instance, fixture_bytes("kev-catalog"))
    claims = changed(instance, first)
    assert set(claims) == {
        *((cve(c), p) for c in LISTED for p in (LISTED_IN, DATE_ADDED, DUE_DATE, RANSOMWARE)),
        *((cve(c), LISTED_IN) for c in UNLISTED),
        # A fresh instance holds no catalog Subject: the first run creates it.
        ("cisa-kev", kit.CATALOG + ".catalog_id"),
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
    # Membership takes effect from dateAdded at 00:00 UTC (D-R29), as accepted.
    catalog = kev_catalog()
    for c in LISTED:
        membership = accepted(instance, claims[(cve(c), LISTED_IN)])
        assert membership.lifecycle.state == "live"
        assert utc(membership.statement.effective_from) == listed_from(catalog, c)
        assert membership.backing.procedure_evidence.value.basis == "extracted"
    assert utc(
        accepted(instance, claims[(cve(LISTED[0]), LISTED_IN)]).statement.effective_from
    ) == ("2021-12-10T00:00:00Z")
    assert summary(first, "extract").complete
    assert (summary(first, "claims").written, summary(first, "claims").inverse_written) == (32, 2)
    scored = epss(instance, fixture_bytes("epss-api"), minute=1)
    assert len(changed(instance, scored)) == 30
    assert scored.terminal_egress[0].settle_outcome == "settled"


def test_g1_identical_runs_write_nothing(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    kev(instance, fixture_bytes("kev-catalog"))
    epss(instance, fixture_bytes("epss-api"), minute=1)
    before = instance.accepted_coordinate()
    again = kev(instance, fixture_bytes("kev-catalog"), minute=2)
    rescored = epss(instance, fixture_bytes("epss-api"), minute=3)
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
    # 32 vulnerability Claims plus the catalog Subject's key the first run creates.
    assert len(claims) == 33
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
    assert utc(accepted(instance, positive).statement.effective_from) == listed_from(
        kev_catalog(), DELISTED
    )
    assert positive.backing.procedure_evidence.value.basis == "extracted"
    assert back.terminal_egress[0].settle_outcome == "settled"


def test_g6_maybe_is_inadmissible_and_its_siblings_write(tmp_path: Path) -> None:
    instance = pilot_world(tmp_path)
    catalog = kev_catalog()
    record(catalog, LISTED[0])["knownRansomwareCampaignUse"] = "Maybe"
    state = kev(instance, catalog)
    claims = changed(instance, state)
    assert {p for c, p in claims if c == cve(LISTED[0])} == {LISTED_IN, DATE_ADDED, DUE_DATE}
    assert len(claims) == 34  # including the created catalog's key
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
    assert len(claims) == 29  # including the created catalog's key
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


# -- EPSS asks for exactly the watched CVEs (D-R34) ------------------------------------

#: 101 watched CVEs of the shortest id length: 100 fill one page exactly, so the
#: watch list splits into two pages.
LONG_WATCH = tuple(f"CVE-2030-{n}" for n in range(1000, 1101))
#: A watched CVE FIRST has no score for: it is absent from every page's answer.
NO_SCORE = LONG_WATCH[7]


def long_answer() -> dict[str, Any]:
    head = {k: v for k, v in epss_answer().items() if k != "data"}
    data = [
        {"cve": c, "epss": "0.012340000", "percentile": "0.500000000", "date": "2026-11-02"}
        for c in LONG_WATCH
        if c != NO_SCORE
    ]
    return {**head, "total": len(data), "data": data}


def call_captures(state: Any) -> tuple[str, ...]:
    (call,) = [n for n in state.nodes if n.node == "scores_api"]
    return tuple(call.summary.capture_digests)


def test_epss_pages_a_long_watch_list_and_a_failed_page_is_incomplete(tmp_path: Path) -> None:
    """101 watched CVEs: two pages, each CVE asked once. A failed second page leaves
    one Capture and an incomplete run whose first page still writes; the next run
    with both pages answered is complete and scores the rest. A CVE FIRST does not
    score gets no Claim, and its absence is not incompleteness."""

    instance = pilot_world(tmp_path, watch=LONG_WATCH)
    before = instance.accepted_coordinate()

    origin = EpssOrigin(long_answer(), fail_page=1)
    failed = epss(instance, origin)
    first_page, second_page = origin.pages
    assert len(first_page) == 100 and len(second_page) == 1
    assert sorted(first_page + second_page) == sorted(LONG_WATCH)
    assert NO_SCORE in first_page
    assert len(call_captures(failed)) == 1
    assert failed.completeness is not None and not failed.completeness.complete
    claims = changed(instance, failed)
    scored = {c for c, _ in claims}
    assert scored == {cve(c) for c in first_page if c != NO_SCORE}
    assert len(claims) == 3 * len(scored)
    assert failed.terminal_egress[0].settle_outcome == "settled"
    assert instance.accepted_coordinate() != before

    both = epss(instance, EpssOrigin(long_answer()), minute=1)
    members = call_captures(both)
    assert len(members) == 2
    assert both.completeness is None
    claims = changed(instance, both)
    # Only the second page's CVE is new; the first page's re-observe.
    assert set(claims) == {
        (cve(c), p) for c in second_page for p in (SCORE, PERCENTILE, SCORE_DATE)
    }
    # Each Claim cites the one page its record came from.
    assert all(
        claim.backing.procedure_evidence.value.capture_digest == members[1]
        for claim in claims.values()
    )
    written = summary(both, "claims")
    assert (written.written, written.re_observed) == (3, 3 * (len(first_page) - 1))
    assert not any(c == cve(NO_SCORE) for c, _ in claims)
    assert both.terminal_egress[0].settle_outcome == "settled"


def test_epss_a_watched_cve_without_a_score_writes_nothing_for_it(tmp_path: Path) -> None:
    """One page; FIRST's answer lacks one watched CVE: its siblings write and the
    run is complete (EPSS writes no absence)."""

    instance = pilot_world(tmp_path)
    answer = epss_answer()
    missing = answer["data"].pop(0)["cve"]
    answer["total"] = len(answer["data"])
    origin = EpssOrigin(answer)
    state = epss(instance, origin)
    assert len(origin.pages) == 1 and len(call_captures(state)) == 1
    claims = changed(instance, state)
    assert len(claims) == 27 and not any(c == cve(missing) for c, _ in claims)
    assert state.completeness is None
    assert not [f for f in state.findings if f.kind == "incomplete_source"]


@pytest.mark.xfail(
    strict=True,
    reason="BLOCKED (kit-epss): web.fetch.pages declines an empty paged parameter "
    "(provider_declined), so the EPSS run is node_refused; no template step can skip "
    "the call (guard/halt are closed in authoring).",
)
def test_epss_with_nothing_watched_asks_nothing_and_writes_nothing(tmp_path: Path) -> None:
    """An empty watch list: no request, nothing written, nothing needing attention."""

    instance = kit_world(tmp_path)
    before = instance.accepted_coordinate()
    replay = Replay({}, epss=EpssOrigin())
    state = service_run(instance, replay, line=kit.EPSS_LINE)
    assert replay.requests == []
    assert instance.accepted_coordinate() == before
    assert state.status == "succeeded", state.terminal
    assert state.completeness is None
    assert not state.findings
