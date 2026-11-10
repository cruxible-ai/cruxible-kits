"""The automation template and its start Runbook (D-R48), on the kit's own definitions.

``automation.json`` (written by ``template.py``) is the one change set an adopter
tailors and submits. Here it authors on a fresh instance holding only the kit's
definitions, through core's own kit-build check (an authoring preview) and then
an ordinary submit, and ``security.start``'s preview reports no order problem:
every step reads only what an earlier step (or a Line outside the Runbook) writes.

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_start_gate.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any

import dependency_replay
import osv
import template
from test_pilot_gate import (
    Replay,
    fixture_bytes,
    kit,
    kit_world,
    submit,
    workspace,
    write_file,
)


def test_the_committed_template_is_the_generated_one() -> None:
    assert template.TEMPLATE.read_text() == template.render()


#: Inside the template's Mandate window (valid from the day before ``DATED``).
TEMPLATE_CLOCK = template.DATED + timedelta(hours=1)


def adopted_world(tmp_path: Path, sbom: bytes, *, expires_at: Any = None) -> Any:
    """The kit's definitions, the committed template adopted, and its SBOM Line's
    file in the workspace. ``expires_at`` re-dates every Mandate (valid from
    2026-01-01) for a run on the wall clock, as an adopter tailors them."""

    instance = kit_world(tmp_path, automation=False)
    adopted = json.loads(template.TEMPLATE.read_text())
    if expires_at is not None:
        for member in adopted["members"]:
            if member["kind"] == "procedure_mandate":
                member["valid_from"] = "2026-01-01T00:00:00Z"
                member["expires_at"] = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    submit(instance, adopted, name="automation-template")
    write_file(tmp_path, template.SBOM[1], sbom)
    return instance


def run_runbook(instance: Any, replay: Replay, name: str, *, minutes: int = 0) -> Any:
    """``cruxible runbook run NAME``: every step as the caller's manual Line run."""

    from cruxible_core.documents.workspace_file import WorkspaceFileReader
    from cruxible_core.service.runbooks import service_run_runbook
    from tests.support.operation_world import actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    at = TEMPLATE_CLOCK + timedelta(minutes=minutes)
    replay.now = at
    return service_run_runbook(
        instance,
        name=name,
        actor_context=actor(),
        caller_rung=3,
        provider_runtime_operator=replay.operator(),
        workspace_file_reader=WorkspaceFileReader(
            instance_id=instance.descriptor.instance_id,
            operating_profile="local",
            attached_roots=(workspace(instance.root.parent),),
            managed_roots=(instance.root,),
        ),
        daemon_clock=_Clock(at),
    )


def quiet_sbom() -> bytes:
    """An inventory whose two components OSV reports nothing for."""

    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {"name": "quiet", "purl": "pkg:generic/quiet-app@1"}
            },
            "components": [
                {"type": "library", "name": name, "purl": f"pkg:pypi/{name}@1.0"}
                for name in ("calm", "still")
            ],
        }
    ).encode()


def quiet_osv() -> Any:
    batch = {"results": [{}, {}]}
    return dependency_replay.RecordedOsv(
        {"https://api.osv.dev/v1/querybatch": (200, json.dumps(batch).encode())}
    )


def step(result: Any, line: str) -> Any:
    (found,) = [s for s in result.steps if s.target.line.target.name == line]
    return found


def test_start_on_an_inventory_nothing_affects_completes_and_asks_epss_nothing(
    tmp_path: Path,
) -> None:
    """A fresh repository with no vulnerable dependency: ``security.start`` runs every
    step to completion; OSV finds nothing, so nothing is watched, EPSS sends no
    request and writes nothing, and its step is not flagged as needing attention."""

    instance = adopted_world(tmp_path, quiet_sbom())
    replay = Replay({kit.KEV_URL: fixture_bytes("kev-catalog")}, osv=quiet_osv())
    result = run_runbook(instance, replay, template.START)
    assert (result.status, result.stop_reason) == ("completed", None), result
    assert [s.status for s in result.steps] == ["succeeded"] * len(template.START_LINES)
    assert not any(url.startswith(kit.EPSS_API) for url in replay.requests), (
        replay.requests
    )
    epss = step(result, kit.EPSS_LINE)
    assert epss.counts is not None and epss.counts.complete, epss
    assert (epss.counts.written, epss.counts.refused, epss.counts.inbox) == (0, 0, 0)
    assert not epss.counts.needs_attention
    # Nothing in the run needs attention: OSV answered in full, KEV read the catalog.
    assert result.attention_steps == (), result.attention_steps


# -- the daily refresh: one Trigger aimed at security.maintain -------------------------

DEMO_SBOM = (
    Path(__file__).resolve().parents[2] / "examples/sboms/log4j-demo-app.cdx.json"
)


def accepted_names(instance: Any, directory: str) -> dict[str, Any]:
    """The accepted artifacts under ``directory/`` by name (their parsed JSON)."""

    tree = instance.tree_at(instance.accepted_coordinate().git_oid)
    return {
        path.removeprefix(directory + "/").removesuffix(".json"): json.loads(raw)
        for path, raw in tree.items()
        if path.startswith(directory + "/")
    }


def test_the_template_adopts_two_runbooks_and_one_daily_trigger(tmp_path: Path) -> None:
    """Adopting the template yields exactly one Trigger, aimed at security.maintain on
    one cron schedule, and two Runbooks: start (SBOM, OSV, KEV, EPSS) and maintain
    (no SBOM import)."""

    instance = kit_world(tmp_path, automation=False)
    seeded = accepted_names(instance, "triggers")  # core's own internal-action Triggers
    submit(
        instance, json.loads(template.TEMPLATE.read_text()), name="automation-template"
    )
    triggers = {
        name: value
        for name, value in accepted_names(instance, "triggers").items()
        if name not in seeded
    }
    runbooks = accepted_names(instance, "runbooks")
    assert set(triggers) == {template.MAINTAIN_TRIGGER}, sorted(triggers)
    assert set(runbooks) == {template.START, template.MAINTAIN}, sorted(runbooks)
    (trigger,) = triggers.values()
    assert trigger["target"] == {
        "kind": "runbook",
        "runbook": {"target": {"kind": "Runbook", "name": template.MAINTAIN}},
    }
    assert trigger["schedule"] == {"kind": "cron", "expression": template.MAINTAIN_CRON}

    def lines(name: str) -> list[str]:
        return [s["line"]["target"]["name"] for s in runbooks[name]["steps"]]

    assert lines(template.START) == list(template.START_LINES)
    assert lines(template.MAINTAIN) == list(template.MAINTAIN_LINES)
    assert template.START_LINES[0] not in template.MAINTAIN_LINES


class KitManager:
    """The daemon manager surface a Trigger-fired Runbook run reads, answering every
    provider call from the scenario's recordings."""

    def __init__(self, instance: Any, replay: Replay) -> None:
        from cruxible_core.documents.workspace_file import WorkspaceFileReader

        self.instance, self.replay = instance, replay
        self.reader = WorkspaceFileReader(
            instance_id=instance.descriptor.instance_id,
            operating_profile="local",
            attached_roots=(workspace(instance.root.parent),),
            managed_roots=(instance.root,),
        )

    def get(self, instance_id: str) -> Any:
        return self.instance

    def workspace_file_reader(self, instance_id: str) -> Any:
        return self.reader

    def provider_runtime_operator(self) -> Any:
        return self.replay.operator()

    def procedure_run_config(self) -> Any:
        from cruxible_core.service.procedures.procedure_runs import (
            ProcedureRunOperationalConfigV1,
        )

        return ProcedureRunOperationalConfigV1(evaluation_instant_skew_seconds=10**9)


def enable(instance: Any, line: str, *, now: Any) -> None:
    """``cruxible line enable LINE`` as the owner (rechecked before every admission)."""

    from cruxible_client.contracts.line_dispatch import LineEnablementPrincipal
    from cruxible_core.service.procedures.line_dispatch import service_enable_line
    from tests.support.operation_world import actor

    service_enable_line(
        instance,
        line,
        principal=LineEnablementPrincipal.model_validate(
            {"kind": "principal_claim", "label": "owner"}
        ),
        actor=actor(),
        now=now,
        daemon_id="kit-start-gate",
    )


def fire_daily(instance: Any, replay: Replay, *, day: int = 1) -> Any:
    """Let the daily Trigger fire once, on the ``day``-th day after it was accepted,
    and run the fired Runbook as the daemon's Runbook consumer does; its run record."""

    from cruxible_core.consumers.runbooks import RUNBOOKS
    from cruxible_core.service.runbooks import latest_runbook_run
    from cruxible_core.triggers.journal import evaluate_triggers, internal_triggers

    (item,) = [
        t
        for t in internal_triggers(instance)
        if t.trigger == f"Trigger:{template.MAINTAIN_TRIGGER}"
    ]
    assert item.action == f"runbook:{template.MAINTAIN}"
    since = item.accepted_at + timedelta(days=day - 1)
    at = item.accepted_at + timedelta(days=day)
    with instance.accepted_history_reader() as history:
        generation = history.sequence
    fired = evaluate_triggers(
        instance, now=at, listening_since=since, listening_generation=generation
    )
    assert [e.trigger for e in fired if e.action == item.action] == [
        f"Trigger:{template.MAINTAIN_TRIGGER}"
    ]
    manager = KitManager(instance, replay)
    work = list(RUNBOOKS.due(instance, now=at))
    assert len(work) == 1, work
    RUNBOOKS.run(manager, "fixture", work[0], now=at)
    return latest_runbook_run(instance, template.MAINTAIN)


def started_world(tmp_path: Path) -> tuple[Any, Any]:
    """The demo app adopted with wall-clock Mandates and seeded by security.start."""

    from datetime import UTC, datetime

    now = datetime.now(UTC).replace(microsecond=0)
    instance = adopted_world(
        tmp_path, DEMO_SBOM.read_bytes(), expires_at=now + timedelta(days=30)
    )
    seeded = run_runbook(instance, demo_replay(), template.START)
    assert seeded.status == "completed", seeded
    return instance, now


def demo_replay() -> Replay:
    from test_pilot_gate import EpssOrigin

    return Replay(
        {kit.KEV_URL: fixture_bytes("kev-catalog")},
        osv=dependency_replay.RecordedOsv(),
        epss=EpssOrigin(),
    )


def test_the_daily_trigger_runs_osv_kev_and_epss_in_order_under_their_enablement(
    tmp_path: Path,
) -> None:
    """One fire of security.maintain-daily runs security.maintain: OSV, KEV, EPSS, in
    that order, each under its Line's own enablement; a Line nobody enabled stops
    the run there (no Mandate is widened for the Runbook)."""

    instance, now = started_world(tmp_path)
    for line in template.MAINTAIN_LINES[:-1]:
        enable(instance, line, now=now)
    replay = demo_replay()
    replay.now = now
    stopped = fire_daily(instance, replay)
    assert stopped is not None and stopped.mode == "trigger", stopped
    assert stopped.trigger == f"Trigger:{template.MAINTAIN_TRIGGER}"
    assert (stopped.stop_reason, stopped.stopped_at_step) == (
        "line_not_enabled",
        len(template.MAINTAIN_LINES),
    )

    enable(instance, template.MAINTAIN_LINES[-1], now=now)
    replay = demo_replay()
    replay.now = now
    ran = fire_daily(instance, replay, day=2)
    assert ran is not None and ran.run_id != stopped.run_id
    assert (ran.status, ran.mode) == ("completed", "trigger"), ran
    assert [s.target.line.target.name for s in ran.steps] == list(
        template.MAINTAIN_LINES
    )
    assert [s.status for s in ran.steps] == ["succeeded"] * len(template.MAINTAIN_LINES)
    assert all(s.run_id for s in ran.steps)
    # OSV asked first, then CISA, then FIRST: the order of the requests themselves.
    hosts = [
        host
        for url in (*replay.osv.requests, *replay.requests)
        for host in ("api.osv.dev", "www.cisa.gov", "api.first.org")
        if host in url
    ]
    assert (
        hosts[0] == "api.osv.dev"
        and "www.cisa.gov" in hosts
        and hosts[-1] == "api.first.org"
    )


class OsvDeclines(Replay):
    """OSV's provider declines the query (``provider_declined``): the step fails."""

    def operator(self) -> Any:
        from test_pilot_gate import _Refused

        operator = super().operator()
        answer = operator.invoker.output

        def output(context: Any) -> Any:
            if context.operation == "osv.query":
                raise _Refused("provider_declined", {})
            return answer(context)

        operator.invoker.output = output
        return operator


def test_a_failed_osv_step_stops_maintain_as_it_stops_start(tmp_path: Path) -> None:
    """A failed OSV step stops either Runbook there: KEV and EPSS do not run."""

    instance = adopted_world(tmp_path, DEMO_SBOM.read_bytes())
    for minutes, (name, lines) in enumerate(
        (
            (template.START, template.START_LINES),
            (template.MAINTAIN, template.MAINTAIN_LINES),
        )
    ):
        replay = OsvDeclines(
            {kit.KEV_URL: fixture_bytes("kev-catalog")},
            osv=dependency_replay.RecordedOsv(),
        )
        result = run_runbook(instance, replay, name, minutes=minutes)
        at = lines.index(osv.OSV_LINE) + 1
        assert (result.status, result.stop_reason, result.stopped_at_step) == (
            "stopped",
            "step_failed",
            at,
        ), result
        statuses = [s.status for s in result.steps]
        assert statuses[at - 1] == "failed" and set(statuses[at:]) == {"not_run"}
        assert not any(
            "cisa.gov" in url or "first.org" in url for url in replay.requests
        )


def _inspected_package(root: Path, *, wheel_sha: str, lock_sha: str) -> Any:
    """An ``InspectedProviderPackage`` from a provider's own source tree.

    The same registration ``provider_build`` (``dependency_replay.py``) and
    ``_web_build`` (``test_pilot_gate.py``) already read to hand-build a
    Provider for the gate's in-process world; wrapped here so the kit-build
    check seeds it through core's own production seeding path
    (``check_automation_template``'s ``providers``), not a bespoke Provider
    object. No wheel is built: the registration reader is metadata-only, and
    the wheel/lock digests are placeholders, exactly as the gate's existing
    hand-built builds already use.
    """

    from cruxible_client.contracts.kits import KitProvider, KitProviderFile
    from cruxible_core.providers.package_inspection import InspectedProviderPackage
    from cruxible_core.providers.package_metadata import read_package_registration

    document = read_package_registration(root)
    distribution = document.manifest.distribution
    provider = KitProvider(
        provider_id=document.manifest.provider_id,
        package=distribution.name,
        version=distribution.version,
        wheel=KitProviderFile(
            filename=(
                f"{distribution.name.replace('-', '_')}-{distribution.version}-py3-none-any.whl"
            ),
            sha256="sha256:" + wheel_sha * (64 // len(wheel_sha)),
        ),
        lock=KitProviderFile(
            filename=f"{distribution.name}-{distribution.version}.uv.lock",
            sha256="sha256:" + lock_sha * 64,
        ),
        operations=tuple(sorted(item.name for item in document.operations)),
    )
    return InspectedProviderPackage(
        provider=provider,
        pin_key="linux-cp311",
        materialization="sha256:" + "c" * 64,
        document=document,
    )


def test_the_template_authors_and_the_start_runbook_has_no_order_problems(
    tmp_path: Path,
) -> None:
    from tests.support.provider_checkout import require_provider_checkout

    from cruxible_client.contracts.kits import KitAutomationTemplate, KitBuildRequest
    from cruxible_core.service.kit_template import check_automation_template
    from cruxible_core.service.kits import build_kit
    from cruxible_core.service.runbook_preview import service_preview_runbook

    instance = kit_world(tmp_path, automation=False)
    content = template.TEMPLATE.read_text()
    head = instance.accepted_coordinate()
    tree = instance.immutable_tree_at(head.git_oid)
    checkout = require_provider_checkout()
    providers = (
        _inspected_package(
            dependency_replay.PROVIDER / "src" / "security_osv_provider",
            wheel_sha="d",
            lock_sha="b",
        ),
        _inspected_package(
            checkout / "packages/cruxible-provider-web/src/cruxible_provider_web",
            wheel_sha="5e",
            lock_sha="b",
        ),
    )
    # The manifest's own declaration (``cruxible-kit.json``: ``owns:
    # ["security."]``), nothing widened. ``build_kit`` sweeps every bundled
    # package's complete operation Contract closure -- input, output and
    # refusal alike -- regardless of which namespace those Contracts live in
    # (a Provider is never carried or walked itself, so nothing else would
    # pin a refusal Contract into the export) -- exactly as ``service_build_kit``
    # passes ``providers`` to ``build_kit`` itself, not only to the template check.
    bundle = build_kit(
        tree,
        KitBuildRequest(
            kit_id="security",
            version="1.3.0",
            owns=("security.",),
        ),
        providers=providers,
    )
    # The check kit build runs: a preview against exactly what the kit exports
    # (``bundle.contents()``) plus the bundled providers' own builds and
    # operations, pinned against those same exported Contracts -- never this
    # publisher instance's other local definitions. A Provider is never a kit
    # artifact (``kit add`` registers its build separately), so it is
    # seeded this way instead of read off the publisher's tree.
    check_automation_template(
        bundle.contents(),
        KitAutomationTemplate(path="automation.json", content=content),
        actor_id="owner",
        providers=providers,
    )
    assert instance.accepted_coordinate() == head

    submit(instance, json.loads(content), name="automation-template")
    preview = service_preview_runbook(instance, name=template.START)
    assert [step.target.line.target.name for step in preview.steps] == list(
        template.START_LINES
    )
    assert not any(step.unavailable for step in preview.steps)
    assert preview.order_problems == (), preview.order_problems
    # The daily refresh reads the inventory the SBOM import Line (outside it) writes.
    maintain = service_preview_runbook(instance, name=template.MAINTAIN)
    assert [step.target.line.target.name for step in maintain.steps] == list(
        template.MAINTAIN_LINES
    )
    assert not any(step.unavailable for step in maintain.steps)
    assert maintain.order_problems == (), maintain.order_problems

    # The order is what the reads and writes imply: reversed, every reader of a
    # later step's writes is reported (the preview reorders nothing).
    submit(
        instance,
        {
            "kind": "change_set",
            "members": [
                {
                    "kind": "runbook",
                    "name": "security.start-reversed",
                    "steps": [
                        {"line": line} for line in reversed(template.START_LINES)
                    ],
                }
            ],
        },
        name="reversed",
    )
    reversed_preview = service_preview_runbook(instance, name="security.start-reversed")
    late = {
        (problem.step, problem.claim_type)
        for problem in reversed_preview.order_problems
        if problem.kind == "reads_later_write"
    }
    assert late, reversed_preview.order_problems
    assert {step for step, _claim_type in late} >= {1, 2, 3}


def _build_real_wheel(project: Path) -> Path:
    uv = shutil.which("uv")
    assert uv is not None, "uv must be on PATH to build a provider wheel"
    dist = project / "dist"
    subprocess.run(
        [uv, "build", "--wheel", "--offline", "--out-dir", str(dist), str(project)],
        check=True,
        capture_output=True,
    )
    return next(dist.glob("*.whl"))


def _real_web_provider(
    tmp_path: Path, repository: Path, wheels: Path
) -> tuple[Path, Path, Path]:
    """Build the exact web source and lock the release builder uses."""
    return _release_provider(tmp_path, "cruxible-provider-web", wheels)


def _real_osv_provider(
    tmp_path: Path, repository: Path, wheels: Path
) -> tuple[Path, Path, Path]:
    """Build OSV with its own identity and frozen lock, without donor rewriting."""
    return _release_provider(tmp_path, "security-osv-provider", wheels)


def _release_provider(
    tmp_path: Path, name: str, wheels: Path
) -> tuple[Path, Path, Path]:
    source = Path(__file__).resolve().parents[1] / "providers" / name
    project = tmp_path / name
    shutil.copytree(
        source, project, ignore=shutil.ignore_patterns("dist", "__pycache__", ".venv")
    )
    wheel = _build_real_wheel(project)
    runtime = next(wheels.glob("cruxible_provider_runtime-*.whl"))
    return wheel, project / "uv.lock", runtime


def _staged_provider(instance: Any, wheel: Path, lock: Path, runtime: Path) -> Any:
    from cruxible_client.contracts.kits import KitBuildProvider
    from cruxible_client.contracts.provider_installation import ProviderWheelObject

    def stage(path: Path) -> tuple[str, bytes]:
        content = path.read_bytes()
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        instance.body_store().store(content)
        return digest, content

    wheel_digest, _ = stage(wheel)
    lock_digest, _ = stage(lock)
    runtime_digest, _ = stage(runtime)
    return KitBuildProvider(
        wheel=ProviderWheelObject(filename=wheel.name, digest=wheel_digest),
        lock_digest=lock_digest,
        dependencies=(
            ProviderWheelObject(filename=runtime.name, digest=runtime_digest),
        ),
    )


def test_the_real_security_kit_builds_through_production_service_build_kit(
    tmp_path: Path,
) -> None:
    """The shipped path: ``service_build_kit`` itself (not ``build_kit`` plus
    ``check_automation_template`` called separately), with real wheels built
    from the kit's own provider sources, staged exactly as ``kit build
    --provider DIR`` stages them.
    """

    from tests.support.provider_checkout import _build_wheels, require_provider_checkout

    from cruxible_client.contracts.kits import KitAutomationTemplate, KitBuildRequest
    from cruxible_core.service.kits import service_build_kit
    from cruxible_core.service.runbook_preview import service_preview_runbook

    instance = kit_world(tmp_path, automation=False)
    content = template.TEMPLATE.read_text()
    head = instance.accepted_coordinate()
    repository = require_provider_checkout()
    # Built once here (this file has no fixture-backed ``provider_checkout``
    # session cache): the runtime wheel bundled dependency, never rebuilt by
    # the osv/web builds below.
    wheels = _build_wheels(repository, tmp_path / "provider-wheels-cache")

    osv_wheel, osv_lock, osv_runtime = _real_osv_provider(
        tmp_path / "osv-src", repository, wheels
    )
    web_wheel, web_lock, web_runtime = _real_web_provider(
        tmp_path / "web-src", repository, wheels
    )
    providers = (
        _staged_provider(instance, osv_wheel, osv_lock, osv_runtime),
        _staged_provider(instance, web_wheel, web_lock, web_runtime),
    )

    result = service_build_kit(
        instance,
        KitBuildRequest(
            kit_id="security",
            version="1.3.0",
            owns=("security.",),
            providers=providers,
            automation_template=KitAutomationTemplate(
                path="automation.json", content=content
            ),
        ),
        template_actor_id="owner",
    )

    assert result.bundle.manifest.automation_template == "automation.json"
    assert instance.accepted_coordinate() == head

    submit(instance, json.loads(content), name="automation-template-real")
    preview = service_preview_runbook(instance, name=template.START)
    assert [step.target.line.target.name for step in preview.steps] == list(
        template.START_LINES
    )
    assert not any(step.unavailable for step in preview.steps)
    assert preview.order_problems == (), preview.order_problems


def test_a_truly_fresh_instance_kit_add_of_the_real_security_kit_succeeds(
    tmp_path: Path,
) -> None:
    """The real bundle installs without pre-accepting any operation Contracts.

    Kit add governs the providers' Contract closure before registering any
    build, then accepts the remaining definitions and names the template.
    """

    from tests.core_support._support import initialize_local
    from cruxible_client.contracts.candidates import canonical_candidate_timestamp
    from cruxible_client.contracts.kits import KitAddRequest
    from cruxible_client.kits import read_kit_directory
    from cruxible_client.contracts.provider_installation import ProviderInstallRequest
    from cruxible_client.contracts.temporal import utc_now
    from cruxible_core.runtime.provider_runtime import (
        PROVIDER_RUNTIME_CONFIG_PATH,
        ProviderRuntimeOperator,
    )
    from cruxible_core.service.kits import service_add_kit
    from cruxible_core.service.procedures.provider_installation import (
        service_install_provider,
    )

    bundle = read_kit_directory(Path(__file__).resolve().parents[2])
    assert bundle.manifest.owns == ("security.",)
    assert bundle.manifest.automation_template == "automation.json"
    assert {p.package for p in bundle.manifest.providers} == {
        "security-osv-provider",
        "cruxible-provider-web",
        "security-sarif-provider",
    }
    assert bundle.document_bodies
    assert "subject-kinds/security.occurrence.json" in bundle.contents()
    assert "procedures/security.osv-query.json" in bundle.contents()
    # The audit extension: its Procedure, Queries and guidance Documents.
    assert "procedures/security.sarif-import.json" in bundle.contents()
    assert "query-definitions/security.coverage_plan.json" in bundle.contents()
    assert {path for path in bundle.contents() if path.startswith("documents/")} == {
        f"documents/security.guidance.{name}.json"
        for name in ("dependency", "hunter", "verifier", "coverage")
    }

    # A second instance that has NEVER accepted anything of this kit's: not
    # the osv/sbom in/out Contracts, not the refusal Contracts, nothing.
    consumer_root = tmp_path / "consumer"
    consumer_root.mkdir()
    consumer, _consumer_owner = initialize_local(consumer_root)
    for item in bundle.provider_files:
        stored = consumer.body_store().store(item.content)
        assert stored.digest in bundle.manifest.provider_files().values()
    for body in bundle.document_bodies:
        consumer.body_store().store(body.content)
    staged = bundle.model_copy(update={"provider_files": ()})

    state_root = tmp_path / "consumer-server-state"
    config_path = state_root / PROVIDER_RUNTIME_CONFIG_PATH
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps(
            {
                "provider_index_urls": [
                    "https://pypi.org/simple",
                    "https://files.pythonhosted.org/",
                ]
            }
        )
    )
    operator = ProviderRuntimeOperator(state_root)

    def install(request: ProviderInstallRequest, *, expected_build: Any = None) -> Any:
        return service_install_provider(
            consumer,
            operator=operator,
            request=request,
            actor_id="owner",
            timestamp=canonical_candidate_timestamp(utc_now()),
            expected_build=expected_build,
        )

    before = consumer.accepted_coordinate()
    before_tree = consumer.immutable_tree_at(before.git_oid)
    assert not any(path in before_tree for path in bundle.contents())
    with consumer.accepted_history_reader() as history:
        before_generation = int(history.sequence)
    added = service_add_kit(
        consumer,
        KitAddRequest(bundle=staged, source="test", dry_run=False),
        actor_id="owner",
        timestamp=canonical_candidate_timestamp(utc_now()),
        install_provider=install,
    )
    assert added.status == "accepted", added
    assert added.automation_template == "automation.json"
    assert added.automation_template in bundle.file_contents()
    assert [step.action for step in added.providers] == ["install"] * 3
    tree = consumer.immutable_tree_at(consumer.accepted_coordinate().git_oid)
    assert all(tree[path] == value for path, value in bundle.contents().items())
    from cruxible_client.contracts.providers import provider_path

    assert all(
        provider_path(provider.build) in tree for provider in bundle.manifest.providers
    )
    with consumer.accepted_history_reader() as history:
        # One Contract change, one registration per provider (three), one kit change.
        assert int(history.sequence) - before_generation == 5

    from cruxible_core.service.runbook_preview import service_preview_runbook

    submit(
        consumer,
        json.loads(bundle.file_contents()["automation.json"]),
        name="committed-template",
    )
    preview = service_preview_runbook(consumer, name=template.START)
    assert not any(step.unavailable for step in preview.steps)
    assert preview.order_problems == ()
