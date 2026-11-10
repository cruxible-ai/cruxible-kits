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
from collections.abc import Callable, Iterable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import dependency_replay
import inventory
import osv
import pytest
import template
import triage
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


def adopted_world(
    tmp_path: Path, sbom: bytes, tailor: Callable[[dict[str, Any]], None] | None = None
) -> Any:
    """The kit's definitions, the committed template adopted, and its SBOM Line's
    file in the workspace. Every Mandate is re-dated around the wall clock (valid
    from 2026-01-01 to 30 days ahead), as an adopter tailors them, so runs on the
    daemon's own clock admit. ``tailor`` edits the template first, as an adopter
    does (a Line's parameters, another SBOM Line)."""

    from datetime import UTC, datetime

    instance = kit_world(tmp_path, automation=False)
    adopted = json.loads(template.TEMPLATE.read_text())
    if tailor is not None:
        tailor(adopted)
    expires_at = datetime.now(UTC) + timedelta(days=30)
    for member in adopted["members"]:
        if member["kind"] == "procedure_mandate":
            member["valid_from"] = "2026-01-01T00:00:00Z"
            member["expires_at"] = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    submit(instance, adopted, name="automation-template")
    write_file(tmp_path, template.SBOM[1], sbom)
    return instance


def run_runbook(instance: Any, replay: Replay, name: str) -> Any:
    """``cruxible runbook run NAME``: every step as the caller's manual Line run, on
    the daemon's clock (the wall clock: each step reads what earlier steps wrote)."""

    from datetime import UTC, datetime

    from cruxible_core.documents.workspace_file import WorkspaceFileReader
    from cruxible_core.service.runbooks import service_run_runbook
    from tests.support.operation_world import actor

    replay.now = datetime.now(UTC)
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
    """The demo app adopted and seeded by security.start."""

    from datetime import UTC, datetime

    instance = adopted_world(tmp_path, DEMO_SBOM.read_bytes())
    seeded = run_runbook(instance, demo_replay(), template.START)
    assert seeded.status == "completed", seeded
    return instance, datetime.now(UTC)


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
    for name, lines in (
        (template.START, template.START_LINES),
        (template.MAINTAIN, template.MAINTAIN_LINES),
    ):
        replay = OsvDeclines(
            {kit.KEV_URL: fixture_bytes("kev-catalog")},
            osv=dependency_replay.RecordedOsv(),
        )
        result = run_runbook(instance, replay, name)
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


#: The judgments only agents write (no Line does, by design: K-CF2a).
AGENT_JUDGMENTS = frozenset(
    {
        f"{inventory.EXPOSURE}.justification",
        f"{inventory.APP_EXPOSURE}.justification",
        f"{inventory.APP_EXPOSURE}.verdict",
    }
)


def unexpected_order_problems(preview: Any, lines: tuple[str, ...]) -> tuple[Any, ...]:
    """Every order problem except the true one the attention steps always carry: they
    read the judgments, which agents write and no Line does (``reads_unwritten``)."""

    attention = {
        index
        for index, line in enumerate(lines, start=1)
        if line in triage.ATTENTION.values()
    }
    expected = {
        (problem.step, problem.claim_type)
        for problem in preview.order_problems
        if problem.kind == "reads_unwritten"
        and problem.step in attention
        and problem.claim_type in AGENT_JUDGMENTS
    }
    assert {step for step, _claim_type in expected} == attention, preview.order_problems
    return tuple(
        problem
        for problem in preview.order_problems
        if (problem.step, problem.claim_type) not in expected
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
    assert unexpected_order_problems(preview, template.START_LINES) == ()
    # The daily refresh reads the inventory the SBOM import Line (outside it) writes.
    maintain = service_preview_runbook(instance, name=template.MAINTAIN)
    assert [step.target.line.target.name for step in maintain.steps] == list(
        template.MAINTAIN_LINES
    )
    assert not any(step.unavailable for step in maintain.steps)
    assert unexpected_order_problems(maintain, template.MAINTAIN_LINES) == ()

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
    assert unexpected_order_problems(preview, template.START_LINES) == ()


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
    assert unexpected_order_problems(preview, template.START_LINES) == ()


# -- urgent unjudged exposures reach the Line inbox ------------------------------------


def wall_world(
    tmp_path: Path,
    sbom: bytes | None = None,
    tailor: Callable[[dict[str, Any]], None] | None = None,
) -> Any:
    return adopted_world(
        tmp_path, DEMO_SBOM.read_bytes() if sbom is None else sbom, tailor
    )


def run_now(instance: Any, name: str, replay: Replay | None = None) -> Any:
    result = run_runbook(instance, replay or demo_replay(), name)
    assert result.status == "completed", result
    return result


def scored_replay(
    scores: Mapping[str, str] | None = None, default: str | None = None
) -> Replay:
    """The demo's recorded OSV and KEV, and an EPSS that scores each CVE asked
    ``scores[cve]``, else ``default`` (``None``: FIRST has no score for it)."""

    from test_pilot_gate import EpssOrigin

    class ScoredEpss(EpssOrigin):
        def respond(self, url: str) -> Any:
            from urllib.parse import parse_qs, urlsplit

            (cves,) = parse_qs(urlsplit(url).query)[kit.EPSS_PARAM]
            for cve in cves.split(","):
                score = (scores or {}).get(cve, default)
                if score is None:
                    self.records.pop(cve, None)
                else:
                    self.records[cve] = {
                        "cve": cve,
                        "epss": score,
                        "percentile": "0.500000000",
                        "date": "2026-11-02",
                    }
            self.recorded = set()  # never the verbatim recording
            return super().respond(url)

    return Replay(
        {kit.KEV_URL: fixture_bytes("kev-catalog")},
        osv=dependency_replay.RecordedOsv(),
        epss=ScoredEpss(),
    )


#: Every demo pair scores over the shipped threshold: the attention tests that are
#: about identity and decisions, not the threshold, see every unjudged pair posted.
def over_threshold() -> Replay:
    return scored_replay(default="0.500000000")


def tailor_line(
    adopted: dict[str, Any], line: str, parameters: Mapping[str, Any]
) -> None:
    """Set one template Line's parameters, as an adopter tailors them."""

    (member,) = [
        m for m in adopted["members"] if m["kind"] == "line" and m["name"] == line
    ]
    member["parameters"] = dict(parameters)


def edit_line(
    instance: Any, line: str, procedure: str, parameters: Mapping[str, Any]
) -> None:
    """Author one attention Line (a new one, or an edit of its parameters)."""

    submit(
        instance,
        {
            "kind": "change_set",
            "rationale": f"Tailor the attention Line {line}.",
            "members": [triage.attention_line(line, procedure, parameters)],
        },
        name=f"tailor-{line}",
    )


def run_line(instance: Any, line: str) -> Any:
    """One manual run of an attention Line (no provider, no workspace file)."""

    from datetime import UTC, datetime

    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        service_run_playbill_line,
    )
    from tests.support.operation_world import actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    state = service_run_playbill_line(
        instance,
        path_identity_digest=line,
        request=LineRunRequest(line=line),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(datetime.now(UTC) + timedelta(seconds=1)),
    )
    assert state.status == "succeeded", state.terminal
    return state


def attention_items(
    instance: Any, lines: Iterable[str] | None = None
) -> dict[tuple[str, str, str], Any]:
    """Every item the attention Lines (``lines``, else the template's two) posted:
    (occurrence, CVE, state) -> envelope."""

    from cruxible_core.service.procedures.line_inbox import (
        service_get_inbox_item,
        service_list_inbox,
    )
    from cruxible_core.storage.cas import BodyAccessContext

    access = BodyAccessContext(principal_id="reader", can_read_body=True)
    out: dict[tuple[str, str, str], Any] = {}
    for line in triage.ATTENTION.values() if lines is None else lines:
        listed = service_list_inbox(instance, line=line, limit=200, access=access)
        assert not listed.truncated
        for entry in listed.entries:
            item = service_get_inbox_item(
                instance, item=entry.item.item_id, access=access
            )
            payload = item.payload
            assert set(payload) == {
                "inventory",
                "component",
                "cve_id",
                "occurrence",
                "state",
            }
            key = (payload["occurrence"], payload["cve_id"], payload["state"])
            assert key not in out, key
            out[key] = item.item
    return out


def urgent_pairs(instance: Any) -> set[tuple[str, str]]:
    from test_dependency_gate import query_rows

    return {(r["occurrence"], r["cve_id"]) for r in query_rows(instance, triage.URGENT)}


def item_of(
    items: dict[tuple[str, str, str], Any], cve_id: str, state: str = "unjudged"
) -> Any:
    (found,) = [item for (o, c, s), item in items.items() if c == cve_id and s == state]
    return found


def decide(instance: Any, item: Any, *, link: str | None = None) -> None:
    """``cruxible inbox ack ITEM``, or ``inbox link ITEM --subject KIND/ID``."""

    from datetime import UTC, datetime

    from cruxible_client.contracts.line_inbox import InboxLinkSubject
    from cruxible_core.service.procedures.line_inbox import (
        service_acknowledge_inbox_item,
        service_link_inbox_item,
    )
    from tests.support.operation_world import actor

    now = datetime.now(UTC)
    if link is None:
        service_acknowledge_inbox_item(
            instance, item=item.item_id, actor_context=actor(), decided_at=now
        )
    else:
        service_link_inbox_item(
            instance,
            item=item.item_id,
            target=InboxLinkSubject(subject=link),
            actor_context=actor(),
            decided_at=now,
        )


def test_urgent_pairs_reach_the_inbox_once_and_decisions_stand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """security.start posts one unread item per urgent pair and next names the Line; a
    rerun with nothing changed posts nothing new and acked or linked items stay
    decided (their sightings count up); a judged pair (not_affected or affected) is
    never posted again; and a linked pair whose judgment is later withdrawn is the
    same item re-sighted: it stays linked, so it does not come back through the
    inbox (security.pair_without_judgment_exposures lists it)."""

    from test_dependency_gate import (
        API,
        API_CVE,
        CORE,
        DEMO_APP,
        LOG4SHELL,
        _next_rows,
        app_judge,
        confirm,
        justification_claim,
        query_rows,
        write,
    )

    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = wall_world(tmp_path)
    started = run_now(instance, template.START, over_threshold())
    urgent = urgent_pairs(instance)
    items = attention_items(instance)
    assert {(o, c) for o, c, _s in items} == urgent and len(items) == len(urgent) > 0
    assert {s for _o, _c, s in items} == {"unjudged"}
    assert {item.status for item in items.values()} == {"unread"}
    posted = step(started, triage.ATTENTION["unjudged"])
    assert posted.counts.inbox == len(urgent) and posted.step in started.attention_steps
    assert step(started, triage.ATTENTION["contested"]).counts.inbox == 0
    rows = [
        row.model_dump(mode="json")
        for row in _next_rows(instance, tmp_path, "line_inbox_unread")
    ]
    (row,) = [r for r in rows if triage.ATTENTION["unjudged"] in json.dumps(r)]
    assert row["detail"]["unread"] == len(urgent), row

    # Nothing changed: the same items, re-sighted; the decided ones stay decided.
    acked, linked = item_of(items, "CVE-2021-45105"), item_of(items, "CVE-2021-44832")
    decide(instance, acked)
    linked_occurrence = next(o for o, c, _s in items if c == "CVE-2021-44832")
    decide(instance, linked, link=f"{inventory.OCCURRENCE}/{linked_occurrence}")
    run_now(instance, template.MAINTAIN, over_threshold())
    again = attention_items(instance)
    assert set(again) == set(items)
    assert (
        again[next(k for k in again if k[1] == "CVE-2021-45105")].status
        == "acknowledged"
    )
    assert again[next(k for k in again if k[1] == "CVE-2021-44832")].status == "linked"
    assert {item.occurrences for item in again.values()} == {2}

    # Judged pairs (app-level not_affected; affected) are never posted again.
    pair = app_judge(instance, DEMO_APP, CORE, LOG4SHELL).changes[0].subject
    confirm(instance, DEMO_APP, API, API_CVE)
    decide(instance, item_of(again, LOG4SHELL), link=pair)
    run_now(instance, template.MAINTAIN, over_threshold())
    judged = attention_items(instance)
    assert set(judged) == set(items)
    assert (
        item_of(judged, LOG4SHELL).occurrences
        == item_of(judged, API_CVE).occurrences
        == 2
    )
    assert {
        item.occurrences
        for (_o, c, _s), item in judged.items()
        if c not in (LOG4SHELL, API_CVE)
    } == {3}

    # Fact-finding: the linked pair's judgment is withdrawn and the pair is urgent again.
    reverse = triage.reverse_judgment(
        justification_claim(instance, pair), because="Withdrawn.", accept="if_allowed"
    )
    assert write(instance, reverse).status == "accepted"
    assert (next(o for o, c, _s in items if c == LOG4SHELL), LOG4SHELL) in urgent_pairs(
        instance
    )
    run_now(instance, template.MAINTAIN, over_threshold())
    back = attention_items(instance)
    assert set(back) == set(items)  # the same key: no new item
    withdrawn = item_of(back, LOG4SHELL)
    assert (withdrawn.status, withdrawn.occurrences) == ("linked", 3), withdrawn
    assert withdrawn.recurred_since_disposition >= 1
    assert {
        r["cve_id"] for r in query_rows(instance, triage.PAIR_WITHOUT_JUDGMENT)
    } == {LOG4SHELL}


def test_a_newly_urgent_or_contested_pair_posts_exactly_one_new_item(
    tmp_path: Path,
) -> None:
    """A pair OSV newly lists posts one new item; a contested judgment on a pair posts
    a contested item, distinct from that pair's unjudged one."""

    from test_dependency_gate import (
        API,
        API_CVE,
        BATCH_ORDER,
        CORE,
        DEMO_APP,
        LOG4SHELL,
        OSV,
        QUERYBATCH,
        _contend,
        app_judge,
        batch_with,
        write,
    )

    def drop_api(results: list[Any]) -> None:
        results[BATCH_ORDER.index(API)] = {}

    instance = wall_world(tmp_path)
    first = over_threshold()
    first.osv = OSV({QUERYBATCH: batch_with(drop_api)})
    run_now(instance, template.START, first)
    before = attention_items(instance)
    assert not any(c == API_CVE for _o, c, _s in before)

    run_now(
        instance, template.MAINTAIN, over_threshold()
    )  # OSV now lists API_CVE for log4j-api
    added = set(attention_items(instance)) - set(before)
    assert [(c, s) for _o, c, s in added] == [(API_CVE, "unjudged")], added

    pair = app_judge(instance, DEMO_APP, CORE, LOG4SHELL).changes[0].subject
    contended = write(
        instance,
        {
            "because": "A competing reason.",
            "changes": [
                _contend(pair, "justification", "inline_mitigations_already_exist")
            ],
        },
    )
    assert contended.status == "accepted", contended
    current = attention_items(instance)
    run_now(instance, template.MAINTAIN, over_threshold())
    after = attention_items(instance)
    added = set(after) - set(current)
    assert [(c, s) for _o, c, s in added] == [(LOG4SHELL, "contested")], added
    (contested_key,) = added
    unjudged_key = (contested_key[0], LOG4SHELL, "unjudged")
    assert after[contested_key].item_id != after[unjudged_key].item_id
    assert after[contested_key].status == "unread"


def test_an_attention_run_posts_at_most_100_items_most_urgent_first(
    tmp_path: Path,
) -> None:
    """105 urgent pairs, the unjudged Line's threshold 0: one run posts the 100 with
    the highest EPSS score (the worklist order), and its terminal reports
    inbox_truncation (cap 100, declared)."""

    from datetime import UTC, datetime

    from cruxible_core.service.procedures.procedure_runs import (
        LineRunRequest,
        service_run_playbill_line,
    )
    from test_dependency_gate import synthetic_osv, synthetic_sbom
    from test_pilot_gate import EpssOrigin, epss_answer
    from tests.support.operation_world import actor
    from tests.test_procedures.test_completeness_transfer import _Clock

    size = 105
    instance = wall_world(
        tmp_path,
        synthetic_sbom(size),
        lambda adopted: tailor_line(
            adopted, triage.ATTENTION["unjudged"], {"min_epss": "0"}
        ),
    )
    head = {k: v for k, v in epss_answer().items() if k != "data"}
    data = [
        {
            "cve": f"CVE-2026-{1000 + i}",
            "epss": f"{(i + 1) / 1000:.9f}",
            "percentile": "0.500000000",
            "date": "2026-11-02",
        }
        for i in range(size)
    ]
    replay = Replay(
        {kit.KEV_URL: fixture_bytes("kev-catalog")},
        osv=synthetic_osv(size),
        epss=EpssOrigin({**head, "total": size, "data": data}),
    )
    started = run_now(instance, template.START, replay)
    assert step(started, triage.ATTENTION["unjudged"]).counts.inbox == 100
    posted = {c for _o, c, _s in attention_items(instance)}
    from test_dependency_gate import query_rows

    ranked = [
        (r["cve_id"], r.get("epss_score"))
        for r in query_rows(instance, triage.URGENT, limit=500)
    ]
    assert posted == {f"CVE-2026-{1000 + i}" for i in range(size - 100, size)}, ranked

    now = datetime.now(UTC) + timedelta(seconds=1)
    state = service_run_playbill_line(
        instance,
        path_identity_digest=triage.ATTENTION["unjudged"],
        request=LineRunRequest(line=triage.ATTENTION["unjudged"]),
        actor_context=actor(),
        caller_rung=2,
        daemon_clock=_Clock(now),
    )
    assert state.status == "succeeded", state.terminal
    (egress,) = state.terminal_egress
    truncation = egress.inbox_truncation
    assert (
        truncation.cap,
        truncation.cap_source,
        truncation.selected,
        truncation.posted,
    ) == (
        100,
        "declared",
        size,
        100,
    )


# -- the unjudged Line's threshold, and Lines for one inventory -------------------------

#: Demo CVEs by the part they play (each affects log4j-core only).
AT, BELOW, UNSCORED = "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"
#: Unscored at first, then scored under the threshold (log4j-core).
LATE_LOW = "CVE-2025-68161"


def unjudged_keys(
    rows: Iterable[Any], *cves: str, inventory: str | None = None
) -> set[Any]:
    """The attention item keys of the worklist ``rows`` for ``cves`` (in ``inventory``)."""

    return {
        (r["occurrence"], r["cve_id"], "unjudged")
        for r in rows
        if r["cve_id"] in cves and inventory in (None, r["inventory"])
    }


def test_the_unjudged_line_posts_kev_listed_scored_at_its_threshold_and_unscored_pairs(
    tmp_path: Path,
) -> None:
    """At the shipped threshold (0.1) a pair scored under it is not posted, one at it
    is, a KEV-listed pair is whatever its EPSS score, and one FIRST has not scored yet
    is; the worklist keeps them all. When a score arrives, a pair scored over the
    threshold (an unscored one, or one under it before) is the same item or one new
    item, its status kept; an unscored pair scored under it is not posted again and its
    item stays as it was. A judged pair stops posting. At threshold 0 every pair nobody
    has judged posts, the posted ones the same items."""

    from test_dependency_gate import (
        API_CVE,
        CORE,
        DEMO_APP,
        LOG4SHELL,
        app_judge,
        query_rows,
    )

    low = "0.000100000"
    first = {
        LOG4SHELL: "0.010000000",
        AT: "0.100000000",
        BELOW: "0.099999999",
        UNSCORED: None,
        LATE_LOW: None,
        API_CVE: None,  # never scored
    }
    instance = wall_world(tmp_path)
    started = run_now(instance, template.START, scored_replay(first, default=low))
    rows = query_rows(instance, triage.URGENT)
    assert {r["cve_id"] for r in rows} >= set(first)
    items = attention_items(instance)
    assert set(items) == unjudged_keys(
        rows, LOG4SHELL, AT, UNSCORED, LATE_LOW, API_CVE
    ), items
    assert step(started, triage.ATTENTION["unjudged"]).counts.inbox == len(items)
    over = query_rows(instance, triage.UNJUDGED_OVER, params={"min_epss": "0.1"})
    assert {(r["occurrence"], r["cve_id"], "unjudged") for r in over} == set(items)
    for cve in (UNSCORED, LATE_LOW):
        decide(instance, item_of(items, cve))

    # FIRST scores BELOW and UNSCORED over the threshold, LATE_LOW under it.
    second = {
        **first,
        BELOW: "0.300000000",
        UNSCORED: "0.400000000",
        LATE_LOW: "0.010000000",
    }
    run_now(instance, template.MAINTAIN, scored_replay(second, default=low))
    scored = attention_items(instance)
    assert set(scored) - set(items) == unjudged_keys(rows, BELOW)
    assert all(scored[key].item_id == items[key].item_id for key in items)
    (late_high,) = unjudged_keys(rows, UNSCORED)
    (late_low,) = unjudged_keys(rows, LATE_LOW)
    assert (scored[late_high].status, scored[late_high].occurrences) == (
        "acknowledged",
        2,
    )
    assert (scored[late_low].status, scored[late_low].occurrences) == (
        "acknowledged",
        1,
    )
    assert {scored[key].occurrences for key in set(items) - {late_low}} == {2}

    # A judged pair stops posting: its item is not re-sighted.
    app_judge(instance, DEMO_APP, CORE, LOG4SHELL)
    run_now(instance, template.MAINTAIN, scored_replay(second, default=low))
    judged = attention_items(instance)
    assert set(judged) == set(scored)
    assert {judged[key].occurrences for key in unjudged_keys(rows, LOG4SHELL)} == {2}
    assert {judged[key].occurrences for key in unjudged_keys(rows, AT, API_CVE)} == {3}
    assert judged[late_low].occurrences == 1

    # Threshold 0: every pair nobody has judged, the posted ones the same items.
    edit_line(
        instance,
        triage.ATTENTION["unjudged"],
        triage.ATTENTION["unjudged"],
        {"min_epss": "0"},
    )
    run_now(instance, template.MAINTAIN, scored_replay(second, default=low))
    everything = attention_items(instance)
    rest = {r["cve_id"] for r in rows} - set(first)
    assert rest and set(everything) - set(judged) == unjudged_keys(rows, *rest)
    assert all(everything[key].item_id == judged[key].item_id for key in judged)
    assert everything[late_low].occurrences == 2
    assert {everything[key].occurrences for key in unjudged_keys(rows, API_CVE)} == {4}


DEMO_LINE = triage.ATTENTION["unjudged"] + ".demo"
OTHER_LINE = triage.ATTENTION["unjudged"] + ".other"


def test_a_line_for_one_inventory_posts_only_its_pairs_at_its_own_threshold(
    tmp_path: Path,
) -> None:
    """Two inventories holding the same components, the shipped unjudged Line (no
    inventory, 0.1) and a Line on the per-inventory Procedure for each (the demo at
    0.5, its twin at 0.05). The shipped Line posts both inventories' pairs over 0.1;
    each per-inventory Line only its own inventory's pairs over its own threshold
    (KEV-listed always), with the same item fields. A pair the shipped Line and a
    per-inventory Line both post is one item in each Line's inbox (the same payload,
    two item ids), decided apart; rerunning both re-sights each and posts nothing new."""

    from test_dependency_gate import (
        DEMO_APP,
        LOG4SHELL,
        OTHER_APP,
        other_sbom,
        query_rows,
    )

    other = ("other", "other.cdx.json")

    def tailor(adopted: dict[str, Any]) -> None:
        members = adopted["members"]
        members += inventory.sbom_automation((other,), now=template.DATED)
        members += [
            triage.attention_line(
                DEMO_LINE,
                triage.ATTENTION_IN_INVENTORY,
                {"inventory": DEMO_APP, "min_epss": "0.5"},
            ),
            triage.attention_line(
                OTHER_LINE,
                triage.ATTENTION_IN_INVENTORY,
                {"inventory": OTHER_APP, "min_epss": "0.05"},
            ),
        ]
        (start,) = [
            m for m in members if m["kind"] == "runbook" and m["name"] == template.START
        ]
        start["steps"].insert(1, {"line": inventory.sbom_line_name(other[0])})

    # Scores here: AT over every threshold, BELOW over 0.1 only, UNSCORED (scored here)
    # over 0.05 only, the rest under all three; LOG4SHELL is KEV-listed.
    scores = {
        LOG4SHELL: "0.010000000",
        AT: "0.600000000",
        BELOW: "0.300000000",
        UNSCORED: "0.070000000",
    }
    instance = wall_world(tmp_path, tailor=tailor)
    write_file(tmp_path, other[1], other_sbom())
    run_now(instance, template.START, scored_replay(scores, default="0.010000000"))
    rows = query_rows(instance, triage.URGENT)
    assert {r["inventory"] for r in rows} == {DEMO_APP, OTHER_APP}

    shipped = attention_items(instance, (triage.ATTENTION["unjudged"],))
    assert set(shipped) == unjudged_keys(rows, LOG4SHELL, AT, BELOW)
    for line in (DEMO_LINE, OTHER_LINE):
        run_line(instance, line)
    demo = attention_items(instance, (DEMO_LINE,))
    assert set(demo) == unjudged_keys(rows, LOG4SHELL, AT, inventory=DEMO_APP)
    twin = attention_items(instance, (OTHER_LINE,))
    assert set(twin) == unjudged_keys(
        rows, LOG4SHELL, AT, BELOW, UNSCORED, inventory=OTHER_APP
    )
    assert {
        (r["occurrence"], r["cve_id"], "unjudged")
        for r in query_rows(
            instance,
            triage.UNJUDGED_OVER_IN,
            params={"inventory": DEMO_APP, "min_epss": "0.5"},
        )
    } == set(demo)

    # The same pair in two Lines' inboxes: two items, decided apart.
    (both,) = unjudged_keys(rows, AT, inventory=DEMO_APP)
    assert shipped[both].item_id != demo[both].item_id
    decide(instance, shipped[both])
    run_now(instance, template.MAINTAIN, scored_replay(scores, default="0.010000000"))
    for line in (DEMO_LINE, OTHER_LINE):
        run_line(instance, line)
    shipped_again = attention_items(instance, (triage.ATTENTION["unjudged"],))
    demo_again = attention_items(instance, (DEMO_LINE,))
    assert (set(shipped_again), set(demo_again)) == (set(shipped), set(demo))
    assert set(attention_items(instance, (OTHER_LINE,))) == set(twin)
    assert (shipped_again[both].status, demo_again[both].status) == (
        "acknowledged",
        "unread",
    )
    assert {item.occurrences for item in demo_again.values()} == {2}
