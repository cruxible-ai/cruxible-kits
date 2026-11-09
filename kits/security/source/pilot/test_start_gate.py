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
from pathlib import Path
from typing import Any

import dependency_replay
import template
from test_pilot_gate import kit_world, submit


def test_the_committed_template_is_the_generated_one() -> None:
    assert template.TEMPLATE.read_text() == template.render()


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

    Kit add governs the providers' Contract closure before registering either
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
    }
    assert bundle.document_bodies
    assert "subject-kinds/security.occurrence.json" in bundle.contents()
    assert "procedures/security.osv-query.json" in bundle.contents()

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
    assert [step.action for step in added.providers] == ["install", "install"]
    tree = consumer.immutable_tree_at(consumer.accepted_coordinate().git_oid)
    assert all(tree[path] == value for path, value in bundle.contents().items())
    from cruxible_client.contracts.providers import provider_path

    assert all(
        provider_path(provider.build) in tree for provider in bundle.manifest.providers
    )
    with consumer.accepted_history_reader() as history:
        # One Contract change, one registration per provider, one kit change.
        assert int(history.sequence) - before_generation == 4

    from cruxible_core.service.runbook_preview import service_preview_runbook

    submit(
        consumer,
        json.loads(bundle.file_contents()["automation.json"]),
        name="committed-template",
    )
    preview = service_preview_runbook(consumer, name=template.START)
    assert not any(step.unavailable for step in preview.steps)
    assert preview.order_problems == ()
