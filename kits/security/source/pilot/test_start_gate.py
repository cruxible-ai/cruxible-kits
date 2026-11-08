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
            filename=f"{distribution.name.replace('-', '_')}-{distribution.version}-py3-none-any.whl",
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
    from cruxible_client.contracts.kits import KitAutomationTemplate, KitBuildRequest
    from cruxible_core.service.kit_template import check_automation_template
    from cruxible_core.service.kits import build_kit
    from cruxible_core.service.runbook_preview import service_preview_runbook
    from tests.support.provider_checkout import require_provider_checkout

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
    # artifact (``kit add`` installs it before the definitions), so it is
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
    """The real ``cruxible-provider-web`` package: its own source, its own lock."""

    source = repository / "packages/cruxible-provider-web"
    project = tmp_path / "cruxible-provider-web"
    shutil.copytree(
        source, project, ignore=shutil.ignore_patterns("dist", "__pycache__", ".venv")
    )
    wheel = _build_real_wheel(project)
    runtime = next(wheels.glob("cruxible_provider_runtime-*.whl"))
    return wheel, project / "uv.lock", runtime


def _real_osv_provider(
    tmp_path: Path, repository: Path, wheels: Path
) -> tuple[Path, Path, Path]:
    """The real ``security-osv-provider`` package: its own source and registration,
    under a borrowed lock (it ships none of its own; D-R48 follow-up).

    ``cruxible-provider-web``'s lock has the same shape (one root package, one
    path dependency on ``cruxible-provider-runtime``, ``httpx`` from the
    registry): borrowed and renamed to this package's own name, exactly as
    ``tests.support.provider_installation.build_local_call`` already borrows
    ``cruxible-provider-workspace``'s lock for its synthetic test packages.
    The borrowed lock's own version becomes this build's version (the wheel's
    identity must match its lock's root exactly), so ``pyproject.toml``'s and
    ``manifest.yaml``'s version lines move to match, ``registration.json``'s
    manifest digest moves to match the repatched ``manifest.yaml``, and
    ``hatchling`` is pinned to the exact build already cached offline here
    (the real ``pyproject.toml`` names it unpinned, which ``uv build
    --offline`` cannot resolve). The declared operations and their Contract
    refs -- what this test is actually proving -- are the real, unmodified
    kit source.
    """

    from tests.support.provider_installation import _lock_root_version

    source = dependency_replay.PROVIDER
    project = tmp_path / "security-osv-provider"
    shutil.copytree(source / "src", project / "src")
    donor_lock = repository / "packages/cruxible-provider-web/uv.lock"
    version = _lock_root_version(donor_lock)

    package_root = project / "src" / "security_osv_provider"
    manifest_path = package_root / "manifest.yaml"
    manifest_text = manifest_path.read_text()
    real_manifest_version = next(
        line.split(":", 1)[1].strip()
        for line in manifest_text.splitlines()
        if line.strip().startswith("version:")
    )
    patched_manifest = manifest_text.replace(
        f"version: {real_manifest_version}", f"version: {version}"
    )
    manifest_path.write_text(patched_manifest)
    new_manifest_digest = (
        "sha256:" + hashlib.sha256(patched_manifest.encode()).hexdigest()
    )
    registration_path = package_root / "registration.json"
    registration = json.loads(registration_path.read_text())
    registration["manifest"]["digest"] = new_manifest_digest
    registration_path.write_text(json.dumps(registration, indent=1) + "\n")

    pyproject = (source / "pyproject.toml").read_text()
    real_version = next(
        line.split('"')[1]
        for line in pyproject.splitlines()
        if line.startswith("version =")
    )
    (project / "pyproject.toml").write_text(
        pyproject.replace(
            f'version = "{real_version}"', f'version = "{version}"'
        ).replace('requires = ["hatchling"]', 'requires = ["hatchling==1.32.1"]')
    )
    (project / "uv.lock").write_text(
        donor_lock.read_text().replace("cruxible-provider-web", "security-osv-provider")
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

    from cruxible_client.contracts.kits import KitAutomationTemplate, KitBuildRequest
    from cruxible_core.service.kits import service_build_kit
    from cruxible_core.service.runbook_preview import service_preview_runbook
    from tests.support.provider_checkout import _build_wheels, require_provider_checkout

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


def test_a_truly_fresh_instance_kit_add_of_the_real_security_kit_hits_the_known_sequencing_gap(
    tmp_path: Path,
) -> None:
    """D-R48 review fix round 3: the manifest's own declaration (``owns:
    ["security."]``), the real built bundle, against a SECOND instance that
    has never accepted anything -- not even the operation Contracts the
    bundled providers pin. Documents plainly what a production ``kit add``
    does: it refuses, and exactly where, because of a separate, pre-existing
    gap this fix round does not touch.

    This is NOT the same claim as F1 (the export is complete: every
    Contract a bundled operation needs, in/out and refusal, is in
    ``bundle.contents()`` -- proved by the build test above and by core's
    own ``test_a_bundled_providers_refusal_contract_outside_owns_builds_and_installs``
    regression, which pre-accepts those Contracts on the consumer first,
    exactly as every other bundled-provider test in the core suite does).
    This test asks the stronger, separate question: can a ``kit add`` that
    pre-accepts *nothing* still succeed, given a kit's bundled provider
    installs before the kit's own definitions land (``_add_kit``/
    ``_install_providers`` in core's ``service/kits.py``, which installs a
    bundled provider through the ordinary single-package install path --
    ``service_install_provider`` -- strictly before diffing and proposing the
    kit's own definitions). It refuses with
    ``cruxible.provider.operation_contract_unresolved`` on the FIRST
    not-yet-accepted Contract a bundled operation pins -- here
    ``search.web.request@1`` (``cruxible-provider-web``'s own operation,
    not even an osv/sbom one) -- because the kit's own copy of that Contract
    (now correctly exported, thanks to F1) lands only after the provider
    install this refusal happens inside. Pinning F1 does not and cannot fix
    this: the Contract genuinely is not accepted yet at the moment the
    provider tries to install.
    """

    import pytest
    from cruxible_client.contracts.candidates import canonical_candidate_timestamp
    from cruxible_client.contracts.kits import (
        KitAddRequest,
        KitAutomationTemplate,
        KitBuildRequest,
    )
    from cruxible_client.contracts.provider_installation import ProviderInstallRequest
    from cruxible_client.contracts.temporal import utc_now
    from cruxible_core.errors import RequestRefusedError
    from cruxible_core.runtime.provider_runtime import (
        PROVIDER_RUNTIME_CONFIG_PATH,
        ProviderRuntimeOperator,
    )
    from cruxible_core.service.kits import service_add_kit, service_build_kit
    from cruxible_core.service.procedures.provider_installation import (
        service_install_provider,
    )
    from tests.core_support._support import initialize_local
    from tests.support.provider_checkout import _build_wheels, require_provider_checkout

    (tmp_path / "publisher").mkdir()
    instance = kit_world(tmp_path / "publisher", automation=False)
    content = template.TEMPLATE.read_text()
    repository = require_provider_checkout()
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
            owns=("security.",),  # the manifest's own declaration, never widened
            providers=providers,
            automation_template=KitAutomationTemplate(
                path="automation.json", content=content
            ),
        ),
        template_actor_id="owner",
    )
    bundle = result.bundle

    # A second instance that has NEVER accepted anything of this kit's: not
    # the osv/sbom in/out Contracts, not the refusal Contracts, nothing.
    consumer_root = tmp_path / "consumer"
    consumer_root.mkdir()
    consumer, _consumer_owner = initialize_local(consumer_root)
    for item in bundle.provider_files:
        stored = consumer.body_store().store(item.content)
        assert stored.digest in bundle.manifest.provider_files().values()
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

    # The known, pre-existing, separate gap: a bundled provider installs
    # through the ordinary single-package path, strictly before the kit's
    # own definitions (now including every Contract its operations pin,
    # thanks to F1) are diffed and proposed. So the FIRST not-yet-accepted
    # Contract any bundled operation pins refuses the install outright, not
    # a graceful "blocked"/"awaiting_providers" KitChangeResult.
    with pytest.raises(RequestRefusedError) as refused:
        service_add_kit(
            consumer,
            KitAddRequest(bundle=staged, source="test", dry_run=False),
            actor_id="owner",
            timestamp=canonical_candidate_timestamp(utc_now()),
            install_provider=install,
        )
    print("FRESH KIT ADD REFUSAL:", refused.value.error_code, str(refused.value))
    assert refused.value.error_code == "cruxible.provider.operation_contract_unresolved"
