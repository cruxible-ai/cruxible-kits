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
    # ``osv.``/``sbom.``/``search.``/``web.``: a bundled operation's in/out
    # Contracts are swept as dependency pins of the owned Procedure that
    # declares the slot, but its REFUSAL Contracts are not (a Provider's own
    # declaration, never carried or walked). Core has no mechanism yet to
    # carry those from the ``owns`` prefix alone, so this gate world (which,
    # like a real release, already authors every one of them:
    # ``osv.provider_contracts()``, ``web_contract_members()``) owns their
    # namespaces directly until core grows one; the real release's ``owns``
    # needs the same widening or that mechanism (follow-up, not this fix
    # round).
    bundle = build_kit(
        tree,
        KitBuildRequest(
            kit_id="security",
            version="1.3.0",
            owns=("osv.", "sbom.", "search.", "security.", "web."),
        ),
    )
    # The check kit build runs: a preview against exactly what the kit exports
    # (``bundle.contents()``) plus the bundled providers' own builds and
    # operations, pinned against those same exported Contracts -- never this
    # publisher instance's other local definitions. A Provider is never a kit
    # artifact (``kit add`` installs it before the definitions), so it is
    # seeded this way instead of read off the publisher's tree.
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
            owns=("osv.", "sbom.", "search.", "security.", "web."),
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
