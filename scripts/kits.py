"""Check and publish the kits in this repository.

    python scripts/kits.py check               # every kit reads, packs deterministically and
                                               # has an up-to-date generated reference
    python scripts/kits.py publish [--dry-run]  # push versions the registry lacks

A published version is immutable: if the registry already holds a kit's version
tag, its manifest digest must equal the one this repository builds, and a
different digest fails instead of overwriting. Publishing needs
CRUXIBLE_REGISTRY, CRUXIBLE_REGISTRY_USERNAME and CRUXIBLE_REGISTRY_PASSWORD.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

import httpx
from cruxible_client.artifacts import RegistryClient, pack_artifact, parse_reference
from cruxible_client.kits import KIT_ARTIFACT, read_kit_directory

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = os.environ.get("CRUXIBLE_KIT_NAMESPACE", "ghcr.io/cruxible-ai/kits")


def _kits() -> list[Path]:
    return sorted(path for path in (ROOT / "kits").iterdir() if path.is_dir())


def _reference_problems(directory: Path) -> list[str]:
    """A kit with ``source/reference.py`` generates its README sections and reference.md
    from its definitions; report where the committed files differ."""

    script = directory / "source" / "reference.py"
    if not script.is_file():
        return []
    spec = importlib.util.spec_from_file_location(f"{directory.name}_reference", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return list(module.check(directory))


def check() -> int:
    failures = 0
    for directory in _kits():
        try:
            bundle = read_kit_directory(directory)
            if bundle.manifest.kit_id != directory.name:
                raise ValueError(f"manifest names kit {bundle.manifest.kit_id}")
            first = pack_artifact(KIT_ARTIFACT, bundle).digest
            second = pack_artifact(KIT_ARTIFACT, read_kit_directory(directory)).digest
            if first != second:
                raise ValueError("packing is not deterministic")
            stale = _reference_problems(directory)
            if stale:
                raise ValueError("; ".join(stale))
        except Exception as error:  # noqa: BLE001 - report every kit, then fail
            failures += 1
            print(f"FAIL {directory.name}: {error}", file=sys.stderr)
            continue
        print(f"ok   {directory.name} {bundle.manifest.version} {first}")
    return 1 if failures else 0


def publish(*, dry_run: bool) -> int:
    failures = 0
    with RegistryClient() as registry:
        for directory in _kits():
            bundle = read_kit_directory(directory)
            image = pack_artifact(KIT_ARTIFACT, bundle)
            ref = parse_reference(f"{NAMESPACE}/{bundle.manifest.kit_id}:{bundle.manifest.version}")
            try:
                published = registry.pull(ref).digest
            except httpx.HTTPStatusError as error:
                if error.response.status_code != 404:
                    raise
                published = None
            if published == image.digest:
                print(f"have {ref}@{image.digest}")
                continue
            if published is not None:
                failures += 1
                print(
                    f"FAIL {ref} is already published as {published}; "
                    f"bump the version instead of changing it ({image.digest})",
                    file=sys.stderr,
                )
                continue
            if dry_run:
                print(f"would push {ref}@{image.digest}")
                continue
            print(f"push {ref.pinned(registry.push(image, ref))}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    publishing = commands.add_parser("publish")
    publishing.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.command == "check":
        return check()
    return publish(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
