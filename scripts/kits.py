"""Check and publish the kits in this repository.

    python scripts/kits.py check               # every kit reads, packs deterministically, lists
                                               # its inert files, its skills' relative links
                                               # resolve, and its generated reference is current
    python scripts/kits.py files               # rewrite each manifest's inert-file list
    python scripts/kits.py publish [--dry-run]  # push versions the registry lacks

A kit's inert files are its top-level Markdown (README.md, reference.md), everything
under ``examples/``, every agent skill under ``skills/<name>/`` and the automation
template its manifest names (``automation_template``, D-R48). They travel in the
bundle for the kit's reader (``cruxible kit pull`` / ``kit docs``) but stay out of the
release's content digest, so a docs fix keeps every definition digest; the image digest
still changes, so a published version needs a patch bump for one.

A published version is immutable: if the registry already holds a kit's version
tag, its manifest digest must equal the one this repository builds, and a
different digest fails instead of overwriting. Publishing needs
CRUXIBLE_REGISTRY, CRUXIBLE_REGISTRY_USERNAME and CRUXIBLE_REGISTRY_PASSWORD.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import httpx
from cruxible_client.artifacts import RegistryClient, pack_artifact, parse_reference
from cruxible_client.contracts.canonical import pretty_canonical_bytes
from cruxible_client.contracts.kits import KIT_MANIFEST_FILE, KitFile, kit_file_entry
from cruxible_client.kits import KIT_ARTIFACT, kit_skill_directory_name, read_kit_directory

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


_INERT_DIRECTORIES = ("examples", "skills")
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _automation_template(directory: Path) -> str | None:
    """The automation template the manifest names (D-R48), a kit file at that path."""

    manifest = directory / KIT_MANIFEST_FILE
    if not manifest.is_file():
        return None
    named = json.loads(manifest.read_bytes()).get("automation_template")
    return named if isinstance(named, str) else None


def _inert_paths(directory: Path) -> list[str]:
    """The kit's inert files: top-level Markdown, ``examples/``, ``skills/`` and the
    automation template the manifest names."""

    paths = [path.name for path in directory.glob("*.md") if path.is_file()]
    template = _automation_template(directory)
    if template is not None:
        if not (directory / template).is_file():
            raise ValueError(f"the manifest names automation template {template}, which is missing")
        paths.append(template)
    for name in _INERT_DIRECTORIES:
        root = directory / name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            relative = path.relative_to(directory)
            if any(part.startswith(".") or part == "__pycache__" for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"{relative.as_posix()} is a symbolic link")
            if path.is_file():
                paths.append(relative.as_posix())
    return sorted(set(paths))


def _inert_files(directory: Path) -> tuple[KitFile, ...]:
    return tuple(
        kit_file_entry(path, (directory / path).read_bytes()) for path in _inert_paths(directory)
    )


def _skill_link_problems(directory: Path) -> list[str]:
    """Relative links in a skill must resolve where ``kit docs --skills`` installs it:
    each skill becomes its own ``<kit>-<skill>/`` directory beside the others, so a
    link may reach its own skill or a sibling whose installed name is its own, never
    the kit's README or reference (name those instead)."""

    skills = (directory / "skills").resolve()
    problems = []
    for path in sorted(skills.rglob("*.md")) if skills.is_dir() else ():
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            resolved = (path.parent / target.partition("#")[0]).resolve()
            where = path.relative_to(skills.parent).as_posix()
            if not resolved.is_relative_to(skills) or resolved == skills:
                problems.append(f"{where} links outside the kit's skills: {target}")
                continue
            own = path.relative_to(skills).parts[0]
            linked = resolved.relative_to(skills).parts[0]
            if linked != own and kit_skill_directory_name(directory.name, linked) != linked:
                problems.append(
                    f"{where} links to skill {linked}, which installs as "
                    f"{kit_skill_directory_name(directory.name, linked)}: {target}"
                )
            elif not resolved.exists():
                problems.append(f"{where} links to a missing file: {target}")
    return problems


def write_files(directory: Path) -> bool:
    """Rewrite one manifest's inert-file list from the directory; True when it changed."""

    manifest_path = directory / KIT_MANIFEST_FILE
    manifest = json.loads(manifest_path.read_bytes())
    files = [item.model_dump(mode="json") for item in _inert_files(directory)]
    if files:
        manifest["files"] = files
    else:
        manifest.pop("files", None)
    content = pretty_canonical_bytes(manifest)
    if content == manifest_path.read_bytes():
        return False
    manifest_path.write_bytes(content)
    return True


def files() -> int:
    for directory in _kits():
        changed = write_files(directory)
        print(f"{'wrote' if changed else 'same '} {directory.name} {KIT_MANIFEST_FILE}")
    return 0


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
            if bundle.manifest.files != _inert_files(directory):
                raise ValueError("the manifest's inert files are stale: run scripts/kits.py files")
            links = _skill_link_problems(directory)
            if links:
                raise ValueError("; ".join(links))
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
    commands.add_parser("files")
    publishing = commands.add_parser("publish")
    publishing.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.command == "check":
        return check()
    if args.command == "files":
        return files()
    return publish(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
