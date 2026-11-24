"""Inspect a workspace and print the security kit commands that fit it.

    cruxible kit run security:init-plan
    cruxible kit run security:init-plan -- --workspace path/to/repo
    cruxible kit run security:init-plan -- --json

The kit registers it as the read-only script ``init-plan``. It reads the workspace
only: file names, the first bytes of candidate SBOM and SARIF files (to tell
CycloneDX, SPDX and SARIF apart) and ``.git/config`` (the ``origin`` remote, for
SARIF's ``repo``). It connects to no daemon, runs no program, makes no network call
and writes nothing; the commands it prints are for you to read and run.

The plan:

1. ``cruxible kit adopt security`` (the shared Lines and Runbooks);
2. one ``cruxible kit adopt security:sbom`` per SBOM found (CycloneDX or SPDX JSON),
   or, with none, the generator command for each ecosystem the workspace shows
   (lockfiles and manifests) and the ``kit adopt`` for the file it would write;
3. one ``cruxible kit adopt security:sarif`` per SARIF file found;
4. ``cruxible kit adopt security:schedule`` (skip it when CI runs the Runbooks);
5. approve, enable, run, and read: ``proposal approve``, ``line enable``,
   ``runbook preview`` / ``run``, ``next`` and ``kit run security:export-vex``.

Paths are relative to the workspace root: ``--workspace``, else the Git repository
holding the current directory, which must be the workspace the Cruxible instance
reads (``workspace.file`` reads paths relative to it).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

KIT = os.environ.get("CRUXIBLE_KIT_ID", "security")
#: The recipe parameter patterns (``kit adopt security --list``).
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,48}$")
PATH_PATTERN = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$")
REPO_PATTERN = re.compile(r"^[a-z0-9.-]+/[^/\s]+/[^/\s]+$")
#: Directories never searched: VCS, dependency and build trees, virtual environments.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".cruxible",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "target",
        "build",
        "dist",
        ".gradle",
        ".idea",
        "vendor",
    }
)
MAX_DEPTH = 4
MAX_ENTRIES = 20000
#: How much of a candidate file is read to recognize its format.
SNIFF_BYTES = 4096
#: An SBOM import reads at most 1 MiB.
SBOM_MAX_BYTES = 1024 * 1024

#: Ecosystem markers -> (label, generator command writing ``{out}``). The command
#: is printed, never run; each names a widely used CycloneDX generator.
GENERATORS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (
        ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml"),
        "Python",
        "cyclonedx-py environment --of JSON -o {out}  # in the project's virtual environment",
    ),
    (
        ("package-lock.json", "npm-shrinkwrap.json"),
        "npm",
        "npx --yes @cyclonedx/cyclonedx-npm --output-file {out}",
    ),
    (("yarn.lock", "pnpm-lock.yaml"), "Node.js", "syft dir:. -o cyclonedx-json={out}"),
    (("go.mod",), "Go", "cyclonedx-gomod mod -json -output {out}"),
    (("Cargo.lock",), "Rust", "cargo cyclonedx --format json  # writes <crate>.cdx.json"),
    (
        ("pom.xml",),
        "Maven",
        "mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json  "
        "# writes target/bom.json; copy it to {out}",
    ),
    (
        ("build.gradle", "build.gradle.kts"),
        "Gradle",
        "syft dir:. -o cyclonedx-json={out}  # or the CycloneDX Gradle plugin",
    ),
    (("Gemfile.lock",), "Ruby", "syft dir:. -o cyclonedx-json={out}"),
    (("composer.lock",), "PHP", "composer CycloneDX:make-sbom --output-format=JSON --output-file={out}"),
)
DOCKERFILES = ("Dockerfile", "Containerfile")


@dataclass
class Found:
    path: str
    format: str
    name: str


@dataclass
class Plan:
    workspace: str
    repo: str | None
    sboms: list[Found] = field(default_factory=list)
    sarifs: list[Found] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    generate: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


def workspace_root(start: Path) -> Path:
    """The Git repository holding ``start``, else ``start`` itself."""

    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return start


def walk(root: Path) -> Iterator[Path]:
    """Files under ``root`` to ``MAX_DEPTH``, skipping ``SKIP_DIRS`` and symbolic links,
    in a stable order; stops after ``MAX_ENTRIES`` entries."""

    seen = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name, reverse=True)
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > MAX_ENTRIES:
                return
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if depth + 1 < MAX_DEPTH and entry.name not in SKIP_DIRS:
                    stack.append((Path(entry.path), depth + 1))
            elif entry.is_file(follow_symlinks=False):
                yield Path(entry.path)


def sniff(path: Path) -> str | None:
    """``cyclonedx``, ``spdx`` or ``sarif`` from a file's first bytes, else ``None``."""

    try:
        with path.open("rb") as handle:
            head = handle.read(SNIFF_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None
    if not head.lstrip().startswith("{"):
        return None
    if re.search(r'"bomFormat"\s*:\s*"CycloneDX"', head):
        return "cyclonedx"
    if re.search(r'"spdxVersion"\s*:\s*"SPDX-2\.[23]"', head):
        return "spdx"
    if path.name.lower().endswith((".sarif", ".sarif.json")) or re.search(
        r'"\$schema"\s*:\s*"[^"]*sarif', head
    ):
        return "sarif"
    if '"runs"' in head and re.search(r'"version"\s*:\s*"2\.1\.0"', head):
        return "sarif"
    return None


def candidate(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".json", ".sarif"))


def suffix_name(relative: str, taken: set[str], fallback: str) -> str:
    """A recipe ``name`` from a file path: its stem without format suffixes, made to
    fit the pattern and unique among ``taken``."""

    stem = Path(relative).name.lower()
    for ending in (".sarif.json", ".cdx.json", ".spdx.json", ".sbom.json", ".json", ".sarif"):
        if stem.endswith(ending):
            stem = stem[: -len(ending)]
            break
    for noise in ("sbom", "bom", "cyclonedx", "spdx", "results", "report"):
        stem = re.sub(rf"(^|[-_.]){noise}($|[-_.])", r"\1\2", stem)
    base = re.sub(r"[^a-z0-9_-]+", "-", stem).strip("-_")
    if not base or not base[0].isalpha():
        base = f"{fallback}-{base}".strip("-") if base else fallback
    base = base[:40]
    name, n = base, 2
    while name in taken or not NAME_PATTERN.fullmatch(name):
        name = f"{base}-{n}"[:49]
        n += 1
    taken.add(name)
    return name


def origin_repo(root: Path) -> str | None:
    """``host/owner/repo`` from ``.git/config``'s ``origin`` URL, lowercase."""

    config = root / ".git" / "config"
    if not config.is_file():
        return None
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    section = re.search(r'\[remote "origin"\]([^\[]*)', text)
    if not section:
        return None
    url = re.search(r"^\s*url\s*=\s*(\S+)", section.group(1), re.MULTILINE)
    if not url:
        return None
    raw = url.group(1).strip()
    match = re.match(r"^(?:[a-z+]+://)?(?:[^@/]+@)?([^/:]+)[:/]+(.+?)(?:\.git)?/?$", raw)
    if not match:
        return None
    host, rest = match.group(1).lower(), match.group(2).lower()
    host = host.split(":", 1)[0]
    parts = [part for part in rest.split("/") if part]
    if len(parts) < 2:
        return None
    repo = f"{host}/{parts[-2]}/{parts[-1]}"
    return repo if REPO_PATTERN.fullmatch(repo) else None


def quote(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(token) for token in argv)


def adopt(recipe: str | None, **params: str) -> str:
    target = KIT if recipe is None else f"{KIT}:{recipe}"
    argv = ["cruxible", "kit", "adopt", target]
    for key, value in params.items():
        argv += ["--param", f"{key}={value}"]
    return quote([*argv, "--yes"])


def inspect(root: Path) -> Plan:
    plan = Plan(workspace=str(root), repo=origin_repo(root))
    names: set[str] = set()
    sarif_names: set[str] = set()
    markers: set[str] = set()
    for path in walk(root):
        relative = path.relative_to(root).as_posix()
        if path.name in DOCKERFILES or path.name.startswith("Dockerfile."):
            plan.containers.append(relative)
        if path.parent == root:
            markers.add(path.name)
        if not candidate(path):
            continue
        kind = sniff(path)
        if kind is None:
            continue
        if not PATH_PATTERN.fullmatch(relative):
            plan.skipped.append(f"{relative}: the path has characters a recipe path refuses")
            continue
        if kind in ("cyclonedx", "spdx"):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > SBOM_MAX_BYTES:
                plan.skipped.append(f"{relative}: {kind} SBOM over 1 MiB (the import's limit)")
                continue
            plan.sboms.append(Found(relative, kind, suffix_name(relative, names, "app")))
        else:
            plan.sarifs.append(Found(relative, kind, suffix_name(relative, sarif_names, "scan")))
    for files, label, command in GENERATORS:
        if markers.intersection(files):
            plan.ecosystems.append(label)
            if not plan.sboms:
                plan.generate.append(command.format(out="sbom.cdx.json"))
    if not plan.sboms and not plan.generate:
        plan.generate.append("syft dir:. -o cyclonedx-json=sbom.cdx.json")
    plan.commands = commands(plan)
    return plan


def commands(plan: Plan) -> list[str]:
    out = [adopt(None)]
    if plan.sboms:
        out += [adopt("sbom", name=item.name, path=item.path) for item in plan.sboms]
    else:
        out.append(adopt("sbom", name="app", path="sbom.cdx.json"))
    for container in plan.containers:
        out.append(
            "# container image: syft IMAGE -o cyclonedx-json=image.cdx.json, then "
            + adopt("sbom", name="image", path="image.cdx.json")
            + f"  # from {container}"
        )
        break
    repo = plan.repo or "github.com/OWNER/REPO"
    for item in plan.sarifs:
        out.append(adopt("sarif", name=item.name, path=item.path, repo=repo))
    out.append(adopt("schedule") + "  # skip when CI runs security.maintain")
    out += [
        "cruxible proposal list  # approve each pending proposal (a reviewer, when "
        "independent approval is required)",
        "cruxible proposal approve PROPOSAL_ID [PROPOSAL_ID ...] --yes",
        "cruxible line enable security.osv-unkeyed --runbook security.start",
        "cruxible runbook preview security.start",
        "cruxible runbook run security.start",
        "cruxible next",
        f"cruxible kit run {KIT}:export-vex -- --format openvex --out vex.openvex.json",
    ]
    return out


def render_text(plan: Plan) -> str:
    lines = [f"workspace: {plan.workspace}"]
    if plan.repo:
        lines.append(f"repo: {plan.repo}")
    if plan.ecosystems:
        lines.append(f"ecosystems: {', '.join(plan.ecosystems)}")
    for item in plan.sboms:
        lines.append(f"sbom: {item.path} ({item.format}) -> name {item.name}")
    for item in plan.sarifs:
        lines.append(f"sarif: {item.path} -> name {item.name}")
    for item in plan.containers:
        lines.append(f"container: {item}")
    for item in plan.skipped:
        lines.append(f"skipped: {item}")
    if plan.sarifs and not plan.repo:
        lines.append("note: no origin remote; replace github.com/OWNER/REPO in the sarif lines")
    if plan.generate:
        lines += ["", "# no SBOM found: generate one first (or point the sbom line at yours)"]
        lines += plan.generate
    lines += ["", "# plan"]
    lines += plan.commands
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="the workspace root to inspect (default: the Git repository holding the "
        "current directory)",
    )
    parser.add_argument("--json", action="store_true", help="print the plan as JSON")
    args = parser.parse_args(argv)
    if args.workspace is not None and not args.workspace.is_dir():
        print(f"init-plan: {args.workspace} is not a directory", file=sys.stderr)
        return 2
    root = args.workspace.resolve() if args.workspace is not None else workspace_root(Path.cwd())
    plan = inspect(root)
    if args.json:
        sys.stdout.write(json.dumps(asdict(plan), indent=1, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
