"""Inspect a workspace and print the security kit commands that fit it.

    cruxible kit run security:init-plan
    cruxible kit run security:init-plan -- --workspace path/to/repo
    cruxible kit run security:init-plan -- --json

The kit registers it as the read-only script ``init-plan``. It reads the workspace
only: file names, the first bytes of candidate SBOM and SARIF files (to tell
CycloneDX, SPDX and SARIF apart) and ``.git/config`` (the ``origin`` remote, for
SARIF's ``repo``). It connects to no daemon, runs no program, makes no network call
and writes nothing; the commands it prints are for you to read and run.

Every read is held beneath the workspace root: the root is opened once and each
file is opened component by component from held directory descriptors with
``O_NOFOLLOW``, so a symbolic link (``.git``, ``.git/config``, a directory or a
candidate file) is skipped or refused, never followed out of the workspace. Every
command argument is shell-quoted, and a file name shown in the text output is
escaped to one line (control characters as ``\\xNN``), so no file name can add a
line to what you paste.

The plan:

1. ``cruxible kit adopt security`` (the shared Lines and Runbooks), then its
   approval: under independent approval the reviewer approves it before the
   recipes that build on it (``security:schedule`` runs ``security.maintain``);
2. one ``cruxible kit adopt security:sbom`` per SBOM found (CycloneDX or SPDX JSON),
   or, with none, the generator command for each ecosystem the workspace shows
   (lockfiles and manifests) and the ``kit adopt`` for the file it writes: one
   ecosystem writes ``sbom.cdx.json`` (``name=app``), several write
   ``sbom-<ecosystem>.cdx.json`` each (``name=<ecosystem>``);
3. one ``cruxible kit adopt security:sarif`` per SARIF file found;
4. ``cruxible kit adopt security:schedule`` (skip it when CI runs the Runbooks),
   then the approval of the SBOM, SARIF and schedule proposals;
5. enable, run and read: ``line enable`` (``security.start``'s Lines and each SARIF
   scanner's attention Line), ``line run`` (each SARIF import), ``runbook preview``
   / ``run``, ``next`` and ``kit run security:export-vex``.

Paths are relative to the workspace root: ``--workspace``, else the Git repository
holding the current directory, which must be the workspace the Cruxible instance
reads (``workspace.file`` reads paths relative to it).
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shlex
import stat
import sys
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

KIT = os.environ.get("CRUXIBLE_KIT_ID", "security")
#: The recipe parameter patterns (``kit adopt security --list``).
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,48}$")
#: ``relative_path``: segments joined by ``/``, never ``.`` or ``..``, no leading ``/``.
_SEGMENT = r"(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\.[A-Za-z0-9_-][A-Za-z0-9._-]*)"
PATH_PATTERN = re.compile(f"^{_SEGMENT}(?:/{_SEGMENT})*$")
#: The import Procedures' ``relative_path`` length cap.
PATH_MAX = 256
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

#: Ecosystem markers -> (label, slug, generator command). The command is printed,
#: never run; each names a widely used CycloneDX generator and writes exactly
#: ``{out}`` (``{stem}`` is ``{out}`` without ``.json``, for cargo-cyclonedx, which
#: appends it). With several ecosystems each writes ``sbom-<slug>.cdx.json``; two
#: markers sharing a slug (npm and Yarn lockfiles) generate once.
GENERATORS: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (
        ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml"),
        "Python",
        "python",
        "cyclonedx-py environment --of JSON -o {out}  # in the project's virtual environment",
    ),
    (
        ("package-lock.json", "npm-shrinkwrap.json"),
        "npm",
        "node",
        "npx --yes @cyclonedx/cyclonedx-npm --output-file {out}",
    ),
    (("yarn.lock", "pnpm-lock.yaml"), "Node.js", "node", "syft dir:. -o cyclonedx-json={out}"),
    (("go.mod",), "Go", "go", "cyclonedx-gomod mod -json -output {out}"),
    (
        ("Cargo.lock",),
        "Rust",
        "rust",
        "cargo cyclonedx --format json --override-filename {stem}  # writes {out}",
    ),
    (
        ("pom.xml",),
        "Maven",
        "maven",
        "mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json "
        "&& cp target/bom.json {out}",
    ),
    (
        ("build.gradle", "build.gradle.kts"),
        "Gradle",
        "gradle",
        "syft dir:. -o cyclonedx-json={out}  # or the CycloneDX Gradle plugin",
    ),
    (("Gemfile.lock",), "Ruby", "ruby", "syft dir:. -o cyclonedx-json={out}"),
    (
        ("composer.lock",),
        "PHP",
        "php",
        "composer CycloneDX:make-sbom --output-format=JSON --output-file={out}",
    ),
)
#: The generator when no ecosystem marker is found.
FALLBACK_GENERATOR = "syft dir:. -o cyclonedx-json={out}"
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
    #: With no SBOM found: the file each generator command writes, as it is adopted.
    generated: list[Found] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


def display(text: str) -> str:
    """``text`` as one safe line: a backslash doubled, and every control, format,
    surrogate or line/paragraph separator character escaped (``\\n``, ``\\x1b``,
    ``\\u202e``), so a file name can never break a line or reorder what is shown."""

    out: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char == "\\":
            out.append("\\\\")
        elif category[0] == "C" or category in ("Zl", "Zp"):
            code = ord(char)
            if code < 0x100:
                out.append(f"\\x{code:02x}")
            elif code < 0x10000:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\U{code:08x}")
        else:
            out.append(char)
    return "".join(out)


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class Refused(OSError):
    """A path beneath the workspace that is (or sits under) a symbolic link, or is not
    a regular file."""


class Workspace:
    """The workspace root held open by descriptor; every read walks beneath it.

    The root is opened once (where the caller's name resolves). Each later path is
    opened component by component from held directory descriptors with
    ``O_NOFOLLOW`` (``O_DIRECTORY`` for each parent), and a file's bytes and size
    come from its own opened descriptor: a symbolic link anywhere beneath the root
    is refused, never followed, and no pathname is resolved twice.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self._fd = os.open(root, _DIRECTORY)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @staticmethod
    def _open(name: str, flags: int, directory: int, relative: str) -> int:
        try:
            return os.open(name, flags, dir_fd=directory)
        except OSError as exc:
            if exc.errno == errno.ELOOP or (
                exc.errno == errno.ENOTDIR
                and stat.S_ISLNK(os.lstat(name, dir_fd=directory).st_mode)
            ):
                raise Refused(exc.errno, f"{relative} is (or sits under) a symbolic link") from exc
            raise

    def _directory(self, parts: Sequence[str], relative: str) -> int:
        current = os.dup(self._fd)
        for part in parts:
            try:
                following = self._open(part, _DIRECTORY, current, relative)
            finally:
                os.close(current)
            current = following
        return current

    def read(self, relative: str, max_bytes: int) -> tuple[bytes, int]:
        """The first ``max_bytes`` of the regular file at ``relative`` and its size."""

        parts = relative.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise Refused(errno.EINVAL, f"{relative} is not a relative path beneath the root")
        directory = self._directory(parts[:-1], relative)
        try:
            handle = self._open(parts[-1], _FILE, directory, relative)
        finally:
            os.close(directory)
        try:
            status = os.fstat(handle)
            if not stat.S_ISREG(status.st_mode):
                raise Refused(errno.EINVAL, f"{relative} is not a regular file")
            chunks: list[bytes] = []
            remaining = max_bytes
            while remaining > 0:
                chunk = os.read(handle, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks), status.st_size
        finally:
            os.close(handle)

    def walk(self) -> Iterator[str]:
        """Relative paths of the files beneath the root to ``MAX_DEPTH``, skipping
        ``SKIP_DIRS`` and symbolic links, in a stable order; stops after
        ``MAX_ENTRIES`` entries. Each directory is listed through its own descriptor,
        opened from its parent's with ``O_NOFOLLOW``."""

        seen = 0

        def listing(directory: int, prefix: str, depth: int) -> Iterator[str]:
            nonlocal seen
            try:
                with os.scandir(directory) as entries:
                    listed = sorted(entries, key=lambda entry: entry.name)
            except OSError:
                return
            for entry in listed:
                seen += 1
                if seen > MAX_ENTRIES:
                    return
                if entry.is_symlink():
                    continue
                relative = f"{prefix}{entry.name}"
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 >= MAX_DEPTH or entry.name in SKIP_DIRS:
                        continue
                    try:
                        child = self._open(entry.name, _DIRECTORY, directory, relative)
                    except OSError:
                        continue
                    try:
                        yield from listing(child, f"{relative}/", depth + 1)
                    finally:
                        os.close(child)
                elif entry.is_file(follow_symlinks=False):
                    yield relative

        root = os.dup(self._fd)
        try:
            yield from listing(root, "", 0)
        finally:
            os.close(root)


def workspace_root(start: Path) -> Path:
    """The Git repository holding ``start`` (the nearest directory with a ``.git``
    entry, which is not followed), else ``start`` itself."""

    start = start.resolve()
    for candidate in (start, *start.parents):
        try:
            os.lstat(candidate / ".git")
        except OSError:
            continue
        return candidate
    return start


def sniff_head(head_bytes: bytes, relative: str) -> str | None:
    """``cyclonedx``, ``spdx`` or ``sarif`` from a file's first bytes, else ``None``."""

    head = head_bytes.decode("utf-8", errors="replace")
    if not head.lstrip().startswith("{"):
        return None
    if re.search(r'"bomFormat"\s*:\s*"CycloneDX"', head):
        return "cyclonedx"
    if re.search(r'"spdxVersion"\s*:\s*"SPDX-2\.[23]"', head):
        return "spdx"
    if relative.lower().endswith((".sarif", ".sarif.json")) or re.search(
        r'"\$schema"\s*:\s*"[^"]*sarif', head
    ):
        return "sarif"
    if '"runs"' in head and re.search(r'"version"\s*:\s*"2\.1\.0"', head):
        return "sarif"
    return None


def candidate(relative: str) -> bool:
    return relative.rsplit("/", 1)[-1].lower().endswith((".json", ".sarif"))


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


def origin_repo(workspace: Workspace) -> str | None:
    """``host/owner/repo`` from ``.git/config``'s ``origin`` URL, lowercase; ``None``
    when ``.git`` or its ``config`` is missing, a symbolic link or not a regular file."""

    try:
        data, _size = workspace.read(".git/config", SBOM_MAX_BYTES)
    except OSError:
        return None
    text = data.decode("utf-8", errors="replace")
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
    with Workspace(root) as workspace:
        return _inspect(root, workspace)


def _inspect(root: Path, workspace: Workspace) -> Plan:
    plan = Plan(workspace=str(root), repo=origin_repo(workspace))
    names: set[str] = set()
    sarif_names: set[str] = set()
    markers: set[str] = set()
    for relative in workspace.walk():
        name = relative.rsplit("/", 1)[-1]
        if name in DOCKERFILES or name.startswith("Dockerfile."):
            plan.containers.append(relative)
        if "/" not in relative:
            markers.add(name)
        if not candidate(relative):
            continue
        try:
            head, size = workspace.read(relative, SNIFF_BYTES)
        except OSError:
            continue
        kind = sniff_head(head, relative)
        if kind is None:
            continue
        if len(relative) > PATH_MAX or not PATH_PATTERN.fullmatch(relative):
            plan.skipped.append(
                f"{relative}: the path has characters (or a length) a recipe "
                "relative_path refuses"
            )
            continue
        if kind in ("cyclonedx", "spdx"):
            if size > SBOM_MAX_BYTES:
                plan.skipped.append(f"{relative}: {kind} SBOM over 1 MiB (the import's limit)")
                continue
            plan.sboms.append(Found(relative, kind, suffix_name(relative, names, "app")))
        else:
            plan.sarifs.append(Found(relative, kind, suffix_name(relative, sarif_names, "scan")))
    detected: list[tuple[str, str]] = []
    slugs: set[str] = set()
    for files, label, slug, command in GENERATORS:
        if markers.intersection(files):
            plan.ecosystems.append(label)
            if slug not in slugs:
                slugs.add(slug)
                detected.append((slug, command))
    if not plan.sboms:
        if not detected:
            detected = [("app", FALLBACK_GENERATOR)]
        for slug, command in detected:
            name, out = ("app", "sbom.cdx.json") if len(detected) == 1 else (
                slug,
                f"sbom-{slug}.cdx.json",
            )
            stem = out.removesuffix(".json")
            plan.generate.append(command.format(out=shlex.quote(out), stem=shlex.quote(stem)))
            plan.generated.append(Found(out, "cyclonedx", name))
    plan.commands = commands(plan)
    return plan


def approve(what: str) -> list[str]:
    """List the open proposals, then approve: under independent approval the reviewer
    approves; under self-approval each adoption has already landed."""

    return [
        "cruxible proposal list --status open",
        "cruxible proposal approve PROPOSAL_ID [PROPOSAL_ID ...] --yes  # " + what
        + ": as the reviewer when independent approval is required "
        "(CRUXIBLE_PRINCIPAL_ID=reviewer); nothing to approve under self-approval",
    ]


def commands(plan: Plan) -> list[str]:
    out = [adopt(None)]
    # The base adoption first: the schedule recipe's Trigger runs security.maintain,
    # which exists only once the reviewer approves it.
    out += approve("the security adoption, before the recipes below")
    for item in plan.sboms or plan.generated:
        out.append(adopt("sbom", name=item.name, relative_path=item.path))
    if plan.containers:
        # No discovered file name goes into a command line, even as a comment.
        out.append(
            "# container image (Dockerfile listed above): syft IMAGE -o "
            "cyclonedx-json=image.cdx.json, then "
            + adopt("sbom", name="image", relative_path="image.cdx.json")
        )
    repo = plan.repo or "github.com/OWNER/REPO"
    for item in plan.sarifs:
        out.append(adopt("sarif", name=item.name, relative_path=item.path, repo=repo))
    out.append(adopt("schedule") + "  # skip when CI runs security.maintain")
    out += approve(
        "the SBOM, SARIF and schedule adoptions" if plan.sarifs else "the SBOM and schedule adoptions"
    )
    out.append("cruxible line enable security.osv-unkeyed --runbook security.start")
    for item in plan.sarifs:
        # The attention Line first, so its landing Trigger admits the import's results.
        out.append(quote(["cruxible", "line", "enable", f"security.sarif-attention.{item.name}"]))
        out.append(quote(["cruxible", "line", "run", f"security.sarif-import.{item.name}"]))
    out += [
        "cruxible runbook preview security.start",
        "cruxible runbook run security.start",
        "cruxible next",
        f"cruxible kit run {KIT}:export-vex -- --format openvex -o vex.openvex.json",
    ]
    return out


def render_text(plan: Plan) -> str:
    # Every discovered name is shown through display(): one line each, whatever it holds.
    lines = [f"workspace: {display(plan.workspace)}"]
    if plan.repo:
        lines.append(f"repo: {display(plan.repo)}")
    if plan.ecosystems:
        lines.append(f"ecosystems: {', '.join(plan.ecosystems)}")
    for item in plan.sboms:
        lines.append(f"sbom: {display(item.path)} ({item.format}) -> name {item.name}")
    for item in plan.sarifs:
        lines.append(f"sarif: {display(item.path)} -> name {item.name}")
    for item in plan.containers:
        lines.append(f"container: {display(item)}")
    for item in plan.skipped:
        lines.append(f"skipped: {display(item)}")
    if plan.sarifs and not plan.repo:
        lines.append("note: no origin remote; replace github.com/OWNER/REPO in the sarif lines")
    if plan.generate:
        lines += ["", "# no SBOM found: generate one first (or point the sbom lines at yours)"]
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
