"""Build the security kit (dependency + audit loops) for Cruxible 0.5 through the public CLI.

    python source/build_release.py NEW_SCRATCH --providers-checkout PROVIDERS \
        [--published-wheels DIR]

The kit's own providers (OSV, SARIF) build offline from their sources and frozen
locks and are bundled in the kit with the published provider runtime wheel. The
general-purpose web provider is a published dependency: the kit names its
published build (delivery ``index``) and carries none of its files, and ``kit
add`` installs it by name from the consumer's provider index. Both published
wheels are fetched from PyPI (or read from ``--published-wheels``) and must match
the sha256 recorded here and the reviewed providers checkout byte for byte.
Provider installation may download the registry dependencies pinned by the
locks. No tests or private accept-tree helpers are used. A fresh publisher (which
holds the base kit from ``init``) installs the three provider builds, each
carrying its own shapes, then accepts the definitions and guidance; production
kit build validates the unchanged template against that exported closure, leaves
out every definition the base kit owns and records ``requires: base``. Only a
successful build replaces the committed release.

The release carries both loops: the dependency loop (SBOM, OSV, KEV, EPSS and the
dependency guidance) and the audit extension (code findings and coverage units,
the SARIF import Procedures with their provider, the audit Queries and the
hunter, verifier and coverage guidance). The reference pages under ``reference/``
ship as plain kit files.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parent
KIT = SOURCE.parent
PROVIDERS = SOURCE / "providers"
RELEASE = "1.3.0"  # Unpublished kit version; targets Cruxible 0.5.
#: The reviewed cruxible-providers commit: the published runtime and web wheels were
#: built from it, and the vendored web source (``providers/cruxible-provider-web``)
#: is its copy.
PROVIDERS_COMMIT = "b3fa37a669e60033a1591c4c886b6db6ad44ff21"
PACKAGES = ("security-osv-provider", "cruxible-provider-web", "security-sarif-provider")
RUNTIME = "cruxible-provider-runtime"
#: The published wheels the release names: version and the sha256 PyPI serves. The
#: kit's own providers bundle the runtime wheel; the web provider is a published
#: dependency the kit names by these bytes (never a local rebuild, whose bytes differ).
PUBLISHED = {
    RUNTIME: ("0.5.0", "356e276998f1daff0dc3479ffd57019ad3146f11692a7639de2d357b852acbc3"),
    "cruxible-provider-web": (
        "0.7.0",
        "fa866f39e2b191c8363f0866c2586f92b521d0c17819db8612305c80a50e49f5",
    ),
}
#: Providers the kit names as published dependencies (``kit build --default-provider``),
#: each with the sha256 of the lock its published wheel embeds (the vendored
#: ``uv.lock`` is the same bytes): kit add installs each by name at exactly its
#: version from the consumer's provider index.
DEFAULT_PROVIDERS = {
    "cruxible-provider-web": "bf9ccb3fe9acaa9a4652d885fcc2b649f543958c6dfc1bd2418e8c5674870f83",
}
#: Where each published wheel's package files are reviewed: its source tree.
PUBLISHED_SOURCES = {
    RUNTIME: "packages/cruxible-provider-runtime/src",
    "cruxible-provider-web": "packages/cruxible-provider-web/src",
}
#: The operations each bundled provider must install for the kit's Procedures.
REQUIRED = {
    "security-osv-provider": {"sbom.components", "osv.query", "osv.match"},
    "cruxible-provider-web": {"web.fetch", "web.fetch.pages"},
    "security-sarif-provider": {"sarif.findings"},
}
#: The kit this release requires: kit build leaves out what it owns (web., workspace.).
REQUIRES = {"base": "1.0.0"}
sys.path.insert(0, str(SOURCE / "pilot"))
sys.path.insert(0, str(PROVIDERS))

import build_registrations  # noqa: E402
import capabilities  # noqa: E402
import definitions as kit  # noqa: E402
import findings  # noqa: E402
import install  # noqa: E402
import template  # noqa: E402


class Session:
    """One isolated CLI workspace, daemon, identity and command log."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.state = self.root / "state"
        self.socket = self.root / "d.sock"
        if len(os.fsencode(self.socket)) >= 104:
            raise ValueError("Choose a shorter scratch path for the Unix socket")
        home = self.root / "home"
        home.mkdir()
        self.env = {
            k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")
        }
        self.env.update(
            UV_CACHE_DIR=os.environ.get("UV_CACHE_DIR", str(Path.home() / ".cache/uv")),
            HOME=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            XDG_CACHE_HOME=str(home / ".cache"),
            CRUXIBLE_STATE_ROOT=str(self.state),
            CRUXIBLE_SERVER_SOCKET=str(self.socket),
            PYTHONDONTWRITEBYTECODE="1",
            SOURCE_DATE_EPOCH="1794009600",
            GIT_AUTHOR_NAME="kit-build",
            GIT_AUTHOR_EMAIL="kit-build@example.invalid",
            GIT_COMMITTER_NAME="kit-build",
            GIT_COMMITTER_EMAIL="kit-build@example.invalid",
        )
        self.binary = os.environ.get(
            "CRUXIBLE_BIN", str(Path(sys.executable).with_name("cruxible"))
        )
        self.daemon: subprocess.Popen[bytes] | None = None

    def command(self, *args: str, check: bool = True) -> Any:
        done = subprocess.run(
            [self.binary, *args],
            cwd=self.workspace,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=900,
        )
        with (self.root / "commands.jsonl").open("a") as log:
            log.write(
                json.dumps(
                    {
                        "args": args,
                        "exit": done.returncode,
                        "stdout": done.stdout,
                        "stderr": done.stderr,
                    }
                )
                + "\n"
            )
        if check and done.returncode:
            raise RuntimeError(
                f"cruxible {' '.join(args)}:\n{done.stdout}{done.stderr}"
            )
        try:
            return json.loads(done.stdout)
        except json.JSONDecodeError:
            return done.stdout

    def start(self) -> None:
        subprocess.run(
            ["git", "init", "-q", "-b", "main"],
            cwd=self.workspace,
            env=self.env,
            check=True,
        )
        config = self.state / "daemon/provider-runtime.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "provider_index_urls": [
                        "https://pypi.org/simple",
                        "https://files.pythonhosted.org/",
                    ]
                }
            )
        )
        with (self.root / "daemon.log").open("wb") as log:
            self.daemon = subprocess.Popen(
                [
                    self.binary,
                    "server",
                    "start",
                    "--socket",
                    str(self.socket),
                    "--state-root",
                    str(self.state),
                ],
                env=self.env,
                cwd=self.workspace,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        for _ in range(120):
            if self.daemon.poll() is not None:
                raise RuntimeError(f"Daemon exited: read {self.root / 'daemon.log'}")
            if self.socket.exists():
                self.command("server", "status", "--json")
                return
            time.sleep(0.25)
        raise TimeoutError("Scratch daemon did not start")

    def stop(self) -> None:
        if self.daemon is None or self.daemon.poll() is not None:
            return
        try:
            self.command(
                "server",
                "stop",
                "--state-root",
                str(self.state),
                "--timeout",
                "30",
                "--json",
            )
        finally:
            try:
                self.daemon.wait(timeout=35)
            except subprocess.TimeoutExpired:
                self.daemon.terminate()
                self.daemon.wait(timeout=30)

    def initialize(self) -> Any:
        return self.command(
            "init",
            "--principal-id",
            "owner",
            "--key-dir",
            str(self.root / "keys/owner"),
            "--reviewer-key-dir",
            str(self.root / "keys/reviewer"),
            "--workspace",
            str(self.workspace),
            "--json",
        )

    def submit(self, name: str, payload: dict[str, Any]) -> Any:
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1) + "\n")
        result = self.command("authoring", "submit", str(path), "--json")
        if result.get("outcome", {}).get("status") != "landed":
            raise RuntimeError(f"{name} did not land: {result}")
        return result


def check_providers_checkout(checkout: Path) -> None:
    """Refuse a providers checkout other than the recorded commit, or a vendored web
    source that is not its copy."""
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if head != PROVIDERS_COMMIT:
        raise RuntimeError(
            f"{checkout} is at {head}, not the recorded providers commit {PROVIDERS_COMMIT}"
        )
    dirty = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--", "packages"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if dirty:
        raise RuntimeError(f"{checkout} has uncommitted package changes:\n{dirty}")
    for name in ("src", "pyproject.toml", "uv.lock"):
        upstream = checkout / "packages/cruxible-provider-web" / name
        vendored = PROVIDERS / "cruxible-provider-web" / name
        if _files(upstream) != _files(vendored):
            raise RuntimeError(
                f"{vendored} is not a copy of {upstream} at {PROVIDERS_COMMIT}"
            )


def _files(root: Path) -> dict[str, bytes]:
    """A file's bytes, or every file under a directory by relative path."""

    if root.is_file():
        return {root.name: root.read_bytes()}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def published_wheel(package: str, root: Path, given: Path | None, checkout: Path) -> Path:
    """The published wheel of ``package`` at its recorded version, verified.

    Read from ``given`` when named, otherwise downloaded from PyPI into ``root``.
    Refuses unless its sha256 is the recorded one and its package files are the
    reviewed checkout's source byte for byte.
    """

    version, sha256 = PUBLISHED[package]
    filename = f"{package.replace('-', '_')}-{version}-py3-none-any.whl"
    if given is not None:
        path = given / filename
    else:
        path = root / filename
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{package}/{version}/json", timeout=60
        ) as response:
            urls = json.load(response)["urls"]
        url = next(item["url"] for item in urls if item["filename"] == filename)
        with urllib.request.urlopen(url, timeout=300) as response:
            path.write_bytes(response.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != sha256:
        raise RuntimeError(f"{path} has sha256 {digest}, not the published {sha256}")
    with zipfile.ZipFile(path) as wheel:
        packaged = {
            name: wheel.read(name)
            for name in wheel.namelist()
            if ".dist-info/" not in name and not name.endswith("/")
        }
    if packaged != _files(checkout / PUBLISHED_SOURCES[package]):
        raise RuntimeError(f"{filename} is not the source at {PROVIDERS_COMMIT}")
    return path


def embedded_lock(wheel: Path) -> bytes:
    """The ``uv.lock`` a published provider wheel embeds."""

    with zipfile.ZipFile(wheel) as archive:
        (name,) = [
            item
            for item in archive.namelist()
            if item.endswith(".dist-info/extra_metadata/uv.lock")
        ]
        return archive.read(name)


def check_registrations() -> None:
    """Refuse a kit provider registration that is not the one the kit's definitions render."""
    stale = [
        package
        for package in build_registrations.PACKAGES
        if not build_registrations.write(package, check=True)
    ]
    if stale:
        raise RuntimeError(
            f"stale registration.json in {stale}: run source/providers/build_registrations.py"
        )


def build_providers(
    root: Path, checkout: Path, env: dict[str, str], given: Path | None
) -> tuple[list[Path], Path]:
    """Lay out each provider package in scratch, never modifying the checkout.

    The kit's own providers build from their exact locked sources; the web
    provider's ``dist/`` holds the published wheel. Returns the package
    directories and the published runtime wheel they install with.
    """
    check_providers_checkout(checkout)
    check_registrations()
    root.mkdir()
    published = root / "published"
    published.mkdir()
    dependency = published_wheel(RUNTIME, published, given, checkout)
    # The runtime source sits where the locks name it by path, for `uv lock --check`.
    shutil.copytree(
        checkout / "packages/cruxible-provider-runtime",
        root / RUNTIME,
        ignore=shutil.ignore_patterns("dist", ".venv", "__pycache__"),
    )

    def build(project: Path) -> Path:
        subprocess.run(
            [
                "uv",
                "build",
                "--wheel",
                "--offline",
                "--out-dir",
                str(project / "dist"),
                str(project),
            ],
            env=env,
            check=True,
        )
        return next((project / "dist").glob("*.whl"))

    projects = []
    for name in PACKAGES:
        project = root / name
        shutil.copytree(
            PROVIDERS / name,
            project,
            ignore=shutil.ignore_patterns("dist", ".venv", "__pycache__"),
        )
        subprocess.run(
            ["uv", "lock", "--check", "--offline"], cwd=project, env=env, check=True
        )
        if name in DEFAULT_PROVIDERS:
            # The published build: the kit records its wheel and the lock it embeds
            # and carries neither. The runtime wheel beside it resolves its closure,
            # so kit build's automation-template check seeds this build (the
            # template binds web operations by provider name); a consumer gets the
            # runtime from its own index.
            (project / "dist").mkdir()
            shutil.copyfile(dependency, project / "dist" / dependency.name)
            wheel = published_wheel(name, project / "dist", given, checkout)
            lock = (project / "uv.lock").read_bytes()
            version = tomllib.loads((project / "pyproject.toml").read_text())["project"][
                "version"
            ]
            if version != PUBLISHED[name][0]:
                raise RuntimeError(f"{name} source is {version}, not {PUBLISHED[name][0]}")
            if (
                embedded_lock(wheel) != lock
                or hashlib.sha256(lock).hexdigest() != DEFAULT_PROVIDERS[name]
            ):
                raise RuntimeError(f"{wheel.name} does not embed the vendored uv.lock")
        else:
            build(project)
            shutil.copyfile(dependency, project / "dist" / dependency.name)
        projects.append(project)
    return projects, dependency


def build_release(
    session: Session, projects: list[Path], dependency: Path, out: Path
) -> None:
    session.initialize()
    installed = session.command("kit", "status", "--offline", "--json")
    held = {item["kit_id"]: item["version"] for item in installed.get("kits", ())}
    for kit_id, version in REQUIRES.items():
        if held.get(kit_id) != version:
            raise RuntimeError(f"the publisher holds {kit_id} {held.get(kit_id)}, not {version}")
    for project in projects:
        # The published runtime wheel is each package's path dependency.
        (wheel,) = [
            p
            for p in (project / "dist").glob("*.whl")
            if not p.name.startswith("cruxible_provider_runtime-")
        ]
        installed = session.command(
            "provider",
            "install",
            str(wheel),
            "--lock",
            str(project / "uv.lock"),
            "--dependency",
            str(dependency),
            "--control-domain",
            project.name,
            "--commit",
            "--json",
        )
        required = REQUIRED[project.name]
        ready = {
            row["operation"] for row in installed["operations"] if row["installed"]
        }
        if not installed.get("registered") or not required <= ready:
            raise RuntimeError(f"Provider not installed: {installed}")
    # Kinds first, without their layouts: a layout pins row Contracts, and a row may
    # name a ClaimType whose evidence rules name the kind. The layouts follow the
    # vocabulary, each a successor that only adds the layout.
    kinds, layouts = kit.staged_capture_kinds(
        {**kit.capture_kinds(), **findings.capture_kinds()}
    )

    def propose_kinds(stage: str, records: dict[str, Any]) -> None:
        for name, record in records.items():
            path = session.root / f"{stage}.{name}.json"
            path.write_text(json.dumps(record, indent=1) + "\n")
            session.command(
                "capture-contract", "propose", "--input", str(path), "--commit", "--json"
            )

    propose_kinds("capture-kind", kinds)
    session.submit("vocabulary", kit.vocabulary())
    session.submit("capabilities", capabilities.change_set())
    session.submit("audit-vocabulary", findings.vocabulary())
    propose_kinds("capture-layout", layouts)
    session.submit("procedures", kit.procedures())
    session.submit("audit-procedures", findings.procedures())

    def store(path: Path) -> str:
        return str(session.command("body", "store", str(path), "--json")["digest"])

    for document in install.guidance_documents(
        store, names=(*install.DEPENDENCY_GUIDANCE, *install.GUIDANCE), references=False
    ):
        path = session.root / "guidance.json"
        path.write_text(json.dumps(document, indent=1) + "\n")
        result = session.command(
            "document",
            "propose",
            "--envelope",
            str(path),
            "--name",
            document["identity"].removeprefix("document:"),
            "--json",
        )
        if result.get("outcome", {}).get("status") != "landed":
            raise RuntimeError(f"Guidance did not land: {result}")
    if template.TEMPLATE.read_text() != template.render():
        raise RuntimeError("automation.json is stale: run source/pilot/template.py")
    args = [
        "kit",
        "build",
        "--id",
        "security",
        "--version",
        RELEASE,
        "--owns",
        "security.",
        # The deployment anchor it.asset (pilot/assets.py): held here until an IT asset
        # kit owns the it. prefix.
        "--owns",
        "it.",
        "--automation-template",
        str(template.TEMPLATE),
        "--out",
        str(out),
    ]
    for project in projects:
        option = "--default-provider" if project.name in DEFAULT_PROVIDERS else "--provider"
        args.extend((option, str(project)))
    session.command(*args, "--json")
    built = json.loads((out / "cruxible-kit.json").read_bytes())
    requires = {item["kit_id"]: item["min_version"] for item in built.get("requires", ())}
    if requires != REQUIRES:
        raise RuntimeError(f"kit build recorded requires {requires}, not {REQUIRES}")


def refresh_files() -> None:
    spec = importlib.util.spec_from_file_location(
        "kit_files", KIT.parents[1] / "scripts/kits.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.write_files(KIT)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "scratch", type=Path, help="new directory; never reused or deleted"
    )
    parser.add_argument("--providers-checkout", required=True, type=Path)
    parser.add_argument(
        "--published-wheels",
        type=Path,
        help="directory holding the published runtime and web wheels (default: fetch from PyPI)",
    )
    args = parser.parse_args()
    session = Session(args.scratch)
    projects, dependency = build_providers(
        session.root / "providers",
        args.providers_checkout.resolve(),
        session.env,
        args.published_wheels.resolve() if args.published_wheels else None,
    )
    out = session.root / "release"
    try:
        session.start()
        build_release(session, projects, dependency, out)
    finally:
        session.stop()
    for name in ("artifacts", "providers", "bodies"):
        target = KIT / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(out / name, target)
    shutil.copyfile(out / "cruxible-kit.json", KIT / "cruxible-kit.json")
    refresh_files()
    print(
        f"Built security:{RELEASE} for Cruxible 0.5 in {KIT}; transcript: {session.root / 'commands.jsonl'}"
    )


if __name__ == "__main__":
    main()
