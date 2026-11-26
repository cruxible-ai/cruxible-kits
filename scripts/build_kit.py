"""Rebuild a definitions-only kit from its authored source, through the public CLI.

    python scripts/build_kit.py kits/<id> /short/new/scratch

``kits/<id>/source/definitions.py`` declares the release: ``KIT_ID``, ``VERSION``,
``OWNS`` and ``change_set()``, one authoring change set (ClaimTypes lowered from
their authored input records with the client's ``lower_claim_type_input``, the
SubjectKinds and the saved Queries). The builder starts a scratch daemon on a
fresh state root under the scratch directory (which must not exist; the socket
needs a short path), runs ``cruxible init``, submits the change set, exports it
with ``cruxible kit build`` and replaces the kit's manifest and ``artifacts/``
with the export. The inert-file list is refreshed last; README and ``source/``
are left as they are.

Recipes and scripts (Cruxible 0.6, ``kit adopt`` / ``kit run``): a kit that
declares them in ``source/recipes.json`` and ``source/scripts.json`` (JSON lists of
the manifest's ``recipes`` and ``scripts`` entries, each ``path`` a file of the kit
under ``recipes/`` or ``scripts/``) has them passed to ``kit build --recipes`` /
``--scripts``, which renders every recipe with its defaults and examples and
refuses the build unless each authors cleanly against the kit's definitions
(:func:`adoption_args`; the security kit's builder uses it too). The daemon is stopped even when a step fails; command
receipts and the daemon log stay under the scratch directory for the caller to
read and delete.

Use the Python interpreter of the target core (with ``cruxible`` beside it, or
``CRUXIBLE_BIN``). Kits with providers, Procedures or Documents have their own
builder (``kits/security/source/build_release.py``).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

from cruxible_client._safe_files import HeldRoot

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Session:
    """One scratch state root, daemon, workspace and command log."""

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
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")}
        self.env.update(
            HOME=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            XDG_CACHE_HOME=str(home / ".cache"),
            CRUXIBLE_STATE_ROOT=str(self.state),
            CRUXIBLE_SERVER_SOCKET=str(self.socket),
            PYTHONDONTWRITEBYTECODE="1",
            GIT_AUTHOR_NAME="kit-build",
            GIT_AUTHOR_EMAIL="kit-build@example.invalid",
            GIT_COMMITTER_NAME="kit-build",
            GIT_COMMITTER_EMAIL="kit-build@example.invalid",
        )
        self.binary = os.environ.get(
            "CRUXIBLE_BIN", str(Path(sys.executable).with_name("cruxible"))
        )
        self.daemon: subprocess.Popen[bytes] | None = None

    def command(self, *args: str) -> Any:
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
        if done.returncode:
            raise RuntimeError(f"cruxible {' '.join(args)}:\n{done.stdout}{done.stderr}")
        try:
            return json.loads(done.stdout)
        except json.JSONDecodeError:
            return done.stdout

    def start(self) -> None:
        subprocess.run(
            ["git", "init", "-q", "-b", "main"], cwd=self.workspace, env=self.env, check=True
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
                "server", "stop", "--state-root", str(self.state), "--timeout", "30", "--json"
            )
        finally:
            try:
                self.daemon.wait(timeout=35)
            except subprocess.TimeoutExpired:
                self.daemon.terminate()
                self.daemon.wait(timeout=30)

    def initialize(self) -> None:
        self.command(
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

    def submit(self, name: str, payload: dict[str, Any]) -> None:
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1) + "\n")
        result = self.command("authoring", "submit", str(path), "--json")
        if result.get("outcome", {}).get("status") != "landed":
            raise RuntimeError(f"{name} did not land: {result}")


#: Where a kit declares its recipes and scripts (build inputs, not shipped).
RECIPE_SPECS = Path("source") / "recipes.json"
SCRIPT_SPECS = Path("source") / "scripts.json"
#: Each declaration list's option and the kit directory its files must sit under.
ADOPTION_ROLES = (("--recipes", RECIPE_SPECS, "recipes"), ("--scripts", SCRIPT_SPECS, "scripts"))
#: A declared file's path: segments of letters, digits, ``_``, ``.`` and ``-``
#: beneath its role directory, never ``.`` or ``..``.
_DECLARED_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")


def _declared_path(source: Path, spec: Any, role: str) -> str:
    """A declared file's kit-relative path, checked to name a file under ``role/``."""

    path = spec.get("path") if isinstance(spec, dict) else None
    if not isinstance(path, str) or not _DECLARED_PATH.fullmatch(path):
        raise ValueError(f"{source}: {path!r} is not a normalized relative path inside the kit")
    parts = path.split("/")
    if len(parts) < 2 or parts[0] != role or any(part in (".", "..") for part in parts):
        raise ValueError(f"{source}: {path} is not a file under the kit's {role}/ directory")
    return path


def adoption_args(kit: Path, workspace: Path) -> list[str]:
    """``kit build`` options for the kit's declared recipes and scripts.

    ``kit build`` reads each declared file relative to the workspace root, so every
    one is copied from the kit to the same relative path under ``workspace``, and
    each declaration list is written beside the workspace. Empty when the kit
    declares neither.

    Every read is held beneath the kit directory (:class:`HeldRoot`: opened once,
    then component by component with ``O_NOFOLLOW``), so a declaration list or a
    declared file that is, or sits under, a symbolic link is refused rather than
    staged from wherever it points. Each declared path must be a normalized path
    under its role's directory (``recipes/`` for ``--recipes``, ``scripts/`` for
    ``--scripts``), checked before anything is copied."""

    # Read and check everything first: nothing is copied unless every list is sound.
    lists: list[tuple[str, Path, bytes, list[tuple[str, bytes]]]] = []
    with HeldRoot(kit) as held:
        for option, relative, role in ADOPTION_ROLES:
            try:
                raw = held.read(relative.as_posix())
            except FileNotFoundError:
                continue
            source = kit / relative
            specs = json.loads(raw)
            if not isinstance(specs, list) or not specs:
                raise ValueError(f"{source} must be a non-empty JSON list")
            paths = [_declared_path(source, spec, role) for spec in specs]
            lists.append((option, relative, raw, [(path, held.read(path)) for path in paths]))
    args: list[str] = []
    for option, relative, raw, files in lists:
        for path, content in files:
            target = workspace.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        declared = workspace.parent / f"kit-{relative.stem}.json"
        declared.write_bytes(raw)
        args += [option, str(declared)]
    return args


def build(kit: Path, scratch: Path) -> None:
    source = _load(kit / "source" / "definitions.py", f"{kit.name}_definitions")
    if source.KIT_ID != kit.name:
        raise ValueError(f"{kit}/source/definitions.py declares kit {source.KIT_ID}")
    session = Session(scratch)
    out = session.root / "out"
    session.start()
    try:
        session.initialize()
        session.submit("definitions", source.change_set())
        if hasattr(source, "guidance_documents"):
            def _store_body(path: Path) -> str:
                return session.command("body", "store", str(path), "--json")["digest"]

            for document in source.guidance_documents(_store_body):
                name = document["identity"].removeprefix("document:")
                doc_path = session.root / f"document.{name}.json"
                doc_path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
                result = session.command(
                    "document", "propose", "--envelope", str(doc_path), "--name", name, "--json"
                )
                if result.get("outcome", {}).get("status") != "landed":
                    raise RuntimeError(f"document {name} did not land: {result}")
        args = ["kit", "build", "--id", source.KIT_ID, "--version", source.VERSION]
        for prefix in source.OWNS:
            args += ["--owns", prefix]
        args += adoption_args(kit, session.workspace)
        session.command(*args, "--out", str(out), "--json")
    finally:
        session.stop()
    built = json.loads((out / "cruxible-kit.json").read_bytes())
    if built.get("requires") or built.get("providers"):
        raise RuntimeError("a definitions-only kit records no requires or providers")
    shutil.rmtree(kit / "artifacts", ignore_errors=True)
    shutil.copytree(out / "artifacts", kit / "artifacts")
    shutil.rmtree(kit / "bodies", ignore_errors=True)
    if (out / "bodies").is_dir():
        shutil.copytree(out / "bodies", kit / "bodies")
    shutil.copyfile(out / "cruxible-kit.json", kit / "cruxible-kit.json")
    _load(ROOT / "scripts" / "kits.py", "kits_script").write_files(kit)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kit", type=Path)
    parser.add_argument("scratch", type=Path)
    args = parser.parse_args()
    build(args.kit.resolve(), args.scratch)


if __name__ == "__main__":
    main()
