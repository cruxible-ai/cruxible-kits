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
are left as they are. The daemon is stopped even when a step fails; command
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
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

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
        args = ["kit", "build", "--id", source.KIT_ID, "--version", source.VERSION]
        for prefix in source.OWNS:
            args += ["--owns", prefix]
        session.command(*args, "--out", str(out), "--json")
    finally:
        session.stop()
    built = json.loads((out / "cruxible-kit.json").read_bytes())
    if built.get("requires") or built.get("providers"):
        raise RuntimeError("a definitions-only kit records no requires or providers")
    shutil.rmtree(kit / "artifacts", ignore_errors=True)
    shutil.copytree(out / "artifacts", kit / "artifacts")
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
