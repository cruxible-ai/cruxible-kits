"""The persistent self-dogfood instance: where it lives and how to talk to it.

Shared by ``setup_persistent.py``, ``refresh_sboms.py`` and ``snapshot.py``;
``daemon.sh`` builds the same environment in shell. Nothing here prints a
credential: the owner's settings file is read into the child environment only.

Layout of the root (``SECURITY_DOGFOOD_ROOT``, default
``~/tmp-workspaces/security-dogfood``)::

    home/       the daemon's and the CLI's HOME (the owner's key and settings)
    state/      the daemon's state root
    ws/         the attached workspace (sboms/, analysis/)
    run/d.sock  the daemon's Unix socket (owner-only directory)
    payloads/   change sets and run inputs the scripts submitted
    logs/       daemon.log, commands.log
    metrics.jsonl  one line per snapshot.py run
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("SECURITY_DOGFOOD_ROOT",
                           Path.home() / "tmp-workspaces" / "security-dogfood")).resolve()
CORE = Path(os.environ.get("SECURITY_DOGFOOD_CORE",
                           Path.home() / "tmp-workspaces" / "security-dogfood-core")).resolve()
HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1] / "kits" / "security"


class Instance:
    """The CLI against the persistent daemon, with the owner's settings loaded."""

    def __init__(self, root: Path = ROOT) -> None:
        self.root = root
        self.home, self.state, self.ws = root / "home", root / "state", root / "ws"
        self.socket = root / "run" / "d.sock"
        self.bin = os.environ.get("CRUXIBLE_BIN") or str(CORE / ".venv" / "bin" / "cruxible")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")}
        self.env.update(
            HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_CACHE_HOME=str(self.home / ".cache"), CRUXIBLE_STATE_ROOT=str(self.state),
            CRUXIBLE_SERVER_SOCKET=str(self.socket),
            CRUXIBLE_ARTIFACT_CACHE=str(self.home / ".cache" / "cruxible-artifacts"),
            CRUXIBLE_CLIENT_TIMEOUT_S="1200",
            GIT_AUTHOR_NAME="security-dogfood", GIT_AUTHOR_EMAIL="security-dogfood@example.invalid",
            GIT_COMMITTER_NAME="security-dogfood",
            GIT_COMMITTER_EMAIL="security-dogfood@example.invalid",
        )
        self.load_settings()

    def load_settings(self) -> None:
        """Act as the owner ``init`` made (its settings file), when there is one."""

        found = sorted((self.home / ".config" / "cruxible" / "keys").glob("*/*/cruxible.env"))
        if not found:
            return
        for line in found[0].read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                key = key.strip().removeprefix("export ").strip()
                if key not in {"CRUXIBLE_SERVER_SOCKET", "CRUXIBLE_STATE_ROOT"}:
                    self.env[key] = value.strip().strip("'\"")

    def cx(self, *args: str, check: bool = True) -> str:
        started = time.monotonic()
        result = subprocess.run([self.bin, *args], env=self.env, cwd=self.ws,
                                capture_output=True, text=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        with (self.root / "logs" / "commands.log").open("a") as log:
            log.write(f"$ cruxible {' '.join(args)}  [{time.monotonic() - started:.1f}s]\n"
                      f"{result.stdout[-4000:]}{result.stderr[-4000:]}(exit {result.returncode})\n")
        if check and result.returncode != 0:
            raise SystemExit(f"cruxible {' '.join(args)}: {result.stdout[-2000:]}"
                             f"{result.stderr[-2000:]}")
        return result.stdout

    def json(self, *args: str) -> Any:
        return json.loads(self.cx(*args, "--json"))

    def payload(self, name: str, value: object) -> Path:
        path = self.root / "payloads" / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=1))
        return path

    def submit(self, name: str, value: object) -> None:
        out = json.loads(self.cx("authoring", "submit", str(self.payload(name, value))))
        if out["outcome"]["status"] != "landed":
            raise SystemExit(f"{name} not accepted: {json.dumps(out)[-1500:]}")

    def runs(self, line: str) -> list[dict[str, Any]]:
        return list(self.json("get", f"Line:{line}")["card"].get("recent_runs") or [])

    def wait_run(self, line: str, before: set[str], timeout: float = 900) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            fresh = [r for r in self.runs(line)
                     if r["run"] not in before and r["status"] != "running"]
            if fresh:
                return fresh[0]
            time.sleep(1)
        raise SystemExit(f"no run on {line} within {timeout:.0f}s")

    def egress(self, run: str) -> dict[str, Any]:
        terminals = self.json("get", run)["card"].get("terminal_egress") or []
        return dict(terminals[0]) if terminals else {}

    def rows(self, name: str) -> list[dict[str, Any]]:
        return list(self.json("query", "--name", name, "--all")["rows"])


def daemon(command: str) -> None:
    """Run ``daemon.sh COMMAND`` for the root this process uses."""

    subprocess.run(["bash", str(HERE / "daemon.sh"), command],
                   env={**os.environ, "SECURITY_DOGFOOD_ROOT": str(ROOT),
                        "SECURITY_DOGFOOD_CORE": str(CORE)}, check=True)


if __name__ == "__main__":  # pragma: no cover - a convenience: run the CLI with the env
    sys.stdout.write(Instance().cx(*sys.argv[1:], check=False))
