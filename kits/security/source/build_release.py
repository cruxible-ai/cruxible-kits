"""Build the security kit (dependency + audit loops) for Cruxible 0.5 through the public CLI.

    python source/build_release.py NEW_SCRATCH --providers-checkout PROVIDERS

The kit's own OSV/web sources and frozen locks build offline. The runtime source
comes from the explicitly selected providers checkout. Provider installation may
download the registry dependencies pinned by those locks. No tests or private
accept-tree helpers are used. A fresh publisher accepts the definitions and
guidance, then production kit build validates the unchanged template against
that exported closure. Only a successful build replaces the committed release.

The release carries both loops: the dependency loop (SBOM, OSV, KEV, EPSS and the
dependency guidance) and the audit extension (code findings and coverage units,
the SARIF import Procedures with their provider, the audit Queries and the
hunter, verifier and coverage guidance). The reference pages under ``reference/``
ship as plain kit files.
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
from typing import Any

SOURCE = Path(__file__).resolve().parent
KIT = SOURCE.parent
PROVIDERS = SOURCE / "providers"
RELEASE = "1.3.0"  # Unpublished kit version; targets Cruxible 0.5.
PACKAGES = ("security-osv-provider", "cruxible-provider-web", "security-sarif-provider")
#: The operations each bundled provider must install for the kit's Procedures.
REQUIRED = {
    "security-osv-provider": {"sbom.components", "osv.query", "osv.match"},
    "cruxible-provider-web": {"web.fetch", "web.fetch.pages"},
    "security-sarif-provider": {"sarif.findings"},
}
sys.path.insert(0, str(SOURCE / "pilot"))

import definitions as kit  # noqa: E402
import findings  # noqa: E402
import install  # noqa: E402
import osv  # noqa: E402
import template  # noqa: E402
import web_contracts  # noqa: E402


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


def build_providers(root: Path, checkout: Path, env: dict[str, str]) -> list[Path]:
    """Build exact locked sources in scratch, never modifying the checkout."""
    root.mkdir()
    runtime = root / "cruxible-provider-runtime"
    shutil.copytree(
        checkout / "packages/cruxible-provider-runtime",
        runtime,
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

    dependency = build(runtime)
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
        build(project)
        shutil.copyfile(dependency, project / "dist" / dependency.name)
        projects.append(project)
    return projects


def build_release(session: Session, projects: list[Path], out: Path) -> None:
    session.initialize()
    web = PROVIDERS / "cruxible-provider-web/src/cruxible_provider_web"
    session.submit(
        "provider-contracts",
        {
            "kind": "change_set",
            "members": [
                *web_contracts.package_members(web),
                *osv.provider_contract_members(),
                *findings.provider_contract_members(),
            ],
        },
    )
    for project in projects:
        wheels = list((project / "dist").glob("*.whl"))
        dependency = next(
            p for p in wheels if p.name.startswith("cruxible_provider_runtime-")
        )
        wheel = next(p for p in wheels if p != dependency)
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
    for name, record in {**kit.capture_kinds(), **findings.capture_kinds()}.items():
        path = session.root / f"capture-kind.{name}.json"
        path.write_text(json.dumps(record, indent=1) + "\n")
        session.command(
            "capture-contract", "propose", "--input", str(path), "--commit", "--json"
        )
    session.submit("vocabulary", kit.vocabulary())
    session.submit("procedures", kit.procedures())
    session.submit("audit-vocabulary", findings.vocabulary())
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
        "--automation-template",
        str(template.TEMPLATE),
        "--out",
        str(out),
    ]
    for project in projects:
        args.extend(("--provider", str(project)))
    session.command(*args, "--json")


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
    args = parser.parse_args()
    session = Session(args.scratch)
    projects = build_providers(
        session.root / "providers", args.providers_checkout.resolve(), session.env
    )
    out = session.root / "release"
    try:
        session.start()
        build_release(session, projects, out)
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
