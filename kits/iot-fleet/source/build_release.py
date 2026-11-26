"""Build the iot-fleet 2.1.0 kit (vocabulary, provider, Procedures, recipes, guidance)
through the public CLI.

    python kits/iot-fleet/source/build_release.py /short/new/scratch \
        [--providers-checkout ../cruxible-providers]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parent
KIT = SOURCE.parent
ROOT = KIT.parents[1]
PROVIDERS_DIR = SOURCE / "providers"
RUNTIME_COMMIT = "ca12589afe1f3c53cee2bd72d3765467948f3120"
RUNTIME_WHEEL = (
    ROOT / "kits" / "security" / "providers" / "cruxible_provider_runtime-0.6.0-py3-none-any.whl"
)
RUNTIME_SHA256 = "dcdb2646e6abd7353dc9766be1f58d442f5b81e41237a710af3e4bc3b1bd4d5e"
REQUIRES = {"base": "1.0.0"}

sys.path.insert(0, str(SOURCE))
import automation as auto  # noqa: E402
import definitions as defs  # noqa: E402


class Session:
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


def _extract_runtime_source(checkout: Path, dest: Path) -> None:
    archive = subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "archive",
            "--format=tar",
            RUNTIME_COMMIT,
            "packages/cruxible-provider-runtime",
        ],
        capture_output=True,
        check=True,
    ).stdout
    dest.mkdir(parents=True)
    prefix = "packages/cruxible-provider-runtime/"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            rel = member.name.removeprefix(prefix)
            handle = tar.extractfile(member)
            assert handle is not None
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(handle.read())


def build_provider(root: Path, checkout: Path, env: dict[str, str]) -> tuple[Path, Path]:
    digest = hashlib.sha256(RUNTIME_WHEEL.read_bytes()).hexdigest()
    if digest != RUNTIME_SHA256:
        raise RuntimeError(f"{RUNTIME_WHEEL} sha256 {digest} != {RUNTIME_SHA256}")
    root.mkdir()
    _extract_runtime_source(checkout, root / "cruxible-provider-runtime")
    project = root / auto.PROVIDER_PACKAGE
    shutil.copytree(
        PROVIDERS_DIR / auto.PROVIDER_PACKAGE,
        project,
        ignore=shutil.ignore_patterns("dist", ".venv", "__pycache__", ".pytest_cache"),
    )
    subprocess.run(["uv", "lock", "--check", "--offline"], cwd=project, env=env, check=True)
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
    dep = project / "dist" / RUNTIME_WHEEL.name
    shutil.copyfile(RUNTIME_WHEEL, dep)
    return project, dep


def _load_script(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scratch", type=Path)
    parser.add_argument(
        "--providers-checkout",
        type=Path,
        default=ROOT.parent / "cruxible-providers",
    )
    args = parser.parse_args()

    auto.write_registration(check=False)
    auto.write_templates()

    session = Session(args.scratch)
    project, dep = build_provider(
        session.root / "providers", args.providers_checkout.resolve(), session.env
    )
    out = session.root / "release"
    session.start()
    try:
        session.initialize()
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
            str(dep),
            "--control-domain",
            auto.PROVIDER_PACKAGE,
            "--commit",
            "--json",
        )
        ready = {row["operation"] for row in installed["operations"] if row["installed"]}
        if not installed.get("registered") or "telemetry.analyze" not in ready:
            raise RuntimeError(f"Provider install failed: {installed}")

        base_kinds, layout_kinds = auto.staged_capture_kinds()

        def propose_kinds(stage: str, records: dict[str, Any]) -> None:
            for name, record in records.items():
                p = session.root / f"{stage}.{name}.json"
                p.write_text(json.dumps(record, indent=1) + "\n")
                session.command(
                    "capture-contract", "propose", "--input", str(p), "--commit", "--json"
                )

        propose_kinds("capture-kind", base_kinds)
        session.submit("vocabulary", defs.vocabulary_change_set(list(auto.ROW_CONTRACTS)))
        session.submit("capabilities", auto.capabilities_change_set())
        propose_kinds("capture-layout", layout_kinds)
        session.submit("procedures", auto.procedures_change_set())

        def store(path: Path) -> str:
            return str(session.command("body", "store", str(path), "--json")["digest"])

        for document in defs.guidance_documents(store):
            name = document["identity"].removeprefix("document:")
            doc_path = session.root / f"document.{name}.json"
            doc_path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
            res = session.command(
                "document", "propose", "--envelope", str(doc_path), "--name", name, "--json"
            )
            if res.get("outcome", {}).get("status") != "landed":
                raise RuntimeError(f"document {name} did not land: {res}")

        build_kit = _load_script(ROOT / "scripts" / "build_kit.py", "kit_builder")
        cmd = [
            "kit",
            "build",
            "--id",
            defs.KIT_ID,
            "--version",
            defs.VERSION,
            "--owns",
            "fleet.",
            "--automation-template",
            str(KIT / "automation.json"),
            "--provider",
            str(project),
            "--out",
            str(out),
        ]
        cmd.extend(build_kit.adoption_args(KIT, session.workspace))
        session.command(*cmd, "--json")
        built = json.loads((out / "cruxible-kit.json").read_bytes())
        requires = {item["kit_id"]: item["min_version"] for item in built.get("requires", ())}
        if requires != REQUIRES:
            raise RuntimeError(f"kit build recorded requires {requires}, not {REQUIRES}")
    finally:
        session.stop()

    for name in ("artifacts", "providers", "bodies"):
        target = KIT / name
        if target.exists():
            shutil.rmtree(target)
        if (out / name).is_dir():
            shutil.copytree(out / name, target)
    shutil.copyfile(out / "cruxible-kit.json", KIT / "cruxible-kit.json")
    _load_script(ROOT / "scripts" / "kits.py", "kits_script").write_files(KIT)
    print(f"Built {defs.KIT_ID}:{defs.VERSION} in {KIT}")


if __name__ == "__main__":
    main()
