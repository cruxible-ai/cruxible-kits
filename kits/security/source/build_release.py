"""Build the security kit release (1.0.1) and its 1.1.0 gate variant from a fresh instance.

    python source/build_release.py SCRATCH_DIR [--providers]

Run with the interpreter of the cruxible build the release targets (its
``cruxible`` beside it, or ``CRUXIBLE_BIN``). ``SCRATCH_DIR`` gets a fresh HOME,
state root and workspace; nothing outside it and this kit directory is written.
``--providers`` first rebuilds both bundled providers (registration, lock-checked
tests, wheel). Then: start a daemon, ``init``, install ``cruxible-provider-web``
0.2.2 and the bundled wheels, author the release's definitions and Procedures,
``kit build`` it, author the 1.1.0 successors on the same instance, ``kit
build`` 1.1.0, copy the release over this kit's ``cruxible-kit.json``, ``artifacts/``
and ``providers/`` and 1.1.0 over ``source/variants/1.1.0``, and stop the daemon.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
SOURCE = KIT / "source"
PROVIDERS = SOURCE / "providers"
BUNDLED = ("security-analysis-provider", "security-sources-provider")
AUTHORING = SOURCE / "authoring" / "security_definitions.py"
RELEASE = "1.0.1"  # keep in step with security_definitions.RELEASE
VARIANT = "1.1.0"


def _bin() -> str:
    explicit = os.environ.get("CRUXIBLE_BIN")
    if explicit:
        return explicit
    beside = Path(sys.executable).with_name("cruxible")
    return str(beside) if beside.exists() else "cruxible"


def _providers(env: dict[str, str]) -> None:
    for name in BUNDLED:
        package = PROVIDERS / name
        for command in (
            ["uv", "run", "--frozen", "python", "build_registration.py"],
            ["uv", "lock", "--check"],
            ["uv", "run", "--frozen", "pytest", "-q"],
        ):
            subprocess.run(command, cwd=package, env=env, check=True)
        shutil.rmtree(package / "dist", ignore_errors=True)
        subprocess.run(["uv", "build", "--wheel", "--out-dir", "dist"], cwd=package, env=env,
                       check=True)


def main() -> None:
    scratch = Path(sys.argv[1]).resolve()
    rebuild = "--providers" in sys.argv[2:]
    if scratch.exists():
        shutil.rmtree(scratch)
    home, state, ws, out = (scratch / name for name in ("home", "state", "ws", "out"))
    for path in (home, state, ws, out):
        path.mkdir(parents=True)
    run_dir = Path(tempfile.mkdtemp(prefix="kb-", dir="/tmp"))
    run_dir.chmod(0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_CACHE_HOME=str(home / ".cache"), CRUXIBLE_STATE_ROOT=str(state),
               CRUXIBLE_SERVER_SOCKET=str(run_dir / "d.sock"),
               GIT_AUTHOR_NAME="kit-build", GIT_AUTHOR_EMAIL="kit-build@example.invalid",
               GIT_COMMITTER_NAME="kit-build", GIT_COMMITTER_EMAIL="kit-build@example.invalid")
    if rebuild:
        _providers({**env, "HOME": os.environ["HOME"]})
    cruxible = _bin()

    def cx(*args: str) -> str:
        result = subprocess.run([cruxible, *args], env=env, cwd=ws, capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"cruxible {' '.join(args)}: {result.stdout}{result.stderr}")
        return result.stdout

    subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=ws, env=env, check=True)
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"], cwd=ws, env=env,
                   check=True)
    daemon = subprocess.Popen([cruxible, "server", "start", "--socket",
                               env["CRUXIBLE_SERVER_SOCKET"], "--state-root", str(state)],
                              env=env, cwd=scratch, stdout=(scratch / "daemon.log").open("ab"),
                              stderr=subprocess.STDOUT)
    try:
        for _ in range(120):
            if subprocess.run([cruxible, "server", "status"], env=env,
                              capture_output=True).returncode == 0:
                break
            time.sleep(1)
        cx("init", "--principal-id", "kit-author")
        # The SDK (security_definitions.py) acts as the owner `init` made, as its settings say.
        (settings,) = (home / ".config" / "cruxible" / "keys").glob("*/*/cruxible.env")
        for line in settings.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                env[key.strip().removeprefix("export ").strip()] = value.strip().strip("'\"")
        cx("provider", "install", "cruxible-provider-web==0.2.2")
        for name in BUNDLED:
            (wheel,) = (PROVIDERS / name / "dist").glob("*.whl")
            cx("provider", "install", str(wheel), "--lock", str(PROVIDERS / name / "uv.lock"))
        for release in (RELEASE, VARIANT):
            for stage in ("definitions", "procedures"):
                result = subprocess.run([sys.executable, str(AUTHORING), stage, "--release",
                                         release], env=env, cwd=ws, capture_output=True,
                                        text=True)
                print(result.stdout, end="")
                if result.returncode != 0:
                    raise SystemExit(result.stdout + result.stderr)
            args = ["kit", "build", "--id", "security", "--version", release, "--owns",
                    "security.", "--out", str(out / release)]
            for name in BUNDLED:
                args += ["--provider", str(PROVIDERS / name)]
            args += ["--default-provider", str(PROVIDERS / "cruxible-provider-web")]
            print(cx(*args), end="")
    finally:
        subprocess.run([cruxible, "server", "stop"], env=env, capture_output=True)
        try:
            daemon.wait(timeout=60)
        except subprocess.TimeoutExpired:
            daemon.terminate()
            daemon.wait(timeout=30)
        shutil.rmtree(run_dir, ignore_errors=True)
    for release, target in ((RELEASE, KIT), (VARIANT, SOURCE / "variants" / VARIANT)):
        for name in ("artifacts", "providers"):
            shutil.rmtree(target / name, ignore_errors=True)
            shutil.copytree(out / release / name, target / name)
        shutil.copyfile(out / release / "cruxible-kit.json", target / "cruxible-kit.json")
    print(f"copied {RELEASE} to {KIT} and {VARIANT} to {SOURCE / 'variants' / VARIANT}")


if __name__ == "__main__":
    main()
