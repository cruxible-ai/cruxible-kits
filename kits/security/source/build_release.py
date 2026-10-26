"""Build the security kit release (1.3.0) and its 1.3.1 gate variant from a fresh instance.

    python source/build_release.py SCRATCH_DIR [--providers]

Run with the interpreter of the cruxible build the release targets (its
``cruxible`` beside it, or ``CRUXIBLE_BIN``). ``SCRATCH_DIR`` gets a fresh HOME,
state root and workspace; nothing outside it and this kit directory is written.
``--providers`` first rebuilds both bundled providers (registration, lock check,
wheel; run provider tests separately). Then: start a daemon, ``init``, install
``cruxible-provider-web``
0.2.2 and the bundled wheels, author the release's definitions and Procedures,
``kit build`` it, install the patched 1.3.1 analysis wheel (the gate-only patch
adds the changed KEV field to each Claim rationale), author the 1.3.1 successors, ``kit
build`` 1.3.1, copy the release over this kit's ``cruxible-kit.json``, ``artifacts/``
and ``providers/`` and 1.3.1 over ``source/variants/1.3.1-gate``, stop the daemon, regenerate
the release's reference (``source/reference.py``: the README's generated sections
and ``reference.md``), and list the kit's inert files (the top-level pages, reference, examples,
skills) in its manifest (``scripts/kits.py files``), outside the release's content digest.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference  # noqa: E402 - the sibling generator, beside this script

KIT = Path(__file__).resolve().parents[1]
SOURCE = KIT / "source"
PROVIDERS = SOURCE / "providers"
BUNDLED = ("security-analysis-provider", "security-sources-provider")
AUTHORING = SOURCE / "authoring" / "security_definitions.py"
RELEASE = "1.3.0"  # keep in step with security_definitions.RELEASE
VARIANT = "1.3.1"  # the gate-only upgrade variant (source/variants/1.3.1-gate)
VARIANT_DIR = SOURCE / "variants" / f"{VARIANT}-gate"


def _bin() -> str:
    explicit = os.environ.get("CRUXIBLE_BIN")
    if explicit:
        return explicit
    beside = Path(sys.executable).with_name("cruxible")
    return str(beside) if beside.exists() else "cruxible"


def _build_provider(package: Path, env: dict[str, str]) -> None:
    for command in ([sys.executable, "build_registration.py"], ["uv", "lock", "--check"]):
        subprocess.run(command, cwd=package, env=env, check=True)
    shutil.rmtree(package / "dist", ignore_errors=True)
    subprocess.run(["uv", "build", "--wheel", "--out-dir", "dist"], cwd=package, env=env,
                   check=True)
    # uv ignores its out-dir; the built wheel is tracked beside its source.
    (package / "dist" / ".gitignore").unlink(missing_ok=True)


def _variant_provider(scratch: Path, env: dict[str, str]) -> Path:
    """Build the gate-only real KEV rationale change from the release provider source."""
    package = scratch / f"analysis-{VARIANT}"
    shutil.copytree(PROVIDERS / "security-analysis-provider", package,
                    ignore=shutil.ignore_patterns("dist", "__pycache__", ".venv", ".ruff_cache"))
    subprocess.run(["git", "apply", str(SOURCE / "variants" / f"analysis-{VARIANT}.patch")],
                   cwd=package, env=env, check=True)
    _build_provider(package, env)
    return package


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
        for name in BUNDLED:
            _build_provider(PROVIDERS / name, env)
    variant_provider = _variant_provider(scratch, env)
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
            if release == VARIANT:
                (wheel,) = (variant_provider / "dist").glob("*.whl")
                cx("provider", "install", str(wheel), "--lock", str(variant_provider / "uv.lock"))
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
                package = (variant_provider if release == VARIANT and
                           name == "security-analysis-provider" else PROVIDERS / name)
                args += ["--provider", str(package)]
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
    for release, target in ((RELEASE, KIT), (VARIANT, VARIANT_DIR)):
        for name in ("artifacts", "providers"):
            shutil.rmtree(target / name, ignore_errors=True)
            shutil.copytree(out / release / name, target / name)
        shutil.copyfile(out / release / "cruxible-kit.json", target / "cruxible-kit.json")
    print(f"copied {RELEASE} to {KIT} and {VARIANT} to {VARIANT_DIR}")
    for path in reference.write(KIT):
        print(f"wrote {path}")
    # The README is final only now, so its digest (and every other inert file's)
    # is listed last.
    if _kits_script().write_files(KIT):
        print(f"listed the inert files in {KIT / 'cruxible-kit.json'}")


def _kits_script():  # noqa: ANN202 - the repository's scripts/kits.py, loaded by path
    script = KIT.parents[1] / "scripts" / "kits.py"
    spec = importlib.util.spec_from_file_location("cruxible_kits_script", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    main()
