"""Install the KEV + EPSS slice into a fresh instance through the served CLI.

Every step is an ordinary governed write the instance's approval policy admits
(an owner with self-approval lands each at once):

1. the Contracts cruxible-provider-web's operations pin (``web_contracts.py``);
2. ``provider install`` of the web wheel (its lock and the runtime wheel beside it);
3. the two CaptureKinds (``capture-contract propose``);
4. vocabulary, Procedures, watched Subjects and the Lines/Mandates/Triggers
   (``authoring submit`` of the change sets ``definitions.py`` writes).

    python install.py PAYLOADS --providers PROVIDERS_CHECKOUT --wheels WHEEL_DIR

``cruxible`` must be on PATH and already pointed at the instance (``cruxible
init`` in the workspace, or CRUXIBLE_SERVER_SOCKET + --instance-id).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import definitions as kit  # noqa: E402
import web_contracts  # noqa: E402


def cruxible(*args: str) -> str:
    done = subprocess.run(["cruxible", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"cruxible {' '.join(args)} failed:\n{done.stdout}\n{done.stderr}")
    return done.stdout


def submit(path: Path) -> None:
    out = cruxible("authoring", "submit", str(path), "--brief")
    if "outcome: accepted" not in out:
        raise SystemExit(f"{path.name} did not land:\n{out}")
    print(f"{path.name}: accepted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("payloads", type=Path, help="the directory definitions.py wrote")
    parser.add_argument("--providers", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    args = parser.parse_args()

    contracts = args.payloads / "web-contracts.json"
    contracts.write_text(
        json.dumps(
            {
                "kind": "change_set",
                "rationale": "The Contracts cruxible-provider-web's operations pin, as shipped.",
                "members": web_contracts.members(args.providers),
            },
            indent=1,
        )
        + "\n"
    )
    submit(contracts)
    web = next(args.wheels.glob("cruxible_provider_web-*.whl"))
    runtime = next(args.wheels.glob("cruxible_provider_runtime-*.whl"))
    installed = json.loads(
        cruxible(
            "provider",
            "install",
            str(web),
            "--lock",
            str(args.providers / "packages/cruxible-provider-web/uv.lock"),
            "--dependency",
            str(runtime),
            "--control-domain",
            "cruxible-provider-web",
            "--commit",
            "--json",
        )
    )
    ready = {row["operation"]: row["installed"] for row in installed["operations"]}
    if not (installed["registered"] and ready.get("web.fetch")):
        raise SystemExit(f"web.fetch is not installed: {installed}")
    print(f"provider: {installed['build']} (web.fetch installed)")
    for name in kit.capture_kinds():
        path = args.payloads / f"capture-kind.{name}.json"
        cruxible("capture-contract", "propose", "--input", str(path), "--commit")
        print(f"capture kind {name}: accepted")
    for name in ("vocabulary", "procedures", "watch", "automation"):
        submit(args.payloads / f"{name}.json")


if __name__ == "__main__":
    main()
