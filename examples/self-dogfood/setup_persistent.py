"""Set up the persistent self-dogfood instance: the security kit, run daily, over Cruxible's deps.

    python setup_persistent.py --core-repo PATH --core-sha SHA --providers-repo PATH --providers-sha SHA [--kit KIT_DIR] [--principal ID]

Creates ``SECURITY_DOGFOOD_ROOT`` (default ``~/tmp-workspaces/security-dogfood``)
fresh -- it refuses a root whose state root is not empty -- and leaves its daemon
running (``daemon.sh`` starts, stops and checks it). Steps, from ``run.py``
without teardown or scale:

1. start the daemon; ``init``; ``kit add`` the kit directory (this repository's
   current build); bind Procedure slots by fit
   (``cruxible-provider-web``, ``security-sources-provider``); the kit's example
   automation change set (Lines, cron and landing Triggers, propose mandates), with
   this repository's own repository and PyPI Lines from intake.md's recipe;
2. graduate KEV and EPSS triage to settle under their mandates at once (their
   Claims are verbatim copies of CISA's and FIRST's data); OSV and CVE-record
   applicability stay propose-only: their proposals are the review queue;
3. enable every Line (KEV 14:17, EPSS 13:45, OSV 15:30 UTC daily; triage,
   attention, SBOM import and CVE-record applicability on landing);
4. import the eight SBOMs (``refresh_sboms.py``) and accept those first import
   proposals, the only proposals this script accepts;
5. first runs: OSV applicability, KEV and EPSS acquisitions (triage and
   attention follow on landing).

Run with any Python 3.11+ that has ``cruxible_client``; the daemon and CLI come
from ``SECURITY_DOGFOOD_CORE``'s ``.venv``. Network: PyPI (provider installs),
cisa.gov, api.osv.dev, epss.empiricalsecurity.com.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

from persistent import KIT, ROOT, Instance, daemon
from refresh_sboms import add_source_arguments, refresh, source_pins

sys.path.insert(0, str(KIT / "gate"))
import recipe  # noqa: E402


def step(label: str, action):  # type: ignore[no-untyped-def]
    started = time.monotonic()
    value = action()
    print(f"[{time.monotonic() - started:7.1f}s] {label}", flush=True)
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kit", default=str(KIT))
    parser.add_argument("--principal", default="security-dogfood")
    add_source_arguments(parser)
    args = parser.parse_args()
    pins = source_pins(args)
    print(json.dumps({"sbom_sources": pins}, indent=2), flush=True)
    state = ROOT / "state"
    if state.exists() and any(state.iterdir()):
        raise SystemExit(f"{ROOT} already holds an instance; setup only creates a fresh one")
    for name in ("home", "state", "ws", "payloads", "logs", "run"):
        (ROOT / name).mkdir(parents=True, exist_ok=True)
    (ROOT / "source-pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    ws = ROOT / "ws"
    if not (ws / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=ws, check=True)
        subprocess.run(["git", "-c", "user.name=security-dogfood",
                        "-c", "user.email=security-dogfood@example.invalid",
                        "commit", "-q", "--allow-empty", "-m", "init"], cwd=ws, check=True)
    step("daemon started", lambda: daemon("start"))
    cx = Instance(ROOT)
    step("init", lambda: cx.cx("init", "--principal-id", args.principal))
    cx.load_settings()
    preview = step("kit add preview", lambda: cx.json("kit", "add", args.kit, "--dry-run"))
    step("kit add commit (installs 3 providers)", lambda: cx.json(
        "kit", "add", args.kit, "--commit", "--at", preview["coordinate"]["git_oid"]))
    step("automation change set", lambda: cx.submit("automation", recipe.automation(sources=True)))
    step("graduate KEV and EPSS triage to settle", lambda: cx.submit(
        "graduate", recipe.graduate()))
    step("enable every Line", lambda: [cx.cx("line", "enable", name) for name in recipe.LINES])

    def import_sboms() -> list[str]:
        # One at a time: each import is evaluated against the head the previous
        # acceptance produced (proposals made against one head go stale together).
        before = {r["run"] for r in cx.runs("security.sbom-import")}
        accepted: list[str] = []

        def accept(name: str) -> None:
            run = cx.wait_run("security.sbom-import", before)
            before.add(run["run"])
            egress = cx.egress(run["run"])
            if run["status"] == "succeeded" and egress.get("proposal_id"):
                cx.cx("proposal", "activate", egress["proposal_id"])
                accepted.append(egress["proposal_id"])
            else:
                print(f"  {name}: import {run['status']}")

        refresh(cx, **pins, after_each=accept)
        return accepted

    accepted = step("SBOM import (8 SBOMs) and acceptance", import_sboms)
    print(f"  accepted {len(accepted)} SBOM-import proposals")

    def first_runs() -> dict[str, object]:
        result: dict[str, object] = {}
        osv = json.loads(cx.cx("line", "run", "security.osv-applicability", "--json"))
        result["osv"] = {"run": osv.get("run_id"), "result": osv.get("result")}
        for acquire, followers in (("security.kev-daily",
                                    ("security.kev-triage", "security.kev-attention")),
                                   ("security.epss-daily", ("security.epss-triage",))):
            before = {line: {r["run"] for r in cx.runs(line)} for line in followers}
            cx.cx("line", "run", acquire)
            for line in followers:
                run = cx.wait_run(line, before[line])
                result[line] = run["status"]
        return result

    print(json.dumps(step("first OSV, KEV and EPSS runs", first_runs), indent=1))
    print(f"instance root {ROOT}; daemon left running (daemon.sh status)")


if __name__ == "__main__":
    main()
