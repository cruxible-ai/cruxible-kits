"""A focused revision-36 kit upgrade: named consent and exact settle authority."""

from __future__ import annotations

from contextlib import contextmanager

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from test_security_kit_gate import (
    FIXTURE,
    HERE,
    LOG4SHELL,
    RELEASE_1_0,
    SETTLES,
    VERSION,
    Gate,
    _wait_for_run,
    recipe,
)


@contextmanager
def _world():

    parent = Path(os.environ["SECURITY_KIT_GATE_ROOT"]).parent
    root = Path(tempfile.mkdtemp(prefix="named-upgrade-", dir=parent))
    print(f"named upgrade evidence: {root}")
    gate = Gate(root)
    try:
        gate.start_registry()
        subprocess.run(
            [
                sys.executable,
                str(HERE / "publish_kit.py"),
                str(RELEASE_1_0),
                f"{gate.registry}:{VERSION}",
            ],
            env=gate.env,
            check=True,
            capture_output=True,
        )
        gate.start_daemon()
        subprocess.run(
            ["git", "init", "-q", "-b", "main", "."],
            cwd=gate.ws,
            env=gate.env,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-q", "--allow-empty", "-m", "init"],
            cwd=gate.ws,
            env=gate.env,
            check=True,
        )
        gate.out("init", "--principal-id", "gate-owner")
        gate.load_settings()
        install = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--dry-run")
        installed = gate.json(
            "kit",
            "add",
            f"{gate.registry}:{VERSION}",
            "--commit",
            "--at",
            install["coordinate"]["git_oid"],
        )
        assert installed["status"] == "accepted", installed
        wheel = next((FIXTURE / "dist").glob("security_gate_sources-*.whl"))
        gate.json("provider", "install", str(wheel), "--lock", str(FIXTURE / "uv.lock"))
        gate.submit("automation", recipe.automation(fixtures=True, sources=True))
        gate.submit("watch-base", recipe.watch(LOG4SHELL, SETTLES))
        gate.submit("graduate", recipe.graduate())
        for name in ("security.kev-triage", "security.epss-triage"):
            gate.out("line", "enable", name)
        for daily, triage in (
            ("security.kev-daily", "security.kev-triage"),
            ("security.epss-daily", "security.epss-triage"),
        ):
            seen = {r["run"] for r in gate.runs(triage)}
            gate.out("line", "run", daily)
            run = _wait_for_run(gate, triage, seen, 180, status="succeeded")
            assert gate.egress(run["run"])["settle_outcome"] == "settled"
        yield gate
    finally:
        gate.close()


def test_named_upgrade_preserves_inputs_and_exact_authority():
    from test_security_kit_gate import test_18_upgrade

    with _world() as gate:
        test_18_upgrade(gate)


def test_procedure_only_revision_preserves_every_line_byte_and_enablement():
    with _world() as gate:
        old_lines = {name: gate.proof("Line:" + name) for name in recipe.LINES}
        old_enablements = {
            name: gate.card("Line:" + name).get("triggers_inactive")
            for name in recipe.LINES
        }
        old_procedures = {
            name: gate.proof("Procedure:" + name)
            for name in ("security.fetch-observed", "security.kev-triage")
        }
        epss_grant = gate.proof("ProcedureMandate:security.epss-triage-settle")
        members = []
        for name, seconds, description in (
            ("security.fetch-observed", 90, " Gate variant: a 90 second budget."),
            ("security.kev-triage", 150, " Gate variant: a 150 second triage budget."),
        ):
            spec = gate.card("Procedure:" + name)["authored"]
            spec["budget"]["wall_clock"] = f"PT{seconds}S"
            spec["description"] += description
            members.append({"kind": "procedure", "spec": spec})
        unpaired = gate.cx(
            "authoring",
            "submit",
            gate.payload(
                "unpaired-revision", {"kind": "change_set", "members": members}
            ),
            "--dry-run",
            check=False,
        )
        assert "successor_pair_required" in unpaired.stdout + unpaired.stderr
        members.extend(
            [
                recipe.mandate("security.kev-triage", "propose"),
                recipe.mandate(
                    "security.kev-triage", "propose", name="security.kev-triage-settle"
                ),
            ]
        )
        gate.submit(
            "procedure-only-variant", {"kind": "change_set", "members": members}
        )
        for name, old in old_lines.items():
            current = gate.proof("Line:" + name)
            assert current["artifact_digest"] == old["artifact_digest"]
            assert current["envelope"] == old["envelope"]
            assert (
                gate.card("Line:" + name).get("triggers_inactive")
                == old_enablements[name]
            )
        for name, old in old_procedures.items():
            current = gate.proof("Procedure:" + name)
            assert current["artifact_digest"] != old["artifact_digest"]
        assert (
            gate.proof("ProcedureMandate:security.epss-triage-settle")[
                "artifact_digest"
            ]
            == epss_grant["artifact_digest"]
        )
        assert (
            gate.proof("ProcedureMandate:security.kev-triage-settle")["envelope"][
                "grants"
            ]
            == "propose"
        )
        gate.submit("watch-revision", recipe.watch("CVE-2023-4966"))
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        gate.out("line", "run", "security.kev-daily")
        capped = _wait_for_run(
            gate, "security.kev-triage", seen, 180, status="succeeded"
        )
        egress = gate.egress(capped["run"])
        assert egress["settle_outcome"] == "proposed"
        assert (
            egress["fallback_reason"]
            == "cruxible.settle.authority_capped_by_mandate_grant"
        )
        gate.out(
            "proposal",
            "withdraw",
            egress["proposal_id"],
            "--reason",
            "Re-grant exact authority.",
        )
        gate.submit(
            "regrant-revision",
            {"kind": "change_set", "members": [recipe.graduate()["members"][0]]},
        )
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        gate.out("line", "run", "security.kev-daily")
        resumed = _wait_for_run(
            gate, "security.kev-triage", seen, 180, status="succeeded"
        )
        assert gate.egress(resumed["run"])["settle_outcome"] == "settled"
