"""A focused revision-36 kit upgrade: named consent and exact settle authority."""

from __future__ import annotations

import json
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
    RELEASE_1_1,
    SETTLES,
    UPGRADE_VERSION,
    VERSION,
    Gate,
    _wait_for_run,
    recipe,
)


def _settle_grant():
    return recipe.mandate(
        "security.kev-triage",
        "settle",
        scope=[
            {
                "claim_type": "security.vulnerability." + field,
                "change_kinds": ["create", "revise"],
            }
            for field in recipe.KEV_FIELDS
        ],
        condition={
            "query_name": "security.settle_condition",
            "binding_parameter": "vulnerability_id",
            "required_fields": ["cve_id"],
            "fallback": "propose",
        },
    )


def test_named_upgrade_preserves_lines_and_requires_a_settle_regrant():
    parent = Path(os.environ["SECURITY_KIT_GATE_ROOT"]).parent
    root = Path(tempfile.mkdtemp(prefix="named-upgrade-", dir=parent))
    print(f"named upgrade evidence: {root}")
    gate = Gate(root)
    try:
        gate.start_registry()
        for release, version in (
            (RELEASE_1_0, VERSION),
            (RELEASE_1_1, UPGRADE_VERSION),
        ):
            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "publish_kit.py"),
                    str(release),
                    f"{gate.registry}:{version}",
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
        assert install["status"] == "would_propose", install
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
        gate.submit(
            "setup",
            {
                "kind": "change_set",
                "members": [
                    {
                        "kind": "acquisition_policy",
                        "acquisition_policy": {
                            "identity": {
                                "kind": "SourceAcquisitionPolicy",
                                "name": "default",
                            },
                            "max_age": "P1D",
                        },
                    },
                    {
                        "kind": "blueprint_instance",
                        "name": "security.kev-acquire",
                        "blueprint": "security.kev-acquire",
                        "bindings": {"catalog": "security-gate-sources"},
                    },
                    recipe.line("security.kev-daily"),
                    recipe.line("security.kev-triage", authority="settle"),
                    _settle_grant(),
                    {
                        "kind": "trigger",
                        "name": "security.upgrade-probe-landed",
                        "line_name": "security.kev-triage",
                        "schedule": {
                            "kind": "capture_landing",
                            "capture_contract": "security.fetched-v1",
                            "logical_sources": ["cisa.kev.catalog"],
                        },
                    },
                ],
            },
        )
        gate.submit("watch-base", recipe.watch(LOG4SHELL))
        gate.out("line", "enable", "security.kev-triage")
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        gate.out("line", "run", "security.kev-daily")
        initial = _wait_for_run(
            gate, "security.kev-triage", seen, 180, status="succeeded"
        )
        assert gate.egress(initial["run"])["settle_outcome"] == "settled"
        old_line = gate.proof("Line:security.kev-triage")
        old_proc = gate.proof("Procedure:security.kev-triage")
        old_inactive = gate.card("Line:security.kev-triage").get("triggers_inactive")
        gate.py(HERE / "edit_kev_exposure.py", "250")
        preview = gate.json(
            "kit", "add", f"{gate.registry}:{UPGRADE_VERSION}", "--dry-run"
        )
        (root / "upgrade-preview.json").write_text(json.dumps(preview, indent=2) + "\n")
        assert preview["status"] == "would_propose", preview
        assert not [
            row for row in preview["automation_carries"] if row["kind"] == "line"
        ]
        (mandate,) = [
            row
            for row in preview["automation_carries"]
            if row["identity"] == "ProcedureMandate:security.kev-triage-settle"
        ]
        assert mandate["loses_settle"] and mandate["new_grant"] == "propose"
        receipt = gate.json(
            "kit",
            "add",
            f"{gate.registry}:{UPGRADE_VERSION}",
            "--keep",
            "QueryDefinition:security.kev_exposure",
            "--commit",
            "--at",
            preview["coordinate"]["git_oid"],
        )
        (root / "upgrade-commit.json").write_text(json.dumps(receipt, indent=2) + "\n")
        assert receipt["status"] == "accepted", receipt
        current = gate.proof("Line:security.kev-triage")
        assert current["artifact_digest"] == old_line["artifact_digest"]
        assert current["envelope"] == old_line["envelope"]
        assert current["envelope"]["procedure"]["target"] == {
            "kind": "Procedure",
            "name": "security.kev-triage",
        }
        assert (
            gate.proof(
                "Procedure:security.kev-triage", at=current["coordinate"]["git_oid"]
            )["artifact_digest"]
            != old_proc["artifact_digest"]
        )
        assert (
            gate.card("Line:security.kev-triage").get("triggers_inactive")
            == old_inactive
        )
        assert (
            gate.proof("ProcedureMandate:security.kev-triage-settle")["envelope"][
                "grants"
            ]
            == "propose"
        )
        assert (
            gate.proof("QueryDefinition:security.kev_exposure")["envelope"]["limit"]
            == 250
        )
        gate.submit("watch-new", recipe.watch(SETTLES))
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        gate.out("line", "run", "security.kev-daily")
        capped = _wait_for_run(
            gate, "security.kev-triage", seen, 180, status="succeeded"
        )
        egress = gate.egress(capped["run"])
        assert egress["settle_outcome"] == "proposed", egress
        assert (
            egress["fallback_reason"]
            == "cruxible.settle.authority_capped_by_mandate_grant"
        )
        gate.out(
            "proposal",
            "withdraw",
            egress["proposal_id"],
            "--reason",
            "Re-grant exact settle authority.",
        )
        gate.submit("regrant", {"kind": "change_set", "members": [_settle_grant()]})
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        gate.out("line", "run", "security.kev-daily")
        settled = _wait_for_run(
            gate, "security.kev-triage", seen, 180, status="succeeded"
        )
        assert gate.egress(settled["run"])["settle_outcome"] == "settled"
        _, claim = gate.claims(
            "security.vulnerability", "security.vulnerability.kev_listed"
        )[SETTLES.lower()]
        assert "Field: security.vulnerability.kev_listed." in gate.out(
            "get", claim, "--detail", "why"
        )
        print(f"named upgrade evidence: {root}")
    finally:
        gate.close()
