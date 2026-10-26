"""Upgrade a retained, stopped K1a scratch world; never author new Blueprints on 36.

The runner's sibling k1b/legacy-template is a copy of the accepted K1a gate world.
SECURITY_KIT_LEGACY_WORLD can select another stopped pre-fold gate world. Each run
copies it before starting a daemon. The copied registry initially names the old
scratch workspace; before public detach/attach finishes, startup floor delivery
may advertise there. The copied ledger and projections remain isolated.
No compiler selector, law, stored artifact, projection or ledger is patched.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from test_security_kit_gate import Gate, KIT


def test_upgrade_retires_all_nine_installed_blueprints_without_keep():
    parent = Path(os.environ["SECURITY_KIT_GATE_ROOT"]).parent
    template = Path(
        os.environ.get("SECURITY_KIT_LEGACY_WORLD", parent / "k1b/legacy-template")
    )
    assert template.is_dir(), (
        "Supply the stopped pre-fold scratch world; see this file's docstring."
    )
    root = Path(tempfile.mkdtemp(prefix="blueprint-retirement-", dir=parent))
    for name in ("home", "state", "ws"):
        shutil.copytree(template / name, root / name, symlinks=True)
    gate = Gate(root)
    try:
        gate.start_daemon()
        gate.load_settings()
        gate.env["CRUXIBLE_SERVER_SOCKET"] = str(gate.run_dir / "d.sock")
        # Detach/attach only the copied host registration through public surfaces.
        # Use an unattached cwd for detach so the copied old workspace marker is not selected.
        workspace = gate.ws
        gate.ws = root
        gate.out(
            "workspace", "detach", "--instance-id", gate.env["CRUXIBLE_INSTANCE_ID"]
        )
        gate.ws = workspace
        gate.out(
            "workspace",
            "attach",
            "--instance-id",
            gate.env["CRUXIBLE_INSTANCE_ID"],
            "--replace",
            "--no-floor-delivery",
        )
        names = (
            "kev-acquire",
            "cve-record-acquire",
            "epss-acquire",
            "osv-applicability",
            "repo-acquire",
            "registry-acquire",
            "release-acquire",
            "asset-fetch",
            "history-acquire",
        )
        before = {
            "security." + name: gate.proof("Blueprint:security." + name)
            for name in names
        }
        assert all(
            p["envelope"]["lifecycle"]["state"] == "live" for p in before.values()
        )
        historical_card = gate.card("Blueprint:security.kev-acquire")
        assert "fits" not in historical_card
        assert "parameters" not in historical_card.get("inputs", {})
        preview = gate.json("kit", "add", str(KIT), "--dry-run")
        (root / "retirement-preview.json").write_text(
            json.dumps(preview, indent=2) + "\n"
        )
        assert preview["status"] == "would_propose", preview
        drops = [r for r in preview["plan"] if r["identity"].startswith("Blueprint:")]
        assert len(drops) == 9 and all(r["action"] == "retire" for r in drops), drops
        receipt = gate.json(
            "kit", "add", str(KIT), "--commit", "--at", preview["coordinate"]["git_oid"]
        )
        (root / "retirement-commit.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        assert receipt["status"] == "accepted", receipt
        for name, previous in before.items():
            current = gate.proof("Blueprint:" + name)
            artifact = current["envelope"]
            assert artifact["lifecycle"]["state"] == "retired"
            assert (
                artifact["lifecycle"]["predecessor_digest"]
                == previous["artifact_digest"]
            )
            old = previous["envelope"]
            assert {k: v for k, v in artifact.items() if k != "lifecycle"} == {
                k: v for k, v in old.items() if k != "lifecycle"
            }
        assert {r["identity"] for r in drops} == {
            "Blueprint:" + name for name in before
        }
        print(f"Blueprint retirement evidence: {root}")
    finally:
        gate.close()
