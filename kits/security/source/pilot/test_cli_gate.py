"""The committed kit on a real Cruxible 0.6 daemon, through the public CLI only.

One instance, set up as the README says, carries the whole supported path:

1. ``cruxible init --require-independent-approval`` (no reviewer key directory),
   ``kit add`` of the committed directory (each provider install and the
   definitions approved by the reviewer), the committed ``automation.json``
   submitted verbatim (``expires: 90d``, ``scope: observations``) and approved,
   and ``cruxible line enable security.osv-unkeyed --runbook security.start``
   enabling all seven Lines in one command;
2. the SBOM import settles; an IT asset and the inventory's link are written; an
   app-level not_affected judgment pinned with ``based_on`` to
   ``it.asset/<slug>#exposure`` and the occurrence's scope stays quiet in ``next``
   and comes back as ``claim_dependency_stale`` when the exposure flips;
3. upgrading the package in the SBOM moves the old release's judgment out of
   ``security.app_not_affected_judgments`` into the departed list;
4. a rebuilt pure ``@derive`` build of ``security-osv-provider`` installed with
   ``provider install --move``: one proposal moves every Line bound to the old
   build; a settle grant that creates no Subjects keeps settle and its Line's
   enablement, and a grant that creates Subjects (the shipped SBOM grant) demotes
   and says why.

It needs the network for provider installs (the locks' registry dependencies and
the published web build come from PyPI) and takes a few minutes, so it runs only
with ``CRUXIBLE_KIT_E2E=1``; nothing reaches OSV, CISA or FIRST.

    CRUXIBLE_KIT_E2E=1 CRUXIBLE_BIN=$(which cruxible) python -m pytest test_cli_gate.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))

pytestmark = pytest.mark.skipif(
    os.environ.get("CRUXIBLE_KIT_E2E") != "1",
    reason="the CLI gate installs providers from PyPI: set CRUXIBLE_KIT_E2E=1",
)

DEMO_SBOM = KIT / "examples" / "sboms" / "log4j-demo-app.cdx.json"
DEMO_APP = "pkg:maven/com.example/log4j-demo-app@1.0.0"
CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
FIXED_CORE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
LOG4SHELL = "CVE-2021-44228"
ASSET = "payments-api"
SBOM_LINE = "security.sbom-import.app"
OSV_PROVIDER = "security-osv-provider"


class Instance:
    """One workspace, daemon and owner, with the reviewer ``init`` made."""

    def __init__(self, root: Path) -> None:
        from build_release import Session

        self.session = Session(root)
        self.root = self.session.root
        self.workspace = self.session.workspace

    def run(self, *args: str, reviewer: bool = False, check: bool = True) -> Any:
        if not reviewer:
            return self.session.command(*args, check=check)
        env = dict(self.session.env, CRUXIBLE_PRINCIPAL_ID="reviewer")
        saved, self.session.env = self.session.env, env
        try:
            return self.session.command(*args, check=check)
        finally:
            self.session.env = saved

    def approve(self, proposal: str) -> Any:
        """The reviewer, a second principal, approves (and so activates) a proposal."""

        return self.run("proposal", "approve", proposal, "--yes", "--json", reviewer=True)

    def write_file(self, relative: str, content: bytes) -> None:
        path = self.workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def write(self, name: str, request: dict[str, Any]) -> Any:
        """``cruxible write FILE`` as the owner, then the reviewer's approval."""

        request = dict(request)
        # A write file states no acceptance: --no-accept is the CLI's accept: never.
        never = request.pop("accept", None) == "never"
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(request, indent=1) + "\n")
        written = self.run("write", str(path), *(["--no-accept"] if never else []), "--json")
        proposal = written.get("proposal", {}).get("proposal_id")
        assert proposal, written
        self.approve(proposal)
        return written

    def query(self, name: str, **params: str) -> list[dict[str, Any]]:
        args = ["query", "--name", name, "--json"]
        for key, value in params.items():
            args += ["--param", f"{key}={value}"]
        return list(self.run(*args)["rows"])

    def next_rows(self, reason: str) -> list[dict[str, Any]]:
        return [row for row in self.run("next", "--json").get("items", ()) if row.get("reason") == reason]


@pytest.fixture(scope="module")
def instance() -> Iterator[Instance]:
    # The daemon socket needs a short path; pytest's temporary directories can exceed it.
    root = Path(tempfile.mkdtemp(prefix="crux-kit-"))
    shutil.rmtree(root)
    world = Instance(root)
    world.session.start()
    try:
        yield world
    finally:
        world.session.stop()
        shutil.rmtree(root, ignore_errors=True)


def _carry(moved: dict[str, Any], mandate: str) -> dict[str, Any]:
    (carry,) = [c for c in moved["automation_carries"] if c["identity"] == f"ProcedureMandate:{mandate}"]
    return carry


def _outcomes(enabled: dict[str, Any]) -> dict[str, str]:
    return {row["line"]: row["enablement"]["outcome"] for row in enabled["lines"]}


def test_the_committed_kit_runs_the_supported_path_on_a_real_daemon(instance: Instance) -> None:
    # -- 1. Set up as the README says: one-command reviewer, kit add, the template.
    init = instance.run(
        "init",
        "--principal-id",
        "owner",
        "--key-dir",
        str(instance.root / "keys/owner"),
        "--require-independent-approval",
        "--workspace",
        str(instance.workspace),
        "--json",
    )
    assert init["approval_policy_mode"] == "independent_approval_required"
    assert init["reviewer_principal_id"] == "reviewer"
    assert Path(init["reviewer_private_key_path"]).is_file()
    instance.approve(init["base_kit"]["proposal_id"])
    preview = instance.run("kit", "add", str(KIT), "--json")
    committed = instance.run(
        "kit", "add", str(KIT), "--commit", "--at", preview["coordinate"]["git_oid"], "--json"
    )
    assert {p["provider_id"] for p in committed["providers"]} == {
        "cruxible-provider-web",
        OSV_PROVIDER,
        "security-sarif-provider",
    }
    for provider in committed["providers"]:
        instance.approve(provider["proposal_id"])
    (resume,) = instance.run("kit", "status", "--offline", "--json")["resumes"]
    instance.approve(resume["proposal_id"])
    kits = instance.run("kit", "status", "--offline", "--json")["kits"]
    assert {k["kit_id"]: k["version"] for k in kits} == {"base": "1.0.0", "security": "1.4.0"}

    template = instance.root / "automation.json"
    shutil.copyfile(KIT / "automation.json", template)
    submitted = instance.run("authoring", "submit", str(template), "--no-accept", "--json")
    assert submitted["outcome"]["status"] == "proposed", submitted["outcome"]
    instance.approve(submitted["outcome"]["proposal_id"])
    # expires: 90d with no valid_from: the window opened at submission.
    for name in ("security.kev-triage-settle", "security.epss-triage-settle", f"{SBOM_LINE}-settle"):
        card = instance.run("get", f"Mandate:{name}", "--json")["card"]
        assert card["grants"] == "settle" and card["state"] == "active", card
        assert card["valid_from"][:10] == submitted["intent"]["canonical_timestamp"][:10]
    # scope: observations lowered to the exact per-ClaimType scope KEV writes.
    kev = instance.run("get", "Mandate:security.kev-triage-settle", "--json")["card"]
    assert {item["claim_type"] for item in kev["scope"]} == {
        f"ClaimType:security.vulnerability.{field}"
        for field in ("listed_in", "kev_date_added", "kev_due_date", "kev_ransomware_use")
    }, kev["scope"]

    enabled = instance.run(
        "line", "enable", "security.osv-unkeyed", "--runbook", "security.start", "--json"
    )
    assert _outcomes(enabled) == {
        line: "enabled"
        for line in (
            "security.osv-unkeyed",
            SBOM_LINE,
            "security.osv-query",
            "security.kev-triage",
            "security.epss-triage",
            "security.exposure-attention.unjudged",
            "security.exposure-attention.contested",
        )
    }

    # -- 2. The SBOM import settles; a judgment pinned to the asset's exposure.
    instance.write_file("sbom.cdx.json", DEMO_SBOM.read_bytes())
    assert instance.run("line", "run", SBOM_LINE, "--json")["status"] == "succeeded"
    rows = instance.query("security.inventory_components", inventory=f"security.inventory/{DEMO_APP}")
    (occurrence,) = [r["occurrence"] for r in rows if r["purl"] == CORE]

    def stated(field: str, value: str) -> dict[str, Any]:
        return {"op": "set", "subject": {"created": "asset"}, "field": field, "value": value}

    instance.write("asset", {
        "because": "Payments API runs in prod behind the internal load balancer only.",
        "changes": [
            {"op": "create", "label": "asset", "subject_kind": "it.asset",
             "key": [{"predicate": "it.asset.slug", "value": ASSET}]},
            stated("title", "Payments API"), stated("owner", "payments-team"),
            stated("environment", "prod"), stated("exposure", "internal"),
            stated("criticality", "critical"),
            {"op": "set", "subject": f"security.inventory/{DEMO_APP}", "field": "asset",
             "value": {"created": "asset"}},
        ],
    })
    import triage

    judgment = triage.app_judgment(
        occurrence,
        LOG4SHELL,
        reason="vulnerable_code_cannot_be_controlled_by_adversary",
        because="Internal-only service: no untrusted client reaches the JNDI lookup.",
        based_on=[
            triage.asset_exposure(ASSET),
            triage.pin(f"security.occurrence/{occurrence}", "scope"),
        ],
    )
    # No OSV run here (nothing reaches OSV): the write creates the vulnerability by key.
    judgment["changes"].insert(0, {
        "op": "create", "label": "vulnerability", "subject_kind": "security.vulnerability",
        "key": [{"predicate": "security.vulnerability.cve_id", "value": LOG4SHELL}],
    })
    for part in judgment["changes"][1]["key"]:
        if part["predicate"].endswith(".vulnerability"):
            part["value"] = {"created": "vulnerability"}
    judged = instance.write("judgment", judgment)
    assert judged["status"] == "awaiting_approval"  # written with --no-accept
    (justification,) = [c["claim"] for c in judged["changes"] if c.get("field") == "justification"]
    current = instance.query("security.app_not_affected_judgments")
    assert [(r["component"], r["cve_id"]) for r in current] == [(CORE, LOG4SHELL)]
    assert instance.next_rows("claim_dependency_stale") == []
    # The SBOM re-observed unchanged: still quiet.
    assert instance.run("line", "run", SBOM_LINE, "--json")["status"] == "succeeded"
    assert instance.next_rows("claim_dependency_stale") == []

    exposed = instance.write("exposed", {
        "because": "The payments API now has a public ingress.",
        "changes": [{"op": "set", "subject": f"it.asset/{ASSET}", "field": "exposure",
                     "value": "internet"}],
    })
    (exposure,) = [c["claim"] for c in exposed["changes"]]
    (stale,) = instance.next_rows("claim_dependency_stale")
    assert stale["subject_identity"] == f"Claim:{justification}", stale
    (pinned,) = stale["detail"]["stale_inputs"]
    assert pinned["pin_role"] == "based-on"
    assert pinned["source_claim_identity"] == f"Claim:{exposure}", pinned

    # -- 3. Upgrading the package moves the old release's judgment out of the view.
    document = json.loads(DEMO_SBOM.read_bytes())
    for item in document["components"]:
        if item.get("purl") == CORE:
            item["purl"], item["version"] = FIXED_CORE, "2.17.1"
    instance.write_file("sbom.cdx.json", json.dumps(document).encode())
    assert instance.run("line", "run", SBOM_LINE, "--json")["status"] == "succeeded"
    assert instance.query("security.app_not_affected_judgments") == []
    (departed,) = instance.query("security.departed_app_not_affected_judgments")
    assert (departed["component"], departed["cve_id"]) == (CORE, LOG4SHELL)

    # -- 4. A rebuilt pure @derive build of the OSV provider, installed with --move.
    # The inventory exists now: the operator re-grants the SBOM Line without
    # subject_creation (new packages then go to review), so that grant creates no
    # Subjects and may follow a pure build move; the OSV Line's grant still creates
    # vulnerabilities.
    import inventory

    regrant = instance.root / "regrant.json"
    regrant.write_text(json.dumps({
        "kind": "change_set",
        "rationale": "Settle the SBOM's scope observations; new Subjects go to review.",
        "members": [{
            "kind": "procedure_mandate", "name": f"{SBOM_LINE}-settle", "line_name": SBOM_LINE,
            "grants": "settle", "namespace": ["claims"], "expires": "90d",
            "scope": [
                {"claim_type": t, "changes": c} for t, c in inventory.SBOM_SETTLE_SCOPE.items()
            ],
        }],
    }))
    regranted = instance.run("authoring", "submit", str(regrant), "--no-accept", "--json")
    instance.approve(regranted["outcome"]["proposal_id"])

    build = instance.root / "osv-build"
    shutil.copytree(
        KIT / "source/providers/security-osv-provider",
        build,
        ignore=shutil.ignore_patterns("tests", "dist", ".venv", "__pycache__"),
    )
    sbom = build / "src/security_osv_provider/sbom.py"
    sbom.write_text(sbom.read_text() + "\n# A rebuilt build: the same operations, new bytes.\n")
    subprocess.run(
        ["uv", "build", "--wheel", "--offline", "--out-dir", str(build / "dist"), str(build)],
        check=True,
        capture_output=True,
        env=dict(instance.session.env),
    )
    (wheel,) = (build / "dist").glob("*.whl")
    (runtime,) = (KIT / "providers").glob("cruxible_provider_runtime-*.whl")
    (lock,) = (KIT / "providers").glob(f"{OSV_PROVIDER}-*.uv.lock")
    moved = instance.run(
        "provider", "install", str(wheel), "--lock", str(lock), "--dependency", str(runtime),
        "--move", "--commit", "--json",
    )
    assert moved["status"] == "awaiting_approval", moved
    # ONE proposal moves every Line bound to the old build.
    assert {m["identity"] for m in moved["moved"]} == {
        f"Line:{SBOM_LINE}", "Line:security.osv-query", "Line:security.osv-unkeyed"
    }
    assert {m["to_build"] for m in moved["moved"]} == {moved["build"]}
    kept = _carry(moved, f"{SBOM_LINE}-settle")
    assert (kept["old_grant"], kept["new_grant"]) == ("settle", "settle"), kept
    assert sorted(kept["retained_scope"]) == sorted(inventory.SBOM_SETTLE_SCOPE)
    assert kept["carries_line_enablement"] is True
    demoted = _carry(moved, "security.osv-query-settle")
    assert (demoted["new_grant"], demoted["demotion"]) == ("propose", "subject_creation")
    instance.approve(moved["proposal_id"])

    # The SBOM Line stayed enabled on its successor; the OSV Line asks to be enabled again.
    assert _outcomes(
        instance.run("line", "enable", SBOM_LINE, "security.osv-query", "--dry-run", "--json")
    ) == {SBOM_LINE: "already_enabled", "security.osv-query": "would_enable"}
    # And it still settles, now on the new build: a scope the SBOM changes revises.
    for item in document["components"]:
        if item.get("name") == "slf4j-api":
            item["scope"] = "optional"
    instance.write_file("sbom.cdx.json", json.dumps(document).encode())
    ran = instance.run("line", "run", SBOM_LINE, "--json")
    assert ran["status"] == "succeeded"
    assert '"settled"' in json.dumps(ran), "the moved Line's run did not settle"
    scopes = {
        r["purl"]: r["scope"]
        for r in instance.query(
            "security.inventory_components", inventory=f"security.inventory/{DEMO_APP}"
        )
    }
    assert scopes["pkg:maven/org.slf4j/slf4j-api@1.7.32"] == "optional"

    # -- 5. The VEX export through cruxible_client, pinned to one coordinate.
    # An own-words affected_by on the upgraded release puts one pair on the worklist.
    instance.write("seed", {
        "because": "Seed: the 2.17.1 release is listed for CVE-2021-44228 (gate stand-in for OSV).",
        "changes": [{"op": "add", "subject": f"security.component/{FIXED_CORE}",
                     "field": "affected_by", "value": f"security.vulnerability/{LOG4SHELL.lower()}",
                     "role": "normative"}],
    })
    exporter = str(KIT / "examples" / "export_vex.py")
    for fmt in ("openvex", "cyclonedx"):
        first = instance.run("python", exporter, "--format", fmt)
        assert instance.run("python", exporter, "--format", fmt) == first  # same coordinate
        if fmt == "openvex":
            (statement,) = first["statements"]
            assert statement["vulnerability"]["name"] == LOG4SHELL
            assert statement["products"] == [{"@id": DEMO_APP, "subcomponents": [{"@id": FIXED_CORE}]}]
            assert statement["status"] == "under_investigation"
            assert "CLM-" in statement["status_notes"]
        else:
            (vulnerability,) = first["vulnerabilities"]
            assert vulnerability["analysis"]["state"] == "in_triage"
            coordinate = {p["name"]: p["value"] for p in first["metadata"]["properties"]}
            assert coordinate["cruxible:instance_id"] == init["trust_root"]["instance_id"]
            claims = [p["value"].split(" ", 1)[0] for p in vulnerability["properties"]
                      if p["name"] == "cruxible:claim"]
            assert claims and all(instance.run("get", c, "--json") for c in claims)

