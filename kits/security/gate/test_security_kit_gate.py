"""The security kit v1 release gate, end to end, offline from cisa.gov.

    CRUXIBLE_BIN=/path/to/cruxible python -m pytest kits/security/gate -q

One fresh Cruxible daemon on a scratch state root and HOME, one throwaway HTTPS OCI
registry on 127.0.0.1, the kit installed from that registry, and every step of the
release gate asserted on what the CLI shows. The KEV catalog and the CVE record
come from ``fixture-web`` (cruxible-provider-web's own ``WebFetch`` serving
vendored responses), bound to the kit's ``fetch`` Blueprint slot; nothing
contacts cisa.gov or cveawg.mitre.org. Provider installs still resolve
``cruxible-provider-web`` 0.2.1 and Python dependencies from PyPI.

Needs ``cruxible`` (the daemon and CLI under test; ``CRUXIBLE_BIN``, else the
one beside this interpreter, else ``PATH``), this interpreter with
``cruxible_client``, ``git`` and ``openssl``. Tests run in file order and share
one gate; a scratch root is kept for inspection when ``SECURITY_KIT_GATE_ROOT``
names it. ``SECURITY_KIT_GATE_CADENCE`` (seconds, default 30) sets the gate
cadence Trigger and ``SECURITY_KIT_GATE_WINDOW`` (default 240) the absent-CVE
prediction window. Results are written to ``<root>/gate-results.md``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
RELEASE_1_0 = KIT
RELEASE_1_1 = KIT / "source" / "variants" / "1.1.0"
FIXTURE_WEB = HERE / "fixture-web"
CADENCE = int(os.environ.get("SECURITY_KIT_GATE_CADENCE", "30"))
ABSENT_WINDOW = int(os.environ.get("SECURITY_KIT_GATE_WINDOW", "240"))
KEV_LISTED = "cve-2021-44228"
ABSENT = "cve-2021-44832"  # not in the fixture catalog (nor in the live one)
SETTLES = "cve-2021-45046"  # listed; graduation adds it with a stated expectation
FALLS_BACK = "cve-2017-5638"  # listed; added with no expectation
RESULTS: dict[str, tuple[str, str]] = {}
STEPS = {
    "01": "init: empty instance, seeded Triggers",
    "02": "kit add from the registry: preview by kind, commit, status",
    "03": "web.fetch implementations: default web 0.2.1 plus the fixture",
    "04": "instantiate Blueprints; unbound and mismatched refused; CVE record run",
    "05": "author Lines, Triggers, propose mandate",
    "06": "watch two CVEs, state beliefs, two prediction contracts",
    "07": "manual Line run retains a kev-http-v1 Capture; triage idle",
    "08": "enable; a Trigger change stops the enablement; re-enable",
    "09": "cadence -> capture_landing triage proposes (settle capped); no_change",
    "10": "accept; Claims cite the Capture; floor matches head",
    "11": "predictions: correct, deadline refusal, incorrect after close",
    "12": "restart: gap rows, lapsed ticks listed, dispatched, none at restart",
    "13": "measure pending; readings pending/open/expired",
    "14": "graduate by max_authority: settled under mandate, fallback to review",
    "15": "upgrade to 1.1.0 keeping a local edit; re-add; downgrade blocked",
    "16": "exit: next empty, run history",
}


def record(step: str, observed: str) -> None:
    RESULTS[step] = ("PASS", observed)


def _cruxible_bin() -> str:
    explicit = os.environ.get("CRUXIBLE_BIN")
    if explicit:
        return explicit
    beside = Path(sys.executable).with_name("cruxible")
    if beside.exists():
        return str(beside)
    found = shutil.which("cruxible")
    if found is None:
        pytest.skip("no cruxible CLI: set CRUXIBLE_BIN")
    return found


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Gate:
    """One scratch daemon, registry and workspace, and the CLI against them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = _cruxible_bin()
        self.home = root / "home"
        self.state = root / "state"
        self.ws = root / "ws"
        self.payloads = root / "payloads"
        for path in (self.home, self.state, self.ws, self.payloads):
            path.mkdir(parents=True, exist_ok=True)
        # A Unix socket path must stay short; the directory must be owner-only.
        self.run_dir = Path(tempfile.mkdtemp(prefix="kg-", dir="/tmp"))
        self.run_dir.chmod(0o700)
        self.port = _free_port()
        self.registry = f"localhost:{self.port}/kits/security"
        env = {k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")}
        env.update(
            HOME=str(self.home),
            XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_CACHE_HOME=str(self.home / ".cache"),
            CRUXIBLE_STATE_ROOT=str(self.state),
            CRUXIBLE_SERVER_SOCKET=str(self.run_dir / "d.sock"),
            CRUXIBLE_ARTIFACT_CACHE=str(self.home / ".cache" / "cruxible-artifacts"),
            GIT_AUTHOR_NAME="kit-gate",
            GIT_AUTHOR_EMAIL="kit-gate@example.invalid",
            GIT_COMMITTER_NAME="kit-gate",
            GIT_COMMITTER_EMAIL="kit-gate@example.invalid",
            UV_CACHE_DIR=os.environ.get("UV_CACHE_DIR", str(root / "uv-cache")),
        )
        self.env = env
        self.daemon: subprocess.Popen[bytes] | None = None
        self.registry_process: subprocess.Popen[bytes] | None = None
        self.values: dict[str, Any] = {}
        self.log = (root / "gate.log").open("a")

    # -- processes -------------------------------------------------------

    def start_registry(self) -> None:
        tls = self.root / "tls"
        tls.mkdir(exist_ok=True)
        openssl = shutil.which("openssl")
        assert openssl, "openssl is needed for the throwaway registry's certificate"

        def run(*args: str) -> None:
            subprocess.run([openssl, *args], check=True, capture_output=True, cwd=tls)

        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out",
            "ca.pem", "-days", "2", "-subj", "/CN=security-kit-gate-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out",
            "server.csr", "-subj", "/CN=localhost")
        (tls / "ext.cnf").write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
        )
        run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "server.pem", "-days", "2", "-extfile", "ext.cnf")
        import certifi

        bundle = tls / "bundle.pem"
        bundle.write_text(Path(certifi.where()).read_text() + (tls / "ca.pem").read_text())
        self.env["SSL_CERT_FILE"] = str(bundle)
        self.registry_process = subprocess.Popen(
            [sys.executable, str(HERE / "registry.py"), str(self.port),
             str(self.root / "registry-data"), str(tls / "server.pem"), str(tls / "server.key")],
            stdout=(self.root / "registry.log").open("ab"), stderr=subprocess.STDOUT,
        )
        self.wait(lambda: self._port_open(), 30, "registry did not listen")

    def _port_open(self) -> bool:
        with socket.socket() as probe:
            return probe.connect_ex(("127.0.0.1", self.port)) == 0

    def start_daemon(self) -> None:
        self.daemon = subprocess.Popen(
            [self.bin, "server", "start", "--socket", self.env["CRUXIBLE_SERVER_SOCKET"],
             "--state-root", str(self.state)],
            env=self.env, cwd=self.root,
            stdout=(self.root / "daemon.log").open("ab"), stderr=subprocess.STDOUT,
        )
        self.wait(lambda: self.cx("server", "status", check=False).returncode == 0, 120,
                  "daemon did not answer")

    def stop_daemon(self) -> None:
        if self.daemon is None:
            return
        self.cx("server", "stop", check=False)
        try:
            self.daemon.wait(timeout=60)
        except subprocess.TimeoutExpired:  # pragma: no cover - reap whatever is left
            self.daemon.send_signal(signal.SIGTERM)
            self.daemon.wait(timeout=30)
        self.daemon = None

    def close(self) -> None:
        try:
            self.stop_daemon()
        finally:
            if self.registry_process is not None:
                self.registry_process.terminate()
                self.registry_process.wait(timeout=30)
            shutil.rmtree(self.run_dir, ignore_errors=True)
            self.log.close()

    # -- the CLI -----------------------------------------------------------

    def load_settings(self) -> None:
        """Act as the owner `init` made, as its settings file says."""

        (settings,) = (self.home / ".config" / "cruxible" / "keys").glob("*/*/cruxible.env")
        for line in settings.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                self.env[key.strip().removeprefix("export ").strip()] = value.strip().strip("'\"")

    def cx(self, *args: str, check: bool = True, timeout: float = 600) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [self.bin, *args], env=self.env, cwd=self.ws, capture_output=True, text=True,
            timeout=timeout,
        )
        self.log.write(f"$ cruxible {' '.join(args)}\n{result.stdout}{result.stderr}(exit {result.returncode})\n")
        self.log.flush()
        if check and result.returncode != 0:
            raise AssertionError(f"cruxible {' '.join(args)} exited {result.returncode}: "
                                 f"{result.stdout[-800:]}{result.stderr[-800:]}")
        return result

    def out(self, *args: str, check: bool = True) -> str:
        return self.cx(*args, check=check).stdout

    def json(self, *args: str) -> Any:
        return json.loads(self.out(*args, "--json"))

    def py(self, script: Path, *args: str) -> str:
        result = subprocess.run([sys.executable, str(script), *args], env=self.env, cwd=self.ws,
                                capture_output=True, text=True, timeout=600)
        self.log.write(f"$ python {script.name} {' '.join(args)}\n{result.stdout}{result.stderr}\n")
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    def payload(self, name: str, value: object) -> str:
        path = self.payloads / f"{name}.json"
        path.write_text(json.dumps(value, indent=1))
        return str(path)

    def submit(self, name: str, value: object) -> dict[str, Any]:
        out = self.out("authoring", "submit", self.payload(name, value), "--and-activate")
        result = json.loads(out)
        assert "activation" in result or result.get("submit", {}).get("status", {}).get(
            "state"
        ) == "accepted", out[-600:]
        return result

    @staticmethod
    def wait(predicate: Callable[[], bool], timeout: float, message: str) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(2)
        raise AssertionError(f"timed out after {timeout:.0f}s: {message}")

    # -- reads -------------------------------------------------------------

    def card(self, ref: str) -> dict[str, Any]:
        return dict(self.json("get", ref)["card"])

    def proof(self, ref: str) -> dict[str, Any]:
        return dict(self.json("get", ref, "--detail", "proof")["proof"])

    def runs(self, line: str) -> list[dict[str, Any]]:
        return list(self.card(f"Line:{line}").get("recent_runs") or [])

    def claims(self, predicate: str) -> dict[str, tuple[Any, str]]:
        """subject_id -> (value, Claim ID) for one KEV field, from the query's Claim cells."""

        rows = self.json("query", "security.vulnerability", "--select", predicate, "--claims")["rows"]
        found = {}
        for row in rows:
            cells = (row.get("claims") or {}).get(predicate) or []
            if cells:
                value = cells[0]["value"]
                assert not (isinstance(value, dict) and value.get("truncated")), value
                found[row["subject_id"]] = (value, cells[0]["claim"])
        return found

    def egress(self, run: str) -> dict[str, Any]:
        (terminal,) = self.card(run)["terminal_egress"]
        return dict(terminal)

    def next_text(self) -> str:
        return self.out("next")

    def activate(self, proposal: str) -> None:
        assert '"failure_code": null' in self.out("proposal", "activate", proposal)

    def mandate_payload(self, name: str, grants: str, **extra: Any) -> dict[str, Any]:
        now = datetime.now(UTC).replace(microsecond=0)
        return {
            "kind": "procedure_mandate", "name": name, "procedure_name": "security.kev-triage",
            "grants": grants, "namespace": ["claims"],
            "valid_from": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
            "resource_ceiling": {"max_wall_clock": {"microseconds": 300_000_000},
                                 "max_provider_calls": 2, "max_capture_bytes": 16_777_216,
                                 "max_items": 1000, "max_repeat_attempts": 1},
            **extra,
        }


def _subject(cve: str) -> dict[str, Any]:
    return {"kind": "subject", "subject": {
        "identity": {"kind": "Subject", "name": f"security.vulnerability/{cve}"},
        "subject_id": cve, "subject_kind": "security.vulnerability", "pins": [],
        "lifecycle": {"predecessor_digest": None, "state": "live"}}}


def _expectation(cve: str) -> dict[str, Any]:
    return {"kind": "claim", "subject": f"security.vulnerability/{cve}",
            "predicate": "security.vulnerability.kev_listing_expected",
            "object": {"kind": "literal", "value": True}, "role": "normative",
            "rationale": f"The gate's stated belief that {cve.upper()} is KEV-listed.",
            "source": {"kind": "self_source", "body": f"expectation: {cve} is KEV-listed\n"}}


def _prediction(gate: Gate, name: str, cve: str, claim: str, seconds: int) -> str:
    start = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    path = gate.payload(name, {"contract": {
        "identity": {"kind": "ResolutionContract", "name": name},
        "hypothesis": claim,
        "observation": {"subject": {"tag": "playbill-semantic-address-v1",
                                    "artifact_path": f"subjects/security.vulnerability/{cve}.json",
                                    "selector": {"scheme": "artifact-v1", "value": ""}},
                        "predicate": "security.vulnerability.kev_listed"},
        "rule": {"tag": "playbill-prediction-equality-rule-v1", "operator": "equality"},
        "window": {"kind": "fixed", "starts_at": start, "duration_seconds": seconds}}})
    out = gate.out("prediction", "propose", path)
    proposal = re.search(r"Proposal: (sha256:[0-9a-f]{64})", out)
    assert proposal, out
    gate.activate(proposal.group(1))
    return start


def _wait_for_run(gate: Gate, line: str, after: set[str], timeout: float) -> dict[str, Any]:
    found: list[dict[str, Any]] = []

    def new_run() -> bool:
        fresh = [r for r in gate.runs(line) if r["run"] not in after and r["status"] != "running"]
        found[:] = fresh
        return bool(fresh)

    gate.wait(new_run, timeout, f"no new run on {line}")
    return found[0]


@pytest.fixture(scope="module")
def gate() -> Iterator[Gate]:
    explicit = os.environ.get("SECURITY_KIT_GATE_ROOT")
    root = Path(explicit) if explicit else Path(tempfile.mkdtemp(prefix="security-kit-gate-"))
    root.mkdir(parents=True, exist_ok=True)
    instance = Gate(root)
    try:
        instance.start_registry()
        subprocess.run([sys.executable, str(HERE / "publish_kit.py"), str(RELEASE_1_0),
                        f"{instance.registry}:1.0.0"], env=instance.env, check=True,
                       capture_output=True)
        instance.start_daemon()
        subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=instance.ws, check=True,
                       env=instance.env)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"], cwd=instance.ws,
                       check=True, env=instance.env)
        yield instance
    finally:
        instance.close()
        lines = ["| Step | Observable | Result | Observed |", "|---|---|---|---|"]
        for step, title in STEPS.items():
            result, observed = RESULTS.get(step, ("NOT RUN", ""))
            lines.append(f"| {step} | {title} | {result} | {observed} |")
        (root / "gate-results.md").write_text("\n".join(lines) + "\n")
        print("\n" + "\n".join(lines))


# --- the gate -----------------------------------------------------------------


def test_01_init(gate: Gate) -> None:
    out = gate.out("init", "--principal-id", "gate-owner")
    assert "Owner principal: gate-owner" in out
    gate.load_settings()
    assert "generation=0" in gate.out("orient")
    triggers = {row["name"]: row["target"] for row in gate.json("query", "Trigger")["rows"]}
    assert {"evidence-sweep", "floor-refresh", "prediction-anchor-retry"} <= set(triggers)
    record("01", f"generation 0; seeded Triggers {sorted(triggers)}")


def test_02_kit_add(gate: Gate) -> None:
    preview = gate.json("kit", "add", f"{gate.registry}:1.0.0", "--dry-run")
    assert (preview["status"], preview["transition"]) == ("would_propose", "install")
    counts: dict[str, int] = {}
    for item in preview["plan"]:
        assert item["action"] == "add", item
        kind = item["identity"].split(":", 1)[0]
        counts[kind] = counts.get(kind, 0) + 1
    assert counts == {"Blueprint": 2, "CaptureContract": 3, "ClaimType": 33, "Procedure": 1,
                      "ProviderInterface": 2, "QueryDefinition": 17,
                      "SourceAcquisitionPolicy": 1}, counts
    actions = {p["package"]: p["action"] for p in preview["providers"]}
    assert set(actions) == {"cruxible-provider-web", "security-kev-provider"}, actions
    committed = gate.json("kit", "add", f"{gate.registry}:1.0.0", "--commit",
                          "--at", preview["coordinate"]["git_oid"])
    assert committed["status"] == "accepted", committed
    status = gate.out("kit", "status")
    assert "security 1.0.0" in status and "up to date" in status, status
    (kit,) = gate.json("kit", "status")["kits"]
    delivery = {p["package"]: (p["delivery"], p["state"]) for p in kit["providers"]}
    assert delivery == {"cruxible-provider-web": ("index", "installed"),
                        "security-kev-provider": ("bundled", "installed")}, delivery
    record("02", f"preview {counts}; accepted; status 1.0.0 up to date; providers {delivery}")


def test_03_web_fetch_implementations(gate: Gate) -> None:
    wheel = next((FIXTURE_WEB / "dist").glob("kev_gate_web-*.whl"))
    out = gate.out("provider", "install", str(wheel), "--lock", str(FIXTURE_WEB / "uv.lock"))
    assert "kev-gate-web: ready" in out, out
    providers = {p["provider"] for p in gate.card("ProviderInterface:web.fetch")["providers"]}
    assert providers == {"cruxible-provider-web", "kev-gate-web"}, providers
    by_name = gate.out("provider", "install", "cruxible-provider-web==0.2.1", "--dry-run")
    assert "already" in by_name, by_name
    record("03", f"web.fetch implementations {sorted(providers)}; web 0.2.1 by name: installed")


def test_04_instantiate(gate: Gate) -> None:
    blueprint = gate.out("get", "Blueprint:security.kev-acquire")
    assert "fetch" in blueprint and "kev-gate-web" in blueprint, blueprint
    unbound = gate.cx("authoring", "submit", gate.payload("unbound", {
        "kind": "blueprint_instance", "name": "security.kev-acquire",
        "blueprint": "security.kev-acquire", "bindings": {}}), "--dry-run", check=False)
    assert "bindings" in unbound.stdout + unbound.stderr
    wrong = gate.out("authoring", "submit", gate.payload("wrong", {
        "kind": "blueprint_instance", "name": "security.kev-acquire",
        "blueprint": "security.kev-acquire", "bindings": {"fetch": "security-kev-provider"},
        "acquisition_policy": "security.kev-acquisition"}), "--dry-run")
    assert "blueprint_provider_interface_mismatch" in wrong
    gate.submit("instances", {"kind": "change_set", "rationale": "Instantiate the Blueprints.",
                              "members": [
        {"kind": "blueprint_instance", "name": name, "blueprint": name,
         "bindings": {"fetch": "kev-gate-web"}, "acquisition_policy": "security.kev-acquisition"}
        for name in ("security.kev-acquire", "security.cve-record-acquire")]})
    assert gate.card("Procedure:security.kev-acquire")["runnable"] == "line"
    assert gate.card("Procedure:security.cve-record-acquire")["runnable"] == "direct"
    origin = json.dumps(gate.proof("Procedure:security.kev-acquire"))
    released = {a["path"]: a["artifact_digest"] for a in json.loads(
        (RELEASE_1_0 / "cruxible-kit.json").read_text())["artifacts"]}
    gate.values["kev_acquire_blueprint"] = released["blueprints/security.kev-acquire.json"]
    assert gate.values["kev_acquire_blueprint"] in origin
    cve = gate.payload("cve-input", {"url": "https://cveawg.mitre.org/api/cve/CVE-2021-44228"})
    run = gate.out("procedure", "run", "security.cve-record-acquire", cve, "--evaluation-time",
                   datetime.now(UTC).isoformat())
    assert ": succeeded" in run and "Capture record:" in run, run
    record("04", "unbound refused; mismatch refused; instances runnable line/direct; Blueprint "
           "origin recorded; CVE record direct run succeeded (full URL input)")


def test_05_automation(gate: Gate) -> None:
    contract = gate.proof("CaptureContract:security.kev-http-v1")["artifact_digest"]
    gate.values["kev_contract"] = contract
    gate.submit("automation", {"kind": "change_set", "rationale": "KEV automation.", "members": [
        {"kind": "line", "name": "security.kev-daily", "procedure_name": "security.kev-acquire",
         "acquisition_policy_name": "security.kev-acquisition", "max_authority": "observe"},
        {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage",
         "acquisition_policy_name": "security.kev-acquisition", "max_authority": "propose",
         "trigger_input": "catalog"},
        {"kind": "trigger", "name": "security.kev-daily", "line_name": "security.kev-daily",
         "schedule": {"kind": "cron", "expression": "17 14 * * *"}},
        {"kind": "trigger", "name": "security.kev-landed", "line_name": "security.kev-triage",
         "schedule": {"kind": "capture_landing", "event": {
             "capture_contract_identity": {"kind": "CaptureContract",
                                           "name": "security.kev-http-v1"},
             "capture_contract_digest": contract}}},
        gate.mandate_payload("security.kev-triage-propose", "propose")]})
    line = gate.card("Line:security.kev-triage")
    assert line["triggers_inactive"] == "not enabled", line["triggers_inactive"]
    rows = gate.json("query", "Trigger", "--where", "target=Line:security.kev-triage")["rows"]
    assert [r["name"] for r in rows] == ["security.kev-landed"], rows
    record("05", "Lines, Triggers, propose mandate accepted; triage Triggers inactive (not "
           "enabled); one Trigger targets the triage Line")


def test_06_watch_and_predict(gate: Gate) -> None:
    gate.submit("watch", {"kind": "change_set", "rationale": "Watch two CVEs.", "members": [
        _subject(KEV_LISTED), _subject(ABSENT), _expectation(KEV_LISTED), _expectation(ABSENT)]})
    beliefs = gate.claims("kev_listing_expected")
    assert beliefs[KEV_LISTED][0] is True and beliefs[ABSENT][0] is True, beliefs
    _prediction(gate, f"security.kev-listing-{KEV_LISTED}", KEV_LISTED, beliefs[KEV_LISTED][1],
                86400)
    gate.values["absent_start"] = datetime.now(UTC)
    _prediction(gate, f"security.kev-listing-{ABSENT}", ABSENT, beliefs[ABSENT][1], ABSENT_WINDOW)
    for cve in (KEV_LISTED, ABSENT):
        listed = gate.out("prediction", "list", beliefs[cve][1])
        assert f"security.kev-listing-{cve}" in listed and "live" in listed, listed
        assert " open" in gate.out("get", f"ResolutionContract:security.kev-listing-{cve}")
    record("06", f"beliefs accepted; contracts live with open windows (1 d, {ABSENT_WINDOW} s)")


def test_07_manual_run(gate: Gate) -> None:
    out = gate.out("line", "run", "security.kev-daily")
    assert ": succeeded" in out, out
    capture = re.search(r"Capture catalog: (sha256:[0-9a-f]{64})", out)
    assert capture, out
    read = json.loads(gate.out("capture", "read", capture.group(1)))
    envelope = read["envelope"]
    assert read["status"] == "verified"
    assert envelope["capture_contract_digest"] == gate.values["kev_contract"]
    assert envelope["source"]["source_identity"] == "cisa.kev.catalog"
    assert envelope["commitment"]["byte_length"] <= 4 * 1024 * 1024
    assert gate.card("Line:security.kev-triage")["runs_total"] == 0
    record("07", f"manual run succeeded; Capture verified under kev-http-v1, "
           f"{envelope['commitment']['byte_length']} bytes; triage runs 0")


def test_08_enable(gate: Gate) -> None:
    for line in ("security.kev-daily", "security.kev-triage"):
        assert "enabled" in gate.out("line", "enable", line)
    gate.submit("cadence", {"kind": "trigger", "name": "security.kev-gate-cadence",
                            "line_name": "security.kev-daily",
                            "schedule": {"kind": "cadence", "interval_seconds": CADENCE}})
    states = {e["state"]: e.get("stop_reason")
              for e in gate.card("Line:security.kev-daily")["enablements"]}
    assert states == {"stopped": "trigger_changed"}, states
    assert "consumer_stalled" in gate.next_text()
    gate.values["daily_before"] = {r["run"] for r in gate.runs("security.kev-daily")}
    gate.values["triage_before"] = {r["run"] for r in gate.runs("security.kev-triage")}
    assert "enabled" in gate.out("line", "enable", "security.kev-daily")
    record("08", "both enabled; cadence Trigger stopped kev-daily (trigger_changed), next named "
           "the repair; re-enabled")


def test_09_triggers_fire(gate: Gate) -> None:
    daily = _wait_for_run(gate, "security.kev-daily", gate.values["daily_before"], CADENCE * 3 + 60)
    triage = _wait_for_run(gate, "security.kev-triage", gate.values["triage_before"], 120)
    # Hold the cadence while the proposal is reviewed, so the next tick reads accepted state.
    gate.out("line", "disable", "security.kev-daily")
    assert daily["status"] == "succeeded" and triage["status"] == "succeeded", (daily, triage)
    proof = json.dumps(gate.proof(f"ProcedureRun:{daily['run']}"))
    assert '"cadence"' in proof
    egress = gate.egress(triage["run"])
    assert egress["kind"] == "settle_change_set"
    assert egress["settle_outcome"] == "proposed", egress
    assert egress["fallback_reason"] == "cruxible.settle.authority_capped_by_line_max_authority"
    assert len(egress["target_paths"]) == 5, egress["target_paths"]
    assert gate.json("orient")["attention"]["open_proposals"] == 1
    gate.values["proposal"] = egress["proposal_id"]
    gate.values["first_triage"] = triage["run"]
    record("09", "cadence tick -> capture_landing triage: settle capped by line_max_authority, "
           "proposed 5 Claims; open_proposals=1")


def test_10_accept_and_floor(gate: Gate) -> None:
    review = gate.out("proposal", "review", gate.values["proposal"])
    assert "Candidate:" in review
    gate.activate(gate.values["proposal"])
    listed = gate.claims("kev_listed")
    assert listed[KEV_LISTED][0] is True and listed[ABSENT][0] is False, listed
    added = gate.claims("kev_date_added")
    assert added[KEV_LISTED][0] == "2021-12-10", added
    gate.values["listed_claim"] = listed[KEV_LISTED][1]
    gate.values["absent_claim"] = listed[ABSENT][1]
    evidence = gate.out("get", listed[ABSENT][1], "--detail", "evidence")
    assert "CaptureContract:security.kev-http-v1" in evidence, evidence
    head = gate.json("orient")["coordinate"]["git_oid"]

    def floor_current() -> bool:
        manifest = gate.ws / ".cruxible" / "floor" / "manifest.json"
        return manifest.exists() and json.loads(manifest.read_text())["coordinate"]["git_oid"] == head

    gate.wait(floor_current, 60, "floor not delivered at head")
    floor = "".join(p.read_text() for p in (gate.ws / ".cruxible/floor/current").rglob("*.yaml"))
    assert listed[KEV_LISTED][1] in floor and listed[ABSENT][1] in floor
    # Idempotence: the next tick re-reads the same catalog and changes nothing.
    before = {r["run"] for r in gate.runs("security.kev-triage")}
    gate.out("line", "enable", "security.kev-daily")
    rerun = _wait_for_run(gate, "security.kev-triage", before, CADENCE * 3 + 60)
    assert rerun["status"] == "halted", rerun
    assert "reason=no_change" in gate.out("get", rerun["run"])
    assert "No repair work" in gate.next_text()
    record("10", "accepted; kev_listed true/false cite the kev-http-v1 Capture; floor manifest at "
           "head; next tick halted no_change; next empty")


def test_11_predictions(gate: Gate) -> None:
    out = gate.out("prediction", "settle", f"security.kev-listing-{KEV_LISTED}",
                   "--observation", gate.values["listed_claim"])
    assert "Outcome: True" in out, out
    late = f"security.kev-listing-{KEV_LISTED}-late"
    beliefs = gate.claims("kev_listing_expected")
    _prediction(gate, late, KEV_LISTED, beliefs[KEV_LISTED][1], 86400)
    refused = gate.cx("prediction", "settle", late, "--observation", gate.values["listed_claim"],
                      check=False)
    assert "prediction_deadline_passed" in refused.stdout + refused.stderr
    record("11", "Log4Shell settled True; an observation accepted before the contract refused "
           "prediction_deadline_passed (absent CVE settles in step 16)")


def test_12_restart(gate: Gate) -> None:
    gate.stop_daemon()
    stopped = datetime.now(UTC)
    time.sleep(CADENCE * 2 + 15)
    gate.start_daemon()
    restarted = datetime.now(UTC)
    text = gate.next_text()
    gaps = re.findall(r"cruxible line evaluate (\S+) --since (\S+) --until (\S+)", text)
    assert {g[0] for g in gaps} == {"security.kev-daily", "security.kev-triage"}, text
    daily = next(g for g in gaps if g[0] == "security.kev-daily")
    dry = gate.json("line", "evaluate", daily[0], "--since", daily[1], "--until", daily[2],
                    "--dry-run")
    ticks = [o for o in dry["occurrences"] if o["binding"]["kind"] == "cadence"]
    assert dry["status"] == "met" and len(ticks) >= 2, dry
    until = datetime.fromisoformat(daily[2])
    lapsed = sorted(datetime.fromisoformat(o["eligible_at"]) for o in ticks)
    assert lapsed[-1] < until and lapsed[0] > stopped - timedelta(seconds=CADENCE), lapsed
    for line, since, until_ in gaps:
        gate.out("line", "evaluate", line, "--since", since, "--until", until_)
    assert "line_work_pending" in gate.next_text()
    before = {r["run"] for r in gate.runs("security.kev-triage")}
    dispatched = gate.out("line", "dispatch", "security.kev-daily")
    assert dispatched.count("admitted run=") == len(ticks), dispatched

    def triage_caught_up() -> bool:
        return len([r for r in gate.runs("security.kev-triage")
                    if r["run"] not in before and r["status"] == "halted"]) >= len(ticks)

    gate.wait(triage_caught_up, 180, "triage did not run on the backfilled Captures")
    assert "line_coverage_gap" not in gate.next_text()
    # No tick at the restart instant: every cadence occurrence after the gap continues
    # the chain (the last lapsed tick plus the interval), never the restart itself.
    gate.wait(lambda: any(datetime.fromisoformat(r["started_at"]) > until + timedelta(seconds=5)
                          and r["run"] not in dispatched for r in gate.runs("security.kev-daily")),
              CADENCE * 2 + 60, "no forward tick after the restart")
    forward = []
    for run in gate.runs("security.kev-daily"):
        if run["run"] in dispatched:
            continue  # a backfilled tick is evaluated when dispatched
        receipt = gate.proof(f"ProcedureRun:{run['run']}").get("receipt") or {}
        instant = receipt.get("occurrence_evaluation_time")
        if instant and datetime.fromisoformat(instant) > lapsed[-1] + timedelta(seconds=1):
            forward.append(datetime.fromisoformat(instant))
    assert forward and min(forward) >= lapsed[-1] + timedelta(seconds=CADENCE - 1), (
        lapsed, forward, restarted)
    record("12", f"gap rows for both Lines; dry-run listed {len(ticks)} lapsed cadence ticks; "
           "dispatched, triage halted no_change on each landing; first forward tick "
           f"{(min(forward) - lapsed[-1]).total_seconds():.0f}s after the last lapsed one, none "
           "at the restart")


def test_13_measure(gate: Gate) -> None:
    out = gate.out("procedure", "measure", "security.kev-triage", "--run-id",
                   gate.values["first_triage"])
    assert "kev-backlog-cleared: pending" in out, out
    now = datetime.now(UTC)
    states = []
    for offset in (0, 4, 11):
        at = (now + timedelta(days=offset)).isoformat()
        line = gate.out("procedure", "readings", "security.kev-triage", "--subject-grain",
                        "procedure_unit", "--evaluation-time", at)
        states.append(line.split(":", 1)[1].split()[0])
    assert states == ["pending", "open", "expired"], states
    record("13", f"measure pending; readings at +0/+4/+11 days {states}")


def test_14_graduate(gate: Gate) -> None:
    before = gate.proof("Procedure:security.kev-triage")["procedure_artifact_digest"]
    gate.submit("graduate", {"kind": "change_set", "rationale": "Graduate to settle.", "members": [
        gate.mandate_payload(
            "security.kev-triage-settle", "settle",
            scope=[{"claim_type": f"security.vulnerability.{field}",
                    "change_kinds": ["create", "revise"]}
                   for field in ("kev_listed", "kev_date_added", "kev_due_date",
                                 "kev_ransomware_use")],
            condition={"query_name": "security.kev_settle_condition",
                       "binding_parameter": "vulnerability_id",
                       "required_fields": ["kev_listing_expected"], "fallback": "propose"}),
        {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage",
         "acquisition_policy_name": "security.kev-acquisition", "max_authority": "settle",
         "trigger_input": "catalog"}]})
    after = gate.proof("Procedure:security.kev-triage")["procedure_artifact_digest"]
    assert before == after
    line = gate.card("Line:security.kev-triage")
    assert line["authority"] == "settle"
    assert any(e.get("stop_reason") == "line_changed" for e in line["enablements"])
    gate.out("line", "enable", "security.kev-triage")
    mandate = gate.proof("ProcedureMandate:security.kev-triage-settle")["artifact_digest"]

    def watch(cve: str, expect: bool) -> dict[str, Any]:
        seen = {r["run"] for r in gate.runs("security.kev-triage")}
        members = [_subject(cve)] + ([_expectation(cve)] if expect else [])
        gate.submit(f"watch-{cve}", {"kind": "change_set", "rationale": f"Watch {cve}.",
                                     "members": members})
        found: list[dict[str, Any]] = []

        def changed() -> bool:
            for run in gate.runs("security.kev-triage"):
                if run["run"] not in seen and run["status"] == "succeeded":
                    found.append(gate.egress(run["run"]))
                    return True
            return False

        gate.wait(changed, CADENCE * 3 + 60, f"no triage run changed {cve}")
        return found[0]

    settled = watch(SETTLES, True)
    assert settled["settle_outcome"] == "settled", settled
    assert settled["procedure_mandate_digest"] == mandate and settled["accepted_git_oid"]
    assert gate.claims("kev_listed")[SETTLES][0] is True
    fallback = watch(FALLS_BACK, False)
    assert fallback["settle_outcome"] == "proposed", fallback
    assert fallback["fallback_reason"] == "cruxible.settle.condition_incomplete", fallback
    gate.activate(fallback["proposal_id"])
    assert gate.claims("kev_listed")[FALLS_BACK][0] is True
    gate.out("line", "disable", "security.kev-daily")
    record("14", "Procedure digest unchanged; authority settle; enablement stopped line_changed; "
           f"{SETTLES} settled under the mandate; {FALLS_BACK} fell back (condition_incomplete)")


def test_15_upgrade(gate: Gate) -> None:
    gate.py(HERE / "edit_kev_exposure.py", "250")
    assert "edited locally: query-definitions/security.kev_exposure.json" in gate.out("kit", "status")
    subprocess.run([sys.executable, str(HERE / "publish_kit.py"), str(RELEASE_1_1),
                    f"{gate.registry}:1.1.0"], env=gate.env, check=True, capture_output=True)
    assert "latest 1.1.0 available" in gate.out("kit", "status")
    preview = gate.json("kit", "add", f"{gate.registry}:1.1.0", "--dry-run")
    assert (preview["status"], preview["transition"]) == ("would_propose", "upgrade")
    changes = {i["identity"]: (i["action"], i["consequence"]) for i in preview["plan"]
               if i["action"] != "unchanged"}
    assert changes == {
        "Blueprint:security.kev-acquire": ("replace", None),
        "ClaimType:security.vulnerability.kev_cwes": ("add", None),
        "QueryDefinition:security.kev_exposure": ("replace", "overwrites_your_edit"),
    }, changes
    committed = gate.json("kit", "add", f"{gate.registry}:1.1.0", "--keep",
                          "QueryDefinition:security.kev_exposure", "--commit", "--at",
                          preview["coordinate"]["git_oid"])
    assert committed["status"] == "accepted", committed
    status = gate.out("kit", "status")
    assert "security 1.1.0" in status and "kept: QueryDefinition:security.kev_exposure" in status
    again = gate.json("kit", "add", f"{gate.registry}:1.1.0", "--dry-run")
    assert again["status"] == "unchanged", again
    down = gate.json("kit", "add", f"{gate.registry}:1.0.0", "--dry-run")
    assert (down["status"], down["transition"]) == ("would_block", "downgrade"), down
    kept = gate.proof("QueryDefinition:security.kev_exposure")["envelope"]
    assert kept["default_budgets"]["max_results"] == 250
    origin = json.dumps(gate.proof("Procedure:security.kev-acquire"))
    assert gate.values["kev_acquire_blueprint"] in origin
    record("15", "upgrade preview: Blueprint replace, kev_cwes add, kev_exposure overwrites your "
           "edit; --keep committed; status 1.1.0 kept; re-add unchanged; 1.0.0 would_block "
           "(downgrade); Procedure keeps Blueprint@1.0.0")


def test_16_exit(gate: Gate) -> None:
    closes = gate.values["absent_start"] + timedelta(seconds=ABSENT_WINDOW + 5)
    time.sleep(max(0.0, (closes - datetime.now(UTC)).total_seconds()))
    gate.wait(lambda: "prediction_settleable" in gate.next_text(), 120,
              "no prediction_settleable row")
    row = re.search(r"cruxible prediction settle (RSC-[0-9a-f]+)", gate.next_text())
    assert row, gate.next_text()
    out = gate.out("prediction", "settle", row.group(1), "--observation",
                   gate.values["absent_claim"])
    assert "Outcome: False" in out, out
    gate.wait(lambda: "No repair work" in gate.next_text(), 60, "next not empty")
    kinds = set()
    for run in gate.runs("security.kev-daily") + gate.runs("security.kev-triage"):
        proof = json.dumps(gate.proof(f"ProcedureRun:{run['run']}"))
        kinds |= {k for k in ("cadence", "capture_landing") if f'"{k}"' in proof}
        if '"enablement"' not in json.dumps(gate.card(run["run"]).get("triggered_by")):
            kinds.add("manual")
    assert {"manual", "cadence", "capture_landing"} <= kinds, kinds
    record("16", f"absent CVE settled False after its window closed; next empty; run history "
           f"{sorted(kinds)} plus dispatched backfill")
