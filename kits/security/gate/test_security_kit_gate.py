"""The security kit v1 release gate, end to end, offline from every security source.

    CRUXIBLE_BIN=/path/to/cruxible python -m pytest kits/security/gate -q

One fresh Cruxible daemon on a scratch state root and HOME, one throwaway HTTPS OCI
registry on 127.0.0.1, the kit installed from that registry, and every step of the
release gate asserted on what the CLI shows. The KEV catalog, CVE record, OSV
answers, EPSS file and the system model's GitHub and PyPI answers come from
``fixture-sources`` (``security-gate-sources``: cruxible-provider-web's own
``WebFetch`` and the kit's own Source adapters, serving vendored responses), bound
to the kit's Blueprint slots; nothing contacts cisa.gov, cveawg.mitre.org,
api.osv.dev, the EPSS site, GitHub or PyPI. Provider installs still
resolve ``cruxible-provider-web`` 0.2.2 and Python dependencies from PyPI.

Needs ``cruxible`` (the daemon and CLI under test; ``CRUXIBLE_BIN``, else the
one beside this interpreter, else ``PATH``), this interpreter with
``cruxible_client``, ``git`` and ``openssl``. Tests run in file order and share
one gate; a scratch root is kept for inspection when ``SECURITY_KIT_GATE_ROOT``
names it. The gate starts on 1.3.0 and upgrades to the 1.3.1 gate variant with a
changed bundled analysis Provider build and live consumer automation, then runs
the system model's scenarios (steps 21-27), the code findings' (steps 28-34,
under independent approval with five principals) and an incident response
(steps 35-42, PHP2Shell: patch, audit, rotate) on the upgraded instance.
``SECURITY_KIT_GATE_CADENCE`` (seconds, default 30) sets the gate
cadence Trigger. Results are written to ``<root>/gate-results.md``.
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
import zipfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import recipe  # noqa: E402

KIT = HERE.parent
RELEASE_1_0 = KIT
RELEASE_1_1 = KIT / "source" / "variants" / "1.3.1-gate"
VERSION = json.loads((RELEASE_1_0 / "cruxible-kit.json").read_text())["version"]
UPGRADE_VERSION = json.loads((RELEASE_1_1 / "cruxible-kit.json").read_text())["version"]
FIXTURE = HERE / "fixture-sources"
SBOM = HERE / "data" / "gate-app.cdx.json"
CADENCE = int(os.environ.get("SECURITY_KIT_GATE_CADENCE", "30"))
LOG4SHELL = "CVE-2021-44228"
ABSENT = "CVE-2021-44832"  # watched; not in the fixture catalog
REQUESTS_FIXED = "CVE-2023-32681"  # requests < 2.31.0: the gate SBOM's 2.32.3 is fixed
STRUTS = "CVE-2017-5638"  # struts2-core: not a gate SBOM component
JINJA = "CVE-2024-34064"  # found by OSV in the gate SBOM's jinja2 3.1.3
SETTLES = "CVE-2026-102490"  # listed (Zammad); first watched after graduation
BARE = "CVE-2024-3400"  # KEV-listed; a vulnerability Subject with no watch_reason or assessment
NEW_KEV = "CVE-2026-102490"  # Zammad, added 2026-10-02 (the catalog's last week)
RESULTS: dict[str, tuple[str, str]] = {}
STEPS = {
    "01": "init: empty instance, seeded Triggers",
    "02": "kit add from the registry: preview by kind, commit, status, providers",
    "03": "fixture Sources: web.fetch, osv-query, epss-daily implementations",
    "04": "instantiate Blueprints; unbound and mismatched refused",
    "05": "author Lines, Triggers, propose mandates; enable",
    "06": "SBOM import first: workspace Source v2 -> landing -> proposal; re-import no_change",
    "07": "inventory by key; watched is derived (watch_reason), a bare Subject is not watched",
    "08": "OSV applicability: affected / not_affected + justification; re-run no_change",
    "09": "analyst judgment: normative not_affected + VEX justification citing a workspace file",
    "10": "applicability bets stated before the record lands",
    "11": "CVE record -> applicability by version range; bets settle True/False",
    "12": "KEV cadence -> triage proposes (capped) and attention posts an inbox item",
    "13": "accept; Claims cite the Capture; floor; no_change; inbox dedupes a sighting",
    "14": "EPSS -> triage; urgent_exposures orders KEV first, then EPSS",
    "15": "restart: gap rows, lapsed ticks listed, dispatched, none at restart",
    "16": "measure pending; readings pending/open/expired",
    "17": "graduate KEV and EPSS triage to settle by max_authority",
    "18": "changed analysis build: one kit add, D8 carry, enable/re-grant, settles resume; keep/re-add/downgrade",
    "19": "SBOM re-import: a changed SBOM and a new release land; OSV assesses the new one",
    "20": "exit: resolve EPSS prior-refusal warning, next empty, run history",
    "21": "system model: gates asked; every answer unknown; one gap item per source",
    "22": "pull each gap's source, parse, accept; answers found/none name their coverage",
    "23": "unchanged re-pull: re-observation, no proposal, no generation; landing fired",
    "24": "moved main: one coverage Claim revised plus only the changed workflow's facts",
    "25": "HQ5 at the publishing commit: a parse Line per source; served matches declared",
    "26": "fail-closed freshness: past stale_after the coverage reads absent, answers unknown",
    "27": "declared/running disagreement posted with both Claims; the investigation resolves",
    "28": "findings: principals; self-approval lets a finder confirm alone; independent mode",
    "29": "(a) report: SARIF -> findings by key; other repo halts; finder cannot approve it",
    "30": "(f) duplicate: an agent's report merges by key; a line-hash tool is its own key; gap",
    "31": "(a') locate + (b) triage: sink cited by file; own words refused; false positive lands",
    "32": "(c) confirm: PoC backs confirmed; finder cannot confirm its own; dispute resolves",
    "33": "(d) remediate: work.finding; HQ6 posts the confirmed finding the release serves",
    "34": "(e) fix: the citation drifts; a full re-scan verifies fixed; HQ6 clears; regression",
    "35": "G14 G1: services state their log sources; a Syft SBOM and the scope's scan land runs; "
          "re-scan no_change; KEV lists it",
    "36": "G2: CVE ranges decide upstream php, OSV the Debian build; urgent_exposures shows "
          "scan-only hosts as observed; incident declared; G1 RQ1; the audit gaps name the "
          "services' log sources",
    "37": "G3 G4 G5: an exception holds RQ2 excepted until it expires; patches close only on "
          "a scan; a claim waits; the scan disagrees; unchanged",
    "38": "G2 G6: 8.3.36 not_affected, OSV decides the fixed Debian build; stale coverage unknown",
    "39": "G7 G9: audits seeded from the services' log sources (one left out is named); audit "
          "three states with the uncovered interval named; own words refused",
    "40": "G8: a contended result is conflict, RQ3 unknown, RQ4 raises its rotation",
    "41": "G10 G11 G12: receipts never verify, state reads do; secret refused; window re-asks",
    "42": "G13: ready_to_close with residue; closed; status page rendered; next empty",
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
        #: principal -> its CLI environment (the owner's, with its own settings file loaded)
        self.principals: dict[str, dict[str, str]] = {}
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

    def cx(self, *args: str, check: bool = True, timeout: float = 900,
           who: str | None = None) -> subprocess.CompletedProcess[str]:
        """Run the CLI as the owner, or as the principal ``who`` (its settings file)."""

        started = time.monotonic()
        result = subprocess.run(
            [self.bin, *args], env=self.principals[who] if who else self.env, cwd=self.ws,
            capture_output=True, text=True, timeout=timeout,
        )
        took = time.monotonic() - started
        self.log.write(f"$ cruxible {' '.join(args)}  [{took:.1f}s]{f' as {who}' if who else ''}\n"
                       f"{result.stdout}{result.stderr}(exit {result.returncode})\n")
        self.log.flush()
        if check and result.returncode != 0:
            raise AssertionError(f"cruxible {' '.join(args)} exited {result.returncode}: "
                                 f"{result.stdout[-1500:]}{result.stderr[-1500:]}")
        return result

    def out(self, *args: str, check: bool = True, who: str | None = None) -> str:
        return self.cx(*args, check=check, who=who).stdout

    def json(self, *args: str, who: str | None = None) -> Any:
        return json.loads(self.out(*args, "--json", who=who))

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
        out = self.out("authoring", "submit", self.payload(name, value))
        result = json.loads(out)
        assert result["outcome"]["status"] == "landed", out[-600:]
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

    def rows(self, name: str, **params: str) -> list[dict[str, Any]]:
        args = ["query", "--name", name, "--all"]
        for key, value in params.items():
            args += ["--param", f"{key}={value}"]
        return list(self.json(*args)["rows"])

    def claims(self, kind: str, predicate: str) -> dict[str, tuple[Any, str]]:
        """subject_id -> (value, Claim ID) for one field, from the query's Claim cells."""

        rows = self.json("query", kind, "--select", predicate, "--claims")["rows"]
        column = predicate.rsplit(".", 1)[-1]
        found = {}
        for row in rows:
            cells = (row.get("claims") or {}).get(column) or []
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
        receipt = self.json("proposal", "activate", proposal)
        assert receipt["status"] == "accepted", receipt
        assert receipt["accepted_coordinate"]["git_oid"], receipt

    def run_line(self, line: str) -> tuple[str, str]:
        out = self.out("line", "run", line)
        found = re.search(r"(RUN-[0-9a-f]+)", out)
        assert found, out
        return found.group(1), out


def _wait_for_run(gate: Gate, line: str, after: set[str], timeout: float,
                  status: str | None = None) -> dict[str, Any]:
    found: list[dict[str, Any]] = []

    def new_run() -> bool:
        fresh = [r for r in gate.runs(line) if r["run"] not in after and r["status"] != "running"
                 and (status is None or r["status"] == status)]
        found[:] = fresh
        return bool(fresh)

    gate.wait(new_run, timeout, f"no new run on {line}")
    return found[0]


def _field(row: dict[str, Any], name: str) -> Any:
    for field in row.get("fields") or ():
        if field["name"] == name:
            return field.get("value")
    return row.get(name)


def _assessments(gate: Gate) -> dict[tuple[str, str], tuple[Any, Any]]:
    """(release_id, cve) -> (status, justification), from security.assessment_index."""

    found = {}
    for row in gate.rows("security.assessment_index"):
        found[(_field(row, "release_id"), _field(row, "cve_id"))] = (
            _field(row, "status"), _field(row, "justification"))
        gate.values.setdefault("assessment_ids", {})[
            (_field(row, "release_id"), _field(row, "cve_id"))] = row["subject_id"]
    return found


def _inbox(gate: Gate, *args: str) -> list[dict[str, Any]]:
    """The inbox item envelopes ``inbox list`` returns."""

    return [entry["item"] for entry in gate.json("inbox", "list", *args)["entries"]]


@pytest.fixture(scope="module")
def gate() -> Iterator[Gate]:
    explicit = os.environ.get("SECURITY_KIT_GATE_ROOT")
    root = Path(explicit) if explicit else Path(tempfile.mkdtemp(prefix="security-kit-gate-"))
    root.mkdir(parents=True, exist_ok=True)
    instance = Gate(root)
    started = time.monotonic()
    try:
        instance.start_registry()
        subprocess.run([sys.executable, str(HERE / "publish_kit.py"), str(RELEASE_1_0),
                        f"{instance.registry}:{VERSION}"], env=instance.env, check=True,
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
        lines.append(f"\nwall clock: {time.monotonic() - started:.0f}s")
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


KIT_COUNTS = {"Blueprint": 9, "CaptureContract": 17, "ClaimType": 132, "Procedure": 21,
              "ProviderInterface": 20, "QueryDefinition": 45, "SourceAcquisitionPolicy": 1,
              "SubjectKind": 23}


def test_02_kit_add(gate: Gate) -> None:
    preview = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--dry-run")
    assert (preview["status"], preview["transition"]) == ("would_propose", "install")
    counts: dict[str, int] = {}
    for item in preview["plan"]:
        assert item["action"] == "add", item
        kind = item["identity"].split(":", 1)[0]
        counts[kind] = counts.get(kind, 0) + 1
    assert counts == KIT_COUNTS, counts
    actions = {p["package"]: p["action"] for p in preview["providers"]}
    assert set(actions) == {"cruxible-provider-web", "security-analysis-provider",
                            "security-sources-provider"}, actions
    committed = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--commit",
                          "--at", preview["coordinate"]["git_oid"])
    assert committed["status"] == "accepted", committed
    status = gate.out("kit", "status")
    assert f"security {VERSION}" in status and "up to date" in status, status
    (kit,) = gate.json("kit", "status")["kits"]
    delivery = {p["package"]: (p["delivery"], p["state"]) for p in kit["providers"]}
    assert delivery == {"cruxible-provider-web": ("index", "installed"),
                        "security-analysis-provider": ("bundled", "installed"),
                        "security-sources-provider": ("bundled", "installed")}, delivery
    kinds = gate.out("get", "SubjectKind:security.assessment")
    assert "security.assessment.release_id" in kinds and "unique" in kinds, kinds
    record("02", f"preview {counts}; accepted; status {VERSION} up to date; providers {delivery}")


def test_03_fixture_sources(gate: Gate) -> None:
    wheel = next((FIXTURE / "dist").glob("security_gate_sources-*.whl"))
    installed = gate.json("provider", "install", str(wheel), "--lock", str(FIXTURE / "uv.lock"))
    assert installed["status"] == "ready", installed
    assert installed["installed"] and installed["registered"], installed
    assert installed["build"].startswith("security-gate-sources/"), installed
    found = {}
    for interface, kit_provider in (("web.fetch", "cruxible-provider-web"),
                                    ("security.osv-query", "security-sources-provider"),
                                    ("security.epss-daily", "security-sources-provider"),
                                    ("security.repo-snapshot", "security-sources-provider"),
                                    ("security.pypi-release", "security-sources-provider"),
                                    ("security.release-asset", "security-sources-provider")):
        builds = {p["provider"] for p in gate.card(f"ProviderInterface:{interface}")["providers"]}
        assert all(re.fullmatch(r"[^/]+/[0-9a-f]{64}", build) for build in builds), builds
        assert {build.split("/", 1)[0] for build in builds} == {
            kit_provider, "security-gate-sources"}, (interface, builds)
        found[interface] = sorted(builds)
    record("03", f"implementations {found}")


def test_04_instantiate(gate: Gate) -> None:
    blueprint = gate.out("get", "Blueprint:security.osv-applicability")
    assert "osv" in blueprint and "security-gate-sources" in blueprint, blueprint
    unbound = gate.cx("authoring", "submit", gate.payload("unbound", {
        "kind": "blueprint_instance", "name": "security.kev-acquire",
        "blueprint": "security.kev-acquire", "bindings": {}}), "--dry-run", check=False)
    assert "bindings" in unbound.stdout + unbound.stderr
    wrong = gate.out("authoring", "submit", gate.payload("wrong", {
        "kind": "blueprint_instance", "name": "security.epss-acquire",
        "blueprint": "security.epss-acquire", "bindings": {"epss": "cruxible-provider-web"},
        "acquisition_policy": "security.acquisition"}), "--dry-run")
    assert "blueprint_provider_interface_mismatch" in wrong
    gate.submit("instances", recipe.instantiate("security-gate-sources", "security-gate-sources"))
    runnable = {name: gate.card(f"Procedure:{name}")["runnable"] for name in (
        "security.kev-acquire", "security.cve-record-acquire", "security.epss-acquire",
        "security.osv-applicability", "security.sbom-acquire")}
    assert runnable == {"security.kev-acquire": "line", "security.cve-record-acquire": "direct",
                        "security.epss-acquire": "line", "security.osv-applicability": "line",
                        "security.sbom-acquire": "direct"}, runnable
    origin = json.dumps(gate.proof("Procedure:security.kev-acquire"))
    gate.values["kev_acquire_blueprint"] = gate.proof(
        "Blueprint:security.kev-acquire")["artifact_digest"]
    assert gate.values["kev_acquire_blueprint"] in origin
    record("04", f"unbound refused; mismatch refused; runnable {runnable}; Blueprint origin "
           "recorded")


def test_05_automation(gate: Gate) -> None:
    gate.submit("automation", recipe.automation())
    line = gate.card("Line:security.kev-triage")
    assert line["triggers_inactive"] == "not enabled", line["triggers_inactive"]
    rows = gate.json("query", "Trigger", "--where", "target=Line:security.kev-triage")["rows"]
    assert [r["name"] for r in rows] == ["security.kev-landed"], rows
    enabled = [name for name in recipe.LINES if name not in recipe.HELD_LINES]
    for name in enabled:
        gate.out("line", "enable", name)
    record("05", f"documented example authored on {VERSION}; Lines, name-based landing "
           f"Triggers and propose Mandates accepted; {len(enabled)} Lines enabled (the pull "
           "Lines wait for the gate's own runs)")


def test_06_sbom_import(gate: Gate) -> None:
    (gate.ws / "sboms").mkdir(exist_ok=True)
    shutil.copyfile(SBOM, gate.ws / "sboms" / "gate-app.cdx.json")
    before = {r["run"] for r in gate.runs("security.sbom-import")}
    request = gate.payload("sbom-input", {"relative_path": "sboms/gate-app.cdx.json"})
    out = gate.out("procedure", "run", "security.sbom-acquire", request)
    assert ": succeeded" in out and "Capture sbom:" in out, out
    run = _wait_for_run(gate, "security.sbom-import", before, 120)
    assert run["status"] == "succeeded", run
    egress = gate.egress(run["run"])
    assert egress["kind"] == "propose_change_set" and egress["proposal_id"], egress
    review = gate.out("proposal", "review", egress["proposal_id"])
    assert "pkg:pypi/jinja2@3.1.3" in review, review[-2000:]
    gate.activate(egress["proposal_id"])
    components = gate.claims("security.release", "security.release.component")
    assert "gate-app--1.0.0" in components, components
    rows = [r for r in gate.rows("security.release_inventory")
            if _field(r, "product_name") == "gate-app"]
    assert sorted(_field(rows[0], "components")) == [
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:pypi/jinja2@3.1.3",
        "pkg:pypi/requests@2.32.3"], rows
    # The same SBOM again: the import finds nothing to add.
    before = {r["run"] for r in gate.runs("security.sbom-import")}
    gate.out("procedure", "run", "security.sbom-acquire", request)
    again = _wait_for_run(gate, "security.sbom-import", before, 120)
    assert again["status"] == "halted", again
    record("06", "first change on a fresh instance: workspace Source (v2 request) retained the "
           "SBOM; landing ran the import: product, release gate-app--1.0.0 and 3 components "
           "proposed (key Claims in the item's own words) and accepted; re-import halted "
           "no_change")


INVENTORY: list[tuple[str, Any]] = [
    ("security.team", "Platform"),
    ("security.service", "Storefront"),
    ("security.asset", "web-1.example.com"),
    ("security.supplier", "Apache Software Foundation"),
    ("security.product", "Apache Log4j2"),
    ("security.product", "Apache Log4j"),
    ("security.release", {"product_name": "Apache Log4j2", "version": "2.14.1"}),
    ("security.release", {"product_name": "Apache Log4j2", "version": "2.17.1"}),
    ("security.release", {"product_name": "Apache Log4j2", "version": "2.12.2"}),
    ("security.release", {"product_name": "Apache Log4j", "version": "1.2.17"}),
    ("security.supplier", "Zammad GmbH"),
    ("security.product", "Zammad"),
    ("security.release", {"product_name": "Zammad", "version": "6.0.0"}),
]
LOG4J_RELEASES = ("apache-log4j2--2.14.1", "apache-log4j2--2.17.1", "apache-log4j2--2.12.2",
                  "apache-log4j--1.2.17")


def _key(kind: str, key: Any) -> dict[str, Any]:
    """A Subject named by its kind and key (subject-key-v1): never a predicted id."""

    return {"subject_kind": kind, "key": key}


def _release(product: str, version: str) -> dict[str, Any]:
    return _key("security.release", {"product_name": product, "version": version})


def _inventory() -> dict[str, Any]:
    members: list[dict[str, Any]] = [recipe.subject(kind, key, f"Inventory: {key}.")
                                     for kind, key in INVENTORY]

    def _text(ref: Any) -> str:
        return json.dumps(ref["key"], sort_keys=True)

    def rel(subject: Any, predicate: str, target: Any) -> dict[str, Any]:
        said = f"{_text(subject)} {predicate.rsplit('.', 1)[-1]} {_text(target)}"
        return {"kind": "claim", "subject": subject, "predicate": predicate,
                "object": {"kind": "subject", "subject": target}, "role": "normative",
                "rationale": f"Inventory: {said}.",
                "source": {"kind": "self_source", "body": said + "\n"}}

    def lit(subject: Any, predicate: str, value: Any) -> dict[str, Any]:
        said = f"{_text(subject)} {predicate.rsplit('.', 1)[-1]} {value}"
        return {"kind": "claim", "subject": subject, "predicate": predicate,
                "object": {"kind": "literal", "value": value}, "role": "normative",
                "rationale": f"Inventory: {said}.",
                "source": {"kind": "self_source", "body": said + "\n"}}

    # Subjects this set creates are named by kind and key (a `kind/<text>` reference
    # resolves against accepted state only).
    asset = _key("security.asset", {"hostname": "web-1.example.com"})
    service = _key("security.service", {"name": "Storefront"})
    members += [
        lit(service, "security.service.criticality", "critical"),
        rel(service, "security.service.owned_by", _key("security.team", {"name": "Platform"})),
        lit(asset, "security.asset.internet_exposed", True),
        lit(asset, "security.asset.environment", "production"),
        rel(asset, "security.asset.serves", service),
        rel(_key("security.product", {"name": "Apache Log4j2"}), "security.product.supplied_by",
            _key("security.supplier", {"name": "Apache Software Foundation"})),
        rel(_key("security.product", {"name": "Zammad"}), "security.product.supplied_by",
            _key("security.supplier", {"name": "Zammad GmbH"})),
        rel(_release("Zammad", "6.0.0"), "security.release.product",
            _key("security.product", {"name": "Zammad"})),
        # A second value of a many-valued slot in the same change set needs an explicit
        # disposition of the first (by a Claim ID the set mints): the gate adds the other
        # installs with `cruxible add` after the set lands.
        rel(asset, "security.asset.installs", _release("Apache Log4j2", "2.14.1")),
    ]
    for kind, key in INVENTORY:
        if kind == "security.release" and key["product_name"].startswith("Apache"):
            members.append(rel(_key(kind, key), "security.release.product",
                               _key("security.product", {"name": key["product_name"]})))
    return {"kind": "change_set", "rationale": "The gate's inventory.", "members": members}


def test_07_inventory_and_watches(gate: Gate) -> None:
    gate.submit("inventory", _inventory())
    for release in ("zammad--6.0.0", "gate-app--1.0.0"):  # ids core rendered from the keys
        gate.out("add", "security.asset/web-1.example.com", "installs",
                 f"security.release/{release}", "--because", f"web-1 runs {release}.")
    releases = sorted(gate.claims("security.release", "security.release.version"))
    assert releases == sorted([*LOG4J_RELEASES, "gate-app--1.0.0", "zammad--6.0.0"]), releases
    # Watching is a decision (a watch_reason), made with the Subject created by key.
    gate.submit("watch", recipe.watch(" cve-2021-44228 ", ABSENT, STRUTS))
    # A bare vulnerability Subject is tracked by nothing.
    gate.submit("bare", {"kind": "change_set", "rationale": "A CVE we only mention.",
                         "members": [recipe.subject("security.vulnerability", BARE,
                                                    "Mentioned in a ticket; not tracked.")]})
    # `set` creates a one-key kind by key and states the decision in one write.
    out = gate.out("set", f"security.vulnerability/{REQUESTS_FIXED}", "watch_reason",
                   "requests in the storefront", "--because", "We ship requests.")
    assert "accepted" in out, out
    subjects = gate.claims("security.vulnerability", "security.vulnerability.cve_id")
    assert {k: v[0] for k, v in subjects.items()} == {
        "cve-2021-44228": LOG4SHELL, "cve-2021-44832": ABSENT, "cve-2017-5638": STRUTS,
        "cve-2023-32681": REQUESTS_FIXED, "cve-2024-3400": BARE}, subjects
    watched = sorted(_field(r, "cve_id") for r in gate.rows("security.watched_vulnerabilities"))
    assert watched == sorted([LOG4SHELL, ABSENT, STRUTS, REQUESTS_FIXED]), watched
    # Creating by a held key reuses it: the same watch again changes nothing.
    head = gate.json("orient")["coordinate"]["git_oid"]
    again = gate.cx("authoring", "submit", gate.payload("watch-again", recipe.watch(LOG4SHELL)),
                    check=False)
    assert gate.json("orient")["coordinate"]["git_oid"] == head, again.stdout[-400:]
    record("07", f"inventory created by key ({len(INVENTORY)} Subjects, ids rendered from "
           f"keys); watched (derived) {watched}; bare {BARE} Subject not watched; re-watch "
           f"moved no generation (exit {again.returncode}); `set` created cve-2023-32681 by "
           "key with its watch_reason")


def test_08_osv_applicability(gate: Gate) -> None:
    run, out = gate.run_line("security.osv-applicability")
    assert ": succeeded" in out, out
    egress = gate.egress(run)
    proposal = egress["proposal_id"]
    assert proposal, egress
    gate.activate(proposal)
    held = _assessments(gate)
    app = "gate-app--1.0.0"
    assert held[(app, LOG4SHELL)] == ("affected", None), held
    assert held[(app, JINJA)] == ("affected", None), held
    assert held[(app, REQUESTS_FIXED)] == ("not_affected", "vulnerable_code_not_present"), held
    assert (app, STRUTS) not in held, held  # no struts2-core component: not assessed
    watched = gate.claims("security.vulnerability", "security.vulnerability.cve_id")
    assert "cve-2024-34064" in watched, watched
    assessment = gate.values["assessment_ids"][(app, LOG4SHELL)]
    statuses = gate.claims("security.assessment", "security.assessment.status")
    evidence = gate.out("get", statuses[assessment][1], "--detail", "evidence")
    assert "CaptureContract:security.osv-query-v1" in evidence, evidence
    # Which dependency brings it in: the assessment names the component OSV listed.
    urgent = {_field(r, "cve_id"): r for r in gate.rows("security.urgent_exposures")}
    assert "pkg:pypi/jinja2@3.1.3" in json.dumps(_field(urgent[JINJA], "component")), urgent
    rerun, rerun_out = gate.run_line("security.osv-applicability")
    assert ": halted" in rerun_out or "no_change" in rerun_out, rerun_out
    affected = sum(1 for (r, _), (s, _) in held.items() if r == app and s == "affected")
    record("08", f"OSV proposal accepted: {affected} affected for {app} (CVEs watched by key), "
           f"(component named on urgent_exposures), "
           f"{REQUESTS_FIXED} not_affected/vulnerable_code_not_present, {STRUTS} (no "
           "struts2-core component) not assessed; evidence cites the OSV Capture; re-run "
           "no_change")


JUDGED = "CVE-2024-56201"  # jinja2 < 3.1.5 (OSV: affected); the analyst judges it unreachable
ANALYSIS_NOTE = """# CVE-2024-56201 in gate-app 1.0.0

The vulnerability needs an attacker to control both a template's content and its
file name. gate-app renders only the templates it ships, from package data, and
never compiles a template from request input (templates/loader.py:12 uses
PackageLoader only).
"""


def _index_row(gate: Gate, assessment: str) -> dict[str, Any]:
    (row,) = [r for r in gate.rows("security.assessment_index") if r["subject_id"] == assessment]
    return row


def test_09_analyst_judgment(gate: Gate) -> None:
    app = "gate-app--1.0.0"
    assessment = gate.values["assessment_ids"][(app, JUDGED)]
    assert _assessments(gate)[(app, JUDGED)] == ("affected", None)
    assert _field(_index_row(gate, assessment), "status_role") == "observation"
    (gate.ws / "analysis").mkdir(exist_ok=True)
    (gate.ws / "analysis" / "jinja2-cve-2024-56201.md").write_text(ANALYSIS_NOTE)
    out = gate.out("procedure", "run", "security.evidence-acquire", gate.payload(
        "evidence-input", {"relative_path": "analysis/jinja2-cve-2024-56201.md"}))
    capture = re.search(r"Capture evidence: (sha256:[0-9a-f]{64})", out)
    assert ": succeeded" in out and capture, out
    cites = {"kind": "capture", "capture": capture.group(1)}
    gate.out("write", gate.payload("judgment", {
        "because": "Analyst review of the OSV verdict: the vulnerable path is unreachable.",
        "subject": f"security.assessment/{assessment}",
        "changes": [
            {"op": "set", "field": "status", "value": "not_affected", "role": "normative",
             "evidence": cites},
            {"op": "set", "field": "justification",
             "value": "vulnerable_code_not_in_execute_path", "role": "normative",
             "evidence": cites},
        ]}))
    assert _assessments(gate)[(app, JUDGED)] == (
        "not_affected", "vulnerable_code_not_in_execute_path")
    # A judgment is visibly a judgment: its role (normative), its evidence; the
    # analyst's reasoning is the write's because.
    rows = gate.json("query", "security.assessment", "--where", f"cve_id={JUDGED}",
                     "--select", "status,justification", "--claims")["rows"]
    cells = rows[0]["claims"]
    assert cells["status"][0]["role"] == "normative", cells
    assert cells["justification"][0]["role"] == "normative", cells
    assert _field(_index_row(gate, assessment), "status_role") == "normative"
    evidence = gate.out("get", cells["status"][0]["claim"], "--detail", "evidence")
    assert "security.workspace-evidence-v1" in evidence, evidence
    assert "the vulnerable path is unreachable" in evidence, evidence  # the write's because
    # An observation in someone's own words has no admitted evidence: its verdict is
    # uncovered, so no worklist (supported Claims only) would ever show it.
    own = gate.cx("set", f"security.assessment/{assessment}", "status", "affected", "--role",
                  "observation", "--because", "I think so.", "--dry-run", check=False)
    assert "verdict uncovered" in own.stdout + own.stderr, own.stdout[-600:]
    # The Procedures never revise a judgment; it is no longer watched (not affected).
    _, rerun = gate.run_line("security.osv-applicability")
    assert ": halted" in rerun or "no_change" in rerun, rerun
    assert _assessments(gate)[(app, JUDGED)] == (
        "not_affected", "vulnerable_code_not_in_execute_path")
    watched = {_field(r, "cve_id") for r in gate.rows("security.watched_vulnerabilities")}
    assert JUDGED not in watched, watched
    record("09", "OSV said affected; the analyst cited a workspace note (evidence-acquire) and "
           "wrote normative not_affected + vulnerable_code_not_in_execute_path; query "
           "--claims shows role normative, assessment_index status_role observation -> "
           "normative; an "
           "own-words observation is uncovered (no admitted evidence); OSV re-run halted "
           "no_change, the judgment stands; no longer watched")


def _bet(gate: Gate, release: str, expected: str) -> str:
    # A claim member names the Subject a sibling member creates by its kind and key.
    assessment = _key("security.assessment", {"release_id": release, "cve_id": LOG4SHELL})
    gate.submit(f"bet-{release}", {"kind": "change_set", "rationale": "State a bet.", "members": [
        recipe.subject("security.assessment", {"release_id": release, "cve_id": LOG4SHELL},
                       f"Assess {release} for {LOG4SHELL}."),
        {"kind": "claim", "subject": assessment, "predicate": "security.assessment.release",
         "object": {"kind": "subject", "subject": f"security.release/{release}"},
         "role": "normative", "rationale": "The assessed release.",
         "source": {"kind": "self_source", "body": f"release {release}\n"}},
        {"kind": "claim", "subject": assessment, "predicate": "security.assessment.vulnerability",
         "object": {"kind": "subject", "subject": f"security.vulnerability/{LOG4SHELL}"},
         "role": "normative", "rationale": "The assessed CVE.",
         "source": {"kind": "self_source", "body": f"cve {LOG4SHELL}\n"}},
        {"kind": "claim", "subject": assessment, "predicate": "security.assessment.expected_status",
         "object": {"kind": "literal", "value": expected}, "role": "normative",
         "rationale": f"The gate bets {release} is {expected} by {LOG4SHELL}.",
         "source": {"kind": "self_source", "body": f"bet: {expected}\n"}},
    ]})
    _assessments(gate)  # the id core gave the assessment, for the observation selector
    subject_id = gate.values["assessment_ids"][(release, LOG4SHELL)]
    claim = gate.claims("security.assessment", "security.assessment.expected_status")[
        subject_id][1]
    name = f"security.applicability-{release}"
    start = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    path = gate.payload(name, {"contract": {
        "identity": {"kind": "ResolutionContract", "name": name},
        "hypothesis": claim,
        "observation": {"subject": {"tag": "playbill-semantic-address-v1",
                                    "artifact_path":
                                        f"subjects/security.assessment/{subject_id}.json",
                                    "selector": {"scheme": "artifact-v1", "value": ""}},
                        "predicate": "security.assessment.status"},
        "rule": {"tag": "playbill-prediction-equality-rule-v1", "operator": "equality"},
        "window": {"kind": "fixed", "starts_at": start, "duration_seconds": 86400}}})
    out = gate.out("prediction", "propose", path)
    proposal = re.search(r"Proposal: (sha256:[0-9a-f]{64})", out)
    assert proposal, out
    gate.activate(proposal.group(1))
    return name


def test_10_applicability_bets(gate: Gate) -> None:
    gate.values["bet_right"] = _bet(gate, "apache-log4j2--2.17.1", "not_affected")
    gate.values["bet_wrong"] = _bet(gate, "apache-log4j2--2.12.2", "affected")
    for name in (gate.values["bet_right"], gate.values["bet_wrong"]):
        assert " open" in gate.out("get", f"ResolutionContract:{name}")
    record("10", "two assessments created by key with expected_status bets; their prediction "
           "contracts live with open windows before any source observed a status")


def test_11_cve_applicability(gate: Gate) -> None:
    before = {r["run"] for r in gate.runs("security.cve-applicability")}
    cve = gate.payload("cve-input", {"url": f"https://cveawg.mitre.org/api/cve/{LOG4SHELL}"})
    run = gate.out("procedure", "run", "security.cve-record-acquire", cve)
    assert ": succeeded" in run and "Capture record:" in run, run
    landed = _wait_for_run(gate, "security.cve-applicability", before, 120)
    assert landed["status"] == "succeeded", landed
    egress = gate.egress(landed["run"])
    gate.activate(egress["proposal_id"])
    held = _assessments(gate)
    decided = {r: held.get((r, LOG4SHELL)) for r in LOG4J_RELEASES}
    assert decided == {
        "apache-log4j2--2.14.1": ("affected", None),
        "apache-log4j2--2.17.1": ("not_affected", "vulnerable_code_not_present"),
        "apache-log4j2--2.12.2": ("not_affected", "vulnerable_code_not_present"),
        "apache-log4j--1.2.17": ("inconclusive", None),
    }, decided
    statuses = gate.claims("security.assessment", "security.assessment.status")
    ids = gate.values["assessment_ids"]
    right = statuses[ids[("apache-log4j2--2.17.1", LOG4SHELL)]][1]
    wrong = statuses[ids[("apache-log4j2--2.12.2", LOG4SHELL)]][1]
    assert "Outcome: True" in gate.out("prediction", "settle", gate.values["bet_right"],
                                       "--observation", right)
    assert "Outcome: False" in gate.out("prediction", "settle", gate.values["bet_wrong"],
                                        "--observation", wrong)
    record("11", f"CVE record landed -> proposal: {decided}; bet not_affected@2.17.1 settled "
           "True, bet affected@2.12.2 settled False")


def test_12_kev_cadence(gate: Gate) -> None:
    gate.submit("cadence", {"kind": "trigger", "name": "security.kev-gate-cadence",
                            "line_name": "security.kev-daily",
                            "schedule": {"kind": "cadence", "interval_seconds": CADENCE}})
    before_triage = {r["run"] for r in gate.runs("security.kev-triage")}
    before_attention = {r["run"] for r in gate.runs("security.kev-attention")}
    assert "enabled" in gate.out("line", "enable", "security.kev-daily")
    daily = _wait_for_run(gate, "security.kev-daily", set(), CADENCE * 3 + 60)
    triage = _wait_for_run(gate, "security.kev-triage", before_triage, 180)
    attention = _wait_for_run(gate, "security.kev-attention", before_attention, 180)
    # Hold the cadence while the proposal is reviewed, so the next tick reads accepted state.
    gate.out("line", "disable", "security.kev-daily")
    assert (daily["status"], triage["status"], attention["status"]) == (
        "succeeded", "succeeded", "succeeded"), (daily, triage, attention)
    assert '"cadence"' in json.dumps(gate.proof(f"ProcedureRun:{daily['run']}"))
    egress = gate.egress(triage["run"])
    assert egress["kind"] == "settle_change_set"
    assert egress["settle_outcome"] == "proposed", egress
    assert egress["fallback_reason"] == "cruxible.settle.authority_capped_by_line_max_authority"
    gate.values["proposal"] = egress["proposal_id"]
    gate.values["first_triage"] = triage["run"]
    gate.values["kev_paths"] = len(egress["target_paths"])
    items = _inbox(gate, "--line", "security.kev-attention", "--status", "unread")
    assert len(items) == 1, items
    item = gate.json("inbox", "get", items[0]["item_id"])
    payload = json.dumps(item)
    assert NEW_KEV in payload and "zammad--6.0.0" in payload and "not_watched" in payload, item
    gate.values["inbox_item"] = items[0]["item_id"]
    record("12", f"cadence tick -> capture_landing: triage proposed {len(egress['target_paths'])} "
           f"Claims (settle capped: {egress['fallback_reason']}); attention posted 1 inbox item "
           f"({NEW_KEV} matches Zammad 6.0.0, not watched)")


def test_13_accept_and_dedupe(gate: Gate) -> None:
    gate.activate(gate.values["proposal"])
    listed = gate.claims("security.vulnerability", "security.vulnerability.kev_listed")
    assert listed["cve-2021-44228"][0] is True and listed["cve-2021-44832"][0] is False, listed
    assert "cve-2024-3400" not in listed, listed  # listed by KEV, but not watched
    added = gate.claims("security.vulnerability", "security.vulnerability.kev_date_added")
    assert added["cve-2021-44228"][0] == "2021-12-10", added
    evidence = gate.out("get", listed["cve-2021-44832"][1], "--detail", "evidence")
    assert "CaptureContract:security.kev-http-v1" in evidence, evidence
    head = gate.json("orient")["coordinate"]["git_oid"]

    def floor_current() -> bool:
        manifest = gate.ws / ".cruxible" / "floor" / "manifest.json"
        return manifest.exists() and json.loads(manifest.read_text())["coordinate"]["git_oid"] == head

    gate.wait(floor_current, 60, "floor not delivered at head")
    before = {r["run"] for r in gate.runs("security.kev-triage")}
    before_attention = {r["run"] for r in gate.runs("security.kev-attention")}
    gate.values["daily_before"] = {r["run"] for r in gate.runs("security.kev-daily")}
    gate.out("line", "enable", "security.kev-daily")
    rerun = _wait_for_run(gate, "security.kev-triage", before, CADENCE * 3 + 60)
    assert rerun["status"] == "halted", rerun
    assert "reason=no_change" in gate.out("get", rerun["run"])
    _wait_for_run(gate, "security.kev-attention", before_attention, 120)
    gate.out("line", "disable", "security.kev-daily")
    items = _inbox(gate, "--line", "security.kev-attention")
    assert len(items) == 1 and items[0]["occurrences"] >= 2, items
    item = items[0]
    gate.out("inbox", "ack", gate.values["inbox_item"])
    record("13", "accepted; kev_listed true/false cite the kev-http-v1 Capture; floor at head; "
           f"next tick: triage no_change; attention re-posted the same item "
           f"({item['occurrences']} sightings, 1 item); acknowledged")


def test_14_epss(gate: Gate) -> None:
    before = {r["run"] for r in gate.runs("security.epss-triage")}
    run, out = gate.run_line("security.epss-daily")
    assert ": succeeded" in out, out
    triage = _wait_for_run(gate, "security.epss-triage", before, 180)
    assert triage["status"] == "succeeded", triage
    egress = gate.egress(triage["run"])
    assert egress["settle_outcome"] == "proposed", egress
    gate.activate(egress["proposal_id"])
    scores = gate.claims("security.vulnerability", "security.vulnerability.epss_score")
    assert scores["cve-2021-44228"][0] == "0.99999" and scores["cve-2024-34064"][0] == "0.00979"
    rows = gate.rows("security.urgent_exposures")
    order = [(_field(r, "cve_id"), _field(r, "kev_listed"), _field(r, "epss_score")) for r in rows]
    listed = [kev for _, kev, _ in order]
    assert listed == sorted(listed, key=lambda v: v is not True), order
    tail = [Decimal(s) if s is not None else Decimal(-1) for _, kev, s in order if kev is not True]
    assert tail == sorted(tail, reverse=True), order
    assert order[0][0] == LOG4SHELL, order
    record("14", f"EPSS file -> triage proposed {len(egress['target_paths'])} scores; accepted; "
           f"urgent_exposures {len(rows)} rows, KEV-listed first then EPSS descending "
           f"(first {order[0]})")



def test_15_restart(gate: Gate) -> None:
    gate.out("line", "enable", "security.kev-daily")
    gate.stop_daemon()
    stopped = datetime.now(UTC)
    time.sleep(CADENCE * 2 + 15)
    gate.start_daemon()
    restarted = datetime.now(UTC)
    text = gate.next_text()
    gaps = re.findall(r"cruxible line evaluate (\S+) --since (\S+) --until (\S+)", text)
    assert "security.kev-daily" in {g[0] for g in gaps}, text
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

    gate.wait(triage_caught_up, 240, "triage did not run on the backfilled Captures")
    gate.wait(lambda: any(datetime.fromisoformat(r["started_at"]) > until + timedelta(seconds=5)
                          and r["run"] not in dispatched for r in gate.runs("security.kev-daily")),
              CADENCE * 2 + 60, "no forward tick after the restart")
    forward = []
    for run in gate.runs("security.kev-daily"):
        if run["run"] in dispatched:
            continue
        receipt = gate.proof(f"ProcedureRun:{run['run']}").get("receipt") or {}
        instant = receipt.get("occurrence_evaluation_time")
        if instant and datetime.fromisoformat(instant) > lapsed[-1] + timedelta(seconds=1):
            forward.append(datetime.fromisoformat(instant))
    assert forward and min(forward) >= lapsed[-1] + timedelta(seconds=CADENCE - 1), (
        lapsed, forward, restarted)
    gate.out("line", "disable", "security.kev-daily")
    # Evaluated gaps of the other Lines leave pending work for explicit dispatch.
    for line in {g[0] for g in gaps} - {"security.kev-daily"}:
        gate.out("line", "dispatch", line)
    assert "line_coverage_gap" not in gate.next_text()
    record("15", f"gap rows for {sorted({g[0] for g in gaps})}; dry-run listed {len(ticks)} "
           "lapsed cadence ticks; dispatched, triage halted no_change on each landing; first "
           f"forward tick {(min(forward) - lapsed[-1]).total_seconds():.0f}s after the last "
           "lapsed one, none at the restart")


def test_16_measure(gate: Gate) -> None:
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
    record("16", f"measure pending; readings at +0/+4/+11 days {states}")


def test_17_graduate(gate: Gate) -> None:
    digests = {name: gate.proof(f"Procedure:{name}")["artifact_digest"]
               for name in ("security.kev-triage", "security.epss-triage")}
    gate.submit("graduate", recipe.graduate())
    for name, digest in digests.items():
        assert gate.proof(f"Procedure:{name}")["artifact_digest"] == digest
        line = gate.card(f"Line:{name}")
        assert line["authority"] == "settle"
        assert gate.proof(f"ProcedureMandate:{name}-settle")["envelope"]["grants"] == "settle"
        gate.out("line", "enable", name)
    kev_mandate = gate.proof("ProcedureMandate:security.kev-triage-settle")["artifact_digest"]
    seen = {r["run"] for r in gate.runs("security.kev-triage")}
    seen_epss = {r["run"] for r in gate.runs("security.epss-triage")}
    gate.submit("watch-settles", recipe.watch(SETTLES))
    gate.out("line", "run", "security.kev-daily")
    kev = _wait_for_run(gate, "security.kev-triage", seen, 180, status="succeeded")
    settled = gate.egress(kev["run"])
    assert settled["settle_outcome"] == "settled", settled
    assert settled["procedure_mandate_digest"] == kev_mandate and settled["accepted_git_oid"]
    assert gate.claims("security.vulnerability",
                       "security.vulnerability.kev_listed")["cve-2026-102490"][0] is True
    gate.out("line", "run", "security.epss-daily")
    epss = _wait_for_run(gate, "security.epss-triage", seen_epss, 180, status="succeeded")
    assert gate.egress(epss["run"])["settle_outcome"] == "settled"
    assert gate.claims("security.vulnerability",
                       "security.vulnerability.epss_score")["cve-2026-102490"][0] == "0.0055"
    record("17", "Initial settle grants authored; Lines enabled; Procedure digests unchanged; "
           f"authority settle; {SETTLES} KEV fields and EPSS scores settled under the mandates "
           "(condition: a keyed vulnerability; triage only changes watched ones)")


def test_18_upgrade(gate: Gate) -> None:
    gate.py(HERE / "edit_kev_exposure.py", "250")
    assert "edited locally: query-definitions/security.kev_exposure.json" in gate.out("kit", "status")
    old_lines = {name: gate.proof(f"Line:{name}") for name in recipe.LINES}
    old_mandates = {f"{name}-{grant}": gate.proof(f"ProcedureMandate:{name}-{grant}")
                    for name in recipe.MANDATES for grant in
                    (("propose", "settle") if name in
                     {"security.kev-triage", "security.epss-triage"} else ("propose",))}
    triggers = {row["name"]: gate.proof(f"Trigger:{row['name']}")
                for row in gate.json("query", "Trigger")["rows"]}
    old_provider_pins = {pin["target"]["name"]: pin for pin in gate.proof(
        "Procedure:security.kev-triage")["artifact"]["pins"] if pin["role"] == "provider"}
    old_analysis = next(p for p in json.loads((RELEASE_1_0 / "cruxible-kit.json").read_text())[
        "providers"] if p["package"] == "security-analysis-provider")
    new_analysis = next(p for p in json.loads((RELEASE_1_1 / "cruxible-kit.json").read_text())[
        "providers"] if p["package"] == "security-analysis-provider")
    assert old_analysis["wheel"]["sha256"] != new_analysis["wheel"]["sha256"]
    source_path = "security_analysis_provider/kev.py"
    with zipfile.ZipFile(RELEASE_1_0 / "providers" / old_analysis["wheel"]["filename"]) as old:
        with zipfile.ZipFile(RELEASE_1_1 / "providers" / new_analysis["wheel"]["filename"]) as new:
            assert old.read(source_path) != new.read(source_path), "a real code change is required"
            assert b'Field: {predicate}' in new.read(source_path)
    subprocess.run([sys.executable, str(HERE / "publish_kit.py"), str(RELEASE_1_1),
                    f"{gate.registry}:{UPGRADE_VERSION}"], env=gate.env, check=True,
                   capture_output=True)
    assert f"latest {UPGRADE_VERSION} available" in gate.out("kit", "status")
    preview = gate.json("kit", "add", f"{gate.registry}:{UPGRADE_VERSION}", "--dry-run")
    (gate.root / "upgrade-preview.json").write_text(json.dumps(preview, indent=2) + "\n")
    assert (preview["status"], preview["transition"]) == ("would_propose", "upgrade"), preview
    changes = {i["identity"]: (i["action"], i["consequence"]) for i in preview["plan"]
               if i["action"] != "unchanged"}
    assert changes["Blueprint:security.kev-acquire"] == ("replace", None)
    assert changes["ClaimType:security.vulnerability.kev_cwes"] == ("add", None)
    assert changes["QueryDefinition:security.kev_exposure"] == ("replace", "overwrites_your_edit")
    carries = preview["automation_carries"]
    lines = {item["identity"]: item for item in carries if item["kind"] == "line"}
    mandates = {item["identity"]: item for item in carries if item["kind"] == "mandate"}
    assert {"Line:security.kev-triage", "Line:security.epss-triage"} <= lines.keys(), carries
    assert all(item["enablement"] == "disabled" for item in lines.values())
    assert all(item["new_grant"] == "propose" for item in mandates.values())
    for name in ("security.kev-triage", "security.epss-triage"):
        assert mandates[f"ProcedureMandate:{name}-settle"]["loses_settle"]
    assert not preview["stops"], preview["stops"]
    committed = gate.json("kit", "add", f"{gate.registry}:{UPGRADE_VERSION}", "--keep",
                          "QueryDefinition:security.kev_exposure", "--commit", "--at",
                          preview["coordinate"]["git_oid"])
    (gate.root / "upgrade-commit.json").write_text(json.dumps(committed, indent=2) + "\n")
    assert committed["status"] == "accepted", committed
    new_provider_pins = {pin["artifact_digest"] for pin in gate.proof(
        "Procedure:security.kev-triage")["artifact"]["pins"] if pin["role"] == "provider"}
    assert new_provider_pins != {pin["artifact_digest"] for pin in old_provider_pins.values()}
    for name, pin in old_provider_pins.items():
        assert gate.proof(f"Provider:{name}")["artifact_digest"] == pin["artifact_digest"]
    for identity, item in lines.items():
        name = identity.removeprefix("Line:")
        proof = gate.proof(identity)
        assert proof["artifact_digest"] != old_lines[name]["artifact_digest"]
        envelope = proof["envelope"]
        assert envelope["identity"] == old_lines[name]["envelope"]["identity"]
        assert envelope["lifecycle"]["predecessor_digest"] == old_lines[name]["artifact_digest"]
        assert envelope["procedure"]["artifact_digest"] != old_lines[name]["envelope"][
            "procedure"]["artifact_digest"]
        assert gate.card(identity)["triggers_inactive"] == "not enabled"
        assert item["old_artifact_digest"] == old_lines[name]["artifact_digest"]
    for identity in mandates:
        name = identity.removeprefix("ProcedureMandate:")
        envelope = gate.proof(identity)["envelope"]
        assert envelope["identity"] == old_mandates[name]["envelope"]["identity"]
        assert envelope["grants"] == "propose"
        assert not envelope.get("scope") and envelope.get("condition") is None
        assert not envelope.get("subject_creation") and envelope.get("subject_scope") is None
        assert envelope["namespace"] == old_mandates[name]["envelope"]["namespace"]
        assert envelope["resource_ceiling"] == old_mandates[name]["envelope"]["resource_ceiling"]
    for name, old in triggers.items():
        current = gate.proof(f"Trigger:{name}")
        assert current["artifact_digest"] == old["artifact_digest"]
        assert json.dumps(current["envelope"], sort_keys=True) == json.dumps(
            old["envelope"], sort_keys=True), name
    findings = [row for row in gate.json("next")["items"]
                if row["reason"] == "line_disabled_by_upgrade"]
    assert len(findings) == len(lines), findings
    assert {row["subject_identity"] for row in findings} == lines.keys()
    for row in findings:
        assert row["repair"]["operation"] == "cruxible.line.enable"
        assert row["repair"]["target"] == row["subject_identity"]
        assert "disabled by upgrade to" in row["detail"]["detail"]
        gate.out("line", "enable", row["repair"]["arguments"]["line"])
    assert not [row for row in gate.json("next")["items"]
                if row["reason"] == "line_disabled_by_upgrade"]

    # Enabling alone restores proposing; only an approved re-grant may restore settle.
    probe = "CVE-2023-4966"  # fresh watched CVE in KEV, not among the OSV assessments
    gate.submit("watch-after-upgrade", recipe.watch(probe))
    seen = {r["run"] for r in gate.runs("security.kev-triage")}
    gate.out("line", "run", "security.kev-daily")
    capped = _wait_for_run(gate, "security.kev-triage", seen, 180, status="succeeded")
    egress = gate.egress(capped["run"])
    assert egress["settle_outcome"] == "proposed", egress
    assert egress["fallback_reason"] == "cruxible.settle.authority_capped_by_mandate_grant"
    gate.out("proposal", "withdraw", egress["proposal_id"], "--reason",
             "Gate: replace this proposed-only probe with an explicitly re-granted settle run.")
    gate.submit("regrant-after-upgrade", recipe.graduate())
    for name in ("security.kev-triage", "security.epss-triage"):
        assert gate.proof(f"ProcedureMandate:{name}-settle")["envelope"]["grants"] == "settle"
        gate.out("line", "enable", name)
    seen = {r["run"] for r in gate.runs("security.kev-triage")}
    gate.out("line", "run", "security.kev-daily")
    kev = _wait_for_run(gate, "security.kev-triage", seen, 180, status="succeeded")
    assert gate.egress(kev["run"])["settle_outcome"] == "settled"
    listed = gate.claims("security.vulnerability", "security.vulnerability.kev_listed")
    assert listed[probe.lower()][0] is True
    assert "Field: security.vulnerability.kev_listed." in gate.out(
        "get", listed[probe.lower()][1], "--detail", "why")
    # Force a real EPSS write for the existing keyed vulnerability after re-granting.
    score = gate.claims("security.vulnerability", "security.vulnerability.epss_score")[
        SETTLES.lower()][1]
    gate.out("retire", score, "--because", "Gate: verify score restoration after re-grant.")
    seen = {r["run"] for r in gate.runs("security.epss-triage")}
    gate.out("line", "run", "security.epss-daily")
    epss = _wait_for_run(gate, "security.epss-triage", seen, 180, status="succeeded")
    assert gate.egress(epss["run"])["settle_outcome"] == "settled"
    assert gate.claims("security.vulnerability", "security.vulnerability.epss_score")[
        SETTLES.lower()][0] == "0.0055"
    # The probe tests the two feeds only; remove its watch before the later OSV fixture run.
    watch = gate.claims("security.vulnerability", "security.vulnerability.watch_reason")[
        probe.lower()][1]
    gate.out("retire", watch, "--because", "Gate: KEV/EPSS upgrade probe completed.")
    status = gate.out("kit", "status")
    assert f"security {UPGRADE_VERSION}" in status
    assert "kept: QueryDefinition:security.kev_exposure" in status
    again = gate.json("kit", "add", f"{gate.registry}:{UPGRADE_VERSION}", "--dry-run")
    assert again["status"] == "unchanged", again
    down = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--dry-run")
    assert (down["status"], down["transition"]) == ("would_block", "downgrade"), down
    assert gate.proof("QueryDefinition:security.kev_exposure")["envelope"][
        "default_budgets"]["max_results"] == 250
    assert gate.values["kev_acquire_blueprint"] in json.dumps(gate.proof(
        "Procedure:security.kev-acquire"))
    record("18", f"ONE kit add {VERSION} -> {UPGRADE_VERSION}: changed analysis code/build; "
           f"{len(lines)} same-identity Lines disabled; {len(mandates)} Mandates propose-only; "
           "Triggers byte-identical; old exact Provider retained; next/line enable repairs; "
           "enable alone proposed; approved KEV/EPSS re-grants resumed settling; new rationale "
           "executed; local edit kept; re-add unchanged; downgrade blocked")


def _import(gate: Gate, source: Path, relative: str) -> dict[str, Any]:
    before = {r["run"] for r in gate.runs("security.sbom-import")}
    shutil.copyfile(source, gate.ws / relative)
    gate.out("procedure", "run", "security.sbom-acquire",
             gate.payload(f"sbom-{source.stem}", {"relative_path": relative}))
    run = _wait_for_run(gate, "security.sbom-import", before, 180)
    assert run["status"] == "succeeded", gate.out("get", run["run"])[-1500:]
    egress = gate.egress(run["run"])
    gate.activate(egress["proposal_id"])
    return egress


def test_19_sbom_reimport(gate: Gate) -> None:
    # The daily-change path: a dependency moved. The same release's SBOM gains a
    # component, and the product's next version arrives as its own SBOM. Each
    # lands without restating what inventory holds (product, supplier, release).
    changed = _import(gate, SBOM.with_name("gate-app-1.0.0-changed.cdx.json"),
                      "sboms/gate-app.cdx.json")
    new = _import(gate, SBOM.with_name("gate-app-1.1.0.cdx.json"),
                  "sboms/gate-app-1.1.0.cdx.json")
    rows = {(_field(r, "product_name"), _field(r, "version")): r
            for r in gate.rows("security.release_inventory")}
    assert "pkg:pypi/urllib3@2.5.0" in _field(rows[("gate-app", "1.0.0")], "components")
    assert len(_field(rows[("gate-app", "1.0.0")], "components")) == 4
    assert _field(rows[("gate-app", "1.1.0")], "supplier_name") == "gate example"
    run, out = gate.run_line("security.osv-applicability")
    assert ": succeeded" in out, out
    gate.activate(gate.egress(run)["proposal_id"])
    held = _assessments(gate)
    assert held[("gate-app--1.1.0", LOG4SHELL)] == (
        "not_affected", "vulnerable_code_not_present"), held
    assert held[("gate-app--1.0.0", LOG4SHELL)] == ("affected", None), held
    record("19", f"changed SBOM added 1 component to gate-app 1.0.0 "
           f"({len(changed['target_paths'])} paths); gate-app 1.1.0 landed as a new release "
           f"({len(new['target_paths'])} paths) reusing product and supplier; OSV assessed "
           "1.1.0 (Log4Shell not_affected at log4j-core 2.17.1); 1.0.0 kept")


def test_20_exit(gate: Gate) -> None:
    for item in _inbox(gate, "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])
    # Retiring and restoring the EPSS score intentionally resurfaces a refusal.
    # Core's documented repair is a Line successor, not waiting for it to age out.
    findings: list[dict[str, Any]] = []

    def restoration_warning() -> bool:
        findings[:] = gate.json("next")["items"]
        return any(row["reason"] == "line_settled_prior_refusals" for row in findings)

    gate.wait(restoration_warning, 120, "EPSS restoration warning not observed")
    (warning,) = findings  # Do not hide unrelated repair work.
    (gate.root / "epss-restoration-warning.json").write_text(
        json.dumps(warning, indent=2) + "\n")
    identity = "Line:security.epss-triage"
    assert warning["severity"] == "warning" and warning["subject_identity"] == identity
    assert warning["repair"]["target"] == identity
    # Core's repair is the ready successor: the same Line capped at propose.
    assert warning["repair"]["operation"] == "cruxible.authoring.submit"
    assert warning["repair"]["required_change"] == (
        "demote_the_line_to_propose_or_bind_a_fixed_procedure")
    successor_payload = warning["repair"]["arguments"]["payload"]
    assert warning["repair"]["arguments"]["line"] == "security.epss-triage"
    assert (successor_payload["kind"], successor_payload["name"],
            successor_payload["max_authority"]) == ("line", "security.epss-triage", "propose")
    egress = gate.egress(warning["detail"]["latest_run_id"])
    assert egress["settle_outcome"] == "settled", egress
    receipts = [receipt for child in egress["children"] for receipt in child["prior_refusals"]]
    assert any(receipt["kind"] == "claim_retired" and receipt["rationale"] ==
               "Gate: verify score restoration after re-grant." for receipt in receipts), receipts
    old = gate.proof(identity)
    assert warning["detail"]["line_spec_digest"] == old["artifact_digest"]
    gate.submit("review-epss-restoration", {
        "kind": "change_set",
        "rationale": "Review EPSS results after the deliberate retirement/restoration probe.",
        "members": [successor_payload],
    })
    successor = gate.proof(identity)["envelope"]
    assert successor["identity"] == old["envelope"]["identity"]
    assert successor["lifecycle"]["predecessor_digest"] == old["artifact_digest"]
    assert successor["max_authority"] == "propose"
    assert successor["procedure"] == old["envelope"]["procedure"]
    gate.out("line", "enable", "security.epss-triage")
    gate.wait(lambda: "No repair work" in gate.next_text(), 120, "next not empty")
    kinds = set()
    for line in recipe.LINES:
        for run in gate.runs(line):
            proof = json.dumps(gate.proof(f"ProcedureRun:{run['run']}"))
            kinds |= {k for k in ("cadence", "capture_landing") if f'"{k}"' in proof}
            if '"enablement"' not in json.dumps(gate.card(run["run"]).get("triggered_by")):
                kinds.add("manual")
    assert {"manual", "cadence", "capture_landing"} <= kinds, kinds
    record("20", "EPSS prior-refusal receipt inspected; core's ready Line successor (capped at "
           f"propose) submitted and re-enabled; warning resolved; next empty; run history "
           f"{sorted(kinds)} plus dispatched backfill")


# --- the system model -----------------------------------------------------------

sys.path.insert(0, str(KIT / "source" / "providers" / "security-analysis-provider" / "src"))
REPO_KEY = {"forge_host": "github.com", "full_name": "cruxible-ai/cruxible"}
WORKFLOWS = {**REPO_KEY, "ref": "main", "scope": "ci.workflows", "path": ".github/workflows/"}
MAIN = "github.com/cruxible-ai/cruxible@main:.github/workflows/"
#: main's two recorded heads' workflow revisions (before and after publish-runtime-image.yml).
MAIN_OLD = "52509a27514eb9b081ede8a91fbd7539026bb322"
MAIN_NEW = "4e9b5db950bc66145fc72252be82b40a7826077c"
RELEASED = "e848cbb6787262db349912c48d9c008d8068ede8"  # v0.3.2: PyPI's provenance names it
MANIFEST = "src/cruxible_core/kit_distribution/manifest.json"
ASSET = "agent-release-0.3.2.tar.gz"
ASSET_URL = f"https://github.com/cruxible-ai/cruxible/releases/download/v0.3.2/{ASSET}"
GITHUB_API = "https://api.github.com/repos/cruxible-ai/cruxible"
SM_TARGETS = (("pypi", "cruxible"), ("pypi", "cruxible-client"),
              ("ghcr", "cruxible-ai/cruxible-runtime"), ("github_release", "cruxible-ai/cruxible"))
#: gap source -> the parse Line that reads its pull's landing.
PARSE_LINES = {"pypi/cruxible": "security.registry-parse.cruxible",
               "pypi/cruxible-client": "security.registry-parse.cruxible-client",
               MAIN: "security.repo-parse.cruxible-ci"}


def _sm_gates() -> dict[str, Any]:
    """Ask the questions: each release target's gate, and its repository where no
    registry provenance states one (PyPI's comes from its provenance)."""

    repo = _key("security.repo", REPO_KEY)
    members: list[dict[str, Any]] = [recipe.subject("security.repo", REPO_KEY,
                                                    "Our source repository.")]
    for registry, name in SM_TARGETS:
        key = {"registry": registry, "name": name}
        target = _key("security.target", key)
        members.append(recipe.subject("security.target", key, f"We publish {registry}/{name}."))
        members.append({"kind": "claim", "subject": target,
                        "predicate": "security.target.publish_gate",
                        "object": {"kind": "literal", "value": "push:tags:v*"},
                        "role": "normative", "rationale": "Only a v* tag push may publish.",
                        "source": {"kind": "self_source", "body": "gate: push:tags:v*\n"}})
        if registry != "pypi":
            members.append({"kind": "claim", "subject": target,
                            "predicate": "security.target.source_repo",
                            "object": {"kind": "subject", "subject": repo},
                            "role": "normative",
                            "rationale": f"{registry}/{name} is published from our repository.",
                            "source": {"kind": "self_source", "body": "source repository\n"}})
    return {"kind": "change_set", "rationale": "Ask the hardening questions.", "members": members}


def _harden(gate: Gate) -> tuple[str, dict[str, Any]]:
    """Run security.harden; its summary (every answer, none included) is the run's result."""

    run, out = gate.run_line("security.harden")
    assert ": succeeded" in out, out[-1500:]
    found = re.search(r"^Result: (\{.*\})$", out, re.M)
    assert found, out[-1500:]
    return run, json.loads(found.group(1))


def _answers(summary: dict[str, Any], question: str) -> dict[str, dict[str, Any]]:
    return {a["subject"]: a for a in summary["answers"] if a["question"] == question}


def _posted(gate: Gate, kind: str) -> list[dict[str, Any]]:
    """The harden Line's unread inbox payloads of one kind (gap or finding), in full."""

    found = []
    for entry in gate.json("inbox", "list", "--line", "security.harden", "--status",
                           "unread")["entries"]:
        payload = gate.json("inbox", "get", entry["item"]["item_id"])
        body = json.dumps(payload)
        if f'"kind": "{kind}"' in body:
            found.append({"item_id": entry["item"]["item_id"], "payload": _payload(payload)})
    return found


def _payload(value: Any) -> dict[str, Any]:
    """The posted object inside an ``inbox get`` answer."""

    if isinstance(value, dict):
        if value.get("kind") in {"gap", "finding"} and ("source" in value or "question" in value):
            return value
        for child in value.values():
            if (found := _payload(child)) is not None:
                return found
    if isinstance(value, list):
        for child in value:
            if (found := _payload(child)) is not None:
                return found
    return None  # type: ignore[return-value]


def _pull(gate: Gate, procedure: str, payload: dict[str, Any], line: str, label: str,
          *, accept: bool = True) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Run one pull; wait for the parse Line its landing runs; activate its proposal."""

    before = {r["run"] for r in gate.runs(line)}
    out = gate.out("procedure", "run", procedure, gate.payload(label, payload))
    assert ": succeeded" in out, out[-1500:]
    run = _wait_for_run(gate, line, before, 240)
    assert run["status"] == "succeeded", gate.out("get", run["run"])[-1500:]
    egress = gate.egress(run["run"])
    if accept and egress.get("proposal_id"):
        gate.activate(egress["proposal_id"])
    return out, run, egress


def _capture(out: str, alias: str) -> str:
    found = re.search(rf"Capture {alias}: (sha256:[0-9a-f]{{64}})", out)
    assert found, out[-800:]
    return found.group(1)


def _item_reasons(review: str) -> list[tuple[str, str]]:
    """(item path, reason) for every item ``proposal review`` lists, all of them."""

    head, _, block = review.partition("Item reasons (")
    count, _, rest = block.partition(")")
    shown, _, total = count.partition(" of ")
    assert shown == total, count  # every item's reason is shown
    items: list[tuple[str, str]] = []
    for line in rest.splitlines()[1:]:
        if line.startswith("    ") and items:
            items[-1] = (items[-1][0], (items[-1][1] + " " + line.strip()).strip())
        elif line.startswith("  ") and line.rstrip().endswith(":"):
            items.append((line.strip().rstrip(":"), ""))
        elif line.strip() and not line.startswith(" "):
            break
    assert len(items) == int(total), (len(items), total)
    return items


def _write(gate: Gate, label: str, payload: dict[str, Any]) -> dict[str, Any]:
    outcome = gate.json("write", gate.payload(label, payload))
    assert outcome["status"] == "accepted", json.dumps(outcome)[-1500:]
    return dict(outcome)


def _parse_line(name: str, *, ref: str, scope: str = "ci.workflows",
                path: str = ".github/workflows/") -> dict[str, Any]:
    """A parse Line for one more source, and its landing Trigger: kits are not rigid."""

    source = f"github.com/cruxible-ai/cruxible@{ref}"
    return {"kind": "change_set", "rationale": f"Model {source}:{path} too.", "members": [
        {"kind": "line", "name": name, "procedure_name": "security.repo-parse",
         "acquisition_policy_name": recipe.POLICY, "max_authority": "propose",
         "trigger_input": "snapshot",
         "parameters": {"source": f"{source}:{path}", "repo_source": source, **REPO_KEY,
                        "ref": ref, "scope": scope, "path": path}},
        {"kind": "trigger", "name": name.replace("repo-parse", "repo-landed"), "line_name": name,
         "schedule": {"kind": "capture_landing", "capture_contract": "security.repo-snapshot-v1"}},
    ]}


def _claim_ids(gate: Gate) -> dict[str, set[str]]:
    """Subject id -> the Claim IDs of every workflow and job fact held (live cells)."""

    held: dict[str, set[str]] = {}
    for kind, fields in (("security.workflow", "trigger,repo,coverage"),
                         ("security.job", "permission,secret,uses,environment,workflow,needs,"
                                          "publishes_to")):
        for row in gate.json("query", kind, "--select", fields, "--claims", "--all")["rows"]:
            ids = held.setdefault(row["subject_id"], set())
            for cells in (row.get("claims") or {}).values():
                ids.update(cell["claim"] for cell in cells or ())
    return held


#: The hardening queries' projected Subject fields, by the kind each binding holds.
BINDINGS = {"target": "security.target", "repo": "security.repo", "job": "security.job",
            "workflow": "security.workflow", "artifact": "security.artifact",
            **{name: "security.coverage" for name in (
                "coverage", "job_coverage", "workflow_coverage", "registry_coverage")}}


def _tap_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A named query's CLI rows in the state-tap row shape the classifier reads."""

    wire = []
    for row in rows:
        bindings, fields = [], []
        for name, value in row.items():
            if name in {"subject", "subject_id", "flags"}:
                continue
            if name in BINDINGS:
                if value:
                    kind = BINDINGS[name]
                    bindings.append({"binding": name, "subject_kind": kind, "subject_id": value,
                                     "subject_path": f"subjects/{kind}/{value}.json",
                                     "subject_identity": f"{kind}/{value}"})
                continue
            fields.append({"name": name, "state": "absent" if value is None else "present",
                           "value": value})
        wire.append({"bindings": bindings, "fields": fields})
    return wire


def test_21_ask_unknown(gate: Gate) -> None:
    for item in _inbox(gate, "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])
    gate.submit("sm-gates", _sm_gates())
    _, summary = _harden(gate)
    states = {a["state"] for a in summary["answers"]}
    assert states == {"unknown"} and summary["unknown"] >= 18, summary
    assert all(a["source"] and a["pull"] for a in summary["answers"]), summary["answers"]
    gaps = _posted(gate, "gap")
    sources = sorted(g["payload"]["source"] for g in gaps)
    assert sources == sorted(PARSE_LINES), sources  # one item per source, not per question
    gate.values["sm_gaps"] = {g["payload"]["source"]: g for g in gaps}
    for gap in gaps:
        assert set(gap["payload"]) == {"kind", "source", "pull", "input"}, gap
    record("21", f"{len(SM_TARGETS)} gated targets: {summary['unknown']} answers, all unknown, "
           f"each naming a source and its pull; {len(gaps)} gap items = distinct sources "
           f"{sources}; no Capture yet")


def test_22_pull_and_answer(gate: Gate) -> None:
    pulls = 0
    # PyPI first: its provenance names the targets' repository, so the repository's
    # parse then derives its jobs' publish edges against every target (harden counts a
    # credentialed job either way).
    for source, gap in sorted(gate.values["sm_gaps"].items(),
                              key=lambda item: (not item[0].startswith("pypi/"), item[0])):
        payload = gap["payload"]
        out, _run, egress = _pull(gate, payload["pull"], payload["input"], PARSE_LINES[source],
                                  f"gap-{pulls}")
        assert egress.get("proposal_id"), egress
        pulls += 1
        gate.values.setdefault("sm_captures", {})[source] = out
        gate.out("inbox", "ack", gap["item_id"])
    _, summary = _harden(gate)
    hq1 = _answers(summary, "HQ1")
    pypi = hq1[f"pypi/cruxible @ {MAIN}"]
    assert (pypi["state"], pypi["source"], pypi["revision"]) == ("none", MAIN, MAIN_OLD), pypi
    assert hq1[f"ghcr/cruxible-ai/cruxible-runtime @ {MAIN}"]["state"] == "found", hq1
    found = {f["payload"]["question"]: f["payload"] for f in _posted(gate, "finding")}
    assert {"HQ1", "HQ2", "HQ3", "HQ4"} <= found.keys(), sorted(found)
    hq2_jobs = {j["job"] for j in found["HQ2"]["jobs"]}
    assert "publish-kev-reference-world.yml#publish" in {j.rsplit("/", 1)[-1] for j in hq2_jobs}
    hq3_jobs = {j["job"].rsplit("/", 1)[-1]: j for j in found["HQ3"]["jobs"]}
    assert "pkg:githubactions/actions/checkout@v4" in hq3_jobs["publish.yml#publish-client"][
        "mutable"]
    assert "pkg:githubactions/actions/checkout@v4" in found["HQ4"]["shared"], found["HQ4"]
    hq5 = _answers(summary, "HQ5")
    waiting = {a["source"] for a in hq5.values() if a["state"] == "unknown"}
    released = f"github.com/cruxible-ai/cruxible@{RELEASED}:.github/workflows/"
    assert released in waiting, hq5  # what PyPI serves waits on the commit it names
    gaps = {g["payload"]["source"] for g in _posted(gate, "gap")}
    assert released in gaps and not gaps & set(PARSE_LINES), gaps
    record("22", f"{pulls} pulls (one per gap) parsed and accepted; HQ1 pypi/cruxible none at "
           f"{MAIN_OLD[:12]}, GHCR found; HQ2-HQ4 found; HQ5 waits on "
           f"{len(waiting)} publishing commit(s), each one gap ({len(gaps)} gaps now)")


def test_23_unchanged_repull(gate: Gate) -> None:
    head = gate.json("orient")["coordinate"]["git_oid"]
    first = _capture(gate.values["sm_captures"][MAIN], "snapshot")
    out, run, egress = _pull(gate, "security.repo-acquire", WORKFLOWS, PARSE_LINES[MAIN],
                             "repull", accept=False)
    second = _capture(out, "snapshot")
    assert second != first  # a new observation, its own envelope
    assert egress.get("proposal_id") is None, egress
    assert egress["children"] and all(c.get("unchanged") for c in egress["children"]), egress
    assert gate.json("orient")["coordinate"]["git_oid"] == head  # no generation
    bodies = [json.loads(gate.out("capture", "read", c, "--max-bytes", "0"))["envelope"][
        "commitment"] for c in (first, second)]
    assert bodies[0] == bodies[1], bodies  # the same content: one body
    record("23", f"identical re-pull: landing ran {run['run'][:16]}; the coverage revision "
           f"re-observed ({len(egress['children'])} unchanged item), no proposal, head unchanged; "
           "two Captures share one commitment")


def test_24_moved_source(gate: Gate) -> None:
    before = _claim_ids(gate)
    (gate.root / "security-gate-fixture.json").write_text(json.dumps(
        {"heads": {"cruxible-ai/cruxible": {"main": 1}}}))
    _out, _run, egress = _pull(gate, "security.repo-acquire", WORKFLOWS, PARSE_LINES[MAIN],
                               "moved", accept=False)
    proposal = egress["proposal_id"]
    assert proposal, egress
    reasons = _item_reasons(gate.out("proposal", "review", proposal))
    revisions = [path for path, why in reasons if "read every file" in why]
    others = [(path, why) for path, why in reasons
              if "read every file" not in why and "publish-runtime-image.yml" not in why]
    assert len(revisions) == 1 and not others, (revisions, others)  # one revision + the new file
    changed = reasons
    gate.activate(proposal)
    (coverage,) = gate.rows("security.coverage_index", source=MAIN, scope="ci.workflows")
    assert _field(coverage, "revision") == MAIN_NEW, coverage
    after = _claim_ids(gate)
    for subject, claims in before.items():
        assert after.get(subject) == claims, subject  # unchanged facts keep their Claims
    added = sorted(set(after) - set(before))
    assert added and all("publish-runtime-image" in subject for subject in added), added
    _, summary = _harden(gate)
    ghcr = _answers(summary, "HQ1")[f"ghcr/cruxible-ai/cruxible-runtime @ {MAIN}"]
    assert (ghcr["state"], ghcr["revision"]) == ("found", MAIN_NEW), ghcr
    finding = next(f["payload"] for f in _posted(gate, "finding")
                   if f["payload"]["question"] == "HQ1" and f["payload"]["revision"] == MAIN_NEW
                   and "ghcr" in f["payload"]["subject"])
    assert any(b["job"].endswith("publish-runtime-image.yml#build")
               and "workflow_dispatch" in b["triggers"] for b in finding["bypass"]), finding
    record("24", f"main moved {MAIN_OLD[:12]} -> {MAIN_NEW[:12]}: one coverage.revision revised, "
           f"{len(changed) - 1} other items all in publish-runtime-image.yml ({len(added)} new "
           f"Subjects); {len(before)} held workflows and jobs kept their Claims; HQ1 GHCR finds "
           "the dispatch bypass")


def test_25_publishing_commit(gate: Gate) -> None:
    name = "security.repo-parse.cruxible-released"
    gate.submit("released-line", _parse_line(name, ref=RELEASED))
    gate.out("line", "enable", name)
    released = f"github.com/cruxible-ai/cruxible@{RELEASED}:.github/workflows/"
    gap = next(g for g in _posted(gate, "gap") if g["payload"]["source"] == released)
    _pull(gate, gap["payload"]["pull"], gap["payload"]["input"], name, "released")
    gate.out("inbox", "ack", gap["item_id"])
    _, summary = _harden(gate)
    hq5 = _answers(summary, "HQ5")
    built = {s: a for s, a in hq5.items() if "0.3.2" in s and s.startswith("pypi/")}
    assert built and all(a["state"] == "none" and a["source"] == released
                         for s, a in built.items() if a.get("jobs")), built
    wheel = built["pypi/cruxible-client:cruxible_client-0.3.2-py3-none-any.whl"]
    assert wheel["jobs"] == ["publish-client"], wheel  # published from its environment's job
    record("25", f"parse Line authored for {RELEASED[:12]} (one write); its pull answered HQ5 "
           f"for {len(built)} 0.3.2 files: none, each naming {RELEASED[:12]}; cruxible-client's "
           "wheel matches publish-client (environment pypi-cruxible-client)")


def test_26_fail_closed(gate: Gate) -> None:
    from security_analysis_provider.harden import harden

    later = (datetime.now(UTC) + timedelta(hours=13)).isoformat().replace("+00:00", "Z")
    params = ["--param", f"source={MAIN}", "--param", "scope=ci.workflows"]
    held = gate.json("query", "--name", "security.coverage_index", *params,
                     "--evaluation-time", later)["rows"]
    assert held, held  # the parse still sees it (stale), to revise it
    rows = {name: _tap_rows(gate.json("query", "--name", query, "--all", "--evaluation-time",
                                      later)["rows"])
            for name, query in (("hq1", "security.publish_paths"),
                                ("hq2", "security.credentialed_jobs"),
                                ("hq3", "security.mutable_actions"),
                                ("hq4", "security.shared_dependencies"),
                                ("hq5", "security.served_vs_declared"),
                                ("hq6", "security.published_findings"))}
    # The coverage Subjects still join; their revision, re-read on every pull, is stale.
    assert rows["hq1"] and all(not any(f["name"] == "coverage_revision" and f["state"] == "present"
                                       for f in r["fields"]) for r in rows["hq1"]), rows["hq1"][:1]
    stale = harden({**rows, "params": {}})
    states = {(a["question"], a["state"]) for a in stale["answers"]
              if a["question"] in {"HQ1", "HQ2", "HQ3", "HQ4"}}
    assert {state for _q, state in states} == {"unknown"}, states
    assert MAIN in {g["source"] for g in stale["items"] if g["kind"] == "gap"}
    _, now = _harden(gate)
    assert now["none"] and now["found"], now  # still current now
    record("26", f"at +13 h (stale_after 12 h) coverage reads absent in every hardening row; "
           f"the classifier answers HQ1-HQ4 unknown and names {MAIN} again; current now")


def test_27_investigation(gate: Gate) -> None:
    import hashlib

    pulls = 0
    # Hop 1: what the release serves.
    out = gate.out("procedure", "run", "security.asset-fetch", gate.payload(
        "asset", {"url": ASSET_URL}))
    pulls += 1
    served = re.search(r'"body_digest": "(sha256:[0-9a-f]{64})"', out).group(1)
    asset_capture = _capture(out, "asset")
    # Hop 2: what the release declared, at the tag: one more source, one parse Line.
    name = "security.repo-parse.cruxible-v0.3.2-manifest"
    gate.submit("manifest-line", _parse_line(name, ref="v0.3.2", scope="release.manifest",
                                             path=MANIFEST))
    gate.out("line", "enable", name)
    _pull(gate, "security.repo-acquire", {**REPO_KEY, "ref": "v0.3.2",
                                          "scope": "release.manifest", "path": MANIFEST},
          name, "manifest")
    pulls += 1
    rows = gate.json("query", "--name", "security.registry_facts", "--param",
                     "registry=github_release", "--param", "name=cruxible-ai/cruxible",
                     "--all")["rows"]
    (row,) = [r for r in rows if _field(r, "artifact_name") == f"v0.3.2/{ASSET}"]
    artifact = _field(row, "artifact")
    declared = _field(row, "declared_sha256")
    assert declared and declared != served, (declared, served)
    _write(gate, "served", {
        "because": "The release serves these bytes (security.asset-fetch).",
        "subject": f"security.artifact/{artifact}",
        "changes": [{"op": "set", "field": "security.artifact.sha256", "value": served,
                     "evidence": {"kind": "capture",
                                                         "capture": asset_capture}}]})
    # The disagreement posts first, with both Claims.
    _, summary = _harden(gate)
    disagreement = next(f["payload"] for f in _posted(gate, "finding")
                        if f["payload"].get("disagreement") == "digest")
    for side, contract in (("declared", "security.repo-snapshot-v1"),
                           ("served", "security.release-asset-v1")):
        assert disagreement[side]["value"] == (declared if side == "declared" else served)
        assert contract in gate.out("get", disagreement[side]["claim"], "--detail", "evidence")
    # Hop 0: the signal, its observation and the note, in one write.
    fingerprint = "sha256:" + hashlib.sha256(
        f"{artifact}|{declared}|{served}".encode()).hexdigest()
    note = f"investigations/{fingerprint.removeprefix('sha256:')[:16]}.md"
    signal = _write(gate, "signal", {
        "because": "HQ5: the served agent-release asset does not match the v0.3.2 manifest.",
        "changes": [
            {"op": "create", "label": "signal", "subject_kind": "security.signal",
             "key": [{"predicate": "security.signal.detector", "value": "security.hq5"},
                     {"predicate": "security.signal.fingerprint", "value": fingerprint}]},
            {"op": "add", "subject": {"created": "signal"}, "field": "security.signal.observed",
             "value": f"security.artifact/{artifact}", "role": "normative",
             "evidence": {"kind": "section", "file": note, "section": ["Observation"],
                          "own_words": True}}],
        "docs": [{"op": "append", "file": note, "text": (
            f"# Observation\n\nv0.3.2 declares {ASSET} as {declared}; the release serves "
            f"{served} (Capture {asset_capture}).\n")}]})
    signal_id = next(c["subject"] for c in signal["changes"] if c["op"] == "create")
    # Hops 3 and 5: who uploaded it, and whether the path ran again.
    release_out = gate.out("procedure", "run", "security.release-acquire", gate.payload(
        "release", {"url": f"{GITHUB_API}/releases/tags/v0.3.2"}))
    runs_out = gate.out("procedure", "run", "security.history-acquire", gate.payload(
        "runs", {"url": f"{GITHUB_API}/actions/workflows/publish.yml/runs?branch=v0.3.2"
                        "&per_page=5"}))
    pulls += 2
    _write(gate, "uploaded", {
        "because": "The release API names the uploader.",
        "subject": f"security.artifact/{artifact}",
        "changes": [{"op": "set", "field": "security.artifact.uploaded_by",
                     "value": "github-actions[bot]",
                     "evidence": {"kind": "capture",
                                  "capture": _capture(release_out, "release")}}]})
    # Hop 6: two hypotheses contend for one slot.
    jobs = gate.rows("security.source_facts", source="github.com/cruxible-ai/cruxible@main")
    (bundles,) = {_field(r, "job") for r in jobs if _field(r, "job_key") == "publish-kit-bundles"}
    target = _field(rows[0], "target")
    for label, value, contend, text in (
        ("h1", f"security.job/{bundles}", False,
         "# H1\n\nA re-run of publish-kit-bundles rebuilt the asset and replaced it with "
         f"--clobber (runs: Capture {_capture(runs_out, 'history')}).\n"),
        ("h2", f"security.target/{target}", True,
         "# H2\n\nA repository writer uploaded the asset by hand.\n"),
    ):
        _write(gate, label, {
            "because": f"Hypothesis {label.upper()}.",
            "subject": f"security.signal/{signal_id.rsplit('/', 1)[-1]}",
            "changes": [{"op": "set", "field": "security.signal.explained_by", "value": value,
                         "contend": contend,
                         "evidence": {"kind": "section", "file": note,
                                      "section": [label.upper()], "own_words": True}}],
            "docs": [{"op": "append", "file": note, "text": text}]})
    assert "claim_conflicted" in {row["reason"] for row in gate.json("next")["items"]}
    # Hop 7: the code responsible; the right hypothesis is revised, the other retired.
    commits = gate.out("procedure", "run", "security.history-acquire", gate.payload(
        "commits", {"url": f"{GITHUB_API}/commits?path=scripts/build_kit_bundles.py"
                           "&sha=v0.3.2&per_page=5"}))
    pulls += 1
    hypotheses = gate.json("query", "security.signal", "--select", "explained_by",
                           "--claims")["rows"][0]["claims"]["explained_by"]
    h2 = next(c["claim"] for c in hypotheses if "security.target" in json.dumps(c["value"]))
    gate.out("retire", h2, "--reason", "was-wrong", "--because",
             "The uploader is the release bot and the run times match: not a hand upload.")
    change = {"op": "create", "label": "change", "subject_kind": "security.change",
              "key": [{"predicate": "security.change.repo_ref",
                       "value": "github.com/cruxible-ai/cruxible"},
                      {"predicate": "security.change.commit_sha",
                       "value": _commit(gate, commits)}]}
    _write(gate, "h1-revised", {
        "because": "build_kit_bundles.py last changed in this commit before v0.3.2.",
        "subject": f"security.signal/{signal_id.rsplit('/', 1)[-1]}",
        "changes": [change, {"op": "set", "field": "security.signal.explained_by",
                             "value": {"created": "change"},
                             "evidence": {"kind": "capture",
                                          "capture": _capture(commits, "history")}}]})
    resolved = gate.json("query", "security.signal", "--select", "explained_by",
                         "--claims")["rows"][0]["claims"]["explained_by"]
    assert len(resolved) == 1 and "security.change" in json.dumps(resolved[0]["value"]), resolved
    # Hop 8: the remediation.
    _write(gate, "remediation", {
        "because": "Verify the bundles before replacing a release asset.",
        "changes": [
            {"op": "create", "label": "fix", "subject_kind": "security.remediation"},
            {"op": "set", "subject": {"created": "fix"}, "field": "security.work.job",
             "value": f"security.job/{bundles}"},
            {"op": "set", "subject": {"created": "fix"}, "field": "security.work.rationale",
             "value": "Verify before --clobber: refuse to replace an asset whose digest differs."},
        ]})
    assert pulls <= 7
    record("27", f"HQ5 posted the digest disagreement citing the manifest (repo-snapshot) and "
           f"served (release-asset) Claims; signal + observation + note in one write; H1/H2 "
           f"contended, H2 retired was-wrong, H1 revised to the change: resolved; remediation "
           f"on publish-kit-bundles; {pulls} pulls")


def _commit(gate: Gate, out: str) -> str:
    """The newest commit a history Capture (GitHub's commits answer) names."""

    import base64

    read = json.loads(gate.out("capture", "read", _capture(out, "history")))
    material = json.loads(base64.b64decode(read["material"]["body_access"]["body_base64"]))
    commits = json.loads(base64.b64decode(material["retrieved"]["body_base64"]))
    return str(commits[0]["sha"])


# --- code findings ----------------------------------------------------------------

SARIF = KIT / "source" / "providers" / "security-analysis-provider" / "tests" / "data" / "sarif"
GATE_APP = "github.com/cruxible-ai/gate-app"
GATE_APP_KEY = {"forge_host": "github.com", "full_name": "cruxible-ai/gate-app"}
VULNERABLE = "a382bce444533bfc4622e7f822b3d6c11cbd7510"  # the SARIF fixtures' revisions
FIXED = "4542a98e11173c33db444e3e537bb2eb0a214fe1"
PRINCIPALS = ("scanner", "auditor", "triage", "reviewer", "maintainer")
FINDING_LINES = {"import": "security.sarif-import.gate-app",
                 "attention": "security.sarif-attention.gate-app"}
SINK = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
GUARD = "if not path.startswith(BASE + os.sep):"
DB_PY = '''"""User lookups for gate-app."""

import sqlite3


class UserRepo:
    def __init__(self, path: str) -> None:
        self.conn = sqlite3.connect(path)

    def find_by_name(self, name: str) -> list[tuple[object, ...]]:
        cursor = self.conn.cursor()
        {sink}
        return cursor.fetchall()
'''
FILES_PY = '''"""Static files for gate-app."""

import os

BASE = "/srv/gate-app/static"


def read_static(relative: str) -> bytes:
    path = os.path.realpath(os.path.join(BASE, relative))
    if not path.startswith(BASE + os.sep):
        raise PermissionError(relative)
    with open(path, "rb") as handle:
        return handle.read()
'''
POC = '''from app.db import UserRepo


def test_rejects_injection(tmp_path):
    repo = UserRepo(str(tmp_path / "users.db"))
    repo.conn.execute("CREATE TABLE users (name TEXT)")
    repo.conn.execute("INSERT INTO users VALUES ('alice'), ('bob')")
    assert repo.find_by_name("x' OR '1'='1") == []
'''
POC_FAILED = '''<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="1" skipped="0" tests="1" time="0.031"
 timestamp="2026-10-21T12:00:00" hostname="gate"><testcase
 classname="tests.security.test_sqli_find_by_name" name="test_rejects_injection" time="0.004"><failure
 message="AssertionError: assert [('alice',), ('bob',)] == []">find_by_name("x' OR '1'='1") returned
every row: the name is interpolated into the SQL text.</failure></testcase></testsuite></testsuites>
'''


def _principals(gate: Gate) -> None:
    """Register each finder and reviewer, signed by the owner; load its settings file."""

    for name in PRINCIPALS:
        custody = gate.root / "keys" / name
        if not (custody / "cruxible.env").is_file():
            gate.out("principal", "add", name, "--key-dir", str(custody))
        env = dict(gate.env)
        for line in (custody / "cruxible.env").read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                env[key.strip().removeprefix("export ").strip()] = value.strip().strip("'\"")
        gate.principals[name] = env


def _approve(gate: Gate, proposal: str, who: str) -> dict[str, Any]:
    """``who`` signs; the signature completes the approval and activates the proposal."""

    receipt = gate.json("proposal", "approve", proposal, "--yes", who=who)
    assert receipt.get("activation"), json.dumps(receipt)[-1500:]
    return dict(receipt)


def _write_as(gate: Gate, who: str, label: str, payload: dict[str, Any], *,
              approver: str | None = None) -> dict[str, Any]:
    """A write by ``who``; independent approval stops it at a proposal ``approver`` signs."""

    outcome = gate.json("write", gate.payload(label, payload), who=who)
    if approver is None:
        return dict(outcome)
    assert outcome["status"] == "awaiting_approval", json.dumps(outcome)[-1500:]
    assert outcome["approval"]["reason"] == "independent_approval_required", outcome
    _approve(gate, outcome["proposal"]["proposal_id"], approver)
    return dict(outcome)


def _scan(gate: Gate, fixture: str, who: str = "scanner") -> dict[str, dict[str, Any]]:
    """Retain one SARIF log; wait for both findings Lines of each repository it lands on."""

    lines = (*FINDING_LINES.values(), "security.sarif-import.cruxible",
             "security.sarif-attention.cruxible")
    before = {line: {r["run"] for r in gate.runs(line)} for line in lines}
    (gate.ws / "scans").mkdir(exist_ok=True)
    shutil.copyfile(SARIF / fixture, gate.ws / "scans" / fixture)
    out = gate.out("procedure", "run", "security.sarif-acquire", gate.payload(
        f"sarif-{fixture}-{len(gate.values.get('scans', []))}",
        {"relative_path": f"scans/{fixture}"}), who=who)
    assert ": succeeded" in out and "Capture sarif:" in out, out[-1200:]
    gate.values.setdefault("scans", []).append(fixture)
    return {line: _wait_for_run(gate, line, before[line], 180) for line in lines}


def _import_proposal(gate: Gate, runs: dict[str, dict[str, Any]]) -> str:
    run = runs[FINDING_LINES["import"]]
    assert run["status"] == "succeeded", gate.out("get", run["run"])[-1500:]
    egress = gate.egress(run["run"])
    assert egress["kind"] == "propose_change_set" and egress["proposal_id"], egress
    return str(egress["proposal_id"])


def _findings(gate: Gate) -> dict[tuple[str, str], dict[str, Any]]:
    """(weakness, locus) -> the finding_index row's fields, with its id."""

    found = {}
    for row in gate.rows("security.finding_index", repo_ref=GATE_APP):
        fields = {name: _field(row, name) for name in (
            "repo_ref", "weakness", "locus", "rules", "reported_by", "severity",
            "verification", "verdict")}
        fields["id"] = row["subject_id"]
        found[(fields["weakness"], fields["locus"])] = fields
    return found


def _finding(gate: Gate, weakness: str, path: str, tool: str | None = None) -> dict[str, Any]:
    (row,) = [row for (w, locus), row in _findings(gate).items()
              if w == weakness and locus.startswith(path + "#")
              and (tool is None or tool in (row.get("reported_by") or ()))]
    return row


def _state(gate: Gate, finding: str, field: str) -> tuple[str, Any]:
    """(state, value) of one finding field as finder_record reads it: present, absent, conflict."""

    for row in gate.rows("security.finder_record", repo_ref=GATE_APP):
        if row["subject_id"] == finding:
            value = _field(row, field)
            if "contested" in (row.get("flags") or ()) and (value is None
                                                            or isinstance(value, list)):
                return "conflict", value
            return ("present" if value is not None else "absent"), value
    raise AssertionError(f"no finder_record row for {finding}")


def test_28_findings_setup(gate: Gate) -> None:
    for item in _inbox(gate, "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])
    (gate.ws / "app").mkdir(exist_ok=True)
    (gate.ws / "app" / "db.py").write_text(DB_PY.format(sink=SINK))
    (gate.ws / "app" / "files.py").write_text(FILES_PY)
    for name, path in (("gate-app-db", "app/db.py"), ("gate-app-files", "app/files.py")):
        gate.out("files", "add", name, path)
    _principals(gate)
    whoami = gate.json("whoami", who="scanner")
    assert "scanner" in json.dumps(whoami), whoami
    # The repository's findings Lines, one write: kits are not rigid.
    gate.submit("findings-lines", {"kind": "change_set", "rationale": "Import gate-app's scans.",
                                   "members": [
        {"kind": "line", "name": FINDING_LINES["import"], "procedure_name": "security.sarif-import",
         "acquisition_policy_name": recipe.POLICY, "max_authority": "propose",
         "trigger_input": "sarif", "parameters": {"repo_ref": GATE_APP}},
        {"kind": "line", "name": FINDING_LINES["attention"],
         "procedure_name": "security.sarif-attention", "acquisition_policy_name": recipe.POLICY,
         "max_authority": "observe", "trigger_input": "sarif",
         "parameters": {"repo_ref": GATE_APP}},
        {"kind": "trigger", "name": "security.sarif-landed.gate-app",
         "line_name": FINDING_LINES["import"],
         "schedule": {"kind": "capture_landing", "capture_contract": "security.sarif-v1"}},
        {"kind": "trigger", "name": "security.sarif-landed-attention.gate-app",
         "line_name": FINDING_LINES["attention"],
         "schedule": {"kind": "capture_landing", "capture_contract": "security.sarif-v1"}}]})
    # The scanner arms its Lines: their runs act as it, so it creates their proposals.
    for name in FINDING_LINES.values():
        gate.out("line", "enable", name, who="scanner")
    # The precondition: under self_approval_allowed a finder confirms its own report alone.
    (gate.ws / "reports").mkdir(exist_ok=True)
    (gate.ws / "reports" / "poc.xml").write_text(POC_FAILED)
    out = gate.out("procedure", "run", "security.reproduction-acquire", gate.payload(
        "poc", {"relative_path": "reports/poc.xml"}), who="scanner")
    assert ": succeeded" in out, out[-1200:]
    gate.values["poc"] = _capture(out, "reproduction")
    alone = {"because": "The scanner confirms the SQL injection it reported.",
             "changes": [
                 {"op": "create", "label": "finding", "subject_kind": "security.finding",
                  "key": [{"predicate": "security.finding.repo_ref", "value": GATE_APP},
                          {"predicate": "security.finding.weakness", "value": "CWE-89"},
                          {"predicate": "security.finding.locus",
                           "value": "app/db.py#snippet:probe"}]},
                 {"op": "set", "subject": {"created": "finding"},
                  "field": "security.finding.verdict", "value": "confirmed",
                  "evidence": {"kind": "capture", "capture": gate.values["poc"]}}]}
    path = gate.payload("finder-confirms", alone)
    assert gate.json("write", path, "--dry-run", who="scanner")["status"] == "would_accept"
    gate.submit("independent", {"kind": "approval_policy",
                                "approval_policy": {"mode": "independent_approval_required"}})
    assert "independent_approval_required" in gate.out("get", "ApprovalPolicy:instance")
    now = gate.json("write", path, "--dry-run", who="scanner")
    assert now["status"] == "would_await_approval", now
    assert now["approval"]["reason"] == "independent_approval_required", now
    record("28", f"{len(PRINCIPALS)} principals; gate-app findings Lines armed by the scanner; "
           "self_approval_allowed: the finder's own confirmed would_accept (the documented "
           "precondition); independent_approval_required: would_await_approval")


def test_29_report(gate: Gate) -> None:
    runs = _scan(gate, "semgrep-gate-app-vulnerable.sarif")
    assert runs["security.sarif-import.cruxible"]["status"] == "halted"
    assert "wrong_repo" in gate.out("get", runs["security.sarif-import.cruxible"]["run"])
    proposal = _import_proposal(gate, runs)
    review = gate.out("proposal", "review", proposal)
    assert "CWE-89" in review and "CWE-22" in review, review[-2000:]
    refused = gate.cx("proposal", "approve", proposal, "--yes", who="scanner", check=False)
    assert refused.returncode != 0 and "creator_forbidden" in refused.stdout + refused.stderr
    _approve(gate, proposal, "reviewer")
    held = _findings(gate)
    assert sorted(w for w, _ in held) == ["CWE-22", "CWE-89"], held
    sqli = _finding(gate, "CWE-89", "app/db.py")
    traversal = _finding(gate, "CWE-22", "app/files.py")
    assert sqli["reported_by"] == ["semgrep"] and sqli["severity"] == "high", sqli
    assert sqli["locus"].startswith("app/db.py#snippet:"), sqli  # Semgrep has no symbols
    assert traversal["severity"] == "medium", traversal
    gate.values.update(sqli=sqli["id"], traversal=traversal["id"])
    card = gate.out("get", f"security.finding/{sqli['id']}")
    assert GATE_APP in card, card[-1500:]
    # The same log again: nothing new.
    again = _scan(gate, "semgrep-gate-app-vulnerable.sarif")
    assert again[FINDING_LINES["import"]]["status"] == "halted"
    assert "no_change" in gate.out("get", again[FINDING_LINES["import"]]["run"])
    record("29", f"Semgrep SARIF -> 2 findings by key (CWE-89 {sqli['locus']}, CWE-22); "
           "the cruxible Line halted wrong_repo; the scanner's approval refused "
           "creator_forbidden, the reviewer's activated it; the same log again halted no_change")


def test_30_duplicate(gate: Gate) -> None:
    runs = _scan(gate, "auditor-gate-app.sarif", who="auditor")
    _approve(gate, _import_proposal(gate, runs), "reviewer")
    sqli = _finding(gate, "CWE-89", "app/db.py", tool="semgrep")
    assert sqli["id"] == gate.values["sqli"] and sqli["reported_by"] == ["auditor", "semgrep"]
    assert "auditor:CWE-89" in sqli["rules"], sqli
    assert len(_findings(gate)) == 2  # the agent's report merged: no new Subject
    attention = runs[FINDING_LINES["attention"]]
    assert attention["status"] == "succeeded", attention
    gaps = [g for g in _inbox(gate, "--line", FINDING_LINES["attention"], "--status", "unread")]
    (gap,) = gaps
    body = json.dumps(gate.json("inbox", "get", gap["item_id"]))
    assert "location_gap" in body and "auditor:CWE-79" in body, body[-1500:]
    gate.out("inbox", "ack", gap["item_id"])
    # CodeQL names no snippet and no symbol: its line hash is its own key.
    runs = _scan(gate, "codeql-gate-app-vulnerable.sarif")
    _approve(gate, _import_proposal(gate, runs), "reviewer")
    codeql = _finding(gate, "CWE-89", "app/db.py", tool="codeql")
    assert codeql["locus"].startswith("app/db.py#line-hash:") and codeql["id"] != sqli["id"]
    gate.values["codeql"] = codeql["id"]
    record("30", "the auditor's SARIF (same sink snippet) added reported_by auditor to the held "
           "finding: no new Subject; its unlocated CWE-79 result posted one location_gap; "
           f"CodeQL's line-hash locus is a third finding ({codeql['locus']})")


def test_31_locate_and_triage(gate: Gate) -> None:
    sqli, traversal = gate.values["sqli"], gate.values["traversal"]
    _write_as(gate, "triage", "locate", {
        "because": "The sink: find_by_name interpolates the caller's name into the SQL text.",
        "subject": f"security.finding/{sqli}",
        "changes": [{"op": "add", "field": "security.finding.location", "value": "app/db.py:12-12",
                     "evidence": {"kind": "file", "file": f"app/db.py#{SINK}"}}]},
              approver="reviewer")
    assert len(_claim_of(gate, sqli, "location")) == 1
    # Own words never back a verdict.
    own = gate.cx("write", gate.payload("own-words", {
        "because": "I read it; the path is checked.",
        "subject": f"security.finding/{traversal}",
        "changes": [{"op": "set", "field": "security.finding.verdict",
                     "value": "false_positive"}]}), "--dry-run", who="triage", check=False)
    assert "cruxible.write.evidence_required" in own.stdout + own.stderr, own.stdout[-1200:]
    for relative, label in (("app/files.py", "files"), ("app/db.py", "db")):
        out = gate.out("procedure", "run", "security.evidence-acquire", gate.payload(
            f"evidence-{label}", {"relative_path": relative}), who="triage")
        gate.values[f"read-{label}"] = _capture(out, "evidence")
    note = f"findings/{traversal}.md"
    _write_as(gate, "triage", "false-positive", {
        "because": "realpath plus the BASE prefix check keeps every path under the static root.",
        "subject": f"security.finding/{traversal}",
        "changes": [
            {"op": "set", "field": "security.finding.verdict", "value": "false_positive",
             "evidence": {"kind": "capture", "capture": gate.values["read-files"]}},
            {"op": "set", "field": "security.finding.justification", "value": "sanitized",
             "role": "normative",
             "evidence": {"kind": "capture", "capture": gate.values["read-files"]}}],
        "docs": [{"op": "append", "file": note, "text": (
            f"# Triage\n\nThe opened path is `os.path.realpath` of the join, refused unless it "
            f"starts with BASE (`{GUARD}`): sanitized.\n")}]}, approver="reviewer")
    # The wrong call on the SQL injection: it stands until someone contends it.
    _write_as(gate, "triage", "sqli-call", {
        "because": "find_by_name is only called with names from the session.",
        "subject": f"security.finding/{sqli}",
        "changes": [
            {"op": "set", "field": "security.finding.verdict", "value": "false_positive",
             "evidence": {"kind": "capture", "capture": gate.values["read-db"]}},
            {"op": "set", "field": "security.finding.justification",
             "value": "not_attacker_controlled", "role": "normative",
             "evidence": {"kind": "capture", "capture": gate.values["read-db"]}}]},
              approver="maintainer")
    assert _state(gate, traversal, "verdict") == ("present", "false_positive")
    assert _state(gate, sqli, "verdict") == ("present", "false_positive")
    record("31", "location cites app/db.py#<the sink line> (origin-only, catalogued file); an "
           "own-words verdict refused evidence_required; the CWE-22 false positive (sanitized, "
           "citing the read of files.py, a Triage section) and triage's SQLi call landed after "
           "review")


def test_32_confirm(gate: Gate) -> None:
    sqli = gate.values["sqli"]
    (gate.ws / "tests" / "security").mkdir(parents=True, exist_ok=True)
    (gate.ws / "tests" / "security" / "test_sqli_find_by_name.py").write_text(POC)
    poc = gate.values["poc"]  # reports/poc.xml: the PoC fails while vulnerable
    confirm = {"subject": f"security.finding/{sqli}",
               "changes": [{"op": "set", "field": "security.finding.verdict",
                            "value": "confirmed", "contend": True,
                            "evidence": {"kind": "capture", "capture": poc}}]}
    # The finder cannot confirm its own report: its approval is refused.
    own = _write_as(gate, "scanner", "scanner-confirms", {
        "because": "My report reproduces.", **confirm})
    assert own["status"] == "awaiting_approval", own
    refused = gate.cx("proposal", "approve", own["proposal"]["proposal_id"], "--yes",
                      who="scanner", check=False)
    assert refused.returncode != 0 and "creator_forbidden" in refused.stdout + refused.stderr
    gate.out("proposal", "withdraw", own["proposal"]["proposal_id"], "--reason",
             "The reviewer confirms with the PoC instead.", who="scanner")
    note = f"findings/{sqli}.md"
    _write_as(gate, "reviewer", "confirm", {
        "because": "The PoC test returns every row for x' OR '1'='1 while find_by_name "
                   "interpolates the name: the injection is real.",
        "subject": f"security.finding/{sqli}",
        "changes": [
            *confirm["changes"],
            {"op": "set", "field": "security.finding.reproduction",
             "value": "tests/security/test_sqli_find_by_name.py::test_rejects_injection",
             "evidence": {"kind": "section", "file": note, "section": ["Reproduction"],
                          "own_words": True}},
            {"op": "add", "field": "security.finding.affects",
             "value": "security.release/gate-app--1.0.0"}],
        "docs": [{"op": "append", "file": note, "text": (
            "# Reproduction\n\n`tests/security/test_sqli_find_by_name.py::test_rejects_injection`"
            " inserts two users and looks up `x' OR '1'='1`; it gets both rows back (Capture "
            f"{poc}).\n")}]}, approver="maintainer")
    assert _state(gate, sqli, "verdict")[0] == "conflict"
    assert "claim_conflicted" in {row["reason"] for row in gate.json("next")["items"]}
    wrong = [c["claim"] for c in _claim_of(gate, sqli, "verdict")
             if c["value"] == "false_positive"]
    wrong += [c["claim"] for c in _claim_of(gate, sqli, "justification")]
    assert len(wrong) == 2, wrong
    _write_as(gate, "maintainer", "retire-wrong-call", {
        "because": "The PoC reproduces the injection: triage's call was wrong.",
        "changes": [{"op": "retire", "target": claim, "reason": "was-wrong"} for claim in wrong]},
              approver="reviewer")
    assert _state(gate, sqli, "verdict") == ("present", "confirmed")
    record("32", "the scanner's own confirmed stopped at a proposal its approval cannot "
           "activate (creator_forbidden); the reviewer's PoC-backed confirmed (contend) plus a "
           "Reproduction section and affects gate-app 1.0.0, approved by the maintainer; the "
           "slot read conflict (next: claim_conflicted); triage's call retired was-wrong; "
           "confirmed")


def _claim_of(gate: Gate, finding: str, field: str) -> list[dict[str, Any]]:
    """The live Claims of one finding field, with their IDs and values."""

    rows = gate.json("query", "security.finding", "--select", field, "--claims", "--all")["rows"]
    (row,) = [row for row in rows if row["subject_id"] == finding]
    return list((row.get("claims") or {}).get(field) or ())


def test_33_remediate(gate: Gate) -> None:
    sqli = gate.values["sqli"]
    _write_as(gate, "maintainer", "remediation", {
        "because": "Parameterize find_by_name.",
        "changes": [
            {"op": "create", "label": "fix", "subject_kind": "security.remediation"},
            {"op": "set", "subject": {"created": "fix"}, "field": "security.work.finding",
             "value": f"security.finding/{sqli}"},
            {"op": "set", "subject": {"created": "fix"}, "field": "security.remediation.progress",
             "value": "in_progress"},
            {"op": "set", "subject": {"created": "fix"}, "field": "security.work.rationale",
             "value": "Bind the name as a query parameter; keep the PoC as a regression test."}]},
              approver="reviewer")
    open_rows = gate.rows("security.open_findings", repo_ref=GATE_APP)
    assert any(r["subject_id"] == sqli and _field(r, "progress") == "in_progress"
               for r in open_rows), open_rows
    # What gate-app's release serves: one cited pull, then the target and its file.
    out = gate.out("procedure", "run", "security.release-acquire", gate.payload(
        "gate-app-release",
        {"url": "https://api.github.com/repos/cruxible-ai/gate-app/releases/tags/v1.0.0"}),
        who="maintainer")
    release = {"kind": "capture", "capture": _capture(out, "release")}
    target_key = [{"predicate": "security.target.registry", "value": "github_release"},
                  {"predicate": "security.target.name", "value": "cruxible-ai/gate-app"}]
    _write_as(gate, "maintainer", "gate-app-target", {
        "because": "gate-app ships as a GitHub release; only a v* tag may publish it.",
        "changes": [
            {"op": "create", "label": "target", "subject_kind": "security.target",
             "key": target_key},
            {"op": "add", "subject": {"created": "target"},
             "field": "security.target.publish_gate", "value": "push:tags:v*"},
            {"op": "create", "label": "repo", "subject_kind": "security.repo",
             "key": [{"predicate": "security.repo.forge_host", "value": "github.com"},
                     {"predicate": "security.repo.full_name", "value": "cruxible-ai/gate-app"}]},
            {"op": "set", "subject": {"created": "target"},
             "field": "security.target.source_repo", "value": {"created": "repo"}},
            {"op": "create", "label": "file", "subject_kind": "security.artifact",
             "key": [{"predicate": "security.artifact.target_ref",
                      "value": "github_release/cruxible-ai/gate-app"},
                     {"predicate": "security.artifact.name",
                      "value": "v1.0.0/gate-app-1.0.0.tar.gz"}]},
            {"op": "set", "subject": {"created": "file"}, "field": "security.artifact.target",
             "value": {"created": "target"}, "evidence": release},
            {"op": "set", "subject": {"created": "file"}, "field": "security.artifact.release",
             "value": "security.release/gate-app--1.0.0", "evidence": release}]},
              approver="reviewer")
    for item in _inbox(gate, "--line", "security.harden", "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])
    _, summary = _harden(gate)
    (hq6,) = [f for f in _posted(gate, "finding") if f["payload"]["question"] == "HQ6"]
    payload = hq6["payload"]
    assert payload["finding"] == f"security.finding/{sqli}", payload
    assert payload["target"] == "github_release/cruxible-ai/gate-app", payload
    assert payload["releases"] == ["security.release/gate-app--1.0.0"], payload
    assert payload["artifacts"] == ["v1.0.0/gate-app-1.0.0.tar.gz"], payload
    gate.out("inbox", "ack", hq6["item_id"])
    record("33", "a remediation answers the finding (work.finding, in_progress: open_findings "
           "shows it); gate-app's release pull cites the gated target's file of release 1.0.0; "
           f"harden posted HQ6 for {payload['finding']} ({payload['severity']}) on "
           f"{payload['target']}")


def test_34_fix_and_verify(gate: Gate) -> None:
    sqli = gate.values["sqli"]
    (location,) = _claim_of(gate, sqli, "location")
    # The fix lands in the workspace: the cited sink line is gone, so the citation drifts.
    (gate.ws / "app" / "db.py").write_text(DB_PY.format(
        sink='cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'))
    drifted = [row for row in gate.json("next")["items"] if row["reason"] == "citation_drifted"
               and location["claim"] in json.dumps(row)]
    assert len(drifted) == 1, gate.json("next")["items"]
    drift_state = drifted[0]["detail"]["drift_state"]
    # A full re-scan of the fixed revision verifies the fix, finding by finding.
    runs = _scan(gate, "semgrep-gate-app-fixed.sarif")
    proposal = _import_proposal(gate, runs)
    reasons = gate.out("proposal", "review", proposal)
    assert "no longer reports" in reasons, reasons[-2000:]
    _approve(gate, proposal, "reviewer")
    runs = _scan(gate, "codeql-gate-app-fixed.sarif")
    _approve(gate, _import_proposal(gate, runs), "reviewer")
    held = {row["id"]: row for row in _findings(gate).values()}
    assert held[sqli]["verification"] == "fixed", held[sqli]
    assert held[gate.values["codeql"]]["verification"] == "fixed", held
    assert held[gate.values["traversal"]]["verification"] is None  # a false positive stays
    # The fix commit, and the location retired: valid then, obsolete now.
    _write_as(gate, "triage", "fixed-by", {
        "because": f"Fixed in {FIXED[:12]}: find_by_name binds the name as a parameter.",
        "subject": f"security.finding/{sqli}",
        "changes": [
            {"op": "create", "label": "change", "subject_kind": "security.change",
             "key": [{"predicate": "security.change.repo_ref", "value": GATE_APP},
                     {"predicate": "security.change.commit_sha", "value": FIXED}]},
            {"op": "set", "field": "security.finding.fixed_by", "value": {"created": "change"}},
            {"op": "retire", "target": location["claim"], "reason": "superseded"}]},
               approver="reviewer")
    assert not [row for row in gate.json("next")["items"] if row["reason"] == "citation_drifted"
                and location["claim"] in json.dumps(row)]
    assert sqli not in {r["subject_id"] for r in gate.rows("security.unverified_fixes")}
    assert sqli not in {r["subject_id"] for r in gate.rows("security.open_findings",
                                                            repo_ref=GATE_APP)}
    _, summary = _harden(gate)
    assert not [a for a in _answers(summary, "HQ6").values()
                if a.get("subject", "").endswith(sqli)], summary["answers"]
    # A later scan that reports it again: a regression, proposed and posted.
    runs = _scan(gate, "semgrep-gate-app-vulnerable.sarif")
    proposal = _import_proposal(gate, runs)
    assert "again after it was verified fixed" in gate.out("proposal", "review", proposal)
    _approve(gate, proposal, "reviewer")
    assert _findings(gate)[(held[sqli]["weakness"], held[sqli]["locus"])][
        "verification"] == "present"
    posted = [json.dumps(gate.json("inbox", "get", item["item_id"])) for item in
              _inbox(gate, "--line", FINDING_LINES["attention"], "--status", "unread")]
    assert any('"regression"' in body and sqli in body for body in posted), posted
    # The finder track record: upheld (confirmed, not_exploitable) against overturned.
    record_rows = gate.rows("security.finder_record", repo_ref=GATE_APP)
    precision: dict[str, list[int]] = {}
    for row in record_rows:
        verdict = _field(row, "verdict")
        if verdict not in {"confirmed", "not_exploitable", "false_positive"}:
            continue
        for finder in _field(row, "reported_by") or ():
            counts = precision.setdefault(finder, [0, 0])
            counts[0 if verdict != "false_positive" else 1] += 1
    assert precision == {"semgrep": [1, 1], "auditor": [1, 0]}, precision
    record("34", f"the fix made the location citation drift ({drift_state}); full Semgrep and "
           "CodeQL re-scans proposed verification fixed (the false positive untouched); "
           "fixed_by + the location retired superseded cleared the drift row; unverified_fixes "
           "and HQ6 clear; the vulnerable log again proposed present and posted a regression; "
           f"finder record upheld/overturned {precision}")


# --- incident response: PHP2Shell, patch, audit, rotate --------------------------------
# The design's roles on the gate's five principals: responder = triage, the actor (ops)
# = maintainer, scanner = scanner, auditor = auditor, the security lead = reviewer.

INCIDENT_DATA = (KIT / "source" / "providers" / "security-analysis-provider" / "tests" /
                 "data" / "incident")
RESPONDER, OPS, SCANNER, AUDITOR, LEAD = "triage", "maintainer", "scanner", "auditor", "reviewer"
PHP2SHELL = ("CVE-2026-109618", "CVE-2026-109619")
INCIDENT_NAME = "PHP2Shell"
WINDOW_START, WINDOW_END = "2026-09-01T00:00:00Z", "2026-10-17T00:00:00Z"
RESPOND = "security.respond.php2shell"
LOG_IMPORT = "security.log-import.php2shell"
PROD, OPS_SCOPE = "security.inventory-import.prod", "security.inventory-import.ops"
CREDENTIAL_IMPORT = "security.credential-import"
HOSTS = {"storefront-a": "k8s:prod/storefront-a", "storefront-b": "k8s:prod/storefront-b",
         "app-1": "app-1.acme.internal", "wiki-1": "wiki-1.ops.acme.internal"}
#: Each service's standing log sources (service.log_source), each citing its section of
#: LOG_DOC: retention, the tool and the owner live there, never in the value.
SERVICE_LOGS = {"storefront": ("storefront/nginx-access", "storefront/php-fpm"),
                "partner-portal": ("partner-portal/apache",), "ops-wiki": ("ops-wiki/nginx",)}
LOG_DOC = "security/log-sources.md"
INCIDENT_NOTE = "incidents/php2shell.md"
#: How long step 37's exception holds: long enough to approve it and ask once.
EXCEPTION_SECONDS = 75
#: One section per service under one heading (a doc append adds one heading subtree).
LOG_DOC_SECTIONS = {
    "storefront": "storefront/nginx-access and storefront/php-fpm: Loki, 30-day retention, "
                  "the platform team.",
    "partner-portal": "partner-portal/apache: the host's /var/log/apache2, 90-day retention, "
                      "the partner team.",
    "ops-wiki": "ops-wiki/nginx: the host's /var/log/nginx, 14-day retention, the ops team."}
CREDENTIALS = {"aws": ("aws-iam/111122223333", "storefront-app", "storefront"),
               "stripe": ("stripe", "storefront-live", "storefront"),
               "postgres": ("postgres/partners-db", "portal", "partner-portal"),
               "github": ("github/acme-ops", "wiki-deploy", "ops-wiki")}


def _incident_ready(gate: Gate) -> None:
    """The owner's settings and the principals (also when steps 35-42 run alone on a kept
    root, after steps 01-34)."""

    here = {key: gate.env[key] for key in (
        "CRUXIBLE_STATE_ROOT", "CRUXIBLE_SERVER_SOCKET", "CRUXIBLE_ARTIFACT_CACHE")}
    if not any(key.startswith("CRUXIBLE_") and key not in here for key in gate.env):
        gate.load_settings()  # a kept root: its settings name the old run's socket
        gate.env.update(here)
    if not gate.principals:
        _principals(gate)
        for env in gate.principals.values():
            env.update(here)


def _find(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if value.get(key):
            return value[key]
        for child in value.values():
            if (found := _find(child, key)) is not None:
                return found
    if isinstance(value, list):
        for child in value:
            if (found := _find(child, key)) is not None:
                return found
    return None


def _submit_as(gate: Gate, who: str, label: str, payload: dict[str, Any],
               approver: str) -> dict[str, Any]:
    """An authored ChangeSet by ``who``; under independent approval ``approver`` signs."""

    result = json.loads(gate.out("authoring", "submit", gate.payload(label, payload), who=who))
    if (result.get("outcome") or {}).get("status") != "landed":
        proposal = _find(result, "proposal_id")
        assert proposal, json.dumps(result)[-1500:]
        _approve(gate, proposal, approver)
    return result


def _incident_file(gate: Gate, fixture: str, relative: str) -> str:
    target = gate.ws / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(INCIDENT_DATA / fixture, target)
    return relative


def _land(gate: Gate, procedure: str, alias: str, fixture: str, relative: str, who: str,
          lines: tuple[str, ...]) -> tuple[str, str, dict[str, dict[str, Any]]]:
    """Acquire one workspace file as ``who``; wait for the Lines its landing runs."""

    before = {line: {r["run"] for r in gate.runs(line)} for line in lines}
    _incident_file(gate, fixture, relative)
    out = gate.out("procedure", "run", procedure, gate.payload(
        f"{alias}-{fixture}-{len(gate.values.setdefault('landings', []))}",
        {"relative_path": relative}), who=who)
    gate.values["landings"].append(fixture)
    assert ": succeeded" in out, out[-1500:]
    run = re.search(r"(RUN-[0-9a-f]+)", out)
    assert run, out[-800:]
    return _capture(out, alias), run.group(1), {
        line: _wait_for_run(gate, line, before[line], 240) for line in lines}


def _proposal(gate: Gate, run: dict[str, Any]) -> str | None:
    assert run["status"] in {"succeeded", "halted"}, gate.out("get", run["run"])[-1500:]
    egress = gate.egress(run["run"]) if run["status"] == "succeeded" else {}
    return egress.get("proposal_id")


def _respond(gate: Gate) -> dict[str, Any]:
    """Run the incident's respond Line; its summary (every answer) is the run's result."""

    out = ""
    for _attempt in range(12):  # a window-close run of the same Line may be in flight
        result = gate.cx("line", "run", RESPOND, check=False)
        out = result.stdout + result.stderr
        if result.returncode == 0 and (": succeeded" in out or ": halted" in out):
            break
        time.sleep(5)
    assert ": succeeded" in out or ": halted" in out, out[-1500:]
    run = re.search(r"(RUN-[0-9a-f]+)", out).group(1)  # type: ignore[union-attr]
    found = re.search(r"^Result: (\{.*\})$", out, re.M)
    if found:
        return dict(json.loads(found.group(1)))
    result = gate.card(run).get("result")
    if isinstance(result, dict):
        return dict(result)
    assert ": halted" in out, out[-1500:]
    return {"halted": True}


def _states(summary: dict[str, Any], question: str) -> dict[str, str]:
    return {a["subject"]: a["state"] for a in summary["answers"] if a["question"] == question}


def _respond_posts(gate: Gate, kind: str | None = None,
                   status: str = "unread") -> list[dict[str, Any]]:
    """The respond Line's inbox payloads (``kind`` only), with their item ids."""

    found = []
    for entry in gate.json("inbox", "list", "--line", RESPOND, "--status", status)["entries"]:
        item = gate.json("inbox", "get", entry["item"]["item_id"])
        body = next((v for v in _walk(item) if isinstance(v, dict)
                     and v.get("incident") == INCIDENT_NAME and "kind" in v), {})
        if kind is None or body.get("kind") == kind:
            found.append({"item_id": entry["item"]["item_id"], "payload": body})
    return found


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _ack_all(gate: Gate) -> None:
    for item in _inbox(gate, "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])


def _key_of(kind: str, **key: str) -> list[dict[str, str]]:
    return [{"predicate": f"{kind}.{name}", "value": value} for name, value in key.items()]


def _write_created(gate: Gate, who: str, label: str, payload: dict[str, Any],
                   approver: str) -> dict[str, str]:
    """A write by ``who`` that ``approver`` signs; label -> kind/id of each Subject it
    creates (the outcome's changes answer the request's changes in order)."""

    outcome = _write_as(gate, who, label, payload, approver=approver)
    created = {}
    for change, answer in zip(payload["changes"], outcome.get("changes") or (), strict=False):
        if change.get("op") == "create" and change.get("label") and answer.get("subject"):
            subject = str(answer["subject"])
            if "/" not in subject:
                subject = f"{change['subject_kind']}/{subject}"
            created[change["label"]] = subject
    assert all(c.get("label") in created for c in payload["changes"] if c["op"] == "create"), (
        json.dumps(outcome)[-1500:])
    return created


def _assessment(gate: Gate, release_id: str, cve: str) -> str:
    _assessments(gate)
    return str(gate.values["assessment_ids"][(release_id, cve)])


def _release_id(gate: Gate, product: str, version: str) -> str:
    for row in gate.rows("security.release_inventory"):
        if _field(row, "product_name") == product and _field(row, "version") == version:
            return str(row["subject_id"])
    raise AssertionError(f"no release {product} {version}")


def _host_ids(gate: Gate) -> dict[str, str]:
    """HOSTS' short names -> their asset Subject ids (query rows name a Subject by id)."""

    return {short: gate.values["incident_subjects"][short].rsplit("/", 1)[-1] for short in HOSTS}


def _audit_asks(gate: Gate) -> dict[str, list[str]]:
    """service -> the log sources the respond Line's audit gap names (read or not)."""

    asks: dict[str, list[str]] = {}
    for status in ("acknowledged", "unread"):
        for post in _respond_posts(gate, "gap", status=status):
            ask = post["payload"].get("input") or {}
            if ask.get("state") == "security.audit.log_source" and "sources" in ask and (
                    "audit" in ask):
                asks[post["payload"]["subject"]] = list(ask["sources"])
    return asks


def test_35_inventory_and_listing(gate: Gate) -> None:
    _incident_ready(gate)
    _ack_all(gate)
    # What the responder knows: the services, the workloads that serve them, what wiki-1
    # declares, and where each credential is used (own words; the lead approves).
    services = {name: f"svc-{name}" for name in ("storefront", "partner-portal", "ops-wiki")}
    changes: list[dict[str, Any]] = []
    for name, label in services.items():
        changes.append({"op": "create", "label": label, "subject_kind": "security.service",
                        "key": _key_of("security.service", name=name)})
        # Where its logs live: pointers only, each citing the service's section of LOG_DOC.
        changes += [{"op": "add", "subject": {"created": label},
                     "field": "security.service.log_source", "value": source,
                     "evidence": {"kind": "section", "file": LOG_DOC,
                                  "section": ["Log sources", name],
                                  "own_words": True}} for source in SERVICE_LOGS[name]]
    serves = {"storefront-a": "storefront", "storefront-b": "storefront", "app-1": "partner-portal",
              "wiki-1": "ops-wiki"}
    for short, host in HOSTS.items():
        changes += [
            {"op": "create", "label": short, "subject_kind": "security.asset",
             "key": _key_of("security.asset", hostname=host)},
            {"op": "set", "subject": {"created": short}, "field": "security.asset.internet_exposed",
             "value": short != "wiki-1"},
            {"op": "add", "subject": {"created": short}, "field": "security.asset.serves",
             "value": {"created": services[serves[short]]}}]
    changes += [
        {"op": "create", "label": "php-old", "subject_kind": "security.release",
         "key": _key_of("security.release", product_name="php", version="8.3.10")},
        {"op": "add", "subject": {"created": "wiki-1"}, "field": "security.asset.installs",
         "value": {"created": "php-old"}}]
    for short, (issuer, name, service) in CREDENTIALS.items():
        changes += [
            {"op": "create", "label": f"cred-{short}", "subject_kind": "security.credential",
             "key": _key_of("security.credential", issuer=issuer, name=name)},
            {"op": "add", "subject": {"created": f"cred-{short}"},
             "field": "security.credential.used_by", "value": {"created": services[service]}}]
    gate.values["incident_subjects"] = _write_created(gate, RESPONDER, "incident-context", {
        "because": "Acme's services, where their logs live, the workloads and hosts serving "
                   "them, and the credentials each uses (non-secret identities only).",
        "changes": changes, "docs": [{"op": "append", "file": LOG_DOC, "text": "# Log sources\n\n"
                                      + "".join(f"## {name}\n\n{text}\n\n" for name, text
                                                in LOG_DOC_SECTIONS.items())}]},
        LEAD)
    held = gate.claims("security.service", "security.service.log_source")
    assert sorted(held) == sorted(gate.values["incident_subjects"][f"svc-{name}"].rsplit(
        "/", 1)[-1] for name in SERVICE_LOGS), held
    # The scanner arms the inventory and credential imports: their proposals are its.
    for line in (PROD, CREDENTIAL_IMPORT):
        gate.out("line", "enable", line, who=SCANNER)
    # G14: a Syft SBOM of one workload's image (annotated with its scope and asset).
    _, sbom_run, runs = _land(gate, "security.inventory-acquire", "inventory",
                              "storefront-a.syft.cdx.json", "inventory/storefront-a.cdx.json",
                              SCANNER, (PROD,))
    proposal = _proposal(gate, runs[PROD])
    assert proposal, gate.out("get", runs[PROD]["run"])[-1500:]
    review = gate.out("proposal", "review", proposal)
    assert "pkg:generic/php@8.3.10" in review and "libc6" in review, review[-2000:]
    refused = gate.cx("proposal", "approve", proposal, "--yes", who=SCANNER, check=False)
    assert refused.returncode != 0 and "creator_forbidden" in refused.stdout + refused.stderr
    _approve(gate, proposal, LEAD)
    # The same image re-scanned: its own timestamp and serial, the same run set.
    head = gate.json("orient")["coordinate"]["git_oid"]
    _, _, again = _land(gate, "security.inventory-acquire", "inventory",
                        "storefront-a.syft.rescan.cdx.json", "inventory/storefront-a.cdx.json",
                        SCANNER, (PROD,))
    assert again[PROD]["status"] == "halted" and "no_change" in gate.out("get",
                                                                          again[PROD]["run"])
    assert gate.json("orient")["coordinate"]["git_oid"] == head
    # The scope's full scan (the kit body): the other two exposed deployments.
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "prod-before.json",
                       "inventory/prod.json", SCANNER, (PROD,))
    proposal = _proposal(gate, runs[PROD])
    assert proposal
    _approve(gate, proposal, LEAD)
    assert {HOSTS["storefront-a"], HOSTS["storefront-b"], HOSTS["app-1"]} <= {
        _field(r, "hostname") for r in gate.rows("security.inventory_index", scope="prod")}
    # KEV lists PHP2Shell: attention says inventory has php.
    marker = gate.root / "security-gate-fixture.json"
    held = json.loads(marker.read_text()) if marker.is_file() else {}
    marker.write_text(json.dumps({**held, "kev": "known_exploited_vulnerabilities-2026-10-17.json"}))
    seen = {r["run"] for r in gate.runs("security.kev-attention")}
    gate.out("line", "run", "security.kev-daily")
    _wait_for_run(gate, "security.kev-attention", seen, 180)
    posted = [json.dumps(gate.json("inbox", "get", i["item_id"])) for i in _inbox(
        gate, "--line", "security.kev-attention", "--status", "unread")]
    listed = [body for body in posted if PHP2SHELL[0] in body and "inventory has php" in body]
    assert listed, posted
    actor = gate.card(sbom_run).get("actor")
    assert actor and SCANNER in json.dumps(actor), gate.card(sbom_run)
    gate.values["scanner_actor"] = actor
    record("35", "the services stated their log sources (pointers citing sections of "
           f"{LOG_DOC}); a Syft SBOM of k8s:prod/storefront-a landed its runs (php 8.3.10 and its "
           "Debian packages) proposed by the scanner (its own approval creator_forbidden); "
           "the re-scanned image (new timestamp) halted no_change, head unchanged; the prod "
           f"scope's full scan added storefront-b and app-1; KEV lists {PHP2SHELL[0]}: "
           f"kev-attention posted 'inventory has php'; the acquiring run's actor is {actor}")


def test_36_applicability_and_declaration(gate: Gate) -> None:
    _incident_ready(gate)
    for cve in PHP2SHELL:
        before = {r["run"] for r in gate.runs("security.cve-applicability")}
        out = gate.out("procedure", "run", "security.cve-record-acquire", gate.payload(
            f"record-{cve}", {"url": f"https://cveawg.mitre.org/api/cve/{cve}"}), who=RESPONDER)
        assert ": succeeded" in out, out[-1200:]
        run = _wait_for_run(gate, "security.cve-applicability", before, 180)
        proposal = _proposal(gate, run)
        assert proposal, gate.out("get", run["run"])[-1500:]
        review = gate.out("proposal", "review", proposal)
        assert "php8.2" not in review, review[-2000:]  # the distro build is OSV's
        _approve(gate, proposal, LEAD)
    run, out = gate.run_line("security.osv-applicability")
    proposal = gate.egress(run).get("proposal_id")
    assert proposal, out[-1500:]
    _approve(gate, proposal, LEAD)
    held = _assessments(gate)
    php = _release_id(gate, "php", "8.3.10")
    debian = _release_id(gate, "php8.2", "8.2.20-1~deb12u1")
    for cve in PHP2SHELL:
        assert held[(php, cve)][0] == "affected", held
        assert held[(debian, cve)][0] == "affected", held
    statuses = gate.claims("security.assessment", "security.assessment.status")
    evidence = gate.out("get", statuses[gate.values["assessment_ids"][(debian, PHP2SHELL[0])]][1],
                        "--detail", "evidence")
    assert "security.osv-query-v1" in evidence, evidence
    gate.values.update(php_release=php, debian_release=debian)
    # Exposure joins what scans observe too: storefront-a/-b and app-1 are known only from
    # scans (observed), wiki-1 only declares php 8.3.10 (asset, not seen running).
    ids = _host_ids(gate)
    urgent = [r for r in gate.rows("security.urgent_exposures")
              if _field(r, "cve_id") in PHP2SHELL]
    php_rows = [r for r in urgent if _field(r, "release") == php]
    assert {_field(r, "asset") for r in php_rows} == {ids["wiki-1"]}, php_rows
    assert {_field(r, "asset_observed") for r in php_rows} == {None}, php_rows
    assert {_field(r, "observed") for r in php_rows} == {ids["storefront-a"],
                                                         ids["storefront-b"]}, php_rows
    assert {_field(r, "observed_internet_exposed") for r in php_rows} == {True}, php_rows
    storefront = gate.values["incident_subjects"]["svc-storefront"].rsplit("/", 1)[-1]
    assert {_field(r, "observed_service") for r in php_rows} == {storefront}, php_rows
    deb_rows = [r for r in urgent if _field(r, "release") == debian]
    assert {(_field(r, "asset"), _field(r, "observed")) for r in deb_rows} == {
        (None, ids["app-1"])}, deb_rows
    # Declare the incident: its Claims, its respond and log-import Lines (README template).
    incident = _write_created(gate, RESPONDER, "incident", {
        "because": "One response to PHP2Shell (CVE-2026-109618, CVE-2026-109619): "
                   "unauthenticated RCE in PHP, exploited in the wild.",
        "changes": [
            {"op": "create", "label": "incident", "subject_kind": "security.incident",
             "key": _key_of("security.incident", name=INCIDENT_NAME)},
            {"op": "set", "subject": {"created": "incident"},
             "field": "security.incident.window_start", "value": WINDOW_START},
            {"op": "set", "subject": {"created": "incident"},
             "field": "security.incident.rotation_policy", "value": "on_found_or_unknown"},
            {"op": "set", "subject": {"created": "incident"}, "field": "security.incident.status",
             "value": "open"},
            {"op": "add", "subject": {"created": "incident"},
             "field": "security.incident.vulnerability",
             "value": f"security.vulnerability/{PHP2SHELL[0].lower()}"}]}, LEAD)
    gate.values["incident"] = incident["incident"]
    _write_as(gate, RESPONDER, "incident-cve-2", {
        "because": "The second PHP2Shell CVE.", "subject": gate.values["incident"],
        "changes": [{"op": "add", "field": "security.incident.vulnerability",
                     "value": f"security.vulnerability/{PHP2SHELL[1].lower()}"}]}, approver=LEAD)
    _submit_as(gate, RESPONDER, "incident-lines", {
        "kind": "change_set", "rationale": "PHP2Shell's respond and log import Lines.",
        "members": [
            {"kind": "line", "name": RESPOND, "procedure_name": "security.respond",
             "max_authority": "observe",
             "parameters": {"incident": INCIDENT_NAME,
                            "inventory_pull": "security.inventory-acquire",
                            "log_pull": "security.log-acquire",
                            "credential_pull": "security.credential-acquire",
                            "record_pull": "security.cve-record-acquire"}},
            {"kind": "line", "name": LOG_IMPORT, "procedure_name": "security.log-import",
             "acquisition_policy_name": recipe.POLICY, "max_authority": "propose",
             "trigger_input": "log", "parameters": {"incident": INCIDENT_NAME}},
            {"kind": "trigger", "name": "security.log-landed.php2shell", "line_name": LOG_IMPORT,
             "schedule": {"kind": "capture_landing", "capture_contract": "security.log-read-v1"}},
            # The gate's re-ask window is 30 s (a deployment's, a day).
            {"kind": "trigger", "name": "security.respond-after-rotation.php2shell",
             "line_name": RESPOND, "schedule": {"kind": "window_close", "window": {
                 "kind": "capture_event", "capture_contract": "security.credential-state-v1",
                 "duration_seconds": 30}}}]}, approver=LEAD)
    for line in (RESPOND, LOG_IMPORT):
        gate.out("line", "enable", line, who=RESPONDER)
    # G1: RQ1 found x3, wiki-1 unknown (declared, outside every scope); RQ2 missing x3.
    summary = _respond(gate)
    rq1 = _states(summary, "RQ1")
    found = sorted(s for s, state in rq1.items() if state == "found")
    assert found == [f"{HOSTS['app-1']}: php8.2 8.2.20-1~deb12u1",
                     f"{HOSTS['storefront-a']}: php 8.3.10",
                     f"{HOSTS['storefront-b']}: php 8.3.10"], rq1
    assert rq1[f"{HOSTS['wiki-1']}: php 8.3.10"] == "unknown", rq1
    gaps = {g["payload"]["subject"]: g["payload"] for g in _respond_posts(gate, "gap")}
    assert gaps[HOSTS["wiki-1"]]["pull"] == "security.inventory-acquire", gaps
    assert len(_respond_posts(gate, "patch_missing")) == 3
    assert len(_respond_posts(gate, "exposed")) == 3
    # No audit is stated yet: each exposed service's gap names its standing log sources.
    assert _audit_asks(gate) == {name: list(SERVICE_LOGS[name])
                                 for name in ("partner-portal", "storefront")}
    record("36", "the CVE records' ranges proposed php 8.3.10 affected and never touched the "
           "Debian build; OSV's distro advisory (upstream CVE ids) proposed php8.2 "
           "8.2.20-1~deb12u1 affected, citing the OSV Capture; PHP2Shell declared (incident, "
           "respond and log-import Lines, a window-close Trigger); urgent_exposures: php 8.3.10 "
           "declared on wiki-1 and observed only on storefront-a/-b, the Debian build observed "
           "only on app-1; respond: RQ1 found x3, wiki-1 unknown naming "
           "security.inventory-acquire, RQ2 patch_missing x3, the RQ3 gaps naming each "
           "service's log sources")


def _patch(gate: Gate, short: str, release: str, target: tuple[str, str], due: str) -> str:
    asset = gate.values["incident_subjects"][short]
    created = _write_created(gate, RESPONDER, f"patch-{short}", {
        "because": f"Move {HOSTS[short]} off the affected PHP build.",
        "changes": [
            {"op": "create", "label": "patch", "subject_kind": "security.remediation"},
            {"op": "set", "subject": {"created": "patch"}, "field": "security.work.asset",
             "value": asset},
            {"op": "set", "subject": {"created": "patch"}, "field": "security.work.assessment",
             "value": f"security.assessment/{_assessment(gate, release, PHP2SHELL[0])}"},
            {"op": "create", "label": "target", "subject_kind": "security.release",
             "key": _key_of("security.release", product_name=target[0], version=target[1])},
            {"op": "set", "subject": {"created": "patch"},
             "field": "security.remediation.target_release", "value": {"created": "target"}},
            {"op": "set", "subject": {"created": "patch"}, "field": "security.remediation.due_at",
             "value": due},
            {"op": "set", "subject": {"created": "patch"},
             "field": "security.remediation.progress", "value": "planned"}]}, LEAD)
    return created["patch"]


def _progress(gate: Gate, remediation: str, value: str, *, refuse_self: bool = False) -> None:
    outcome = _write_as(gate, OPS, f"progress-{remediation.rsplit('/', 1)[-1]}-{value}", {
        "because": f"Done with our own tools: {value}.", "subject": remediation,
        "changes": [{"op": "set", "field": "security.remediation.progress", "value": value}]})
    assert outcome["status"] == "awaiting_approval", outcome
    proposal = outcome["proposal"]["proposal_id"]
    if refuse_self:
        refused = gate.cx("proposal", "approve", proposal, "--yes", who=OPS, check=False)
        assert refused.returncode != 0 and "creator_forbidden" in refused.stdout + refused.stderr
    _approve(gate, proposal, LEAD)


def _verification(gate: Gate, remediation: str) -> Any:
    for row in gate.rows("security.incident_patches", incident=INCIDENT_NAME):
        if _field(row, "patch") == remediation.rsplit("/", 1)[-1]:
            return _field(row, "verification")
    raise AssertionError(f"no patch {remediation}")


def test_37_patch_closes_only_on_a_scan(gate: Gate) -> None:
    _incident_ready(gate)
    _ack_all(gate)  # each step reads only what it posts
    php, debian = _release_id(gate, "php", "8.3.10"), _release_id(gate, "php8.2",
                                                                  "8.2.20-1~deb12u1")
    # An accepted risk: the lead excepts app-1's Debian build for both CVEs, briefly. While
    # it holds, RQ2 is excepted (no patch_missing) and the status page shows its expiry;
    # past expires_at (the query clock) it is patch_missing again.
    expires = (datetime.now(UTC) + timedelta(seconds=EXCEPTION_SECONDS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    changes: list[dict[str, Any]] = []
    for index, cve in enumerate(PHP2SHELL):
        label = f"exception-{index}"
        changes += [
            {"op": "create", "label": label, "subject_kind": "security.exception"},
            {"op": "set", "subject": {"created": label}, "field": "security.work.asset",
             "value": gate.values["incident_subjects"]["app-1"]},
            {"op": "set", "subject": {"created": label}, "field": "security.work.assessment",
             "value": f"security.assessment/{_assessment(gate, debian, cve)}"},
            {"op": "set", "subject": {"created": label}, "field": "security.exception.expires_at",
             "value": expires},
            {"op": "set", "subject": {"created": label}, "field": "security.exception.approval",
             "value": "approved", "evidence": {"kind": "section", "file": INCIDENT_NOTE,
                                               "section": ["Exception for app-1"],
                                               "own_words": True}}]
    _write_created(gate, RESPONDER, "exception-app-1", {
        "because": "app-1's upgrade waits for the partner's maintenance window; the WAF rule "
                   "blocks the exploit path meanwhile.", "changes": changes,
        "docs": [{"op": "append", "file": INCIDENT_NOTE, "text": (
            f"# Exception for app-1\n\nThe Debian build stays until {expires}: the partner's "
            "maintenance window; a WAF rule blocks `?-d` query strings meanwhile.\n")}]}, LEAD)
    excepted = f"{HOSTS['app-1']}: php8.2 8.2.20-1~deb12u1"
    summary = _respond(gate)
    rq2 = _states(summary, "RQ2")
    assert rq2[excepted] == "excepted" and rq2[f"{HOSTS['storefront-a']}: php 8.3.10"] == (
        "found"), summary["answers"]
    status = gate.rows("security.incident_status", incident=INCIDENT_NAME)
    assert {_field(r, "excepted_until") for r in status
            if _field(r, "host") == HOSTS["app-1"]} == {expires}, status
    lapse = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    time.sleep(max(0.0, (lapse - datetime.now(UTC)).total_seconds()) + 2)
    summary = _respond(gate)
    assert _states(summary, "RQ2")[excepted] == "found", summary["answers"]
    assert not [r for r in gate.rows("security.incident_status", incident=INCIDENT_NAME)
                if _field(r, "host") == HOSTS["app-1"]]
    patches = {"storefront-a": _patch(gate, "storefront-a", php, ("php", "8.3.36"),
                                      "2026-12-01T00:00:00Z"),
               "storefront-b": _patch(gate, "storefront-b", php, ("php", "8.3.36"),
                                      "2026-10-18T00:00:00Z"),
               "app-1": _patch(gate, "app-1", debian, ("php8.2", "8.2.29-1~deb12u1"),
                               "2026-12-01T00:00:00Z")}
    gate.values["patches"] = patches
    summary = _respond(gate)
    overdue = [p["payload"] for p in _respond_posts(gate, "patch_overdue")]
    assert [p["asset"] for p in overdue] == [HOSTS["storefront-b"]], overdue
    # G3: ops claims all three done; the claim alone closes nothing, and ops cannot approve it.
    for index, remediation in enumerate(patches.values()):
        _progress(gate, remediation, "completed", refuse_self=index == 0)
    summary = _respond(gate)
    rq2 = _states(summary, "RQ2")
    assert {rq2[f"{HOSTS[s]}: {label}"] for s, label in (
        ("storefront-a", "php 8.3.10"), ("app-1", "php8.2 8.2.20-1~deb12u1"))} == {"unknown"}, rq2
    # G4: the scanner's scan disagrees for storefront-b (still 8.3.10): failed, disputed.
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "prod-mid.json",
                       "inventory/prod.json", SCANNER, (PROD,))
    proposal = _proposal(gate, runs[PROD])
    review = gate.out("proposal", "review", proposal)
    assert "still runs" in review and "no longer runs" in review, review[-2500:]
    _approve(gate, proposal, LEAD)
    assert _verification(gate, patches["storefront-a"]) == "verified"
    assert _verification(gate, patches["app-1"]) == "verified"
    assert _verification(gate, patches["storefront-b"]) == "failed"
    summary = _respond(gate)
    disputed = [p["payload"] for p in _respond_posts(gate, "patch_disputed")]
    assert [p["asset"] for p in disputed] == [HOSTS["storefront-b"]], disputed
    assert _states(summary, "RQ2")[f"{HOSTS['storefront-a']}: php 8.3.10"] == "none"
    # ops fixes it; the next full scan verifies (revising failed).
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "prod-after.json",
                       "inventory/prod.json", SCANNER, (PROD,))
    _approve(gate, _proposal(gate, runs[PROD]), LEAD)  # type: ignore[arg-type]
    assert _verification(gate, patches["storefront-b"]) == "verified"
    # G5: the same fleet again: a re-observation, no proposal, no generation.
    head = gate.json("orient")["coordinate"]["git_oid"]
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "prod-after.json",
                       "inventory/prod.json", SCANNER, (PROD,))
    egress = gate.egress(runs[PROD]["run"])
    assert egress.get("proposal_id") is None and all(
        c.get("unchanged") for c in egress.get("children") or ()), egress
    assert gate.json("orient")["coordinate"]["git_oid"] == head
    # The ops scope: its own import Line (kits are not rigid), wiki-1 runs 8.3.10.
    _submit_as(gate, RESPONDER, "ops-scope", {
        "kind": "change_set", "rationale": "Import the ops scope's inventory too.", "members": [
            {"kind": "line", "name": OPS_SCOPE, "procedure_name": "security.inventory-import",
             "acquisition_policy_name": recipe.POLICY, "max_authority": "propose",
             "trigger_input": "inventory", "parameters": {"scope": "ops"}},
            {"kind": "trigger", "name": "security.inventory-landed.ops", "line_name": OPS_SCOPE,
             "schedule": {"kind": "capture_landing",
                          "capture_contract": "security.runtime-inventory-v1"}}]}, approver=LEAD)
    gate.out("line", "enable", OPS_SCOPE, who=SCANNER)
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "ops-before.json",
                       "inventory/ops.json", SCANNER, (PROD, OPS_SCOPE))
    assert runs[PROD]["status"] == "halted" and "other_scope" in gate.out("get",
                                                                           runs[PROD]["run"])
    _approve(gate, _proposal(gate, runs[OPS_SCOPE]), LEAD)  # type: ignore[arg-type]
    summary = _respond(gate)
    assert _states(summary, "RQ1")[f"{HOSTS['wiki-1']}: php 8.3.10"] == "found", summary
    # wiki-1 declares php 8.3.10 and the ops scan sees it running: declared and observed,
    # never a second, observed-only row; the patched storefront workloads have left.
    ids = _host_ids(gate)
    rows = [r for r in gate.rows("security.urgent_exposures") if _field(r, "release") == php]
    assert {(_field(r, "asset"), _field(r, "asset_observed"), _field(r, "observed"))
            for r in rows} == {(ids["wiki-1"], ids["wiki-1"], None)}, rows
    patches["wiki-1"] = _patch(gate, "wiki-1", php, ("php", "8.3.36"), "2026-12-01T00:00:00Z")
    _progress(gate, patches["wiki-1"], "completed")
    _, _, runs = _land(gate, "security.inventory-acquire", "inventory", "ops-after.json",
                       "inventory/ops.json", SCANNER, (OPS_SCOPE,))
    _approve(gate, _proposal(gate, runs[OPS_SCOPE]), LEAD)  # type: ignore[arg-type]
    summary = _respond(gate)
    rq2 = _states(summary, "RQ2")
    assert all(rq2[f"{HOSTS[s]}: {label}"] == "none" for s, label in (
        ("storefront-a", "php 8.3.10"), ("storefront-b", "php 8.3.10"), ("wiki-1", "php 8.3.10"),
        ("app-1", "php8.2 8.2.20-1~deb12u1"))), rq2
    assert not gate.rows("security.open_patches", incident=INCIDENT_NAME)
    record("37", f"an approved exception for app-1 (both CVEs, expiring {EXCEPTION_SECONDS} s "
           "on) made its RQ2 excepted and showed on the status page (excepted_until); past "
           "its expiry RQ2 was patch_missing again and the row left the page; "
           "storefront-b's patch (due 2026-10-18) posted patch_overdue; ops' completed "
           "claims left RQ2 unknown (ops' own approval creator_forbidden); the scanner's scan "
           "proposed verified x2 and failed for storefront-b (patch_disputed); the fix's scan "
           "revised it verified; the same scan again: no proposal, head unchanged; the ops "
           "scope's Line (prod's halted other_scope) found wiki-1 on 8.3.10 (urgent_exposures: "
           "declared and observed), a 4th patch verified; RQ2 none x4, open_patches empty")


#: The incident queries' projected Subject fields, by the kind each binding holds.
RESPOND_BINDINGS = {
    "incident": "security.incident", "assessment": "security.assessment",
    "release": "security.release", "asset": "security.asset", "coverage": "security.coverage",
    "service": "security.service", "declared": "security.asset",
    "declared_coverage": "security.coverage", "patch": "security.remediation",
    "target": "security.release", "owner": "security.team", "audit": "security.audit",
    "credential": "security.credential", "rotation": "security.remediation",
    "rotation_audit": "security.audit", "exception": "security.exception"}


def _respond_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """An incident query's CLI rows in the state-tap row shape the classifier reads."""

    wire = []
    for row in rows:
        bindings, fields = [], []
        for name, value in row.items():
            if name in {"subject", "subject_id", "flags"}:
                continue
            if name in RESPOND_BINDINGS:
                if value:
                    kind = RESPOND_BINDINGS[name]
                    bindings.append({"binding": name, "subject_kind": kind, "subject_id": value,
                                     "subject_path": f"subjects/{kind}/{value}.json",
                                     "subject_identity": f"{kind}/{value}"})
                continue
            fields.append({"name": name, "state": "absent" if value is None else "present",
                           "value": value})
        wire.append({"bindings": bindings, "fields": fields})
    return wire


def test_38_fixed_builds_and_freshness(gate: Gate) -> None:
    from security_analysis_provider.response import respond

    _incident_ready(gate)
    _ack_all(gate)  # each step reads only what it posts
    # G2: the upstream fix is decided by the CVE record's ranges, the distro fix by OSV.
    before = {r["run"] for r in gate.runs("security.cve-applicability")}
    gate.out("procedure", "run", "security.cve-record-acquire", gate.payload(
        "record-again", {"url": f"https://cveawg.mitre.org/api/cve/{PHP2SHELL[0]}"}),
        who=RESPONDER)
    run = _wait_for_run(gate, "security.cve-applicability", before, 180)
    proposal = _proposal(gate, run)
    assert proposal, gate.out("get", run["run"])[-1500:]
    review = gate.out("proposal", "review", proposal)
    assert "php8.2" not in review, review[-2000:]
    _approve(gate, proposal, LEAD)
    run, out = gate.run_line("security.osv-applicability")
    proposal = gate.egress(run).get("proposal_id")
    assert proposal, out[-1500:]
    _approve(gate, proposal, LEAD)
    held = _assessments(gate)
    fixed = _release_id(gate, "php", "8.3.36")
    debian_fixed = _release_id(gate, "php8.2", "8.2.29-1~deb12u1")
    assert held[(fixed, PHP2SHELL[0])][0] == "not_affected", held
    for cve in PHP2SHELL:
        assert held[(debian_fixed, cve)] == ("not_affected", "vulnerable_code_not_present"), held
    # G6: 13 h on (stale_after 12 h) every coverage revision reads absent: none turns unknown.
    later = (datetime.now(UTC) + timedelta(hours=13)).isoformat().replace("+00:00", "Z")
    taps = {alias: _respond_rows(gate.json(
        "query", "--name", query, "--all", "--param", f"incident={INCIDENT_NAME}",
        "--evaluation-time", later)["rows"]) for alias, query in (
            ("exposure", "security.incident_exposure"), ("patches", "security.incident_patches"),
            ("overdue", "security.overdue_patches"),
            ("exceptions", "security.incident_exceptions"), ("audits", "security.audit_status"),
            ("credentials", "security.incident_credentials"))}
    stale = respond({**taps, "params": {"incident": INCIDENT_NAME}, "truncated": {}})
    rq2 = {s: state for s, state in _states(stale, "RQ2").items()}
    assert set(rq2.values()) == {"unknown"} and len(rq2) == 4, rq2
    assert {g["subject"] for g in stale["items"] if g["kind"] == "gap"} >= set(HOSTS.values())
    now = _respond(gate)
    assert set(_states(now, "RQ2").values()) == {"none"}, now["answers"]
    record("38", f"re-reading {PHP2SHELL[0]}'s record proposed php 8.3.36 not_affected and no "
           "php8.2 build; OSV proposed php8.2 8.2.29-1~deb12u1 not_affected "
           "(vulnerable_code_not_present) for both CVEs; at +13 h the coverage revisions read "
           "absent and RQ2 answers turn unknown x4, each naming its asset's scan; none now")


def _claim_ids_of(gate: Gate, kind: str, field: str) -> dict[str, list[dict[str, Any]]]:
    rows = gate.json("query", kind, "--select", field, "--claims", "--all")["rows"]
    return {row["subject_id"]: list((row.get("claims") or {}).get(field) or ()) for row in rows}


def test_39_audit_three_states(gate: Gate) -> None:
    _incident_ready(gate)
    _ack_all(gate)  # each step reads only what it posts
    subjects = gate.values["incident_subjects"]
    incident = gate.values["incident"]
    # The audits start from the services' lists, as each RQ3 gap names them (ops-wiki's
    # came with wiki-1's patch). The auditor starts storefront on its access log alone.
    asks = _audit_asks(gate)
    assert asks == {name: list(sources) for name, sources in SERVICE_LOGS.items()}, asks
    asks["storefront"] = ["storefront/nginx-access"]
    changes: list[dict[str, Any]] = []
    for service, listed in asks.items():
        label = f"audit-{service}"
        changes += [
            {"op": "create", "label": label, "subject_kind": "security.audit",
             "key": _key_of("security.audit", incident_ref=INCIDENT_NAME, service_ref=service)},
            {"op": "set", "subject": {"created": label}, "field": "security.audit.incident",
             "value": incident},
            {"op": "set", "subject": {"created": label}, "field": "security.audit.service",
             "value": subjects[f"svc-{service}"]}]
        changes += [{"op": "add", "subject": {"created": label},
                     "field": "security.audit.log_source", "value": source}
                    for source in listed]
    audits = _write_created(gate, AUDITOR, "audits", {
        "because": "The log sources that must be read in full over PHP2Shell's window, from "
                   "each service's log_source list.", "changes": changes}, LEAD)
    gate.values["audits"] = {s: audits[f"audit-{s}"] for s in asks}
    # The service lists php-fpm too: until the audit states it, storefront's RQ3 is unknown.
    _respond(gate)
    left_out = [g["payload"]["input"] for g in _respond_posts(gate, "gap")
                if g["payload"]["subject"] == "storefront"
                and g["payload"]["input"].get("state") == "security.audit.log_source"]
    assert [ask.get("sources") for ask in left_out] == [["storefront/php-fpm"]], left_out
    _ack_all(gate)
    _write_as(gate, AUDITOR, "audit-php-fpm", {
        "because": "storefront's log_source list names PHP-FPM's log, which records which "
                   "scripts ran.",
        "subject": gate.values["audits"]["storefront"],
        "changes": [{"op": "add", "field": "security.audit.log_source",
                     "value": "storefront/php-fpm"}]}, approver=LEAD)
    reads: dict[str, str] = {}
    for fixture, relative in (
            ("log-storefront-nginx.json", "logs/storefront-nginx.json"),
            ("log-storefront-php-fpm.json", "logs/storefront-php-fpm.json"),
            ("log-partner-portal-apache.json", "logs/partner-portal-apache.json"),
            ("log-ops-wiki-nginx-window.json", "logs/ops-wiki-nginx-window.json"),
            ("log-ops-wiki-nginx-retained.json", "logs/ops-wiki-nginx-retained.json")):
        capture, _, runs = _land(gate, "security.log-acquire", "log", fixture, relative, AUDITOR,
                                 (LOG_IMPORT,))
        reads[fixture] = capture
        proposal = _proposal(gate, runs[LOG_IMPORT])
        if fixture == "log-ops-wiki-nginx-window.json":
            assert proposal is None, gate.out("get", runs[LOG_IMPORT]["run"])[-1500:]
            continue
        assert proposal, gate.out("get", runs[LOG_IMPORT]["run"])[-1500:]
        _approve(gate, proposal, LEAD)
    posted = [json.dumps(gate.json("inbox", "get", i["item_id"])) for i in _inbox(
        gate, "--line", LOG_IMPORT, "--status", "unread")]
    assert any("read_incomplete" in body and "retention is 14 days" in body for body in posted)
    gate.values["reads"] = reads
    # G9: a result in the auditor's own words is refused.
    own = gate.cx("write", gate.payload("own-words-result", {
        "because": "I looked; nothing happened.", "subject": gate.values["audits"]["partner-portal"],
        "changes": [{"op": "set", "field": "security.audit.result", "value": "not_exploited"}]}),
        "--dry-run", who=AUDITOR, check=False)
    assert "evidence_required" in own.stdout + own.stderr, own.stdout[-1200:]
    note = "incidents/php2shell.md"
    for service, result, fixture, why in (
            ("storefront", "exploited", "log-storefront-nginx.json",
             "POST /index.php?-d allow_url_include=1 from 203.0.113.45 on 2026-10-03, then a "
             "new uploads/x5.php that PHP-FPM executed: a webshell."),
            ("partner-portal", "not_exploited", "log-partner-portal-apache.json",
             "The whole window, every record: no exploit pattern, no new .php file served."),
            ("ops-wiki", "not_exploited", "log-ops-wiki-nginx-retained.json",
             "What is retained (from 2026-10-04) shows nothing.")):
        _write_as(gate, AUDITOR, f"result-{service}", {
            "because": why, "subject": gate.values["audits"][service],
            "changes": [
                {"op": "set", "field": "security.audit.result", "value": result,
                 "evidence": {"kind": "capture", "capture": reads[fixture]}},
                {"op": "set", "field": "security.audit.window_end", "value": WINDOW_END}],
            "docs": [{"op": "append", "file": note,
                      "text": f"# Audit: {service}\n\n{result}: {why}\n"}]}, approver=LEAD)
    summary = _respond(gate)
    rq3 = _states(summary, "RQ3")
    assert rq3 == {"storefront": "found", "partner-portal": "none", "ops-wiki": "unknown"}, rq3
    (gap,) = [g["payload"] for g in _respond_posts(gate, "gap")
              if g["payload"]["subject"] == "ops-wiki"]
    assert (gap["input"]["source"], gap["input"]["from"], gap["input"]["to"]) == (
        "ops-wiki/nginx", WINDOW_START, "2026-10-04T00:00:00Z"), gap
    assert gap["pull"] == "security.log-acquire"
    assert [p["payload"]["service"] for p in _respond_posts(gate, "exploited")] == ["storefront"]
    record("39", "the RQ3 gaps named each service's log sources and the audits started from "
           "them; storefront's, stated without php-fpm, stayed unknown naming it until the "
           "auditor added it; four complete reads recorded, ops-wiki's "
           "window read posted read_incomplete (14-day retention); an own-words result refused "
           "evidence_required; results citing the decisive reads with Audit sections: RQ3 "
           "storefront found, partner-portal none, ops-wiki unknown with ops-wiki/nginx "
           f"{WINDOW_START} to 2026-10-04 named as the uncovered interval")


def test_40_contended_audit(gate: Gate) -> None:
    _incident_ready(gate)
    _ack_all(gate)  # each step reads only what it posts
    audit = gate.values["audits"]["partner-portal"]
    _write_as(gate, OPS, "contend", {
        "because": "The portal's apache log rotates mid-day; I am not sure every record was "
                   "searched.", "subject": audit,
        "changes": [{"op": "set", "field": "security.audit.result", "value": "inconclusive",
                     "contend": True, "evidence": {
                         "kind": "capture",
                         "capture": gate.values["reads"]["log-partner-portal-apache.json"]}}]},
               approver=LEAD)
    rows = [r for r in gate.rows("security.audit_status", incident=INCIDENT_NAME)
            if r["subject_id"] and _field(r, "service_ref") == "partner-portal"]
    assert rows and "contested" in json.dumps(rows), rows
    assert "claim_conflicted" in {row["reason"] for row in gate.json("next")["items"]}
    summary = _respond(gate)
    assert _states(summary, "RQ3")["partner-portal"] == "unknown", summary["answers"]
    # Step 39's run before the results already posted this rotate (audit unknown, patch
    # verified) and its item was acknowledged there: the same payload is a re-sighting.
    rotate = {p["payload"]["credential"] for status in ("unread", "acknowledged")
              for p in _respond_posts(gate, "rotate", status=status)}
    assert "postgres/partners-db/portal" in rotate, rotate
    wrong = [c["claim"] for c in _claim_ids_of(gate, "security.audit", "result")[
        audit.rsplit("/", 1)[-1]] if c["value"] == "inconclusive"]
    assert len(wrong) == 1, wrong
    _write_as(gate, OPS, "retire-contender", {
        "because": "The apache read was complete: the rotation finished before the window.",
        "changes": [{"op": "retire", "target": wrong[0], "reason": "was-wrong"}]},
              approver=LEAD)
    summary = _respond(gate)
    assert _states(summary, "RQ3")["partner-portal"] == "none"
    assert _states(summary, "RQ4")["postgres/partners-db/portal"] == "none"
    record("40", "a second reading (inconclusive, contend) made partner-portal's result a "
           "conflict (next: claim_conflicted): RQ3 unknown, RQ4 posted a rotation of "
           "postgres/partners-db/portal; retired was-wrong, RQ3 none and RQ4 none again")


def _credential(short: str) -> str:
    return f"{CREDENTIALS[short][0]}/{CREDENTIALS[short][1]}"


def _key_ids(gate: Gate) -> dict[str, Any]:
    return {f"{_field(r, 'issuer')}/{_field(r, 'name')}": _field(r, "key_id")
            for r in gate.rows("security.rotation_work")}


def test_41_rotate(gate: Gate) -> None:
    _incident_ready(gate)
    _ack_all(gate)  # each step reads only what it posts
    # What each credential's current key is, read by the scanner before anyone rotates.
    for short in CREDENTIALS:
        _, _, runs = _land(gate, "security.credential-acquire", "credential",
                           f"cred-{short}-initial.json", f"credentials/{short}-initial.json",
                           SCANNER, (CREDENTIAL_IMPORT,))
        _approve(gate, _proposal(gate, runs[CREDENTIAL_IMPORT]), LEAD)  # type: ignore[arg-type]
    keys = _key_ids(gate)
    assert keys[_credential("aws")] == "AKIAQ3EXAMPLEOLDKEY1", keys
    summary = _respond(gate)
    rotate = {p["payload"]["credential"]: p["payload"] for p in _respond_posts(gate, "rotate")}
    assert sorted(rotate) == sorted(_credential(s) for s in ("aws", "stripe", "github")), rotate
    assert rotate[_credential("github")]["services"] == {
        "ops-wiki": {"audit": "unknown", "patch": "verified"}}, rotate
    # The responder raises the rotations (revokes_key = the held key id); the lead approves.
    rotations = {}
    services = {"aws": "storefront", "stripe": "storefront", "github": "ops-wiki"}
    for short, service in services.items():
        credential = gate.values["incident_subjects"][f"cred-{short}"]
        created = _write_created(gate, RESPONDER, f"rotation-{short}", {
            "because": f"{service}'s audit is {rotate[_credential(short)]['services'][service]['audit']}"
                       ": rotate what it could read.",
            "changes": [
                {"op": "create", "label": "rotation", "subject_kind": "security.remediation"},
                {"op": "set", "subject": {"created": "rotation"},
                 "field": "security.work.credential", "value": credential},
                {"op": "set", "subject": {"created": "rotation"}, "field": "security.work.audit",
                 "value": gate.values["audits"][service]},
                {"op": "set", "subject": {"created": "rotation"},
                 "field": "security.remediation.revokes_key", "value": keys[_credential(short)]},
                {"op": "set", "subject": {"created": "rotation"},
                 "field": "security.remediation.due_at", "value": "2026-12-01T00:00:00Z"}]},
                                 LEAD)
        rotations[short] = created["rotation"]
        _progress(gate, rotations[short], "completed")
    # G10: ops records the issuers' receipts: new key ids, never a verification.
    for short in services:
        _, _, runs = _land(gate, "security.credential-acquire", "credential",
                           f"cred-{short}-receipt.json", f"credentials/{short}-receipt.json",
                           OPS, (CREDENTIAL_IMPORT,))
        proposal = _proposal(gate, runs[CREDENTIAL_IMPORT])
        assert proposal and "security.work.verification" not in gate.out(
            "proposal", "review", proposal)
        _approve(gate, proposal, LEAD)
    # Claimed, no separate state read: unknown, a gap naming the credential pull.
    _respond(gate)
    (claimed,) = [g for g in _respond_posts(gate, "gap")
                  if g["payload"]["subject"] == _credential("github")]
    assert claimed["payload"]["pull"] == "security.credential-acquire", claimed
    _ack_all(gate)
    # G11: a body with a secret is refused whole and echoes nothing.
    _, _, runs = _land(gate, "security.credential-acquire", "credential", "cred-aws-leaky.json",
                       "credentials/aws-leaky.json", OPS, (CREDENTIAL_IMPORT,))
    assert _proposal(gate, runs[CREDENTIAL_IMPORT]) is None
    bodies = [json.dumps(gate.json("inbox", "get", i["item_id"])) for i in _inbox(
        gate, "--line", CREDENTIAL_IMPORT, "--status", "unread")]
    assert any("secret_shape" in b for b in bodies) and not any(
        "wJalrXUtnFEMI" in b for b in bodies), bodies
    # The contracts a secret may slip into authorize erasure (`cruxible capture erase`).
    for contract in ("security.credential-state-v1", "security.log-read-v1",
                     "security.runtime-inventory-v1"):
        policy = gate.proof(f"CaptureContract:{contract}")["envelope"]["retention_erasure_policy"]
        assert policy["erasure"] == "authorized_by_rule" and policy["erasure_rule_digest"], policy
    # G12: 30 s after that landing the respond Line re-asks on its own (window_close): the
    # acknowledged gap is sighted again and counts the recurrence, keeping its decision.
    def resighted() -> bool:
        envelope = _find(gate.json("inbox", "get", claimed["item_id"]), "recurred_since_disposition")
        return isinstance(envelope, int) and envelope >= 1

    gate.wait(resighted, 240, "the window-close run did not re-sight the rotation gap")
    again = gate.json("inbox", "get", claimed["item_id"])
    assert _find(again, "status") == "acknowledged", again
    latest = _find(again, "recent_sightings")[0]["run_id"]  # it recurred after the ack
    assert "window_close" in json.dumps(gate.proof(f"ProcedureRun:{latest}")), latest
    # The state reads, acquired by the scanner (not the rotator): verified, or failed.
    state_runs = {}
    for short, fixture in (("stripe", "cred-stripe-state.json"),
                           ("github", "cred-github-state.json"),
                           ("aws", "cred-aws-state-still-active.json")):
        _, state_runs[short], runs = _land(gate, "security.credential-acquire", "credential",
                                           fixture, f"credentials/{short}-state.json", SCANNER,
                                           (CREDENTIAL_IMPORT,))
        _approve(gate, _proposal(gate, runs[CREDENTIAL_IMPORT]), LEAD)  # type: ignore[arg-type]
    verification = {_credential(s): _field(r, "verification") for s in services
                    for r in gate.rows("security.rotation_work")
                    if _field(r, "rotation") == rotations[s].rsplit("/", 1)[-1]}
    assert verification == {_credential("stripe"): "verified", _credential("github"): "verified",
                            _credential("aws"): "failed"}, verification
    summary = _respond(gate)
    assert [p["payload"]["credential"] for p in _respond_posts(gate, "rotation_disputed")] == [
        _credential("aws")]
    _, state_runs["aws"], runs = _land(gate, "security.credential-acquire", "credential",
                                       "cred-aws-state.json", "credentials/aws-state.json",
                                       SCANNER, (CREDENTIAL_IMPORT,))
    _approve(gate, _proposal(gate, runs[CREDENTIAL_IMPORT]), LEAD)  # type: ignore[arg-type]
    summary = _respond(gate)
    rq4 = _states(summary, "RQ4")
    assert all(rq4[_credential(s)] == "none" for s in CREDENTIALS), rq4
    actor = gate.card(state_runs["aws"]).get("actor")
    assert actor and SCANNER in json.dumps(actor) and OPS not in json.dumps(actor), actor
    record("41", "initial state reads stated each current key; respond posted rotate x3 with "
           "each service's audit and patch state; three rotations raised (revokes_key the held "
           "id) and claimed; receipts proposed new key ids, never a verification; 30 s after a "
           "landing the window-close run re-sighted the unverified rotation's acknowledged gap "
           "(recurred_since_disposition counted, decision kept); a "
           "body with secret_access_key refused (secret_shape, nothing echoed; the three incident "
           "contracts authorize erasure); the scanner's "
           "state reads verified two and failed AWS (old key still active: rotation_disputed) "
           f"until the next read verified it; RQ4 none x4; the state read's actor is {actor}")


def test_42_close(gate: Gate) -> None:
    _incident_ready(gate)
    summary = _respond(gate)
    assert summary["ready_to_close"] == 1, summary["answers"]
    readies = [p["payload"] for p in (*_respond_posts(gate, "ready_to_close"),
                                      *_respond_posts(gate, "ready_to_close",
                                                      status="acknowledged"))]
    residue = [{"service": "ops-wiki", "audit": "unknown"}]
    ready = next((p for p in readies if p["residue"] == residue), None)
    assert ready is not None, readies
    assert ready["exploited"] == ["storefront"], ready
    _write_as(gate, LEAD, "close", {
        "because": "Every exposure patched and verified by a scan, every warranted key rotated "
                   "and verified by a state read; ops-wiki's audit stays unknown (14-day "
                   "retention) and its deploy key is rotated.",
        "subject": gate.values["incident"],
        "changes": [{"op": "set", "field": "security.incident.status", "value": "closed"}],
        "docs": [{"op": "append", "file": "incidents/php2shell.md", "text": (
            "# Closure\n\nClosed on the respond Line's ready_to_close. Residue: ops-wiki's "
            "audit is unknown (logs before 2026-10-03 are gone); github/acme-ops/wiki-deploy "
            "was rotated anyway.\n")}]}, approver=RESPONDER)
    _ack_all(gate)
    closed = _respond(gate)
    assert closed.get("status", "closed") == "closed" and not closed.get("posted"), closed
    assert not _respond_posts(gate)  # a closed incident posts nothing
    # The status page: one projection block the status query renders.
    page = gate.ws / "incidents" / "php2shell-status.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(KIT / "examples" / "incident-status.md", page)
    gate.out("files", "add", "php2shell-status", "incidents/php2shell-status.md")
    params = json.dumps({"incident": INCIDENT_NAME}, sort_keys=True, separators=(",", ":"))
    gate.out("block", "repin", "php2shell-status", "status", "--query",
             "QueryDefinition:security.incident_status", "--params", params, "--render")
    text = page.read_text()
    assert "| subject |" in text and HOSTS["storefront-b"] in text and "verified" in text, text
    _ack_all(gate)
    rows = [row for row in gate.json("next")["items"]
            if RESPOND in json.dumps(row) or INCIDENT_NAME.lower() in json.dumps(row).lower()]
    assert not rows, rows
    record("42", "respond posted ready_to_close (residue: ops-wiki's audit unknown; exploited: "
           "storefront); the lead closed the incident with a Closure section, the responder "
           "approved; a closed incident posts nothing; the status page block rendered the "
           "incident's patches, audits and rotations; next shows nothing for the incident")
