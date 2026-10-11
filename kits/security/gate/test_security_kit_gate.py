"""The security kit v1 release gate, end to end, offline from every security source.

    CRUXIBLE_BIN=/path/to/cruxible python -m pytest kits/security/gate -q

One fresh Cruxible daemon on a scratch state root and HOME, one throwaway HTTPS OCI
registry on 127.0.0.1, the kit installed from that registry, and every step of the
release gate asserted on what the CLI shows. The KEV catalog, CVE record, OSV
answers and EPSS file come from ``fixture-sources`` (``security-gate-sources``:
cruxible-provider-web's own ``WebFetch`` and the kit's own OSV and EPSS adapters,
serving vendored responses), bound to the kit's Blueprint slots; nothing contacts
cisa.gov, cveawg.mitre.org, api.osv.dev or the EPSS site. Provider installs still
resolve ``cruxible-provider-web`` 0.2.1 and Python dependencies from PyPI.

Needs ``cruxible`` (the daemon and CLI under test; ``CRUXIBLE_BIN``, else the
one beside this interpreter, else ``PATH``), this interpreter with
``cruxible_client``, ``git`` and ``openssl``. Tests run in file order and share
one gate; a scratch root is kept for inspection when ``SECURITY_KIT_GATE_ROOT``
names it. ``SECURITY_KIT_GATE_CADENCE`` (seconds, default 30) sets the gate
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
import unicodedata
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
RELEASE_1_1 = KIT / "source" / "variants" / "1.1.0"
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
    "18": "upgrade to 1.1.0 keeping a local edit; re-add; downgrade blocked",
    "19": "exit: next empty, run history",
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

    def cx(self, *args: str, check: bool = True,
           timeout: float = 900) -> subprocess.CompletedProcess[str]:
        started = time.monotonic()
        result = subprocess.run(
            [self.bin, *args], env=self.env, cwd=self.ws, capture_output=True, text=True,
            timeout=timeout,
        )
        took = time.monotonic() - started
        self.log.write(f"$ cruxible {' '.join(args)}  [{took:.1f}s]\n"
                       f"{result.stdout}{result.stderr}(exit {result.returncode})\n")
        self.log.flush()
        if check and result.returncode != 0:
            raise AssertionError(f"cruxible {' '.join(args)} exited {result.returncode}: "
                                 f"{result.stdout[-1500:]}{result.stderr[-1500:]}")
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

    def rows(self, name: str, **params: str) -> list[dict[str, Any]]:
        args = ["query", "--name", name, "--limit", "500"]
        for key, value in params.items():
            args += ["--param", f"{key}={value}"]
        rows: list[dict[str, Any]] = []
        cursor: list[str] = []
        while True:  # pages hold at most 500 rows
            page = self.json(*args, *cursor)
            rows += page["rows"]
            if not page.get("next_cursor"):
                return rows
            cursor = ["--cursor", page["next_cursor"]]

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
        assert '"failure_code": null' in self.out("proposal", "activate", proposal)

    def run_line(self, line: str) -> tuple[str, str]:
        out = self.out("line", "run", line)
        found = re.search(r"(RUN-[0-9a-f]+)", out)
        assert found, out
        return found.group(1), out

    def capture_digest(self, contract: str) -> str:
        return str(self.proof(f"CaptureContract:{contract}")["artifact_digest"])


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


def _render(*parts: str) -> str:
    """The id core renders from a canonical key (cli-reference "Subject kinds and creation").

    A JSON change set names a Subject it creates in the same set by that id.
    """

    rendered = []
    for part in parts:
        text = re.sub(r"[^a-z0-9.]+", "-", unicodedata.normalize("NFKC", part).lower()).strip("-")
        rendered.append(text)
    joined = "--".join(rendered)
    return joined if joined[:1].isalpha() else "x" + joined


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


KIT_COUNTS = {"Blueprint": 4, "CaptureContract": 7, "ClaimType": 47, "Procedure": 7,
              "ProviderInterface": 9, "QueryDefinition": 19, "SourceAcquisitionPolicy": 1,
              "SubjectKind": 11}


def test_02_kit_add(gate: Gate) -> None:
    preview = gate.json("kit", "add", f"{gate.registry}:1.0.0", "--dry-run")
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
    committed = gate.json("kit", "add", f"{gate.registry}:1.0.0", "--commit",
                          "--at", preview["coordinate"]["git_oid"])
    assert committed["status"] == "accepted", committed
    status = gate.out("kit", "status")
    assert "security 1.0.0" in status and "up to date" in status, status
    (kit,) = gate.json("kit", "status")["kits"]
    delivery = {p["package"]: (p["delivery"], p["state"]) for p in kit["providers"]}
    assert delivery == {"cruxible-provider-web": ("index", "installed"),
                        "security-analysis-provider": ("bundled", "installed"),
                        "security-sources-provider": ("bundled", "installed")}, delivery
    kinds = gate.out("get", "SubjectKind:security.assessment")
    assert "security.assessment.release_id" in kinds and "unique" in kinds, kinds
    record("02", f"preview {counts}; accepted; status 1.0.0 up to date; providers {delivery}")


def test_03_fixture_sources(gate: Gate) -> None:
    wheel = next((FIXTURE / "dist").glob("security_gate_sources-*.whl"))
    out = gate.out("provider", "install", str(wheel), "--lock", str(FIXTURE / "uv.lock"))
    assert "security-gate-sources: ready" in out, out
    found = {}
    for interface, kit_provider in (("web.fetch", "cruxible-provider-web"),
                                    ("security.osv-query", "security-sources-provider"),
                                    ("security.epss-daily", "security-sources-provider")):
        providers = {p["provider"] for p in gate.card(f"ProviderInterface:{interface}")["providers"]}
        assert providers == {kit_provider, "security-gate-sources"}, (interface, providers)
        found[interface] = sorted(providers)
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
    released = {a["path"]: a["artifact_digest"] for a in json.loads(
        (RELEASE_1_0 / "cruxible-kit.json").read_text())["artifacts"]}
    gate.values["kev_acquire_blueprint"] = released["blueprints/security.kev-acquire.json"]
    assert gate.values["kev_acquire_blueprint"] in origin
    record("04", f"unbound refused; mismatch refused; runnable {runnable}; Blueprint origin "
           "recorded")


def test_05_automation(gate: Gate) -> None:
    digests = {name: gate.capture_digest(name) for name in recipe.LANDING_CONTRACTS}
    gate.submit("automation", recipe.automation(digests))
    line = gate.card("Line:security.kev-triage")
    assert line["triggers_inactive"] == "not enabled", line["triggers_inactive"]
    rows = gate.json("query", "Trigger", "--where", "target=Line:security.kev-triage")["rows"]
    assert [r["name"] for r in rows] == ["security.kev-landed"], rows
    for name in recipe.LINES:
        if name != "security.kev-daily":  # the cadence step enables it
            assert "enabled" in gate.out("line", "enable", name), name
    record("05", f"{len(recipe.LINES)} Lines, Triggers and {len(recipe.MANDATES)} propose "
           "mandates in one change set; triage Triggers inactive until enabled; 7 Lines enabled")


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


def _inventory() -> dict[str, Any]:
    members: list[dict[str, Any]] = [recipe.subject(kind, key, f"Inventory: {key}.")
                                     for kind, key in INVENTORY]

    def rel(subject: str, predicate: str, target: str) -> dict[str, Any]:
        return {"kind": "claim", "subject": subject, "predicate": predicate,
                "object": {"kind": "subject", "subject": target}, "role": "normative",
                "rationale": f"Inventory: {subject} {predicate.rsplit('.', 1)[-1]} {target}.",
                "source": {"kind": "self_source", "body": f"{subject} -> {target}\n"}}

    def lit(subject: str, predicate: str, value: Any) -> dict[str, Any]:
        return {"kind": "claim", "subject": subject, "predicate": predicate,
                "object": {"kind": "literal", "value": value}, "role": "normative",
                "rationale": f"Inventory: {subject} {predicate.rsplit('.', 1)[-1]}.",
                "source": {"kind": "self_source", "body": f"{subject}: {value}\n"}}

    asset = "security.asset/web-1.example.com"
    members += [
        lit("security.service/storefront", "security.service.criticality", "critical"),
        rel("security.service/storefront", "security.service.owned_by", "security.team/platform"),
        lit(asset, "security.asset.internet_exposed", True),
        lit(asset, "security.asset.environment", "production"),
        rel(asset, "security.asset.serves", "security.service/storefront"),
        rel("security.product/apache-log4j2", "security.product.supplied_by",
            "security.supplier/apache-software-foundation"),
        rel("security.product/zammad", "security.product.supplied_by",
            "security.supplier/zammad-gmbh"),
        rel("security.release/zammad--6.0.0", "security.release.product",
            "security.product/zammad"),
        # A second value of a many-valued slot in the same change set needs an explicit
        # disposition of the first (by a Claim ID the set mints): the gate adds the other
        # installs with `cruxible add` after the set lands.
        rel(asset, "security.asset.installs", "security.release/apache-log4j2--2.14.1"),
    ]
    for release in LOG4J_RELEASES:
        product = "apache-log4j" if release.startswith("apache-log4j--") else "apache-log4j2"
        members.append(rel(f"security.release/{release}", "security.release.product",
                           f"security.product/{product}"))
    return {"kind": "change_set", "rationale": "The gate's inventory.", "members": members}


def test_07_inventory_and_watches(gate: Gate) -> None:
    gate.submit("inventory", _inventory())
    for release in ("zammad--6.0.0", "gate-app--1.0.0"):
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
                    "--and-activate", check=False)
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
    assert assessment == _render(app, LOG4SHELL), assessment
    statuses = gate.claims("security.assessment", "security.assessment.status")
    evidence = gate.out("get", statuses[assessment][1], "--detail", "evidence")
    assert "CaptureContract:security.osv-query-v1" in evidence, evidence
    rerun, rerun_out = gate.run_line("security.osv-applicability")
    assert ": halted" in rerun_out or "no_change" in rerun_out, rerun_out
    affected = sum(1 for (r, _), (s, _) in held.items() if r == app and s == "affected")
    record("08", f"OSV proposal accepted: {affected} affected for {app} (CVEs watched by key), "
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


def test_09_analyst_judgment(gate: Gate) -> None:
    app = "gate-app--1.0.0"
    assessment = gate.values["assessment_ids"][(app, JUDGED)]
    assert _assessments(gate)[(app, JUDGED)] == ("affected", None)
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
            {"op": "set", "field": "judgment",
             "value": "gate-app compiles only its packaged templates; the filename and "
                      "content an attacker needs are never theirs (analysis note)."},
        ]}))
    assert _assessments(gate)[(app, JUDGED)] == (
        "not_affected", "vulnerable_code_not_in_execute_path")
    # A judgment is visibly a judgment: its role, its reasoning, its evidence.
    rows = gate.json("query", "security.assessment", "--where", f"cve_id={JUDGED}",
                     "--select", "status,justification,judgment", "--claims")["rows"]
    cells = rows[0]["claims"]
    assert cells["status"][0]["role"] == "normative", cells
    assert cells["justification"][0]["role"] == "normative", cells
    assert cells["judgment"][0]["value"].startswith("gate-app compiles"), cells
    index = [r for r in gate.rows("security.assessment_index") if r["subject_id"] == assessment]
    assert _field(index[0], "judgment"), index
    evidence = gate.out("get", cells["status"][0]["claim"], "--detail", "evidence")
    assert "security.workspace-evidence-v1" in evidence, evidence
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
           "wrote normative not_affected + vulnerable_code_not_in_execute_path + judgment; "
           "query --claims shows role normative, assessment_index shows the judgment; an "
           "own-words observation is uncovered (no admitted evidence); OSV re-run halted "
           "no_change, the judgment stands; no longer watched")


def _bet(gate: Gate, release: str, expected: str) -> str:
    # A claim member names the Subject a sibling member creates by the id core renders.
    assessment = f"security.assessment/{_render(release, LOG4SHELL)}"
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
    claim = gate.claims("security.assessment", "security.assessment.expected_status")[
        _render(release, LOG4SHELL)][1]
    name = f"security.applicability-{release}"
    start = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    path = gate.payload(name, {"contract": {
        "identity": {"kind": "ResolutionContract", "name": name},
        "hypothesis": claim,
        "observation": {"subject": {"tag": "playbill-semantic-address-v1",
                                    "artifact_path": f"subjects/{assessment}.json",
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
    right = statuses[_render("apache-log4j2--2.17.1", LOG4SHELL)][1]
    wrong = statuses[_render("apache-log4j2--2.12.2", LOG4SHELL)][1]
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
           "Claims (settle capped by line_max_authority); attention posted 1 inbox item "
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
        assert any(e.get("stop_reason") == "line_changed" for e in line["enablements"])
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
    record("17", "Procedure digests unchanged; authority settle; enablements stopped "
           f"line_changed; {SETTLES} KEV fields and EPSS scores settled under the mandates "
           "(condition: a keyed vulnerability; triage only changes watched ones)")


def test_18_upgrade(gate: Gate) -> None:
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
    record("18", "upgrade preview: Blueprint replace, kev_cwes add, kev_exposure overwrites your "
           "edit; --keep committed; status 1.1.0 kept; re-add unchanged; 1.0.0 would_block "
           "(downgrade); Procedure keeps Blueprint@1.0.0")


def test_19_exit(gate: Gate) -> None:
    for item in _inbox(gate, "--status", "unread"):
        gate.out("inbox", "ack", item["item_id"])
    gate.wait(lambda: "No repair work" in gate.next_text(), 120, "next not empty")
    kinds = set()
    for line in recipe.LINES:
        for run in gate.runs(line):
            proof = json.dumps(gate.proof(f"ProcedureRun:{run['run']}"))
            kinds |= {k for k in ("cadence", "capture_landing") if f'"{k}"' in proof}
            if '"enablement"' not in json.dumps(gate.card(run["run"]).get("triggered_by")):
                kinds.add("manual")
    assert {"manual", "cadence", "capture_landing"} <= kinds, kinds
    record("19", f"next empty; run history {sorted(kinds)} plus dispatched backfill")
