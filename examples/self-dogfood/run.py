"""Self-dogfood: the security kit's full loop, live, over Cruxible's own dependency tree.

    python run.py SCRATCH_DIR SBOM_DIR [--kit KIT_DIR] [--scale-batches N] [--scale-size M]

Run with the interpreter of the cruxible build under test (its ``cruxible``
beside it, or ``CRUXIBLE_BIN``). ``SCRATCH_DIR`` gets a fresh HOME, state root
and workspace; ``SBOM_DIR`` holds the CycloneDX SBOMs ``sbom_from_uv_lock.py``
wrote (one per product release). The loop, every step timed:

1. ``init``; ``kit add`` the kit directory; bind Procedure slots by fit on the
   real providers (``cruxible-provider-web``, ``security-sources-provider``);
   the kit's example automation change set; enable every Line.
2. SBOM import: ``procedure run security.sbom-acquire`` per SBOM; each landing
   runs ``security.sbom-import``; accept each proposal.
3. OSV applicability (live api.osv.dev): ``line run``; accept the proposal.
4. KEV (live cisa.gov): ``line run security.kev-daily``; triage proposes,
   attention posts; accept the triage proposal.
5. EPSS (live epss.empiricalsecurity.com): ``line run security.epss-daily``;
   accept the triage proposal.
6. ``security.urgent_exposures``.
7. Scale: graduate KEV triage to settle, then N batches: watch M KEV-listed
   CVEs, ``line run security.kev-daily``, time the settle of their ~4M Claims.

Writes ``SCRATCH_DIR/report.json`` (timings, findings, the urgent rows) and
prints a summary. Network: cisa.gov, api.osv.dev, epss.empiricalsecurity.com
(and PyPI for provider installs). Stops and reaps its daemon.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1] / "kits" / "security"
sys.path.insert(0, str(KIT / "gate"))
import recipe  # noqa: E402


class Session:
    def __init__(self, scratch: Path) -> None:
        if scratch.exists():
            shutil.rmtree(scratch)
        self.scratch = scratch
        self.home, self.state, self.ws = (scratch / n for n in ("home", "state", "ws"))
        for path in (self.home, self.state, self.ws, scratch / "payloads"):
            path.mkdir(parents=True)
        self.run_dir = Path(tempfile.mkdtemp(prefix="kd-", dir="/tmp"))
        self.run_dir.chmod(0o700)
        self.bin = os.environ.get("CRUXIBLE_BIN") or str(Path(sys.executable).with_name("cruxible"))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CRUXIBLE_")}
        self.env.update(
            HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_CACHE_HOME=str(self.home / ".cache"), CRUXIBLE_STATE_ROOT=str(self.state),
            CRUXIBLE_SERVER_SOCKET=str(self.run_dir / "d.sock"),
            CRUXIBLE_ARTIFACT_CACHE=str(self.home / ".cache" / "cruxible-artifacts"),
            GIT_AUTHOR_NAME="dogfood", GIT_AUTHOR_EMAIL="dogfood@example.invalid",
            GIT_COMMITTER_NAME="dogfood", GIT_COMMITTER_EMAIL="dogfood@example.invalid",
            CRUXIBLE_CLIENT_TIMEOUT_S="1200",
        )
        self.log = (scratch / "commands.log").open("a")
        self.timings: dict[str, float] = {}
        self.daemon: subprocess.Popen[bytes] | None = None

    def cx(self, *args: str, check: bool = True) -> str:
        started = time.monotonic()
        result = subprocess.run([self.bin, *args], env=self.env, cwd=self.ws,
                                capture_output=True, text=True)
        self.log.write(f"$ cruxible {' '.join(args)}  [{time.monotonic() - started:.1f}s]\n"
                       f"{result.stdout}{result.stderr}(exit {result.returncode})\n")
        self.log.flush()
        if check and result.returncode != 0:
            raise SystemExit(f"cruxible {' '.join(args)}: {result.stdout[-2000:]}"
                             f"{result.stderr[-2000:]}")
        return result.stdout

    def json(self, *args: str) -> Any:
        return json.loads(self.cx(*args, "--json"))

    def submit(self, name: str, payload: object) -> None:
        path = self.scratch / "payloads" / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1))
        out = json.loads(self.cx("authoring", "submit", str(path)))
        assert out["outcome"]["status"] == "landed", json.dumps(out)[-1500:]

    def timed(self, label: str, action: Any) -> Any:
        started = time.monotonic()
        value = action()
        self.timings[label] = round(time.monotonic() - started, 2)
        print(f"[{self.timings[label]:7.1f}s] {label}", flush=True)
        return value

    def start(self) -> None:
        subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=self.ws, env=self.env,
                       check=True)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"], cwd=self.ws,
                       env=self.env, check=True)
        self.daemon = subprocess.Popen(
            [self.bin, "server", "start", "--socket", self.env["CRUXIBLE_SERVER_SOCKET"],
             "--state-root", str(self.state)], env=self.env, cwd=self.scratch,
            stdout=(self.scratch / "daemon.log").open("ab"), stderr=subprocess.STDOUT)
        for _ in range(120):
            if subprocess.run([self.bin, "server", "status"], env=self.env,
                              capture_output=True).returncode == 0:
                return
            time.sleep(1)
        raise SystemExit("daemon did not answer")

    def stop(self) -> None:
        subprocess.run([self.bin, "server", "stop"], env=self.env, capture_output=True)
        if self.daemon is not None:
            try:
                self.daemon.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.daemon.terminate()
                self.daemon.wait(timeout=30)
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def settings(self) -> None:
        (settings,) = (self.home / ".config" / "cruxible" / "keys").glob("*/*/cruxible.env")
        for line in settings.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                self.env[key.strip().removeprefix("export ").strip()] = value.strip().strip("'\"")

    def runs(self, line: str) -> list[dict[str, Any]]:
        return list(self.json("get", f"Line:{line}")["card"].get("recent_runs") or [])

    def wait_run(self, line: str, before: set[str], timeout: float = 900) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            fresh = [r for r in self.runs(line) if r["run"] not in before
                     and r["status"] != "running"]
            if fresh:
                return fresh[0]
            time.sleep(1)
        raise SystemExit(f"no run on {line}")

    def egress(self, run: str) -> dict[str, Any]:
        (terminal,) = self.json("get", run)["card"]["terminal_egress"]
        return dict(terminal)

    def accept(self, run: dict[str, Any]) -> int:
        """Activate a run's proposal; the number of paths it changed (0 when none)."""

        if run["status"] != "succeeded":
            return 0
        egress = self.egress(run["run"])
        if egress.get("proposal_id") and egress.get("settle_outcome") != "settled":
            self.cx("proposal", "activate", egress["proposal_id"])
        return len(egress.get("target_paths") or ())

    def rows(self, name: str) -> list[dict[str, Any]]:
        return list(self.json("query", "--name", name, "--all")["rows"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scratch", type=Path)
    parser.add_argument("sboms", type=Path)
    parser.add_argument("--kit", type=Path, default=KIT)
    parser.add_argument("--scale-batches", type=int, default=5)
    parser.add_argument("--scale-size", type=int, default=100)
    parser.add_argument("--cve", default="CVE-2024-34064",
                        help="one CVE record to fetch live (default: a Jinja2 CVE)")
    args = parser.parse_args()
    s = Session(args.scratch.resolve())
    report: dict[str, Any] = {"timings": s.timings}
    s.start()
    try:
        s.cx("init", "--principal-id", "dogfood")
        s.settings()
        preview = s.timed("kit add preview", lambda: s.json("kit", "add", str(args.kit),
                                                            "--dry-run"))
        s.timed("kit add commit (installs 3 providers)", lambda: s.json(
            "kit", "add", str(args.kit), "--commit", "--at", preview["coordinate"]["git_oid"]))
        s.timed("automation change set", lambda: s.submit("automation",
                                                         recipe.automation()))
        s.timed("enable Lines", lambda: [s.cx("line", "enable", n) for n in recipe.LINES])

        # 2. SBOM import.
        (s.ws / "sboms").mkdir()
        sboms = sorted(args.sboms.glob("*.cdx.json"))
        components = 0
        for sbom in sboms:
            shutil.copyfile(sbom, s.ws / "sboms" / sbom.name)

        def import_all() -> None:
            nonlocal components
            for sbom in sboms:
                before = {r["run"] for r in s.runs("security.sbom-import")}
                path = s.scratch / "payloads" / f"sbom-{sbom.name}.json"
                path.write_text(json.dumps({"relative_path": f"sboms/{sbom.name}"}))
                s.cx("procedure", "run", "security.sbom-acquire", str(path))
                run = s.wait_run("security.sbom-import", before)
                components += s.accept(run)

        s.timed(f"SBOM import ({len(sboms)} SBOMs: acquire, import, accept)", import_all)
        releases = s.rows("security.release_inventory")
        report["releases"] = sorted(
            f"{r.get('product_name')} {r.get('version')} ({len(r.get('components') or [])} "
            "components)" for r in releases)

        # 3. OSV applicability.
        def osv() -> dict[str, Any]:
            run = s.cx("line", "run", "security.osv-applicability", "--json")
            result = json.loads(run)
            run_id = result.get("run_id") or re.search(r"RUN-[0-9a-f]+", run).group(0)
            card = s.json("get", run_id)["card"]
            changed = 0
            if card["status"] == "succeeded":
                changed = s.accept({"run": run_id, "status": "succeeded"})
            return {"run": run_id, "status": card["status"], "paths": changed,
                    "summary": result.get("result")}

        report["osv"] = s.timed("OSV applicability (live): run + accept", osv)

        # 4. KEV.
        def kev() -> dict[str, Any]:
            before_t = {r["run"] for r in s.runs("security.kev-triage")}
            before_a = {r["run"] for r in s.runs("security.kev-attention")}
            s.cx("line", "run", "security.kev-daily")
            triage = s.wait_run("security.kev-triage", before_t)
            attention = s.wait_run("security.kev-attention", before_a)
            paths = s.accept(triage)
            return {"triage": triage["status"], "paths": paths,
                    "attention": attention["status"]}

        report["kev"] = s.timed("KEV (live): acquire, triage, attention, accept", kev)
        inbox = s.json("inbox", "list")["entries"]
        report["inbox"] = [e["payload_preview"]["preview"][:300] for e in inbox]

        # 5. EPSS.
        def epss() -> dict[str, Any]:
            before = {r["run"] for r in s.runs("security.epss-triage")}
            s.cx("line", "run", "security.epss-daily")
            triage = s.wait_run("security.epss-triage", before)
            return {"triage": triage["status"], "paths": s.accept(triage)}

        report["epss"] = s.timed("EPSS (live): acquire, triage, accept", epss)

        # One CVE record (live cveawg.mitre.org): its landing runs cve-applicability.
        def cve_record() -> dict[str, Any]:
            before = {r["run"] for r in s.runs("security.cve-applicability")}
            path = s.scratch / "payloads" / "cve.json"
            path.write_text(json.dumps({"url": f"https://cveawg.mitre.org/api/cve/{args.cve}", "logical_source": "cve.record", "max_bytes": 1048576}))
            s.cx("procedure", "run", "security.fetch", str(path))
            run = s.wait_run("security.cve-applicability", before)
            return {"cve": args.cve, "status": run["status"], "paths": s.accept(run)}

        report["cve_record"] = s.timed(f"CVE record {args.cve} (live): acquire, applicability",
                                       cve_record)
        # Day two: every CVE found yesterday is watched now; OSV answers every pair again.
        report["osv_day2"] = s.timed("OSV applicability day 2 (found CVEs watched)", osv)

        # 6. Findings.
        assessments = s.rows("security.assessment_index")
        report["assessments"] = sorted(
            (a.get("release_id"), a.get("cve_id"), a.get("status"), a.get("justification"))
            for a in assessments)
        urgent = s.rows("security.urgent_exposures")
        report["urgent"] = [
            {k: r.get(k) for k in ("cve_id", "kev_listed", "kev_due_date", "epss_score",
                                    "epss_percentile", "product_name", "version")}
            for r in urgent]

        # 7. Scale: settle KEV triage over growing watch lists.
        s.timed("graduate KEV and EPSS triage to settle", lambda: s.submit(
            "graduate", recipe.graduate()))
        for name in ("security.kev-triage", "security.epss-triage"):
            s.cx("line", "enable", name)
        catalog = sorted(
            cve for cve in _kev_ids(s) if cve not in {a.get("cve_id") for a in assessments})
        batches = []
        for index in range(args.scale_batches):
            chunk = catalog[index * args.scale_size:(index + 1) * args.scale_size]
            s.timed(f"scale batch {index + 1}: watch {len(chunk)} KEV CVEs",
                    lambda chunk=chunk, index=index: s.submit(f"scale-{index}",
                                                             recipe.watch(*chunk)))
            before = {r["run"] for r in s.runs("security.kev-triage")}
            started = time.monotonic()
            s.cx("line", "run", "security.kev-daily")
            run = s.wait_run("security.kev-triage", before)
            wall = time.monotonic() - started
            card = s.json("get", run["run"])["card"]
            egress = s.egress(run["run"])
            batches.append({
                "batch": index + 1, "watched_total": (index + 1) * len(chunk),
                "claims": len(egress.get("target_paths") or ()),
                "outcome": egress.get("settle_outcome"),
                "triage_elapsed_s": round(card.get("elapsed_us", 0) / 1e6, 2),
                "acquire_to_settled_s": round(wall, 2),
            })
            print(f"  batch {index + 1}: {batches[-1]}", flush=True)
        report["scale"] = batches
    finally:
        s.stop()
        (s.scratch / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps({k: report[k] for k in ("timings", "osv", "kev", "epss", "cve_record",
                                             "osv_day2", "scale") if k in report}, indent=1))


def _kev_ids(s: Session) -> list[str]:
    """The CVE ids the live KEV catalog lists (the scale batches watch them)."""

    del s
    with urllib.request.urlopen(KEV_URL, timeout=60) as response:  # noqa: S310 - fixed https URL
        catalog = json.loads(response.read())
    return [v["cveID"] for v in catalog["vulnerabilities"]]


if __name__ == "__main__":
    main()
