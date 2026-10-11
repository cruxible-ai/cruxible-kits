"""Record the gate's vendored responses from the live sources (run by hand, rarely).

    uv run --no-project --with httpx python record_responses.py

Writes ``src/security_gate_sources/responses/``:

- ``known_exploited_vulnerabilities.json``: the gate catalog (kept as committed;
  ``ADD_KEV`` entries are copied in from the live catalog when missing);
- ``cve/<CVE>.json``: CVE JSON 5 records from cveawg.mitre.org;
- ``osv/querybatch.json``: OSV's answer per gate SBOM purl, and ``osv/vulns/<id>.json``
  for every hit, every watched CVE and their aliases (exactly the requests the
  real ``security.osv-query`` makes for the gate's inventory);
- ``epss_scores.csv.gz``: the live EPSS daily file's header and the rows of the
  gate's CVEs.

Hosts: cisa.gov, cveawg.mitre.org, api.osv.dev, epss.empiricalsecurity.com.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
RESPONSES = HERE / "src" / "security_gate_sources" / "responses"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ADD_KEV = ["CVE-2026-102490"]  # Zammad, added 2026-10-02: the gate's newly listed CVE
CVE_RECORDS = ["CVE-2021-44228"]
#: The gate SBOM's components and the CVEs the gate watches before OSV runs.
PURLS = [
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "pkg:pypi/jinja2@3.1.3",
    "pkg:pypi/requests@2.32.3",
]
WATCHED = ["CVE-2017-5638", "CVE-2021-44228", "CVE-2021-44832", "CVE-2023-32681"]
EPSS_CVES = {
    "CVE-2017-5638", "CVE-2021-44228", "CVE-2021-44832", "CVE-2021-45046", "CVE-2023-32681",
    "CVE-2024-34064", "CVE-2026-102490",
}


def main() -> None:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        catalog_path = RESPONSES / "known_exploited_vulnerabilities.json"
        catalog = json.loads(catalog_path.read_text())
        live = {v["cveID"]: v for v in client.get(KEV_URL).json()["vulnerabilities"]}
        held = {v["cveID"] for v in catalog["vulnerabilities"]}
        for cve in ADD_KEV:
            if cve not in held:
                catalog["vulnerabilities"].insert(0, live[cve])
        catalog["count"] = len(catalog["vulnerabilities"])
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")

        (RESPONSES / "cve").mkdir(exist_ok=True)
        for cve in CVE_RECORDS:
            body = client.get(f"https://cveawg.mitre.org/api/cve/{cve}").content
            (RESPONSES / "cve" / f"{cve}.json").write_bytes(body)

        osv = RESPONSES / "osv"
        (osv / "vulns").mkdir(parents=True, exist_ok=True)
        batch = client.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": [{"package": {"purl": p}} for p in PURLS]},
        ).json()
        answers = dict(zip(PURLS, batch["results"], strict=True))
        (osv / "querybatch.json").write_text(json.dumps(answers, indent=2, sort_keys=True) + "\n")
        wanted = {v["id"] for r in batch["results"] for v in r.get("vulns", ())} | set(WATCHED)
        fetched: set[str] = set()
        while wanted - fetched:
            follow: set[str] = set()
            for item in sorted(wanted - fetched):
                fetched.add(item)
                response = client.get(f"https://api.osv.dev/v1/vulns/{item}")
                if response.status_code == 200:
                    (osv / "vulns" / f"{item}.json").write_bytes(response.content)
                    if item in WATCHED:
                        follow.update(response.json().get("aliases") or ())
            wanted |= follow

        daily = gzip.decompress(
            client.get("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz").content
        ).decode()
        lines = daily.splitlines()
        rows = [line for line in lines[2:] if line.split(",", 1)[0] in EPSS_CVES]
        text = "\n".join(lines[:2] + rows) + "\n"
        (RESPONSES / "epss_scores.csv.gz").write_bytes(gzip.compress(text.encode(), mtime=0))
    print(f"osv records: {len(list((osv / 'vulns').iterdir()))}; epss rows: {len(rows)}")


if __name__ == "__main__":
    main()
