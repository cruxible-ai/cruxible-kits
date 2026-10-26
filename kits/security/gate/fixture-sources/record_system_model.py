"""Record the system-model gate fixtures from GitHub and PyPI (run by hand, rarely).

    uv run --no-project --with httpx python record_system_model.py

Writes ``src/security_gate_sources/responses/github/`` and ``.../pypi/``: exactly
the requests the kit's ``security.repo-snapshot`` and ``security.pypi-release``
Sources and its slotted HTTP Procedures make for the gate's questions about
cruxible-ai/cruxible, answered by the live sources once:

- ``github/repo.json``: the commits and contents answers for the workflows at two
  heads of ``main`` (before and after the runtime-image workflow landed: the
  gate moves ``main`` from the first to the second) and for the kit manifest at
  ``v0.3.2``; ``github/raw/<revision>/<path>``: each file's bytes;
  ``github/refs.json``: which head each ref names;
- ``github/api/<name>.json``: the v0.3.2 release, its publish.yml runs and the
  commits that touched scripts/build_kit_bundles.py, and ``github/assets/``:
  one release asset's bytes (the gate serves it altered, see ``web.py``);
- ``pypi/<project>.json`` and ``pypi/provenance/<file>.json`` for the newest
  three versions of cruxible and cruxible-client.

About 12 unauthenticated GitHub API calls (the limit is 60 an hour).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import httpx

HERE = Path(__file__).resolve().parent
OUT = HERE / "src" / "security_gate_sources" / "responses"
REPO = "cruxible-ai/cruxible"
#: main before the runtime-image workflow (first parent of the 0.3.2 merge's
#: workflow history) and main at the 0.3.2 release.
MAIN_HEADS = ["9eb531a47", "v0.3.2"]
WORKFLOWS = ".github/workflows"
MANIFEST = "src/cruxible_core/kit_distribution/manifest.json"
ASSET = "agent-release-0.3.2.tar.gz"
PROJECTS = ["cruxible", "cruxible-client"]
VERSIONS = 3


def main() -> None:
    api = httpx.Client(base_url="https://api.github.com", timeout=60,
                       headers={"accept": "application/vnd.github+json"})
    raw = httpx.Client(base_url="https://raw.githubusercontent.com", timeout=60)
    github = OUT / "github"
    (github / "api").mkdir(parents=True, exist_ok=True)
    (github / "assets").mkdir(parents=True, exist_ok=True)
    recorded: dict[str, dict[str, object]] = {"commits": {}, "contents": {}}
    heads: list[str] = []

    def snapshot(head: str, path: str) -> None:
        commits = api.get(f"/repos/{REPO}/commits",
                          params={"sha": head, "path": path, "per_page": 1})
        commits.raise_for_status()
        recorded["commits"][f"{head}|{path}"] = commits.json()
        revision = commits.json()[0]["sha"]
        contents = api.get(f"/repos/{REPO}/contents/{path}", params={"ref": revision})
        contents.raise_for_status()
        recorded["contents"][f"{revision}|{path}"] = contents.json()
        body = contents.json()
        for entry in body if isinstance(body, list) else [body]:
            if entry.get("type") != "file":
                continue
            target = github / "raw" / revision / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            data = raw.get(f"/{REPO}/{revision}/{quote(entry['path'])}")
            data.raise_for_status()
            target.write_bytes(data.content)

    for ref in MAIN_HEADS:
        head = api.get(f"/repos/{REPO}/commits/{ref}")
        head.raise_for_status()
        heads.append(head.json()["sha"])
        snapshot(heads[-1], WORKFLOWS)
    snapshot(heads[-1], MANIFEST)
    refs = {REPO: {"main": heads, "v0.3.2": heads[-1]}}
    (github / "refs.json").write_text(json.dumps(refs, indent=2, sort_keys=True) + "\n")
    (github / "repo.json").write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")

    release = api.get(f"/repos/{REPO}/releases/tags/v0.3.2")
    release.raise_for_status()
    (github / "api" / "release-v0.3.2.json").write_bytes(release.content)
    runs = api.get(f"/repos/{REPO}/actions/workflows/publish.yml/runs",
                   params={"branch": "v0.3.2", "per_page": 5})
    runs.raise_for_status()
    (github / "api" / "runs-publish-v0.3.2.json").write_bytes(runs.content)
    touched = api.get(f"/repos/{REPO}/commits", params={
        "path": "scripts/build_kit_bundles.py", "sha": "v0.3.2", "per_page": 5})
    touched.raise_for_status()
    (github / "api" / "commits-build_kit_bundles-v0.3.2.json").write_bytes(touched.content)
    (asset,) = [a for a in release.json()["assets"] if a["name"] == ASSET]
    data = httpx.get(asset["browser_download_url"], follow_redirects=True, timeout=60)
    data.raise_for_status()
    (github / "assets" / ASSET).write_bytes(data.content)

    pypi = OUT / "pypi"
    (pypi / "provenance").mkdir(parents=True, exist_ok=True)
    with httpx.Client(base_url="https://pypi.org", timeout=60) as client:
        for project in PROJECTS:
            body = client.get(f"/pypi/{project}/json")
            body.raise_for_status()
            (pypi / f"{project}.json").write_bytes(body.content)
            releases = body.json()["releases"]
            dated = sorted(
                ((max(f["upload_time_iso_8601"] for f in files), version)
                 for version, files in releases.items() if files), reverse=True)
            for _at, version in dated[:VERSIONS]:
                for item in releases[version]:
                    name = item["filename"]
                    answer = client.get(f"/integrity/{project}/{version}/{name}/provenance")
                    if answer.status_code == 200:
                        (pypi / "provenance" / f"{name}.json").write_bytes(answer.content)
    print("recorded", heads)


if __name__ == "__main__":
    main()
