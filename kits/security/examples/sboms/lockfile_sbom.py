"""Generate a CycloneDX 1.6 JSON SBOM from common lockfiles using Python stdlib only.

Zero-dependency starter for agents and local quickstarts when syft or ecosystem
CycloneDX plugins are not installed. Reads whichever lockfiles exist in a repo:

  - requirements.txt (pinned `pkg==version` lines)
  - uv.lock (TOML `[[package]]` entries)
  - package-lock.json (npm v2/v3 `packages` map)
  - Cargo.lock (TOML `[[package]]` entries)
  - go.mod (`require` module lines)

Usage:
    python3 lockfile_sbom.py [REPO_DIR] -o sbom.cdx.json [--name APP] [--version 0.1.0]
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)", line)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        out.append((name, version, f"pkg:pypi/{_pep503(name)}@{version}"))
    return out


def _parse_uv_lock(path: Path) -> list[tuple[str, str, str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", {})
        if not name or not version or isinstance(source, dict) and ("editable" in source or "virtual" in source):
            continue
        out.append((name, str(version), f"pkg:pypi/{_pep503(name)}@{version}"))
    return out


def _parse_package_lock(path: Path) -> list[tuple[str, str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str, str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            name = meta.get("name")
            if not name:
                parts = key.split("node_modules/")
                name = parts[-1] if len(parts) > 1 else ""
            if not name:
                continue
            encoded = quote(name, safe="/")
            out.append((name, str(version), f"pkg:npm/{encoded}@{version}"))
    return out


def _parse_cargo_lock(path: Path) -> list[tuple[str, str, str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version or not pkg.get("source"):
            continue
        out.append((name, str(version), f"pkg:cargo/{name}@{version}"))
    return out


def _parse_go_mod(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            mod, version = parts[0], parts[1]
            out.append((mod, version, f"pkg:golang/{mod}@{version}"))
    return out


PARSERS = (
    ("uv.lock", _parse_uv_lock),
    ("requirements.txt", _parse_requirements),
    ("package-lock.json", _parse_package_lock),
    ("Cargo.lock", _parse_cargo_lock),
    ("go.mod", _parse_go_mod),
)


def build_sbom(repo: Path, *, app_name: str, app_version: str) -> dict:
    seen: dict[str, dict] = {}
    sources: list[str] = []
    for filename, parser in PARSERS:
        candidate = repo / filename
        if not candidate.is_file():
            continue
        rows = parser(candidate)
        if not rows:
            continue
        sources.append(filename)
        for name, version, purl in rows:
            seen.setdefault(
                purl,
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": name,
                    "version": version,
                    "purl": purl,
                },
            )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {"type": "application", "name": "cruxible-security-lockfile-sbom", "version": "1"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": app_name,
                "version": app_version,
                "purl": f"pkg:generic/{app_name}",
            },
            "properties": [{"name": "lockfiles", "value": ",".join(sources)}],
        },
        "components": [seen[k] for k in sorted(seen)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a CycloneDX 1.6 SBOM from repo lockfiles.")
    parser.add_argument("repo", nargs="?", default=".", help="Repository root (default: current directory)")
    parser.add_argument("-o", "--out", default="sbom.cdx.json", help="Output path (default: sbom.cdx.json)")
    parser.add_argument("--name", help="Application name (default: repo folder name)")
    parser.add_argument("--version", default="0.1.0", help="Application version (default: 0.1.0)")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    app_name = args.name or repo.name
    doc = build_sbom(repo, app_name=app_name, app_version=args.version)
    out = Path(args.out)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    lockfiles = doc["metadata"]["properties"][0]["value"] or "none"
    print(f"Wrote {out} ({len(doc['components'])} components from {lockfiles})")


if __name__ == "__main__":
    main()
