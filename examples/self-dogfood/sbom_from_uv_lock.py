"""A CycloneDX 1.5 JSON SBOM for one package of a uv workspace, from its uv.lock.

    python sbom_from_uv_lock.py LOCK PACKAGE OUT [--supplier NAME]

The SBOM's ``metadata.component`` is PACKAGE at its locked version; its
``components`` are PACKAGE's runtime dependency closure in the lock: every
package its ``dependencies`` name, transitively, with the extras a dependency
entry requests (``uvicorn[standard]``) followed too. A package's own
optional-dependencies (unless requested) and dev groups are not followed.
Environment markers are not evaluated, so a platform-only dependency (say a
Windows-only one) is listed: the closure is the superset any install could
hold. Each component is ``pkg:pypi/<name>@<version>`` with the name normalized
as the purl spec requires (lowercase, ``_``/``.`` runs to ``-``).

The lock is only read. ``uv export --format cyclonedx1.5`` would do this from a
uv new enough to have it (0.9+); this script stands in for older ones.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import tomllib


def _purl_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def closure(lock: dict[str, Any], root: str) -> dict[str, str]:
    """name -> version of ``root``'s runtime closure (``root`` excluded)."""

    packages = {_purl_name(p["name"]): p for p in lock["package"]}
    seen: dict[str, str] = {}
    pending: list[tuple[str, tuple[str, ...]]] = [(_purl_name(root), ())]
    visited: set[tuple[str, tuple[str, ...]]] = set()
    while pending:
        name, extras = pending.pop()
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        package = packages[name]
        edges = list(package.get("dependencies") or ())
        for extra in extras:
            edges += (package.get("optional-dependencies") or {}).get(extra, [])
        for edge in edges:
            child = _purl_name(edge["name"])
            if child not in packages:
                continue
            seen[child] = str(packages[child].get("version", ""))
            pending.append((child, tuple(sorted(edge.get("extra") or ()))))
    seen.pop(_purl_name(root), None)
    return dict(sorted(seen.items()))


def sbom(lock: dict[str, Any], root: str, supplier: str | None) -> dict[str, Any]:
    package = next(p for p in lock["package"] if _purl_name(p["name"]) == _purl_name(root))
    version = str(package["version"])
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": f"pkg:pypi/{_purl_name(root)}@{version}",
        "name": package["name"],
        "version": version,
        "purl": f"pkg:pypi/{_purl_name(root)}@{version}",
    }
    if supplier:
        component["supplier"] = {"name": supplier}
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{dep_version}",
            "name": name,
            "version": dep_version,
            "purl": f"pkg:pypi/{name}@{dep_version}",
        }
        for name, dep_version in closure(lock, root).items()
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": component},
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lock", type=Path)
    parser.add_argument("package")
    parser.add_argument("out", type=Path)
    parser.add_argument("--supplier")
    args = parser.parse_args()
    lock = tomllib.loads(args.lock.read_text())
    document = sbom(lock, args.package, args.supplier)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2) + "\n")
    print(f"{args.out}: {document['metadata']['component']['name']} "
          f"{document['metadata']['component']['version']}, "
          f"{len(document['components'])} components")


if __name__ == "__main__":
    main()
