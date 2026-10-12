"""Regenerate the dogfood SBOMs from the current uv.lock files; re-acquire the changed ones.

    python refresh_sboms.py [--core-ref claude/cut-b] [--providers-ref main] [--dry-run]

Run it when Cruxible's dependencies change (after a deploy, or a lock bump on
either repository). It reads each lock read-only through git (``git show
REF:uv.lock``) from ``~/tmp-workspaces/cruxible-cut-b`` (packages ``cruxible``
and ``cruxible-client``) and ``~/Git/cruxible-providers`` (the six provider
packages), writes the CycloneDX SBOMs into the instance workspace's
``sboms/``, and runs ``security.sbom-acquire`` for every SBOM whose bytes
changed. Each acquisition's landing runs ``security.sbom-import``, whose
proposal (a new release, or components a release did not hold) waits for review
with the other proposals: this script accepts nothing. Proposals made against
the same head go stale as soon as one of them is activated: activate one, then
``cruxible proposal readmit`` the next (or review them one per refresh). A new
version of a
package becomes a new release; the old release stays (removing components and
retiring releases are out of the kit's v1 scope).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import tomllib

from persistent import ROOT, Instance
from sbom_from_uv_lock import sbom

CORE_REPO = Path(os.environ.get("SECURITY_DOGFOOD_CORE_REPO",
                                Path.home() / "tmp-workspaces" / "cruxible-cut-b"))
PROVIDERS_REPO = Path(os.environ.get("SECURITY_DOGFOOD_PROVIDERS_REPO",
                                     Path.home() / "Git" / "cruxible-providers"))
CORE_PACKAGES = ("cruxible", "cruxible-client")
PROVIDER_PACKAGES = (
    "cruxible-provider-runtime", "cruxible-provider-web", "cruxible-provider-docs",
    "cruxible-provider-quant", "cruxible-provider-noop", "cruxible-provider-workspace",
)


def _lock(repo: Path, ref: str) -> dict[str, object]:
    text = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:uv.lock"],
                          capture_output=True, text=True, check=True).stdout
    return tomllib.loads(text)


def generate(core_ref: str, providers_ref: str) -> dict[str, bytes]:
    """file name -> SBOM bytes, for all eight packages."""

    out: dict[str, bytes] = {}
    for repo, ref, packages in ((CORE_REPO, core_ref, CORE_PACKAGES),
                                (PROVIDERS_REPO, providers_ref, PROVIDER_PACKAGES)):
        lock = _lock(repo, ref)
        for package in packages:
            document = sbom(lock, package, "Cruxible")
            out[f"{package}.cdx.json"] = (json.dumps(document, indent=2) + "\n").encode()
    return out


def refresh(instance: Instance, core_ref: str, providers_ref: str,
            dry_run: bool = False, after_each: Callable[[str], None] | None = None) -> list[str]:
    """Write changed SBOMs and acquire each; the names that changed.

    ``after_each`` runs after each acquisition (setup waits for the import and
    accepts it there, so the next import is evaluated against the new head).
    """

    target = instance.ws / "sboms"
    target.mkdir(parents=True, exist_ok=True)
    changed = []
    for name, content in sorted(generate(core_ref, providers_ref).items()):
        path = target / name
        if path.exists() and path.read_bytes() == content:
            continue
        changed.append(name)
        if dry_run:
            continue
        path.write_bytes(content)
        request = instance.payload(f"sbom-{name}", {"relative_path": f"sboms/{name}"})
        instance.cx("procedure", "run", "security.sbom-acquire", str(request))
        if after_each is not None:
            after_each(name)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--core-ref", default="claude/cut-b")
    parser.add_argument("--providers-ref", default="main")
    parser.add_argument("--dry-run", action="store_true", help="list what changed, acquire nothing")
    args = parser.parse_args()
    changed = refresh(Instance(ROOT), args.core_ref, args.providers_ref, args.dry_run)
    print("unchanged" if not changed else
          ("would acquire: " if args.dry_run else "acquired: ") + ", ".join(changed))
    if changed and not args.dry_run:
        print("Each landing runs security.sbom-import; review its proposal: "
              "daemon.sh cx proposal list")


if __name__ == "__main__":
    main()
