"""Write the kit providers' ``registration.json`` (schema 3) from the kit's own definitions.

    python build_registrations.py [--check]

Run with core's ``src`` and client and the provider runtime's ``src`` on
``PYTHONPATH`` (as ``../build_release.py`` expects). Each operation names the
kit capability it serves and carries byte-for-byte copies of what the kit
authors (``../pilot/capabilities.py``): the capability's request and result
Contracts and the CaptureKinds they name, layouts included, rendered by core's
own lowering. ``built_against`` records the capabilities and kinds by digest.
The refusal Contracts are the providers' own and are written here. Nothing is
installed on an instance from these copies; core fits them against the kit's
capabilities when a Line binds a slot.

``--check`` writes nothing and exits 1 when a committed registration is stale;
``build_release.py`` runs it before building.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "pilot"))

import capabilities  # noqa: E402

REPOSITORY = "https://github.com/cruxible-ai/cruxible-kits"


def _source(package: str, module: str) -> dict[str, str]:
    root = f"kits/security/source/providers/{package}/src/{package.replace('-', '_')}"
    return {"path": f"{root}/{module}.py", "repository": REPOSITORY}


def _declined(operation: str, description: str) -> dict[str, Any]:
    return {
        "artifact_format": "cruxible-contract-v1",
        "description": description,
        "fields": {},
        "name": f"{operation}.refusal.provider_declined",
        "version": 1,
    }


def _refusals(operation: str) -> dict[str, Any]:
    return {
        "provider_declined": {
            "contract": f"{operation}.refusal.provider_declined@1",
            "absorbable": False,
        }
    }


#: Each package: its operations as the author writes them, and its own refusal Contracts.
PACKAGES: dict[str, dict[str, Any]] = {
    "security-osv-provider": {
        "operations": [
            {
                "name": "osv.match",
                "description": "Matches this run's OSV responses to the components asked about: "
                "one document of (component, CVE) pairs with the advisory and the versions OSV "
                "lists as fixed, the components answered in full, and those left unchecked "
                "with why.",
                "source": _source("security-osv-provider", "osv"),
                "serves": [capabilities.OSV_MATCH],
                "in": capabilities.OSV_MATCH + ".request@1",
                "out": capabilities.OSV_MATCH + ".result@1",
                "effect": "pure",
                "refusals": _refusals("osv.match"),
                "entrypoint": "security_osv_provider.osv:OsvMatch",
            },
            {
                "name": "osv.query",
                "description": "Asks api.osv.dev about each component (one POST /v1/querybatch "
                "per 1000, then GET /v1/vulns/{id} for every advisory named) and returns every "
                "response as canonical JSON, one Capture each; distro packages are never asked.",
                "source": _source("security-osv-provider", "osv"),
                "serves": [capabilities.OSV_QUERY],
                "in": capabilities.OSV_QUERY + ".request@1",
                "out": capabilities.OSV_QUERY + ".result@1",
                "effect": "external_read",
                "refusals": _refusals("osv.query"),
                "entrypoint": "security_osv_provider.osv:OsvQuery",
            },
            {
                "name": "sbom.components",
                "description": "Reads one CycloneDX JSON SBOM: one document naming its "
                "inventory and each distinct component by purl with its scope, nested "
                "components flattened, unidentified ones counted.",
                "source": _source("security-osv-provider", "sbom"),
                "serves": [capabilities.SBOM_COMPONENTS],
                "in": capabilities.SBOM_COMPONENTS + ".request@1",
                "out": capabilities.SBOM_COMPONENTS + ".result@1",
                "effect": "pure",
                "refusals": _refusals("sbom.components"),
                "entrypoint": "security_osv_provider.sbom:SbomComponents",
            },
        ],
        "refusals": [
            _declined(
                "osv.match",
                "Detail of a provider_declined refusal (too many advisories, or unreadable "
                "input).",
            ),
            _declined(
                "osv.query",
                "Detail of a provider_declined refusal (too many advisories, or unreadable "
                "input).",
            ),
            _declined(
                "sbom.components",
                "Detail of a provider_declined refusal (the bytes are not a CycloneDX JSON "
                "SBOM, or list too many components).",
            ),
        ],
    },
    "security-sarif-provider": {
        "operations": [
            {
                "name": "sarif.findings",
                "description": "Reads this run's SARIF 2.1.0 logs for one repository with the "
                "findings it holds: one document of findings by repository, weakness and locus, "
                "present or fixed, the held findings a full run covers, and attention records "
                "for regressions and location gaps.",
                "source": _source("security-sarif-provider", "sarif"),
                "serves": [capabilities.SARIF_FINDINGS],
                "in": capabilities.SARIF_FINDINGS + ".request@1",
                "out": capabilities.SARIF_FINDINGS + ".result@1",
                "effect": "pure",
                "refusals": _refusals("sarif.findings"),
                "entrypoint": "security_sarif_provider.sarif:SarifFindings",
            }
        ],
        "refusals": [
            _declined(
                "sarif.findings",
                "Detail of a provider_declined refusal (an unreadable SARIF log or held row, "
                "too many logs or results).",
            )
        ],
    },
}


def package_root(package: str) -> Path:
    return HERE / package / "src" / package.replace("-", "_")


def write(package: str, *, check: bool) -> bool:
    """Write (or with ``check``, compare) one package's registration; True when current."""

    import shutil
    import tempfile

    from cruxible_provider_runtime.registration import write_registration

    spec = PACKAGES[package]
    root = package_root(package)
    contracts, kinds, built_against = capabilities.provider_shapes()
    with tempfile.TemporaryDirectory(prefix="kit-registration-") as scratch:
        # The writer keeps the operations as written and replaces declares; it reads
        # and writes registration.json in place, so it runs on a scratch copy.
        copy = Path(scratch) / root.name
        copy.mkdir()
        manifest = root / "manifest.yaml"
        shutil.copyfile(manifest, copy / "manifest.yaml")
        (copy / "registration.json").write_text(
            json.dumps(
                {
                    "schema_version": 3,
                    "manifest": {"path": "manifest.yaml", "digest": "sha256:" + "0" * 64},
                    "operations": sorted(spec["operations"], key=lambda item: item["name"]),
                    "declares": {"contracts": spec["refusals"]},
                    "runtime_requirements": [],
                }
            )
        )
        pool = [*contracts, *spec["refusals"]]
        write_registration(copy, contracts=pool, capture_kinds=kinds)
        # built_against: only what this package's copies were made from.
        carried = {
            item["name"]
            for item in json.loads((copy / "registration.json").read_bytes())["declares"].get(
                "capture_kinds", ()
            )
        }
        served = {name for item in spec["operations"] for name in item["serves"]}
        write_registration(
            copy,
            contracts=pool,
            capture_kinds=kinds,
            built_against=[
                item
                for item in built_against
                if (item["kind"] == "Capability" and item["name"] in served)
                or (item["kind"] == "CaptureKind" and item["name"] in carried)
            ],
        )
        rendered = (copy / "registration.json").read_bytes()
    target = root / "registration.json"
    current = target.is_file() and target.read_bytes() == rendered
    if not current and not check:
        target.write_bytes(rendered)
    return current


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if stale")
    args = parser.parse_args()
    stale = [package for package in PACKAGES if not write(package, check=args.check)]
    for package in stale:
        print(f"{package}: registration.json {'is stale' if args.check else 'written'}")
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
