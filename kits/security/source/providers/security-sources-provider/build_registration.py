"""Write the package's registration files (manifest, vocabularies, fixtures, registration.json).

Run after any change to a contract or a module, before ``uv build``:

    uv run --no-project --with cruxible-provider-runtime==0.2.0 python build_registration.py

Every file the registration references is hashed here, so the registration a
built wheel carries always matches the bytes beside it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cruxible_provider_runtime.canonical import domain_digest
from cruxible_provider_runtime.registration import INTERFACE_DOMAIN, load_registration

ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "src" / "security_sources_provider"
VERSION = "1.2.1"


def _dimension(name: str, description: str, classes: dict[str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "classes": [{"id": key, "description": value} for key, value in classes.items()],
    }


def _rows(name: str, value: object) -> list[dict[str, Any]]:
    return [{"bindings": [], "fields": [{"name": name, "state": "present", "value": value}]}]


#: interface -> (entrypoint, classifier, description, dimensions, fixture input, bucket,
#:               declared selector, declared endpoints, capture contract family)
INTERFACES: dict[
    str, tuple[str, str, str, list[dict[str, Any]], dict[str, Any], str, str, list[str], str]
] = {
    "security.osv-query": (
        "sources:OsvQuery",
        "sources:classify_osv",
        "Component package URLs and watched CVEs to ask OSV.dev about.",
        [
            _dimension(
                "components",
                "how many component purls the request carries",
                {"none": "no component", "small": "at most 1000", "large": "more than 1000"},
            ),
            _dimension(
                "watchlist",
                "how many watched CVEs the request carries",
                {"small": "at most 1000", "large": "more than 1000"},
            ),
        ],
        {
            "releases": _rows("components", ["pkg:pypi/jinja2@3.1.3"]),
            "watched": _rows("cve_id", "CVE-2024-34064"),
            "ecosystems": {"input_bucket": "list=osv", "retrieved": {
                "url": "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt",
                "status_code": 200, "content_type": "text/plain", "byte_count": 5,
                "body_sha256": "sha256:" + hashlib.sha256(b"PyPI\n").hexdigest(),
                "body_base64": base64.b64encode(b"PyPI\n").decode(), "source": "fixture"}},
            "purl_types": {"osv_ecosystems": {"pypi": "PyPI"}},
        },
        "components=small;watchlist=small",
        "components=*;watchlist=*",
        ["https://api.osv.dev"],
        "security.osv.exchanges.v1",
    ),
    "security.osv-ecosystems": (
        "sources:OsvEcosystems",
        "sources:classify_ecosystems",
        "OSV's published ecosystem list (ecosystems.txt) to retain.",
        [_dimension("list", "which list", {"osv": "OSV's ecosystems.txt"})],
        {},
        "list=osv",
        "list=osv",
        ["https://osv-vulnerabilities.storage.googleapis.com"],
        "security.osv.ecosystems.v1",
    ),
    "security.repo-snapshot": (
        "sources:RepoSnapshot",
        "sources:classify_repo",
        "One GitHub repository's declared files at one ref for one scope.",
        [
            _dimension(
                "scope",
                "what the snapshot reads",
                {
                    "ci.workflows": "every workflow file under a directory",
                    "release.manifest": "one release manifest file",
                },
            )
        ],
        {
            "forge_host": "github.com",
            "full_name": "cruxible-ai/cruxible",
            "ref": "main",
            "scope": "ci.workflows",
            "path": ".github/workflows/",
        },
        "scope=ci.workflows",
        "scope=*",
        ["https://api.github.com", "https://raw.githubusercontent.com"],
        "security.github.snapshot.v1",
    ),
    "security.pypi-release": (
        "sources:PypiRelease",
        "sources:classify_pypi",
        "What PyPI serves for one project: its newest versions' files and provenance.",
        [
            _dimension(
                "versions",
                "how many of the newest versions the request reads",
                {"few": "at most 3", "many": "4 to 10"},
            )
        ],
        {"project": "cruxible", "versions": 3},
        "versions=few",
        "versions=*",
        ["https://pypi.org"],
        "security.pypi.release.v1",
    ),
    "security.release-asset": (
        "sources:ReleaseAsset",
        "sources:classify_asset",
        "One GitHub release asset's served bytes.",
        [_dimension("asset", "what is read", {"release": "a release download URL"})],
        {"url": "https://github.com/cruxible-ai/cruxible/releases/download/v0.3.2/"
                "agent-release-0.3.2.tar.gz"},
        "asset=release",
        "asset=release",
        ["https://github.com", "https://objects.githubusercontent.com",
         "https://release-assets.githubusercontent.com"],
        "security.github.asset.v1",
    ),
}


def _write(name: str, value: object) -> dict[str, str]:
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    (MODULE / name).parent.mkdir(parents=True, exist_ok=True)
    (MODULE / name).write_bytes(content)
    return _ref(name)


def _ref(name: str) -> dict[str, str]:
    digest = hashlib.sha256((MODULE / name).read_bytes()).hexdigest()
    return {"path": name, "digest": "sha256:" + digest}


def main() -> None:
    implementations = []
    interfaces = []
    for interface, (
        entry,
        classifier,
        description,
        dims,
        fixture,
        bucket,
        selector,
        endpoints,
        family,
    ) in INTERFACES.items():
        contract_path = f"contracts/{interface}.json"
        definition = json.loads((MODULE / contract_path).read_bytes())
        digest = domain_digest(INTERFACE_DOMAIN, definition)
        vocabulary = _write(
            f"vocab/{interface}.json",
            {
                "interface_id": interface,
                "version": 1,
                "status": "draft",
                "description": description,
                "dimensions": dims,
            },
        )
        fixture_id = interface.removeprefix("security.") + "-fixture"
        fixtures = _write(
            f"registration-fixtures/{interface}.json",
            [{"fixture_id": fixture_id, "canonical_input": fixture, "measured_bucket_id": bucket}],
        )
        module, _, _ = classifier.partition(":")
        implementations.append(
            {
                "interface_id": interface,
                "interface_digest": digest,
                "entrypoint": f"security_sources_provider.{entry}",
                "backends": ["local_env"],
                "requires_extras": [],
                "declared_input_buckets": [selector],
                "bucket_conformance": {selector: fixture_id},
                "declared_endpoints": endpoints,
                "capture_contract_families": [family],
                "deterministic": False,
                "side_effects": False,
            }
        )
        interfaces.append(
            {
                "interface_id": interface,
                "interface_digest": digest,
                "definition": _ref(contract_path),
                "vocabulary": vocabulary,
                "classifier": {
                    "identity": f"{interface}.input",
                    "version": 1,
                    "entrypoint": f"security_sources_provider.{classifier}",
                    "source": _ref(f"{module}.py"),
                },
                "fixtures": fixtures,
                "predecessors": [],
            }
        )
        print(f"{interface} {digest}")
    manifest = _write(
        "manifest.json",
        {
            "schema_version": 1,
            "provider_id": "security-sources-provider",
            "distribution": {"name": "security-sources-provider", "version": VERSION},
            "entrypoint_group": "cruxible.providers",
            "supported_protocol_majors": [1],
            "implementations": implementations,
        },
    )
    _write(
        "registration.json",
        {
            "schema_version": 1,
            "manifest": manifest,
            "interfaces": interfaces,
            "runtime_requirements": [],
        },
    )
    load_registration(MODULE)  # verifies every reference and cross-link


if __name__ == "__main__":
    main()
