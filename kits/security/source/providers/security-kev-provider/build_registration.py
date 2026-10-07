"""Write the package's registration files (manifest, vocabulary, fixtures, registration.json).

Run after any change to the contract or provider.py, before ``uv build``:

    uv run --no-project --with cruxible-provider-runtime==0.2.0 python build_registration.py

Every file the registration references is hashed here, so the registration a
built wheel carries always matches the bytes beside it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cruxible_provider_runtime.canonical import domain_digest
from cruxible_provider_runtime.registration import INTERFACE_DOMAIN, load_registration

ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "src" / "security_kev_provider"
INTERFACE = "security.kev-catalog"
VERSION = "1.0.0"
BUCKET = "catalog=present;watchlist=small"


def _write(name: str, value: object) -> dict[str, str]:
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    (MODULE / name).parent.mkdir(parents=True, exist_ok=True)
    (MODULE / name).write_bytes(content)
    return _ref(name)


def _ref(name: str) -> dict[str, str]:
    return {"path": name, "digest": "sha256:" + hashlib.sha256((MODULE / name).read_bytes()).hexdigest()}


def main() -> None:
    contract_path = f"contracts/{INTERFACE}.json"
    definition = json.loads((MODULE / contract_path).read_bytes())
    digest = domain_digest(INTERFACE_DOMAIN, definition)
    sample = {"catalogVersion": "fixture", "vulnerabilities": [{"cveID": "CVE-0000-0000"}]}
    vocabulary = _write(
        f"vocab/{INTERFACE}.json",
        {
            "interface_id": INTERFACE,
            "version": 1,
            "status": "draft",
            "description": "A KEV catalog body and the watched vulnerabilities to compare it with.",
            "dimensions": [
                {
                    "name": "catalog",
                    "description": "whether a catalog body is present",
                    "classes": [{"id": "present", "description": "a nonempty base64 body"}],
                },
                {
                    "name": "watchlist",
                    "description": "how many watched vulnerabilities the request carries",
                    "classes": [
                        {"id": "small", "description": "at most 1000 rows"},
                        {"id": "large", "description": "more than 1000 rows"},
                    ],
                },
            ],
        },
    )
    fixtures = _write(
        f"registration-fixtures/{INTERFACE}.json",
        [
            {
                "fixture_id": "kev-catalog-small",
                "canonical_input": {
                    "catalog_base64": base64.b64encode(json.dumps(sample).encode()).decode(),
                    "watched": [],
                },
                "measured_bucket_id": BUCKET,
            }
        ],
    )
    manifest = _write(
        "manifest.json",
        {
            "schema_version": 1,
            "provider_id": "security-kev-provider",
            "distribution": {"name": "security-kev-provider", "version": VERSION},
            "entrypoint_group": "cruxible.providers",
            "supported_protocol_majors": [1],
            "implementations": [
                {
                    "interface_id": INTERFACE,
                    "interface_digest": digest,
                    "entrypoint": "security_kev_provider.provider:KevCatalog",
                    "backends": ["local_env"],
                    "requires_extras": [],
                    "declared_input_buckets": [BUCKET],
                    "bucket_conformance": {BUCKET: "kev-catalog-small"},
                    "declared_endpoints": [],
                    "capture_contract_families": [],
                    "deterministic": True,
                    "side_effects": False,
                }
            ],
        },
    )
    _write(
        "registration.json",
        {
            "schema_version": 1,
            "manifest": manifest,
            "interfaces": [
                {
                    "interface_id": INTERFACE,
                    "interface_digest": digest,
                    "definition": _ref(contract_path),
                    "vocabulary": vocabulary,
                    "classifier": {
                        "identity": f"{INTERFACE}.input",
                        "version": 1,
                        "entrypoint": "security_kev_provider.provider:classify",
                        "source": _ref("provider.py"),
                    },
                    "fixtures": fixtures,
                    "predecessors": [],
                }
            ],
            "runtime_requirements": [],
        },
    )
    load_registration(MODULE)  # verifies every reference and cross-link
    print(f"{INTERFACE} {digest}")


if __name__ == "__main__":
    main()
