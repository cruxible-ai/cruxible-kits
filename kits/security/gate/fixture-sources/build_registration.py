"""Write manifest.json and registration.json for the gate's web.fetch package.

    uv run --no-project --with cruxible-provider-web==0.2.1 python build_registration.py

The definition, vocabulary and fixtures are cruxible-provider-web 0.2.1's,
byte for byte, so installing this package binds core's web.fetch registration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cruxible_provider_runtime.canonical import domain_digest
from cruxible_provider_runtime.registration import INTERFACE_DOMAIN, load_registration

MODULE = Path(__file__).resolve().parent / "src" / "kev_gate_web"


def ref(name: str) -> dict[str, str]:
    return {"path": name, "digest": "sha256:" + hashlib.sha256((MODULE / name).read_bytes()).hexdigest()}


def write(name: str, value: object) -> dict[str, str]:
    (MODULE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return ref(name)


def main() -> None:
    definition = json.loads((MODULE / "contracts/web.fetch.json").read_bytes())
    digest = domain_digest(INTERFACE_DOMAIN, definition)
    manifest = write(
        "manifest.json",
        {
            "schema_version": 1,
            "provider_id": "kev-gate-web",
            "distribution": {"name": "kev-gate-web", "version": "0.1.0"},
            "entrypoint_group": "cruxible.providers",
            "supported_protocol_majors": [1],
            "implementations": [
                {
                    "interface_id": "web.fetch",
                    "interface_digest": digest,
                    "entrypoint": "kev_gate_web.provider:GateWebFetch",
                    "backends": ["local_env"],
                    "requires_extras": [],
                    "declared_input_buckets": ["source_kind=api_json;access=*;page_weight=*"],
                    "bucket_conformance": {
                        "source_kind=api_json;access=*;page_weight=*": "web-fetch-api-json"
                    },
                    "declared_endpoints": ["dynamic:target-from-run-input"],
                    "capture_contract_families": ["web.fetch.retrieval.v1"],
                    "deterministic": True,
                    "side_effects": False,
                }
            ],
        },
    )
    write(
        "registration.json",
        {
            "schema_version": 1,
            "manifest": manifest,
            "interfaces": [
                {
                    "interface_id": "web.fetch",
                    "interface_digest": digest,
                    "definition": ref("contracts/web.fetch.json"),
                    "vocabulary": ref("vocab/web.fetch.yaml"),
                    "classifier": {
                        "identity": "web.fetch.input",
                        "version": 1,
                        "entrypoint": "kev_gate_web.classifier:classify_web_fetch",
                        "source": ref("classifier.py"),
                    },
                    "fixtures": ref("registration-fixtures/web.fetch.json"),
                    "predecessors": [],
                }
            ],
            "runtime_requirements": [],
        },
    )
    load_registration(MODULE)
    print("web.fetch", digest)


if __name__ == "__main__":
    main()
