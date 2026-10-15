"""Write the gate fixture's registration (and vendor the kit's Source adapters).

    uv run --no-project --with cruxible-provider-web==0.2.2 python build_registration.py

web.fetch's definition, vocabulary and fixtures are cruxible-provider-web
0.2.2's, byte for byte, so installing this package binds core's web.fetch
registration. ``security.osv-query`` and ``security.epss-daily`` are the kit's
security-sources-provider definitions, vocabularies and fixtures, copied here
with its ``sources.py`` (as ``_sources.py``), so the fixture registers the
interfaces the kit carries and runs the kit's adapter code.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from cruxible_provider_runtime.canonical import domain_digest
from cruxible_provider_runtime.registration import INTERFACE_DOMAIN, load_registration

MODULE = Path(__file__).resolve().parent / "src" / "security_gate_sources"
SOURCES = (
    Path(__file__).resolve().parents[2]
    / "source" / "providers" / "security-sources-provider" / "src" / "security_sources_provider"
)
VENDORED = "# Vendored from security-sources-provider by build_registration.py: do not edit.\n"


def ref(name: str) -> dict[str, str]:
    digest = hashlib.sha256((MODULE / name).read_bytes()).hexdigest()
    return {"path": name, "digest": "sha256:" + digest}


def write(name: str, value: object) -> dict[str, str]:
    (MODULE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return ref(name)


def _vendor() -> dict[str, dict[str, object]]:
    (MODULE / "_sources.py").write_text(VENDORED + (SOURCES / "sources.py").read_text())
    kit = json.loads((SOURCES / "manifest.json").read_text())
    implementations = {item["interface_id"]: item for item in kit["implementations"]}
    for interface in ("security.osv-query", "security.epss-daily"):
        for folder in ("contracts", "vocab", "registration-fixtures"):
            shutil.copyfile(SOURCES / folder / f"{interface}.json",
                            MODULE / folder / f"{interface}.json")
    return implementations


def main() -> None:
    kit = _vendor()
    implementations = []
    interfaces = []
    specs = [
        ("web.fetch", "web:GateWebFetch", "classifier:classify_web_fetch", "classifier.py",
         "vocab/web.fetch.yaml", {
             "declared_input_buckets": ["source_kind=api_json;access=*;page_weight=*"],
             "bucket_conformance": {
                 "source_kind=api_json;access=*;page_weight=*": "web-fetch-api-json"},
             "declared_endpoints": ["dynamic:target-from-run-input"],
             "capture_contract_families": ["web.fetch.retrieval.v1"],
         }),
        ("security.osv-query", "feeds:GateOsvQuery", "_sources:classify_osv", "_sources.py",
         "vocab/security.osv-query.json", kit["security.osv-query"]),
        ("security.epss-daily", "feeds:GateEpssDaily", "_sources:classify_epss", "_sources.py",
         "vocab/security.epss-daily.json", kit["security.epss-daily"]),
    ]
    for interface, entry, classifier, source, vocabulary, declared in specs:
        definition = json.loads((MODULE / f"contracts/{interface}.json").read_bytes())
        digest = domain_digest(INTERFACE_DOMAIN, definition)
        implementations.append({
            "interface_id": interface,
            "interface_digest": digest,
            "entrypoint": f"security_gate_sources.{entry}",
            "backends": ["local_env"],
            "requires_extras": [],
            "declared_input_buckets": declared["declared_input_buckets"],
            "bucket_conformance": declared["bucket_conformance"],
            "declared_endpoints": declared["declared_endpoints"],
            "capture_contract_families": declared["capture_contract_families"],
            "deterministic": True,
            "side_effects": False,
        })
        interfaces.append({
            "interface_id": interface,
            "interface_digest": digest,
            "definition": ref(f"contracts/{interface}.json"),
            "vocabulary": ref(vocabulary),
            "classifier": {
                "identity": f"{interface}.input",
                "version": 1,
                "entrypoint": f"security_gate_sources.{classifier}",
                "source": ref(source),
            },
            "fixtures": ref(f"registration-fixtures/{interface}.json"),
            "predecessors": [],
        })
        print(interface, digest)
    manifest = write(
        "manifest.json",
        {
            "schema_version": 1,
            "provider_id": "security-gate-sources",
            "distribution": {"name": "security-gate-sources", "version": "0.2.1"},
            "entrypoint_group": "cruxible.providers",
            "supported_protocol_majors": [1],
            "implementations": implementations,
        },
    )
    write(
        "registration.json",
        {"schema_version": 1, "manifest": manifest, "interfaces": interfaces,
         "runtime_requirements": []},
    )
    load_registration(MODULE)


if __name__ == "__main__":
    main()
