"""Write the package's registration files (manifest, vocabularies, fixtures, registration.json).

Run after any change to a contract or a module, before ``uv build``:

    uv run --no-project --with cruxible-provider-runtime==0.2.0 python build_registration.py

Every file the registration references is hashed here, so the registration a
built wheel carries always matches the bytes beside it.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from cruxible_provider_runtime.canonical import domain_digest
from cruxible_provider_runtime.registration import INTERFACE_DOMAIN, load_registration

ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "src" / "security_analysis_provider"
VERSION = "1.3.0"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


_CATALOG = _b64(
    json.dumps(
        {
            "catalogVersion": "fixture",
            "dateReleased": "2026-01-01T00:00:00Z",
            "vulnerabilities": [{"cveID": "CVE-0000-0000", "dateAdded": "2026-01-01"}],
        }
    ).encode()
)
_EPSS = _b64(
    gzip.compress(
        b"#model_version:fixture,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n"
        b"CVE-0000-0000,0.00100,0.10000\n",
        mtime=0,
    )
)
_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "fixture", "version": "1.0"}},
        "components": [
            {"type": "library", "name": "dep", "version": "1.0", "purl": "pkg:pypi/dep@1.0"}
        ],
    }
)
_RECORD = _b64(
    json.dumps(
        {
            "cveMetadata": {"cveId": "CVE-0000-0000"},
            "containers": {"cna": {"affected": [{"vendor": "v", "product": "p", "versions": []}]}},
        }
    ).encode()
)


_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fixture", "rules": [{"id": "CWE-89"}]}},
                "versionControlProvenance": [
                    {"repositoryUri": "https://github.com/fixture/fixture", "revisionId": "0"}
                ],
                "results": [],
            }
        ],
    }
)


_SNAPSHOT = {
    "input_bucket": "scope=ci.workflows",
    "source": "fixture",
    "forge_host": "github.com",
    "full_name": "fixture/fixture",
    "ref": "main",
    "scope": "ci.workflows",
    "path": ".github/workflows/",
    "locator": "github.com/fixture/fixture@main:.github/workflows/",
    "revision": "0" * 40,
    "files": [],
}


def _dimension(name: str, description: str, classes: dict[str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "classes": [{"id": key, "description": value} for key, value in classes.items()],
    }


SIZE = {"small": "at most 1000 rows", "large": "more than 1000 rows"}

#: interface -> (entrypoint, classifier, description, dimensions, fixture input, bucket,
#:               declared selector)
INTERFACES: dict[str, tuple[str, str, str, list[dict[str, Any]], dict[str, Any], str, str]] = {
    "security.kev-catalog": (
        "kev:KevTriage",
        "kev:classify_triage",
        "A KEV catalog body and the watched vulnerabilities to compare it with.",
        [
            _dimension(
                "catalog",
                "whether a catalog body is present",
                {"present": "a nonempty base64 body"},
            ),
            _dimension("watchlist", "how many watched vulnerabilities the request carries", SIZE),
        ],
        {"catalog_base64": _CATALOG, "watched": []},
        "catalog=present;watchlist=small",
        "catalog=present;watchlist=*",
    ),
    "security.kev-attention": (
        "kev:KevAttention",
        "kev:classify_attention",
        "A KEV catalog body and the inventory to find newly listed, unwatched exposure in.",
        [
            _dimension(
                "catalog",
                "whether a catalog body is present",
                {"present": "a nonempty base64 body"},
            ),
            _dimension("inventory", "how many releases the request carries", SIZE),
        ],
        {"catalog_base64": _CATALOG, "releases": [], "watched": [], "assessments": []},
        "catalog=present;inventory=small",
        "catalog=present;inventory=*",
    ),
    "security.epss-scores": (
        "epss:EpssTriage",
        "epss:classify",
        "An EPSS daily file and the watched vulnerabilities to score.",
        [
            _dimension(
                "daily", "whether a daily file is present", {"present": "a nonempty base64 body"}
            ),
            _dimension("watchlist", "how many watched vulnerabilities the request carries", SIZE),
        ],
        {"daily_base64": _EPSS, "watched": []},
        "daily=present;watchlist=small",
        "daily=present;watchlist=*",
    ),
    "security.cyclonedx-components": (
        "sbom:CycloneDxComponents",
        "sbom:classify",
        "A CycloneDX JSON SBOM and the releases already in inventory.",
        [
            _dimension("sbom", "whether an SBOM text is present", {"present": "a nonempty text"}),
            _dimension(
                "size", "how large the SBOM is", {"small": "at most 4 MiB", "large": "more"}
            ),
        ],
        {"sbom_text": _SBOM, "releases": []},
        "sbom=present;size=small",
        "sbom=present;size=small",
    ),
    "security.osv-applicability": (
        "applicability:OsvApplicability",
        "applicability:classify_osv",
        "An OSV query Capture body, the releases, the watched CVEs and held assessments.",
        [
            _dimension("osv", "whether an OSV body is present", {"present": "an object"}),
            _dimension("inventory", "how many releases the request carries", SIZE),
        ],
        {"osv": {"exchanges": []}, "releases": [], "watched": [], "assessments": []},
        "osv=present;inventory=small",
        "osv=present;inventory=*",
    ),
    "security.cve-applicability": (
        "applicability:CveApplicability",
        "applicability:classify_cve",
        "A CVE record Capture body, the releases (with their source repositories), the "
        "watched CVEs, held assessments and the collectionURL map.",
        [
            _dimension("record", "whether a record body is present", {"present": "a base64 body"}),
            _dimension("inventory", "how many releases the request carries", SIZE),
        ],
        {"record_base64": _RECORD, "releases": [], "watched": [], "assessments": [],
         "sources": [], "collections": {"collections": {"https://pypi.org": {"type": "pypi"}}}},
        "record=present;inventory=small",
        "record=present;inventory=*",
    ),
    "security.workflow-facts": (
        "workflows:WorkflowFacts",
        "workflows:classify",
        "A repository snapshot Capture body and what is held for its source.",
        [
            _dimension(
                "scope",
                "what the snapshot read",
                {"ci.workflows": "workflow files", "release.manifest": "a release manifest"},
            )
        ],
        {"snapshot": _SNAPSHOT, "coverage": [], "held": [], "targets": [], "releases": []},
        "scope=ci.workflows",
        "scope=*",
    ),
    "security.registry-facts": (
        "registry:RegistryFacts",
        "registry:classify",
        "A PyPI release Capture body and what is held for the project's target.",
        [_dimension("release", "whether a release body is present", {"present": "an object"})],
        {"release": {"project": "fixture", "versions": []}, "coverage": [], "held": []},
        "release=present",
        "release=present",
    ),
    "security.sarif-findings": (
        "sarif:SarifFindings",
        "sarif:classify",
        "A SARIF 2.1.0 log and the findings held for the Line's repository.",
        [
            _dimension("sarif", "whether a SARIF log is present", {"present": "a nonempty text"}),
            _dimension(
                "size", "how large the log is", {"small": "at most 16 MiB", "large": "more"}
            ),
        ],
        {"sarif_text": _SARIF, "held": [], "repo_ref": "github.com/fixture/fixture",
         "truncated": False},
        "sarif=present;size=small",
        "sarif=present;size=small",
    ),
    "security.runtime-inventory": (
        "response:RuntimeInventory",
        "response:classify_inventory",
        "A runtime-inventory scan (the kit body or a CycloneDX SBOM of one asset) and what "
        "one scope's coverage holds.",
        [
            _dimension("inventory", "whether an inventory text is present",
                       {"present": "a text"}),
            _dimension("size", "how large the scan is",
                       {"small": "at most 1 MiB", "large": "more"}),
        ],
        {"inventory_text": json.dumps({"scope": "fixture", "looked_for": ["*"],
                                       "coverage": "full", "assets": []}),
         "held": [], "patches": [], "scope": "fixture", "truncated": {}},
        "inventory=present;size=small",
        "inventory=present;size=small",
    ),
    "security.log-reads": (
        "response:LogReads",
        "response:classify_log",
        "One log read and the incident's audits.",
        [_dimension("read", "whether a log read text is present", {"present": "a text"})],
        {"read_text": json.dumps({"audit": {"incident": "fixture", "service": "fixture"},
                                  "source": "fixture/log", "from": "2026-01-01T00:00:00Z",
                                  "to": "2026-01-02T00:00:00Z", "complete": True}),
         "held": [], "incident": "fixture", "truncated": False},
        "read=present",
        "read=present",
    ),
    "security.credential-state": (
        "response:CredentialState",
        "response:classify_credential",
        "One credential's key state (non-secret ids only) and every held credential.",
        [_dimension("state", "whether a credential-state text is present",
                    {"present": "a text"})],
        {"state_text": json.dumps({"issuer": "fixture", "name": "fixture", "read": "receipt",
                                   "keys": [{"key_id": "fp:0000000000000000",
                                             "state": "active"}]}),
         "held": [], "truncated": False},
        "state=present",
        "state=present",
    ),
    "security.respond": (
        "response:Respond",
        "response:classify_respond",
        "One incident's exposure, scanned-run, patch, exception, audit and credential rows.",
        [_dimension("rows", "how many rows the request carries", {
            "small": "at most 5000 rows", "large": "more than 5000 rows"})],
        {"exposure": [], "hosts": [], "patches": [], "overdue": [], "exceptions": [],
         "audits": [], "credentials": [], "params": {}, "truncated": {}},
        "rows=small",
        "rows=*",
    ),
    "security.harden": (
        "harden:Harden",
        "harden:classify",
        "The six hardening queries' rows for the gated targets.",
        [_dimension("rows", "how many rows the request carries", {
            "small": "at most 5000 rows", "large": "more than 5000 rows"})],
        {"hq1": [], "hq2": [], "hq3": [], "hq4": [], "hq5": [], "hq6": [], "params": {},
         "truncated": {}},
        "rows=small",
        "rows=*",
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
                "entrypoint": f"security_analysis_provider.{entry}",
                "backends": ["local_env"],
                "requires_extras": [],
                "declared_input_buckets": [selector],
                "bucket_conformance": {selector: fixture_id},
                "declared_endpoints": [],
                "capture_contract_families": [],
                "deterministic": True,
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
                    "entrypoint": f"security_analysis_provider.{classifier}",
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
            "provider_id": "security-analysis-provider",
            "distribution": {"name": "security-analysis-provider", "version": VERSION},
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
