"""Write the package's Contracts and registration.json from the declarations below.

Run after any change to a Contract or the manifest (core's client on PYTHONPATH):

    python build_registration.py

Contracts are rendered by core's own Contract renderer, nested ``name@N`` refs
pinned by digest, so the files are exactly what an accepted tree holds.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cruxible_client.contracts.shapes import (
    contract_digest,
    pin_contract_refs,
    render_contract,
    validate_contract,
)

ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "src" / "security_sarif_provider"
ENTRYPOINT = "security_sarif_provider.sarif:SarifFindings"
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_REPO = 'string{max_len: 256, pattern: "^[a-z0-9.-]+/[^/\\\\s]+/[^/\\\\s]+$"}'

#: In dependency order: a Contract names only Contracts above it.
CONTRACTS: list[dict[str, Any]] = [
    {
        "name": "sarif.held-finding",
        "description": "One finding the instance holds for a repository: its Subject, key "
        "parts, the rules that reported it (tool:ruleId) and its verification.",
        "fields": {
            "subject_kind": "string{max_len: 64}",
            "subject_id": "string{max_len: 256}",
            "weakness": "string{max_len: 256}",
            "locus": "string{max_len: 256}",
            "rules": "list<string{max_len: 256}>{max_items: 64}?",
            "verification": "string{max_len: 16}?",
        },
    },
    {
        "name": "sarif.findings.request",
        "description": "This run's SARIF Captures (their bytes, passed by core), the findings "
        "the instance holds for the Line's repository, the repository (host/owner/repo) and "
        "the logical source the derived document is committed under.",
        "fields": {
            "logs": "list<capture<*>>{max_items: 16}",
            "held": "list<sarif.held-finding@1>{max_items: 20000}",
            "repo": _REPO,
            "logical_source": _SOURCE,
        },
    },
    {
        "name": "sarif.findings.result",
        "description": "One derived JSON document: findings by (repo, weakness, locus) with "
        "their verification (present, or fixed for a held finding a full scan of its rules no "
        "longer reports); the header queried (the rule set that ran), full and covered (the "
        "held findings a full run's rules cover: the Claims' expect); attention records "
        "(regressions, location gaps) and routed dependency advisories.",
        "fields": {"document": "capture<*>"},
    },
    {
        "name": "sarif.findings.refusal.provider_declined",
        "description": "Detail of a provider_declined refusal (an unreadable SARIF log or "
        "held row, too many logs or results).",
        "fields": {},
    },
]


def contracts() -> list[Any]:
    built: dict[tuple[str, int], Any] = {}
    out = []
    for item in CONTRACTS:
        declared = validate_contract({"version": 1, **item})

        def pin(ref: Any) -> Any:
            return ref.model_copy(
                update={"digest": contract_digest(built[(ref.name, ref.version)]).tagged}
            )

        pinned = pin_contract_refs(declared, pin)
        built[(pinned.name, pinned.version)] = pinned
        out.append(pinned)
    return out


def main() -> None:
    for contract in contracts():
        path = MODULE / "contracts" / contract.name / f"v{contract.version}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(render_contract(contract))
    manifest = (MODULE / "manifest.yaml").read_bytes()
    registration = {
        "schema_version": 2,
        "manifest": {
            "path": "manifest.yaml",
            "digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
        },
        "operations": [
            {
                "name": "sarif.findings",
                "in": "sarif.findings.request@1",
                "out": "sarif.findings.result@1",
                "effect": "pure",
                "refusals": {
                    "provider_declined": {
                        "contract": "sarif.findings.refusal.provider_declined@1",
                        "absorbable": False,
                    }
                },
                "entrypoint": ENTRYPOINT,
            }
        ],
        "runtime_requirements": [],
    }
    (MODULE / "registration.json").write_text(json.dumps(registration, indent=1) + "\n")
    print("wrote", len(CONTRACTS), "contracts and registration.json")


if __name__ == "__main__":
    main()
