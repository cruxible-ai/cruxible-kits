"""The default provider's Contracts as one authoring change set.

A kit ships the Contracts its default provider's operations pin (core refuses a
provider install whose operation Contracts are not accepted). This renders the
exact members cruxible-provider-web ships (``contracts/<name>/v<N>.json``) as
``contract`` authoring members, so they land through ``authoring submit`` and
lower to the same accepted members.

    python web_contracts.py PROVIDERS_CHECKOUT OUT.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cruxible_client.contracts.shapes import parse_contract, render_type


def _spelling(field_type: object) -> str:
    return render_type(field_type)  # type: ignore[arg-type]


def members(checkout: Path) -> list[dict[str, object]]:
    root = checkout / "packages/cruxible-provider-web/src/cruxible_provider_web/contracts"
    out = []
    for path in sorted(root.rglob("*.json")):
        member = "contracts/" + path.relative_to(root).as_posix()
        contract = parse_contract(path.read_bytes(), path=member)
        fields: dict[str, object] = {}
        for name, field in contract.fields.items():
            spelling = _spelling(field.type) + ("?" if field.optional else "")
            fields[name] = (
                {"type": spelling, "description": field.description}
                if field.description
                else spelling
            )
        item: dict[str, object] = {
            "kind": "contract",
            "name": contract.name,
            "version": contract.version,
            "fields": fields,
        }
        if contract.description:
            item["description"] = contract.description
        out.append(item)

    # Nested Contracts first: a member names name@N of one accepted or earlier in the set.
    def nested(item: dict[str, object]) -> int:
        text = json.dumps(item["fields"])
        return 1 if "@" in text else 0

    return sorted(out, key=nested)


if __name__ == "__main__":
    payload = {
        "kind": "change_set",
        "rationale": "The Contracts cruxible-provider-web's operations pin, as the package ships them.",
        "members": members(Path(sys.argv[1])),
    }
    Path(sys.argv[2]).write_text(json.dumps(payload, indent=1) + "\n")
    print(len(payload["members"]), "contracts")
