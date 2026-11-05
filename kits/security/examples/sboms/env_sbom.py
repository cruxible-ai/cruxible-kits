"""A CycloneDX 1.6 JSON SBOM of the Python environment running this script.

The local equivalent of ``cyclonedx-py environment`` (that tool could not be
fetched here): one ``library`` component per installed distribution, named by
its PyPI package URL (``pkg:pypi/<pep503 name>@<version>``), read from
``importlib.metadata`` of the interpreter that runs it.

    <python> env_sbom.py OUT.json --name NAME --version VERSION
"""

import argparse
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from importlib import metadata


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("out")
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    seen: dict[str, dict] = {}
    for dist in metadata.distributions():
        name = dist.metadata.get("Name")
        version = dist.version
        if not name or not version:
            continue
        purl = f"pkg:pypi/{pep503(name)}@{version}"
        seen.setdefault(
            purl,
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
            },
        )
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {"type": "application", "name": "kit-b1 env_sbom.py", "version": "1"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": args.name,
                "version": args.version,
                "purl": f"pkg:generic/{args.name}",
            },
            "properties": [{"name": "python", "value": sys.version.split()[0]}],
        },
        "components": [seen[k] for k in sorted(seen)],
    }
    with open(args.out, "w") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    print(len(seen), "components")


if __name__ == "__main__":
    main()
