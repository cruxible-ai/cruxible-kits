"""Push one kit directory to a registry reference (the gate's throwaway registry).

    python publish_kit.py KIT_DIR REGISTRY/NAMESPACE/ID:VERSION
"""

from __future__ import annotations

import sys
from pathlib import Path

from cruxible_client.artifacts import RegistryClient, pack_artifact, parse_reference
from cruxible_client.kits import KIT_ARTIFACT, read_kit_directory


def main() -> None:
    bundle = read_kit_directory(Path(sys.argv[1]))
    reference = parse_reference(sys.argv[2])
    with RegistryClient() as registry:
        print(registry.push(pack_artifact(KIT_ARTIFACT, bundle), reference))


if __name__ == "__main__":
    main()
