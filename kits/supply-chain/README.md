# Supply chain kit

## What it is

A starter vocabulary for supply chain and vendor review: suppliers, the
components they make, the products that use them, and each supplier's
attestations to standards such as SOC 2 or ISO 9001. Facts read from BOMs and
certificates are observations; supplier risk, attestation verdicts and
component approvals are governed decisions that cite their source.

A component's approval is pinned to the attestations it relied on, so it
carries forward across every product that uses the component. When an
attestation is renewed or revised, exactly the approvals that rest on it are
flagged for a re-check, and a lapsing certificate shows up before it expires.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which products does a supplier touch? | `supply.affected_products` (parameter `supplier`, such as `acme-sensors`) |
| Which attestations lapse soon? | `supply.expiring_attestations` (lapsed, or lapsing within 30 days) |
| Which critical parts lack production approval? | `supply.unapproved_critical_components` (criticality `high` or worse, reviewed or not) |
| Which approvals rest on a changed attestation? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `supply.supplier` | its slug (`acme-sensors`) | `title`, `country`, `risk_tier`, `status` |
| `supply.component` | its part number (`fw-crypto-2.4`) | `title`, `supplier`, `category`, `criticality`, `review_status` |
| `supply.product` | its SKU (`edge-gateway-v3`) | `title`, `lifecycle` |
| `supply.usage` | its product and component (`edge-gateway-v3--fw-crypto-2.4`) | `quantity`, `sourcing` (`sole_source`, `primary`, `alternate`) |
| `supply.attestation` | its supplier and standard (`acme-sensors--soc2-type2`) | `issued_at`, `valid_until`, `verdict` |

`supply.usage` and `supply.attestation` are pair kinds: the relationship has
its own state, so it is its own Subject, keyed by its ends. A renewal revises
the one attestation pair in place and keeps its history. `risk_tier` and
`criticality` are ordered enums (`low` to `critical`). `review_status` runs
`pending_review`, `approved_for_prototype`, `approved_for_production`,
`approved_with_conditions`, `rejected`. Every field admits your own words or a
passage of a catalogued workspace file; a verdict or approval should cite the
report or certificate it rests on.

## Recording a judgment

A production approval pinned to the attestation it relied on:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.supply.component["fw-crypto-2.4"].set(
        review_status="approved_for_production",
        because="SOC 2 Type II accepted with no exceptions; sole source for two SKUs.",
        evidence=FileEvidence(file="vendors/acme-soc2-2025.md#Opinion: no exceptions noted."),
        based_on=[
            "supply.attestation/acme-sensors--soc2-type2#verdict",
            "supply.attestation/acme-sensors--soc2-type2#valid_until",
        ],
    )
```

## Install

```sh
cruxible kit add /path/to/cruxible-kits/kits/supply-chain                  # preview; prints the coordinate
cruxible kit add /path/to/cruxible-kits/kits/supply-chain --commit --at OID
```

`cruxible kit add supply-chain:1.0.0` installs the same release from the
registry once it is published. The kit carries definitions only: no values,
Providers, Procedures or Lines. In the kits repository the release rebuilds
from `kits/supply-chain/source/definitions.py` with
`python scripts/build_kit.py kits/supply-chain SCRATCH`.
