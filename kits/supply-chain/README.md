# Supply chain kit

## What it is

A starter vocabulary for supply chain, BOM blast radius, and vendor review:
suppliers, their facilities, the components they manufacture, the products that
use them, each supplier's compliance certificates (SOC 2, ISO 9001, RoHS,
AS9100, ISO 13485, and any other standard slug), and active incidents. ERP
keeps pricing, inventory, and purchase orders; Cruxible holds qualification
verdicts, sole-source exposure, and the exact audit evidence each decision
rests on.

A component's approval is pinned to the certificates and supplier standing it
relied on, so it carries forward across every product that uses the component.
When a certificate is renewed or revised, exactly the approvals that rest on it
are flagged for a re-check, and lapsing certificates show up before they expire.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which products does a supplier touch? | `supply.affected_products` (parameter `supplier`, such as `acme-sensors`) |
| Which certificates lapse soon? | `supply.expiring_certificates` (lapsed, or lapsing within 30 days) |
| Which critical parts lack production approval? | `supply.unapproved_critical_components` (`criticality >= high`, reviewed or not) |
| Where are we exposed to sole-source risk? | `supply.sole_source_critical` (production products with sole-source critical parts or high-risk/suspended suppliers) |
| Which supply incidents are still open? | `supply.open_incidents` (`open`, severity `medium` or worse) |
| Which approvals rest on a changed certificate? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `supply.supplier` | its slug (`acme-sensors`) | `title`, `country`, `risk_tier`, `status` |
| `supply.facility` | its slug (`acme-penang-fab-2`) | `supplier`, `title`, `country`, `role`, `status` |
| `supply.component` | its supplier MPN (`fw-crypto-2.4`) | `title`, `supplier`, `facility`, `category`, `criticality`, `review_status` |
| `supply.product` | its SKU (`edge-gateway-v3`) | `title`, `lifecycle` |
| `supply.usage` | its product and component (`edge-gateway-v3--fw-crypto-2.4`) | `quantity`, `sourcing` (`sole_source`, `primary`, `alternate`) |
| `supply.certificate` | its supplier and standard (`acme-sensors--soc2-type2`) | `facility`, `issued_at`, `valid_until`, `verdict` |
| `supply.incident` | its slug (`penang-power-outage-2026`) | `affects`, `category`, `severity`, `disposition` |

`supply.usage` and `supply.certificate` are pair kinds keyed by their ends. A
renewal revises the one certificate pair in place and keeps its history.
`risk_tier`, `criticality`, `severity`, and `status` (`approved` to
`disqualified`) are ordered enums so queries can compare rank. The kit also
installs one governed review guidance Document
(`document:supply.guidance.review-guidance`) attached to supplier risk/status,
component review, certificate verdict, and incident disposition.

## Recording a judgment

A production approval pinned to the certificate it relied on:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.supply.component["fw-crypto-2.4"].set(
        review_status="approved_for_production",
        because="SOC 2 Type II accepted with no exceptions; sole source for two SKUs.",
        evidence=FileEvidence(file="vendors/acme-soc2-2025.md#Opinion: no exceptions noted."),
        based_on=[
            "supply.certificate/acme-sensors--soc2-type2#verdict",
            "supply.certificate/acme-sensors--soc2-type2#valid_until",
        ],
    )
```

## Install

```sh
cruxible kit add supply-chain
```

The kit carries definitions and review guidance only: no values, Providers,
Procedures, or Lines. In the kits repository the release rebuilds from
`kits/supply-chain/source/definitions.py` with
`python scripts/build_kit.py kits/supply-chain SCRATCH`.
