# Supply chain review guidance

Guides: `supply.supplier.risk_tier`, `supply.supplier.status`, `supply.component.review_status`, `supply.certificate.verdict`, `supply.incident.disposition`.

## Mirror vs. fetch boundary

Keep live unit pricing, inventory counts, purchase orders, and transit tracking in your ERP or PLM. Cruxible holds what the ERP does not: supplier risk ratings, facility approvals, certificate verdicts, component qualification decisions, sole-source exposure, and the exact audit evidence each judgment rests on.

## Evaluating a certificate (`supply.certificate.verdict`)

- Cite the specific report, scope, or auditor opinion passage (`FileEvidence`) that backs `accepted`, `accepted_with_exceptions`, or `rejected`.
- Record exact `issued_at` and `valid_until` timestamps from the certificate so `supply.expiring_certificates` flags renewals before lapse.
- Renew a certificate by revising the same `(supplier, standard)` pair Subject in place so every downstream component review pinned to it via `based_on` reopens selectively.

## Qualifying a component (`supply.component.review_status`)

- Treat each `supply.component` as a supplier-specific manufacturer part number (MPN). Alternate suppliers get their own `supply.component` Subject and appear as `alternate` rows in `supply.usage`.
- Pin (`based_on`) `approved_for_production` and `approved_with_conditions` to the `supply.certificate` `verdict` and `valid_until` claims relied on, plus the supplier's `status`.
- Never clear a `critical` or `high` criticality component for production while its supplier is `suspended` or `disqualified`.

## Managing incidents (`supply.incident.disposition`)

- Link each incident to the exact `supply.supplier`, `supply.facility`, or `supply.component` affected so blast-radius queries trace directly to shipping products.
- Record mitigation or acceptance rationale in a cited workspace memo before closing an incident.
